package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"

	"code.cloudfoundry.org/credhub-cli/credhub"
	"code.cloudfoundry.org/credhub-cli/credhub/auth"
	"code.cloudfoundry.org/credhub-cli/credhub/credentials/values"
	"github.com/gofrs/uuid"
	"github.com/gorilla/mux"
	"github.com/qntfy/kazaam"
)

var Version string

type fakeMount struct {
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Config      struct{} `json:"config"`
	Options     struct{} `json:"options"`
}

func main() {

	if (len(os.Args[1:]) >= 1) {
		if (os.Args[1] == "-v" || os.Args[1] == "--version") {
			if Version != "" {
				fmt.Fprintf(os.Stderr, "vault-credhub-proxy v%s\n", Version)
			} else {
				fmt.Fprintf(os.Stderr, "vault-credhub-proxy (development build)\n")
			}
			os.Exit(0)
			return
		}
	}

	router := mux.NewRouter()
	router.Use(requestLogger)
	subrouter := router.PathPrefix("/v1").Subrouter()
	subrouter.HandleFunc("/sys/internal/ui/mounts", Mounts).Methods("GET")
	subrouter.HandleFunc("/sys/mounts", Mounts).Methods("GET")
	subrouter.HandleFunc("/sys/seal-status", SealStatus).Methods("GET")
	subrouter.HandleFunc("/sys/health", SealStatus).Methods("GET")
	subrouter.HandleFunc("/sys/leader", Leader).Methods("GET")
	subrouter.HandleFunc("/auth/token/lookup-self", CheckToken).Methods("GET")
	subrouter.HandleFunc("/auth/approle/login", AppRoleLogin).Methods("POST")
	subrouter.HandleFunc("/secret/handshake", SecretHandshake).Methods("GET")
	subrouter.HandleFunc("/{path:.*}", ListSecret).Methods("LIST")
	subrouter.HandleFunc("/{path:.*}", GetSecret).Methods("GET")
	subrouter.HandleFunc("/{path:.*}", SetSecret).Methods("PUT")
	subrouter.HandleFunc("/{path:.*}", DelSecret).Methods("DELETE")

	addr := "127.0.0.1:8200"
	if a := os.Getenv("ADDRESS"); a != "" {
		addr = a
	}
	if os.Getenv("TLS_CERT_FILE") != "" {
		log.Fatal(http.ListenAndServeTLS(addr,
			os.Getenv("TLS_CERT_FILE"), os.Getenv("TLS_KEY_FILE"), router))
	} else {
		log.Fatal(http.ListenAndServe(addr, router))
	}
}

func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create a struct to hold the data
		reqData := struct {
			Method string
			URL    string
			Header http.Header
		}{
			Method: r.Method,
			URL:    r.URL.String(),
			Header: r.Header,
		}

		// Serialize to JSON
		jsonData, err := json.Marshal(reqData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshalling request data: %v", err)
			// Even if we couldn't marshal the data, we still want to handle the request
			next.ServeHTTP(w, r)
			return
		}

		// Print to stdout
		fmt.Println(string(jsonData))

		// Handle the request
		next.ServeHTTP(w, r)
	})
}

func Mounts(w http.ResponseWriter, r *http.Request) {
	log.Print("mounts")
	ch, err := getCredhubClient(r.Header.Get("X-Vault-Token"))
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"errors":["Error connecting to credhub: %s"]}`, err.Error()),
			http.StatusInternalServerError)
		log.Printf("Error connecting to Credhub: %s", err)
		return
	}

	path := "";
	results, err := ch.FindByPath(path)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"errors":["Error connecting to credhub: %s"]}`, err.Error()),
			http.StatusInternalServerError)
		log.Printf("error returned by credhub FindByPath %s", err)
		return
	}

	mounts := make(map[string]fakeMount)
	for _, key := range results.Credentials {
		mountName := strings.Split(strings.TrimPrefix(key.Name, fmt.Sprintf("/%s", path)), "/")[0]
		mounts[mountName] = fakeMount{
			Type:        "kv",
			Description: "A vault proxy backend",
		}
	}
	out, _ := json.Marshal(mounts)
	w.Write(out)
	log.Printf("mounts found: %s", out)
}

func SealStatus(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`{"sealed":false}`))
	log.Print("seal status")
}

func CheckToken(w http.ResponseWriter, r *http.Request) {	
	token := r.Header.Get("X-Vault-Token")
	uuid, _ := uuid.NewGen().NewV1()
	_, err := getCredhubClient(token)
	if err != nil {
		log.Printf("token invalid: %s\n", err.Error())
		http.Error(w, fmt.Sprintf(`{"errors":["permission denied: %s"]}`, err.Error()), http.StatusForbidden)
		return
	}
	
	type Data struct {
		Accessor       string    `json:"accessor"`
		CreationTime   int       `json:"creation_time"`
		CreationTTL    int       `json:"creation_ttl"`
		DisplayName    string    `json:"display_name"`
		EntityId       string    `json:"entity_id"`
		ExpireTime     *struct{} `json:"expire_time"`
		ExplicitMaxTTL int       `json:"explicit_max_ttl"`
		ID             string    `json:"id"`
		Meta           *struct{} `json:"meta"`
		NumUses        int       `json:"num_uses"`
		Orphan         bool      `json:"orphan"`
		Path           string    `json:"path"`
		Policies       []string  `json:"policies"`
		TTL            int       `json:"ttl"`
		Type           string    `json:"type"`
	}

	type Request struct {
		RequestId     string    `json:"request_id"`
		LeaseId       string    `json:"lease_id"`
		Renewable     bool      `json:"renewable"`
		LeaseDuration int       `json:"lease_duration"`
		Data          Data      `json:"data"`
		WrapInfo      *struct{} `json:"wrap_info"`
		Warnings      *struct{} `json:"warnings"`
		Auth          *struct{} `json:"auth"`
	}
	
	req := Request{
		RequestId:     uuid.String(),
		LeaseId:       "",
		Renewable:     false,
		LeaseDuration: 0,
		Data: Data{
			Accessor:       "",
			CreationTime:   1676509870,
			CreationTTL:    0,
			DisplayName:    "root",
			EntityId:       "",
			ExpireTime:     nil,
			ExplicitMaxTTL: 0,
			ID:             token,
			Meta:           nil,
			NumUses:        0,
			Orphan:         true,
			Path:           "auth/token/root",
			Policies:       []string{"root"},
			TTL:            0,
			Type:           "service",
		},
		WrapInfo:  nil,
		Warnings:  nil,
		Auth:      nil,
	}

	reqJSONB, err := json.Marshal(req)
	if err != nil {
		fmt.Printf("Error marshalling struct to JSON: %v\n", err)
		return
	}
	fmt.Println(string(reqJSONB))

	w.Write(reqJSONB)

	log.Printf("token lookup-self")
}

func Leader(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`{"is_self":true}`))
	log.Print("leader status")
}

func SecretHandshake(w http.ResponseWriter, r *http.Request) {
	// Genesis uses secret/handshake as a health check
	// And is typically set during vault initialization (safe init)
	// Credhub does not have an init process so just fake the handshake
	ch, err := getCredhubClient(r.Header.Get("X-Vault-Token"))
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"errors":["Error connecting to credhub: %s"]}`, err.Error()),
			http.StatusInternalServerError)
		log.Printf("Error connecting to Credhub: %s", err)
		return
	}

	cred, err := ch.GetLatestVersion("secret/handshake")
	if err != nil {
		log.Printf("ERROR: %s", err.Error())
		value := values.JSON{}
		err = json.Unmarshal([]byte(`{"knock":"knock"}`), &value)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error setting secret: %s", err),
				http.StatusInternalServerError)
		}
		_, err := ch.SetJSON("secret/handshake", value)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error setting secret: %s", err),
				http.StatusInternalServerError)
		}
		w.Write([]byte(`{"data":{"knock":"knock"}}`))
		return
	}
	j, _ := json.Marshal(cred)
	var k *kazaam.Kazaam
	switch cred.Metadata.Type {
	case "password":
		k, _ = kazaam.New(`[{"operation": "shift", "spec": {"data.password": "value"}}]`, kazaam.NewDefaultConfig())
	case "value":
		k, _ = kazaam.New(`[{"operation": "shift", "spec": {"data.value": "value"}}]`, kazaam.NewDefaultConfig())
	case "certificate":
		k, _ = kazaam.New(`[{"operation": "shift", "spec": {"data.ca": "value.ca", "data.key": "value.private_key", "data.certificate": "value.certificate"}}]`, kazaam.NewDefaultConfig())
	default:
		k, _ = kazaam.New(`[{"operation": "shift", "spec": {"data": "value"}}]`, kazaam.NewDefaultConfig())
	}
	o, _ := k.TransformInPlace(j)
	w.Write(o)

	log.Print("secret handshake")
}

func AppRoleLogin(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"errors":["Error: reading request body"]}`,
			http.StatusInternalServerError)
		return
	}
	k, _ := kazaam.New(`[{"operation": "shift", "spec": {"auth.client_token": "secret_id"}}]`, kazaam.NewDefaultConfig())
	o, _ := k.TransformInPlace(body)
	w.Write(o)
	log.Print("app role login")
}

func ListSecret(w http.ResponseWriter, r *http.Request) {
	ch, err := getCredhubClient(r.Header.Get("X-Vault-Token"))
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"errors":["Error connecting to credhub: %s"]}`, err.Error()),
			http.StatusInternalServerError)
		log.Printf("Error connecting to Credhub: %s", err)
		return
	}

	path := mux.Vars(r)["path"]
	results, err := ch.FindByPath(path)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"errors":["Error connecting to credhub: %s"]}`, err.Error()),
			http.StatusInternalServerError)
		log.Printf("error returned by credhub FindByPath %s", err)
		return
	}

	j, _ := json.Marshal(results.Credentials)
	k, _ := kazaam.New(`[{"operation": "shift", "spec": {"data": "$"}}]`, kazaam.NewDefaultConfig())
	o, _ := k.TransformInPlace(j)
	k, _ = kazaam.New(`[{"operation": "shift", "spec": {"data.keys": "data[*].name"}}]`, kazaam.NewDefaultConfig())
	o, _ = k.TransformInPlace(o)
	if string(o) == `{"data":{"keys":[]}}` {
		http.Error(w, `{"errors":[]}`,
			http.StatusNotFound)
	}
	var tmp struct {
		Data struct {
			Keys []string
		}
	}

	keymap := map[string]bool{}

	json.Unmarshal(o, &tmp)
	for _, key := range tmp.Data.Keys {
		relativeKey := strings.Split(strings.TrimPrefix(key, fmt.Sprintf("/%s", path)), "/")[1]
		if len(strings.Split(strings.TrimPrefix(key, fmt.Sprintf("/%s", path)), "/")) != 2 {
			relativeKey = relativeKey + "/"
		}
		keymap[relativeKey] = true
	}

	tmp.Data.Keys = []string{}
	for key := range keymap {
		tmp.Data.Keys = append(tmp.Data.Keys, key)
	}

	sort.Strings(tmp.Data.Keys)
	out, _ := json.Marshal(tmp)
	w.Write(out)
	log.Printf("list path %s", path)

}

func GetSecret(w http.ResponseWriter, r *http.Request) {
	ch, err := getCredhubClient(r.Header.Get("X-Vault-Token"))
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"errors":["Error talking to credhub: %s"]}`, err.Error()),
			http.StatusInternalServerError)
		log.Printf("Error connecting to Credhub: %s", err)
		return
	}

	list := r.URL.Query().Get("list")
	if (list == "true") {
		ListSecret(w,r)
		return
	}

	path := mux.Vars(r)["path"]
	cred, err := ch.GetLatestVersion(path)
	if err != nil {
		http.Error(w, `{"errors":[]}`,
			http.StatusNotFound)
	}
	j, _ := json.Marshal(cred)
	var k *kazaam.Kazaam
	switch cred.Metadata.Type {
	case "password":
		k, _ = kazaam.New(`[{"operation": "shift", "spec": {"data.password": "value"}}]`, kazaam.NewDefaultConfig())
	case "value":
		k, _ = kazaam.New(`[{"operation": "shift", "spec": {"data.value": "value"}}]`, kazaam.NewDefaultConfig())
	case "certificate":
		k, _ = kazaam.New(`[{"operation": "shift", "spec": {"data.ca": "value.ca", "data.key": "value.private_key", "data.certificate": "value.certificate"}}]`, kazaam.NewDefaultConfig())
	default:
		k, _ = kazaam.New(`[{"operation": "shift", "spec": {"data": "value"}}]`, kazaam.NewDefaultConfig())
	}
	o, _ := k.TransformInPlace(j)
	w.Write(o)

	log.Printf("get path %s", path)

}

func SetSecret(w http.ResponseWriter, r *http.Request) {
	ch, err := getCredhubClient(r.Header.Get("X-Vault-Token"))
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"errors":["Error talking to credhub: %s"]}`, err.Error()),
			http.StatusInternalServerError)
		log.Printf("Error connecting to Credhub: %s", err)
		return
	}

	path := mux.Vars(r)["path"]
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body",
			http.StatusInternalServerError)
	}
	value := values.JSON{}
	err = json.Unmarshal(body, &value)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error unmarshalling json secret: %s", err),
			http.StatusInternalServerError)
	}
	cred, err := ch.SetJSON(path, value)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error setting secret: %s", err),
			http.StatusInternalServerError)
	}

	j, _ := json.Marshal(cred)
	k, _ := kazaam.New(`[{"operation": "shift", "spec": {"data": "value"}}]`, kazaam.NewDefaultConfig())
	o, _ := k.TransformInPlace(j)
	w.Write(o)
	log.Printf("set path %s", path)
}

func DelSecret(w http.ResponseWriter, r *http.Request) {
	ch, err := getCredhubClient(r.Header.Get("X-Vault-Token"))
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"errors":["Error talking to credhub: %s"]}`, err.Error()),
			http.StatusInternalServerError)
		log.Printf("Error connecting to Credhub: %s", err)
		return
	}

	path := mux.Vars(r)["path"]
	err = ch.Delete(path)
	if err != nil {
		http.Error(w, "Error in Delete",
			http.StatusInternalServerError)
	}
	log.Printf("del path %s", path)
}

func getCredhubClient(tokenHeader string) (*credhub.CredHub, error) {
	token := strings.Split(tokenHeader, ":")

	if len(token) < 2 || len(token[0]) == 0 || len(token[1]) == 0 {
		return nil, errors.New("Invalid Request Header 'X-Vault-Token', required format: \"${CREDHUB_CLIENT}:${CREDHUB_SECRET}\", where the value of CREDHUB_CLIENT is the admin user.")
	}

	caCert, err := ioutil.ReadFile(os.Getenv("CREDHUB_CA_CERT"))
	if err != nil {
		return nil, err
	}

	return credhub.New(
		os.Getenv("CREDHUB_SERVER"),
		credhub.CaCerts(string(caCert)),
		credhub.Auth(auth.UaaClientCredentials(token[0], token[1])),
	)
}
