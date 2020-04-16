package main

import (
	"encoding/json"
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
	"github.com/gorilla/mux"
	"github.com/qntfy/kazaam"
)

type tmpMount struct {
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Config      struct{} `json:"config"`
}

func main() {
	router := mux.NewRouter()
	subrouter := router.PathPrefix("/v1").Subrouter()
	subrouter.HandleFunc("/sys/internal/ui/mounts", Mounts).Methods("GET")
	subrouter.HandleFunc("/sys/mounts", Mounts).Methods("GET")
	subrouter.HandleFunc("/sys/seal-status", SealStatus).Methods("GET")
	subrouter.HandleFunc("/sys/health", SealStatus).Methods("GET")
	subrouter.HandleFunc("/sys/leader", Leader).Methods("GET")
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

func Mounts(w http.ResponseWriter, r *http.Request) {
	log.Print("mounts")
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

	mounts := make(map[string]tmpMount)
	for _, key := range results.Credentials {
		mountName := strings.Split(strings.TrimPrefix(key.Name, fmt.Sprintf("/%s", path)), "/")[0]
		mounts[mountName] = tmpMount{
			Type:        "kv",
			Description: "A vault proxy backend",
		}
	}
	out, _ := json.Marshal(mounts)
	w.Write(out)
	log.Printf("list path %s", path)
}

func SealStatus(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`{"sealed":false}`))
	log.Print("seal status")
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
