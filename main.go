package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"code.cloudfoundry.org/credhub-cli/credhub"
	"code.cloudfoundry.org/credhub-cli/credhub/auth"
	"code.cloudfoundry.org/credhub-cli/credhub/credentials/values"
	"github.com/gorilla/mux"
	"github.com/qntfy/kazaam"
)

func main() {
	router := mux.NewRouter()
	subrouter := router.PathPrefix("/v1").Subrouter()
	subrouter.HandleFunc("/sys/seal-status", SealStatus).Methods("GET")
	subrouter.HandleFunc("/sys/leader", Leader).Methods("GET")
	subrouter.HandleFunc("/auth/approle/login", AppRoleLogin).Methods("POST")
	subrouter.HandleFunc("/secret/handshake", SecretHandshake).Methods("GET")
	subrouter.HandleFunc("/{path:.*}", ListSecret).Methods("LIST")
	subrouter.HandleFunc("/{path:.*}", GetSecret).Methods("GET")
	subrouter.HandleFunc("/{path:.*}", SetSecret).Methods("POST")
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
	w.Write([]byte(`{"value":{"knock":"knock"}}`))
	log.Print("secret handshake")
}

func AppRoleLogin(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body",
			http.StatusInternalServerError)
	}
	k, _ := kazaam.New(`[{"operation": "shift", "spec": {"auth.client_token": "secret_id"}}]`, kazaam.NewDefaultConfig())
	o, _ := k.TransformInPlace(body)
	w.Write(o)
	log.Print("app role login")

}

func ListSecret(w http.ResponseWriter, r *http.Request) {
	ch, err := getCredhubClient(r.Header.Get("X-Vault-Token"))
	if err != nil {
		log.Fatal("Error connection to Credhub: ", err)
	}

	path := mux.Vars(r)["path"]
	results, err := ch.FindByPath(path)
	if err != nil {
		log.Printf("error returned by credhub FindByPath %s", err)
	}

	j, _ := json.Marshal(results.Credentials)
	k, _ := kazaam.New(`[{"operation": "shift", "spec": {"data": "$"}}]`, kazaam.NewDefaultConfig())
	o, _ := k.TransformInPlace(j)
	k, _ = kazaam.New(`[{"operation": "shift", "spec": {"data.keys": "data[*].name"}}]`, kazaam.NewDefaultConfig())
	o, _ = k.TransformInPlace(o)
	w.Write(o)
	log.Printf("list path %s", path)

}

func GetSecret(w http.ResponseWriter, r *http.Request) {
	ch, err := getCredhubClient(r.Header.Get("X-Vault-Token"))
	if err != nil {
		log.Fatal("Error connection to Credhub: ", err)
	}

	path := mux.Vars(r)["path"]
	cred, err := ch.GetLatestVersion(path)
	if err != nil {
		http.Error(w, "Not Found or Access Denied",
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
		log.Fatal("Error connection to Credhub: ", err)
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
		log.Fatal("Error connection to Credhub: ", err)
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
