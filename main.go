package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/cloudfoundry-incubator/credhub-cli/credhub"
	"github.com/cloudfoundry-incubator/credhub-cli/credhub/auth"
	"github.com/cloudfoundry-incubator/credhub-cli/credhub/credentials/values"
	"github.com/gorilla/mux"
	"github.com/qntfy/kazaam"
)

func main() {
	ch, err := getCredhubClient()
	if err != nil {
		log.Fatal("Error connection to Credhub: ", err)
	}

	router := mux.NewRouter()
	subrouter := router.PathPrefix("/v1").Subrouter()
	subrouter.HandleFunc("/{path:.*}", ListSecret(ch)).Methods("GET").Queries("list", "1")
	subrouter.HandleFunc("/{path:.*}", GetSecret(ch)).Methods("GET")
	subrouter.HandleFunc("/{path:.*}", SetSecret(ch)).Methods("POST")
	subrouter.HandleFunc("/{path:.*}", DelSecret(ch)).Methods("DELETE")
	log.Fatal(http.ListenAndServe(":8000", router))
}

func ListSecret(ch *credhub.CredHub) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
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
}

func GetSecret(ch *credhub.CredHub) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
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
		default:
			k, _ = kazaam.New(`[{"operation": "shift", "spec": {"data": "value"}}]`, kazaam.NewDefaultConfig())
		}
		o, _ := k.TransformInPlace(j)
		w.Write(o)

		log.Printf("get path %s", path)
	}
}

func SetSecret(ch *credhub.CredHub) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		path := mux.Vars(r)["path"]
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading request body",
				http.StatusInternalServerError)
		}
		value := values.JSON{}
		err = json.Unmarshal(body, &value)
		cred, err := ch.SetJSON(path, value, credhub.Converge)
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
}

func DelSecret(ch *credhub.CredHub) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		path := mux.Vars(r)["path"]
		err := ch.Delete(path)
		if err != nil {
			http.Error(w, "Error in Delete",
				http.StatusInternalServerError)
		}
		log.Printf("del path %s", path)
	}
}

func getCredhubClient() (*credhub.CredHub, error) {
	caCert, err := ioutil.ReadFile(os.Getenv("CREDHUB_CA_CERT"))
	if err != nil {
		return nil, err
	}

	return credhub.New(
		os.Getenv("CREDHUB_SERVER"),
		credhub.CaCerts(string(caCert)),
		credhub.Auth(auth.UaaClientCredentials(os.Getenv("CREDHUB_CLIENT"), os.Getenv("CREDHUB_SECRET"))),
	)
}
