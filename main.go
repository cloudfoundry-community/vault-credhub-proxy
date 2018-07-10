package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/cloudfoundry-incubator/credhub-cli/credhub"
	"github.com/cloudfoundry-incubator/credhub-cli/credhub/auth"
	"github.com/gorilla/mux"
	"github.com/qntfy/kazaam"
)

// our main function
func main() {
	ch, err := getCredhubClient()
	if err != nil {
		log.Fatal("Error connection to Credhub: ", err)
	}

	router := mux.NewRouter()
	subrouter := router.PathPrefix("/v1").Subrouter()
	subrouter.HandleFunc("/{path:.*}", ListSecret(ch)).Methods("GET").Queries("list", "1")
	subrouter.HandleFunc("/{path:.*}", GetSecret).Methods("GET")
	subrouter.HandleFunc("/{path:.*}", SetSecret).Methods("POST")
	subrouter.HandleFunc("/{path:.*}", DelSecret).Methods("DELETE")
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

func GetSecret(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	log.Printf("get path %s", params["path"])
}

func SetSecret(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	log.Printf("set path %s", params["path"])
}
func DelSecret(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	log.Printf("del path %s", params["path"])
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
