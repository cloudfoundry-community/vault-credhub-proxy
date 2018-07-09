package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

// our main function
func main() {
	router := mux.NewRouter()
	subrouter := router.PathPrefix("/v1").Subrouter()
	subrouter.HandleFunc("/{path:.*}", ListSecret).Methods("GET").Queries("list", "1")
	subrouter.HandleFunc("/{path:.*}", GetSecret).Methods("GET")
	subrouter.HandleFunc("/{path:.*}", SetSecret).Methods("POST")
	subrouter.HandleFunc("/{path:.*}", DelSecret).Methods("DELETE")
	log.Fatal(http.ListenAndServe(":8000", router))
}

func ListSecret(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	log.Printf("list path %s", params["path"])

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
