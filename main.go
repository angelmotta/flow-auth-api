package main

import (
	"github.com/angelmotta/flow-auth-api/app"
	"log"
	"net/http"
)

func main() {
	log.Println("Start authServer flowApp")

	// Create authServer
	a := app.NewAuthServer()

	// Run http server
	log.Fatal(http.ListenAndServe(":8080", a.Router))
}
