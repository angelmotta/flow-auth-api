package main

import (
	"github.com/angelmotta/flow-auth-api/app"
	"log"
	"net/http"
)

func main() {
	// Create authServer
	a := app.NewAuthServer()
	log.Printf("Start flowApp-authServer at port %v", a.Config.HttpAddr)
	// Run http server
	log.Fatal(http.ListenAndServe(a.Config.HttpAddr, a.Router))
}
