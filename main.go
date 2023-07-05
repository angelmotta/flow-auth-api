package main

import (
	"github.com/go-chi/chi/v5"
	"log"
	"net/http"
)

func main() {
	log.Println("Auth Server: hellow world")

	r := chi.NewRouter()

	r.Post("/api/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, world!"))
	})
}
