package app

import (
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"log"
	"net/http"
)

type AuthServer struct {
	Router *chi.Mux
}

func NewAuthServer() *AuthServer {
	r := chi.NewRouter()

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins: []string{"https://mysideproject.com", "http://localhost:5173"},
		// AllowOriginFunc:  func(r *http.Request, origin string) bool { return true },
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders: []string{"Link"},
		//AllowCredentials: false,
		//MaxAge:           300, // Maximum value not ignored by any of major browsers
	}))

	// Create a new AuthServer
	a := &AuthServer{
		Router: r,
	}
	// Register routes
	a.routes()

	return a
}

type loginGoogleRequest struct {
	Credential string `json:"credential"`
}

func (a *AuthServer) handleLoginGoogle(w http.ResponseWriter, r *http.Request) {
	// Unmarshal body request into loginGoogleRequest struct
	var request loginGoogleRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err := dec.Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check if credential field is empty
	log.Println("request:", request)
	if request.Credential == "" {
		http.Error(w, "credential field is required", http.StatusBadRequest)
		return
	}
	// get tokenId from credential
	tokenId := request.Credential
	log.Println("tokenId:", tokenId)

	// Validate token Id using Google auth api
	// If token is valid, return access token

	// If token is invalid, return error

	// Create access token App

	// Return status
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write([]byte(`{"status": "ok"}`))
	if err != nil {
		log.Printf("Error sending response: %v", err.Error())
		return
	}
}
