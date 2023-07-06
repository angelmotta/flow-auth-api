package app

import (
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"log"
	"net/http"
)

type AuthServer struct {
	Router *chi.Mux
}

func NewAuthServer() *AuthServer {
	r := chi.NewRouter()

	a := &AuthServer{
		Router: r,
	}

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
	// Validate token Id

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
