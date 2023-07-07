package app

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"google.golang.org/api/idtoken"
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

func (a *AuthServer) isValidGoogleIdToken(tokenId string) (bool, string) {
	// Verify the ID token, including the expiry, signature, issuer, and audience.
	tokenPayload, err := idtoken.Validate(context.Background(), tokenId, "535433429806-oc8egpmgdvuot4bic0pc900q3pl3i7rv.apps.googleusercontent.com")
	if err != nil {
		log.Println("Invalid token")
		log.Println(err)
		return false, ""
	}

	// Valid Token, you can use the token to get user information.
	fmt.Println("Token verified successfully.")
	email := tokenPayload.Claims["email"].(string)
	return true, email
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

	// Validate tokenId using Google auth library client
	isValid, email := a.isValidGoogleIdToken(tokenId)
	if !isValid {
		http.Error(w, "invalid credential", http.StatusBadRequest)
		return
	}
	log.Println("Token is valid: ", email)

	// Create access token FlowApp

	// Return status
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write([]byte(`{"status": "ok"}`))
	if err != nil {
		log.Printf("Error sending response: %v", err.Error())
		return
	}
}
