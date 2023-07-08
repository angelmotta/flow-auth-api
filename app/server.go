package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/angelmotta/flow-auth-api/internal/config"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/api/idtoken"
	"io"
	"log"
	"net/http"
	"time"
)

type AuthServer struct {
	Router *chi.Mux
	Config *config.Config
}

type MyCustomClaims struct {
	Email string `json:"email"`
	Role  string `json:"role"`
	jwt.RegisteredClaims
}

type loginGoogleRequest struct {
	Credential string `json:"credential"`
}

type loginGoogleResponse struct {
	Token string `json:"token"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

func NewAuthServer() *AuthServer {
	// Prepare router
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

	// Get general Config for authServer
	globalConfig := config.GetConfig()

	// Create a new AuthServer
	a := &AuthServer{
		Router: r,
		Config: globalConfig,
	}

	// Register routes for AuthServer
	a.routes()

	return a
}

func (a *AuthServer) isValidGoogleIdToken(tokenId string) (bool, string) {
	// Verify the ID token, including the expiry, signature, issuer, and audience.
	tokenPayload, err := idtoken.Validate(context.Background(), tokenId, a.Config.GClientId)
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

func (a *AuthServer) generateToken(email string) (string, error) {
	key := []byte(a.Config.SecretJWTKey)

	// Prepare claims
	claims := MyCustomClaims{
		email,
		"customer",
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "flow-app",
		},
	}
	// Create token
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := t.SignedString(key)
	if err != nil {
		log.Println("Error generating token:", err)
		return "", err
	}
	return tokenString, nil
}

// verifyFlowAppToken verifies if received token is valid
func (a *AuthServer) verifyFlowAppToken(tokenString string) (*MyCustomClaims, error) {
	// verify token using the same key used to generate the token
	secretKey := []byte(a.Config.SecretJWTKey)
	token, err := jwt.ParseWithClaims(tokenString, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// validate alg
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})

	// Happy path: token is valid
	if claims, ok := token.Claims.(*MyCustomClaims); ok && token.Valid {
		log.Println("Token is valid")
		log.Println(claims)
		return claims, nil
	} else {
		// Error path: token is invalid
		log.Println("Token is invalid:")
		log.Println(err)
		if errors.Is(err, jwt.ErrTokenMalformed) {
			fmt.Println("That's not even a token")
		} else if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			// Invalid signature
			fmt.Println("Invalid signature")
		} else if errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet) {
			// Token is either expired or not active yet
			fmt.Println("Timing is everything")
		} else {
			fmt.Println("Couldn't handle this token:", err)
		}
		return nil, err
	}
}

func getTokenFromRequest(bodyRequest io.ReadCloser) (string, error) {
	// Unmarshal body request into loginGoogleRequest struct
	log.Println(`getTokenFromRequest`)
	var request loginGoogleRequest
	dec := json.NewDecoder(bodyRequest)
	dec.DisallowUnknownFields()
	err := dec.Decode(&request) // set data into 'request' struct
	if err != nil {
		return "", err
	}
	// Input validation: check if credential field is empty
	if request.Credential == "" {
		// Generate an Error
		return "", errors.New("credential field is required")
	}
	// get tokenId from request
	tokenId := request.Credential
	log.Println("tokenId:", tokenId)

	return tokenId, nil
}

func (a *AuthServer) handleLoginGoogle(w http.ResponseWriter, r *http.Request) {
	// Get tokenId from request
	tokenId, err := getTokenFromRequest(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate tokenId using Google auth library client
	isValid, email := a.isValidGoogleIdToken(tokenId)
	if !isValid {
		http.Error(w, "invalid credential", http.StatusUnauthorized)
		return
	}
	log.Println("Token is valid: ", email)

	// TODO: check if user is already registered in DB
	// If customer is not registered (TBD: return error or automatically register it)

	// If customer is already registered, generate token and send it back
	// Create custom access token from FlowApp
	token, err := a.generateToken(email)
	// Prepare response
	response := loginGoogleResponse{
		Token: token,
		Email: email,
		Role:  "customer", // retrieved from DB
	}
	res, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshalling response: %v", err.Error())
		return
	}
	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(res)
	if err != nil {
		log.Printf("Error sending response: %v", err.Error())
		return
	}
}

// handleAuthorization handles http request to verify token
func (a *AuthServer) handleAuthorization(w http.ResponseWriter, r *http.Request) {
	// Get token from header
	mytoken := r.Header.Get("Authorization")
	if mytoken == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}

	// Verify token
	userClaims, err := a.verifyFlowAppToken(mytoken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Println("Token successfully verified")
	log.Printf("Email: %v", userClaims.Email)
	log.Printf("Role: %v", userClaims.Role)

	// Struct response
	type response struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	res := response{
		Email: userClaims.Email,
		Role:  userClaims.Role,
	}
	// Marshal response
	resJson, err := json.Marshal(res)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// response to client http 200
	w.WriteHeader(http.StatusOK)

	_, err = w.Write(resJson)
	if err != nil {
		log.Printf("Error sending response to client: %v", err.Error())
		return
	}
}
