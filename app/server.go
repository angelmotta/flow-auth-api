package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/angelmotta/flow-auth-api/internal/authdb"
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
	Router       *chi.Mux
	Config       *config.Config
	AuthDBClient *authdb.Authdb
}

type MyCustomClaims struct {
	Email string `json:"email"`
	Role  string `json:"role"`
	jwt.RegisteredClaims
}

type loginGoogleRequest struct {
	Credential string `json:"credential"`
}

type loginResponse struct {
	Token string `json:"token"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func NewAuthServer() *AuthServer {
	log.Println("Setting AuthServer...")
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
		//AuthDBClient not yet initialized
	}
	// Setup DB connection and assign it to AuthServer
	mongoUser := a.Config.MongoUser
	mongoPass := a.Config.MongoPass
	mongoHost := a.Config.MongoHost
	dbConn := authdb.New(mongoUser, mongoPass, mongoHost)
	a.AuthDBClient = dbConn
	// Register routes into AuthServer
	a.routes()
	log.Println("AuthServer configured successfully.")
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
		errRes := errorResponse{
			Error: err.Error(),
		}
		sendJsonResponse(w, errRes, http.StatusBadRequest)
		return
	}

	// Validate tokenId using Google auth library client
	isValid, email := a.isValidGoogleIdToken(tokenId)
	if !isValid {
		errRes := errorResponse{
			Error: "invalid credential",
		}
		sendJsonResponse(w, errRes, http.StatusUnauthorized)
		return
	}
	log.Println("Token is valid: ", email)

	// Check user in DB
	// If customer is not registered respond with error (Go to register flow)
	userResult, err := a.AuthDBClient.GetUser(email)
	if err != nil {
		errRes := errorResponse{
			Error: "Servicio no disponible",
		}
		sendJsonResponse(w, errRes, http.StatusInternalServerError)
		return
	}
	if userResult == nil {
		errRes := errorResponse{
			Error: "Usuario no registrado",
		}
		sendJsonResponse(w, errRes, http.StatusNotFound)
		return
	}

	// If user exists, generate token
	// Create custom access token from FlowApp
	token, err := a.generateToken(email)
	// Prepare response
	response := loginResponse{
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

// handleAuthorization handles http request to verify FlowApp token
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

func (a *AuthServer) handleSignup(w http.ResponseWriter, r *http.Request) {
	// Get tokenId from request
	tokenId, err := getTokenFromRequest(r.Body)
	if err != nil {
		errRes := errorResponse{
			Error: err.Error(),
		}
		sendJsonResponse(w, errRes, http.StatusBadRequest)
		return
	}

	// Validate tokenId using Google auth library client
	isValid, email := a.isValidGoogleIdToken(tokenId)
	if !isValid {
		errRes := errorResponse{
			Error: "invalid credential",
		}
		sendJsonResponse(w, errRes, http.StatusUnauthorized)
		return
	}
	log.Println("Token is valid: ", email)

	// Check user in DB
	// Validate if customer is already registered (respond error message)
	userResult, err := a.AuthDBClient.GetUser(email)
	if err != nil {
		errRes := errorResponse{
			Error: "Servicio no disponible",
		}
		sendJsonResponse(w, errRes, http.StatusInternalServerError)
		return
	}
	if userResult != nil {
		errRes := errorResponse{
			Error: "Usuario ya registrado",
		}
		sendJsonResponse(w, errRes, http.StatusConflict)
		return
	}
	// Prepare response to user
	//token, err := a.generateToken(email)
	//response := loginResponse{
	//	Token: token,
	//	Email: email,
	//	Role:  "customer", // retrieved from DB
	//}
	sendJsonResponse(w, `{}`, http.StatusOK)
}

// handleSignupUser handles http request to register a new customer
func (a *AuthServer) handleSignupUser(w http.ResponseWriter, r *http.Request) {
	// Get tokenId from authorization header
	tokenId := r.Header.Get("Authorization")
	if tokenId == "" {
		errRes := errorResponse{
			Error: "token is required",
		}
		sendJsonResponse(w, errRes, http.StatusBadRequest)
		return
	}

	// Validate tokenId using Google auth library client
	isValid, email := a.isValidGoogleIdToken(tokenId)
	if !isValid {
		errRes := errorResponse{
			Error: "invalid credential",
		}
		sendJsonResponse(w, errRes, http.StatusUnauthorized)
		return
	}
	log.Println("Google IdToken is valid for: ", email)
	// Only for test
	/*
		email := r.Header.Get("email")
		if email == "" {
			errRes := errorResponse{
				Error: "email field in header is required",
			}
			sendJsonResponse(w, errRes, http.StatusBadRequest)
			return
		}
	*/
	// Validate if email is available to use in DB
	userResult, err := a.AuthDBClient.GetUser(email)
	if err != nil {
		errRes := errorResponse{
			Error: "Servicio no disponible",
		}
		sendJsonResponse(w, errRes, http.StatusInternalServerError)
		return
	}
	if userResult != nil {
		errRes := errorResponse{
			Error: "Usuario ya esta registrado",
		}
		sendJsonResponse(w, errRes, http.StatusConflict)
		return
	}
	log.Printf("Email %v is available to use", email)
	// Get request from body and unmarshall into User struct
	var userRequest authdb.UserInfo
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err = dec.Decode(&userRequest)
	if err != nil {
		log.Println(err.Error())
		errRes := errorResponse{
			Error: "invalid request",
		}
		sendJsonResponse(w, errRes, http.StatusBadRequest)
		return
	}
	// Validate userRequest struct
	log.Printf("Received UserInfo: %v", userRequest)
	err = validateSignupRequest(userRequest)
	if err != nil {
		errRes := errorResponse{
			Error: err.Error(),
		}
		sendJsonResponse(w, errRes, http.StatusBadRequest)
		return
	}

	// Register new user in DB
	u := authdb.User{
		Email:    email,
		Role:     "customer",
		UserInfo: userRequest,
	}
	log.Printf("Registering new user in DB: %v", u)
	err = a.AuthDBClient.CreateUser(u) // insert new userRequest in DB
	if err != nil {
		errRes := errorResponse{
			Error: "Servicio no disponible",
		}
		sendJsonResponse(w, errRes, http.StatusInternalServerError)
		return
	}
	// Prepare response to userRequest
	token, err := a.generateToken(email)
	response := loginResponse{
		Token: token,
		Email: email,
		Role:  "customer", // retrieved from DB
	}
	sendJsonResponse(w, response, http.StatusOK)
}

func sendJsonResponse(w http.ResponseWriter, response interface{}, statusCode int) {
	responseJson, err := json.Marshal(response)
	if err != nil {
		// Marshal error (internal server error)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Set headers
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	// Write Json response
	_, err = w.Write(responseJson)
	if err != nil {
		log.Printf("Error sending response: %v", err.Error())
		return
	}
}

func validateSignupRequest(user authdb.UserInfo) error {
	// create null Error
	var err error
	if user.Dni == "" {
		err = errors.New("DNI is required")
	} else if user.Nombre == "" {
		err = errors.New("Nombre is required")
	} else if user.Apellidop == "" {
		err = errors.New("Apellidop is required")
	} else if user.Apellidom == "" {
		err = errors.New("Apellidom is required")
	} else if user.Direccion == "" {
		err = errors.New("Direccion is required")
	}
	return err
}
