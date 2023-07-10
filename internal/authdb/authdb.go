package authdb

import (
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"log"
	"time"
)

type Authdb struct {
	mongoCli *mongo.Client
}

type User struct {
	Email     string `json:"email"`
	Dni       string `json:"dni"`
	Nombre    string `json:"nombre"`
	Apellidop string `json:"apellidop"`
	Apellidom string `json:"apellidom"`
	Direccion string `json:"direccion"`
	Role      string `json:"role,omitempty"`
}

//type User struct {
//	Email string
//	Dni   string
//}

func New(dbUser, dbPass string) *Authdb {
	// Get client MongoDB
	uriMongoDB := "mongodb+srv://" + dbUser + ":" + dbPass + "@cluster0.jqgmumw.mongodb.net/?retryWrites=true&w=majority"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uriMongoDB))
	if err != nil {
		log.Panicf("Something went wrong connecting to MongoDB: %v", err)
	}
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		log.Panicf("Ping went wrong connecting to MongoDB: %v", err)
	}
	log.Println("Connected to MongoDB!")
	return &Authdb{
		mongoCli: client,
	}
}

// GetUser retrieve a user document from MongoDB
func (a *Authdb) GetUser(email string) (bson.M, error) {
	var result bson.M
	collection := a.mongoCli.Database("usersdb").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := collection.FindOne(ctx, bson.D{{"email", email}}).Decode(&result)
	if err == mongo.ErrNoDocuments {
		log.Println("No documents found")
		return nil, nil // No documents found
	}
	if err != nil {
		return nil, err
	}
	//jsonData, err := json.MarshalIndent(result, "", "  ")
	log.Println("Found a single document:")
	log.Println(result)
	return result, nil
}

// CreateUser create a user document in MongoDB
func (a *Authdb) CreateUser(newUser User) error {
	//user := User{Email: email}
	collection := a.mongoCli.Database("usersdb").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := collection.InsertOne(ctx, newUser)
	if err != nil {
		log.Printf("Error creating user: %v", err)
		return err
	}
	log.Printf("User created successfully with id: %v", res.InsertedID)
	log.Println(res)
	return nil
}
