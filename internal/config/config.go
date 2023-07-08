package config

import (
	"log"
	"os"
)

type Config struct {
	HttpAddr     string
	SecretJWTKey string
	GClientId    string
	MongoUser    string
	MongoPass    string
}

func (c *Config) init() {
	c.HttpAddr = ":" + getEnvStr("HTTP_PORT")
	c.SecretJWTKey = getEnvStr("SECRET_JWT_KEY")
	c.GClientId = "535433429806-oc8egpmgdvuot4bic0pc900q3pl3i7rv.apps.googleusercontent.com"
	c.MongoUser = getEnvStr("MONGO_USER")
	c.MongoPass = getEnvStr("MONGO_PASS")
}

func GetConfig() *Config {
	c := &Config{}
	c.init()
	return c
}

func getEnvStr(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Panicf("Error loading Config: you must set '%s' Environment Variable", key)
	}
	return value
}
