package config

import (
	"fmt"
	"os"
)

type Config struct {
	HttpAddr     string
	SecretJWTKey string
	GClientId    string
}

func (c *Config) init() {
	c.HttpAddr = ":" + getEnvStr("HTTP_PORT")
	c.SecretJWTKey = getEnvStr("SECRET_JWT_KEY")
	c.GClientId = "535433429806-oc8egpmgdvuot4bic0pc900q3pl3i7rv.apps.googleusercontent.com"
}

func GetConfig() *Config {
	c := &Config{}
	c.init()
	return c
}

func getEnvStr(key string) string {
	value := os.Getenv(key)
	if value == "" {
		panic(fmt.Sprintf("env var loading error: %s", key))
	}
	return value
}
