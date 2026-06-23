package authclient

import (
	"fmt"
	"os"
	"time"
)

// Environment variable names read by FromEnv / NewFromEnv.
const (
	EnvJWKSURL    = "AUTH_JWKS_URL"         // required: full JWKS URL of the auth service
	EnvIssuer     = "AUTH_ISSUER"           // required: expected token "iss" claim
	EnvMinRefresh = "AUTH_JWKS_MIN_REFRESH" // optional: min JWKS re-fetch interval, e.g. "5m"
)

// FromEnv builds a Config from environment variables so consuming services never
// hardcode them:
//
//	AUTH_JWKS_URL          (required) e.g. http://user-manager/api/v1/users/.well-known/jwks.json
//	AUTH_ISSUER            (required) e.g. ishema-user-manager
//	AUTH_JWKS_MIN_REFRESH  (optional) Go duration, default 1m
//
// It returns an error listing any missing required variables.
func FromEnv() (Config, error) {
	cfg := Config{
		JWKSURL: os.Getenv(EnvJWKSURL),
		Issuer:  os.Getenv(EnvIssuer),
	}

	var missing []string
	if cfg.JWKSURL == "" {
		missing = append(missing, EnvJWKSURL)
	}
	if cfg.Issuer == "" {
		missing = append(missing, EnvIssuer)
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("authclient: missing required environment variables: %v", missing)
	}

	if raw := os.Getenv(EnvMinRefresh); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("authclient: invalid %s %q: %w", EnvMinRefresh, raw, err)
		}
		cfg.MinRefreshInterval = d
	}
	return cfg, nil
}

// NewFromEnv builds a Validator using configuration read from the environment.
// It is shorthand for New(FromEnv()).
func NewFromEnv() (*Validator, error) {
	cfg, err := FromEnv()
	if err != nil {
		return nil, err
	}
	return New(cfg)
}
