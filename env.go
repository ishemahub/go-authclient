package authclient

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Environment variable names read by FromEnv / NewFromEnv.
const (
	EnvJWKSURL        = "AUTH_JWKS_URL"         // single-issuer: full JWKS URL
	EnvIssuer         = "AUTH_ISSUER"           // single-issuer: expected "iss"
	EnvAllowedIssuers = "AUTH_ALLOWED_ISSUERS"  // multi-issuer: comma-separated trusted issuer prefixes
	EnvMinRefresh     = "AUTH_JWKS_MIN_REFRESH" // optional: min JWKS re-fetch interval, e.g. "5m"
)

// FromEnv builds a Config from environment variables. Configure ONE mode:
//
//	Single-issuer:
//	  AUTH_JWKS_URL   e.g. https://auth.ishema.rw/realms/default/.well-known/jwks.json
//	  AUTH_ISSUER     e.g. https://auth.ishema.rw/realms/default
//
//	Multi-issuer (multi-tenant):
//	  AUTH_ALLOWED_ISSUERS   e.g. https://auth.ishema.rw/realms/
//	  (JWKS is discovered from each token's iss)
//
//	Optional (both modes):
//	  AUTH_JWKS_MIN_REFRESH  Go duration, default 1m
func FromEnv() (Config, error) {
	cfg := Config{
		JWKSURL: os.Getenv(EnvJWKSURL),
		Issuer:  os.Getenv(EnvIssuer),
	}
	if raw := os.Getenv(EnvAllowedIssuers); raw != "" {
		for _, p := range strings.Split(raw, ",") {
			if t := strings.TrimSpace(p); t != "" {
				cfg.AllowedIssuers = append(cfg.AllowedIssuers, t)
			}
		}
	}

	if len(cfg.AllowedIssuers) == 0 {
		// Single-issuer mode requires both.
		var missing []string
		if cfg.JWKSURL == "" {
			missing = append(missing, EnvJWKSURL)
		}
		if cfg.Issuer == "" {
			missing = append(missing, EnvIssuer)
		}
		if len(missing) > 0 {
			return Config{}, fmt.Errorf("authclient: set %s, or %s+%s (missing: %v)",
				EnvAllowedIssuers, EnvJWKSURL, EnvIssuer, missing)
		}
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
func NewFromEnv() (*Validator, error) {
	cfg, err := FromEnv()
	if err != nil {
		return nil, err
	}
	return New(cfg)
}
