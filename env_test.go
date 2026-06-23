package authclient

import (
	"testing"
	"time"
)

func TestFromEnv(t *testing.T) {
	t.Setenv(EnvJWKSURL, "http://svc/api/v1/users/.well-known/jwks.json")
	t.Setenv(EnvIssuer, "ishema-user-manager")
	t.Setenv(EnvMinRefresh, "5m")

	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.JWKSURL == "" || cfg.Issuer != "ishema-user-manager" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if cfg.MinRefreshInterval != 5*time.Minute {
		t.Errorf("MinRefreshInterval = %v, want 5m", cfg.MinRefreshInterval)
	}
}

func TestFromEnvMissingRequired(t *testing.T) {
	t.Setenv(EnvJWKSURL, "")
	t.Setenv(EnvIssuer, "")
	if _, err := FromEnv(); err == nil {
		t.Fatal("expected error when required env vars are missing")
	}
}

func TestFromEnvInvalidDuration(t *testing.T) {
	t.Setenv(EnvJWKSURL, "http://svc/jwks")
	t.Setenv(EnvIssuer, "iss")
	t.Setenv(EnvMinRefresh, "not-a-duration")
	if _, err := FromEnv(); err == nil {
		t.Fatal("expected error for invalid duration")
	}
}
