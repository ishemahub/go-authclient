package authclient

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testKID = "test-kid"

// newIssuer returns a signing key and a JWKS server mimicking the Ishema User
// Manager, so this module's tests stand alone (no dependency on that repo).
func newIssuer(t *testing.T) (*rsa.PrivateKey, *httptest.Server) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pub := priv.PublicKey
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": testKID,
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	}))
	t.Cleanup(srv.Close)
	return priv, srv
}

func sign(t *testing.T, priv *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = testKID
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func accessClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss":         "ishema-user-manager",
		"sub":         "user-123",
		"email":       "a@b.com",
		"roles":       []string{"Admin"},
		"permissions": []string{"users.read"},
		"token_type":  "access",
		"exp":         time.Now().Add(time.Hour).Unix(),
		"iat":         time.Now().Unix(),
	}
}

func TestValidateIssuedToken(t *testing.T) {
	priv, srv := newIssuer(t)
	v, err := New(Config{JWKSURL: srv.URL, Issuer: "ishema-user-manager"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	claims, err := v.Validate(context.Background(), sign(t, priv, accessClaims()))
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.UserID() != "user-123" || claims.Email != "a@b.com" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if !claims.HasRole("Admin") || claims.HasRole("User") {
		t.Errorf("roles wrong: %v", claims.Roles)
	}
	if !claims.HasPermission("users.read") {
		t.Errorf("permissions wrong: %v", claims.Permissions)
	}
}

func TestRejectsWrongIssuer(t *testing.T) {
	priv, srv := newIssuer(t)
	v, _ := New(Config{JWKSURL: srv.URL, Issuer: "some-other-issuer"})
	if _, err := v.Validate(context.Background(), sign(t, priv, accessClaims())); err == nil {
		t.Fatal("expected failure for wrong issuer")
	}
}

func TestRejectsRefreshToken(t *testing.T) {
	priv, srv := newIssuer(t)
	v, _ := New(Config{JWKSURL: srv.URL, Issuer: "ishema-user-manager"})
	c := accessClaims()
	c["token_type"] = "refresh"
	if _, err := v.Validate(context.Background(), sign(t, priv, c)); err == nil {
		t.Fatal("expected refresh token to be rejected")
	}
}

func TestRejectsExpired(t *testing.T) {
	priv, srv := newIssuer(t)
	v, _ := New(Config{JWKSURL: srv.URL, Issuer: "ishema-user-manager"})
	c := accessClaims()
	c["exp"] = time.Now().Add(-time.Hour).Unix()
	if _, err := v.Validate(context.Background(), sign(t, priv, c)); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestMultiIssuerDiscovery(t *testing.T) {
	priv, srv := newIssuer(t) // serves the JWKS at any path
	iss := srv.URL + "/realms/acme"

	v, err := New(Config{AllowedIssuers: []string{srv.URL + "/realms/"}})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	c := accessClaims()
	c["iss"] = iss
	c["tenant_id"] = "tenant-1"
	c["tenant"] = "acme"

	claims, err := v.Validate(context.Background(), sign(t, priv, c))
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.TenantID() != "tenant-1" || claims.Tenant != "acme" {
		t.Fatalf("tenant claims not parsed: %+v", claims)
	}

	// A token from an issuer outside the allowlist is rejected before any fetch.
	c["iss"] = "https://evil.example/realms/acme"
	if _, err := v.Validate(context.Background(), sign(t, priv, c)); err == nil {
		t.Fatal("expected rejection for issuer outside the allowlist")
	}
}
