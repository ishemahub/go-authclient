// Package authclient is a drop-in JWT validator for services that consume tokens
// issued by the Ishema User Manager. It fetches the issuer's JWKS, caches the
// public keys (handling key rotation by `kid`), and validates RS256 access
// tokens locally — no network call per request.
//
// It is framework-agnostic; Gin middleware lives in gin.go (delete it if you
// don't use Gin). Only github.com/golang-jwt/jwt/v5 is required by this file.
//
// # Migrating from Keycloak
//
// Replace your Keycloak validator with one of these and update two values:
//
//	v, _ := authclient.New(authclient.Config{
//	    // Keycloak was: https://kc/realms/<realm>/protocol/openid-connect/certs
//	    JWKSURL: "https://gateway/api/v1/users/.well-known/jwks.json",
//	    // Keycloak was: https://kc/realms/<realm>
//	    Issuer:  "ishema-user-manager", // == the service's JWT_ISSUER
//	})
//
// Claims differ from Keycloak: roles are a flat top-level "roles" array (not
// realm_access.roles), and there is a flat "permissions" array. The user id is
// still "sub" and the email is still "email".
package authclient

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Config configures a Validator.
type Config struct {
	// JWKSURL is the full URL of the issuer's JWKS document, e.g.
	// "https://gateway/api/v1/users/.well-known/jwks.json".
	JWKSURL string
	// Issuer must equal the issuing service's JWT_ISSUER (the token "iss" claim).
	Issuer string
	// MinRefreshInterval throttles JWKS re-fetches when an unknown kid is seen
	// (defends against refresh storms). Default 1 minute.
	MinRefreshInterval time.Duration
	// HTTPClient is used to fetch the JWKS. Default: 10s timeout.
	HTTPClient *http.Client
}

// Claims is the validated token payload.
type Claims struct {
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	TokenType   string   `json:"token_type"`
	jwt.RegisteredClaims
}

// UserID returns the authenticated user's id (the "sub" claim).
func (c *Claims) UserID() string { return c.Subject }

// HasRole reports whether the principal holds the named role.
func (c *Claims) HasRole(role string) bool { return contains(c.Roles, role) }

// HasPermission reports whether the principal holds the named permission.
func (c *Claims) HasPermission(perm string) bool { return contains(c.Permissions, perm) }

// Validator validates tokens against a cached JWKS.
type Validator struct {
	cfg    Config
	client *http.Client

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	lastFetch time.Time
}

// New builds a Validator and performs a best-effort initial JWKS fetch (a
// failure here is non-fatal; keys are re-fetched lazily on first use).
func New(cfg Config) (*Validator, error) {
	if cfg.JWKSURL == "" {
		return nil, errors.New("authclient: JWKSURL is required")
	}
	if cfg.Issuer == "" {
		return nil, errors.New("authclient: Issuer is required")
	}
	if cfg.MinRefreshInterval == 0 {
		cfg.MinRefreshInterval = time.Minute
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	v := &Validator{cfg: cfg, client: client, keys: map[string]*rsa.PublicKey{}}
	_ = v.refresh(context.Background()) // best-effort warm-up
	return v, nil
}

// Validate parses and verifies a token string and returns its claims. It checks
// the RS256 signature, the issuer, expiry, and that it is an access token.
func (v *Validator) Validate(ctx context.Context, tokenString string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("authclient: unexpected signing method %q", t.Method.Alg())
		}
		kid, _ := t.Header["kid"].(string)
		return v.keyByID(ctx, kid)
	}, jwt.WithIssuer(v.cfg.Issuer), jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		return nil, err
	}
	if claims.TokenType != "" && claims.TokenType != "access" {
		return nil, errors.New("authclient: not an access token")
	}
	return claims, nil
}

func (v *Validator) keyByID(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	key, ok := v.keys[kid]
	v.mu.RUnlock()
	if ok {
		return key, nil
	}
	// Unknown kid — the issuer may have rotated keys. Refresh and retry.
	if err := v.refresh(ctx); err != nil {
		return nil, err
	}
	v.mu.RLock()
	key, ok = v.keys[kid]
	v.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("authclient: no signing key for kid %q", kid)
	}
	return key, nil
}

func (v *Validator) refresh(ctx context.Context) error {
	v.mu.RLock()
	cooling := len(v.keys) > 0 && time.Since(v.lastFetch) < v.cfg.MinRefreshInterval
	v.mu.RUnlock()
	if cooling {
		return nil
	}

	keys, err := v.fetch(ctx)
	if err != nil {
		return err
	}
	v.mu.Lock()
	v.keys = keys
	v.lastFetch = time.Now()
	v.mu.Unlock()
	return nil
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (v *Validator) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authclient: JWKS fetch returned %d", resp.StatusCode)
	}

	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}

	out := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := parseRSAPublicKey(k)
		if err != nil {
			continue
		}
		out[k.Kid] = pub
	}
	if len(out) == 0 {
		return nil, errors.New("authclient: JWKS contained no usable RSA keys")
	}
	return out, nil
}

func parseRSAPublicKey(k jwk) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// BearerToken extracts the token from an "Authorization: Bearer <token>" header
// value. Useful when wiring the validator into a framework this package doesn't
// ship middleware for.
func BearerToken(authorizationHeader string) (string, bool) {
	const prefix = "Bearer "
	if len(authorizationHeader) > len(prefix) && strings.EqualFold(authorizationHeader[:len(prefix)], prefix) {
		return authorizationHeader[len(prefix):], true
	}
	return "", false
}
