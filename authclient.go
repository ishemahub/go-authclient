// Package authclient is a drop-in JWT validator for services that consume tokens
// issued by the Ishema User Manager. It validates RS256 access tokens locally
// against the issuer's JWKS — no per-request call back.
//
// It supports two modes:
//
//   - Single-issuer: set JWKSURL + Issuer (one realm).
//   - Multi-issuer (multi-tenant): set AllowedIssuers to trusted issuer prefixes.
//     The JWKS is discovered from the token's `iss`
//     (`{iss}/.well-known/jwks.json`) and cached per issuer. This is how
//     per-tenant tokens (iss = https://auth.ishema.rw/realms/{tenant}) validate.
//
// Only github.com/golang-jwt/jwt/v5 is required by this file.
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

// Config configures a Validator. Provide either single-issuer (JWKSURL+Issuer)
// or multi-issuer (AllowedIssuers) settings.
type Config struct {
	// Single-issuer mode.
	JWKSURL string
	Issuer  string

	// Multi-issuer mode: trusted issuer prefixes, e.g.
	// "https://auth.ishema.rw/realms/". A token's `iss` must start with one of
	// these; its JWKS is fetched from `{iss}/.well-known/jwks.json`.
	AllowedIssuers []string

	MinRefreshInterval time.Duration
	HTTPClient         *http.Client
}

// Claims is the validated token payload.
type Claims struct {
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	TokenType   string   `json:"token_type"`
	Tenant      string   `json:"tenant"`
	TenantIDVal string   `json:"tenant_id"`
	jwt.RegisteredClaims
}

// UserID returns the authenticated user's id (the "sub" claim).
func (c *Claims) UserID() string { return c.Subject }

// TenantID returns the tenant/realm id claim (empty for single-tenant issuers).
func (c *Claims) TenantID() string { return c.TenantIDVal }

// HasRole reports whether the principal holds the named role.
func (c *Claims) HasRole(role string) bool { return contains(c.Roles, role) }

// HasPermission reports whether the principal holds the named permission.
func (c *Claims) HasPermission(perm string) bool { return contains(c.Permissions, perm) }

// Validator validates tokens against cached JWKS documents (one per issuer).
type Validator struct {
	cfg    Config
	client *http.Client

	mu        sync.RWMutex
	keys      map[string]map[string]*rsa.PublicKey // jwksURL -> kid -> key
	lastFetch map[string]time.Time                 // jwksURL -> last fetch
}

// New builds a Validator.
func New(cfg Config) (*Validator, error) {
	if cfg.JWKSURL == "" && len(cfg.AllowedIssuers) == 0 {
		return nil, errors.New("authclient: set JWKSURL (single-issuer) or AllowedIssuers (multi-issuer)")
	}
	if cfg.JWKSURL != "" && cfg.Issuer == "" && len(cfg.AllowedIssuers) == 0 {
		return nil, errors.New("authclient: Issuer is required in single-issuer mode")
	}
	if cfg.MinRefreshInterval == 0 {
		cfg.MinRefreshInterval = time.Minute
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	v := &Validator{
		cfg: cfg, client: client,
		keys:      map[string]map[string]*rsa.PublicKey{},
		lastFetch: map[string]time.Time{},
	}
	if cfg.JWKSURL != "" {
		_ = v.refresh(context.Background(), cfg.JWKSURL) // best-effort warm-up
	}
	return v, nil
}

// Validate parses and verifies a token and returns its claims.
func (v *Validator) Validate(ctx context.Context, tokenString string) (*Claims, error) {
	jwksURL, expectedIssuer, err := v.resolveIssuer(tokenString)
	if err != nil {
		return nil, err
	}

	claims := &Claims{}
	_, err = jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("authclient: unexpected signing method %q", t.Method.Alg())
		}
		kid, _ := t.Header["kid"].(string)
		return v.keyByID(ctx, jwksURL, kid)
	}, jwt.WithIssuer(expectedIssuer), jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		return nil, err
	}
	if claims.TokenType != "" && claims.TokenType != "access" {
		return nil, errors.New("authclient: not an access token")
	}
	return claims, nil
}

// resolveIssuer decides which JWKS to use and which issuer to require.
func (v *Validator) resolveIssuer(tokenString string) (jwksURL, expectedIssuer string, err error) {
	if len(v.cfg.AllowedIssuers) == 0 {
		return v.cfg.JWKSURL, v.cfg.Issuer, nil // single-issuer mode
	}
	iss, err := unverifiedIssuer(tokenString)
	if err != nil {
		return "", "", err
	}
	if !v.issuerAllowed(iss) {
		return "", "", fmt.Errorf("authclient: issuer %q is not allowed", iss)
	}
	return strings.TrimRight(iss, "/") + "/.well-known/jwks.json", iss, nil
}

func (v *Validator) issuerAllowed(iss string) bool {
	for _, p := range v.cfg.AllowedIssuers {
		if iss == p || strings.HasPrefix(iss, p) {
			return true
		}
	}
	return false
}

// unverifiedIssuer reads the `iss` claim without verifying the signature (only
// to pick the correct JWKS; the signature is verified afterwards).
func unverifiedIssuer(tokenString string) (string, error) {
	mc := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(tokenString, mc)
	if err != nil {
		return "", err
	}
	iss, _ := mc["iss"].(string)
	if iss == "" {
		return "", errors.New("authclient: token has no issuer")
	}
	return iss, nil
}

func (v *Validator) keyByID(ctx context.Context, jwksURL, kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	key := v.keys[jwksURL][kid]
	v.mu.RUnlock()
	if key != nil {
		return key, nil
	}
	if err := v.refresh(ctx, jwksURL); err != nil {
		return nil, err
	}
	v.mu.RLock()
	key = v.keys[jwksURL][kid]
	v.mu.RUnlock()
	if key == nil {
		return nil, fmt.Errorf("authclient: no signing key for kid %q", kid)
	}
	return key, nil
}

func (v *Validator) refresh(ctx context.Context, jwksURL string) error {
	v.mu.RLock()
	cooling := len(v.keys[jwksURL]) > 0 && time.Since(v.lastFetch[jwksURL]) < v.cfg.MinRefreshInterval
	v.mu.RUnlock()
	if cooling {
		return nil
	}
	set, err := v.fetch(ctx, jwksURL)
	if err != nil {
		return err
	}
	v.mu.Lock()
	v.keys[jwksURL] = set
	v.lastFetch[jwksURL] = time.Now()
	v.mu.Unlock()
	return nil
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (v *Validator) fetch(ctx context.Context, jwksURL string) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
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
		if pub, err := parseRSAPublicKey(k); err == nil {
			out[k.Kid] = pub
		}
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

// BearerToken extracts the token from an "Authorization: Bearer <token>" header.
func BearerToken(authorizationHeader string) (string, bool) {
	const prefix = "Bearer "
	if len(authorizationHeader) > len(prefix) && strings.EqualFold(authorizationHeader[:len(prefix)], prefix) {
		return authorizationHeader[len(prefix):], true
	}
	return "", false
}
