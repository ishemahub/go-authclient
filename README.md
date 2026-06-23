# authclient

Drop-in JWT validator for services that consume tokens issued by the **Ishema
User Manager**. Validates RS256 access tokens **locally** against the issuer's
JWKS (cached, with key-rotation support) — no per-request call back to the auth
service.

## Install

```bash
go get github.com/ishemahub/authclient@latest
```

```go
import "github.com/ishemahub/authclient"
```

> Replace `github.com/ishemahub/authclient` with your actual repository path — it
> must match the `module` line in `go.mod`. Runtime deps: `golang-jwt/jwt/v5`
> and, for `gin.go`, `gin-gonic/gin` (delete `gin.go` if you don't use Gin).

## Configuration (from env)

Consuming services should supply config via environment variables — don't
hardcode them:

| Env var | Required | Description |
|---------|----------|-------------|
| `AUTH_JWKS_URL` | yes | Full JWKS URL, e.g. `http://user-manager/api/v1/users/.well-known/jwks.json` |
| `AUTH_ISSUER` | yes | Expected token issuer (`iss`), e.g. `ishema-user-manager` |
| `AUTH_JWKS_MIN_REFRESH` | no | Min JWKS re-fetch interval (Go duration), default `1m` |

```go
v, err := authclient.NewFromEnv() // reads AUTH_JWKS_URL, AUTH_ISSUER, ...
if err != nil {
    log.Fatal(err)
}
```

Or pass values explicitly (e.g. if you read env yourself):

```go
v, err := authclient.New(authclient.Config{
    JWKSURL: os.Getenv("AUTH_JWKS_URL"),
    Issuer:  os.Getenv("AUTH_ISSUER"),
})
if err != nil {
    log.Fatal(err)
}
```

## Usage (Gin)

```go
api := r.Group("/orders")
api.Use(v.Authenticate())                         // 401 if no/invalid token
api.GET("",  authclient.RequirePermission("orders.read"), listOrders)
api.POST("", authclient.RequireRole("Admin"),             createOrder)

func listOrders(c *gin.Context) {
    claims, _ := authclient.ClaimsFromContext(c)
    userID := claims.UserID()      // the "sub" claim
    _ = claims.Email
    _ = claims.Roles
    _ = claims.Permissions
}
```

## Usage (any framework / net/http)

```go
token, ok := authclient.BearerToken(r.Header.Get("Authorization"))
if !ok { /* 401 */ }
claims, err := v.Validate(r.Context(), token)
if err != nil { /* 401 */ }
if !claims.HasPermission("orders.read") { /* 403 */ }
```

## Migrating from Keycloak

Swap your Keycloak validator for this one and change two settings:

| Setting | Keycloak | Ishema User Manager |
|---------|----------|---------------------|
| JWKS URL | `…/realms/<realm>/protocol/openid-connect/certs` | `…/api/v1/users/.well-known/jwks.json` |
| Issuer (`iss`) | `https://kc/realms/<realm>` | `ishema-user-manager` (the `JWT_ISSUER`) |
| User id | `sub` | `sub` (unchanged) |
| Email | `email` | `email` (unchanged) |
| Roles | `realm_access.roles` / `resource_access.<client>.roles` | flat top-level `roles` array |
| Permissions | (usually none) | flat top-level `permissions` array |

So `claims.RealmAccess.Roles` becomes `claims.Roles`, and you gain a first-class
`claims.Permissions`. Everything else (signature verification, `exp`, caching the
JWKS) is handled for you.

## Notes

- Only **access** tokens are accepted (refresh tokens are rejected).
- The signing algorithm is pinned to **RS256**; `alg: none`/HS256 are rejected.
- The JWKS is cached and re-fetched automatically when an unknown `kid` appears
  (key rotation), throttled by `MinRefreshInterval` (default 1 minute).
- If the auth service runs behind a gateway with a `ROUTE_PREFIX`, point
  `JWKSURL` at the full external path (e.g. `…/api/v1/users/.well-known/jwks.json`).
