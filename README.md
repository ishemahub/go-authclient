# authclient

Drop-in JWT validator for services that consume tokens issued by the **Ishema
User Manager**. Validates RS256 access tokens **locally** against the issuer's
JWKS (cached, with key-rotation support) — no per-request call back to the auth
service.

Supports the auth service's **multi-tenant (realm) model**: one validator can
verify tokens from any tenant, discovering each realm's JWKS from the token's
`iss` and caching it per tenant.

## Install

```bash
go get github.com/ishemahub/go-authclient@latest
```

```go
import authclient "github.com/ishemahub/go-authclient"
```

> The import path is `github.com/ishemahub/go-authclient`; the package name is
> `authclient` (the alias above is optional but explicit). Runtime deps:
> `golang-jwt/jwt/v5` and, for `gin.go`, `gin-gonic/gin` (delete `gin.go` if you
> don't use Gin).

## How it fits the auth service

The Ishema User Manager signs each token with the **tenant's** key and sets
`iss = {PUBLIC_BASE_URL}/realms/{slug}` (e.g. `https://auth.ishema.rw/realms/default`).
Public keys are published at `GET {iss}/.well-known/jwks.json`. This client reads a
token's `iss`, confirms it's trusted, fetches that realm's JWKS, and verifies the
signature locally — caching one JWKS per realm.

> The `iss` the client trusts must match the auth service's `PUBLIC_BASE_URL`. Set
> that to the URL your services can actually reach.

## Two modes

### Multi-tenant (recommended) — trust an issuer prefix

One validator serves tokens from every realm. The JWKS is discovered from each
token's `iss` (`{iss}/.well-known/jwks.json`).

```go
v, err := authclient.New(authclient.Config{
    AllowedIssuers: []string{"https://auth.ishema.rw/realms/"}, // trailing slash
})
```

### Single-tenant — pin one realm

If a service only ever serves one realm, pin its exact issuer and JWKS URL.

```go
v, err := authclient.New(authclient.Config{
    JWKSURL: "https://auth.ishema.rw/realms/default/.well-known/jwks.json",
    Issuer:  "https://auth.ishema.rw/realms/default",
})
```

## Configuration (from env)

Prefer supplying config via environment variables. Configure **one** mode.

| Env var | Mode | Description |
|---------|------|-------------|
| `AUTH_ALLOWED_ISSUERS` | multi-tenant | Comma-separated trusted issuer **prefixes**, e.g. `https://auth.ishema.rw/realms/`. A token's `iss` must start with one; its JWKS is fetched from `{iss}/.well-known/jwks.json`. |
| `AUTH_JWKS_URL` | single-tenant | Full JWKS URL, e.g. `https://auth.ishema.rw/realms/default/.well-known/jwks.json` |
| `AUTH_ISSUER` | single-tenant | Expected token issuer (`iss`), e.g. `https://auth.ishema.rw/realms/default` |
| `AUTH_JWKS_MIN_REFRESH` | both (optional) | Min JWKS re-fetch interval (Go duration), default `1m` |

```go
v, err := authclient.NewFromEnv() // reads AUTH_ALLOWED_ISSUERS, or AUTH_JWKS_URL+AUTH_ISSUER
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
    _ = claims.Tenant              // the realm slug, e.g. "default", "ishema-ticket"
    _ = claims.TenantID()          // the tenant's UUID
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
// Optional extra check: restrict this service to a specific realm.
if claims.Tenant != "ishema-ticket" { /* 403 */ }
```

## Working with tenants & permissions

- The validator confirms the signature and a **trusted issuer**. If your service
  must only serve certain realms, enforce it with `claims.Tenant` / `claims.TenantID()`.
- Permissions/roles are what the auth service put in the token at mint time. Define
  your service's permissions in each tenant (`POST /realms/{slug}/permissions` +
  `/roles`, then assign) so tokens carry them.
- Roles/permissions are a snapshot; they refresh when the user re-logs-in or
  refreshes (max staleness ≈ the access-token TTL).

## Local user directory (poll-and-sync)

When another service stores a `user_id` as "who did the action", the frontend only
has a UUID. Instead of calling auth on every render, replicate the directory: keep
a local `users` table and poll the auth service's incremental feed to keep it
fresh. Then joins are local and instant, and rendering survives auth downtime.

Two things power this:

- **The `name` claim** — access tokens carry a `name` (display name). For the
  common "who did the action" case you can snapshot `claims.UserID()` +
  `claims.DisplayName()` at write time and skip the directory entirely.
- **`UserSyncer`** — polls `GET /realms/{slug}/sync` and upserts each page into a
  `UserStore` you implement. Soft-deleted users arrive as tombstones
  (`rec.Deleted() == true`) so you can remove them locally.

The poller authenticates with a **service API key** that has the `users.read`
scope (mint one in the realm). It tracks a watermark so restarts resume
incrementally.

```go
syncer, err := authclient.NewUserSyncer(authclient.UserSyncerConfig{
    BaseURL: "https://auth.ishema.rw",
    Realm:   "ishema-ticket",
    APIKey:  os.Getenv("AUTH_SYNC_API_KEY"), // service key w/ users.read scope
    Store:   &GormUserStore{db: db},
    // PageSize: 100, Interval: 30 * time.Second, // optional
})
if err != nil { log.Fatal(err) }

// Run in the background; it syncs immediately, then every Interval.
go syncer.Run(ctx, func(err error) { log.Printf("user sync: %v", err) })
```

A ready GORM `UserStore` (drop into your service, adjust the model):

```go
type DirectoryUser struct {
    ID          string    `gorm:"primaryKey"`
    Username    string
    Email       string
    FirstName   string
    LastName    string
    PhoneNumber string
    AvatarURL   string
    IsActive    bool
    UpdatedAt   time.Time `gorm:"index"`
}

type syncState struct {
    ID        int       `gorm:"primaryKey"` // single row, id=1
    Watermark time.Time
}

type GormUserStore struct{ db *gorm.DB }

func (s *GormUserStore) Upsert(ctx context.Context, users []authclient.UserRecord) error {
    return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
        for _, u := range users {
            if u.Deleted() {
                if err := tx.Delete(&DirectoryUser{}, "id = ?", u.ID).Error; err != nil {
                    return err
                }
                continue
            }
            row := DirectoryUser{
                ID: u.ID, Username: u.Username, Email: u.Email,
                FirstName: u.FirstName, LastName: u.LastName,
                PhoneNumber: u.PhoneNumber, AvatarURL: u.AvatarURL,
                IsActive: u.IsActive, UpdatedAt: u.UpdatedAt,
            }
            // Idempotent upsert; ignore an out-of-order record older than ours.
            if err := tx.Clauses(clause.OnConflict{
                Columns:   []clause.Column{{Name: "id"}},
                DoUpdates: clause.AssignmentColumns([]string{"username", "email", "first_name", "last_name", "phone_number", "avatar_url", "is_active", "updated_at"}),
                Where:     clause.Where{Exprs: []clause.Expression{gorm.Expr("directory_users.updated_at <= ?", u.UpdatedAt)}},
            }).Create(&row).Error; err != nil {
                return err
            }
        }
        return nil
    })
}

func (s *GormUserStore) Watermark(ctx context.Context) (time.Time, error) {
    var st syncState
    if err := s.db.WithContext(ctx).First(&st, 1).Error; err != nil {
        return time.Time{}, nil // first run → full backfill
    }
    return st.Watermark, nil
}

func (s *GormUserStore) SaveWatermark(ctx context.Context, ts time.Time) error {
    return s.db.WithContext(ctx).Save(&syncState{ID: 1, Watermark: ts}).Error
}
```

**Notes**
- The feed is keyset-paginated by `(updated_at, id)`; `UserSyncer` follows
  `next_cursor` until caught up, then advances the watermark.
- Upsert must be idempotent and reorder-safe — the `updated_at <= ?` guard above
  ensures a late-arriving stale record never clobbers newer data.
- Tombstones only fire for soft-deletes in auth; a *hard* delete leaves no row to
  emit, so keep deletions soft upstream (auth does).
- This is the poll-only design. If you later want push, the same `UserStore` can
  be fed by a Kafka consumer instead.

## Migrating from Keycloak

Swap your Keycloak validator for this one:

| Setting | Keycloak | Ishema User Manager |
|---------|----------|---------------------|
| JWKS URL | `…/realms/<realm>/protocol/openid-connect/certs` | `…/realms/<slug>/.well-known/jwks.json` (auto-discovered in multi-tenant mode) |
| Issuer (`iss`) | `https://kc/realms/<realm>` | `{PUBLIC_BASE_URL}/realms/<slug>` |
| Multi-realm | one issuer per realm | `AllowedIssuers: ["{PUBLIC_BASE_URL}/realms/"]` covers all |
| User id | `sub` | `sub` (unchanged) |
| Email / tenant | `email` | `email`, plus `tenant` (slug) and `tenant_id` |
| Roles | `realm_access.roles` / `resource_access.<client>.roles` | flat top-level `roles` array |
| Permissions | (usually none) | flat top-level `permissions` array |

So `claims.RealmAccess.Roles` becomes `claims.Roles`, and you gain first-class
`claims.Permissions`, `claims.Tenant`, and `claims.TenantID()`. Signature
verification, `exp`, issuer checks, and JWKS caching are handled for you.

## Notes

- Only **access** tokens are accepted (refresh tokens are rejected).
- The signing algorithm is pinned to **RS256**; `alg: none`/HS256 are rejected.
- The JWKS is cached per issuer and re-fetched automatically when an unknown `kid`
  appears (key rotation), throttled by `MinRefreshInterval` (default 1 minute).
- Set the auth service's `PUBLIC_BASE_URL` to the externally reachable base URL —
  it becomes the `iss` this client derives the JWKS URL from.
```
