package authclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// UserRecord mirrors one row from the auth service's /users/sync feed. A record
// with Deleted() == true is a tombstone — the user was removed upstream and
// should be deleted or deactivated in the local directory.
type UserRecord struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	Email       string     `json:"email"`
	FirstName   string     `json:"first_name"`
	LastName    string     `json:"last_name"`
	PhoneNumber string     `json:"phone_number"`
	AvatarURL   string     `json:"avatar_url"`
	IsActive    bool       `json:"is_active"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `json:"deleted_at"`
}

// Deleted reports whether this record is a tombstone (removed upstream).
func (u UserRecord) Deleted() bool { return u.DeletedAt != nil }

// DisplayName returns "First Last" when set, else the email, else the username.
func (u UserRecord) DisplayName() string {
	name := u.FirstName
	if u.LastName != "" {
		if name != "" {
			name += " "
		}
		name += u.LastName
	}
	if name != "" {
		return name
	}
	if u.Email != "" {
		return u.Email
	}
	return u.Username
}

// UserStore is the local user directory the syncer writes into. Implement it over
// your database (a `users` table keyed by the auth user id).
//
// Upsert receives a batch in ascending UpdatedAt order and MUST be idempotent:
// insert-or-update by ID, and for a record where Deleted() is true, delete or
// deactivate the local row. To stay correct under reordering, ignore a record
// whose UpdatedAt is older than the row you already have.
//
// Watermark/SaveWatermark persist the sync position (the max UpdatedAt processed)
// so a restart resumes incrementally instead of re-scanning everything. Return a
// zero time from Watermark on first run to request a full backfill.
type UserStore interface {
	Upsert(ctx context.Context, users []UserRecord) error
	Watermark(ctx context.Context) (time.Time, error)
	SaveWatermark(ctx context.Context, ts time.Time) error
}

// UserSyncerConfig configures a UserSyncer.
type UserSyncerConfig struct {
	// BaseURL is the auth service origin, e.g. "https://auth.ishema.rw". Combined
	// with Realm to form {BaseURL}/realms/{Realm}/sync. Ignored if Endpoint is set.
	BaseURL string
	// Realm is the tenant slug whose directory to replicate, e.g. "ishema-ticket".
	Realm string
	// Endpoint optionally overrides the full sync URL (use when your deployment
	// mounts the API under a path prefix).
	Endpoint string

	// APIKey is a service API key with the users.read scope, sent as X-API-Key.
	APIKey string

	// Store is the local directory to upsert into (required).
	Store UserStore

	// PageSize is the sync page size (default 100, max 500 server-side).
	PageSize int
	// Interval is the poll period used by Run (default 30s).
	Interval time.Duration

	HTTPClient *http.Client
}

// UserSyncer polls the auth service's incremental user feed and upserts each page
// into a local UserStore. It is the poll-and-upsert half of the "local user
// directory" pattern: every service keeps its own users table, kept fresh here.
type UserSyncer struct {
	endpoint string
	apiKey   string
	store    UserStore
	pageSize int
	interval time.Duration
	client   *http.Client
}

// NewUserSyncer builds a UserSyncer. It returns an error if required fields are
// missing.
func NewUserSyncer(cfg UserSyncerConfig) (*UserSyncer, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("authclient: UserSyncer requires a Store")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("authclient: UserSyncer requires an APIKey")
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		if cfg.BaseURL == "" || cfg.Realm == "" {
			return nil, fmt.Errorf("authclient: UserSyncer requires BaseURL+Realm or Endpoint")
		}
		endpoint = strings.TrimRight(cfg.BaseURL, "/") + "/realms/" + url.PathEscape(cfg.Realm) + "/sync"
	}
	pageSize := cfg.PageSize
	if pageSize <= 0 {
		pageSize = 100
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &UserSyncer{
		endpoint: endpoint,
		apiKey:   cfg.APIKey,
		store:    cfg.Store,
		pageSize: pageSize,
		interval: interval,
		client:   client,
	}, nil
}

// syncPage is the server's page payload (inside the response envelope's "data").
type syncPage struct {
	Data       []UserRecord `json:"data"`
	NextCursor string       `json:"next_cursor"`
	HasMore    bool         `json:"has_more"`
}

// envelope is the auth service's standard response wrapper.
type envelope struct {
	Data    json.RawMessage `json:"data"`
	Success bool            `json:"success"`
	Message string          `json:"message"`
}

// SyncOnce polls from the stored watermark, upserting every page until caught up,
// then advances the watermark to the newest UpdatedAt seen. It returns the number
// of records processed. Safe to call repeatedly; each call resumes where the last
// left off.
func (s *UserSyncer) SyncOnce(ctx context.Context) (int, error) {
	since, err := s.store.Watermark(ctx)
	if err != nil {
		return 0, fmt.Errorf("authclient: read watermark: %w", err)
	}

	processed := 0
	maxSeen := since
	cursor := ""
	for {
		page, err := s.fetch(ctx, since, cursor)
		if err != nil {
			return processed, err
		}
		if len(page.Data) > 0 {
			if err := s.store.Upsert(ctx, page.Data); err != nil {
				return processed, fmt.Errorf("authclient: upsert: %w", err)
			}
			processed += len(page.Data)
			for _, u := range page.Data {
				if u.UpdatedAt.After(maxSeen) {
					maxSeen = u.UpdatedAt
				}
			}
		}
		if !page.HasMore || page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}

	if maxSeen.After(since) {
		if err := s.store.SaveWatermark(ctx, maxSeen); err != nil {
			return processed, fmt.Errorf("authclient: save watermark: %w", err)
		}
	}
	return processed, nil
}

// Run calls SyncOnce every Interval until ctx is cancelled. A failed poll is
// returned only if ctx is done; otherwise the error is passed to onError (if set)
// and the loop continues, so a transient auth outage doesn't kill the syncer.
func (s *UserSyncer) Run(ctx context.Context, onError func(error)) error {
	// Sync immediately, then on a ticker.
	if _, err := s.SyncOnce(ctx); err != nil && onError != nil {
		onError(err)
	}
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if _, err := s.SyncOnce(ctx); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}

func (s *UserSyncer) fetch(ctx context.Context, since time.Time, cursor string) (*syncPage, error) {
	q := url.Values{}
	if !since.IsZero() {
		q.Set("updated_since", since.UTC().Format(time.RFC3339Nano))
	}
	q.Set("limit", strconv.Itoa(s.pageSize))
	if cursor != "" {
		q.Set("cursor", cursor)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", s.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authclient: sync request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authclient: sync returned %s", resp.Status)
	}

	var env envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return nil, fmt.Errorf("authclient: decode envelope: %w", err)
	}
	var page syncPage
	if err := json.Unmarshal(env.Data, &page); err != nil {
		return nil, fmt.Errorf("authclient: decode page: %w", err)
	}
	return &page, nil
}
