package authclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// memStore is an in-memory UserStore for tests.
type memStore struct {
	users     map[string]UserRecord
	watermark time.Time
}

func newMemStore() *memStore { return &memStore{users: map[string]UserRecord{}} }

func (m *memStore) Upsert(_ context.Context, users []UserRecord) error {
	for _, u := range users {
		if u.Deleted() {
			delete(m.users, u.ID) // tombstone → remove locally
			continue
		}
		m.users[u.ID] = u
	}
	return nil
}
func (m *memStore) Watermark(context.Context) (time.Time, error)       { return m.watermark, nil }
func (m *memStore) SaveWatermark(_ context.Context, t time.Time) error { m.watermark = t; return nil }

func TestUserSyncerPagesAndTombstones(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	// Server-side dataset, ascending UpdatedAt.
	all := []UserRecord{
		{ID: "a", FirstName: "Ann", UpdatedAt: t0.Add(1 * time.Second), IsActive: true},
		{ID: "b", FirstName: "Bob", UpdatedAt: t0.Add(2 * time.Second), IsActive: true},
		{ID: "c", FirstName: "Cid", UpdatedAt: t0.Add(3 * time.Second), IsActive: true},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "svc-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Page size 2, keyset by index encoded as the cursor.
		start := 0
		if cur := r.URL.Query().Get("cursor"); cur != "" {
			// cursor is the last returned id; resume after it.
			for i, u := range all {
				if u.ID == cur {
					start = i + 1
				}
			}
		}
		end := start + 2
		if end > len(all) {
			end = len(all)
		}
		page := all[start:end]
		body := map[string]any{
			"data": map[string]any{
				"data":     page,
				"has_more": end < len(all),
			},
			"success": true,
		}
		if end < len(all) {
			body["data"].(map[string]any)["next_cursor"] = page[len(page)-1].ID
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer srv.Close()

	store := newMemStore()
	syncer, err := NewUserSyncer(UserSyncerConfig{
		Endpoint: srv.URL, APIKey: "svc-key", Store: store, PageSize: 2,
	})
	if err != nil {
		t.Fatalf("new syncer: %v", err)
	}

	n, err := syncer.SyncOnce(context.Background())
	if err != nil {
		t.Fatalf("sync once: %v", err)
	}
	if n != 3 {
		t.Fatalf("processed = %d, want 3", n)
	}
	if len(store.users) != 3 {
		t.Fatalf("store has %d users, want 3", len(store.users))
	}
	if !store.watermark.Equal(t0.Add(3 * time.Second)) {
		t.Fatalf("watermark = %v, want %v", store.watermark, t0.Add(3*time.Second))
	}

	// Now upstream deletes "b": next feed carries a tombstone.
	del := t0.Add(10 * time.Second)
	all = []UserRecord{{ID: "b", UpdatedAt: del, DeletedAt: &del}}
	// Reset paging dataset watermark: the store's watermark makes the client ask
	// updated_since; our stub ignores it and just returns `all`, which is fine here.
	n, err = syncer.SyncOnce(context.Background())
	if err != nil {
		t.Fatalf("sync delete: %v", err)
	}
	if n != 1 {
		t.Fatalf("processed = %d, want 1", n)
	}
	if _, ok := store.users["b"]; ok {
		t.Fatal("tombstoned user b should have been removed locally")
	}
	if len(store.users) != 2 {
		t.Fatalf("store has %d users after delete, want 2", len(store.users))
	}
}

func TestUserSyncerRequiresConfig(t *testing.T) {
	if _, err := NewUserSyncer(UserSyncerConfig{APIKey: "k", Store: newMemStore()}); err == nil {
		t.Fatal("expected error without BaseURL/Realm/Endpoint")
	}
	if _, err := NewUserSyncer(UserSyncerConfig{Endpoint: "http://x", Store: newMemStore()}); err == nil {
		t.Fatal("expected error without APIKey")
	}
}
