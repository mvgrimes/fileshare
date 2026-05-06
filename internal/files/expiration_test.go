package files

import (
	"database/sql"
	"testing"
	"time"

	"fileshare/internal/db"
)

func TestIsFileExpired(t *testing.T) {
	now := time.Date(2026, 5, 2, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		expires string
		valid   bool
		want    bool
	}{
		{name: "no expiry", valid: false, want: false},
		{name: "future", expires: "2026-05-02T12:00:01Z", valid: true, want: false},
		{name: "exact boundary", expires: "2026-05-02T12:00:00Z", valid: true, want: true},
		{name: "past", expires: "2026-05-02T11:59:59Z", valid: true, want: true},
		{name: "invalid format ignored", expires: "not-a-time", valid: true, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			file := db.File{ExpiresAt: expiresNullString(tc.expires, tc.valid)}
			got := IsFileExpired(file, now)
			if got != tc.want {
				t.Fatalf("IsFileExpired() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFilterVisibleFiles(t *testing.T) {
	now := time.Date(2026, 5, 2, 12, 0, 0, 0, time.UTC)
	files := []db.File{
		{ID: "a", ExpiresAt: expiresNullString("2026-05-02T11:00:00Z", true)},
		{ID: "b", ExpiresAt: expiresNullString("2026-05-03T11:00:00Z", true)},
		{ID: "c", ExpiresAt: expiresNullString("", false)},
	}

	visible := FilterVisibleFiles(files, now)
	if len(visible) != 2 {
		t.Fatalf("len(visible) = %d, want 2", len(visible))
	}
	if visible[0].ID != "b" || visible[1].ID != "c" {
		t.Fatalf("visible IDs = [%s,%s], want [b,c]", visible[0].ID, visible[1].ID)
	}
}

func TestExpiresAtStringUTC(t *testing.T) {
	tm := time.Date(2026, 5, 2, 15, 30, 0, 0, time.FixedZone("UTC+3", 3*60*60))
	ns := ExpiresAtString(tm)
	if !ns.Valid {
		t.Fatal("expected valid expires string")
	}
	if ns.String != "2026-05-02T12:30:00Z" {
		t.Fatalf("expires string = %q, want 2026-05-02T12:30:00Z", ns.String)
	}
}

func expiresNullString(v string, valid bool) sql.NullString {
	return sql.NullString{Valid: valid, String: v}
}
