package files

import (
	"database/sql"
	"time"

	"fileshare/internal/db"
)

func IsFileExpired(file db.File, now time.Time) bool {
	if !file.ExpiresAt.Valid {
		return false
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, file.ExpiresAt.String)
	if err != nil {
		return false
	}
	return !expiresAt.After(now.UTC())
}

func FilterVisibleFiles(files []db.File, now time.Time) []db.File {
	visible := make([]db.File, 0, len(files))
	for _, file := range files {
		if IsFileExpired(file, now) {
			continue
		}
		visible = append(visible, file)
	}
	return visible
}

func ExpiresAtString(t time.Time) sql.NullString {
	return sql.NullString{Valid: true, String: t.UTC().Format(time.RFC3339Nano)}
}
