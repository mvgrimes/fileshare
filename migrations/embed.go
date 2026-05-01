package migrations

import (
	"embed"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
)

//go:embed *.sql
var files embed.FS

var versionPattern = regexp.MustCompile(`^(\d+)_.*\.sql$`)

func FS() fs.FS {
	return files
}

func LatestVersion() (int64, error) {
	entries, err := files.ReadDir(".")
	if err != nil {
		return 0, err
	}

	var latest int64
	var found bool
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		parts := versionPattern.FindStringSubmatch(filepath.Base(entry.Name()))
		if len(parts) != 2 {
			continue
		}
		v, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return 0, err
		}
		if !found || v > latest {
			latest = v
			found = true
		}
	}

	if !found {
		return 0, fs.ErrNotExist
	}

	return latest, nil
}
