# Migrations

This project uses `goose` SQL migrations in this directory.

## Naming Convention

- Use timestamp prefixes in UTC with this format:
  - `YYYYMMDDHHMMSS_description.sql`
- Keep descriptions short and action-oriented.
- Never edit an already-applied migration in shared environments; add a new migration instead.

## Local Usage

- Set a local SQLite `DATABASE_URL` (for example: `DATABASE_URL=fileshare.db`).
- Run:
  - `go run . migrate up`
  - `go run . migrate status`
  - `go run . migrate down`

## CI Usage

- Use a writable SQLite path in the job workspace (for example: `DATABASE_URL=$PWD/fileshare-ci.db`).
- Run migrations in order to validate both apply and rollback paths:
  - `go run . migrate up`
  - `go run . migrate status`
  - `go run . migrate down`

## DATABASE_URL Rules

- Supported values:
  - Plain SQLite file path (for example: `fileshare.db` or `/tmp/fileshare.db`)
  - `sqlite://` URL form (for example: `sqlite:///tmp/fileshare.db`)
- Unsupported values:
  - `libsql://...` (goose currently uses the SQLite driver in this repo)
  - Other URL schemes such as `postgres://...`

## Notes

- Turso/libsql URLs are not used directly by this command path yet.
- Use local SQLite during early development for schema iteration and tests.
