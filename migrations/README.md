# Migrations

This project uses `goose` SQL migrations in this directory.

## Naming Convention

- Use timestamp prefixes in UTC with this format:
  - `YYYYMMDDHHMMSS_description.sql`
- Keep descriptions short and action-oriented.
- Never edit an already-applied migration in shared environments; add a new migration instead.

## Local Usage

- Set a local SQLite `DATABASE_URL` (for example: `DATABASE_URL=sharefile.db`).
- Run:
  - `go run . migrate up`
  - `go run . migrate status`
  - `go run . migrate down`

## Notes

- Turso/libsql URLs are not used directly by this command path yet.
- Use local SQLite during early development for schema iteration and tests.
