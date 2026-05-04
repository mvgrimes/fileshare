# ShareFile

ShareFile is a Go web application for secure file exchange between internal users and external clients. It uses server-rendered pages, role-based access control, and dual authentication flows (internal SSO cookie bridge + client magic-link login).

## Current Status

- Sprint 01 is complete (bootstrap, schema/migrations, sqlc query layer, auth/session middleware, SSO login bridge, magic-link flow, RBAC gates).
- Core HTTP server and routes are in place, with health endpoints at `/healthz` and `/readyz`.
- Test coverage exists for config, migrations, auth/session lifecycle, SSO validation, magic links, RBAC policy, and server route behavior.
- Next sprint focus: persistent auth state, file upload/storage workflows, notifications, and admin CRUD pages.

## Stack

- Backend: Go + Echo
- Data: SQLite/Turso + Goose + sqlc
- UI: `html/template` (server-rendered multi-page app)
- Styling: TailwindCSS + daisyUI (compiled to `internal/web/assets/dist/app.css`)
- Auth: session cookies, SSO JWT cookie bridge (users), magic-link flow (clients)

## Implemented Features (Sprint 01)

- Cobra CLI commands: `server`, `migrate`, `bootstrap`, `add-user`, `add-client`, `seed` (`seed` placeholder)
- Structured config + logging
- Migration baseline for core domain tables
- Generated typed SQL access layer (`internal/db`)
- Session middleware: load/require auth + actor-type checks
- Role gates for `admin`, `account_manager`, and `uploader`
- Auth endpoints:
  - `POST /auth/session`
  - `POST /auth/logout`
  - `POST /auth/sso/login`
  - `POST /auth/magic/request`
  - `POST /auth/magic/verify`

## Project Layout

```text
cmd/                  # CLI commands (server, migrate, seed)
internal/
  auth/               # session, SSO, magic-link, RBAC policy
  config/             # environment config and validation
  db/                 # sqlc-generated query layer
  logger/             # slog setup
  server/             # Echo server wiring and route groups
  web/templates/      # HTML templates
migrations/           # goose migrations
sql/                  # schema and sqlc query definitions
data/                 # local runtime artifacts (for dev)
```

## Getting Started

### 1) Prerequisites

- Go (matching `go.mod`)
- Optional: `just` for task shortcuts
- Optional: `air` for live reload (`just run-watch`)

### 2) Configure Environment

Copy `.env.example` to `.env` and fill required values:

- `DATABASE_URL`
- `SESSION_SECRET`
- `JWT_SECRET`

SSO settings are optional and default to:

- `SSO_COOKIE_NAME=sso_jwt`
- `SSO_ISSUER=sharefile-sso`
- `SSO_AUDIENCE=sharefile`

### 3) Run Migrations

```bash
go run ./... migrate up
```

Note: Goose migrations use the SQLite driver and do not support `libsql://` URLs directly. For migration commands, use a local SQLite path in `DATABASE_URL` (for example `data/sharefile.db`).

### 4) Bootstrap (Optional but Recommended)

```bash
go run ./... bootstrap
```

`bootstrap` applies migrations and attempts to create an initial admin user. It is idempotent when run with `--if-missing` (default true).

Environment variables for bootstrap admin user:

- `SHAREFILE_USER_EMAIL` (required)
- `SHAREFILE_USER_PASSWORD` (required)
- `SHAREFILE_USER_ROLE` (optional, default `admin`)
- `SHAREFILE_USER_FULL_NAME` (optional, default email)

For container startup, use an entrypoint/command that runs bootstrap before the server:

```bash
sharefile bootstrap && sharefile server
```

### 5) Start the Server

```bash
go run ./... server
```

The app runs on `SERVER_ADDRESS:SERVER_PORT` (defaults: `0.0.0.0:8080`).

### 6) Run Tests

```bash
go test ./...
```

### 7) Build Frontend CSS

```bash
sfw pnpm install
pnpm run css:build
```

For iterative UI work:

```bash
pnpm run css:watch
```

Run a minio server for local S3 emulation:

```bash
podman run --rm \
  --name sharefile-minio \
  -p 9000:9000 \
  -p 9001:9001 \
  -e MINIO_ROOT_USER=sharefile \
  -e MINIO_ROOT_PASSWORD=sharefile123 \
  -v "$(pwd)/data/minio:/data" \
  quay.io/minio/minio server /data --console-address ":9001"

  mc alias set local http://127.0.0.1:9000 sharefile sharefile123
  mc mb -p local/sharefile-uploads
```

## CLI Commands

- `go run ./... server` - start HTTP server
- `go run ./... migrate up` - apply migrations
- `go run ./... migrate down` - rollback latest migration
- `go run ./... migrate status` - show migration status
- `go run ./... bootstrap` - apply migrations and initialize admin user
- `go run ./... add-user` - create/update a user
- `go run ./... add-client` - create/update a client
- `go run ./... seed` - seed dev data (currently placeholder)

## Development Notes

- Sessions and magic-link state are currently in-memory (not yet DB-backed).
- CSRF currently skips selected auth endpoints for browser-driven flow compatibility.
- The MVP roadmap and architecture plan are documented in `PLAN.md`.
- Session progress and completed tickets are documented in `data/SESSION_LOG_2026-05-01.md`.
