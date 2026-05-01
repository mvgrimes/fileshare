# ShareFile Implementation Plan

## Architecture and Core Stack

- Backend: Go with `echo` for routing and middleware.
- Database: Turso (cloud SQLite) with `goose` migrations and `sqlc` typed queries.
- Frontend: server-rendered multi-page app using `html/template`, TailwindCSS, and `daisyUI`.
- Storage: S3-compatible object storage for uploaded files.
- Email: Mailgun for transactional notifications.
- Auth: session-based app auth, plus SSO JWT cookie support for internal users and magic-link/passwordless login for clients.

## Phase 0: Project Bootstrap (Day 1-2)

- Initialize Go module and add `cobra` CLI.
- Create primary commands: `server`, `migrate`, `seed`.
- Add environment-based configuration for DB, S3, Mailgun, session secret, and JWT settings.
- Set up structured logging, request IDs, and health endpoints (`/healthz`, `/readyz`).
- Wire base `echo` middleware: recover, logging, security headers, CSRF, and rate limiting.

## Phase 1: Data Layer Foundation (Day 2-4)

- Establish `goose` migration structure and `sqlc` generation configuration.
- Create initial schema:
  - `users`, `roles`, `user_roles`
  - `clients`, `client_groups`, `client_group_members`
  - `user_groups`, `user_group_members`
  - `client_upload_permissions`
  - `files`, `shares`
  - `sessions`, `magic_links`
  - `audit_logs`, `email_events`
- Generate queries with `sqlc`.
- Add repository/service data access patterns for transactions and shared query flows.

## Phase 2: Auth and Sessions (Day 4-7)

- Implement secure session middleware supporting both actor types: `user` and `client`.
- Internal user flow:
  - validate external SSO JWT cookie
  - upsert local user record
  - issue local session
- Client flow:
  - request magic link
  - send link via Mailgun
  - verify one-time token (store token hash, enforce expiry, consume on use)
  - optional password auth per-client setting
- Add logout, session invalidation, and auth audit logging.

## Phase 3: RBAC and Authorization (Day 7-8)

- Implement role permissions:
  - `admin`: manage users/roles
  - `account_manager`: manage clients and client-groups
  - `uploader`: upload/share files only
- Implement client permissions:
  - download items shared directly or through groups
  - upload only if account enabled
  - upload targets constrained by `client_upload_permissions`
- Enforce authz in both route middleware and service layer.

## Phase 4: Multi-Page UI Foundation (Day 8-10)

- Build template structure with shared layouts and partials.
- Integrate TailwindCSS and `daisyUI` build pipeline.
- Build key pages:
  - login/request-link
  - dashboard
  - clients and groups management
  - upload/share forms
  - shared files listing and detail pages
- Add progressive enhancement only where it improves UX materially.

## Phase 5: File Upload and Sharing Flows (Day 10-13)

- Implement S3 upload integration and metadata persistence.
- Store file metadata (`s3_key`, size, mime type, uploader identity, optional expiration).
- Implement sharing workflows:
  - user -> client(s)/client-group(s) with optional message
  - client -> user(s)/user-group(s) with optional note, constrained by visibility rules
- Implement download authorization checks and short-lived signed URLs.
- Enforce expiration visibility and access rules.

## Phase 6: Notifications and Auditability (Day 13-15)

- Add Mailgun templates and delivery for:
  - magic-link login
  - file shared notifications
  - client upload notifications to users/user-groups
  - optional user invitation/registration notices
- Persist notification event records and delivery status.
- Expand audit log coverage for auth, uploads, shares, downloads, and admin actions.

## Phase 7: Maintenance and Background Operations (Day 15-16)

- Add CLI jobs:
  - `cleanup-expired-files`
  - `resend-failed-emails`
  - migration helpers
- Define cleanup behavior for expired files and associated S3 objects.
- Support scheduled execution via external scheduler or periodic in-process runner.

## Phase 8: Hardening, Testing, and Release Readiness (Day 16-20)

- Security hardening:
  - strict cookie settings
  - CSRF coverage
  - auth endpoint rate limiting
  - upload size/type restrictions
  - safe file naming and content-type handling
- Testing strategy:
  - unit tests for auth, token, and RBAC logic
  - integration tests for data layer and critical handlers
  - end-to-end smoke tests for login/upload/share/download/expiration
- Ops readiness:
  - environment documentation
  - migration runbook
  - Turso backup/recovery plan
  - S3 lifecycle policy review

## Suggested Repository Layout

```text
cmd/
  sharefile/
    main.go
internal/
  app/
  auth/
  rbac/
  db/
    queries/        # sqlc generated
  repository/
  files/
  mail/
  web/
    handlers/
    middleware/
    templates/
    assets/
migrations/
sql/
  queries/
```

## MVP Scope

- Internal user login via SSO JWT cookie and role-based dashboard.
- Client magic-link login.
- Client and group management (including memberships).
- File upload to S3 and metadata storage.
- Sharing to clients/client-groups with optional message.
- Recipient email notifications.
- File listing/download with expiration enforcement.
- Basic audit logging.

## Decisions to Finalize Before Build

- SSO JWT contract details: cookie name, issuer, audience, JWKs/rotation.
- Magic-link TTL (recommended: 15 minutes) and session TTL (recommended: 8-12 hours).
- Upload limits: max size and allowed MIME types.
- Expired-file object lifecycle in S3: immediate delete vs grace period.
- Client password policy: per-client toggle (recommended) vs global.
