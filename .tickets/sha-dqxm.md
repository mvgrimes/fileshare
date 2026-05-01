---
id: sha-dqxm
status: closed
deps: []
links: []
created: 2026-05-01T15:57:29Z
type: feature
priority: 1
parent: sha-hgi9
tags: [sprint-01, platform]
---
# Bootstrap CLI, server, and config

Initialize Go module structure with Cobra commands (server, migrate, seed), env config loading, structured logging, and health endpoints.

## Acceptance Criteria

sharefile server starts; /healthz and /readyz respond; config validation fails fast on missing required secrets; command help/docs are present.
