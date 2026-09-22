# ADR-0020: Rename the product to agent-runtime-security

Status: Accepted
Date: September 22, 2026

## Context

The original `AiDR` working name no longer described the product precisely and was difficult to discover. The project now needs one descriptive name across its repository, executable, runtime state, policy language, schemas, telemetry, and documentation before its first GitHub publication.

## Decision

Rename the product to **Agent Runtime Security**, with `agent-runtime-security` as the repository slug, CLI executable, event service name, and filesystem namespace.

The related technical names become:

- `.agent-runtime-security/` for local runtime code and state;
- `ARS_*` for injected trace environment variables;
- `ARSQuery` and `arsquery/2` for the policy authoring language;
- `.arsq` for policy source files;
- `agent_runtime_security.*` for detection type identifiers; and
- `com.agent_runtime_security.*` for namespaced detection extensions.

This is a pre-release breaking rename. The alpha does not retain aliases for the old executable, environment variables, paths, schema filenames, or telemetry names. Existing users must reinstall hooks and recompile policies after updating.

## Consequences

- The GitHub repository and user-facing command use the same descriptive name.
- Checked-in files contain no legacy product branding except where historical migration context explicitly requires it.
- Existing hook registrations referencing the old runtime path stop working until reinstalled.
- Existing diagnostic state is not migrated automatically; it was never a stable product interface.
