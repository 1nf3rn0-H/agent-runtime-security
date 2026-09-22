# ADR-0018: Add a local CLI and reversible Codex hook installation

Status: Accepted  
Date: September 22, 2026

## Context

The Codex proof of concept could enforce policy, but operating it required hand-editing `hooks.json`, directly invoking Python modules, and knowing which files represented source policy, runtime policy, and detections. That is not a workable installation or verification experience. Hook files may also contain unrelated user configuration that AiDR must not overwrite.

Codex project hooks are a trust boundary. Installation must leave their exact command visible for review instead of attempting to approve or conceal it.

## Decision

Provide a repository-root, dependency-free `aidr` CLI as the alpha control plane. It owns these workflows:

- idempotently merge AiDR handlers into project- or user-scoped Codex hooks;
- remove only handlers recognizable as AiDR-owned;
- preserve unrelated configuration and create a timestamped backup before replacement;
- diagnose adapter, policy, storage, and smoke-test health;
- compile and check AiDRQL policy;
- simulate policy locally without dispatch or network access; and
- inspect product status and detection events.

The installer registers six lifecycle events and uses an absolute path to the adapter and runtime policy in the current checkout. It does not modify Codex's trust state. Users review project hooks through Codex after installation.

Configuration replacement is atomic and uses user-only file permissions. The CLI remains a thin control plane over the existing compiler and enforcement modules; it does not create a second policy engine.

## Consequences

- A user can install, validate, safely demonstrate, inspect, and remove AiDR through one interface.
- Existing hook configuration is retained, and rollback artifacts are available.
- Moving or deleting the checkout breaks an installed alpha hook until AiDR is reinstalled.
- User-scoped installation broadens coverage but does not make application hooks tamper-proof.
- Packaged executables, signed artifacts, upgrades, and organization-managed deployment remain future work.
