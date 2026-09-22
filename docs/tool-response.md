# Tool-agnostic response layer

Status: Prototype  
Last updated: September 12, 2026

## Objective

Apply one deterministic pre-execution decision path to every local tool invocation exposed through a supported agent-harness hook. Tool-specific adapters normalize vendor input, while the policy result remains `allow` or `deny`.

## Codex coverage

AiDR configures `PreToolUse`, `PermissionRequest`, and `PostToolUse` with `matcher: "*"`.

| Tool path | Normalized family | Normalized action | Pre-execution response | Trace mechanism |
|---|---|---|---|---|
| Bash and unified exec | `shell` | `process.exec` | Allow, deny, or rewrite command | Injected process environment |
| `apply_patch` | `file_edit` | `file.modify` | Allow or deny; future adapter may safely rewrite | Hook/session correlation |
| MCP tools | `mcp` | `integration.call` | Allow or deny; future adapter may safely rewrite arguments | Hook/session correlation |
| Agent/subagent tool | `agent` | `agent.delegate` | Allow or deny when surfaced as a tool call | Hook/session and actor correlation |
| Other local function tools | `local_function` | `tool.call` | Allow or deny | Hook/session correlation |

The hook records only the input kind, top-level argument names, byte size, and SHA-256 digest for non-shell tool input. It does not copy complete file patches, MCP arguments, or function-tool arguments into diagnostic telemetry. Bash command retention remains controlled separately by the prototype telemetry policy.

## Decision contract

Before execution, AiDR always evaluates a supported tool and uses the documented Codex response appropriate to the result:

- `deny` rejects the tool call before it runs;
- an unchanged allow returns no hook override, preserving Codex's normal permission flow; and
- `allow` with `updatedInput` is used for Bash trace-environment injection.

Input rewriting beyond Bash is deliberately adapter-specific. A malformed rewrite is more dangerous than an unchanged allow, so AiDR will add rewrite implementations only with per-tool contract tests.

`PostToolUse` observes completion and can contribute evidence to a later detection. Blocking at that stage cannot reverse side effects and is not treated as preventive response.

## Permission boundary

`PermissionRequest` provides a second synchronous decision point when Codex is about to ask the user for elevated shell, managed-network, file-edit, or MCP permission. AiDR evaluates the same policy again:

- a deny returns the dedicated `PermissionRequest` deny response;
- an allow result deliberately returns no decision, so the normal user approval prompt remains visible; and
- evaluation failure returns a permission-specific deny and fails closed.

AiDR never automatically approves a permission request. In Codex, an explicit permission-hook allow would suppress the user prompt, which is outside the current response policy.

## Boundary

Codex hooks cover Bash, unified exec, `apply_patch`, MCP calls, and most local function tools. They do not cover hosted tools such as web search, `write_stdin` does not create a second pre-execution event for an existing command, and specialized paths can opt out. AiDR therefore uses “every tool” to mean every invocation delivered through the supported local hook boundary—not every possible action available to an agent.

Tools outside this boundary require a harness-specific integration or an operating-system control.
