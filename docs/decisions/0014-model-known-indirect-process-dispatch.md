# ADR-0014: Model known indirect process dispatch

Status: Accepted for prototype  
Date: 2026-09-21  
Extends: ADR-0013

## Context

A shell AST identifies syntactic commands, but utilities can accept another command as data and execute it later. A rule blocking `ping evil.com` could otherwise be bypassed with `xargs`, `find -exec`, `watch`, `eval`, or execution wrappers such as `timeout` and `chroot`.

Runtime-supplied values add a second problem. In `printf evil.com | xargs ping`, the proposed command names `ping` but its destination arrives through pipeline data. Treating the statically visible argument list as complete would produce an unsafe allow.

## Options considered

1. Leave indirect dispatch to a future endpoint process sensor.
2. Reject every utility that can dispatch another process.
3. Add typed extractors for bounded, understood dispatcher contracts and fail closed on unknown or runtime-dependent results that could change policy.

## Decision

Use option 3. Normalize transparent execution prefixes including `sudo`, `env`, `timeout`, `nice`, `setsid`, `stdbuf`, and `chroot` to their effective executable. Extract child commands from supported `xargs`, `find -exec/-execdir/-ok/-okdir`, `watch`, `eval`, and nested shell `-c` contracts.

Mark arguments supplied by `xargs` input and `find {}` substitution as dynamic. If the effective executable matches a process rule and those values could change its argument result, fail closed. Preserve statically sufficient positive matches as normal rule matches and detections.

Attach an ordered `dispatch_chain` to normalized invocations and expose it to policy as the list field `process.dispatch_chain`. Runtime IR `1.1.0` adds this optional field with the existing `HAS_ANY`, `HAS_ALL`, `HAS_NONE`, `EXISTS`, and `NOT_EXISTS` operators.

Reject `parallel` for now because its command-template and replacement semantics are not modeled.

## Consequences

- Known wrapper and dispatcher bypasses are evaluated before execution.
- Policies can explicitly match indirect execution paths.
- Runtime-injected destinations deny conservatively instead of being mistaken for an empty static argument list.
- Diagnostic invocation telemetry explains the dispatcher path.
- Utility-version and platform differences require continued fixtures and compatibility testing.
- Embedded language code, build systems, package scripts, and unknown dispatchers remain outside this extractor set and require endpoint defense in depth.

