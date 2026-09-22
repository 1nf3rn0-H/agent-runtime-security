# ADR-0013: Replace flat command splitting with a bounded non-executing parser

Status: Accepted for prototype
Date: 2026-09-21
Supersedes: the `shlex` implementation described in the command-interpretation section of the engineering direction

## Context

The initial `shlex` tokenizer split commands at control operators. It could preserve executable/argument relationships for simple and compound commands, but it could not model commands inside `$()`, backticks, process substitutions, redirections, or several execution wrappers. Matching only the visible outer command created straightforward policy bypasses.

No mature shell-parser dependency is currently installed in the prototype environment. Executing a shell in analysis mode is outside the security model.

## Options considered

1. Continue flat splitting and add regular expressions for individual evasions.
2. Add a third-party Bash parser immediately.
3. Implement a dependency-free, explicitly bounded subset parser, reject unsupported security-sensitive syntax, and retain a mature parser as the production direction.

## Decision

Use option 3 for the prototype. Represent simple commands, words, nested substitution programs, and redirections structurally. Inspect nested command/process substitutions and shell `-c` payloads recursively. Preserve quote semantics, separate redirection targets from arguments, normalize known wrappers, and track whether executable or argument values depend on runtime expansion.

Dynamic executables fail closed. Dynamic arguments cause a policy error only when they can change the result of process predicates whose static executable conditions match. Unsupported control flow and here-documents fail closed.

Enforce hard limits on input length, nesting, token count, command count, and word length.

## Consequences

- Previously hidden direct invocations are visible to process policy.
- Redirection filenames no longer create false process-argument matches.
- Static executable conditions prevent unrelated variable use from causing blanket denials.
- The parser has no runtime dependency and never executes input.
- Some valid shell programs are intentionally denied because their semantics are unsupported.
- Embedded language code, indirect dispatcher utilities, external script content, and shell-runtime configuration remain outside this parser's coverage.
- A mature, differential-tested shell parser and endpoint controls remain necessary before claiming production shell coverage.

