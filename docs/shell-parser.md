# Agent Runtime Security bounded shell parser

Status: Implemented for prototype
Last updated: September 21, 2026

## Purpose

Agent Runtime Security must decide whether a proposed shell action matches process policy without executing, expanding, sourcing, or importing the command. Flat token splitting cannot safely preserve executable/argument relationships across substitutions, subshells, redirections, and execution wrappers.

The dependency-free parser in [`.agent-runtime-security/shell_parser.py`](../.agent-runtime-security/shell_parser.py) builds a bounded structural representation of the supported shell subset. The Codex adapter converts its simple-command nodes into process invocations and evaluates all process predicates for a rule against the same invocation.

This is a security-oriented subset parser, not a complete Bash implementation.

## Current structural model

```text
ShellProgram
  └── SimpleCommand[]
        ├── ShellWord[]
        │     ├── literal value after quote removal
        │     ├── dynamic-expansion flag
        │     └── nested ShellProgram[]
        └── Redirection[]
              ├── operator
              └── target ShellWord
```

No parser action performs shell expansion. Nested command and process substitutions are parsed as additional programs. Redirection targets remain distinct from process arguments.

## Supported behavior

- Simple commands and quoted/escaped words.
- Lists, pipelines, background separators, and subshell groups using `;`, newline, `&&`, `||`, `|`, `|&`, `&`, and parentheses.
- `$()` and backtick command substitution.
- `<()` and `>()` process substitution.
- Standard input/output redirections and here-strings.
- Environment-assignment prefixes.
- `command`, `builtin`, `exec`, `nohup`, `time`, `env`, and `sudo` wrapper normalization.
- `timeout`, `nice`, `setsid`, `stdbuf`, and `chroot` execution-prefix normalization.
- Typed child-command extraction for supported `xargs`, `find -exec/-execdir/-ok/-okdir`, `watch`, and `eval` forms.
- Typed target extraction for recognized network, filesystem, Git, and package-manager invocation contracts.
- Direct and combined shell command flags such as `sh -c` and `bash -lc`.
- Comments outside words and quotes.
- Dynamic parameter, glob, tilde, brace, arithmetic, and substitution markers.

For example, each of these exposes a `ping` invocation to the same policy rule:

```text
ping evil.com
sudo -u root -- ping evil.com
bash -lc 'ping evil.com'
echo $(ping evil.com)
cat <(ping evil.com)
(ping evil.com)
printf x | xargs ping evil.com
find . -exec ping evil.com {} \;
```

Single-quoted text remains literal, so this does not create a `ping` invocation:

```text
printf '%s' '$(ping evil.com)'
```

## Dynamic-value semantics

The parser marks a word as dynamic when its runtime value depends on parameter expansion, command/process substitution, arithmetic, globbing, tilde expansion, or brace expansion.

- A dynamic executable fails closed because Agent Runtime Security cannot identify the program that will run.
- A dynamic argument does not automatically deny an unrelated executable.
- When the static executable matches a process rule and the dynamic argument could change that rule result, evaluation fails closed.
- A statically present positive match remains deterministic. `ping evil.com "$EXTRA"` matches and emits the normal rule detection; it does not degrade into a parser-error denial.
- Negative list predicates such as `HAS_NONE` remain uncertain when extra dynamic arguments exist and therefore fail closed.
- Values appended from `xargs` input and substituted for `find {}` are dynamic. Their dispatchers remain recorded in the invocation's `dispatch_chain`.
- Semantic fields retain their own uncertainty markers. A dynamic destination can fail closed a network-target rule without affecting an unrelated file or executable rule.

This provides conservative behavior without denying a benign command such as `printf "$HOME"` solely because another rule protects `ping` destinations.

## Bounds

| Resource | Limit |
|---|---:|
| Input characters per parsed program | 65,536 |
| Nested programs/interpreters | 8 |
| Tokens per program | 4,096 |
| Commands/invocations | 512 |
| Characters per word | 8,192 |

Boundary violations raise a controlled policy error. Preventive hooks fail closed; the underlying shell is never invoked by the parser.

## Unsupported syntax and behavior

The current parser rejects here-documents, function definitions, arithmetic-command syntax, `case`, loops, and `if` control flow. These constructs fail closed instead of being partially interpreted.

The following remain explicit security gaps rather than supported interpretations:

- Code embedded in `python -c`, `node -e`, `perl -e`, `ruby -e`, or similar language runtimes.
- Command templates handled by unsupported `parallel` forms, unknown dispatcher options, build systems, or package lifecycle scripts.
- Shell scripts loaded from files rather than present in the proposed command string.
- Runtime filesystem glob results, parameter values, aliases, functions, and shell startup configuration.
- Exact behavioral differences among Bash, Zsh, Dash, Ksh, and platform utilities.

Supported indirect dispatch is recorded in [ADR-0014](decisions/0014-model-known-indirect-process-dispatch.md). Remaining paths require more typed dispatcher extractors, file-content correlation, a mature shell grammar, or an operating-system enforcement layer. The parser must not be described as protection against all indirect execution.

Typed target extraction is recorded in [ADR-0015](decisions/0015-extract-typed-semantic-targets.md). It parses recognized CLI contracts only; it does not resolve DNS, canonicalize filesystem paths against the host, inspect repository configuration, or execute package-manager logic.

## Verification methodology

Tests cover direct, compound, nested, quoted, malformed, oversized, substituted, redirected, wrapped, and dynamic commands. A deterministic randomized corpus exercises 500 malformed/mixed inputs and requires either a valid bounded AST or a controlled `ShellParseError`; internal exceptions are test failures.

Every parser bypass or false denial must become a minimized regression fixture. Future mature-parser adoption requires differential tests comparing both parsers on the full corpus before the enforcement implementation changes.

See [ADR-0013](decisions/0013-bounded-non-executing-shell-parser.md).
