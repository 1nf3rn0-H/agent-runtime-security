"""Bounded, non-executing parser for the shell subset enforced by Agent Runtime Security."""

from __future__ import annotations

from dataclasses import dataclass


MAX_COMMAND_LENGTH = 65_536
MAX_NESTING = 8
MAX_TOKENS = 4_096
MAX_COMMANDS = 512
MAX_WORD_LENGTH = 8_192

CONTROL_OPERATORS = {";", "&&", "||", "|", "|&", "&", "\n", "(", ")"}
UNSUPPORTED_OPERATORS = {";;", ";&", ";;&", "((", "))"}
UNSUPPORTED_COMMANDS = {
    "if",
    "then",
    "else",
    "elif",
    "fi",
    "while",
    "until",
    "do",
    "done",
    "for",
    "in",
    "case",
    "esac",
    "select",
    "function",
    "coproc",
    "[[",
    "]]",
    "{",
    "}",
}
REDIRECTION_OPERATORS = (
    "&>>",
    "<<<",
    "<<-",
    ">>",
    "<<",
    "<>",
    ">&",
    "<&",
    ">|",
    "&>",
    ">",
    "<",
)
SHELL_OPERATORS = (
    ";;&", "&&", "||", "|&", ";;", ";&", "((", "))", ";", "|", "&", "(", ")"
)


class ShellParseError(ValueError):
    pass


@dataclass(frozen=True)
class ShellWord:
    value: str
    dynamic: bool = False
    substitutions: tuple["ShellProgram", ...] = ()


@dataclass(frozen=True)
class Redirection:
    operator: str
    target: ShellWord


@dataclass(frozen=True)
class SimpleCommand:
    words: tuple[ShellWord, ...]
    redirections: tuple[Redirection, ...]


@dataclass(frozen=True)
class ShellProgram:
    commands: tuple[SimpleCommand, ...]


@dataclass(frozen=True)
class _Token:
    kind: str
    value: str | ShellWord


def _balanced(text: str, opening_index: int, opening: str, closing: str) -> tuple[str, int]:
    depth = 0
    quote: str | None = None
    index = opening_index
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if quote is not None:
            if char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            index += 1
            continue
        if char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return text[opening_index + 1:index], index + 1
        index += 1
    raise ShellParseError(f"unterminated {opening}{closing} expression")


class _Lexer:
    def __init__(self, text: str, depth: int) -> None:
        self.text = text
        self.depth = depth
        self.index = 0
        self.tokens: list[_Token] = []

    def emit(self, kind: str, value: str | ShellWord) -> None:
        if len(self.tokens) >= MAX_TOKENS:
            raise ShellParseError(f"shell input exceeds {MAX_TOKENS} tokens")
        self.tokens.append(_Token(kind, value))

    def lex(self) -> list[_Token]:
        while self.index < len(self.text):
            char = self.text[self.index]
            if char in " \t\r":
                self.index += 1
                continue
            if char == "\n":
                self.emit("operator", "\n")
                self.index += 1
                continue
            if char == "#":
                newline = self.text.find("\n", self.index)
                self.index = len(self.text) if newline < 0 else newline
                continue
            redirection = self._redirection()
            if redirection is not None:
                self.emit("redirection", redirection)
                continue
            operator = self._operator()
            if operator is not None:
                self.emit("operator", operator)
                continue
            self.emit("word", self._word())
        return self.tokens

    def _operator(self) -> str | None:
        for operator in SHELL_OPERATORS:
            if self.text.startswith(operator, self.index):
                self.index += len(operator)
                return operator
        return None

    def _redirection(self) -> str | None:
        start = self.index
        if self.text.startswith(("<(", ">("), start):
            return None
        cursor = start
        while cursor < len(self.text) and self.text[cursor].isdigit():
            cursor += 1
        prefix = self.text[start:cursor]
        for operator in REDIRECTION_OPERATORS:
            if self.text.startswith(operator, cursor):
                if operator.startswith("&") and prefix:
                    continue
                self.index = cursor + len(operator)
                return prefix + operator
        return None

    def _quoted(self, quote: str) -> tuple[str, bool, list[ShellProgram]]:
        self.index += 1
        value: list[str] = []
        dynamic = False
        substitutions: list[ShellProgram] = []
        while self.index < len(self.text):
            char = self.text[self.index]
            if char == quote:
                self.index += 1
                return "".join(value), dynamic, substitutions
            if quote == "'":
                value.append(char)
                self.index += 1
                continue
            if char == "\\":
                if self.index + 1 >= len(self.text):
                    raise ShellParseError("trailing escape in quoted word")
                escaped = self.text[self.index + 1]
                if escaped in {'"', "\\", "$", "`"}:
                    value.append(escaped)
                elif escaped != "\n":
                    value.extend(("\\", escaped))
                self.index += 2
                continue
            if char == "$":
                literal, expansion_dynamic, programs = self._dollar_expansion()
                value.append(literal)
                dynamic = dynamic or expansion_dynamic
                substitutions.extend(programs)
                continue
            if char == "`":
                substitutions.append(self._backtick())
                dynamic = True
                continue
            value.append(char)
            self.index += 1
        raise ShellParseError(f"unterminated {quote} quote")

    def _backtick(self) -> ShellProgram:
        self.index += 1
        start = self.index
        escaped = False
        while self.index < len(self.text):
            char = self.text[self.index]
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == "`":
                inner = self.text[start:self.index]
                self.index += 1
                return parse_shell(inner, self.depth + 1)
            self.index += 1
        raise ShellParseError("unterminated backtick substitution")

    def _dollar_expansion(self) -> tuple[str, bool, list[ShellProgram]]:
        start = self.index
        self.index += 1
        if self.index >= len(self.text):
            return "$", False, []
        char = self.text[self.index]
        if char == "(":
            inner, end = _balanced(self.text, self.index, "(", ")")
            self.index = end
            if inner.startswith("(") and inner.endswith(")"):
                arithmetic = inner[1:-1]
                if "$(" in arithmetic or "`" in arithmetic:
                    raise ShellParseError("command substitution inside arithmetic is unsupported")
                return "", True, []
            return "", True, [parse_shell(inner, self.depth + 1)]
        if char == "{":
            inner, end = _balanced(self.text, self.index, "{", "}")
            if "$(" in inner or "`" in inner:
                raise ShellParseError("command substitution inside parameter expansion is unsupported")
            self.index = end
            return "", True, []
        if char == "'":
            literal, _, _ = self._quoted("'")
            return literal, False, []
        if char == '"':
            return self._quoted('"')
        if char.isalpha() or char == "_":
            self.index += 1
            while self.index < len(self.text) and (
                self.text[self.index].isalnum() or self.text[self.index] == "_"
            ):
                self.index += 1
            return "", True, []
        if char.isdigit() or char in "@*#?$!-0":
            self.index += 1
            return "", True, []
        self.index = start + 1
        return "$", False, []

    def _process_substitution(self) -> ShellProgram:
        opening = self.index + 1
        inner, end = _balanced(self.text, opening, "(", ")")
        self.index = end
        return parse_shell(inner, self.depth + 1)

    def _word(self) -> ShellWord:
        value: list[str] = []
        dynamic = False
        consumed = False
        substitutions: list[ShellProgram] = []
        while self.index < len(self.text):
            char = self.text[self.index]
            if char in " \t\r\n;&|()<>" :
                if char in "<>" and self.text.startswith(("<(", ">("), self.index):
                    substitutions.append(self._process_substitution())
                    dynamic = True
                    consumed = True
                    continue
                break
            if char == "\\":
                if self.index + 1 >= len(self.text):
                    raise ShellParseError("trailing escape in shell word")
                escaped = self.text[self.index + 1]
                if escaped != "\n":
                    value.append(escaped)
                self.index += 2
                consumed = True
                continue
            if char in {"'", '"'}:
                literal, quote_dynamic, programs = self._quoted(char)
                value.append(literal)
                dynamic = dynamic or quote_dynamic
                substitutions.extend(programs)
                consumed = True
                continue
            if char == "`":
                substitutions.append(self._backtick())
                dynamic = True
                consumed = True
                continue
            if char == "$":
                literal, expansion_dynamic, programs = self._dollar_expansion()
                value.append(literal)
                dynamic = dynamic or expansion_dynamic
                substitutions.extend(programs)
                consumed = True
                continue
            if char in "*?[":
                dynamic = True
            value.append(char)
            self.index += 1
            consumed = True
            if len(value) > MAX_WORD_LENGTH:
                raise ShellParseError(f"shell word exceeds {MAX_WORD_LENGTH} characters")
        if not consumed:
            raise ShellParseError(f"unsupported shell token at offset {self.index}")
        word_value = "".join(value)
        if "{" in word_value and "," in word_value and "}" in word_value:
            dynamic = True
        if word_value.startswith("~"):
            dynamic = True
        return ShellWord(word_value, dynamic, tuple(substitutions))


def _parse_tokens(tokens: list[_Token]) -> ShellProgram:
    commands: list[SimpleCommand] = []
    words: list[ShellWord] = []
    redirections: list[Redirection] = []
    pending_redirection: str | None = None
    group_depth = 0

    def flush() -> None:
        nonlocal words, redirections
        if words or redirections:
            commands.append(SimpleCommand(tuple(words), tuple(redirections)))
            if len(commands) > MAX_COMMANDS:
                raise ShellParseError(f"shell input exceeds {MAX_COMMANDS} commands")
            words = []
            redirections = []

    for token in tokens:
        if pending_redirection is not None:
            if token.kind != "word":
                raise ShellParseError(f"redirection {pending_redirection!r} requires a target")
            target = token.value
            assert isinstance(target, ShellWord)
            operator = pending_redirection
            pending_redirection = None
            if "<<" in operator and "<<<" not in operator:
                raise ShellParseError("here-document syntax is unsupported")
            redirections.append(Redirection(operator, target))
            continue
        if token.kind == "redirection":
            pending_redirection = str(token.value)
            continue
        if token.kind == "word":
            word = token.value
            assert isinstance(word, ShellWord)
            words.append(word)
            continue

        operator = str(token.value)
        if operator in UNSUPPORTED_OPERATORS:
            raise ShellParseError(f"operator {operator!r} is unsupported")
        if operator == "(":
            if words or redirections:
                raise ShellParseError("function definitions and argument-adjacent groups are unsupported")
            group_depth += 1
            continue
        if operator == ")":
            flush()
            group_depth -= 1
            if group_depth < 0:
                raise ShellParseError("unmatched closing parenthesis")
            continue
        if operator not in CONTROL_OPERATORS:
            raise ShellParseError(f"operator {operator!r} is unsupported")
        flush()

    if pending_redirection is not None:
        raise ShellParseError(f"redirection {pending_redirection!r} requires a target")
    flush()
    if group_depth:
        raise ShellParseError("unmatched opening parenthesis")

    for command in commands:
        executable = next(
            (
                word.value
                for word in command.words
                if not (
                    "=" in word.value
                    and word.value.split("=", 1)[0].replace("_", "a").isalnum()
                    and not word.value.split("=", 1)[0][0].isdigit()
                )
            ),
            "",
        )
        if executable in UNSUPPORTED_COMMANDS:
            raise ShellParseError(f"shell control construct {executable!r} is unsupported")
    return ShellProgram(tuple(commands))


def parse_shell(command: str, depth: int = 0) -> ShellProgram:
    """Parse a bounded shell subset without expanding or executing its contents."""
    if not isinstance(command, str):
        raise ShellParseError("shell input must be a string")
    if depth > MAX_NESTING:
        raise ShellParseError(f"shell nesting exceeds {MAX_NESTING}")
    if len(command) > MAX_COMMAND_LENGTH:
        raise ShellParseError(f"shell input exceeds {MAX_COMMAND_LENGTH} characters")
    return _parse_tokens(_Lexer(command, depth).lex())


def walk_commands(program: ShellProgram):
    """Yield commands and the commands executed by substitutions in their words."""
    for command in program.commands:
        yield command
        expansion_words = list(command.words) + [item.target for item in command.redirections]
        for word in expansion_words:
            for substitution in word.substitutions:
                yield from walk_commands(substitution)
