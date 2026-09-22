"""Bounded semantic target extraction for recognized process and tool contracts."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit

from shell_parser import Redirection, ShellWord


MAX_TARGETS_PER_FIELD = 64
MAX_TARGET_LENGTH = 8_192
HOSTNAME = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)
URL_SCHEMES = {"ftp", "ftps", "git", "http", "https", "ssh"}
NETWORK_EXECUTABLES = {
    "curl", "dig", "host", "nc", "ncat", "netcat", "nslookup", "ping", "ping6",
    "scp", "sftp", "ssh", "wget",
}
FILE_EXECUTABLES = {
    "cat", "chmod", "chown", "chgrp", "cp", "head", "install", "less", "ln", "mkdir",
    "more", "mv", "readlink", "realpath", "rm", "rmdir", "tail", "touch", "unlink",
}
PACKAGE_EXECUTABLES = {
    "apt": {"install", "remove", "purge", "upgrade"},
    "apt-get": {"install", "remove", "purge", "upgrade"},
    "brew": {"install", "reinstall", "uninstall", "upgrade"},
    "cargo": {"add", "install", "remove", "uninstall", "update"},
    "gem": {"install", "uninstall", "update"},
    "go": {"get", "install"},
    "npm": {"add", "install", "remove", "uninstall", "update"},
    "pip": {"install", "uninstall"},
    "pip3": {"install", "uninstall"},
    "pnpm": {"add", "install", "remove", "update"},
    "yarn": {"add", "install", "remove", "upgrade"},
}
TOOL_TARGET_KEYS = {
    "domain", "domains", "destination", "destinations", "file", "file_path", "files",
    "host", "hosts", "package", "packages", "path", "paths", "repo", "repository",
    "target", "targets", "uri", "uris", "url", "urls",
}


def _bounded_unique(values: Iterable[str]) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value or len(value) > MAX_TARGET_LENGTH or value in seen:
            continue
        seen.add(value)
        result.append(value)
        if len(result) >= MAX_TARGETS_PER_FIELD:
            break
    return tuple(result)


def normalize_host(value: str) -> str | None:
    candidate = value.strip().rstrip(".")
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1:candidate.index("]")]
    if "@" in candidate:
        candidate = candidate.rsplit("@", 1)[1]
    if ":" in candidate:
        try:
            ipaddress.ip_address(candidate)
            return candidate.casefold()
        except ValueError:
            candidate = candidate.split(":", 1)[0]
    try:
        ipaddress.ip_address(candidate)
        return candidate.casefold()
    except ValueError:
        return candidate.casefold() if HOSTNAME.fullmatch(candidate) else None


def normalize_url(value: str) -> tuple[str, str] | None:
    try:
        parsed = urlsplit(value)
        if parsed.scheme.casefold() not in URL_SCHEMES or not parsed.hostname:
            return None
        host = normalize_host(parsed.hostname)
        if not host:
            return None
        rendered_host = f"[{host}]" if ":" in host else host
        netloc = rendered_host + (f":{parsed.port}" if parsed.port is not None else "")
        sanitized = urlunsplit((parsed.scheme.casefold(), netloc, parsed.path, "", ""))
        return sanitized, host
    except ValueError:
        return None


def _static_positionals(
    words: tuple[ShellWord, ...], options_with_values: set[str] | None = None
) -> tuple[list[ShellWord], bool]:
    """Return positionals and whether dynamic/unknown option layout makes them incomplete."""
    options_with_values = options_with_values or set()
    result: list[ShellWord] = []
    uncertain = False
    index = 0
    after_options = False
    while index < len(words):
        word = words[index]
        value = word.value
        if word.dynamic:
            uncertain = True
        if not after_options and value == "--":
            after_options = True
            index += 1
            continue
        if not after_options and value.startswith("-") and value != "-":
            option = value.split("=", 1)[0]
            if option in options_with_values and "=" not in value:
                index += 1
                if index >= len(words):
                    return result, True
                if words[index].dynamic:
                    uncertain = True
            index += 1
            continue
        result.append(word)
        index += 1
    return result, uncertain


@dataclass(frozen=True)
class SemanticTargets:
    network_destinations: tuple[str, ...] = ()
    network_urls: tuple[str, ...] = ()
    file_paths: tuple[str, ...] = ()
    git_operations: tuple[str, ...] = ()
    git_repositories: tuple[str, ...] = ()
    package_operations: tuple[str, ...] = ()
    package_names: tuple[str, ...] = ()
    uncertain_fields: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, list[str]]:
        return {
            "network.destinations": list(self.network_destinations),
            "network.urls": list(self.network_urls),
            "file.paths": list(self.file_paths),
            "git.operations": list(self.git_operations),
            "git.repositories": list(self.git_repositories),
            "package.operations": list(self.package_operations),
            "package.names": list(self.package_names),
        }


def extract_process_targets(
    executable: str,
    argument_words: tuple[ShellWord, ...],
    redirections: tuple[Redirection, ...] = (),
    *,
    force_dynamic: bool = False,
) -> SemanticTargets:
    """Extract typed targets without expanding or executing any argument."""
    network_destinations: list[str] = []
    network_urls: list[str] = []
    file_paths: list[str] = []
    git_operations: list[str] = []
    git_repositories: list[str] = []
    package_operations: list[str] = []
    package_names: list[str] = []
    uncertain: set[str] = set()
    dynamic = force_dynamic or any(word.dynamic for word in argument_words)

    for redirection in redirections:
        if ">&" in redirection.operator or "<&" in redirection.operator:
            continue
        if redirection.target.dynamic:
            uncertain.add("file.paths")
        elif redirection.target.value:
            file_paths.append(redirection.target.value)

    if executable in NETWORK_EXECUTABLES:
        network_option_values = {
            "-b", "-c", "-F", "-H", "-I", "-i", "-m", "-o", "-p", "-Q", "-S",
            "-s", "-T", "-t", "-u", "-w", "-X", "-x", "--connect-timeout", "--data",
            "--form", "--header", "--interface", "--max-time", "--output", "--proxy",
            "--request", "--user", "--user-agent",
        }
        positionals, layout_uncertain = _static_positionals(argument_words, network_option_values)
        candidates = positionals
        if executable in {"ping", "ping6"} and positionals:
            candidates = positionals[-1:]
        elif executable in {"ssh", "sftp"} and positionals:
            candidates = positionals[:1]
        elif executable in {"nc", "ncat", "netcat"} and len(positionals) >= 2:
            candidates = positionals[-2:-1]
        elif executable in {"dig", "host", "nslookup"} and positionals:
            candidates = [word for word in positionals if not word.value.startswith("@")][:1]
        elif executable == "scp":
            candidates = [word for word in positionals if ":" in word.value]
            file_paths.extend(
                word.value for word in positionals if ":" not in word.value and not word.dynamic
            )
        for word in candidates:
            if word.dynamic:
                uncertain.add("network.destinations")
                uncertain.add("network.urls")
                continue
            parsed_url = normalize_url(word.value)
            if parsed_url:
                url, host = parsed_url
                network_urls.append(url)
                network_destinations.append(host)
                continue
            remote = word.value.split(":", 1)[0] if executable == "scp" else word.value
            host = normalize_host(remote)
            if host:
                network_destinations.append(host)
        if dynamic or layout_uncertain:
            uncertain.update(("network.destinations", "network.urls"))

    if executable in FILE_EXECUTABLES:
        file_option_values = {
            "-d", "-f", "-g", "-m", "-o", "-S", "-t", "--group", "--mode", "--owner",
            "--reference", "--suffix", "--target-directory",
        }
        positionals, layout_uncertain = _static_positionals(argument_words, file_option_values)
        file_paths.extend(word.value for word in positionals if not word.dynamic and word.value)
        if dynamic or layout_uncertain:
            uncertain.add("file.paths")

    if executable == "git":
        global_option_values = {
            "-C", "-b", "-c", "-o", "-u", "--branch", "--config", "--depth",
            "--exec-path", "--filter", "--git-dir", "--namespace", "--origin",
            "--upload-pack", "--work-tree",
        }
        positionals, layout_uncertain = _static_positionals(argument_words, global_option_values)
        if positionals:
            operation_word = positionals[0]
            if operation_word.dynamic:
                uncertain.add("git.operations")
            else:
                operation = operation_word.value.casefold()
                git_operations.append(operation)
                repo_candidates: list[ShellWord] = []
                if operation == "clone" and len(positionals) > 1:
                    repo_candidates = positionals[1:2]
                elif operation in {"fetch", "pull", "push"} and len(positionals) > 1:
                    repo_candidates = positionals[1:2]
                elif operation == "remote" and len(positionals) > 3 and positionals[1].value == "add":
                    repo_candidates = positionals[3:4]
                for word in repo_candidates:
                    if word.dynamic:
                        uncertain.add("git.repositories")
                    else:
                        git_repositories.append(word.value)
                        parsed_url = normalize_url(word.value)
                        if parsed_url:
                            url, host = parsed_url
                            network_urls.append(url)
                            network_destinations.append(host)
        elif dynamic:
            uncertain.add("git.operations")
        if layout_uncertain:
            uncertain.update(("git.operations", "git.repositories"))

    package_verbs = PACKAGE_EXECUTABLES.get(executable)
    if package_verbs is not None:
        positionals, layout_uncertain = _static_positionals(argument_words)
        operation_index = next(
            (index for index, word in enumerate(positionals) if word.value.casefold() in package_verbs),
            None,
        )
        if operation_index is not None:
            operation_word = positionals[operation_index]
            operation = operation_word.value.casefold()
            package_operations.append(f"{executable}.{operation}")
            for word in positionals[operation_index + 1:]:
                if word.dynamic:
                    uncertain.add("package.names")
                elif word.value:
                    package_names.append(word.value)
        elif dynamic:
            uncertain.add("package.operations")
        if layout_uncertain:
            uncertain.update(("package.operations", "package.names"))

    return SemanticTargets(
        network_destinations=_bounded_unique(value.casefold() for value in network_destinations),
        network_urls=_bounded_unique(network_urls),
        file_paths=_bounded_unique(file_paths),
        git_operations=_bounded_unique(git_operations),
        git_repositories=_bounded_unique(git_repositories),
        package_operations=_bounded_unique(package_operations),
        package_names=_bounded_unique(package_names),
        uncertain_fields=tuple(sorted(uncertain)),
    )


def extract_tool_targets(event: dict[str, Any]) -> tuple[str, ...]:
    """Extract bounded direct target values from a harness tool input contract."""
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        return ()
    values: list[str] = []
    for key, value in tool_input.items():
        if str(key).casefold() not in TOOL_TARGET_KEYS:
            continue
        if isinstance(value, str):
            parsed_url = normalize_url(value)
            values.append(parsed_url[0] if parsed_url else value)
        elif isinstance(value, list):
            for item in value:
                if not isinstance(item, str):
                    continue
                parsed_url = normalize_url(item)
                values.append(parsed_url[0] if parsed_url else item)
    return _bounded_unique(values)


def extract_typed_tool_targets(event: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    """Preserve direct tool-input target types for reputation matching."""
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        return ()
    typed: list[tuple[str, str]] = []
    for raw_key, raw_value in tool_input.items():
        key = str(raw_key).casefold()
        values = [raw_value] if isinstance(raw_value, str) else raw_value
        if not isinstance(values, list):
            continue
        for value in values:
            if not isinstance(value, str) or not value:
                continue
            if key in {"url", "urls", "uri", "uris"}:
                parsed = normalize_url(value)
                if parsed is not None:
                    typed.extend((("url", parsed[0]), ("domain", parsed[1])))
            elif key in {"domain", "domains", "host", "hosts"}:
                try:
                    typed.append(("ip", str(ipaddress.ip_address(value))))
                except ValueError:
                    host = normalize_host(value)
                    if host is not None:
                        typed.append(("domain", host))
            elif key in {"file", "file_path", "files", "path", "paths"}:
                typed.append(("file_path", value))
            elif key in {"package", "packages"}:
                typed.append(("package", value))
            elif key in {"repo", "repository"}:
                typed.append(("repository", value))
            elif key in {"destination", "destinations", "target", "targets"}:
                parsed = normalize_url(value)
                if parsed is not None:
                    typed.extend((("url", parsed[0]), ("domain", parsed[1])))
                    continue
                try:
                    typed.append(("ip", str(ipaddress.ip_address(value))))
                except ValueError:
                    if "." in value and "/" not in value:
                        host = normalize_host(value)
                        if host is not None:
                            typed.append(("domain", host))
    return tuple(dict.fromkeys(typed))
