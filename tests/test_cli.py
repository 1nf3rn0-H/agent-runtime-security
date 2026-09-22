from __future__ import annotations

import importlib.util
import io
import json
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
ARS = ROOT / ".agent-runtime-security"
if str(ARS) not in sys.path:
    sys.path.insert(0, str(ARS))

spec = importlib.util.spec_from_file_location("agent_runtime_security_cli_tests", ARS / "cli.py")
cli = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = cli
spec.loader.exec_module(cli)


class CliTests(unittest.TestCase):
    def test_policy_check_uses_stable_project_relative_source(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            result = cli.main(["policy", "check"])
        self.assertEqual(result, 0)
        self.assertIn("current: 2 rules", output.getvalue())

    def test_install_merges_and_uninstall_preserves_unrelated_hooks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            config = project / ".codex" / "hooks.json"
            config.parent.mkdir()
            config.write_text(
                json.dumps(
                    {
                        "description": "existing",
                        "hooks": {
                            "PreToolUse": [
                                {
                                    "matcher": "Bash",
                                    "hooks": [
                                        {
                                            "type": "command",
                                            "command": "python3 unrelated.py",
                                        }
                                    ],
                                }
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )

            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    cli.main(["install", "--scope", "project", "--target", str(project)]),
                    0,
                )
            installed = json.loads(config.read_text(encoding="utf-8"))
            self.assertEqual(set(cli.MANAGED_EVENTS), set(installed["hooks"]) - set())
            pre_handlers = [
                handler
                for group in installed["hooks"]["PreToolUse"]
                for handler in group["hooks"]
            ]
            self.assertTrue(any(handler["command"] == "python3 unrelated.py" for handler in pre_handlers))
            self.assertTrue(any(cli._is_agent_runtime_security_handler(handler) for handler in pre_handlers))
            self.assertTrue(list(config.parent.glob("hooks.json.agent-runtime-security-backup-*")))
            self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)

            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    cli.main(["uninstall", "--scope", "project", "--target", str(project)]),
                    0,
                )
            uninstalled = json.loads(config.read_text(encoding="utf-8"))
            self.assertEqual(
                uninstalled["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
                "python3 unrelated.py",
            )
            self.assertFalse(
                any(
                    cli._is_agent_runtime_security_handler(handler)
                    for groups in uninstalled["hooks"].values()
                    for group in groups
                    for handler in group.get("hooks", [])
                )
            )
            self.assertGreaterEqual(
                len(list(config.parent.glob("hooks.json.agent-runtime-security-backup-*"))),
                2,
            )

    def test_reinstall_is_idempotent(self) -> None:
        first = cli._merged_hooks(None)
        second = cli._merged_hooks(first)
        for event in cli.MANAGED_EVENTS:
            handlers = [
                handler
                for group in second["hooks"][event]
                for handler in group.get("hooks", [])
                if cli._is_agent_runtime_security_handler(handler)
            ]
            self.assertEqual(len(handlers), 1)

    def test_simulation_is_non_executing_and_network_free(self) -> None:
        marker = ROOT / ".agent-runtime-security" / "CLI_SIMULATION_WAS_EXECUTED"
        if marker.exists():
            marker.unlink()
        output = io.StringIO()
        command = f"touch {marker} && ping evil.com"
        with redirect_stdout(output):
            result = cli.main(["simulate", "--command", command])
        decision = json.loads(output.getvalue())
        self.assertEqual(result, 2)
        self.assertEqual(decision["decision"], "deny")
        self.assertEqual(decision["network_requests"], 0)
        self.assertEqual(decision["side_effects"], 0)
        self.assertFalse(marker.exists())

    def test_dry_run_does_not_write_hooks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            output = io.StringIO()
            with redirect_stdout(output):
                result = cli.main(
                    ["install", "--scope", "project", "--target", str(project), "--dry-run"]
                )
            self.assertEqual(result, 0)
            self.assertFalse((project / ".codex" / "hooks.json").exists())
            self.assertEqual(
                Path(json.loads(output.getvalue())["path"]).resolve(),
                (project / ".codex" / "hooks.json").resolve(),
            )


if __name__ == "__main__":
    unittest.main()
