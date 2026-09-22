#!/usr/bin/env python3
"""Print selected trace variables in this process and one child process."""

import json
import os
import subprocess
import sys


NAMES = (
    "AIDR_TRACE_ID",
    "AIDR_TRACE_TOKEN",
    "AIDR_ACTOR_ID",
    "AIDR_ACTOR_TOKEN",
    "AIDR_CODEX_SESSION_ID",
    "AIDR_TOOL_CALL_ID",
    "AIDR_ACTION_ID",
    "AIDR_REQUEST_FINGERPRINT",
)


def selected_environment():
    return {name: os.environ.get(name) for name in NAMES}


print(json.dumps({"level": "parent", "environment": selected_environment()}, sort_keys=True))
child_code = (
    "import json,os; "
    f"names={NAMES!r}; "
    "print(json.dumps({'level':'child','environment':{n:os.environ.get(n) for n in names}},sort_keys=True))"
)
subprocess.run([sys.executable, "-c", child_code], check=True)
