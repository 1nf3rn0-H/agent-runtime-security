#!/usr/bin/env python3
"""Print selected trace variables in this process and one child process."""

import json
import os
import subprocess
import sys


NAMES = (
    "ARS_TRACE_ID",
    "ARS_TRACE_TOKEN",
    "ARS_ACTOR_ID",
    "ARS_ACTOR_TOKEN",
    "ARS_CODEX_SESSION_ID",
    "ARS_TOOL_CALL_ID",
    "ARS_ACTION_ID",
    "ARS_REQUEST_FINGERPRINT",
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
