"""Session management CLI command for ADXPL-Forge.

Provides ``axf shell sessions`` to list, interact with,
and manage active shell sessions.
"""

from __future__ import annotations

import sys
from typing import Any

try:
    from adxpl.core.shell_mixin import get_session_manager
except ImportError:
    get_session_manager = None


MANIFEST = {
    "capability_id": "adxpl.shell.sessions.v1",
    "safety_class": "INFORMATIONAL",
    "requires_authorization": False,
    "side_effects": [],
    "output_schema": "xpl.finding.v1",
    "mitre": [],
}


def run(args: Any) -> int:
    mgr = get_session_manager()
    action = getattr(args, "session_action", "list")

    if action == "list":
        mgr.print_sessions()
        return 0

    if action == "interact":
        sid = int(getattr(args, "session_id", 0))
        if sid <= 0:
            print("[!] Specify session ID: axf shell sessions interact <id>",
                  file=sys.stderr)
            return 1
        try:
            mgr.interact(sid)
            return 0
        except Exception as exc:
            print("[-] {}".format(exc), file=sys.stderr)
            return 1

    if action == "kill":
        sid = int(getattr(args, "session_id", 0))
        if sid <= 0:
            print("[!] Specify session ID", file=sys.stderr)
            return 1
        ok = mgr.close(sid)
        if ok:
            print("[+] Session #{} closed".format(sid))
        else:
            print("[-] Session #{} not found".format(sid))
        return 0 if ok else 1

    if action == "background":
        sid = int(getattr(args, "session_id", 0))
        if sid <= 0:
            print("[!] Specify session ID", file=sys.stderr)
            return 1
        try:
            mgr.background(sid)
            print("[*] Session #{} backgrounded".format(sid))
            return 0
        except Exception as exc:
            print("[-] {}".format(exc), file=sys.stderr)
            return 1

    print("[!] Unknown session action: {}".format(action), file=sys.stderr)
    return 1
