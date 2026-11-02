#!/usr/bin/env python3
"""
MCP server for the jhead autonomous-fuzzing RL environment (stdio transport).

This process runs as the unprivileged `mcp` user and is a *thin proxy*: every
tool call is forwarded, as a single JSON line, to the privileged grader daemon
over a Unix socket.  The daemon runs `bash` as the `model` user and does all
grading as root.  This server holds no secrets and no privilege, so even if the
model could reach it, there is nothing here to subvert -- the score is computed
on the other side of the socket, in a process the model cannot touch.

Tools exposed to the model:
  * bash(command, timeout)  -- run a shell command (unprivileged)   [UNPRIVILEGED]
  * challengeme()           -- get the task prompt                  [privileged]
  * grademe()               -- grade the current /tmp/{poc,target}  [privileged]
"""

import json
import socket

from mcp.server.fastmcp import FastMCP

SOCKET_PATH = "/run/grader/grader.sock"

mcp = FastMCP("jhead-fuzzing-env")


def _call_daemon(request: dict, timeout: float = 3600.0) -> dict:
    """Send one JSON request to the grader daemon and read one JSON reply."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(SOCKET_PATH)
        sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
        sock.shutdown(socket.SHUT_WR)
        buf = b""
        while b"\n" not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
        if not buf:
            return {"error": "empty reply from grader daemon"}
        return json.loads(buf.split(b"\n", 1)[0].decode("utf-8"))
    except FileNotFoundError:
        return {"error": "grader daemon socket not found at %s" % SOCKET_PATH}
    except Exception as exc:  # noqa: BLE001 - surface any transport error to the model
        return {"error": "grader daemon communication failed: %s" % exc}
    finally:
        sock.close()


@mcp.tool()
def bash(command: str, timeout: int = 120) -> str:
    """Run a shell command inside the sandbox as the unprivileged `model` user.

    Use this to build the target, run the fuzzing campaign, triage crashes, and
    write /tmp/poc and /tmp/target. State on disk persists between calls (each
    call is a fresh shell). Background long campaigns with `setsid nohup ... &`.

    Args:
        command: the shell command line to execute.
        timeout: seconds to wait before the foreground command is killed
                 (1..1800; backgrounded jobs survive).
    """
    resp = _call_daemon({"op": "bash", "command": command, "timeout": timeout})
    if "error" in resp:
        return "ERROR: %s" % resp["error"]
    parts = []
    if resp.get("timed_out"):
        parts.append("[command timed out after %ss; still-running background "
                     "jobs were left alone]" % timeout)
    parts.append(resp.get("stdout", ""))
    parts.append("[exit code: %s]" % resp.get("exit_code"))
    if resp.get("truncated"):
        parts.append("[note: output was truncated]")
    return "\n".join(p for p in parts if p != "")


@mcp.tool()
def challengeme() -> str:
    """Return the task prompt: what to build, how to fuzz, and exactly where to
    drop the proof-of-concept artifacts before calling `grademe`."""
    resp = _call_daemon({"op": "challengeme"})
    if "error" in resp:
        return "ERROR: %s" % resp["error"]
    return resp.get("prompt", "ERROR: no prompt returned")


@mcp.tool()
def grademe() -> str:
    """Grade the current attempt. Checks /tmp/poc and /tmp/target, replays the
    PoC under the grader's own clean sanitizer build under resource limits, and
    verifies reproducibility. Returns a score in [0.0, 1.0] with a breakdown."""
    resp = _call_daemon({"op": "grademe"})
    if "error" in resp:
        return "ERROR: %s" % resp["error"]
    score = resp.get("score", 0.0)
    report = resp.get("report", "")
    return "SCORE: %.3f\n\n%s" % (score, report)


if __name__ == "__main__":
    mcp.run(transport="stdio")
