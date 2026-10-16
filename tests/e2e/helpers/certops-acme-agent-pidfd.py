#!/usr/bin/env python3
"""Exact, already-idle native agent attachment. No numeric signaling/tree kill.

The real certificate outcome must exist independently before the JS owner asks
for this explicit restart stop. This is not proof of job cancellation or grace.
"""
import json
import os
import re
import select
import signal
import sys
import time


def identity(pid):
    with open(f"/proc/{pid}/stat", encoding="utf8") as stream:
        raw = stream.read(32769)
    fields = raw[raw.rfind(") ") + 2:].split()
    if len(raw) > 32768 or len(fields) < 20:
        raise ValueError("Bounded process identity required")
    return int(fields[1]), fields[19]


def children(pid):
    found = []
    for name in os.listdir("/proc"):
        if not name.isdecimal():
            continue
        try:
            parent, _ = identity(int(name))
        except FileNotFoundError:
            continue
        if parent == pid:
            found.append(int(name))
    return found


def send(value):
    os.write(1, (json.dumps(value, separators=(",", ":")) + "\n").encode())


def main():
    if sys.platform != "linux" or len(sys.argv) != 1:
        raise ValueError("Linux owned attachment required")
    raw = sys.stdin.buffer.readline(16385)
    if len(raw) > 16384 or not raw.endswith(b"\n"):
        raise ValueError("Bounded attachment input required")
    expected = json.loads(raw)
    if set(expected) != {"pid", "parentPid", "startTicks", "executable", "argvHex", "token"}:
        raise ValueError("Closed attachment input required")
    pid = expected["pid"]
    if type(pid) is not int or pid <= 1 or not re.fullmatch(r"[a-f0-9]{32}", expected["token"]):
        raise ValueError("Exact agent identity required")
    handle = os.pidfd_open(pid, 0)
    try:
        with open(f"/proc/self/fdinfo/{handle}", encoding="ascii") as stream:
            if not any(line.split() == ["Pid:", str(pid)] for line in stream):
                raise ValueError("Original retained pidfd required")
        parent, birth = identity(pid)
        with open(f"/proc/{pid}/cmdline", "rb") as stream:
            argv = stream.read(32769)
        if (parent != expected["parentPid"] or birth != expected["startTicks"]
                or argv != bytes.fromhex(expected["argvHex"])
                or os.readlink(f"/proc/{pid}/exe") != expected["executable"]
                or children(pid)):
            raise ValueError("Original idle agent identity required")
        signal.pidfd_send_signal(handle, 0)
        common = {"token": expected["token"], "pid": pid, "startTicks": birth}
        send({"kind": "agent-pidfd-attached", **common,
              "pidfdPinned": True, "noChildBeforeStop": True})
        deadline = time.monotonic() + 60
        command = b""
        while time.monotonic() < deadline:
            if select.select([handle], [], [], 0)[0]:
                raise ValueError("Agent exited before explicit restart stop")
            if select.select([0], [], [], 0.05)[0]:
                command = os.read(0, 4097)
                break
        if command != ("stop:" + expected["token"] + "\n").encode():
            raise ValueError("Explicit owned restart stop required")
        if identity(pid) != (parent, birth) or children(pid):
            raise ValueError("Agent spawned an unknown consumer before restart")
        # The only signal authority is the originally retained kernel handle.
        signal.pidfd_send_signal(handle, signal.SIGTERM)
        if not select.select([handle], [], [], 30)[0]:
            raise ValueError("Original agent did not exit after restart stop")
        end = time.monotonic() + 5
        while os.path.exists(f"/proc/{pid}") and time.monotonic() < end:
            time.sleep(0.025)
        # Parent must reap the exact original root. PID reuse is a refusal,
        # never an excuse to signal or adopt a different process.
        if os.path.exists(f"/proc/{pid}") or children(pid):
            raise ValueError("Original root/consumer drainage unconfirmed")
    finally:
        os.close(handle)
    send({"kind": "agent-pidfd-closed", **common, "rootExited": True,
          "noChildAfterStop": True, "pidfdClosed": True, "explicitRestartStop": True})


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.stderr.write("Owned agent restart attachment failed; preserve fixture.\n")
        sys.exit(1)
