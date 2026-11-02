#!/usr/bin/env python3
"""Pin the already-running, still-armed qualification command by Linux pidfd.

This is not a launcher or process-group termination API. The actual production
agent owns the command. Only its independently identified root descriptor may
receive a signal; unknown group members prevent a drainage receipt. This uses
the same kernel interface as certops-acme-background-pidfd.py without changing
that controller's launch-before-exec contract.
"""
import hashlib
import json
import os
import re
import select
import signal
import stat
import sys
import time


def process_fields(raw):
    end = raw.rfind(") ")
    fields = raw[end + 2:].split()
    if end <= 0 or not re.match(r"^[1-9][0-9]* \(", raw) or len(fields) < 20:
        raise ValueError("Incomplete owned process identity")
    if not re.fullmatch(r"[1-9][0-9]*", fields[19]):
        raise ValueError("Owned process birth required")
    return {"parentPid": int(fields[1]), "processGroup": int(fields[2]),
            "startTicks": fields[19]}


def read_owned_file(expected):
    """Read only the original, bounded regular file through its descriptor."""
    flags = os.O_RDONLY | os.O_NOFOLLOW
    fd = os.open(expected["path"], flags)
    try:
        before = os.fstat(fd)
        if not (stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_ino > 0 and stat.S_IMODE(before.st_mode) == 0o600
                and before.st_uid == os.getuid()
                and str(before.st_dev) == expected["dev"]
                and str(before.st_ino) == expected["ino"]
                and before.st_size <= 8192):
            raise ValueError("Owned file identity refused")
        data = os.read(fd, 8193)
        after = os.fstat(fd)
        current = os.lstat(expected["path"])
        if (len(data) != before.st_size or
                (before.st_dev, before.st_ino, before.st_size,
                 before.st_mtime_ns, before.st_ctime_ns) !=
                (after.st_dev, after.st_ino, after.st_size,
                 after.st_mtime_ns, after.st_ctime_ns) or
                (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)
                or hashlib.sha256(data).hexdigest() != expected["sha256"]):
            raise ValueError("Owned file changed")
        return json.loads(data)
    finally:
        os.close(fd)


def group_members(group):
    result = []
    for entry in os.listdir("/proc"):
        if not entry.isdecimal():
            continue
        try:
            with open(f"/proc/{entry}/stat", encoding="utf8") as stream:
                identity = process_fields(stream.read())
        except FileNotFoundError:
            continue
        # Inaccessible process identity is not evidence of an empty group.
        if identity["processGroup"] == group:
            result.append(int(entry))
    return sorted(result)


def send(value):
    os.write(1, (json.dumps(value, separators=(",", ":")) + "\n").encode())


def main():
    if sys.platform != "linux" or len(sys.argv) != 1:
        raise ValueError("Linux owned command attachment required")
    raw = sys.stdin.buffer.readline(16385)
    if len(raw) > 16384 or not raw.endswith(b"\n"):
        raise ValueError("Bounded attachment manifest required")
    expected = json.loads(raw)
    pid = expected["pid"]
    if (type(pid) is not int or pid <= 1 or expected["processGroup"] != pid
            or not re.fullmatch(r"[a-f0-9-]{36}", expected["token"])):
        raise ValueError("Owned root identity required")
    # Pin FIRST, then independently inspect identity. PID reuse between the
    # manifest and this open can only cause refusal, never authorize a signal.
    handle = os.pidfd_open(pid, 0)
    try:
        with open(f"/proc/self/fdinfo/{handle}", encoding="ascii") as stream:
            if not any(line.split() == ["Pid:", str(pid)] for line in stream):
                raise ValueError("Retained process descriptor refused")
        with open(f"/proc/{pid}/stat", encoding="utf8") as stream:
            identity = process_fields(stream.read())
        if identity != {key: expected[key] for key in identity}:
            raise ValueError("Owned process birth refused")
        with open(f"/proc/{pid}/cmdline", "rb") as stream:
            argv = stream.read(32769)
        if (len(argv) > 32768 or argv != bytes.fromhex(expected["argvHex"])
                or os.readlink(f"/proc/{pid}/exe") != expected["executable"]
                or group_members(pid) != [pid]):
            raise ValueError("Owned command identity refused")
        arm = read_owned_file(expected["arm"])
        receipt = read_owned_file(expected["receipt"])
        if arm.get("token") != expected["token"] or any(
                receipt.get(key) != expected[key]
                for key in ["token", "pid", "parentPid", "processGroup", "startTicks"]):
            raise ValueError("Owned barrier refused")
        signal.pidfd_send_signal(handle, 0)
        send({"kind": "lease-pidfd-attached", "token": expected["token"],
              "pid": pid, "startTicks": identity["startTicks"],
              "pidfdPinned": True, "initialGroupRootOnly": True})
        deadline = time.monotonic() + 120
        stopping = False
        used = False
        while not select.select([handle], [], [], 0.05)[0]:
            ready, _, _ = select.select([0], [], [], 0)
            if ready:
                command = os.read(0, 4097)
                if command not in [b"", ("stop:" + expected["token"] + "\n").encode()]:
                    raise ValueError("Owned attachment control refused")
                stopping = True
            if time.monotonic() >= deadline:
                stopping = True
            if stopping and not used:
                # No numeric PID or PGID is ever a signal target.
                try:
                    signal.pidfd_send_signal(handle, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                used = True
        # pidfd readability precedes the real owning parent's wait/reap. Give
        # that parent a bounded chance to reap the exited root, without
        # treating a zombie as a live process or signaling any group member.
        reap_deadline = time.monotonic() + 5
        members = group_members(pid)
        while members == [pid] and time.monotonic() < reap_deadline:
            time.sleep(0.05)
            members = group_members(pid)
        if members:
            raise ValueError("Unknown group consumer remains; preserve fixture")
        # Keep both public ownership files intact until the JS owner receives
        # this receipt AND observes this controller's actual close event.
        read_owned_file(expected["arm"])
        read_owned_file(expected["receipt"])
    finally:
        os.close(handle)
    send({"kind": "lease-pidfd-closed", "token": expected["token"],
          "pid": pid, "startTicks": expected["startTicks"],
          "rootExited": True, "groupEmpty": True, "pidfdClosed": True,
          "pidfdSignalUsed": used})


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Never print argv, manifest, environment, credentials or file bytes.
        sys.stderr.write("Owned command attachment failed; preserve fixture.\n")
        sys.exit(1)
