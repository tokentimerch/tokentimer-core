#!/usr/bin/env python3
"""Retain a Linux pidfd before the owned production runner can execute.

The forked child stops itself before exec. Only the retained pidfd receives
CONT/TERM. The parent never signals a numeric PID or substitutes a sweep.
Control uses a private inherited stdin pipe; raw environment is never persisted.
An unresponsive worker leaves this controller and its handle alive so parent
cleanup cannot pretend drainage. EOF also requests genuine graceful shutdown.
"""
import json
import os
import select
import signal
import sys
import time

OWNED = {"handle": None, "child": None, "waited": False}


def send(value):
    os.write(1, (json.dumps(value, separators=(",", ":")) + "\n").encode())


def main():
    node, entry, nonce = sys.argv[1:]
    assert sys.platform == "linux" and os.path.isabs(node) and os.path.isabs(entry)
    assert len(nonce) == 32 and all(c in "0123456789abcdef" for c in nonce)
    assert hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal")
    # Probe the actual kernel ABI before creating any stopped child. Signal0
    # checks the retained descriptor without delivering a native signal.
    probe = os.pidfd_open(os.getpid(), 0)
    try:
        signal.pidfd_send_signal(probe, 0)
    finally:
        os.close(probe)
    child = os.fork()
    if child == 0:
        os.close(0)
        signal.raise_signal(signal.SIGSTOP)
        os.execve(node, [node, entry, "certops"], dict(os.environ))
        os._exit(127)
    OWNED["child"] = child
    handle = os.pidfd_open(child, 0)
    OWNED["handle"] = handle
    stopped, status = os.waitpid(child, os.WUNTRACED)
    assert stopped == child and os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGSTOP
    fdinfo = open(f"/proc/self/fdinfo/{handle}", encoding="ascii").read().splitlines()
    assert any(line.split()==["Pid:",str(child)] for line in fdinfo)
    raw = open(f"/proc/{child}/stat", encoding="utf8").read()
    fields = raw[raw.rfind(") ")+2:].split()
    assert int(fields[1]) == os.getpid() and int(fields[2]) == os.getpgrp() and int(fields[3]) == os.getsid(0)
    send({"kind":"certops-acme-worker-pidfd-ready","nonce":nonce,"wrapperPid":os.getpid(),"workerPid":child,"parentPid":int(fields[1]),"birth":fields[19],"groupId":int(fields[2]),"sessionId":int(fields[3]),"pidfdPinnedBeforeExec":True})
    started = False
    stopping = False
    def stop(*_):
        nonlocal stopping
        if stopping:
            return
        stopping = True
        try:
            signal.pidfd_send_signal(handle, signal.SIGTERM)
            if not started:
                signal.pidfd_send_signal(handle, signal.SIGCONT)
        except ProcessLookupError:
            pass
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    deadline = time.monotonic()+30
    buffer = b""
    while True:
        found, status = os.waitpid(child, os.WNOHANG)
        if found:
            assert found == child
            OWNED["waited"] = True
            code = os.waitstatus_to_exitcode(status)
            os.close(handle)
            OWNED["handle"] = None
            send({"kind":"certops-acme-worker-pidfd-closed","nonce":nonce,"wrapperPid":os.getpid(),"workerPid":child,"rootExitCode":code,"pidfdSignalUsed":stopping,"pidfdClosed":True,"workerWaited":True})
            return 0 if code == 0 else 1
        if not started and time.monotonic()>deadline:
            stop()
        ready, _, _ = select.select([0] if not stopping else [], [], [], 0.1)
        if ready:
            chunk = os.read(0,4096)
            if not chunk:
                stop()
                continue
            buffer += chunk
            assert len(buffer) <= 8192
            while b"\n" in buffer:
                command, buffer = buffer.split(b"\n",1)
                if command == ("start:"+nonce).encode() and not started and not stopping:
                    started = True
                    signal.pidfd_send_signal(handle, signal.SIGCONT)
                elif command == ("stop:"+nonce).encode():
                    stop()
                else:
                    stop()
                    raise ValueError("Unexpected owned worker control")
        if started and time.monotonic()>deadline+480:
            stop()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        handle, child = OWNED["handle"], OWNED["child"]
        if child is not None and not OWNED["waited"]:
            # An unavailable pidfd never authorizes numeric signaling. Preserve
            # this controller/child rather than abandon an unknown native owner.
            if handle is None:
                while True:
                    time.sleep(1)
            try:
                signal.pidfd_send_signal(handle, signal.SIGTERM)
                signal.pidfd_send_signal(handle, signal.SIGCONT)
            except ProcessLookupError:
                pass
            _, status = os.waitpid(child, 0)
            OWNED["waited"] = True
            os.close(handle)
            OWNED["handle"] = None
            send({"kind":"certops-acme-worker-pidfd-closed","nonce":sys.argv[3],"wrapperPid":os.getpid(),"workerPid":child,"rootExitCode":os.waitstatus_to_exitcode(status),"pidfdSignalUsed":True,"pidfdClosed":True,"workerWaited":True})
        # No private environment or raw worker output enters failure diagnostics.
        sys.stderr.write("Owned pidfd worker controller failed; preserve fixture.\n")
        sys.exit(1)
