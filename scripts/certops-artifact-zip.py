"""Read bounded artifact members through Python's CRC/overlap-checked ZIP reader."""
import base64
import io
import json
import re
import stat
import sys
import zipfile

LIMIT = 24 * 1024 * 1024

try:
    data = sys.stdin.buffer.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError()
    result = {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if not 0 < len(entries) <= 8:
            raise ValueError()
        total = 0
        for entry in entries:
            total += entry.file_size
            if (entry.filename != entry.orig_filename or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,127}", entry.filename)
                    or entry.filename in result or entry.flag_bits & 1 or entry.is_dir()
                    or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                    or stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFREG)
                    or entry.file_size > LIMIT or entry.compress_size > LIMIT or total > LIMIT):
                raise ValueError()
            with archive.open(entry) as stream:
                member = stream.read(entry.file_size + 1)
            if len(member) != entry.file_size:
                raise ValueError()
            result[entry.filename] = base64.b64encode(member).decode("ascii")
    sys.stdout.write(json.dumps(result, separators=(",", ":")))
except Exception:
    sys.stderr.write("CERTOPS_ARTIFACT_ZIP_REJECTED\n")
    sys.exit(1)
