"""Stage and repack the exact Windows pilot archive without executing its contents."""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import tarfile


def load_sibling(filename):
    spec = importlib.util.spec_from_file_location(Path(filename).stem, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SBOM = load_sibling("agent-sbom-enrich.py")
BINDING = load_sibling("windows-release-artifact-binding.py")


def read_bounded(path, limit):
    entry = path.lstat()
    if not stat.S_ISREG(entry.st_mode) or entry.st_size <= 0 or entry.st_size > limit:
        raise ValueError("Pilot input must be a bounded regular file")
    if getattr(entry, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise ValueError("Pilot input must not be a reparse point")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
        if len(data) != entry.st_size:
            raise ValueError("Pilot input changed while reading")
        return data


def verified_members(archive, expected_sha, upstream):
    if hashlib.sha256(archive).hexdigest() != expected_sha:
        raise ValueError("Unsigned archive digest mismatch")
    baseline = json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": [],
        "metadata": {"component": {"type": "file", "version": "sha256:" + expected_sha}},
    }).encode()
    SBOM.enrich(archive, expected_sha, upstream, baseline, "amd64")

    members = []
    tar_end = 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as source:
        for member in source:
            if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE):
                raise ValueError("Pilot archive requires regular files and directories")
            name = BINDING._name(member.name, member.isdir())
            tar_end = member.offset_data + ((member.size + 511) // 512) * 512
            if member.isdir():
                members.append((name, member.mode, None))
                continue
            with source.extractfile(member) as entry:
                data = entry.read(member.size + 1)
            if len(data) != member.size:
                raise ValueError("Truncated entry in pilot archive")
            members.append((name, member.mode, data))
    BINDING._check_complete_stream(archive, tar_end)
    return members


def extract(members, stage):
    stage.mkdir()
    for name, _, data in members:
        target = stage.joinpath(*name.split("/"))
        if data is None:
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as output:
                output.write(data)


def repack(members, stage, signed_targets, output):
    target_names = {"package/" + name for name in signed_targets}
    if len(signed_targets) != 14 or len(target_names) != 14:
        raise ValueError("Pilot requires fourteen distinct signing targets")
    if not target_names <= {name for name, _, data in members if data is not None}:
        raise ValueError("Signing target absent from the unsigned archive")

    # Use only names and permissions present in the reviewed source archive.
    # Do not repackage extra files created by a tool in the signing directory.
    with output.open("xb") as destination, tarfile.open(fileobj=destination, mode="w:gz") as bundle:
        for name, mode, unsigned in members:
            member = tarfile.TarInfo(name)
            member.mode = mode & 0o777
            if unsigned is None:
                member.type = tarfile.DIRTYPE
                bundle.addfile(member)
                continue
            signed = read_bounded(stage.joinpath(*name.split("/")), BINDING.MAX_ARCHIVE)
            if (signed != unsigned) != (name in target_names):
                raise ValueError(f"Unexpected signing delta for {name}")
            member.size = len(signed)
            bundle.addfile(member, io.BytesIO(signed))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("extract", "repack"))
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--node-zip", type=Path, required=True)
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--signing-targets", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    members = verified_members(
        read_bounded(args.archive, BINDING.MAX_ARCHIVE),
        args.archive_sha256,
        read_bounded(args.node_zip, BINDING.MAX_ARCHIVE),
    )
    if args.operation == "extract":
        extract(members, args.stage)
    else:
        if args.output is None or args.signing_targets is None:
            parser.error("repack requires --output and --signing-targets")
        targets = json.loads(read_bounded(args.signing_targets, 16 * 1024))
        if not isinstance(targets, list) or not all(isinstance(item, str) for item in targets):
            raise ValueError("Invalid trusted signing-target list")
        repack(members, args.stage, targets, args.output)


if __name__ == "__main__":
    main()
