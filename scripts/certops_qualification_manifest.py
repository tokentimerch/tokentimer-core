"""Expand shared source lists before inspecting report or candidate fingerprints."""
import copy
import json
import re


def expand(value):
    manifest = copy.deepcopy(value)
    groups = manifest.pop("sourceGroups", {})
    if not isinstance(groups, dict) or len(groups) > 512:
        raise ValueError("Invalid source groups")
    for name, sources in groups.items():
        if (not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", name)
                or not isinstance(sources, list) or not 0 < len(sources) <= 256
                or not all(isinstance(file, str) and file for file in sources)
                or len(set(sources)) != len(sources)):
            raise ValueError("Invalid source group")
    for slot in manifest.get("slots", []):
        if "requiredSourceGroup" not in slot:
            continue
        name = slot["requiredSourceGroup"]
        if "requiredSources" in slot or not isinstance(name, str) or name not in groups:
            raise ValueError("Conflicting or unknown source group")
        slot["requiredSources"] = list(groups[name])
        del slot["requiredSourceGroup"]
    return manifest


def load(file):
    return expand(json.loads(file.read_text()))
