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
    environments = manifest.pop("environmentGroups", {})
    if not isinstance(environments, dict) or len(environments) > 512:
        raise ValueError("Invalid environment groups")
    for name, environment in environments.items():
        if (not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", name)
                or not isinstance(environment, dict) or not environment):
            raise ValueError("Invalid environment group")
    for slot in manifest.get("slots", []):
        if "environmentGroup" in slot:
            name = slot["environmentGroup"]
            if "environment" in slot or not isinstance(name, str) or name not in environments:
                raise ValueError("Conflicting or unknown environment group")
            slot["environment"] = copy.deepcopy(environments[name])
            del slot["environmentGroup"]
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


def load_groups(file):
    groups = json.loads(file.read_text())
    for definition in groups.values():
        if "requiredTestsByFile" not in definition:
            continue
        parts = definition.pop("requiredTestsByFile")
        if "requiredTests" in definition or not isinstance(parts, list) or not parts:
            raise ValueError("Conflicting case inventories")
        tests = []
        for part in parts:
            names, source = part.get("names"), part.get("file")
            if (source not in definition["files"] or not isinstance(names, list)
                    or not names or not all(isinstance(name, str) and name for name in names)):
                raise ValueError("Invalid mandatory case source or names")
            tests.extend({"file": source, "name": name} for name in names)
        if len({(row["file"], row["name"]) for row in tests}) != len(tests):
            raise ValueError("Duplicate mandatory case")
        definition["requiredTests"] = tests
    return groups
