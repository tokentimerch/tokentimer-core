"""Expand shared source lists before inspecting report or candidate fingerprints."""
import copy
import json
import re


def expand(value):
    manifest = copy.deepcopy(value)
    test_groups = manifest.pop("testGroups", {})
    if not isinstance(test_groups, dict) or len(test_groups) > 512:
        raise ValueError("Invalid test groups")
    for name, tests in test_groups.items():
        if (not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", name)
                or not isinstance(tests, list) or not 0 < len(tests) <= 256
                or not all(isinstance(test, str) and test for test in tests)
                or len(set(tests)) != len(tests)):
            raise ValueError("Invalid test group")
    if "slots" in manifest:
        if not isinstance(manifest["slots"], list) or len(manifest["slots"]) > 512:
            raise ValueError("Invalid slots")
        slots = []
        for slot in manifest["slots"]:
            if "environmentVariants" not in slot:
                slots.append(slot)
                continue
            variants = slot.pop("environmentVariants")
            if (any(key in slot for key in ("id", "environment", "environmentGroup"))
                    or not isinstance(variants, dict) or not 0 < len(variants) <= 512):
                raise ValueError("Invalid or conflicting slot variants")
            for name, environment in variants.items():
                if (not isinstance(name, str) or not 0 < len(name) <= 128
                        or not isinstance(environment, str)):
                    raise ValueError("Invalid slot variant")
                slots.append({**copy.deepcopy(slot), "id": name, "environmentGroup": environment})
        ids = [slot["id"] for slot in slots if "id" in slot]
        if len(slots) > 512 or len(set(ids)) != len(ids):
            raise ValueError("Duplicate or oversized slots")
        manifest["slots"] = slots
    capability_groups = manifest.pop("capabilityGroups", {})
    if not isinstance(capability_groups, dict) or len(capability_groups) > 512:
        raise ValueError("Invalid capability groups")
    for name, entries in capability_groups.items():
        if (not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", name)
                or not isinstance(entries, list) or not 0 < len(entries) <= 256
                or not all(isinstance(entry, str) and entry for entry in entries)
                or len(set(entries)) != len(entries)):
            raise ValueError("Invalid capability group")
    definitions = manifest.pop("suiteDefinitions", None)
    if "suiteDefinitions" in value:
        if not isinstance(definitions, dict) or not 0 < len(definitions) <= 512:
            raise ValueError("Invalid suite definitions")
        for field in ("suites", "requiredCapabilities", "suiteEvidenceLevels"):
            if field in manifest:
                raise ValueError("Conflicting suite declarations")
            manifest[field] = {}
        levels = manifest.setdefault("scenarioEvidenceLevels", {})
        if not isinstance(levels, dict):
            raise ValueError("Invalid scenario classifications")
        for name, definition in definitions.items():
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", name):
                raise ValueError("Invalid suite name")
            if not isinstance(definition, dict):
                raise ValueError("Invalid suite definition")
            scenarios, capabilities = definition.get("scenarios"), definition.get("capabilities")
            if "capabilityGroup" in definition:
                name_ref = definition["capabilityGroup"]
                if "capabilities" in definition or not isinstance(name_ref, str) or name_ref not in capability_groups:
                    raise ValueError("Conflicting or unknown capability group")
                capabilities = list(capability_groups[name_ref])
            for entries in (scenarios, capabilities):
                if (not isinstance(entries, list) or not entries
                        or not all(isinstance(entry, str) and entry for entry in entries)
                        or len(set(entries)) != len(entries)):
                    raise ValueError("Invalid suite obligations")
            suite_level, default = definition.get("evidenceLevel"), definition.get("scenarioEvidenceLevel", definition.get("evidenceLevel"))
            valid = ("unit", "integration", "real-host", "e2e")
            overrides = definition.get("scenarioEvidenceOverrides", {})
            if (suite_level not in valid[1:] or default not in valid
                    or not isinstance(overrides, dict) or name in levels
                    or any(key not in scenarios or level not in valid for key, level in overrides.items())):
                raise ValueError("Invalid or conflicting scenario classifications")
            manifest["suites"][name] = scenarios
            manifest["requiredCapabilities"][name] = capabilities
            manifest["suiteEvidenceLevels"][name] = suite_level
            levels[name] = {key: overrides.get(key, default) for key in scenarios}
    groups = manifest.pop("sourceGroups", {})
    if not isinstance(groups, dict) or len(groups) > 512:
        raise ValueError("Invalid source groups")
    for name in groups:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", name):
            raise ValueError("Invalid source group")
    resolved = {}

    def sources_for(name, visiting):
        if len(visiting) >= 32:
            raise ValueError("Source group nesting exceeds bounds")
        if name not in groups or name in visiting:
            raise ValueError("Unknown or cyclic source group")
        if name not in resolved:
            resolved[name] = expand_sources(groups[name], visiting | {name})
        return resolved[name]

    def expand_sources(sources, visiting=frozenset()):
        if not isinstance(sources, list) or not 0 < len(sources) <= 256:
            raise ValueError("Invalid source group")
        result = []
        for source in sources:
            if isinstance(source, str) and source:
                result.append(source)
            elif isinstance(source, dict) and set(source) == {"sourceGroup"} and isinstance(source["sourceGroup"], str):
                result.extend(sources_for(source["sourceGroup"], visiting))
            else:
                raise ValueError("Invalid source obligation")
        if len(result) > 256 or len(set(result)) != len(result):
            raise ValueError("Duplicate or oversized source obligations")
        return result

    for name in groups:
        sources_for(name, frozenset())
    environments = manifest.pop("environmentGroups", {})
    if not isinstance(environments, dict) or len(environments) > 512:
        raise ValueError("Invalid environment groups")
    for name, environment in environments.items():
        if (not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", name)
                or not isinstance(environment, dict) or not environment):
            raise ValueError("Invalid environment group")
    for slot in manifest.get("slots", []):
        if "requiredTestGroup" in slot:
            name = slot["requiredTestGroup"]
            if "requiredTests" in slot or not isinstance(name, str) or name not in test_groups:
                raise ValueError("Conflicting or unknown test group")
            slot["requiredTests"] = list(test_groups[name])
            del slot["requiredTestGroup"]
        if "environmentGroup" in slot:
            name = slot["environmentGroup"]
            if "environment" in slot or not isinstance(name, str) or name not in environments:
                raise ValueError("Conflicting or unknown environment group")
            slot["environment"] = copy.deepcopy(environments[name])
            del slot["environmentGroup"]
        if "requiredSources" in slot:
            slot["requiredSources"] = expand_sources(slot["requiredSources"])
        if "requiredSourceGroup" not in slot:
            continue
        name = slot["requiredSourceGroup"]
        if "requiredSources" in slot or not isinstance(name, str) or name not in groups:
            raise ValueError("Conflicting or unknown source group")
        slot["requiredSources"] = list(sources_for(name, frozenset()))
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
