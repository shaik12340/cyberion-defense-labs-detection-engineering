from pathlib import Path
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
import yaml

DATASET = Path("data/raw/EVTX-ATTACK-SAMPLES")
RULE_DIR = Path("rules")
OUTPUT = Path("reports/phase5_baseline.md")


def local_name(tag):
    return tag.split("}", 1)[-1]


def get_field(event_root, field):
    for elem in event_root.iter():
        if local_name(elem.tag) == field:
            return elem.text or ""

    # Sysmon EventData fields
    for elem in event_root.iter():
        if local_name(elem.tag) == "Data":
            if elem.attrib.get("Name") == field:
                return elem.text or ""

    return ""


def get_event_id(event_root):
    value = get_field(event_root, "EventID")

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def value_matches(actual, expected, modifier):
    actual = str(actual or "")
    expected = str(expected)

    if modifier == "contains":
        return expected.lower() in actual.lower()

    if modifier == "endswith":
        return actual.lower().endswith(expected.lower())

    if modifier == "startswith":
        return actual.lower().startswith(expected.lower())

    # Plain Sigma field equality
    return actual.lower() == expected.lower()


def selection_matches(event_root, selection):
    event_id = get_event_id(event_root)

    if "EventID" in selection:
        expected = selection["EventID"]

        if isinstance(expected, list):
            if event_id not in [int(x) for x in expected]:
                return False
        else:
            if event_id != int(expected):
                return False

    for field, expected in selection.items():

        if field == "EventID":
            continue

        if "|" in field:
            field_name, modifier = field.split("|", 1)
        else:
            field_name = field
            modifier = "equals"

        actual = get_field(event_root, field_name)

        if isinstance(expected, list):
            if not any(
                value_matches(actual, item, modifier)
                for item in expected
            ):
                return False
        else:
            if not value_matches(actual, expected, modifier):
                return False

    return True


print("=== PHASE 5 — RULE TESTING BASELINE ===")
print()

evtx_files = sorted(DATASET.rglob("*.evtx"))

print(f"EVTX files found: {len(evtx_files)}")

if not evtx_files:
    raise SystemExit("[ERROR] No EVTX files found.")

rules = []

for rule_path in sorted(RULE_DIR.glob("*.yml")):

    # Correlation/base rules handled separately
    if rule_path.name.startswith("base_"):
        continue

    if rule_path.name.startswith("mr_"):
        continue

    rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))

    rules.append((rule_path, rule))

print(f"Primary rules loaded: {len(rules)}")
print()

results = []

for rule_path, rule in rules:

    detection = rule.get("detection", {})

    selections = {
        key: value
        for key, value in detection.items()
        if key not in {
            "condition",
            "timeframe",
            "near",
            "by",
            "group-by"
        }
    }

    matches = []

    for evtx_path in evtx_files:

        try:
            with Evtx(str(evtx_path)) as log:

                for record in log.records():

                    try:
                        root = ET.fromstring(record.xml())
                    except Exception:
                        continue

                    for selection_name, selection in selections.items():

                        if not isinstance(selection, dict):
                            continue

                        if selection_matches(root, selection):

                            event_id = get_event_id(root)

                            matches.append({
                                "file": str(evtx_path.relative_to(DATASET)),
                                "event_id": event_id,
                                "selection": selection_name
                            })

                            break

        except Exception as exc:
            print(
                f"[WARN] Could not parse {evtx_path}: "
                f"{type(exc).__name__}: {exc}"
            )

    unique_files = sorted({
        item["file"]
        for item in matches
    })

    result = {
        "rule": rule_path.name,
        "title": rule.get("title", ""),
        "technique": [
            tag.replace("attack.", "")
            for tag in rule.get("tags", [])
            if tag.startswith("attack.t")
        ],
        "level": rule.get("level", ""),
        "matches": len(matches),
        "evidence_files": len(unique_files),
        "sample": matches[0] if matches else None
    }

    results.append(result)

    if matches:
        sample = matches[0]

        print(
            f"[MATCH] {rule_path.name:<38} "
            f"matches={len(matches):<4} "
            f"event_id={sample['event_id']}"
        )
        print(
            f"         evidence={sample['file']}"
        )

    else:
        print(
            f"[NO MATCH] {rule_path.name}"
        )


print()
print("=== SUMMARY ===")

matched_rules = sum(
    1 for result in results
    if result["matches"] > 0
)

unmatched_rules = len(results) - matched_rules

print(f"Primary rules tested: {len(results)}")
print(f"Rules with matches: {matched_rules}")
print(f"Rules without matches: {unmatched_rules}")

OUTPUT.parent.mkdir(parents=True, exist_ok=True)

with OUTPUT.open("w", encoding="utf-8") as f:

    f.write("# Phase 5 — Rule Testing Baseline\n\n")

    f.write("## Dataset\n\n")
    f.write("- Dataset: EVTX-ATTACK-SAMPLES\n")
    f.write(f"- EVTX files: {len(evtx_files)}\n")
    f.write("- Parser: python-evtx\n")
    f.write("- Purpose: Pre-tuning detection baseline\n\n")

    f.write("## Primary Detection Results\n\n")

    f.write(
        "| Rule | ATT&CK | Severity | Matches | "
        "Evidence Files | Sample Event | Evidence |\n"
    )

    f.write(
        "|---|---|---|---:|---:|---:|---|\n"
    )

    for result in results:

        techniques = ", ".join(result["technique"])

        if result["sample"]:
            event_id = result["sample"]["event_id"]
            evidence = result["sample"]["file"]
        else:
            event_id = "-"
            evidence = "-"

        f.write(
            f"| {result['rule']} | {techniques} | "
            f"{result['level']} | {result['matches']} | "
            f"{result['evidence_files']} | {event_id} | "
            f"`{evidence}` |\n"
        )

    f.write("\n## Baseline Interpretation\n\n")

    f.write(
        "This baseline records detection matches against the "
        "EVTX-ATTACK-SAMPLES dataset before the Phase 5 "
        "false-positive review and tuning process. "
        "A match confirms that the rule condition was observed "
        "in the selected telemetry; it does not independently "
        "establish malicious intent.\n"
    )

print()
print(f"[CREATED] {OUTPUT}")
