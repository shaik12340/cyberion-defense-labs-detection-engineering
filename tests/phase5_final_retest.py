from pathlib import Path
import yaml
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

DATASET = Path("data/raw/EVTX-ATTACK-SAMPLES")
RULE_DIR = Path("rules")
OUTPUT = Path("reports/phase5_final_retest.md")

PRIMARY_RULES = sorted([
    p for p in RULE_DIR.glob("*.yml")
    if not p.name.startswith("base_")
    and not p.name.startswith("mr_")
])

def lname(tag):
    return tag.split("}", 1)[-1]

def get_event_id(root):
    for elem in root.iter():
        if lname(elem.tag) == "EventID":
            return (elem.text or "").strip()
    return ""

def get_data(root, name):
    for elem in root.iter():
        if lname(elem.tag) == "Data" and elem.attrib.get("Name") == name:
            return elem.text or ""
    return ""

def get_field(root, name):
    if name == "EventID":
        return get_event_id(root)
    return get_data(root, name)

def value_match(actual, expected):
    actual = str(actual or "").lower()

    if isinstance(expected, list):
        return any(value_match(actual, item) for item in expected)

    return actual == str(expected).lower()

def contains_match(actual, expected):
    actual = str(actual or "").lower()

    if isinstance(expected, list):
        return any(str(x).lower() in actual for x in expected)

    return str(expected).lower() in actual

def endswith_match(actual, expected):
    actual = str(actual or "").lower()

    if isinstance(expected, list):
        return any(
            actual.endswith(str(x).lower())
            for x in expected
        )

    return actual.endswith(str(expected).lower())

def event_matches(root, selection):
    for field, expected in selection.items():

        if "|" in field:
            field_name, modifier = field.split("|", 1)
        else:
            field_name = field
            modifier = None

        actual = get_field(root, field_name)

        if modifier == "contains":
            if not contains_match(actual, expected):
                return False

        elif modifier == "endswith":
            if not endswith_match(actual, expected):
                return False

        else:
            if not value_match(actual, expected):
                return False

    return True


# Load primary rules
rules = {}

for path in PRIMARY_RULES:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    detection = data.get("detection", {})
    selection = detection.get("selection")

    if isinstance(selection, dict):
        rules[path.name] = {
            "title": data.get("title", path.name),
            "selection": selection
        }

print("=== PHASE 5 FINAL RETEST — CORRECTED ===")
print(f"Primary rules: {len(rules)}")
print()

results = {
    name: {
        "matches": 0,
        "first_evidence": None
    }
    for name in rules
}

evtx_count = 0
event_count = 0
error_count = 0

for evtx_path in sorted(DATASET.rglob("*.evtx")):
    evtx_count += 1

    try:
        with Evtx(str(evtx_path)) as log:

            for record in log.records():
                event_count += 1

                try:
                    root = ET.fromstring(record.xml())
                except Exception:
                    continue

                for rule_name, rule in rules.items():

                    if event_matches(root, rule["selection"]):

                        results[rule_name]["matches"] += 1

                        if results[rule_name]["first_evidence"] is None:
                            results[rule_name]["first_evidence"] = {
                                "file": str(
                                    evtx_path.relative_to(DATASET)
                                ),
                                "event_id": get_event_id(root)
                            }

    except Exception as exc:
        error_count += 1
        print(
            f"[WARN] {evtx_path}: "
            f"{type(exc).__name__}: {exc}"
        )

matched = sum(
    1 for result in results.values()
    if result["matches"] > 0
)

print(f"EVTX files scanned: {evtx_count}")
print(f"Events scanned: {event_count}")
print(f"Files with errors: {error_count}")
print()

print("RULE RESULTS")
print("-" * 75)

for name, result in results.items():

    evidence = result["first_evidence"]

    if evidence:
        evidence_text = (
            f"{evidence['event_id']} — "
            f"{evidence['file']}"
        )
    else:
        evidence_text = "No match"

    print(
        f"{name:40} "
        f"matches={result['matches']:4} "
        f"{evidence_text}"
    )

print()
print(
    f"Summary: {matched}/{len(results)} "
    f"rules produced at least one match."
)

# Write report
lines = [
    "# Phase 5 — Final Rule Retest",
    "",
    "## Test Scope",
    "",
    "- Dataset: `EVTX-ATTACK-SAMPLES`",
    f"- EVTX files scanned: {evtx_count}",
    f"- Events scanned: {event_count}",
    f"- Primary Sigma rules tested: {len(results)}",
    f"- Files with parser errors: {error_count}",
    "",
    "## Final Retest Results",
    "",
    "| Rule | Matches | Evidence |",
    "|---|---:|---|"
]

for name, result in results.items():

    evidence = result["first_evidence"]

    if evidence:
        evidence_text = (
            f"{evidence['event_id']} — "
            f"`{evidence['file']}`"
        )
    else:
        evidence_text = "No match"

    lines.append(
        f"| {rules[name]['title']} | "
        f"{result['matches']} | {evidence_text} |"
    )

lines += [
    "",
    "## Summary",
    "",
    f"- Rules producing matches: **{matched}/{len(results)}**",
    f"- Rules without matches: **{len(results) - matched}**",
    f"- EVTX parser errors: **{error_count}**",
    "",
    "## Interpretation",
    "",
    "The final retest uses the EVTX EventID field explicitly and "
    "re-evaluates the primary Sigma selection logic against the "
    "same telemetry dataset used for baseline testing.",
]

OUTPUT.write_text(
    "\n".join(lines),
    encoding="utf-8"
)

print()
print(f"[PASS] Final retest report written to: {OUTPUT}")
