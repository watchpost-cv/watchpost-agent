#!/bin/sh
# action-pins.sh scans every workflow file under .github/workflows/ (both *.yml
# and *.yaml) and rejects any external `uses:` reference that is not pinned to a
# full immutable 40-hex commit SHA.
#
# It uses a genuine YAML parser (PyYAML, present on the GitHub-hosted Ubuntu
# runners that execute these scans) and recursively walks the parsed document,
# validating every mapping key whose DECODED value is exactly the string `uses`
# — whether it appears as:
#   - a step-level action reference (`- uses: owner/action@ref`);
#   - a job-level reusable workflow reference
#     (`uses: owner/repo/.github/workflows/wf.yml@ref`);
#   - a single-quoted, double-quoted, or escaped quoted key;
#   - a flow-style mapping (`- { uses: owner/action@ref }`).
#
# Decoding quoted and escaped keys is done by the YAML parser itself, so no
# text-pattern enumeration is relied on as a security boundary.
#
# Rules:
#   - local repository actions (`uses: ./path`) are exempt;
#   - every external `uses:` reference must end in exactly 40 hexadecimal
#     characters;
#   - comments and multiline `run: |` block-scalar bodies are parsed by YAML
#     and never produce a `uses:` mapping, so they cannot create false
#     positives or conceal a reference;
#   - the scan fails if no workflow files exist;
#   - the scan FAILS CLOSED if PyYAML is unavailable, rather than risking a
#     mutable reference passing through an incomplete parser.
#
# A comment (e.g. `# v4.2.2`) after a reference is allowed and ignored.
#
# Usage: scripts/action-pins.sh [workflow-dir]
#   workflow-dir defaults to .github/workflows.
set -eu

dir=${1:-.github/workflows}
[ -d "$dir" ] || { echo "missing workflow directory $dir" >&2; exit 1; }

python3 - "$dir" <<'PY'
import os
import re
import sys

workflow_dir = sys.argv[1]

try:
    import yaml
except Exception as e:  # pragma: no cover - environmental
    sys.stderr.write(
        "action-pins FAILED CLOSED: PyYAML is unavailable and a genuine YAML "
        f"parser is required ({e})\n"
    )
    sys.exit(1)


def find_workflow_files(d):
    """Return every *.yml / *.yaml file under d, sorted."""
    files = []
    for name in sorted(os.listdir(d)):
        path = os.path.join(d, name)
        if os.path.isfile(path) and (name.endswith(".yml") or name.endswith(".yaml")):
            files.append(path)
    return files


def walk_and_validate(node, refs):
    """Recursively inspect every mapping key whose decoded value is `uses` and
    collect its reference value. Strings that appear only as values (e.g. block
    scalars) are never keys and are not treated as references."""
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(k, str) and k == "uses":
                if isinstance(v, str):
                    refs.append(v)
                else:
                    # A non-string `uses:` value is not a valid action reference.
                    refs.append("")
            else:
                walk_and_validate(v, refs)
    elif isinstance(node, list):
        for item in node:
            walk_and_validate(item, refs)


def validate_ref(value):
    if not isinstance(value, str):
        return False
    if value.startswith("./"):
        return True  # local repository action, exempt
    if "@" not in value:
        return False
    ref = value.rsplit("@", 1)[1]
    return bool(re.fullmatch(r"[0-9a-fA-F]{40}", ref))


files = find_workflow_files(workflow_dir)
if not files:
    sys.stderr.write(f"no workflow files found under {workflow_dir}\n")
    sys.exit(1)

bad = False
for wf in files:
    try:
        with open(wf, "r", encoding="utf-8", errors="replace") as f:
            doc = yaml.safe_load(f.read())
    except yaml.YAMLError as e:
        sys.stderr.write(f"{wf}: invalid YAML: {e}\n")
        bad = True
        continue

    refs = []
    walk_and_validate(doc, refs)
    # A workflow with no `uses:` references is valid: there is nothing to pin,
    # so the invariant holds vacuously. (Only an absence of workflow FILES is a
    # failure, enforced below.)
    for value in refs:
        if not validate_ref(value):
            sys.stderr.write(
                f"{wf}: action ref is not a full 40-hex SHA: {value!r}\n"
            )
            bad = True

if bad:
    sys.stderr.write(
        "action-pins scan FAILED: mutable or unpinned action references present\n"
    )
    sys.exit(1)

print(
    f"action-pins scan passed: every external action in {workflow_dir} is pinned to a full commit SHA"
)
PY