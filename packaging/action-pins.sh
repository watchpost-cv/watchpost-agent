#!/bin/sh
# action-pins.sh scans every workflow file under .github/workflows/ (both *.yml
# and *.yaml) and rejects any external `uses:` reference that is not pinned to a
# full immutable 40-hex commit SHA.
#
# It inspects every YAML mapping key named `uses`, whether it is:
#   - a step-level action reference (`- uses: owner/action@ref`); or
#   - a job-level reusable workflow reference
#     (`uses: owner/repo/.github/workflows/wf.yml@ref`).
#
# Rules:
#   - local repository actions (`uses: ./path`) are exempt;
#   - every external `uses:` reference must end in exactly 40 hexadecimal
#     characters;
#   - indentation and optional YAML quoting are handled structurally;
#   - comments never conceal or satisfy a reference;
#   - `uses:` text inside a multiline `run: |` block scalar or a comment is
#     never treated as an active reference;
#   - the scan fails if no workflow files exist.
#
# A comment (e.g. `# v4.2.2`) after a reference is allowed and ignored.
#
# This uses a narrowly scoped YAML parser written in Python (available on the
# GitHub-hosted runners that execute these scans) so no third-party YAML
# dependency is required; block-scalar boundaries and quoting are handled
# explicitly.
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


def find_workflow_files(d):
    """Return every *.yml / *.yaml file under d, sorted."""
    files = []
    for name in sorted(os.listdir(d)):
        path = os.path.join(d, name)
        if os.path.isfile(path) and (name.endswith(".yml") or name.endswith(".yaml")):
            files.append(path)
    return files


def strip_comment(line):
    """Strip a trailing YAML comment, respecting single/double quotes."""
    in_single = False
    in_double = False
    i = 0
    while i < len(line):
        c = line[i]
        if c == "'" and not in_double:
            in_single = not in_single
        elif c == '"' and not in_single:
            in_double = not in_double
        elif c == "#" and not in_single and not in_double and (i == 0 or line[i - 1].isspace()):
            return line[:i]
        i += 1
    return line


def unquote(s):
    """Remove one layer of surrounding single or double quotes if present."""
    s = s.strip()
    if len(s) >= 2:
        if (s[0] == '"' and s[-1] == '"') or (s[0] == "'" and s[-1] == "'"):
            return s[1:-1]
    return s


def iter_uses_values(path):
    """Yield every active `uses:` value (key or `- uses:`) outside block scalars
    and comments. Structural: indentation tracks block-scalar scope so `uses:`
    text inside a multiline `run: |` body is not treated as a reference."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()

    # Block-scalar scope: while set, a line at greater indentation is literal
    # body (ignored). The scope closes at the first line at or above the key's
    # indentation (or EOF). Handles `key: |`, `key: >`, and their chomping
    # variants (`|-`, `|+`, `>-`, `>+`, with an optional explicit indent digit).
    block_indent = None
    block_owner = None

    for ln, raw in enumerate(lines, 1):
        # Skip a pure blank line (also terminates a block scalar? No: blank lines
        # inside a block scalar are body; handle by indentation rule below).
        stripped = raw.strip()
        if stripped == "":
            if block_indent is not None:
                # Blank lines inside a block scalar are still body and do not
                # close it. They are only meaningful once a non-blank line at a
                # lower indent appears, which the next non-blank iteration sees.
                pass
            continue

        indent = len(raw) - len(raw.lstrip(" "))
        content = raw[indent:]

        if block_indent is not None:
            if indent > block_indent:
                # Literal block body: never a workflow key.
                continue
            block_indent = None
            block_owner = None
            # Fall through: this line is at/above the block key indentation and
            # is a new YAML construct.

        content = strip_comment(content).rstrip()
        if content == "":
            continue

        # Match a mapping entry: optional sequence dash, then `key:`.
        m = re.match(r"^(?:-\s+)?([A-Za-z0-9_.-]+)\s*:\s*(.*)$", content)
        if not m:
            continue
        key, rest = m.group(1), m.group(2).strip()

        if key == "uses":
            yield unquote(rest), path, ln

        # Detect the start of a block scalar on any key (e.g. `run: |`).
        if re.search(r"[|>][+-]?[0-9]?$", rest):
            block_indent = indent
            block_owner = key


def validate_ref(value, path, ln):
    if value.startswith("./"):
        return True  # local repository action, exempt
    if "@" not in value:
        sys.stderr.write(f"{path}:{ln}: action has no ref: {value}\n")
        return False
    ref = value.rsplit("@", 1)[1]
    if not re.fullmatch(r"[0-9a-fA-F]{40}", ref):
        sys.stderr.write(
            f"{path}:{ln}: action ref is not a full 40-hex SHA: {value}\n"
        )
        return False
    return True


files = find_workflow_files(workflow_dir)
if not files:
    sys.stderr.write(f"no workflow files found under {workflow_dir}\n")
    sys.exit(1)

bad = False
for wf in files:
    for value, path, ln in iter_uses_values(wf):
        if not validate_ref(value, path, ln):
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