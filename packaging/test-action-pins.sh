#!/bin/sh
# test-action-pins.sh proves scripts/action-pins.sh rejects every class of
# mutable or unpinned action reference while accepting pinned references,
# job-level reusable workflows, local actions, comments and block scalars. It
# never modifies the real workflow files; fixtures are built under mktemp.
set -eu
cd "$(dirname "$0")/.."

V=packaging/action-pins.sh

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/.github/workflows"
WF="$tmp/.github/workflows"
STAGE="$tmp/stage"
mkdir -p "$STAGE"

# --- Helpers ---------------------------------------------------------------
run_scan() {
  # run_scan <expect_exit> <name> [files...]
  expect=$1
  name=$2
  shift 2
  rm -rf "$WF"/*.yml "$WF"/*.yaml
  for f in "$@"; do cp "$STAGE/$f" "$WF/"; done
  if [ "$expect" -eq 0 ]; then
    "$V" "$WF" >/dev/null 2>&1 || { echo "FAIL: accepted fixture rejected: $name" >&2; exit 1; }
  else
    if "$V" "$WF" >/dev/null 2>&1; then
      echo "FAIL: mutable reference accepted: $name" >&2
      exit 1
    fi
  fi
  echo "ok: $name"
}

# --- Negative fixtures (mutable / unpinned) --------------------------------
# Each must be rejected. Fixture names below are staged under $STAGE.

# 1. Single-quoted step-level uses key.
cat > "$STAGE/neg_quoted.yml" <<'EOF'
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - 'uses': actions/checkout@v4
EOF

# 2. Double-quoted step-level uses key.
cat > "$STAGE/neg_doublequoted.yml" <<'EOF'
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - "uses": actions/checkout@v4
EOF

# 3. Flow-style step mapping.
cat > "$STAGE/neg_flow_step.yml" <<'EOF'
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - { uses: actions/checkout@v4 }
EOF

# 4. Quoted job-level reusable-workflow uses.
cat > "$STAGE/neg_job_quoted.yml" <<'EOF'
name: test
on: push
jobs:
  delegated:
    'uses': attacker/example/.github/workflows/reusable.yml@main
EOF

# 5. Flow-style job-level reusable-workflow mapping.
cat > "$STAGE/neg_job_flow.yml" <<'EOF'
name: test
on: push
jobs:
  delegated: { uses: attacker/example/.github/workflows/reusable.yml@main }
EOF

# 6. Double-quoted escaped key that YAML decodes to `uses` (\u0075 uses...).
cat > "$STAGE/neg_escaped.yml" <<'EOF'
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - "u\u0073es": actions/checkout@v4
EOF

# 7. Step-level plain mutable tag (regression).
cat > "$STAGE/neg_plain_v4.yml" <<'EOF'
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
EOF

# 8. Step-level branch name (regression).
cat > "$STAGE/neg_branch.yml" <<'EOF'
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
EOF

# 9. Step-level short SHA (regression).
cat > "$STAGE/neg_short.yml" <<'EOF'
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@abcd1234
EOF

# 10. Missing ref (regression).
cat > "$STAGE/neg_noref.yml" <<'EOF'
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout
EOF

# 11. Job-level plain @main (regression).
cat > "$STAGE/neg_job_main.yml" <<'EOF'
name: test
on: push
jobs:
  delegated:
    uses: attacker/example/.github/workflows/reusable.yml@main
EOF

# 12. Job-level version tag (regression).
cat > "$STAGE/neg_job_v1.yml" <<'EOF'
name: test
on: push
jobs:
  delegated:
    uses: owner/repo/.github/workflows/wf.yml@v1
EOF

# 13. Mutable reference in a .yaml file.
cat > "$STAGE/neg_yaml.yaml" <<'EOF'
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-go@v5
EOF

# 14. Flow-style step mapping with a pinned-look ref but non-hex (mutable).
cat > "$STAGE/neg_flow_short.yml" <<'EOF'
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - { uses: actions/checkout@abcd }
EOF

# --- Positive fixtures (must be accepted) ----------------------------------

# 15. Pinned step-level action, plain key.
cat > "$STAGE/pos_plain_pinned.yml" <<'EOF'
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
EOF

# 16. Pinned step-level action, quoted key.
cat > "$STAGE/pos_quoted_pinned.yml" <<'EOF'
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - 'uses': actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
EOF

# 17. Pinned step-level action, flow mapping.
cat > "$STAGE/pos_flow_pinned.yml" <<'EOF'
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - { uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 }
EOF

# 18. Pinned job-level reusable workflow, quoted key.
cat > "$STAGE/pos_job_quoted_pinned.yml" <<'EOF'
name: test
on: push
jobs:
  delegated:
    'uses': owner/repo/.github/workflows/wf.yml@3d3c42e5aac5ba805825da76410c181273ba90b1
EOF

# 19. Pinned job-level reusable workflow, flow mapping.
cat > "$STAGE/pos_job_flow_pinned.yml" <<'EOF'
name: test
on: push
jobs:
  delegated: { uses: owner/repo/.github/workflows/wf.yml@3d3c42e5aac5ba805825da76410c181273ba90b1 }
EOF

# 20. Local actions remain accepted.
cat > "$STAGE/pos_local.yml" <<'EOF'
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/local
      - run: echo hi
EOF

# 21. Comments and block scalars containing fake `uses:` must not create
#     false positives; a real pinned ref alongside is accepted.
cat > "$STAGE/pos_comments_blocks.yml" <<'EOF'
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # uses: attacker/evil@main
      - run: |
          echo "uses: attacker/example@v4"
          uses: fake/thing@main
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
  delegated:
    uses: owner/repo/.github/workflows/wf.yml@3d3c42e5aac5ba805825da76410c181273ba90b1
EOF

# 22. Pinned .yaml file.
cat > "$STAGE/pos_yaml_pinned.yaml" <<'EOF'
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-go@0a12ed9d6a96ab950c8f026ed9f722fe0da7ef32
EOF

# --- Run negative cases ----------------------------------------------------
run_scan 1 "single-quoted step-level uses"     neg_quoted.yml
run_scan 1 "double-quoted step-level uses"     neg_doublequoted.yml
run_scan 1 "flow-style step mapping"           neg_flow_step.yml
run_scan 1 "quoted job-level reusable uses"    neg_job_quoted.yml
run_scan 1 "flow-style job-level reusable"     neg_job_flow.yml
run_scan 1 "double-quoted escaped uses key"    neg_escaped.yml
run_scan 1 "plain step-level v4"               neg_plain_v4.yml
run_scan 1 "step-level branch name"            neg_branch.yml
run_scan 1 "step-level short SHA"              neg_short.yml
run_scan 1 "step-level missing ref"            neg_noref.yml
run_scan 1 "job-level plain @main"             neg_job_main.yml
run_scan 1 "job-level version tag"             neg_job_v1.yml
run_scan 1 "mutable reference in .yaml"        neg_yaml.yaml
run_scan 1 "flow-style step short SHA"         neg_flow_short.yml

# --- Run positive cases ----------------------------------------------------
run_scan 0 "pinned plain step action"          pos_plain_pinned.yml
run_scan 0 "pinned quoted step action"         pos_quoted_pinned.yml
run_scan 0 "pinned flow step action"           pos_flow_pinned.yml
run_scan 0 "pinned quoted job reusable"        pos_job_quoted_pinned.yml
run_scan 0 "pinned flow job reusable"          pos_job_flow_pinned.yml
run_scan 0 "local uses: ./path"                pos_local.yml
run_scan 0 "comments and block scalars ignored" pos_comments_blocks.yml
run_scan 0 "pinned action in .yaml"            pos_yaml_pinned.yaml

# --- No-workflow failure ---------------------------------------------------
rm -rf "$WF"/*.yml "$WF"/*.yaml
if "$V" "$WF" >/dev/null 2>&1; then
  echo "FAIL: scan succeeded with no workflow files" >&2
  exit 1
fi
echo "ok: no-workflow failure"

# A workflow with no uses: references at all is valid and accepted (nothing to pin).
cat > "$STAGE/pos_nouses.yml" <<'EOF'
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
      - run: make test
EOF
cp "$STAGE/pos_nouses.yml" "$WF/"
if ! "$V" "$WF" >/dev/null 2>&1; then
  echo "FAIL: workflow with no uses rejected" >&2
  exit 1
fi
echo "ok: workflow with no uses accepted"

echo "action-pins negative and positive tests: PASS"