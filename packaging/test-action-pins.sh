#!/bin/sh
# test-action-pins.sh proves scripts/action-pins.sh rejects every class of
# mutable or unpinned action reference while accepting pinned references,
# job-level reusable workflows, local actions, comments and block scalars. It
# never modifies the real workflow files; fixtures are built under mktemp.
set -eu
cd "$(dirname "$0")/.."

V=packaging/action-pins.sh

# Working fixtures dir: files are copied/mutated here, never the real repo.
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

# --- Negative fixtures -----------------------------------------------------
mk_step_v4() {
  cat > "$1" <<'EOF'
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
EOF
}
mk_step_branch() {
  cat > "$1" <<'EOF'
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
EOF
}
mk_step_short_sha() {
  cat > "$1" <<'EOF'
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@abcd1234
EOF
}
mk_step_no_ref() {
  cat > "$1" <<'EOF'
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout
EOF
}
mk_job_main() {
  cat > "$1" <<'EOF'
name: test
on: push
jobs:
  delegated:
    uses: attacker/example/.github/workflows/reusable.yml@main
EOF
}
mk_job_v1() {
  cat > "$1" <<'EOF'
name: test
on: push
jobs:
  delegated:
    uses: owner/repo/.github/workflows/wf.yml@v1
EOF
}
mk_yaml_mutable() {
  # A *.yaml workflow with a step-level mutable tag.
  cat > "$1" <<'EOF'
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-go@v5
EOF
}

# --- Positive fixtures -----------------------------------------------------
mk_step_pinned() {
  cat > "$1" <<'EOF'
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
EOF
}
mk_job_pinned() {
  cat > "$1" <<'EOF'
name: test
on: push
jobs:
  delegated:
    uses: owner/repo/.github/workflows/wf.yml@3d3c42e5aac5ba805825da76410c181273ba90b1
EOF
}
mk_local() {
  cat > "$1" <<'EOF'
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/local
      - run: echo hi
EOF
}
mk_comments_and_blocks() {
  # Comments and block-scalar bodies containing fake `uses:` strings must not
  # be treated as active workflow references; pinned step and job refs are
  # accepted alongside them.
  cat > "$1" <<'EOF'
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
}
mk_yaml_pinned() {
  cat > "$1" <<'EOF'
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-go@0a12ed9d6a96ab950c8f026ed9f722fe0da7ef32
EOF
}

# --- Run negative cases ----------------------------------------------------
mk_step_v4 "$STAGE/neg1.yml";         run_scan 1 "step-level major-version tag v4"        neg1.yml
mk_step_branch "$STAGE/neg2.yml";     run_scan 1 "step-level branch name"                 neg2.yml
mk_step_short_sha "$STAGE/neg3.yml";  run_scan 1 "step-level short SHA"                   neg3.yml
mk_step_no_ref "$STAGE/neg4.yml";     run_scan 1 "step-level missing ref"                 neg4.yml
mk_job_main "$STAGE/neg5.yml";        run_scan 1 "job-level reusable workflow @main"      neg5.yml
mk_job_v1 "$STAGE/neg6.yml";          run_scan 1 "job-level reusable workflow version tag" neg6.yml
mk_yaml_mutable "$STAGE/neg7.yaml";   run_scan 1 "mutable reference in a .yaml file"      neg7.yaml

# --- Run positive cases ----------------------------------------------------
mk_step_pinned "$STAGE/pos1.yml";         run_scan 0 "step-level external action pinned 40 hex"     pos1.yml
mk_job_pinned "$STAGE/pos2.yml";          run_scan 0 "job-level reusable workflow pinned 40 hex"    pos2.yml
mk_local "$STAGE/pos3.yml";               run_scan 0 "local uses: ./path"                           pos3.yml
mk_comments_and_blocks "$STAGE/pos4.yml"; run_scan 0 "comments and block-scalar fake uses ignored"   pos4.yml
mk_yaml_pinned "$STAGE/pos5.yaml";        run_scan 0 "pinned step-level action in a .yaml file"      pos5.yaml

echo "action-pins negative and positive tests: PASS"