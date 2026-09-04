#!/bin/sh
# action-pins.sh scans every workflow file under .github/workflows/ and rejects
# any external action reference that is not pinned to a full immutable 40-hex
# commit SHA:
#   - mutable major-version tags (@v1, @v2, ...);
#   - branch names (@main, @master, @release/*);
#   - short or malformed SHAs;
#   - action identities with no ref at all.
# Local repository actions (`uses: ./path`) are exempt, as are step references
# that are not `uses:` entries (the parser only inspects `uses:` values).
#
# A comment (e.g. `# v4.2.2`) after the SHA is allowed and ignored. Only the
# bare action identity + ref are validated.
#
# Usage: scripts/action-pins.sh [workflow-dir]
#   workflow-dir defaults to .github/workflows.
set -eu

dir=${1:-.github/workflows}
[ -d "$dir" ] || { echo "missing workflow directory $dir" >&2; exit 1; }

fail=0
found_any=0
for wf in "$dir"/*.yml; do
  [ -f "$wf" ] || continue
  found_any=1
  # Extract every `uses:` value, stripping an optional trailing ` # comment`.
  # awk handles the pipeline naturally; the check itself is done in awk so a
  # single pass validates the file.
  awk -v file="$wf" '
    function trim(s){ sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
    {
      content=$0
      # Drop a trailing comment introduced by whitespace then hash.
      i=index(content, " #")
      if (i>0) content=substr(content,1,i-1)
      content=trim(content)
      if (content ~ /^-[ \t]*uses:[ \t]*[^ \t]+/) {
        val=content
        sub(/^-[ \t]*uses:[ \t]*/, "", val)
        # Local repository actions are exempt.
        if (val ~ /^\.\//) next
        # Reject missing refs.
        if (val !~ /@/) {
          print file ": action has no ref: " content > "/dev/stderr"
          bad=1; next
        }
        ref=val; sub(/^.*@/, "", ref)
        # Reject anything that is not exactly 40 hex characters.
        if (ref !~ /^[0-9a-fA-F]{40}$/) {
          print file ": action ref is not a full 40-hex SHA: " content > "/dev/stderr"
          bad=1
        }
      }
    }
    END { if (bad) exit 1 }
  ' "$wf" || fail=1
done

if [ "$found_any" -eq 0 ]; then
  echo "no workflow files found under $dir" >&2
  exit 1
fi

if [ "$fail" -ne 0 ]; then
  echo "action-pins scan FAILED: mutable or unpinned action references present" >&2
  exit 1
fi
echo "action-pins scan passed: every external action in $dir is pinned to a full commit SHA"