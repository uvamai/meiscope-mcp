#!/usr/bin/env bash
# DCO check: every non-merge commit in BASE..HEAD must carry a
# "Signed-off-by:" trailer naming its author exactly (name and email), as
# `git commit -s` writes it. See CONTRIBUTING.md and https://developercertificate.org/.
#
# Usage: dco-check.sh <base-sha> <head-sha>
set -euo pipefail

base="${1:?base commit}"
head="${2:?head commit}"
fail=0
count=0
for c in $(git rev-list --no-merges "$base..$head"); do
  count=$((count + 1))
  author="$(git log -1 --format='%an <%ae>' "$c")"
  signoffs="$(git log -1 --format='%(trailers:key=Signed-off-by,valueonly)' "$c" | sed 's/[[:space:]]*$//')"
  if ! printf '%s\n' "$signoffs" | grep -Fxq -- "$author"; then
    echo "::error::commit $(git log -1 --format='%h %s' "$c") has no 'Signed-off-by: $author' (use git commit -s)"
    fail=1
  fi
done
echo "checked $count commit(s)"
exit "$fail"
