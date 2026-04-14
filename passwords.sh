#!/bin/bash

LOGS_DIR="/var/docker/docker/ssh-auth-logger/log"
WORKING_DIR="/var/docker/docker/ssh-auth-logger/ssh-passwords"

set -euo pipefail

cd "$WORKING_DIR" || exit 1

STATS="stats.passwords.txt"
UNIQ="uniq.passwords.txt"
RAW="raw.passwords.txt"

touch "$STATS" "$UNIQ"

# Generate the files
#grep -h "Request with password" "$LOGS_DIR"/ssh-auth-logger.log | jq -r '.password | @json' | sort >> "$RAW"
zgrep -h "Request with password" "$LOGS_DIR"/ssh-auth-logger.log.* | jq -r '.password | @json' | sort >> $RAW

cat "$RAW" "$UNIQ" | sort -u > "$UNIQ.tmp"
mv "$UNIQ.tmp" "$UNIQ"
sort "$RAW" | uniq -c | sort -nr | sed -e 's/^[[:space:]]*//g' > "new.$STATS"

# Merge statistics
awk '
function get_key(line) {
  sub(/^[0-9]+[[:space:]]+/, "", line)
  return line
}
FNR==NR {
  key = get_key($0)
  count[key] = $1
  next
}
{
  key = get_key($0)
  count[key] += $1
}
END {
  for (k in count)
    print count[k], k
}' "$STATS" "new.$STATS" | sort -nr > "$STATS.tmp"

mv "$STATS.tmp" "$STATS"

rm "new.$STATS"

# Push to the git
git add -A
git diff --cached --quiet || git commit -m "Automatic update from: $(date -R)"
git push

exit 0
