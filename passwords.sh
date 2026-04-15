#!/bin/bash
# SSH honeypot password stats collector with Have I Been Pwned enrichment.
#
# Output stats format: <hits> "<password>" <hibp_count>
#   hibp_count = number of times the password appears in HIBP dataset
#   hibp_count = 0   → password not found in HIBP
#   hibp_count = -1  → HIBP API error during lookup (will be retried next run)
#   hibp_count = ?   → not yet queried (HIBP_LIMIT reached or lookup skipped)
#
# Environment variables (override defaults):
#   HIBP_LIMIT   Max new HIBP lookups per run. Default: 1000. Set to 0 to skip lookups.
#   HIBP_DELAY   Seconds to sleep between API calls (float). Default: 0.15

LOGS_DIR="/var/docker/docker/ssh-auth-logger/log"
WORKING_DIR="/var/docker/docker/ssh-auth-logger/ssh-passwords"

set -euo pipefail

cd "$WORKING_DIR" || exit 1

STATS="stats.passwords.txt"
UNIQ="uniq.passwords.txt"
RAW="raw.passwords.txt"
CACHE="hibp.cache.txt"   # SHA1-based cache

HIBP_LIMIT="${HIBP_LIMIT:-1000}"
HIBP_DELAY="${HIBP_DELAY:-0.15}"

# Remove cache if older than 15 days
find "$CACHE" -ctime +15 -exec rm {} \;

touch "$STATS" "$UNIQ" "$CACHE"

# ---------------------------------------------------------------------------
# 1. Collect raw passwords from logs
# ---------------------------------------------------------------------------
zgrep -h "Request with password" "$LOGS_DIR"/ssh-auth-logger.log.1.gz \
    | jq -r '.password | @json' | sort > "$RAW"

# Update unique password list
cat "$RAW" "$UNIQ" | sort -u > "$UNIQ.tmp"
mv "$UNIQ.tmp" "$UNIQ"

# Count occurrences in this batch
sort "$RAW" | uniq -c | sort -nr | sed -e 's/^[[:space:]]*//g' > "new.$STATS"

# ---------------------------------------------------------------------------
# 2. Merge new counts with existing stats
#    Handles both 2-col (hits "pw") and 3-col (hits "pw" hibp) format in $STATS
#    by stripping the trailing HIBP column in get_key before summing.
# ---------------------------------------------------------------------------
awk '
function get_key(line,    tmp) {
    tmp = line
    sub(/^[0-9]+[[:space:]]+/, "", tmp)   # strip leading hit count
    sub(/[[:space:]]+[-0-9?]+$/, "", tmp) # strip trailing HIBP count (if present)
    return tmp
}
/^#/ || /^[[:space:]]*$/ { next }         # skip comments and blank lines
FNR==NR {
    key = get_key($0)
    count[key] += $1 + 0
    next
}
{
    key = get_key($0)
    count[key] += $1 + 0
}
END {
    for (k in count)
        print count[k], k
}' "$STATS" "new.$STATS" | sort -nr > "$STATS.tmp"

rm "new.$STATS"

# ---------------------------------------------------------------------------
# 3. HIBP enrichment
#    Load existing HIBP results from stats file into memory, then query any
#    passwords not yet looked up (marked as "?") or that errored out ("-1").
# ---------------------------------------------------------------------------

# Load HIBP results already stored in stats: hibp_map["json_pw"] = count
declare -A hibp_map
while IFS= read -r stats_line; do
    [[ -z "$stats_line" || "$stats_line" == \#* ]] && continue
    _hibp_count="${stats_line##* }"
    _pw_key="${stats_line% *}"          # strip trailing hibp count
    _pw_key="${_pw_key#* }"             # strip leading hit count
    # Only load entries that have a resolved count (not "?" = unqueried)
    [[ "$_hibp_count" == "?" ]] && continue
    hibp_map["$_pw_key"]="$_hibp_count"
done < "$STATS"

# ---------------------------------------------------------------------------
# 4. Load SHA1 cache
# ---------------------------------------------------------------------------
declare -A cache_map
while IFS= read -r line; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    sha="${line%% *}"
    cnt="${line##* }"
    cache_map["$sha"]="$cnt"
done < "$CACHE"

# ---------------------------------------------------------------------------
# 5. HIBP lookups with SHA1 cache
# ---------------------------------------------------------------------------
new_lookups=0
api_errors=0

if (( HIBP_LIMIT > 0 )); then
    while IFS= read -r stats_line; do
        (( new_lookups >= HIBP_LIMIT )) && break

        pw_key="${stats_line#* }"   # strip leading hit count → JSON-encoded password

        # Already resolved (skip -1 errors so they get retried)
        [[ -v hibp_map["$pw_key"] && "${hibp_map[$pw_key]}" != "-1" ]] && continue

        # Decode JSON string to raw bytes for hashing
        raw_pw=$(printf '%s\n' "$pw_key" | jq -r '.' 2>/dev/null) || {
            hibp_map["$pw_key"]="-1"
            (( api_errors++ )) || true
            continue
        }

        # SHA-1 hash of the raw password (no trailing newline)
        sha1=$(printf '%s' "$raw_pw" | sha1sum | tr '[:lower:]' '[:upper:]' | cut -c1-40)

        # CACHE CHECK (by SHA1)
        if [[ -v cache_map["$sha1"] ]]; then
            hibp_map["$pw_key"]="${cache_map[$sha1]}"
            continue
        fi

        prefix="${sha1:0:5}"
        suffix="${sha1:5}"

        # k-anonymity: only the 5-char prefix leaves this machine
        sleep "$HIBP_DELAY"
        api_resp=$(curl -sf --retry 2 --max-time 10 \
            -H "Add-Padding: true" \
            "https://api.pwnedpasswords.com/range/${prefix}" 2>/dev/null) || api_resp=""

        if [[ -z "$api_resp" ]]; then
            hibp_map["$pw_key"]="-1"
            (( api_errors++ )) || true
            continue
        fi

        # Cache FULL response (all suffixes)
        while IFS=: read -r resp_suffix resp_count; do
            resp_suffix="${resp_suffix^^}"  # uppercase
            full_sha="${prefix}${resp_suffix}"
            resp_count="${resp_count//$'\r'/}"

            # store in cache (skip overwrite for speed)
            if [[ ! -v cache_map["$full_sha"] ]]; then
                cache_map["$full_sha"]="$resp_count"
                printf '%s %s\n' "$full_sha" "$resp_count" >> "$CACHE"
            fi
        done <<< "$api_resp"

        (( new_lookups++ )) || true

        # Now resolve current password from freshly cached data
        if [[ -v cache_map["$sha1"] ]]; then
            hibp_map["$pw_key"]="${cache_map[$sha1]}"
        else
            hibp_map["$pw_key"]="0"
        fi

    done < "$STATS.tmp"

    echo "HIBP: looked up ${new_lookups} new password(s), ${api_errors} API error(s)." >&2
fi

# ---------------------------------------------------------------------------
# 6. Write final stats: <hits> "<password>" <hibp_count>
# ---------------------------------------------------------------------------
{
    echo "# Hits \"Password\" HaveIBeenPwned_hits"
    while IFS= read -r stats_line; do
        hit_count="${stats_line%% *}"
        pw_key="${stats_line#* }"
        hibp_count="${hibp_map[$pw_key]:-?}"   # ? = not yet queried
        printf '%s %s %s\n' "$hit_count" "$pw_key" "$hibp_count"
    done < "$STATS.tmp"
} > "$STATS"

rm "$STATS.tmp"

# ---------------------------------------------------------------------------
# 7. Push to git
# ---------------------------------------------------------------------------
git add -A
git diff --cached --quiet || git commit -m "Automatic update from: $(date -R)"
git push

exit 0
