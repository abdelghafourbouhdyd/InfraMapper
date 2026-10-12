#!/usr/bin/env bash
# Keep the threat report dataset current (dataset/ + cases/knowledge.db).
#
#   ./update_reports.sh                 run an incremental ingest now (last 14 days, new articles only)
#   ./update_reports.sh --ai            same, each new report enriched by Claude Code (claude -p, your login)
#   ./update_reports.sh --install       schedule it with cron: every 6 hours (or: --install "0 7 * * *")
#   ./update_reports.sh --install --ai  scheduled, with AI enrichment
#   ./update_reports.sh --uninstall     remove the schedule
#   ./update_reports.sh --status        show the schedule and the last runs
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="$HERE/logs/ingest.log"
TAG="# inframapper report ingest"
mkdir -p "$HERE/logs"

AI=""
args=()
for a in "$@"; do [ "$a" = "--ai" ] && AI="--ai" || args+=("$a"); done
set -- "${args[@]+"${args[@]}"}"

case "${1:-run}" in
  --install)
    when="${2:-0 */6 * * *}"
    line="$when $HERE/update_reports.sh $AI >/dev/null 2>&1 $TAG"
    { crontab -l 2>/dev/null | grep -vF "$TAG" || true; echo "$line"; } | crontab -
    echo "scheduled: $when  (log: $LOG)"
    ;;
  --uninstall)
    { crontab -l 2>/dev/null | grep -vF "$TAG" || true; } | crontab -
    echo "schedule removed"
    ;;
  --status)
    crontab -l 2>/dev/null | grep -F "$TAG" || echo "not scheduled"
    [ -f "$LOG" ] && grep -E "ingest:|unavailable|failed|Traceback" "$LOG" | tail -n 8 || true
    ;;
  run)
    # one run at a time: a slow ingest must not overlap the next scheduled one
    exec 9>"$HERE/logs/.ingest.lock"
    flock -n 9 || { echo "$(date -Is) previous ingest still running, skipped" >> "$LOG"; exit 0; }
    {
      echo "=== $(date -Is) ingest start"
      COLUMNS=200 "$HERE/.venv/bin/python" "$HERE/ioc_investigator.py" --ingest --days 14 --no-serve $AI || echo "ingest exited with $?"
      echo "=== $(date -Is) ingest end"
    } >> "$LOG" 2>&1
    tail -n 5000 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"   # keep the log small
    # run by hand: show what this run did (the full log stays in logs/ingest.log)
    sed -n '/ingest start/h; /ingest start/!H; ${x;p}' "$LOG" | grep -E "kept|AI \(|ingest:|unavailable|failed|skipped|Traceback" \
      | sed -E 's/^[0-9:]+ +//; s/^ +//; s/ +$//' || true
    ;;
  *)
    sed -n '2,10p' "$0"; exit 1
    ;;
esac
