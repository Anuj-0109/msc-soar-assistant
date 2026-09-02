#!/usr/bin/env bash
set -o pipefail

cd /home/ubuntu/msc-soar-assistant || exit 1
source venv/bin/activate || exit 1

mkdir -p dissertation_appendix_evidence/test_backup

for db in soar_platform.db soar_audit.db geolocation_cache.db; do
  if [ -f "$db" ]; then
    cp -a "$db" dissertation_appendix_evidence/test_backup/
  fi
done

TEST_GUARD="$(mktemp -d)"
cleanup() {
  rm -rf "$TEST_GUARD"
  for db in soar_platform.db soar_audit.db geolocation_cache.db; do
    if [ -f "dissertation_appendix_evidence/test_backup/$db" ]; then
      cp -a "dissertation_appendix_evidence/test_backup/$db" .
    fi
  done
}
trap cleanup EXIT

cat > "$TEST_GUARD/sudo" <<'SH'
#!/bin/sh
echo "TEST SAFETY GUARD: sudo execution disabled." >&2
exit 99
SH
chmod +x "$TEST_GUARD/sudo"

echo "============================================="
echo "MSc SOAR dissertation protected test run"
echo "Date: $(date -Is)"
echo "Python: $(python --version 2>&1)"
echo "============================================="

PATH="$TEST_GUARD:$PATH" \
python -m unittest discover -s tests -p 'test_*.py' -v \
  2>&1 | tee dissertation_appendix_evidence/appendix_test_run.txt

status=${PIPESTATUS[0]}
echo
echo "Test exit status: $status"
exit "$status"
