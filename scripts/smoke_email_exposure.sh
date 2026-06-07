#!/usr/bin/env bash
# Linux smoke test for the Aegis email_exposure plugin.
#
# This script starts a temporary local HTTP fixture containing a synthetic
# email/password-like exposure, calls the running Aegis API synchronously, and
# validates that the plugin returns a PII-safe normalized finding.

set -euo pipefail

API_BASE="${AEGIS_API_URL:-http://127.0.0.1:8000}"
API_BASE="${API_BASE%/}"
TARGET="${AEGIS_EMAIL_SMOKE_TARGET:-example.com}"
TARGET_TYPE="${AEGIS_EMAIL_SMOKE_TARGET_TYPE:-domain}"
FIXTURE_HOST="${AEGIS_EMAIL_SMOKE_HOST:-127.0.0.1}"
FIXTURE_PORT="${AEGIS_EMAIL_SMOKE_PORT:-8765}"
AUTH_TOKEN="${AEGIS_API_AUTH_TOKEN:-${AEGIS_AUTH_TOKEN:-}}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[email_exposure smoke] Missing required command: $1" >&2
    exit 127
  fi
}

require_cmd curl
require_cmd python3

TMP_DIR="$(mktemp -d)"
RESPONSE_FILE="$TMP_DIR/response.json"
HTTP_PID=""

cleanup() {
  if [[ -n "$HTTP_PID" ]] && kill -0 "$HTTP_PID" >/dev/null 2>&1; then
    kill "$HTTP_PID" >/dev/null 2>&1 || true
    wait "$HTTP_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

cat >"$TMP_DIR/leak.txt" <<'EOF_LEAK'
public dump alice@example.com:Sup3rSecret123!
EOF_LEAK

(
  cd "$TMP_DIR"
  python3 -m http.server "$FIXTURE_PORT" --bind "$FIXTURE_HOST" >/dev/null 2>&1
) &
HTTP_PID="$!"

FIXTURE_URL="http://$FIXTURE_HOST:$FIXTURE_PORT/leak.txt"

echo "[email_exposure smoke] Fixture URL: $FIXTURE_URL"

for _ in {1..30}; do
  if curl -fsS "$FIXTURE_URL" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

if ! curl -fsS "$FIXTURE_URL" >/dev/null 2>&1; then
  echo "[email_exposure smoke] Local fixture server did not become ready." >&2
  exit 1
fi

curl_headers=(-H "Content-Type: application/json")
if [[ -n "$AUTH_TOKEN" ]]; then
  curl_headers+=(-H "Authorization: Bearer $AUTH_TOKEN")
fi

if ! curl -fsS "${curl_headers[@]}" "$API_BASE/health" >/dev/null 2>&1; then
  cat >&2 <<EOF_API
[email_exposure smoke] Aegis API is not reachable at $API_BASE.

Start it in another terminal, for example:
  source .venv/bin/activate
  uvicorn backend.api.app:create_app --factory --host 127.0.0.1 --port 8000

If you use a custom prefix/port, set:
  AEGIS_API_URL=http://127.0.0.1:8000 ./scripts/smoke_email_exposure.sh
EOF_API
  exit 2
fi

PAYLOAD=$(TARGET="$TARGET" TARGET_TYPE="$TARGET_TYPE" FIXTURE_URL="$FIXTURE_URL" python3 - <<'PY'
import json
import os

print(json.dumps({
    "target": os.environ["TARGET"],
    "target_type": os.environ["TARGET_TYPE"],
    "plugin_name": "email_exposure",
    "config": {
        "source_urls": [os.environ["FIXTURE_URL"]],
        "max_findings_per_source": 10,
    },
    "enrich": False,
    "async_mode": False,
}))
PY
)

echo "[email_exposure smoke] Calling $API_BASE/collections/run for target=$TARGET target_type=$TARGET_TYPE"

HTTP_STATUS=$(curl -sS -o "$RESPONSE_FILE" -w "%{http_code}" \
  -X POST "$API_BASE/collections/run" \
  "${curl_headers[@]}" \
  -d "$PAYLOAD")

if [[ "$HTTP_STATUS" != "200" ]]; then
  echo "[email_exposure smoke] Unexpected HTTP status: $HTTP_STATUS" >&2
  echo "[email_exposure smoke] Response body:" >&2
  cat "$RESPONSE_FILE" >&2
  exit 3
fi

python3 - "$RESPONSE_FILE" <<'PY'
import hashlib
import json
import re
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    response = json.load(fh)

def fail(message: str) -> None:
    print(f"[email_exposure smoke] FAIL: {message}", file=sys.stderr)
    print(json.dumps(response, indent=2, sort_keys=True), file=sys.stderr)
    raise SystemExit(4)

plugin_results = response.get("plugin_results") or []
email_result = next((item for item in plugin_results if item.get("plugin_name") == "email_exposure"), None)
if not email_result:
    fail("missing email_exposure plugin result")
if email_result.get("status") != "completed":
    fail(f"plugin status is not completed: {email_result.get('status')!r}")

findings = response.get("findings") or email_result.get("findings") or []
if len(findings) != 1:
    fail(f"expected exactly one finding, got {len(findings)}")

finding = findings[0]
data = finding.get("data") or {}
raw_evidence = finding.get("raw_evidence") or {}
data_types = set(data.get("data_types_found") or [])
expected_hash = hashlib.sha256("alice@example.com".encode("utf-8")).hexdigest()

if finding.get("source") != "email_exposure":
    fail("finding.source is not email_exposure")
if finding.get("type") != "email.exposure":
    fail("finding.type is not email.exposure")
if finding.get("indicator_type") != "email":
    fail("finding.indicator_type is not email")
if finding.get("severity") != "high":
    fail("finding.severity is not high")
if finding.get("value") != expected_hash:
    fail("finding.value is not the expected SHA-256 email hash")
if not re.fullmatch(r"[0-9a-f]{64}", str(finding.get("value", ""))):
    fail("finding.value is not a 64-character lowercase hex hash")
if data.get("redacted_email") != "al***@example.com":
    fail("data.redacted_email is not al***@example.com")
if data.get("email_domain") != "example.com":
    fail("data.email_domain is not example.com")
if not {"email", "password"}.issubset(data_types):
    fail("data_types_found does not include both email and password")

serialized = json.dumps(response, sort_keys=True)
if "alice@example.com" in serialized:
    fail("raw email leaked in API response")
if "Sup3rSecret123!" in serialized:
    fail("raw password-like value leaked in API response")
if "al***@example.com" not in serialized:
    fail("redacted email is missing from response")
if "evidence_hash" not in raw_evidence:
    fail("raw_evidence.evidence_hash is missing")

print("[email_exposure smoke] PASS")
print(json.dumps({
    "plugin_status": email_result.get("status"),
    "finding_count": len(findings),
    "severity": finding.get("severity"),
    "indicator_type": finding.get("indicator_type"),
    "redacted_email": data.get("redacted_email"),
    "email_hash": finding.get("value"),
    "data_types_found": sorted(data_types),
}, indent=2, sort_keys=True))
PY
