#!/usr/bin/env bash
# =============================================================================
# full_fabric_clean_start.sh
# -----------------------------------------------------------------------------
# One-shot script: tear down the entire Fabric environment, wipe all volumes,
# bring everything back up, and deploy chaincode iot-integrity v1.2.
#
# What this replaces:
#   - ./network.sh down + ./network.sh up createChannel (manual)
#   - redeploy.sh                                       (manual)
#
# Workflow:
#   Phase 1  — prerequisite checks (binaries, source files)
#   Phase 2  — full teardown (peers, orderer, CCaaS, volumes, network)
#   Phase 3  — fresh Fabric network up + channel creation
#   Phase 4  — build v1.2 Docker image
#   Phase 5  — build CCaaS package (nested tarball)
#   Phase 6  — install chaincode on Org1 and Org2 peers
#   Phase 7  — capture package ID
#   Phase 8  — approve from both orgs
#   Phase 9  — check commit readiness
#   Phase 10 — commit chaincode definition
#   Phase 11 — start CCaaS container running v1.2 binary
#   Phase 12 — verify the deployment
#
# After this script completes, the channel is fresh (sequence 1) and v1.2 is
# the only committed chaincode definition. You can then run:
#       cd ~/iot-pipeline && python3 -m ingestion.fabric_access
#
# Author : PFE — Telecommunication Systems, USTHB
# =============================================================================

set -euo pipefail

# ============================================================================
# 0. Configuration
# ============================================================================
PROJECT_DIR=~/iot-pipeline
TEST_NETWORK=~/hyperFabric/fabric-samples/test-network

CHANNEL=mychannel
CC_NAME=iot-integrity
CC_VERSION=1.2
CC_SEQUENCE=1                       # FRESH deployment (volumes wiped)
CC_LABEL="${CC_NAME}_${CC_VERSION}"
IMAGE_TAG="${CC_NAME}-cc:${CC_VERSION}"

CCAAS_CONTAINER=iot-integrity-cc
CCAAS_PORT=7052

# Fabric environment (Org1 by default; helper functions switch identity)
export PATH=~/hyperFabric/fabric-samples/bin:$PATH
export FABRIC_CFG_PATH=~/hyperFabric/fabric-samples/config
export CORE_PEER_TLS_ENABLED=true

ORDERER_CA="$TEST_NETWORK/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"
ORG1_TLS="$TEST_NETWORK/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
ORG2_TLS="$TEST_NETWORK/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"

PACKAGE="$PROJECT_DIR/ccaas-package/iot-integrity-ccaas-v1.2.tar.gz"
PKG_ID_FILE="$PROJECT_DIR/ccaas-package/PACKAGE_ID"

# Docker network name (default in fabric-samples is fabric_test)
DOCKER_NETWORK=fabric_test

# ----------------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------------
use_org1() {
    export CORE_PEER_LOCALMSPID=Org1MSP
    export CORE_PEER_ADDRESS=localhost:7051
    export CORE_PEER_TLS_ROOTCERT_FILE="$ORG1_TLS"
    export CORE_PEER_MSPCONFIGPATH="$TEST_NETWORK/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
}
use_org2() {
    export CORE_PEER_LOCALMSPID=Org2MSP
    export CORE_PEER_ADDRESS=localhost:9051
    export CORE_PEER_TLS_ROOTCERT_FILE="$ORG2_TLS"
    export CORE_PEER_MSPCONFIGPATH="$TEST_NETWORK/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp"
}

phase() { echo ""; echo "════════════════════════════════════════"; echo "▶ $*"; echo "════════════════════════════════════════"; }

# ============================================================================
# 1. Prerequisite checks
# ============================================================================
phase "Phase 1 — Prerequisite checks"

command -v peer   >/dev/null || { echo "❌ peer binary not in PATH"; exit 1; }
command -v docker >/dev/null || { echo "❌ docker not installed"; exit 1; }

[ -d "$TEST_NETWORK" ] \
    || { echo "❌ test-network not found at $TEST_NETWORK"; exit 1; }

[ -f "$PROJECT_DIR/chaincode/iot_contract.go" ] \
    || { echo "❌ Missing $PROJECT_DIR/chaincode/iot_contract.go"; exit 1; }

# v1.2-specific symbol — RegisterDevice alone is not enough, that exists in v1.1 too
grep -q "RegisterTypePolicy" "$PROJECT_DIR/chaincode/iot_contract.go" \
    || { echo "❌ iot_contract.go does not contain RegisterTypePolicy — not v1.2?"; exit 1; }

[ -f "$PROJECT_DIR/chaincode/Dockerfile" ] \
    || { echo "❌ Missing Dockerfile at $PROJECT_DIR/chaincode/Dockerfile"; exit 1; }

echo "✅ peer binary OK"
echo "✅ docker OK"
echo "✅ test-network present"
echo "✅ v1.2 chaincode source present (contains RegisterTypePolicy)"
echo "✅ Dockerfile present"

# ============================================================================
# 2. Full teardown — Group A + Group B + network + volumes
# ============================================================================
phase "Phase 2 — Full teardown (this wipes ALL Fabric state)"

# 2a. Tear down Group A — peers, orderer, CAs (network.sh handles this + its volumes)
cd "$TEST_NETWORK"
./network.sh down 2>&1 | tail -5 || true
echo "✅ Group A torn down (peers, orderer, CAs)"

# 2b. Tear down Group B — the CCaaS chaincode container is NOT managed by network.sh
docker stop "$CCAAS_CONTAINER" 2>/dev/null || true
docker rm   "$CCAAS_CONTAINER" 2>/dev/null || true
echo "✅ Group B torn down (CCaaS container)"

# 2c. Remove the Docker network so it can be re-created cleanly
docker network rm "$DOCKER_NETWORK" 2>/dev/null || true
echo "✅ Docker network $DOCKER_NETWORK removed"

# 2d. Prune any orphan volumes that survived the teardown
#     (network.sh down usually catches them, but we add a safety net)
ORPHAN_VOLUMES=$(docker volume ls --format '{{.Name}}' \
                 | grep -E '(orderer|peer0|ca_)' || true)
if [ -n "$ORPHAN_VOLUMES" ]; then
    echo "$ORPHAN_VOLUMES" | xargs docker volume rm 2>/dev/null || true
    echo "✅ Orphan Fabric volumes removed"
else
    echo "✅ No orphan Fabric volumes"
fi

# 2e. Optional — remove old chaincode images from previous versions
#     (saves disk, prevents image-cache confusion)
OLD_IMAGES=$(docker images --format '{{.Repository}}:{{.Tag}}' \
             | grep "^${CC_NAME}-cc:" || true)
if [ -n "$OLD_IMAGES" ]; then
    echo "$OLD_IMAGES" | xargs docker rmi -f 2>/dev/null || true
    echo "✅ Old ${CC_NAME}-cc images removed"
fi

sleep 2   # give Docker a moment to release resources

# ============================================================================
# 3. Bring up the Fabric network fresh
# ============================================================================
phase "Phase 3 — Bring up fresh Fabric network + create channel"

# Pre-create the Docker network (Docker 29.x compatibility — see §6 of memoir)
docker network create --driver bridge "$DOCKER_NETWORK" 2>/dev/null || true

cd "$TEST_NETWORK"
./network.sh up createChannel -ca -c "$CHANNEL" 2>&1 | tail -10

# Sanity check — both peers must be up
docker ps --format '{{.Names}}' | grep -q peer0.org1.example.com \
    || { echo "❌ peer0.org1 did not come up"; exit 1; }
docker ps --format '{{.Names}}' | grep -q peer0.org2.example.com \
    || { echo "❌ peer0.org2 did not come up"; exit 1; }

echo "✅ Fabric network up, channel '$CHANNEL' created"

# ============================================================================
# 4. Build the Docker image for the v1.2 chaincode
# ============================================================================
phase "Phase 4 — Build Docker image $IMAGE_TAG"

cd "$PROJECT_DIR/chaincode"
docker build --pull=false -t "$IMAGE_TAG" . 2>&1 | tail -8
echo "✅ Image $IMAGE_TAG built"

# ============================================================================
# 5. Build the CCaaS package (nested tar format — see §28 of memoir)
# ============================================================================
phase "Phase 5 — Build CCaaS package"

BUILD_DIR="$PROJECT_DIR/ccaas-package/build"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cat > metadata.json <<EOF
{
  "type": "ccaas",
  "label": "$CC_LABEL"
}
EOF

cat > connection.json <<EOF
{
  "address": "${CCAAS_CONTAINER}:${CCAAS_PORT}",
  "dial_timeout": "10s",
  "tls_required": false
}
EOF

# Inner archive — code.tar.gz contains connection.json
tar -czf code.tar.gz connection.json

# Outer archive — metadata.json + code.tar.gz
tar -czf "$PACKAGE" metadata.json code.tar.gz

echo "✅ Package built: $PACKAGE"
echo "   Contents:"
tar tzf "$PACKAGE" | sed 's/^/   /'

# ============================================================================
# 6. Install chaincode on Org1 and Org2 peers
# ============================================================================
phase "Phase 6a — Install chaincode on Org1 peer"
use_org1
peer lifecycle chaincode install "$PACKAGE" 2>&1 | tail -3

phase "Phase 6b — Install chaincode on Org2 peer"
use_org2
peer lifecycle chaincode install "$PACKAGE" 2>&1 | tail -3

# ============================================================================
# 7. Capture the package ID
# ============================================================================
phase "Phase 7 — Capture package ID"
use_org1

PKG_ID=$(peer lifecycle chaincode queryinstalled 2>/dev/null \
    | grep "Label: ${CC_LABEL}\$" \
    | head -1 \
    | sed -E 's/^Package ID: ([^,]+),.*/\1/')

if [ -z "$PKG_ID" ]; then
    echo "❌ Could not find a package matching label '$CC_LABEL'"
    echo "   Full queryinstalled output:"
    peer lifecycle chaincode queryinstalled
    exit 1
fi

echo "$PKG_ID" > "$PKG_ID_FILE"
export NEW_CC_PACKAGE_ID="$PKG_ID"

echo "✅ Package ID: $PKG_ID"
echo "   Saved to:   $PKG_ID_FILE"

# ============================================================================
# 8. Approve chaincode definition from both orgs
# ============================================================================
phase "Phase 8a — Approve from Org1"
use_org1
peer lifecycle chaincode approveformyorg \
    -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" \
    --channelID "$CHANNEL" --name "$CC_NAME" \
    --version "$CC_VERSION" --package-id "$PKG_ID" --sequence "$CC_SEQUENCE"

phase "Phase 8b — Approve from Org2"
use_org2
peer lifecycle chaincode approveformyorg \
    -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" \
    --channelID "$CHANNEL" --name "$CC_NAME" \
    --version "$CC_VERSION" --package-id "$PKG_ID" --sequence "$CC_SEQUENCE"

# ============================================================================
# 9. Check commit readiness
# ============================================================================
phase "Phase 9 — Verify both orgs approved"
use_org1
READINESS=$(peer lifecycle chaincode checkcommitreadiness \
    --channelID "$CHANNEL" --name "$CC_NAME" \
    --version "$CC_VERSION" --sequence "$CC_SEQUENCE" --output json)
echo "$READINESS"

if echo "$READINESS" | grep -q '"Org1MSP": false\|"Org2MSP": false'; then
    echo "❌ At least one org has not approved — aborting before commit."
    exit 1
fi
echo "✅ Both orgs approved"

# ============================================================================
# 10. Commit chaincode definition to the channel
# ============================================================================
phase "Phase 10 — Commit chaincode definition"
use_org1
peer lifecycle chaincode commit \
    -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" \
    --channelID "$CHANNEL" --name "$CC_NAME" \
    --version "$CC_VERSION" --sequence "$CC_SEQUENCE" \
    --peerAddresses localhost:7051 --tlsRootCertFiles "$ORG1_TLS" \
    --peerAddresses localhost:9051 --tlsRootCertFiles "$ORG2_TLS"

echo "✅ Committed"

# ============================================================================
# 11. Start the CCaaS container running the v1.2 binary
# ============================================================================
phase "Phase 11 — Start CCaaS container"

docker run -d --name "$CCAAS_CONTAINER" \
    --network "$DOCKER_NETWORK" \
    -e CHAINCODE_ID="$PKG_ID" \
    -e CHAINCODE_SERVER_ADDRESS="0.0.0.0:${CCAAS_PORT}" \
    "$IMAGE_TAG"

# Give the container 5 s to either crash or stay up
sleep 5

if docker ps --format '{{.Names}}' | grep -q "^${CCAAS_CONTAINER}\$"; then
    echo "✅ CCaaS container running"
else
    echo "❌ CCaaS container died — last logs:"
    docker logs "$CCAAS_CONTAINER" 2>&1 | tail -30
    exit 1
fi

# ============================================================================
# 12. Verify the deployment
# ============================================================================
phase "Phase 12 — Verify deployment"
use_org1

echo "→ Committed chaincode definitions on channel '$CHANNEL':"
peer lifecycle chaincode querycommitted --channelID "$CHANNEL" --name "$CC_NAME"

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "✅ Clean deployment complete"
echo "   Chaincode:    $CC_NAME v$CC_VERSION (sequence $CC_SEQUENCE)"
echo "   Package ID:   $PKG_ID"
echo "   Saved to:     $PKG_ID_FILE"
echo "   Container:    $CCAAS_CONTAINER on $DOCKER_NETWORK"
echo "   Channel:      $CHANNEL"
echo ""
echo "   Next step:    python3 -m ingestion.fabric_access   (smoke test)"
echo "════════════════════════════════════════════════════════════════"