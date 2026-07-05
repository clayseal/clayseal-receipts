#!/usr/bin/env bash
# Fetch the local workload X.509 SVID and print the SPIFFE ID from the cert SAN.
set -euo pipefail

SOCKET="${SPIRE_SOCKET:-/run/spire/sockets/agent.sock}"
OUT="${SVID_DIR:-/tmp/svid}"

/opt/spire/bin/spire-agent api fetch x509 -socketPath "$SOCKET" -write "$OUT"

echo "=== X.509 SVID files ==="
ls -1 "$OUT"

echo
echo "=== SPIFFE ID (URI SAN) ==="
openssl x509 -in "$OUT/svid.0.pem" -text -noout | sed -n '/Subject Alternative Name/,+3p'

echo
echo "=== Validity ==="
openssl x509 -in "$OUT/svid.0.pem" -noout -dates
