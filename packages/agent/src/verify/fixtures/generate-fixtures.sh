#!/usr/bin/env bash
# Test-only X.509 fixtures for packages/agent/src/verify.
# Regenerates real PEM certificates/keys used by validateCertificateForDeploy tests.
# Requires openssl >= 1.1. Do NOT use these keys outside the test suite.
set -euo pipefail
cd "$(dirname "$0")"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
cd "$tmpdir"

openssl genrsa -out ca.key.pem 2048
openssl req -x509 -new -nodes -key ca.key.pem -sha256 -days 3650 \
  -out ca.crt.pem -subj "/CN=TokenTimer Test CA"

openssl genrsa -out leaf.key.pem 2048
cat > leaf.cnf <<'EOF'
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no
[req_dn]
CN = valid.example.com
[v3_req]
subjectAltName = @alt_names
basicConstraints = CA:FALSE
keyUsage = digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
[alt_names]
DNS.1 = valid.example.com
DNS.2 = www.valid.example.com
EOF
openssl req -new -key leaf.key.pem -out leaf.csr.pem -config leaf.cnf
openssl x509 -req -in leaf.csr.pem -CA ca.crt.pem -CAkey ca.key.pem -CAcreateserial \
  -out leaf.crt.pem -days 825 -sha256 -extfile leaf.cnf -extensions v3_req

openssl genrsa -out intermediate.key.pem 2048
cat > intermediate.cnf <<'EOF'
[req]
distinguished_name = req_dn
prompt = no
[req_dn]
CN = TokenTimer Test Intermediate
[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
openssl req -new -key intermediate.key.pem -out intermediate.csr.pem -config intermediate.cnf
openssl x509 -req -in intermediate.csr.pem -CA ca.crt.pem -CAkey ca.key.pem -CAcreateserial \
  -out intermediate.crt.pem -days 1825 -sha256 -extfile intermediate.cnf -extensions v3_ca

openssl genrsa -out chain-leaf.key.pem 2048
cat > chain-leaf.cnf <<'EOF'
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no
[req_dn]
CN = chain.example.com
[v3_req]
subjectAltName = DNS:chain.example.com
basicConstraints = CA:FALSE
keyUsage = digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
EOF
openssl req -new -key chain-leaf.key.pem -out chain-leaf.csr.pem -config chain-leaf.cnf
openssl x509 -req -in chain-leaf.csr.pem -CA intermediate.crt.pem -CAkey intermediate.key.pem \
  -CAcreateserial -out chain-leaf.crt.pem -days 825 -sha256 \
  -extfile chain-leaf.cnf -extensions v3_req

openssl genrsa -out wrong-san.key.pem 2048
cat > wrong-san.cnf <<'EOF'
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no
[req_dn]
CN = other.example.com
[v3_req]
subjectAltName = DNS:other.example.com
basicConstraints = CA:FALSE
keyUsage = digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
EOF
openssl req -new -key wrong-san.key.pem -out wrong-san.csr.pem -config wrong-san.cnf
openssl x509 -req -in wrong-san.csr.pem -CA ca.crt.pem -CAkey ca.key.pem -CAcreateserial \
  -out wrong-san.crt.pem -days 825 -sha256 -extfile wrong-san.cnf -extensions v3_req

openssl genrsa -out mismatch.key.pem 2048

openssl genrsa -out expired.key.pem 2048
cat > expired.cnf <<'EOF'
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no
[req_dn]
CN = expired.example.com
[v3_req]
subjectAltName = DNS:expired.example.com
basicConstraints = CA:FALSE
keyUsage = digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
EOF
openssl req -new -key expired.key.pem -out expired.csr.pem -config expired.cnf

openssl genrsa -out future.key.pem 2048
cat > future.cnf <<'EOF'
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no
[req_dn]
CN = future.example.com
[v3_req]
subjectAltName = DNS:future.example.com
basicConstraints = CA:FALSE
keyUsage = digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
EOF
openssl req -new -key future.key.pem -out future.csr.pem -config future.cnf

cat > ca.conf <<'EOF'
[ca]
default_ca = CA_default
[CA_default]
dir = .
database = index.txt
serial = serial.txt
new_certs_dir = .
certificate = ca.crt.pem
private_key = ca.key.pem
default_md = sha256
policy = policy_anything
email_in_dn = no
[policy_anything]
commonName = supplied
EOF
: > index.txt
echo 1000 > serial.txt
openssl ca -batch -config ca.conf -in expired.csr.pem -out expired.crt.pem \
  -extensions v3_req -extfile expired.cnf \
  -startdate 20200101000000Z -enddate 20200102000000Z
openssl ca -batch -config ca.conf -in future.csr.pem -out future.crt.pem \
  -extensions v3_req -extfile future.cnf \
  -startdate 20350101000000Z -enddate 20360101000000Z

openssl req -x509 -new -nodes -key leaf.key.pem -sha256 -days 825 \
  -out selfsigned.crt.pem -subj "/CN=valid.example.com" \
  -addext "subjectAltName=DNS:valid.example.com,DNS:www.valid.example.com"

DEST="$(cd "$(dirname "$0")" && pwd)"
cp ca.crt.pem intermediate.crt.pem \
  leaf.crt.pem leaf.key.pem \
  chain-leaf.crt.pem chain-leaf.key.pem \
  wrong-san.crt.pem wrong-san.key.pem \
  mismatch.key.pem \
  expired.crt.pem expired.key.pem \
  future.crt.pem future.key.pem \
  selfsigned.crt.pem \
  "$DEST/"
# leaf.crt.pem is signed directly by the test CA (not the intermediate).
cat leaf.crt.pem ca.crt.pem > "$DEST/leaf-fullchain.crt.pem"
cat chain-leaf.crt.pem intermediate.crt.pem > "$DEST/chain-leaf-fullchain.crt.pem"
echo "Wrote fixtures to $DEST"
