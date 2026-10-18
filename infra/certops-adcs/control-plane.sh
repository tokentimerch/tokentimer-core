#!/usr/bin/env bash
# Disposable Linux control-plane setup for the protected AD CS lab provisioner.
# Checks out the exact public candidate, starts actual isolated API/PostgreSQL
# and test TLS, and accepts only the explicit experimental lease selector.
# Private fixture credentials stay inside the lab; reports expose public facts.
set -euo pipefail
candidate="${1#*=}"
[[ "$candidate" =~ ^[a-f0-9]{40}$ ]] || { echo 'Invalid candidate SHA' >&2; exit 1; }
journal_phase_arg="${2:-journal_phase=none}"
journal_phase="${journal_phase_arg#*=}"
case "$journal_phase" in none|keygen_intent|prepared|submitting|installing|accepted-before-bind|bound-before-complete) ;; *) echo 'Unsupported journal phase experiment' >&2; exit 1 ;; esac
ttl24h_arg="${3:-adcs_ttl24h=0}"
ttl24h="${ttl24h_arg#*=}"
case "$ttl24h" in 0|1) ;; *) echo 'Unsupported default TTL qualification selector' >&2; exit 1 ;; esac
[[ "$ttl24h" == 0 || "$journal_phase" == none ]] || { echo 'Default TTL qualification cannot combine timing experiments' >&2; exit 1; }
api_certificate_days=1
if [[ "$ttl24h" == 1 ]]; then api_certificate_days=7; fi
workspace=/opt/ttqualification
test ! -e "$workspace" || { echo 'Refusing existing qualification workspace' >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q git openssl nginx ca-certificates curl
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
. /etc/os-release
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $VERSION_CODENAME stable" > /etc/apt/sources.list.d/docker.list
apt-get update -q
apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
git clone --no-checkout https://github.com/tokentimerch/tokentimer-core.git "$workspace"
git -C "$workspace" checkout --detach "$candidate"
test "$(git -C "$workspace" rev-parse HEAD)" = "$candidate"
cd "$workspace"
compose_files=(-f deploy/compose/docker-compose.test.yml)
if [[ "$journal_phase" != none ]]; then
  cat > "$workspace/qualification-journal-timing.yml" <<'TIMING'
services:
  api:
    environment:
      CERTOPS_JOB_LEASE_SECONDS: '60'
      CERTOPS_LEASE_HARD_GRACE_MS: '60000'
TIMING
  compose_files+=(-f "$workspace/qualification-journal-timing.yml")
fi
docker compose "${compose_files[@]}" up -d --build postgres api mailhog
for attempt in $(seq 1 120); do
  if curl -fsS http://127.0.0.1:4000/health >/dev/null; then break; fi
  sleep 2
done
curl -fsS http://127.0.0.1:4000/health >/dev/null
install -d -m 700 /etc/ttqualification
openssl req -x509 -newkey rsa:2048 -nodes -days "$api_certificate_days" -subj /CN=tt-control.lab.certops.test -addext subjectAltName=DNS:tt-control.lab.certops.test,IP:10.64.0.6 -keyout /etc/ttqualification/api.key -out /etc/ttqualification/api.pem >/dev/null 2>&1
chmod 600 /etc/ttqualification/api.key
cat > /etc/nginx/conf.d/ttqualification.conf <<'NGINX'
server {
  listen 10.64.0.6:443 ssl;
  ssl_certificate /etc/ttqualification/api.pem;
  ssl_certificate_key /etc/ttqualification/api.key;
  location / {
    proxy_pass http://127.0.0.1:4000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_http_version 1.1;
    proxy_buffering off;
  }
}
NGINX
nginx -t
systemctl restart nginx
curl --cacert /etc/ttqualification/api.pem -fsS https://10.64.0.6/ >/dev/null
echo 'CERTOPS_STAGE=private-https-control-plane-running'
# Public TLS trust material only. No API/domain credentials or private key.
cat /etc/ttqualification/api.pem
