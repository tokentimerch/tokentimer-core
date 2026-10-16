#!/usr/bin/env bash
# Optional full AD CS lane add-on, run only inside its newly owned control VM.
# Build the exact public candidate dashboard and serve it beside the real API
# over the existing private HTTPS origin. No extra VM or persistent lab is used.
set -euo pipefail
candidate="${1#*=}"
[[ "$candidate" =~ ^[a-f0-9]{40}$ ]] || { echo 'Invalid browser candidate SHA' >&2; exit 1; }
workspace=/opt/ttqualification
test -d "$workspace/.git" && test "$(git -C "$workspace" rev-parse HEAD)" = "$candidate"
test -s /etc/ttqualification/api.pem && test -s /etc/nginx/conf.d/ttqualification.conf
cd "$workspace"
test ! -e qualification-browser.yml || { echo 'Browser add-on already configured' >&2; exit 1; }
test -z "$(docker ps -aq --filter name='^ttqualification-dashboard$')" || { echo 'Dashboard fixture already exists' >&2; exit 1; }
cat > qualification-browser.yml <<'COMPOSE'
services:
  api:
    environment:
      APP_URL: https://10.64.0.6
      API_URL: https://10.64.0.6
COMPOSE
# This add-on runs before the Windows tests; restarting the fresh API publishes
# its actual browser origin/cookie configuration without interrupting test jobs.
docker compose -f deploy/compose/docker-compose.test.yml -f qualification-browser.yml up -d --no-deps api
docker build -f deploy/compose/Dockerfile.dashboard --build-arg VITE_API_URL= --build-arg API_URL= -t "ttqualification-dashboard:$candidate" .
docker run -d --name ttqualification-dashboard --label certops.disposable-lab=true --label "certops.candidate=$candidate" \
  --read-only --tmpfs /var/cache/nginx:uid=1000,gid=1000,mode=0700 --tmpfs /var/run:uid=1000,gid=1000,mode=0700 \
  -p 127.0.0.1:5173:8080 -e API_URL=https://10.64.0.6 "ttqualification-dashboard:$candidate" >/dev/null
cat > /etc/nginx/conf.d/ttqualification.conf <<'NGINX'
server {
  listen 10.64.0.6:443 ssl;
  ssl_certificate /etc/ttqualification/api.pem;
  ssl_certificate_key /etc/ttqualification/api.key;
  location = /health { proxy_pass http://127.0.0.1:4000; }
  location ~ ^/(api|auth)(/|$) {
    proxy_pass http://127.0.0.1:4000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_http_version 1.1;
    proxy_buffering off;
  }
  location / {
    proxy_pass http://127.0.0.1:5173;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_http_version 1.1;
  }
}
NGINX
nginx -t
systemctl reload nginx
for attempt in $(seq 1 90); do
  if curl --cacert /etc/ttqualification/api.pem -fsS https://10.64.0.6/health >/dev/null \
    && curl --cacert /etc/ttqualification/api.pem -fsS https://10.64.0.6/login | grep -q 'id="root"'; then
    echo 'CERTOPS_STAGE=private-same-origin-dashboard-ready'
    exit 0
  fi
  sleep 2
done
echo 'Dashboard or actual API did not become ready' >&2
exit 1
