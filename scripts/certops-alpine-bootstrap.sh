#!/bin/sh
set -eu
test "${CERTOPS_ALPINE_DISPOSABLE_STACK:-}" = 1
test -f /.dockerenv
test -f /lib/ld-musl-x86_64.so.1
test "$(. /etc/os-release; printf '%s' "$ID")" = alpine
test "$(. /etc/os-release; printf '%s' "$VERSION_ID")" = 3.23.6
test ! -e /workspace/package.json
mkdir -p /workspace
tar -xf /input/candidate.tar -C /workspace
cd /workspace
apk add --no-cache bash git go openssl python3 py3-pip py3-virtualenv make gcc musl-dev libffi-dev openssl-dev cargo pkgconfig
npm install --global pnpm@11.13.0
pnpm install --frozen-lockfile
node apps/api/migrations/migrate.js
python3 -m venv /opt/qualification-certbot
/opt/qualification-certbot/bin/pip install certbot==4.2.0
git init /opt/qualification-acmesh
git -C /opt/qualification-acmesh remote add origin https://github.com/acmesh-official/acme.sh.git
git -C /opt/qualification-acmesh fetch --depth 1 origin 40290ad42a37aba57eb246e507c11944a52c0f68
git -C /opt/qualification-acmesh checkout --detach FETCH_HEAD
test "$(git -C /opt/qualification-acmesh rev-parse HEAD)" = 40290ad42a37aba57eb246e507c11944a52c0f68
export CERTOPS_LINUX_ACMESH=/opt/qualification-acmesh/acme.sh
export GOBIN=/opt/qualification-pebble
go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.8.0
go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@v2.8.0
export PATH="/opt/qualification-certbot/bin:/opt/qualification-pebble:$PATH"
export CERTOPS_REAL_ACME_SURFACE=alpine-container
node scripts/certops-real-acme.js
