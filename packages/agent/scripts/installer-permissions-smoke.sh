#!/bin/sh
# Run only in a disposable container with the repository mounted read-only at
# /repo, e.g. node:22-bookworm. No service or registration request is started.
set -eu
test -f /.dockerenv || { echo 'This smoke check requires a disposable Docker container.' >&2; exit 1; }
test -f /repo/packages/agent/scripts/install-agent.sh
mkdir -p /tmp/tt-installer-tools /etc/systemd/system
printf '#!/bin/sh\nexit 0\n' >/tmp/tt-installer-tools/systemctl
chmod 0755 /tmp/tt-installer-tools/systemctl
PATH="/tmp/tt-installer-tools:$PATH"
export PATH
cp -a /repo/packages /tmp/tt-installer-source
find /tmp/tt-installer-source/agent -type d -exec chmod 0700 {} \;
export TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=ttboot_installer_permissions_fixture
umask 077
sh /tmp/tt-installer-source/agent/scripts/install-agent.sh \
  --api-url https://example.test \
  --workspace-id 11111111-1111-4111-8111-111111111111 --no-trust-store
runuser -u tokentimer-agent -- test -r /opt/tokentimer-agent/app/bin/tokentimer-agent.js
test "$(stat -c %a /opt/tokentimer-agent)" = 755
test "$(stat -c %a /opt/tokentimer-agent/state)" = 700
test "$(stat -c %a /opt/tokentimer-agent/state/config.json)" = 600
test "$(stat -c %a /opt/tokentimer-agent/state/bootstrap.env)" = 600
test "$(stat -c %U /opt/tokentimer-agent/app/bin)" = root
echo INSTALLER_PERMISSIONS_SMOKE_PASS
