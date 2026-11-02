#!/usr/bin/env bash
# Keep the native client within the pinned qualification API server's supported
# version skew; install only into this disposable hosted run's temporary path.
set -euo pipefail
test "$(uname -s)" = Linux
test "$(uname -m)" = x86_64
test "${GITHUB_ACTIONS:-}" = true
test "${RUNNER_ENVIRONMENT:-}" = github-hosted
test -n "${RUNNER_TEMP:-}"
tools_directory=$(mktemp -d "$RUNNER_TEMP/certops-kubernetes-tools.XXXXXX")
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  https://dl.k8s.io/release/v1.35.0/bin/linux/amd64/kubectl -o "$tools_directory/kubectl"
printf '%s  %s\n' 'a2e984a18a0c063279d692533031c1eff93a262afcc0afdc517375432d060989' "$tools_directory/kubectl" | sha256sum -c -
chmod 0755 "$tools_directory/kubectl"
"$tools_directory/kubectl" version --client=true --output=json | node -e 'let text="";process.stdin.on("data",chunk=>text+=chunk);process.stdin.on("end",()=>{const value=JSON.parse(text);if(value.clientVersion.gitVersion!=="v1.35.0")throw new Error("Unexpected qualification kubectl version");console.log(value.clientVersion.gitVersion);});'
echo "$tools_directory" >> "$GITHUB_PATH"
