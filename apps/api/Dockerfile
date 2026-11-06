# Build context must be the repo root.
# Prefer deploy/compose/Dockerfile.api for production Compose/CI images.
FROM golang:1.26.10-alpine3.23 AS subfinder-builder

RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache ca-certificates git

RUN git clone --depth 1 --branch v2.14.0 https://github.com/projectdiscovery/subfinder.git /src

WORKDIR /src/cmd/subfinder
RUN go get \
      github.com/projectdiscovery/utils@v0.11.12 \
      golang.org/x/crypto@v0.58.1-0.20261009181718-2f1f834330b2 \
      golang.org/x/net@v0.62.0 \
      golang.org/x/sys@v0.49.0 \
      github.com/cloudflare/circl@v1.6.3 \
      github.com/andybalholm/brotli@v1.2.7 \
      github.com/klauspost/compress@v1.20.2 && \
    go mod tidy && \
    go list -m all > /tmp/subfinder-modules && \
    ! grep -q '^golang.org/x/crypto/openpgp ' /tmp/subfinder-modules && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /go/bin/subfinder . && \
    go version -m /go/bin/subfinder > /tmp/subfinder-build-info && \
    grep -Eq 'github.com/andybalholm/brotli[[:space:]]+v1[.]2[.]7([[:space:]]|$)' /tmp/subfinder-build-info && \
    grep -Eq 'github.com/klauspost/compress[[:space:]]+v1[.]20[.]2([[:space:]]|$)' /tmp/subfinder-build-info

FROM node:22.23.4-slim

WORKDIR /app

RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    tini \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r nodejs -g 1001 \
    && useradd -r -u 1001 -g nodejs nodejs

COPY --from=subfinder-builder /go/bin/subfinder /usr/local/bin/subfinder
RUN subfinder -version

RUN corepack enable && corepack prepare pnpm@11.28.8 --activate

COPY package.json pnpm-workspace.yaml pnpm-lock.yaml .npmrc ./
COPY --chown=nodejs:nodejs packages ./packages
COPY --chown=nodejs:nodejs apps/api ./apps/api

ENV NODE_ENV=production

RUN pnpm install --prod --frozen-lockfile --filter @tokentimer/api... && \
    (pnpm audit --audit-level=high || true)

WORKDIR /app/apps/api

USER nodejs

EXPOSE 4000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:4000/', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) })"

ENTRYPOINT ["/usr/bin/tini", "--"]

CMD ["node", "index.js"]
