FROM golang:1.26.4-alpine3.23 AS subfinder-builder

RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache ca-certificates git

RUN git clone --depth 1 --branch v2.14.0 https://github.com/projectdiscovery/subfinder.git /src

WORKDIR /src/cmd/subfinder
RUN go get \
      golang.org/x/crypto@v0.52.0 \
      golang.org/x/net@v0.55.0 \
      golang.org/x/sys@v0.45.0 \
      github.com/cloudflare/circl@v1.6.3 && \
    go mod tidy && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /go/bin/subfinder .

FROM node:22.22.2-slim

# Create app directory
WORKDIR /app

# Install security updates and runtime packages
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    tini \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r nodejs -g 1001 \
    && useradd -r -u 1001 -g nodejs nodejs

# Install subfinder v2.14.0 for Domain Checker discovery.
COPY --from=subfinder-builder /go/bin/subfinder /usr/local/bin/subfinder
RUN subfinder -version

# Enable pnpm via corepack
RUN corepack enable && corepack prepare pnpm@11.13.0 --activate

# Copy package files. Standalone apps/api context: inject allowBuilds for pnpm 11.
COPY package.json pnpm-lock.yaml* ./
RUN printf '%s\n' \
      'allowBuilds:' \
      '  "@scarf/scarf": true' \
      '  esbuild: true' \
      '  sharp: true' \
      > pnpm-workspace.yaml

# Ensure production mode for installs/runtime
ENV NODE_ENV=production

# Install production dependencies (using frozen lockfile for deterministic builds)
RUN pnpm install --prod --frozen-lockfile && \
    pnpm audit --audit-level=high || true

# Copy source code (node_modules should not be in build context).
# --chown instead of a later `RUN chown -R /app`: the blanket chown duplicated
# every layer (source + node_modules) and roughly doubled the image size.
# node_modules stays root-owned; the app only needs read access at runtime.
COPY --chown=nodejs:nodejs . .

USER nodejs

# Expose port
EXPOSE 4000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:4000/', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) })"

# Use tini for proper signal handling
ENTRYPOINT ["/usr/bin/tini", "--"]

# Start the application
CMD ["node", "index.js"]
