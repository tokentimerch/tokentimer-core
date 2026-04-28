FROM golang:1.26.2-alpine3.23 AS subfinder-builder

RUN apk add --no-cache ca-certificates git && \
    CGO_ENABLED=0 go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.13.0

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

# Install subfinder v2.13.0 for Domain Checker discovery.
COPY --from=subfinder-builder /go/bin/subfinder /usr/local/bin/subfinder
RUN subfinder -version

# Enable pnpm via corepack
RUN corepack enable && corepack prepare pnpm@10.33.0 --activate

# Copy package files
COPY package.json pnpm-lock.yaml* ./

# Ensure production mode for installs/runtime
ENV NODE_ENV=production

# Install production dependencies (using frozen lockfile for deterministic builds)
RUN pnpm install --prod --frozen-lockfile && \
    pnpm audit --audit-level=high || true

# Copy source code (node_modules should not be in build context)
COPY . .

# Change ownership to nodejs user
RUN chown -R nodejs:nodejs /app
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
