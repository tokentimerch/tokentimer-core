FROM node:22.22.2-slim AS build

# Build arguments (leave empty by default so production uses relative /api)
ARG VITE_API_URL=
ARG API_URL=
ARG REACT_APP_ENVIRONMENT=production

WORKDIR /app

# Install essential packages for building
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Enable pnpm via corepack
RUN corepack enable && corepack prepare pnpm@10.33.4 --activate

# Copy package files
COPY package.json pnpm-lock.yaml* ./

# Install all dependencies with security audit (using frozen lockfile for deterministic builds)
RUN pnpm install --frozen-lockfile && \
    pnpm audit --audit-level=high || true

# Copy source code
COPY . .

# Set environment variables for build and keep API_URL fallback compatibility
ENV REACT_APP_ENVIRONMENT=$REACT_APP_ENVIRONMENT

# Build the application
RUN VITE_API_URL="${VITE_API_URL:-$API_URL}" pnpm run build

# Production stage with Nginx
FROM nginx:1.28.3-alpine3.23

# Refresh indexes and upgrade base packages (openssl/musl) so scans see current Alpine 3.23 fixes.
# CVE-2026-9256: pin nginx=1.28.3-r2 (remove unused nginx-module-* first to avoid r1/r2 conflict).
RUN apk update && apk upgrade --no-cache \
    && apk del --no-cache \
        nginx-module-acme \
        nginx-module-geoip \
        nginx-module-image-filter \
        nginx-module-njs \
        nginx-module-xslt \
    && apk add --no-cache nginx=1.28.3-r2 \
    && test "$(apk list -I nginx | cut -d- -f2- | cut -d' ' -f1)" = "1.28.3-r2"

# Create non-root user for Nginx
RUN mkdir -p /usr/share/nginx/html && \
    addgroup -g 1001 -S nginx-user && \
    adduser -S nginx-user -u 1001

# Copy built application
COPY --from=build /app/dist /usr/share/nginx/html

# Copy custom Nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Runtime env injection for SPA
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Change ownership of web files
RUN chown -R nginx-user:nginx-user /usr/share/nginx/html

# Expose unprivileged port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/ || exit 1

# Start via entrypoint to generate /usr/share/nginx/html/env.js from env vars
ENTRYPOINT ["/docker-entrypoint.sh"]
