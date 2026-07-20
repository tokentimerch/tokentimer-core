# Build context must be the repo root.
# Prefer deploy/compose/Dockerfile.dashboard for production Compose/CI images.
FROM node:22.23.0-slim AS build

ARG VITE_API_URL=
ARG API_URL=
ARG REACT_APP_ENVIRONMENT=production

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

RUN corepack enable && corepack prepare pnpm@11.13.0 --activate

COPY package.json pnpm-workspace.yaml pnpm-lock.yaml .npmrc ./
COPY apps/dashboard/package.json ./apps/dashboard/

RUN pnpm install --frozen-lockfile --filter @tokentimer/dashboard... && \
    (pnpm audit --audit-level=high || true)

COPY apps/dashboard ./apps/dashboard

ENV REACT_APP_ENVIRONMENT=$REACT_APP_ENVIRONMENT

RUN VITE_API_URL="${VITE_API_URL:-$API_URL}" pnpm --filter @tokentimer/dashboard run build

FROM nginx:1.28.3-alpine3.23

# Refresh indexes and upgrade base packages (openssl/musl) so scans see current Alpine 3.23 fixes.
# CVE-2026-9256 / CVE-2026-49975: pin nginx=1.28.3-r4 (patched Alpine 3.23 revision).
# Drop unused nginx-module-* packages first; their r1 revisions block apk upgrades.
RUN apk update && apk upgrade --no-cache \
    && apk add --no-cache libcrypto3=3.5.7-r0 libssl3=3.5.7-r0 \
    && apk del --no-cache \
        nginx \
        nginx-module-acme \
        nginx-module-geoip \
        nginx-module-image-filter \
        nginx-module-njs \
        nginx-module-xslt \
    && apk add --no-cache nginx=1.28.3-r4 \
    && test "$(apk list -I libcrypto3 | cut -d- -f2- | cut -d' ' -f1)" = "3.5.7-r0" \
    && test "$(apk list -I nginx | cut -d- -f2- | cut -d' ' -f1)" = "1.28.3-r4" \
    && mkdir -p /run/nginx

RUN mkdir -p /usr/share/nginx/html && \
    addgroup -g 1001 -S nginx-user && \
    adduser -S nginx-user -u 1001

COPY --from=build /app/apps/dashboard/dist /usr/share/nginx/html

COPY apps/dashboard/nginx.conf /etc/nginx/nginx.conf
COPY apps/dashboard/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

RUN chown -R nginx-user:nginx-user /usr/share/nginx/html

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/ || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]
