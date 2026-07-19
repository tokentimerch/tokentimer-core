FROM node:22.23.0-alpine3.23

# Refresh indexes and upgrade base packages (openssl/musl) so scans see current Alpine 3.23 fixes.
# Explicit pin avoids stale GHA cache layers reporting pre-fix libcrypto3/libssl3 revisions.
RUN apk update && apk upgrade --no-cache \
    && apk add --no-cache libcrypto3=3.5.7-r0 libssl3=3.5.7-r0 \
    && test "$(apk list -I libcrypto3 | cut -d- -f2- | cut -d' ' -f1)" = "3.5.7-r0"

WORKDIR /app

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Enable pnpm via corepack
RUN corepack enable && corepack prepare pnpm@11.13.0 --activate

# Ensure production mode
ENV NODE_ENV=production

# Copy workspace config, root package.json, and lockfile from repo root
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml .npmrc ./

# Copy workspace packages and the worker app. --chown instead of a later
# `RUN chown -R /app`, which duplicated source + node_modules into a second
# layer. node_modules stays root-owned; the worker only reads it at runtime.
COPY --chown=nodejs:nodejs packages ./packages
COPY --chown=nodejs:nodejs apps/worker ./apps/worker
COPY --chown=nodejs:nodejs apps/api/services/certops ./apps/api/services/certops
COPY --chown=nodejs:nodejs apps/api/utils/secretMaterial.js ./apps/api/utils/secretMaterial.js
COPY --chown=nodejs:nodejs apps/api/utils/logger.js ./apps/api/utils/logger.js
COPY --chown=nodejs:nodejs apps/api/db/database.js ./apps/api/db/database.js

# Install production dependencies using frozen lockfile
RUN pnpm install --prod --frozen-lockfile --filter @tokentimer/worker...

# Set working directory to worker
WORKDIR /app/apps/worker

USER nodejs

# Default command (overridden by tests/orchestration)
CMD ["node", "-e", "console.log('worker container ready')"]
