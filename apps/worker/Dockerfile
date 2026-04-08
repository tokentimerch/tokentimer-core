FROM node:22.22.2-alpine3.23

WORKDIR /app

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Enable pnpm via corepack
RUN corepack enable && corepack prepare pnpm@10.33.0 --activate

# Ensure production mode
ENV NODE_ENV=production

# Copy workspace config, root package.json, and lockfile from repo root
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml .npmrc ./

# Copy workspace packages and the worker app
COPY packages ./packages
COPY apps/worker ./apps/worker

# Install production dependencies using frozen lockfile
RUN pnpm install --prod --frozen-lockfile --filter @tokentimer/worker...

# Set working directory to worker
WORKDIR /app/apps/worker

# Change ownership to nodejs user
RUN chown -R nodejs:nodejs /app
USER nodejs

# Default command (overridden by tests/orchestration)
CMD ["node", "-e", "console.log('worker container ready')"]
