FROM node:22.23.0-alpine3.23

# Keep the controller base aligned with the worker image's patched Alpine base.
RUN apk update && apk upgrade --no-cache \
    && apk add --no-cache libcrypto3=3.5.7-r0 libssl3=3.5.7-r0 \
    && test "$(apk list -I libcrypto3 | cut -d- -f2- | cut -d' ' -f1)" = "3.5.7-r0"

WORKDIR /app

RUN addgroup -g 1001 -S tokentimer \
    && adduser -u 1001 -S tokentimer -G tokentimer \
    && corepack enable \
    && corepack prepare pnpm@11.13.0 --activate

ENV NODE_ENV=production

COPY package.json pnpm-workspace.yaml pnpm-lock.yaml .npmrc ./
COPY --chown=tokentimer:tokentimer packages ./packages
COPY --chown=tokentimer:tokentimer apps/k8s-controller ./apps/k8s-controller
# The controller reuses the canonical parser, its direct identity helper, and
# the shared detector without importing the API server or a generic Secret API.
COPY --chown=tokentimer:tokentimer apps/api/utils/secretMaterial.js ./apps/api/utils/secretMaterial.js
COPY --chown=tokentimer:tokentimer apps/api/services/certops/parser.js ./apps/api/services/certops/parser.js
COPY --chown=tokentimer:tokentimer apps/api/services/certops/identitySafety.js ./apps/api/services/certops/identitySafety.js

RUN pnpm install --prod --frozen-lockfile --filter @tokentimer/k8s-controller...

WORKDIR /app/apps/k8s-controller

USER tokentimer

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "const rawPort=process.env.CERTOPS_HEALTH_PORT || 8080;const port=Number(rawPort);if(!Number.isInteger(port)||port<1||port>65535||String(rawPort).trim()!==String(port))process.exit(1);require('http').get({host:'127.0.0.1',port,path:'/healthz'},(res)=>process.exit(res.statusCode===200?0:1)).on('error',()=>process.exit(1))"

CMD ["node", "src/index.js"]
