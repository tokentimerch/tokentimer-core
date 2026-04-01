#!/bin/sh
set -e

# Generate runtime env.js from environment variables so the SPA can read
# config that was not available at build time (e.g. API_URL).
cat > /var/cache/nginx/env.js << EOF
window.__ENV__ = {
  API_URL: "${API_URL:-}"
};
EOF

exec nginx -g 'daemon off;'
