#!/bin/sh
set -e

# Generate runtime env file for SPA (write into writable cache volume)
cat > /var/cache/nginx/env.js << EOF
window.__ENV__ = {
  API_URL: "${API_URL:-}"
};
EOF

exec nginx -g 'daemon off;'
