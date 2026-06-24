#!/bin/sh
set -e

# Initialize database on first run
if [ ! -f /app/data/lazy-balancer.db ]; then
    echo "Initializing database..."
    /usr/local/bin/lazy-balancer --init
    chown -R caddy:caddy /app/data
fi

# Generate Caddyfile if not exists
if [ ! -f /app/config/Caddyfile ]; then
    if [ -f /app/config/Caddyfile.dist ]; then
        cp /app/config/Caddyfile.dist /app/config/Caddyfile
    else
        echo "placeholder" > /app/config/Caddyfile
    fi
fi

# Set DNSPod credentials from environment if provided
if [ -n "$DNSPOD_ID" ]; then
    export DNSPOD_ID
fi
if [ -n "$DNSPOD_TOKEN" ]; then
    export DNSPOD_TOKEN
fi

# Export ACME DNS provider credentials as environment variables for Caddy
if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "${DATA_DIR:-/app/data}/lazy-balancer.db" "SELECT id, dns_provider, dns_credentials FROM certificate_configs WHERE enabled=1;" | while IFS='|' read -r id provider creds; do
        if [ -n "$creds" ]; then
            env_var_name=""
            token=""
            case "$provider" in
                dnspod)
                    token=$(echo "$creds" | jq -r '.auth_token // empty')
                    env_var_name="DNSPOD_AUTH_TOKEN_${id}"
                    ;;
                cloudflare)
                    token=$(echo "$creds" | jq -r '.api_token // empty')
                    env_var_name="CF_API_TOKEN_${id}"
                    ;;
            esac
            if [ -n "$env_var_name" ] && [ -n "$token" ]; then
                export "$env_var_name=$token"
                echo "Exported $env_var_name"
            fi
        fi
    done
fi

# Start Caddy in background
echo "Starting Caddy..."
caddy run --config /app/config/Caddyfile --adapter caddyfile &

# Start backend
echo "Starting Lazy Balancer..."
exec /usr/local/bin/lazy-balancer serve