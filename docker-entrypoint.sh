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

# Start Caddy in background
echo "Starting Caddy..."
caddy run --config /app/config/Caddyfile --adapter caddyfile &

# Start backend
echo "Starting Lazy Balancer..."
exec /usr/local/bin/lazy-balancer serve