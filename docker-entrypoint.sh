#!/bin/sh
set -e

# Use /app/data as the single persistent data directory.
export XDG_DATA_HOME=/app/data
mkdir -p /app/data/caddy

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

# Set timezone from database if available
if [ -f /app/data/lazy-balancer.db ]; then
    TZ=$(sqlite3 /app/data/lazy-balancer.db "SELECT COALESCE(timezone,'Asia/Shanghai') FROM global_config WHERE id=1" 2>/dev/null || echo "Asia/Shanghai")
    export TZ
    echo "Timezone: $TZ"
fi

# Start Caddy in background
echo "Starting Caddy..."
caddy run --config /app/config/Caddyfile --adapter caddyfile &

# Start backend
echo "Starting Lazy Balancer..."
exec /usr/local/bin/lazy-balancer serve