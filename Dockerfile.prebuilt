FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40 as base
RUN apk add --no-cache ca-certificates curl

FROM golang:1.26.1-alpine@sha256:2389ebfa5b7f43eeafbd6be0c3700cc46690ef842ad962f6c5bd6be49ed82039 AS xcaddy-builder
RUN apk add --no-cache git
ENV GOPROXY=https://goproxy.cn,direct
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.5
WORKDIR /app

ENV GOTOOLCHAIN=auto
COPY . .
RUN xcaddy build v2.11.4 \
  --with github.com/mholt/caddy-l4@v0.1.2 \
  --with github.com/caddyserver/transform-encoder@ba4124974830222da7f12a091cf11ddf4d49363f \
  --with github.com/mholt/caddy-ratelimit@v0.1.0 \
  --with github.com/corazawaf/coraza-caddy/v2@v2.5.0 \
  --with lazy-balancer-v2/caddygeoip=./caddygeoip

# Build Go backend
FROM golang:1.26.1-alpine@sha256:2389ebfa5b7f43eeafbd6be0c3700cc46690ef842ad962f6c5bd6be49ed82039 AS backend
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
WORKDIR /app/cmd/server
RUN CGO_ENABLED=0 GOOS=linux go build -o lazy-balancer

# Final image
FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
ARG VERSION=2.1.0
ENV APP_VERSION=${VERSION}
RUN apk add --no-cache ca-certificates shadow sqlite tzdata
WORKDIR /app

COPY --from=xcaddy-builder /app/caddy /usr/local/bin/caddy
COPY --from=backend /app/cmd/server/lazy-balancer /usr/local/bin/lazy-balancer
COPY web/dist /app/ui

RUN mkdir -p /app/data /app/config /app/logs /app/certs /app/waf/crs /app/waf/custom /app/waf/audit

# Download OWASP CRS rules
RUN apk add --no-cache git && \
    git clone --depth 1 --branch v4.14.0 https://github.com/coreruleset/coreruleset.git /tmp/crs && \
    cp -r /tmp/crs/rules /app/waf/crs/rules && \
    cp /tmp/crs/crs-setup.conf.example /app/waf/crs/crs-setup.conf && \
    rm -rf /tmp/crs && \
    apk del git
# Pristine copy used to seed an empty bind-mounted /app/waf on first boot
RUN cp -r /app/waf /app/waf.dist
# Initial GeoIP database seed
RUN apk add --no-cache curl && \
    curl -sL -o /app/waf.dist/ip2region.xdb https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb && \
    apk del curl
RUN adduser -u 1000 -s /bin/sh -D -h /app caddy

COPY --from=backend /app/config /app/config

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 80 443 8000

ENTRYPOINT ["docker-entrypoint.sh"]
