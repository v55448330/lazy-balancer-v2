FROM golang:1.26.6-alpine@sha256:af8d6740070b8906d12eae1c3e3ea0957fb63f492051ea05e354c38ef9fe88df AS xcaddy-builder
RUN apk add --no-cache git
ENV GOPROXY=https://goproxy.cn,direct
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.6
WORKDIR /app

ENV GOTOOLCHAIN=auto
COPY . .
RUN xcaddy build v2.11.4 \
  --with github.com/mholt/caddy-l4@v0.1.2 \
  --with github.com/caddyserver/transform-encoder@ba4124974830222da7f12a091cf11ddf4d49363f \
  --with github.com/mholt/caddy-ratelimit@v0.1.0 \
  --with github.com/corazawaf/coraza-caddy/v2@v2.5.0 \
  --with lazy-balancer-v2/caddygeoip=./caddygeoip \
  --with lazy-balancer-v2/caddydeps=./caddydeps
# 构建期断言：镜像扫描要求的最低依赖版本未被 MVS 抬升到位则直接失败
# （版本下限：grpc>=v1.82、otel>=v1.44、x/net>=v0.56；go version -m 各列以 TAB 分隔，
#  用 awk 做数值化语义比较，不设上限，依赖升到大版本也不会误报）
RUN go version -m /app/caddy | tee /tmp/caddy-mods.txt && \
    awk -F'\t' '
      function ge(ver, floor,   va, fa, i, a, b) {
        split(substr(ver, 2), va, "."); split(substr(floor, 2), fa, ".")
        for (i = 1; i <= 3; i++) {
          a = va[i] + 0; b = fa[i] + 0
          if (a > b) return 1
          if (a < b) return 0
        }
        return 1
      }
      {
        for (i = 1; i < NF; i++) {
          if ($i == "google.golang.org/grpc") ok1 = ge($(i+1), "v1.82.0")
          else if ($i == "go.opentelemetry.io/otel") ok2 = ge($(i+1), "v1.44.0")
          else if ($i == "golang.org/x/net") ok3 = ge($(i+1), "v0.56.0")
        }
      }
      END { exit (ok1 && ok2 && ok3) ? 0 : 1 }
    ' /tmp/caddy-mods.txt

# Build Go backend
FROM golang:1.26.6-alpine@sha256:af8d6740070b8906d12eae1c3e3ea0957fb63f492051ea05e354c38ef9fe88df AS backend
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
WORKDIR /app/cmd/server
RUN CGO_ENABLED=0 GOOS=linux go build -o lazy-balancer

# Final image
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
ARG VERSION=2.1.5
ENV APP_VERSION=${VERSION}
RUN apk add --no-cache ca-certificates shadow sqlite tzdata
WORKDIR /app

COPY --from=xcaddy-builder /app/caddy /usr/local/bin/caddy
COPY --from=backend /app/cmd/server/lazy-balancer /usr/local/bin/lazy-balancer
COPY web/dist /app/ui

RUN mkdir -p /app/data /app/config /app/logs /app/certs /app/waf/crs /app/waf/custom /app/waf/audit

# Download OWASP CRS rules (via ghfast.top proxy — direct GitHub access is
# unreliable from the build network; proxy does not support git protocol,
# so use the archive tarball instead of git clone). VERSION marker lets
# startup reconciliation tell the bundled version from user-updated ones.
ARG CRS_VERSION=v4.28.0
RUN apk add --no-cache curl && \
    mkdir -p /tmp/crs-src && \
    curl -sL "https://ghfast.top/https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_VERSION}.tar.gz" | tar xz --strip-components=1 -C /tmp/crs-src && \
    cp -r /tmp/crs-src/rules /app/waf/crs/rules && \
    cp /tmp/crs-src/crs-setup.conf.example /app/waf/crs/crs-setup.conf && \
    echo "${CRS_VERSION}" > /app/waf/crs/VERSION && \
    rm -rf /tmp/crs-src && \
    apk del curl
# Pristine copy used to seed an empty bind-mounted /app/waf on first boot
RUN cp -r /app/waf /app/waf.dist
# Initial GeoIP database seed
RUN apk add --no-cache curl && \
    curl -sL -o /app/waf.dist/ip2region.xdb "https://ghfast.top/https://raw.githubusercontent.com/lionsoul2014/ip2region/v3.17.0/data/ip2region_v4.xdb" && \
    apk del curl
RUN adduser -u 1000 -s /bin/sh -D -h /app caddy

COPY --from=backend /app/config /app/config

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 80 443 8000

ENTRYPOINT ["docker-entrypoint.sh"]
