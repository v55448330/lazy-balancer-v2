FROM golang:1.26.6-alpine@sha256:af8d6740070b8906d12eae1c3e3ea0957fb63f492051ea05e354c38ef9fe88df AS xcaddy-builder
RUN apk add --no-cache git
# GOPROXY 逗号多级回退：阿里云 404/410 时依次回落 goproxy.cn、直连；
# 校验不符类瞬态错误由下方 xcaddy build 的重试循环兜底
ENV GOPROXY=https://mirrors.aliyun.com/goproxy/,https://goproxy.cn,direct
# 模块缓存挂载按 builder 持久（lazy-builder GC 48h）：xcaddy 自身依赖复用
# /go/pkg/mod，避免每次构建全量重拉
RUN --mount=type=cache,target=/go/pkg/mod \
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.6
WORKDIR /app

ENV GOTOOLCHAIN=auto
# INFRA-P1（第 69 轮）：xcaddy 阶段只需三个本地插件目录（--with 引用），
# 窄化 COPY 面——此前 COPY . . 全仓入镜，任何前端/文档变更即 bust 该层并重跑
# xcaddy build（缓存挂载兜底仍需分钟级增量编译）。backend 阶段保留全量 COPY
#（Go 编译需全源码）。
COPY caddygeoip/ caddygeoip/
COPY caddydeps/ caddydeps/
COPY wafiplist/ wafiplist/
# 双缓存挂载（模块+编译缓存）按 builder 持久（lazy-builder GC 48h）：
# 根治冷缓存全量重编 42 分钟——命中缓存后增量编译只需数分钟。
# 3 次重试兜底镜像源偶发供应与 sum.golang.org 校验不符的比特
# （pebble@v2.10.0、go-tpm-tools@v0.4.8 类瞬态错误），重试拿到一致比特即过。
# set -e 下 if 条件中的失败不触发退出，由 built 标志统一判定后显式 exit 1
RUN --mount=type=cache,target=/go/pkg/mod \
  --mount=type=cache,target=/root/.cache/go-build \
  set -e; \
  built=0; \
  for attempt in 1 2 3; do \
    if xcaddy build v2.11.6 \
      --with github.com/mholt/caddy-l4@v0.1.2 \
      --with github.com/caddyserver/transform-encoder@ba4124974830222da7f12a091cf11ddf4d49363f \
      --with github.com/mholt/caddy-ratelimit@v0.1.0 \
      --with github.com/corazawaf/coraza-caddy/v2@v2.6.1 \
      --with lazy-balancer-v2/caddygeoip=./caddygeoip \
      --with lazy-balancer-v2/caddydeps=./caddydeps \
      --with lazy-balancer-v2/wafiplist=./wafiplist; then \
      built=1; break; \
    fi; \
    echo ">>> xcaddy build 第 ${attempt}/3 次失败，10s 后重试" >&2; \
    sleep 10; \
  done; \
  [ "$built" -eq 1 ] || { echo ">>> xcaddy build 3 次全部失败" >&2; exit 1; }; \
  [ -f /app/caddy ] || { echo ">>> 构建成功但 /app/caddy 未生成" >&2; exit 1; }
# 构建期断言：镜像扫描要求的最低依赖版本未被 MVS 抬升到位则直接失败
# （版本下限：grpc>=v1.83.2、otel>=v1.45、x/net>=v0.58、x/crypto>=v0.56；
#  cel-go v2.11.6 起随上游 v0.29.2（celmatcher 已适配）；caddydeps 钉同版防传递抬偏，见
#  caddydeps/go.mod 注释；go version -m 各列以 TAB 分隔，用 awk 的 ge()
#  做逐段数值化语义比较，不设上限，依赖升到大版本也不会误报。
#  ge() 的局部变量必须以多余形参声明，否则会覆盖主循环的 i 导致漏检；
#  且 awk 程序必须保持单行——多行函数体会破坏 RUN 指令解析）
RUN go version -m /app/caddy | tee /tmp/caddy-mods.txt && \
    awk -F'\t' 'function ge(v, f,  a, b, av, bv, i) { split(substr(v, 2), a, "."); split(substr(f, 2), b, "."); for (i = 1; i <= 3; i++) { av = a[i] + 0; bv = b[i] + 0; if (av > bv) return 1; if (av < bv) return 0 } return 1 } { for (i = 1; i < NF; i++) { if ($i == "google.golang.org/grpc") ok1 = ge($(i+1), "v1.83.2"); else if ($i == "go.opentelemetry.io/otel") ok2 = ge($(i+1), "v1.45.0"); else if ($i == "golang.org/x/net") ok3 = ge($(i+1), "v0.58.0"); else if ($i == "golang.org/x/crypto") ok4 = ge($(i+1), "v0.56.0") } } END { exit (ok1 && ok2 && ok3 && ok4) ? 0 : 1 }' /tmp/caddy-mods.txt

# Build Go backend
FROM golang:1.26.6-alpine@sha256:af8d6740070b8906d12eae1c3e3ea0957fb63f492051ea05e354c38ef9fe88df AS backend
WORKDIR /app
# U8b-2（第 68 轮审计）：GOPROXY 逗号多级回退——与 xcaddy-builder 阶段对称
#（阶段间 ENV 不继承，backend 此前用官方默认 proxy.golang.org，构建网络对
# 其不可达时 go mod download 无回退直接失败）：阿里云 404/410 时依次回落
# goproxy.cn、直连；校验不符类瞬态错误由下方 3 次重试兜底。
ENV GOPROXY=https://mirrors.aliyun.com/goproxy/,https://goproxy.cn,direct
# wafiplist 叶模块经根 go.mod replace ./wafiplist 引用（v2.3.4）——go mod
# download 解析 replace 需要被替换模块的 go.mod/go.sum 在场。
COPY wafiplist/go.mod wafiplist/go.sum ./wafiplist/
COPY go.mod go.sum ./
# 模块缓存挂载（lazy-builder GC 48h）：go.sum 未变时 download 直接命中缓存；
# 3 次重试兜底镜像源偶发供应与校验不符的瞬态错误（与 xcaddy build 同形态）。
# set -e 下 if 条件中的失败不触发退出，由 dl 标志统一判定后显式 exit 1
RUN --mount=type=cache,target=/go/pkg/mod \
  set -e; \
  dl=0; \
  for attempt in 1 2 3; do \
    if go mod download; then \
      dl=1; break; \
    fi; \
    echo ">>> go mod download 第 ${attempt}/3 次失败，10s 后重试" >&2; \
    sleep 10; \
  done; \
  [ "$dl" -eq 1 ] || { echo ">>> go mod download 3 次全部失败" >&2; exit 1; }
COPY . .
WORKDIR /app/cmd/server
# 双缓存挂载（模块+编译缓存，lazy-builder GC 48h）：增量编译只重编改动包；
# 纯本地编译无网络请求，无需重试
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -o lazy-balancer

# Final image
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
ARG VERSION=v2.3.5
# 构建机网络受限时经 --build-arg HTTP(S)_PROXY 透传给 RUN 下载步骤
# （CRS/ip2region 钉版下载）；未传参时为空值，行为不变（官方惯例形态）。
ARG HTTP_PROXY=""
ARG HTTPS_PROXY=""
ENV APP_VERSION=${VERSION}
# 安全修复：显式钉版 openssl=3.5.9-r0（CVE 修复版）——openssl 经 curl 的
# libssl3/libcrypto3 依赖隐式装入，钉版保证镜像可复现且不携带旧版；
# 升级源超出此版本时构建会失败提示，届时同步更新钉版值。
RUN apk add --no-cache ca-certificates shadow sqlite tzdata openssl=3.5.9-r0
WORKDIR /app

COPY --from=xcaddy-builder /app/caddy /usr/local/bin/caddy
COPY --from=backend /app/cmd/server/lazy-balancer /usr/local/bin/lazy-balancer
COPY web/dist /app/ui

RUN mkdir -p /app/data /app/config /app/logs /app/certs /app/waf/crs /app/waf/audit

# Download OWASP CRS rules (dual-source, aligned with the xdb seed below:
# ghfast.top proxy first, fall back to direct GitHub — their reachability
# from the build network complements each other. Proxy does not support git
# protocol, so use the archive tarball instead of git clone). VERSION marker
# lets startup reconciliation tell the bundled version from user-updated ones.
ARG CRS_VERSION=v4.28.0
# INFRA-R1（第 69 轮）：两段逐字相同的 apk-curl 三次重试循环合并为单个 RUN——
# 一次装 curl → CRS 下载/校验/解包 → waf.dist 快照 → xdb 下载/校验 → 一次
# apk del curl；少两层、少一次装删、重试逻辑单份。
# apk add 包 3 次重试：Alpine CDN 偶发 zstd 解压 I/O error（下载块损坏类
# 瞬态错误），重试重新拉包即可消化；curl 双源回退逻辑保持不变
RUN n=0; until apk add --no-cache curl; do \
      n=$((n+1)); \
      if [ "$n" -ge 3 ]; then echo ">>> apk add curl 3 次失败" >&2; exit 1; fi; \
      echo ">>> apk add curl 第 ${n}/3 次失败，10s 后重试" >&2; sleep 10; \
    done && \
    mkdir -p /tmp/crs-src && \
    (curl -sfL -o /tmp/crs.tar.gz "https://ghfast.top/https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_VERSION}.tar.gz" || \
     curl -sfL -o /tmp/crs.tar.gz "https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_VERSION}.tar.gz") && \
    echo "d8acc96f25ad07c8e3a595a23c797324f6d77e59ddf9e26e90dd95ebd2e676ce  /tmp/crs.tar.gz" | sha256sum -c - && \
    tar xzf /tmp/crs.tar.gz --strip-components=1 -C /tmp/crs-src && \
    cp -r /tmp/crs-src/rules /app/waf/crs/rules && \
    cp /tmp/crs-src/crs-setup.conf.example /app/waf/crs/crs-setup.conf && \
    echo "${CRS_VERSION}" > /app/waf/crs/VERSION && \
    rm -rf /tmp/crs-src /tmp/crs.tar.gz && \
    cp -r /app/waf /app/waf.dist && \
    (curl -sfL -o /app/waf.dist/ip2region.xdb "https://ghfast.top/https://raw.githubusercontent.com/lionsoul2014/ip2region/v3.17.0/data/ip2region_v4.xdb" || \
     curl -sfL -o /app/waf.dist/ip2region.xdb "https://raw.githubusercontent.com/lionsoul2014/ip2region/v3.17.0/data/ip2region_v4.xdb") && \
    echo "6307a9696f5711f84bcb8b25f07894de68a64a0ed4a1cc7e990562dd3084f210  /app/waf.dist/ip2region.xdb" | sha256sum -c - && \
    apk del curl
# 容器以 root 运行（无 USER/降权，与常见 Caddy 镜像同态）；如需非 root，需
# 同时给 80/443 加 CAP_NET_BIND_SERVICE 并预置 bind 挂载属主（第 47 轮 F-47-29）

COPY --from=backend /app/config /app/config

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# 443/udp = HTTP/3（QUIC）——Caddy 默认启用，EXPOSE 补全声明（INFRA-P2）。
EXPOSE 80 443 443/udp 8000

ENTRYPOINT ["docker-entrypoint.sh"]
