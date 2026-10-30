# 编译阶段固定在构建机架构执行（--platform=$BUILDPLATFORM）：buildx 多架构构建
# 不会为目标架构起 QEMU 跑 Go 工具链（跨架构编译慢数倍）。产物架构由下方
# GOOS/GOARCH 显式指定；CGO_ENABLED=0 使交叉编译无需目标架构的 C 工具链。
FROM --platform=$BUILDPLATFORM golang:1.26.10-alpine@sha256:27f2d3b83cfc5803c8078f8e730af0f7c431bf067afaec8f60a36fb763187cba AS xcaddy-builder
RUN apk add --no-cache git
# GOPROXY 逗号多级回退：阿里云 404/410 时依次回落 goproxy.cn、直连；
# 校验不符类瞬态错误由下方 xcaddy build 的重试循环兜底
ENV GOPROXY=https://mirrors.aliyun.com/goproxy/,https://goproxy.cn,direct
# 模块缓存挂载按 builder 持久（lazy-builder GC 48h）：xcaddy 自身依赖复用
# /go/pkg/mod，避免每次构建全量重拉
RUN --mount=type=cache,target=/go/pkg/mod \
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.6
WORKDIR /app

# GOTOOLCHAIN=auto（本阶段仅作显式诊断兜底）：xcaddy 在临时主模块里按 Caddy
# 声明的 go 指令构建；若 Caddy 提高到更高 Go 要求，auto 会拉取新工具链，而下方
# go1.26.10 精确断言会立即拒绝产物。此时必须同步 bump 基础镜像与断言，不得把
# 自动升级静默带入镜像；backend 阶段用 local 执行同一精确版本契约。
ENV GOTOOLCHAIN=auto
# 代理不在此声明：Docker 预定义 HTTP_PROXY/HTTPS_PROXY 等构建参数，经
# --build-arg 传入后自动注入每条 RUN 的环境，无需 ARG 声明（声明了却不引用
# 等于把代理值写进该声明之后各层的缓存键，同一份代码在不同网络环境下无法复用
# 已有层）。三条 golang/alpine 阶段同此口径。
#
# 交叉编译目标：buildx 预定义参数；无 buildx 时 TARGETARCH 为空，回落构建机
# 架构（本阶段已固定在 BUILDPLATFORM 上执行，必须显式指定产物平台）。
ARG TARGETOS=linux
ARG TARGETARCH
# xcaddy 阶段只需四个本地目录（--with 引用），窄化 COPY 面——整目录复制会让
# 任何前端/文档变更 bust 该层并重跑 xcaddy build（缓存挂载兜底仍需分钟级增量
# 编译）。backend 阶段同样用显式清单（见该阶段注释）。geoipnames 是零依赖
# 共享表库——
# --with 在此兼作 replace 载体（插件模块内 replace 对 xcaddy 临时主模块无效，
# 与 wafiplist 同模式双保险）。
COPY caddygeoip/ caddygeoip/
COPY caddydeps/ caddydeps/
COPY wafiplist/ wafiplist/
COPY geoipnames/ geoipnames/
# 双缓存挂载（模块+编译缓存）按 builder 持久（lazy-builder GC 48h）：
# 根治冷缓存全量重编 42 分钟——命中缓存后增量编译只需数分钟。
# 3 次重试兜底镜像源偶发供应与 sum.golang.org 校验不符的比特
# （pebble@v2.10.0、go-tpm-tools@v0.4.8 类瞬态错误），重试拿到一致比特即过。
# set -e 下 if 条件中的失败不触发退出，由 built 标志统一判定后显式 exit 1
RUN --mount=type=cache,target=/go/pkg/mod \
  --mount=type=cache,target=/root/.cache/go-build \
  export CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-$(go env GOARCH)}"; \
  set -e; \
  built=0; \
  for attempt in 1 2 3; do \
    if xcaddy build v2.11.7 \
      --with github.com/mholt/caddy-l4@v0.1.2 \
      --with github.com/caddyserver/transform-encoder@ba4124974830222da7f12a091cf11ddf4d49363f \
      --with github.com/mholt/caddy-ratelimit@v0.1.0 \
      --replace github.com/go-chi/chi/v5=github.com/go-chi/chi/v5@v5.4.0 \
      --with github.com/corazawaf/coraza-caddy/v2@v2.6.2 \
      --with lazy-balancer-v2/caddygeoip=./caddygeoip \
      --with lazy-balancer-v2/caddydeps=./caddydeps \
      --with lazy-balancer-v2/wafiplist=./wafiplist \
      --with lazy-balancer-v2/geoipnames=./geoipnames; then \
      built=1; break; \
    fi; \
    echo ">>> xcaddy build 第 ${attempt}/3 次失败，10s 后重试" >&2; \
    sleep 10; \
  done; \
  [ "$built" -eq 1 ] || { echo ">>> xcaddy build 3 次全部失败" >&2; exit 1; }; \
  [ -f /app/caddy ] || { echo ">>> 构建成功但 /app/caddy 未生成" >&2; exit 1; }
# 构建期断言：镜像扫描要求的最低依赖版本未被 MVS 抬升到位则直接失败
# （版本下限：grpc>=v1.83.2、otel>=v1.45、x/net>=v0.62、x/crypto>=v0.58、
#  go-jose/v4>=v4.1.6、cel.dev/cel-go>=v0.32.0、go-chi/chi/v5>=v5.4.0——
#  Caddy v2.11.7 上游对 grpc/cel-go 同值、otel 更高；x/net/x/crypto/go-jose
#  三条是漏洞修复下限（上游传递图更低），由 caddydeps floor 主动抬升；
#  注意模块路径是 cel.dev/cel-go，github.com/google/cel-go 是另一个
#  模块路径，钉旧路径不参与 MVS）；go version -m 各列以 TAB 分隔，用 awk 的 ge()
#  做逐段数值化语义比较，不设上限，依赖升到大版本也不会误报。
#  ge() 的局部变量必须以多余形参声明，否则会覆盖主循环的 i 导致漏检；
#  且 awk 程序必须保持单行——多行函数体会破坏 RUN 指令解析）
#  唯一例外是 github.com/corazawaf/coraza/v3：安全拦截计数/计时
#  分段归属依赖 coraza tx.ID 长度=16，MVS 抬升次版本可能静默改变该假设，故按
#  [v3.8.1, v3.9) 区间断言（ge(v,"v3.8.1") && !ge(v,"v3.9.0")）——此处刻意设
#  上限，升级需同步复核 blocked_counter.go 的 len(ID)==16 判定与本断言。
#  归因：模块表由 BEGIN 段一次登记（改阈值只改这一处），END 段逐项打印
#  「>>> 依赖下限不满足: <模块> 需要 <阈值>（实际 <版本>）」到 stderr 后再非零
#  退出——构建日志直接指出失败项，无需人工解析阈值表；模块整体从依赖图消失
#  时实际值报「未出现在依赖图中」（同样判失败）。
RUN go version -m /app/caddy | tee /tmp/caddy-mods.txt && \
    grep -q 'go1.26.10' /tmp/caddy-mods.txt || { echo ">>> Caddy 未使用 go1.26.10 构建" >&2; exit 1; }; \
    awk -F'\t' 'function ge(v, f,  a, b, av, bv, i) { split(substr(v, 2), a, "."); split(substr(f, 2), b, "."); for (i = 1; i <= 3; i++) { av = a[i] + 0; bv = b[i] + 0; if (av > bv) return 1; if (av < bv) return 0 } return 1 } BEGIN { n = split("google.golang.org/grpc v1.83.2;go.opentelemetry.io/otel v1.45.0;go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.45.0;go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.45.0;go.opentelemetry.io/otel/metric v1.45.0;go.opentelemetry.io/otel/trace v1.45.0;golang.org/x/net v0.62.0;golang.org/x/crypto v0.58.0;github.com/go-jose/go-jose/v4 v4.1.6;cel.dev/cel-go v0.32.0;github.com/corazawaf/coraza/v3 v3.8.1;github.com/go-chi/chi/v5 v5.4.0", spec, ";"); for (k = 1; k <= n; k++) { split(spec[k], pair, " "); mods[k] = pair[1]; floor[mods[k]] = pair[2] } } { for (i = 1; i < NF; i++) { if (floor[$i] != "") { ver[$i] = $(i+1); ok[$i] = ge($(i+1), floor[$i]); if ($i == "github.com/corazawaf/coraza/v3" && ge($(i+1), "v3.9.0")) ok[$i] = 0 } } } END { rc = 0; for (k = 1; k <= n; k++) { m = mods[k]; if (ok[m] != 1) { rc = 1; want = ">= " floor[m]; if (m == "github.com/corazawaf/coraza/v3") want = want " 且 < v3.9.0"; actual = (ver[m] == "") ? "未出现在依赖图中" : ver[m]; print ">>> 依赖下限不满足: " m " 需要 " want "（实际 " actual "）" > "/dev/stderr" } } exit rc }' /tmp/caddy-mods.txt

# Build Go backend
# 与 xcaddy-builder 阶段同理：编译在构建机架构执行，产物平台由 GOOS/GOARCH 指定。
FROM --platform=$BUILDPLATFORM golang:1.26.10-alpine@sha256:27f2d3b83cfc5803c8078f8e730af0f7c431bf067afaec8f60a36fb763187cba AS backend
WORKDIR /app
# 交叉编译目标（buildx 预定义参数；无 buildx 时 TARGETARCH 为空则回落构建机架构）
ARG TARGETOS=linux
ARG TARGETARCH
# GOPROXY 逗号多级回退——与 xcaddy-builder 阶段对称
#（阶段间 ENV 不继承，backend 此前用官方默认 proxy.golang.org，构建网络对
# 其不可达时 go mod download 无回退直接失败）：阿里云 404/410 时依次回落
# goproxy.cn、直连；校验不符类瞬态错误由下方 3 次重试兜底。
ENV GOPROXY=https://mirrors.aliyun.com/goproxy/,https://goproxy.cn,direct
# GOTOOLCHAIN=local：镜像内的 Go 二进制只由基础镜像声明的工具链产出。auto 会在
# 模块 go 指令高于本地工具链时构建期下载新工具链——同一 Dockerfile 在不同时间
# 可能得到不同编译器产物，且下载失败与依赖拉取失败的错误形态混淆。工具链不足
# 时应由构建显性失败，同步 bump 基础镜像。
ENV GOTOOLCHAIN=local
# wafiplist/geoipnames 叶模块经根 go.mod replace ./wafiplist ./geoipnames 引用
# ——go mod download 解析 replace 需要被替换模块的 go.mod/go.sum 在场
# （geoipnames 零依赖无 go.sum）。
COPY wafiplist/go.mod wafiplist/go.sum ./wafiplist/
COPY geoipnames/go.mod ./geoipnames/
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
# 显式 COPY 清单（不用 `COPY . .`）：构建上下文含 web/、docs/、scripts/ 等非 Go
# 内容，整目录复制会让任意一处非 Go 变更 bust 本层与随后的 Go 编译层。
# go.mod/go.sum 已在上方下载层复制（本阶段内，同在清单范围），此处不再重复。
# 清单必须覆盖 go list 派生到的全部顶层 Go 目录（cmd/internal/caddygeoip/
# caddydeps/wafiplist/geoipnames）——scripts/check-dockerfile-copy-manifest.sh
# 按 backend 阶段切块，比对清单与受控 + 未跟踪（未被 .gitignore 忽略）的顶层
# Go 目录，与 test-all 同口径；新增顶层 Go 目录必须同步本行。
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY caddygeoip/ ./caddygeoip/
COPY caddydeps/ ./caddydeps/
COPY wafiplist/ ./wafiplist/
COPY geoipnames/ ./geoipnames/
COPY config/ ./config/
WORKDIR /app/cmd/server
# 双缓存挂载（模块+编译缓存，lazy-builder GC 48h）：增量编译只重编改动包；
# 纯本地编译无网络请求，无需重试。
# 产物平台显式取自 TARGETOS/TARGETARCH（本阶段跑在 BUILDPLATFORM 上）：
# -trimpath 去掉构建机绝对路径（可复现构建，panic 栈只留模块相对路径）；
# -ldflags="-s -w" 去符号表与 DWARF（版本号走运行时 APP_VERSION，不经 ldflags）。
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-$(go env GOARCH)}" \
    go build -trimpath -ldflags="-s -w" -o lazy-balancer && \
    go version -m lazy-balancer | grep -q 'go1.26.10' || { echo ">>> 后端二进制未使用 go1.26.10 构建" >&2; exit 1; }

# Final image
FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
# 版本号注入（ARG VERSION + ENV APP_VERSION）刻意放在下方 CRS/xdb 下载层之后
# ——见该层前的层序说明。此处不得放 ENV：版本号每次发版必变，提前注入会让
# 之后所有外网下载层缓存失效。
# 构建机网络受限时经 --build-arg HTTP(S)_PROXY 透传给本阶段下载步骤
# （CRS/ip2region 钉版下载）：Docker 预定义代理参数传入后自动注入 RUN 环境，
# 无需 ARG 声明；未传参时为空值，行为不变。
# 安全修复：显式钉版 openssl=3.5.9-r0（CVE 修复版）——openssl 经 curl 的
# libssl3/libcrypto3 依赖隐式装入，钉版保证镜像可复现且不携带旧版；
# 升级源超出此版本时构建会失败提示，届时同步更新钉版值。
# 不装 shadow——全仓（entrypoint/Dockerfile RUN 链/docs/compose）无
# useradd/usermod/groupadd 等调用，镜像内无消费方。
# zlib 钉版 1.3.2-r1：alpine 3.24.2 基础镜像快照携带 r0，r1 为上游安全修复——
# 沿 openssl 钉版先例显式升级（sqlite 依赖隐式装入 zlib）。
# 安全修复（CVE 扫描）：musl 1.2.6-r6 目前只存在于 alpine edge 仓库——3.24
# 分支最新仍为 r3。这里只对 musl/musl-utils 两个包指定 edge 仓库并精确钉版，
# 基础系统（busybox/apk/openssl/zlib）仍来自 3.24.3；实测仅这两个包升级，
# apk 正常运行。edge 若移除 r6，构建在此显性失败（不会静默用回 r3）。
RUN apk add --no-cache ca-certificates sqlite tzdata tini openssl=3.5.9-r0 zlib=1.3.2-r1 && \
    apk add --no-cache --repository https://dl-cdn.alpinelinux.org/alpine/edge/main \
      musl=1.2.6-r6 musl-utils=1.2.6-r6 && \
    apk list -I | grep -Eq '^musl-1\.2\.6-r6 ' && \
    apk list -I | grep -Eq '^musl-utils-1\.2\.6-r6 '
WORKDIR /app

# —— 层序：慢变 + 外网层前移 ——
# CRS/xdb 下载只依赖紧随其后的钉版版本号与校验和，与后端二进制、web/dist
# 无关。若放在 COPY 二进制之后，任何一次代码或前端改动都会令该层缓存失效，
# 每次发版重走 apk add curl + 双源下载 + sha256 校验 + apk del，等于把发版
# 成功率绑到 ghfast.top / github.com / raw.githubusercontent.com 的可用性上。
RUN mkdir -p /app/data /app/logs /app/certs /app/waf/crs /app/waf/audit
# /app/config 不在此创建——下方 `COPY --from=backend /app/config /app/config`
# 会自建目标目录。/app/waf/audit 与 internal/services/crsseed.go 的运行期重建
# 成双份创建属历史兼容（老挂载回滚时目录骨架已在），crsseed 侧幂等补齐。

# Download OWASP CRS rules (dual-source, aligned with the xdb seed below:
# ghfast.top proxy first, fall back to direct GitHub — their reachability
# from the build network complements each other. Proxy does not support git
# protocol, so use the archive tarball instead of git clone). VERSION marker
# lets startup reconciliation tell the bundled version from user-updated ones.
# CRS 版本与校验和收敛为本 RUN 内的一对变量（单一事实源）。
# 此前是 `ARG CRS_VERSION` + 写死校验和——`--build-arg CRS_VERSION=` 覆盖版本后
# 校验必然失败，属「可覆盖但覆盖即坏」的假参数；版本与校验和必须成对修改，
# 相邻书写让升级时漏改其中一行立刻显性失败。ip2region xdb 的钉版同理。
# 两段逐字相同的 apk-curl 三次重试循环合并为单个 RUN——
# 一次装 curl → CRS 下载/校验/解包 → waf.dist 快照 → xdb 下载/校验 → 一次
# apk del curl；少两层、少一次装删、重试逻辑单份。
# apk add 包 3 次重试：Alpine CDN 偶发 zstd 解压 I/O error（下载块损坏类
# 瞬态错误），重试重新拉包即可消化；CRS/xdb 双源下载同样包 3 次重试——
# 受限网络下双源同时瞬时失败不应直接终止构建（与同 RUN 内 apk 及构建期
# go mod download/xcaddy 的重试口径对齐，失败仍显性报错、行为不弱化）。
# 校验和（sha256sum -c）在重试环**内**——镜像源返回 200 但内容是
# 损坏包/HTML 错误页时同样重试，否则「瞬态污染」这一被重试覆盖的形态会在
# 环外立即终止构建；3 次仍失败照常 exit 1，可复现性不减。
RUN crs_version=v4.28.0; \
    crs_sha256=d8acc96f25ad07c8e3a595a23c797324f6d77e59ddf9e26e90dd95ebd2e676ce; \
    xdb_sha256=6307a9696f5711f84bcb8b25f07894de68a64a0ed4a1cc7e990562dd3084f210; \
    n=0; until apk add --no-cache curl; do \
      n=$((n+1)); \
      if [ "$n" -ge 3 ]; then echo ">>> apk add curl 3 次失败" >&2; exit 1; fi; \
      echo ">>> apk add curl 第 ${n}/3 次失败，10s 后重试" >&2; sleep 10; \
    done && \
    mkdir -p /tmp/crs-src && \
    n=0; until (curl -sfL -o /tmp/crs.tar.gz "https://ghfast.top/https://github.com/coreruleset/coreruleset/archive/refs/tags/${crs_version}.tar.gz" || \
                curl -sfL -o /tmp/crs.tar.gz "https://github.com/coreruleset/coreruleset/archive/refs/tags/${crs_version}.tar.gz") && \
               echo "${crs_sha256}  /tmp/crs.tar.gz" | sha256sum -c -; do \
      n=$((n+1)); \
      if [ "$n" -ge 3 ]; then echo ">>> CRS 下载/校验 3 次失败" >&2; exit 1; fi; \
      echo ">>> CRS 下载/校验第 ${n}/3 次失败，10s 后重试" >&2; sleep 10; \
    done && \
    tar xzf /tmp/crs.tar.gz --strip-components=1 -C /tmp/crs-src && \
    cp -r /tmp/crs-src/rules /app/waf/crs/rules && \
    cp /tmp/crs-src/crs-setup.conf.example /app/waf/crs/crs-setup.conf && \
    echo "${crs_version}" > /app/waf/crs/VERSION && \
    rm -rf /tmp/crs-src /tmp/crs.tar.gz && \
    cp -r /app/waf /app/waf.dist && \
    n=0; until (curl -sfL -o /app/waf.dist/ip2region.xdb "https://ghfast.top/https://raw.githubusercontent.com/lionsoul2014/ip2region/v3.17.0/data/ip2region_v4.xdb" || \
                curl -sfL -o /app/waf.dist/ip2region.xdb "https://raw.githubusercontent.com/lionsoul2014/ip2region/v3.17.0/data/ip2region_v4.xdb") && \
               echo "${xdb_sha256}  /app/waf.dist/ip2region.xdb" | sha256sum -c -; do \
      n=$((n+1)); \
      if [ "$n" -ge 3 ]; then echo ">>> ip2region xdb 下载/校验 3 次失败" >&2; exit 1; fi; \
      echo ">>> ip2region xdb 下载/校验第 ${n}/3 次失败，10s 后重试" >&2; sleep 10; \
    done && \
    apk del curl

# 爬虫地址库内置首版：离线新实例由 PrimeCrawlerIPLists 读取并落库/生成 .fast。
# 数据文件移入 geoipnames 包并随包嵌入二进制（同一份字节
# 同时是镜像资产与 services 的离线回退），此处 COPY 必须指向嵌入路径。
COPY geoipnames/crawler-ip-lists.seed.json /app/waf.dist/crawler-ip-lists.seed.json

# 版本号硬编码点：本文件 ARG VERSION、docker-compose.yml 两处 image tag 与
# build.args.VERSION、README 两版 docker build 示例（--build-arg VERSION 与
# 镜像 tag）、web/src/utils/branding.ts 的 appVersion 回退值；发布时另需
# buildx --build-arg 显式传参。以上各处须同步递增（config.go 的 APP_VERSION
# 未注入时显示 unknown，不参与硬编码）。
#
# 双轨口径（有意设计，非分叉）：`VERSION`
# 恒为**正式版本号**（如 v2.3.9，面板/`/api/v1/branding` 展示口径）；镜像
# 正式版 tag 与 VERSION 相同；beta 通道才给 tag 加 `-beta` 后缀。二者刻意不同，
# 发布时的判定口径是「tag 去掉通道后缀 == APP_VERSION」。改此约定需同时改
# README 两版示例、docker-compose.yml、branding/config 回退与发布检查单。
#
# 位置约束：ARG/ENV 必须停在上方 CRS/xdb 下载层之后。VERSION 每次发版必变，
# 提前注入会让 apk 与三条外网下载全部缓存失效（见上方层序说明）——移动前
# 先确认没有更早的层消费它（当前仅 ENV 自身与运行期二进制消费）。
ARG VERSION=v2.4.0
ENV APP_VERSION=${VERSION}

# 以下各层只随各自产物变化：CRS/xdb 层已在上方固化，不受影响。
COPY --from=xcaddy-builder /app/caddy /usr/local/bin/caddy
COPY --from=backend /app/cmd/server/lazy-balancer /usr/local/bin/lazy-balancer
COPY web/dist /app/ui
# Apache-2.0 §4(a)：随分发（镜像）提供许可证副本。
COPY LICENSE /app/LICENSE

COPY --from=backend /app/config /app/config

# 容器以 root 运行（无 USER/降权，与常见 Caddy 镜像同态）；如需非 root，需
# 同时给 80/443 加 CAP_NET_BIND_SERVICE 并预置 bind 挂载属主。

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# 443/udp = HTTP/3（QUIC）——Caddy 默认启用，EXPOSE 需一并声明。
# 探针使用二进制自带子命令（exec 形式，零 shell）：不派生 sh/客户端子进程。
# 旧形态在 PID 1 不回收孤儿的容器里每 30s 泄漏子进程（生产实证：十余小时
# 堆到 2252 个僵尸 ssl_client，打满 cgroup pids 配额，容器内连 cat 都无法 fork）。
# 语义不变：HTTPS 先行（管理 TLS 是常态）→ 失败回落明文；只认第一跳 200、
# 不跟随跳转（避免把登录页 200 误判为健康）。探针端口固定 8000，与容器启动参数
# 无关：entrypoint 会透传 `docker run` 的显式参数，但用 -config 改 port 会让本探针
# 打错端口（Docker DNS/健康状态误判），容器形态请不要改面板端口。
# 两段尝试各 2s，合计小于 --timeout=5s。
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
  CMD ["/usr/local/bin/lazy-balancer", "--healthcheck"]

EXPOSE 80 443 443/udp 8000

# tini 作为 PID 1：回收任何被遗弃的子进程（健康检查/运维 exec/入口脚本），
# 不再依赖部署方记得加 --init。信号由 tini 转发给入口脚本与面板进程。
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
