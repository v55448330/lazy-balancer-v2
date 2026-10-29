module lazy-balancer-v2/caddydeps

go 1.26.0

// 该模块不提供任何功能代码，只声明镜像扫描要求的最低依赖版本（floor）。
// 实际约束机制分两层：
//  1. MVS floor：下方 require 是构建图的版本下限——其他依赖要求更低版本时
//     取高者；当前 Caddy v2.11.7 的传递图为 cel.dev/cel-go 0.32.0、grpc
//     1.83.2（与本 floor 等值）、otel 1.46.0（高于本 floor），x/net 0.60.0、
//     x/crypto 0.57.0、go-jose/v4 4.1.5（低于本 floor）。因此下方 10 条
//     require（6 个模块族：cel-go / go-jose / otel / x-crypto / x-net / grpc；
//     otel 族含 otel 本体 + exporters×2 + metric + trace 五个独立 require）
//     今日为 2 等值 + 5 低于 + 3 抬升——抬升的三条是漏洞修复下限，必须盖过
//     上游传递图（x/net 0.60→0.62、x/crypto 0.57→0.58、go-jose/v4 4.1.5→4.1.6）。
//     维护 floor 时五个 otel 子模块必须同代次一起改，漏改其一即族内版本分裂。
//  2. 构建期断言：Dockerfile 的 `go version -m` 检查（阈值与下方 require 同值）
//     才是实际门禁——不达标直接失败。断言另含 github.com/corazawaf/coraza/v3
//     的区间 [v3.8.1, v3.9)：安全拦截判定依赖 coraza tx.ID 长度=16，该 pin 在
//     各 go.mod（根模块/caddygeoip/wafiplist），不是本模块的 floor。
// cel-go：Caddy v2.11.7 的 celmatcher 依赖 **cel.dev/cel-go v0.32.0**（模块
// 路径自上游切换后为 cel.dev/cel-go；github.com/google/cel-go 是另一个独立
// 模块路径——require 旧路径不参与本依赖图的 MVS，等于空转）。调整下方 require
// 时同步 Dockerfile 断言阈值。
//
// go.sum 的消费面：本模块经 `--with lazy-balancer-v2/caddydeps=./caddydeps`
// 参与 xcaddy 构建时是**本地替换目标**，依赖校验走构建主模块的 go.sum，本文件
// 的 go.sum 不参与构建；本包无导入，逐模块 go vet/go test 也不读它。它只服务
// 本模块自身的显式依赖操作（go mod download / go mod verify），保持与本模块
// require 代次一致即可——新增或升级 require 后执行 `go mod download` 刷新。
require (
	cel.dev/cel-go v0.32.0
	github.com/go-jose/go-jose/v4 v4.1.6
	go.opentelemetry.io/otel v1.45.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.45.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.45.0
	go.opentelemetry.io/otel/metric v1.45.0
	go.opentelemetry.io/otel/trace v1.45.0
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.62.0
	google.golang.org/grpc v1.83.2
)
