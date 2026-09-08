module lazy-balancer-2/caddydeps

go 1.26.0

// 该模块不提供任何功能代码，仅通过 MVS 抬升 Caddy 二进制的传递依赖版本，
// 满足镜像扫描的最低版本要求（见 Dockerfile xcaddy build 的 --with 引用）。
// cel-go 显式钉住 v0.28.1：v0.29 变更 interpreter API（NewCall 参数改
// []InterpretableV2）与 Caddy v2.11.4 源码不兼容——2026-09-08 实测复现
// celmatcher.go:506/529 编译错误，需等上游稳定版包含适配提交（b2693fb6）
// 后再升级；显式钉住防传递依赖经 MVS 意外抬过 v0.28.x 直接炸构建。
// 调整版本时同步更新 Dockerfile 内的构建期断言。
require (
	github.com/google/cel-go v0.28.1
	go.opentelemetry.io/otel v1.45.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.45.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.45.0
	go.opentelemetry.io/otel/metric v1.45.0
	go.opentelemetry.io/otel/trace v1.45.0
	golang.org/x/crypto v0.56.0
	golang.org/x/net v0.58.0
	google.golang.org/grpc v1.83.1
)
