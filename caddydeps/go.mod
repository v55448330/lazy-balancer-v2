module lazy-balancer-v2/caddydeps

go 1.26.0

// 该模块不提供任何功能代码，仅通过 MVS 抬升 Caddy 二进制的传递依赖版本，
// 满足镜像扫描的最低版本要求（见 Dockerfile xcaddy build 的 --with 引用）。
// 调整版本时同步更新 Dockerfile 内的构建期断言。
require (
	github.com/google/cel-go v0.29.2
	go.opentelemetry.io/otel v1.45.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.45.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.45.0
	go.opentelemetry.io/otel/metric v1.45.0
	go.opentelemetry.io/otel/trace v1.45.0
	golang.org/x/net v0.58.0
	google.golang.org/grpc v1.83.0
)
