package services

// 仪表盘延迟 P50/P95/P99 直方图桶内线性插值（histogram_quantile 语义，
// 2026-10-09 用户裁定）：旧实现返回分位数落桶的 le 边界——值永远落在
// 5/10/25/50/2500ms 桶边上「太整齐」；插值后按观察值在桶内的假设均匀
// 分布估计真实分位数（Prometheus histogram_quantile 同算法）。

import (
	"strings"
	"testing"
)

// Given 累计直方图：le=0.1 计 2、le=0.2 计 20（即 (0,0.1] 2 个观察、
// (0.1,0.2] 18 个观察）。
// When 估计 P50。
// Then 桶内线性插值：rank=10 → 落 (0.1,0.2] 桶，fraction=(10-2)/18≈0.444
// → 0.1+0.1×0.444≈0.144s=144ms——旧实现返回桶边 200ms（RED）。
func TestEstimateLatencyPercentiles_interpolatesWithinBucket(t *testing.T) {
	text := `caddy_http_request_duration_seconds_bucket{handler="x",le="0.1"} 2
caddy_http_request_duration_seconds_bucket{handler="x",le="0.2"} 20
caddy_http_request_duration_seconds_bucket{handler="x",le="+Inf"} 20`
	p50, p95, p99, err := estimateLatencyPercentiles(text)
	if err != nil {
		t.Fatal(err)
	}
	// P50: rank=10 → (0.1,0.2] 桶 fraction=8/18≈0.444 → 144ms
	if p50 != 144 {
		t.Fatalf("P50 应为桶内插值 144ms, got %d（桶边 200ms=旧语义）", p50)
	}
	// P95: rank=19 → fraction=17/18≈0.944 → 0.194s=194ms
	if p95 != 194 {
		t.Fatalf("P95 应为桶内插值 194ms, got %d", p95)
	}
	// P99: rank=19.8 → fraction=0.99 → 0.199s=199ms
	if p99 != 199 {
		t.Fatalf("P99 应为桶内插值 199ms, got %d", p99)
	}
}

// 回归形状 1：分位数落 +Inf 桶（长尾超过最大有限桶）——回退最大有限桶边，
// 不可对无穷桶插值。
func TestEstimateLatencyPercentiles_infBucketFallsBackToMaxFinite(t *testing.T) {
	text := `caddy_http_request_duration_seconds_bucket{handler="x",le="0.5"} 10
caddy_http_request_duration_seconds_bucket{handler="x",le="+Inf"} 12`
	p50, p95, p99, err := estimateLatencyPercentiles(text)
	if err != nil {
		t.Fatal(err)
	}
	// total=12；P50 rank=6 落 (0,0.5] 桶插值 fraction=0.6→300ms；
	// P95 rank=11.4、P99 rank=11.88 均超有限桶累计 10 → 回退 500ms
	if p50 != 300 || p95 != 500 || p99 != 500 {
		t.Fatalf("+Inf 尾部分位应 300/500/500, got %d/%d/%d", p50, p95, p99)
	}
}

// 回归形状 2：空输入/零观察 → 全零。
func TestEstimateLatencyPercentiles_emptyStaysZero(t *testing.T) {
	p50, p95, p99, err := estimateLatencyPercentiles("# no metrics")
	if err != nil {
		t.Fatal(err)
	}
	if p50 != 0 || p95 != 0 || p99 != 0 {
		t.Fatalf("空输入应全零, got %d/%d/%d", p50, p95, p99)
	}
}

// 回归形状 3：多序列聚合（handler/host 标签）——同 le 跨序列累计后再插值。
func TestEstimateLatencyPercentiles_aggregatesAcrossSeries(t *testing.T) {
	text := strings.Join([]string{
		`caddy_http_request_duration_seconds_bucket{handler="a",le="0.1"} 2`,
		`caddy_http_request_duration_seconds_bucket{handler="a",le="0.2"} 4`,
		`caddy_http_request_duration_seconds_bucket{handler="a",le="+Inf"} 4`,
		`caddy_http_request_duration_seconds_bucket{handler="b",le="0.1"} 4`,
		`caddy_http_request_duration_seconds_bucket{handler="b",le="0.2"} 16`,
		`caddy_http_request_duration_seconds_bucket{handler="b",le="+Inf"} 16`,
	}, "\n")
	// 聚合：le=0.1 计 6、le=0.2 计 20、+Inf 计 20；total=20。
	// P50 rank=10 → (0.1,0.2] fraction=(10-6)/14≈0.2857 → 0.1286s=129ms
	p50, _, _, err := estimateLatencyPercentiles(text)
	if err != nil {
		t.Fatal(err)
	}
	if p50 != 129 {
		t.Fatalf("跨序列聚合 P50 应为 129ms, got %d", p50)
	}
}
