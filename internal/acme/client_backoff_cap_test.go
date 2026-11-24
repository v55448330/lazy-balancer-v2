package acme

import (
	"net/http"
	"testing"
	"time"
)

// 退避封顶是硬上限：抖动只能落在封顶之下，最终等待不得超过 10s。
//
// 此前实现先 min(曲线, 10s) 再加 0~1s 抖动——封顶档实际等待 10~11s，
// Retry-After 被钳到 10s 后同样再叠抖动，与「上限沿用 10s（分段预算不变）」
// 的注释不符。封顶只截上限：不得压低曲线基线，也不得以删掉抖动的方式求封顶
// （抖动是多规则并发签发防同步重试的手段）。
func TestNewClientRetryBackoff_jitterNeverExceedsCap(t *testing.T) {
	// Given
	client, err := newClient("https://acme.example/directory", "admin@example.com", t.TempDir(), nil)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	backoff := client.acme.RetryBackoff
	if backoff == nil {
		t.Fatal("RetryBackoff not configured")
	}
	const capDelay = 10 * time.Second
	const samples = 20000
	withRetryAfter := func(retryAfter string) *http.Response {
		header := http.Header{}
		header.Set("Retry-After", retryAfter)
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: header}
	}

	// When/Then：多种随机取值下，基线落在封顶档的三条路径最终等待都不超封顶
	capped := []struct {
		name string
		n    int
		resp *http.Response
	}{
		{"指数曲线封顶档", 5, nil},
		{"Retry-After 远超上限", 1, withRetryAfter("3600")},
		{"Retry-After 恰等于上限", 1, withRetryAfter("10")},
	}
	for _, tc := range capped {
		t.Run(tc.name, func(t *testing.T) {
			for range samples {
				got := backoff(tc.n, nil, tc.resp)
				if got > capDelay {
					t.Fatalf("backoff(n=%d)=%v, want ≤ %v（抖动不得突破封顶）", tc.n, got, capDelay)
				}
				if got < capDelay {
					t.Fatalf("backoff(n=%d)=%v, want ≥ 封顶档基线 %v（封顶只截上限）", tc.n, got, capDelay)
				}
			}
		})
	}

	// 封顶之下抖动必须仍在：基线 1s 的档位在足够多的采样里既要出现贴近
	// 基线的取值，也要出现贴近基线+1s 的取值（20000 次采样下漏采概率可忽略）。
	lowest, highest := time.Duration(1)<<62, time.Duration(0)
	for range samples {
		got := backoff(1, nil, nil)
		lowest, highest = min(lowest, got), max(highest, got)
	}
	if lowest > 1400*time.Millisecond || highest < 1600*time.Millisecond {
		t.Fatalf("backoff(n=1) 采样区间 [%v, %v], want 覆盖 1s 基线上下的完整抖动（抖动被删除或截断）", lowest, highest)
	}
}
