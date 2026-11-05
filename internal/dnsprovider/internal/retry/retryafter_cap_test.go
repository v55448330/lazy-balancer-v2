package retry

// 服务器 Retry-After 的尊重与封顶。
//
// 历史形态：Retry-After 与本地退避共用 MaxBackoff（默认 30s）封顶——服务端
// 要求的更长限流窗口被截短成「到点即重试」，重试撞墙再吃 429，三次尝试在
// 90s 窗口内烧完。新形态：本地退避仍按 MaxBackoff 封顶；服务器显式
// Retry-After 只抬高等待，采纳后按独立封顶 retryAfterCap（120s）——既尊重
// 服务端窗口，又防 DoS 式超长封存（Retry-After: 86400）停摆签发链。

import (
	"net/http"
	"testing"
	"time"
)

// configurableRetryAfterTransport 按 seconds 注入 Retry-After 头。
type configurableRetryAfterTransport struct {
	next    http.RoundTripper
	seconds string
}

func (t *configurableRetryAfterTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	resp, err := t.next.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	resp.Header.Set("Retry-After", t.seconds)
	return resp, nil
}

func narrowRetryAfterCap(t *testing.T, d time.Duration) {
	t.Helper()
	old := retryAfterCap
	retryAfterCap = d
	t.Cleanup(func() { retryAfterCap = old })
}

// 服务器 Retry-After 超过本地 MaxBackoff 时必须被尊重（只被 retryAfterCap
// 截短）：MaxBackoff=5ms、Retry-After=3600、cap=20ms → 两次等待各 20ms，
// 总耗时 ≥ 40ms（证明等待超出 MaxBackoff）且远小于 cap=120s 的未收窄形态
// （证明封顶生效）。
func TestTransport_respects_retry_after_up_to_cap(t *testing.T) {
	narrowRetryAfterCap(t, 20*time.Millisecond)
	base := &countingTransport{statuses: []int{http.StatusTooManyRequests, http.StatusTooManyRequests}}
	transport := &Transport{
		Base:           &configurableRetryAfterTransport{next: base, seconds: "3600"},
		InitialBackoff: time.Millisecond,
		MaxBackoff:     5 * time.Millisecond,
	}

	start := time.Now()
	resp, err := transport.RoundTrip(newRequest(t, "value=abc"))
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()
	if elapsed < 40*time.Millisecond {
		t.Fatalf("elapsed=%v, want ≥40ms（两次 Retry-After 等待，必须超出 MaxBackoff=5ms）", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("elapsed=%v, want ≤2s（Retry-After=3600 必须被 cap=20ms 截短）", elapsed)
	}
	if base.attempts != 3 {
		t.Fatalf("attempts=%d, want 3（429,429 → 默认三次尝试）", base.attempts)
	}
}

// 无 Retry-After 时本地退避仍按 MaxBackoff 封顶（既有语义不受影响）。
func TestTransport_caps_local_backoff_at_max(t *testing.T) {
	base := &countingTransport{statuses: []int{http.StatusTooManyRequests}}
	transport := &Transport{Base: base, InitialBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond}

	start := time.Now()
	resp, err := transport.RoundTrip(newRequest(t, "value=abc"))
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()
	if elapsed > time.Second {
		t.Fatalf("elapsed=%v, want capped well below 1s", elapsed)
	}
	if base.attempts != 2 {
		t.Fatalf("attempts=%d, want 2", base.attempts)
	}
}

// Retry-After 不高于本地退避时不缩短等待（只抬高不压低）。
func TestTransport_retry_after_below_backoff_is_ignored(t *testing.T) {
	narrowRetryAfterCap(t, time.Second)
	base := &countingTransport{statuses: []int{http.StatusTooManyRequests}}
	transport := &Transport{
		Base:           &configurableRetryAfterTransport{next: base, seconds: "0"},
		InitialBackoff: 50 * time.Millisecond,
		MaxBackoff:     time.Second,
	}

	start := time.Now()
	resp, err := transport.RoundTrip(newRequest(t, "value=abc"))
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()
	if elapsed < 50*time.Millisecond {
		t.Fatalf("elapsed=%v, want ≥50ms（本地退避不被 Retry-After=0 压低）", elapsed)
	}
}
