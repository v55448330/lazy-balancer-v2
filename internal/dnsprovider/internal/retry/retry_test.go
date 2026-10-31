package retry

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// countingTransport returns scripted status codes, then a final 200. It
// records each request body so replay correctness can be asserted.
type countingTransport struct {
	statuses []int
	attempts int
	bodies   []string
}

func (t *countingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	if closeErr := request.Body.Close(); closeErr != nil {
		return nil, closeErr
	}
	t.bodies = append(t.bodies, string(body))
	status := http.StatusOK
	if t.attempts < len(t.statuses) {
		status = t.statuses[t.attempts]
	}
	t.attempts++
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"status":{"code":"1"}}`)),
		Request:    request,
	}, nil
}

// retryAfterTransport decorates responses from next with a header.
type retryAfterTransport struct {
	next http.RoundTripper
}

func (t *retryAfterTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	resp, err := t.next.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	resp.Header.Set("Retry-After", strconv.Itoa(3600))
	return resp, nil
}

func newRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	return newRequestPath(t, "https://dns.example/Record.Create", body)
}

func newRequestPath(t *testing.T, url, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	return req
}

func TestTransport_retries_transient_5xx_then_succeeds(t *testing.T) {
	// Given: first two attempts of a non-create action return 500/502, third 200
	// （自此 5xx 重试仅限非创建类动作；创建类见下方专项测试）
	base := &countingTransport{statuses: []int{http.StatusInternalServerError, http.StatusBadGateway}}
	transport := &Transport{Base: base, InitialBackoff: time.Millisecond}

	// When
	resp, err := transport.RoundTrip(newRequestPath(t, "https://dns.example/Record.List", "value=abc"))

	// Then
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	if base.attempts != 3 {
		t.Fatalf("attempts=%d, want 3", base.attempts)
	}
}

// 创建类请求（DNSPod Record.Create / 腾讯云
// CreateRecord）对 5xx 不重放——创建响应丢失时重试会在 DNS 侧产生无 ID
// 幽灵 TXT（清理只按 ownership 记录 ID 删除，幽灵条目永不收敛）。
func TestTransport_createRecord_5xx_is_not_replayed(t *testing.T) {
	for _, shape := range []struct {
		name string
		req  func(t *testing.T) *http.Request
	}{
		{name: "dnspod path", req: func(t *testing.T) *http.Request {
			return newRequest(t, "value=abc")
		}},
		{name: "tencent header", req: func(t *testing.T) *http.Request {
			req := newRequestPath(t, "https://dns.example/", "value=abc")
			req.Header.Set("X-TC-Action", "CreateRecord")
			return req
		}},
		{name: "aliyun header", req: func(t *testing.T) *http.Request {
			req := newRequestPath(t, "https://alidns.example/", "value=abc")
			req.Header.Set("x-acs-action", "AddDomainRecord")
			return req
		}},
	} {
		t.Run(shape.name, func(t *testing.T) {
			// Given：持续 502
			base := &countingTransport{statuses: []int{http.StatusBadGateway, http.StatusBadGateway, http.StatusBadGateway}}
			transport := &Transport{Base: base, InitialBackoff: time.Millisecond}

			// When
			resp, err := transport.RoundTrip(shape.req(t))

			// Then：首个 502 原样返回，单次调用不重试
			if err != nil {
				t.Fatalf("round trip: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadGateway {
				t.Fatalf("status=%d, want 502（创建类 5xx 原样返回）", resp.StatusCode)
			}
			if base.attempts != 1 {
				t.Fatalf("attempts=%d, want 1（创建类 5xx 不重放）", base.attempts)
			}
		})
	}
}

// 创建类请求遇 429 恒定重试——限流响应意味着记录未被创建，
// 重放无幽灵条目风险。
func TestTransport_createRecord_429_is_still_retried(t *testing.T) {
	// Given：先 429 后 200
	base := &countingTransport{statuses: []int{http.StatusTooManyRequests}}
	transport := &Transport{Base: base, InitialBackoff: time.Millisecond}

	// When
	resp, err := transport.RoundTrip(newRequest(t, "value=abc"))

	// Then
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200（429 后重试成功）", resp.StatusCode)
	}
	if base.attempts != 2 {
		t.Fatalf("attempts=%d, want 2（创建类 429 恒定重试）", base.attempts)
	}
}

// 非创建类动作（Record.List/Remove 等）5xx 维持现状重试。
func TestTransport_nonCreateAction_5xx_is_still_retried(t *testing.T) {
	// Given：Record.List 先 503 后 200
	base := &countingTransport{statuses: []int{http.StatusServiceUnavailable}}
	transport := &Transport{Base: base, InitialBackoff: time.Millisecond}

	// When
	resp, err := transport.RoundTrip(newRequestPath(t, "https://dns.example/Record.List", "value=abc"))

	// Then
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	if base.attempts != 2 {
		t.Fatalf("attempts=%d, want 2（非创建类 5xx 仍重试）", base.attempts)
	}
}

func TestTransport_replays_identical_body(t *testing.T) {
	// Given: a retried POST whose body must be replayed byte-for-byte
	base := &countingTransport{statuses: []int{http.StatusTooManyRequests}}
	transport := &Transport{Base: base, InitialBackoff: time.Millisecond}

	// When
	resp, err := transport.RoundTrip(newRequest(t, "value=abc&ttl=600"))

	// Then
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()
	if len(base.bodies) != 2 {
		t.Fatalf("attempts=%d, want 2", len(base.bodies))
	}
	if base.bodies[0] != base.bodies[1] {
		t.Fatalf("replayed body %q differs from original %q", base.bodies[1], base.bodies[0])
	}
}

func TestTransport_returns_last_response_when_attempts_exhausted(t *testing.T) {
	// Given: persistent 429 responses
	base := &countingTransport{statuses: []int{http.StatusTooManyRequests, http.StatusTooManyRequests, http.StatusTooManyRequests}}
	transport := &Transport{Base: base, InitialBackoff: time.Millisecond}

	// When
	resp, err := transport.RoundTrip(newRequest(t, "value=abc"))

	// Then: the final 429 is returned, not turned into an error
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status=%d, want 429", resp.StatusCode)
	}
	if base.attempts != 3 {
		t.Fatalf("attempts=%d, want 3", base.attempts)
	}
}

func TestTransport_does_not_retry_client_errors(t *testing.T) {
	// Given: a plain 404
	base := &countingTransport{statuses: []int{http.StatusNotFound}}
	transport := &Transport{Base: base, InitialBackoff: time.Millisecond}

	// When
	resp, err := transport.RoundTrip(newRequest(t, "value=abc"))

	// Then
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()
	if base.attempts != 1 {
		t.Fatalf("attempts=%d, want 1", base.attempts)
	}
}

func TestTransport_caps_wait_at_max_backoff(t *testing.T) {
	// Given: 429 with a huge Retry-After; MaxBackoff clamps the wait
	base := &countingTransport{statuses: []int{http.StatusTooManyRequests}}
	transport := &Transport{Base: &retryAfterTransport{next: base}, InitialBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond}

	start := time.Now()

	// When
	resp, err := transport.RoundTrip(newRequest(t, "value=abc"))
	elapsed := time.Since(start)

	// Then
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

func TestTransport_stops_on_context_cancellation(t *testing.T) {
	// Given: a 429 response followed by a long backoff, and an already
	// cancelled context
	base := &countingTransport{statuses: []int{http.StatusTooManyRequests, http.StatusTooManyRequests}}
	transport := &Transport{Base: base, InitialBackoff: 10 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://dns.example/Record.Create", strings.NewReader("value=abc"))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	// When
	resp, err := transport.RoundTrip(req)

	// Then
	if err == nil {
		resp.Body.Close()
		t.Fatal("round trip succeeded, want context error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v, want context.Canceled", err)
	}
	if base.attempts != 1 {
		t.Fatalf("attempts=%d, want 1 (no retry after cancellation)", base.attempts)
	}
}

func TestRetryable_classifies_status(t *testing.T) {
	// Given/When/Then
	for _, status := range []int{429, 500, 502, 503, 504} {
		if !Retryable(status) {
			t.Fatalf("status %d should be retryable", status)
		}
	}
	for _, status := range []int{200, 301, 400, 401, 403, 404, 422} {
		if Retryable(status) {
			t.Fatalf("status %d should not be retryable", status)
		}
	}
}

func TestAfter_parses_retry_after_header(t *testing.T) {
	// Given/When/Then: seconds form
	if got := After("2"); got != 2*time.Second {
		t.Fatalf("After(\"2\")=%v, want 2s", got)
	}
	// HTTP-date form in the near future
	future := time.Now().Add(3 * time.Second).UTC().Format(http.TimeFormat)
	if got := After(future); got <= 0 || got > 3*time.Second {
		t.Fatalf("After(date)=%v, want within (0,3s]", got)
	}
	// garbage and past dates yield zero
	if got := After("not-a-date"); got != 0 {
		t.Fatalf("After(garbage)=%v, want 0", got)
	}
	past := time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)
	if got := After(past); got != 0 {
		t.Fatalf("After(past)=%v, want 0", got)
	}
	if got := After(""); got != 0 {
		t.Fatalf("After(empty)=%v, want 0", got)
	}
}

// 退避必须指数增长：全部用例用 1ms 且只数尝试次数时，`backoff *= 2` 改成
// 常量退避（甚至删掉）仍全绿，而真实 API 限流下会把 3 次重试压在毫秒内打完。
// 用下界断言（负载只会拉长耗时，不会缩短）：常量退避总等待 2×初始值，
// 指数退避为 1×+2×，下界取两者之间。
func TestTransport_backoff_doubles_between_attempts(t *testing.T) {
	// Given：初始 20ms、上限 1s，两次 429 后再 200（等待 20ms + 40ms）
	base := &countingTransport{statuses: []int{http.StatusTooManyRequests, http.StatusTooManyRequests}}
	transport := &Transport{Base: base, InitialBackoff: 20 * time.Millisecond, MaxBackoff: time.Second}

	start := time.Now()
	resp, err := transport.RoundTrip(newRequestPath(t, "https://dns.example/Record.List", "value=abc"))
	elapsed := time.Since(start)

	// Then
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()
	if base.attempts != 3 {
		t.Fatalf("attempts=%d, want 3", base.attempts)
	}
	if elapsed < 60*time.Millisecond {
		t.Fatalf("elapsed=%v, want ≥ 20ms+40ms（退避未逐次加倍）", elapsed)
	}
}

// Attempts 字段此前从未被设置：把它改成常量 3 或用错字段都不会红。
func TestTransport_attempts_field_controls_total_attempts(t *testing.T) {
	base := &countingTransport{statuses: []int{
		http.StatusTooManyRequests, http.StatusTooManyRequests, http.StatusTooManyRequests,
		http.StatusTooManyRequests, http.StatusTooManyRequests,
	}}
	transport := &Transport{Base: base, Attempts: 5, InitialBackoff: time.Millisecond}

	resp, err := transport.RoundTrip(newRequestPath(t, "https://dns.example/Record.List", "value=abc"))
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()
	if base.attempts != 5 {
		t.Fatalf("attempts=%d, want 5（Attempts 字段必须生效）", base.attempts)
	}
}

// erroringTransport 永远返回传输错误。
type erroringTransport struct{ calls int }

func (t *erroringTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls++
	return nil, errors.New("connection reset")
}

// 传输错误不得重试（连接已断时重放既无意义也可能重复创建）：错误原样上抛。
func TestTransport_transport_errors_are_not_retried(t *testing.T) {
	base := &erroringTransport{}
	transport := &Transport{Base: base, InitialBackoff: time.Millisecond}

	resp, err := transport.RoundTrip(newRequestPath(t, "https://dns.example/Record.List", "value=abc"))
	if err == nil {
		resp.Body.Close()
		t.Fatal("round trip succeeded, want transport error")
	}
	if base.calls != 1 {
		t.Fatalf("calls=%d, want 1（传输错误不重试）", base.calls)
	}
}

// failingCloser 的 Close 返回错误，模拟连接已半关闭。
type failingCloser struct{}

func (failingCloser) Read([]byte) (int, error) { return 0, io.EOF }
func (failingCloser) Close() error             { return errors.New("broken pipe") }

// failingBodyTransport 首次返回 429 + 无法关闭的 body。
type failingBodyTransport struct{ attempts int }

func (t *failingBodyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	t.attempts++
	return &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Header:     make(http.Header),
		Body:       failingCloser{},
		Request:    request,
	}, nil
}

// body 关闭失败时立即返回该响应（不再重试），避免在半关闭连接上继续等待。
func TestTransport_body_close_failure_stops_retrying(t *testing.T) {
	base := &failingBodyTransport{}
	transport := &Transport{Base: base, InitialBackoff: time.Millisecond}

	resp, err := transport.RoundTrip(newRequestPath(t, "https://dns.example/Record.List", "value=abc"))
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status=%d, want 429 原样返回", resp.StatusCode)
	}
	if base.attempts != 1 {
		t.Fatalf("attempts=%d, want 1（body 关闭失败不得重试）", base.attempts)
	}
}
