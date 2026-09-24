// Package retry provides an http.RoundTripper that retries transient DNS API
// failures (HTTP 429 and 5xx) with exponential backoff. It is shared by the
// DNSPod and Tencent Cloud providers so a momentary API hiccup does not
// immediately fail an ACME DNS-01 challenge and burn CA order quota.
//
// F50-6（第 50 轮审计）：创建类请求（DNSPod Record.Create / 腾讯云
// CreateRecord）对 5xx 不重放——创建响应丢失时重试会在 DNS 侧产生一条
// 无 ID 幽灵 TXT（清理只按 ownership 记录 ID 删除，幽灵条目永不收敛）；
// 429 恒定重试（限流响应意味着记录未被创建）。非创建类动作维持重试；
// 传输错误/超时本就不重试（RoundTrip 直接返回错误）。
package retry

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	defaultAttempts       = 3
	defaultInitialBackoff = time.Second
	defaultMaxBackoff     = 30 * time.Second
)

// Retryable reports whether an HTTP status code is a transient failure that
// is worth another attempt (429 and 5xx).
func Retryable(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

// After parses a Retry-After header value (delay-seconds or HTTP-date) into a
// duration. Unparseable, empty, or past values yield zero.
func After(header string) time.Duration {
	if header == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(header); err == nil {
		if seconds <= 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	if date, err := http.ParseTime(header); err == nil {
		if until := time.Until(date); until > 0 {
			return until
		}
	}
	return 0
}

// createRecordAction 判定创建类 DNS 请求：DNSPod 走 URL 路径
// （apiBase+"Record.Create"），腾讯云走 X-TC-Action 头。
func createRecordAction(request *http.Request) bool {
	if strings.EqualFold(request.Header.Get("X-TC-Action"), "CreateRecord") {
		return true
	}
	return strings.HasSuffix(request.URL.Path, "/Record.Create")
}

// Transport wraps a base RoundTripper and retries requests whose response is
// a transient failure (HTTP 429/5xx). Non-retryable responses and transport
// errors are returned as-is; the last response is returned once attempts are
// exhausted. Request bodies are buffered so retries replay identical bytes
// (the only request field this wrapper mutates, as the original body is
// consumed by the first attempt).
type Transport struct {
	Base           http.RoundTripper
	Attempts       int           // total attempts per request; 0 means 3
	InitialBackoff time.Duration // wait before the 2nd attempt; 0 means 1s
	MaxBackoff     time.Duration // upper bound for any single wait; 0 means 30s
}

func (t *Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	attempts, initial, max := t.defaults()
	var body []byte
	if request.Body != nil {
		readErr := func() error {
			var readErr error
			body, readErr = io.ReadAll(request.Body)
			if readErr != nil {
				return readErr
			}
			return request.Body.Close()
		}()
		if readErr != nil {
			return nil, readErr
		}
	}

	backoff := initial
	for attempt := 1; ; attempt++ {
		if body != nil {
			request.Body = io.NopCloser(bytes.NewReader(body))
		}
		response, err := t.base().RoundTrip(request)
		if err != nil {
			return nil, err
		}
		if attempt >= attempts || !Retryable(response.StatusCode) {
			return response, nil
		}
		if response.StatusCode != http.StatusTooManyRequests && createRecordAction(request) {
			// F50-6：创建类动作的 5xx 不重放（幽灵 TXT，见包注释）；429 恒定重试。
			return response, nil
		}
		wait := backoff
		if after := After(response.Header.Get("Retry-After")); after > wait {
			wait = after
		}
		if wait > max {
			wait = max
		}
		if closeErr := response.Body.Close(); closeErr != nil {
			// Body already consumed or broken connection: stop retrying and
			// surface this response instead of racing a half-closed body.
			return response, nil
		}
		backoff *= 2
		timer := time.NewTimer(wait)
		select {
		case <-request.Context().Done():
			timer.Stop()
			return nil, request.Context().Err()
		case <-timer.C:
		}
	}
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

func (t *Transport) defaults() (attempts int, initial, max time.Duration) {
	attempts, initial, max = t.Attempts, t.InitialBackoff, t.MaxBackoff
	if attempts <= 0 {
		attempts = defaultAttempts
	}
	if initial <= 0 {
		initial = defaultInitialBackoff
	}
	if max <= 0 {
		max = defaultMaxBackoff
	}
	return attempts, initial, max
}
