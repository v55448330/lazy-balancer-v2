// Package retry provides an http.RoundTripper that retries transient DNS API
// failures (HTTP 429 and 5xx) with exponential backoff. It is shared by the
// DNSPod, Tencent Cloud and Aliyun providers so a momentary API hiccup does
// not immediately fail an ACME DNS-01 challenge and burn CA order quota.
//
// 创建类请求（DNSPod Record.Create / 腾讯云
// CreateRecord / 阿里云 AddDomainRecord / Cloudflare POST
// /zones/{id}/dns_records）对 5xx 不重放——创建响应丢失时重试
// 会在 DNS 侧产生一条无 ID 幽灵 TXT（清理只按 ownership 记录 ID 删除，幽灵
// 条目永不收敛）；429 恒定重试（限流响应意味着记录未被创建；阿里云的
// Throttling 400 由 aliyun 包的 throttlingTransport 先改写为 429）。
// 非创建类动作维持重试；传输错误/超时本就不重试（RoundTrip 直接返回错误）。
package retry

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"time"

	"lazy-balancer-v2/internal/retryafter"
)

const (
	defaultAttempts       = 3
	defaultInitialBackoff = time.Second
	defaultMaxBackoff     = 30 * time.Second
	// maxRetryDrainBytes 是重试前响应体排水上限：排空才能复用连接，但异常
	// 大响应体（限流页/错误页偶发巨型 body）不得把退避路径变成整段读取。
	maxRetryDrainBytes = 64 << 10
)

// retryAfterCap 是服务器 Retry-After 被采纳的等待封顶：限流窗口是服务端
// 状态，服务器显式要求的等待被本地退避封顶（defaultMaxBackoff 30s）截短，
// 会变成「到点即重试→再吃 429」的撞墙循环。Retry-After 采纳后按本值独立
// 封顶——既尊重服务端窗口，又防 DoS 式超长封存（Retry-After: 86400）把
// 签发链停摆在单次 Present 上。var 供测试收窄（与 dnspod
// domainIDNegativeTTL 同型约定）。
// 60s < DNS SDK 的 90s 单请求包络（dnspod/tencent/cloudflare/aliyun），为
// 重试请求本身留出余量；超过客户端超时的服务端窗口只能按超时失败。
var retryAfterCap = 60 * time.Second

// Retryable reports whether an HTTP status code is a transient failure that
// is worth another attempt (429 and 5xx).
func Retryable(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

// After parses a header value (delay-seconds or HTTP-date) into a
// duration. Unparseable, empty, or past values yield zero.
//
// 解析实现单源在 internal/retryafter.Parse（与 services.parseRetryAfter 共用
// 同一份代码与测试表）；本函数只保留包内调用点与 now=time.Now() 的绑定，
// 不再各自维护副本（此前靠注释互相约束「任一侧变更 MUST 同步」，无机器拦截）。
func After(header string) time.Duration {
	return retryafter.Parse(header, time.Now())
}

// createRecordAction 判定创建类 DNS 请求：DNSPod 走 URL 路径
// （apiBase+"Record.Create"），腾讯云走 X-TC-Action 头，阿里云走
// x-acs-action 头（AddDomainRecord；429/Throttling 改写后的限流响应在
// 本判定之前已按 429 恒重试，不受创建类约束），Cloudflare 走 POST
// /zones/{id}/dns_records（无动作头，按方法+路径后缀判定；同路径的 GET
// 列表不受创建类约束）。创建响应丢失时重试会产生无 ID 幽灵 TXT，故创建类
// 5xx 一律不重放。
func createRecordAction(request *http.Request) bool {
	if strings.EqualFold(request.Header.Get("X-TC-Action"), "CreateRecord") {
		return true
	}
	if strings.EqualFold(request.Header.Get("x-acs-action"), "AddDomainRecord") {
		return true
	}
	if request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/dns_records") {
		return true
	}
	return strings.HasSuffix(request.URL.Path, "/Record.Create")
}

// Transport wraps a base RoundTripper and retries requests whose response is
// a transient failure (HTTP 429/5xx). responses and transport
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

// retryWait 计算下一次等待：本地退避按 max 封顶；Retry-After 先按 cap 封顶，
// 再只抬高不压低本地退避。cap < max 的测试缝/未来配置不得让服务端头把等待
// 压到本地退避以下（Retry-After 只应放大等待）。
func retryWait(backoff, max, after, cap time.Duration) time.Duration {
	wait := backoff
	if wait > max {
		wait = max
	}
	if after > 0 {
		if after > cap {
			after = cap
		}
		if after > wait {
			wait = after
		}
	}
	return wait
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
			// 创建类动作的 5xx 不重放（幽灵 TXT，见包注释）；429 恒定重试。
			return response, nil
		}
		// 本地退避先按 MaxBackoff 封顶；服务器显式 Retry-After 只抬高
		// 等待（不压低本地退避），采纳后按 retryAfterCap 独立封顶——
		// 不再被 MaxBackoff 截短成撞墙重试（见 retryAfterCap 注释）。
		wait := retryWait(backoff, max, After(response.Header.Get("Retry-After")), retryAfterCap)
		// 复用连接前必须先排水：直接 Close 会把仍有未读字节的响应体对应的
		// 连接标记为不可复用（net/http 语义），连续重试每次都新建 TLS 连接。
		// 有界排水（丢弃，最多 maxRetryDrainBytes）——异常大响应体不得让
		// 退避路径变成整段读取。
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxRetryDrainBytes))
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
