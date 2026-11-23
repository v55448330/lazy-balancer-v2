package retry

// 重试前响应体排水：直接 Close 未读 body 会让 net/http 丢弃连接，连续重试
// 每次新建 TLS 连接。排水必须有界——异常大响应体不得让退避路径整段读取。

import (
	"io"
	"net/http"
	"testing"
	"time"
)

// drainTrackingBody 记录被读字节数与 Close，用于断言「先排水再关闭」。
type drainTrackingBody struct {
	remaining int
	read      int
	closed    bool
}

func (b *drainTrackingBody) Read(p []byte) (int, error) {
	if b.remaining == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > b.remaining {
		n = b.remaining
	}
	b.remaining -= n
	b.read += n
	return n, nil
}

func (b *drainTrackingBody) Close() error {
	b.closed = true
	return nil
}

type drainScriptedTransport struct {
	first  *drainTrackingBody
	calls  int
	status []int
}

func (t *drainScriptedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	status := http.StatusOK
	if t.calls < len(t.status) {
		status = t.status[t.calls]
	}
	t.calls++
	var body io.ReadCloser
	if t.calls == 1 {
		body = t.first
	} else {
		body = io.NopCloser(io.LimitReader(nilReader{}, 0))
	}
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: body, Request: req}, nil
}

type nilReader struct{}

func (nilReader) Read([]byte) (int, error) { return 0, io.EOF }

func TestTransport_drains_retryable_body_before_close(t *testing.T) {
	// Given: 首次 429 带 10 字节 body，第二次 200。
	first := &drainTrackingBody{remaining: 10}
	base := &drainScriptedTransport{first: first, status: []int{http.StatusTooManyRequests}}
	transport := &Transport{Base: base, InitialBackoff: time.Millisecond}

	// When
	resp, err := transport.RoundTrip(newRequestPath(t, "https://dns.example/Record.List", "value=abc"))

	// Then
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()
	if first.read != 10 {
		t.Fatalf("首次响应体读取 %d 字节, want 10（重试前必须排水以复用连接）", first.read)
	}
	if !first.closed {
		t.Fatal("重试前响应体必须关闭")
	}
}

func TestTransport_bounds_retry_drain_for_large_body(t *testing.T) {
	// Given: 首次 429 带 1MiB body。
	first := &drainTrackingBody{remaining: 1 << 20}
	base := &drainScriptedTransport{first: first, status: []int{http.StatusTooManyRequests}}
	transport := &Transport{Base: base, InitialBackoff: time.Millisecond}

	// When
	resp, err := transport.RoundTrip(newRequestPath(t, "https://dns.example/Record.List", "value=abc"))

	// Then
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()
	if first.read != maxRetryDrainBytes {
		t.Fatalf("首次响应体读取 %d 字节, want %d（排水必须有界）", first.read, maxRetryDrainBytes)
	}
}
