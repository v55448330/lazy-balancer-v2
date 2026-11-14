package caddygeoip

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// 同端口明文跳转包装器行为验收（引擎级 validate 由 services 引擎验收族
// 覆盖，运行时 E2E 由容器验证链覆盖）：
//   - TLS 首字节（0x16）连接：透传且首字节重放（握手完整性）
//   - 白名单 Host 明文 GET：301 → https://同域名:目标端口（保留 path+query）
//   - 白名单外 Host / 解析失败：Go 标准文案 400（fail-closed）

func newRedirectSplitListener(t *testing.T, httpsPort int, domains []string) net.Listener {
	t.Helper()
	p := &HTTPSRedirectSplitWrapper{HTTPSPort: httpsPort, Domains: domains}
	ctx, cancel := caddy.NewContextWithCause(caddy.Context{Context: context.Background()})
	t.Cleanup(func() { cancel(nil) })
	if err := p.Provision(ctx); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = base.Close() })
	return p.WrapListener(base)
}

// startAccept 启动包装器 Accept 循环：明文连接由包装器内部 goroutine 就地
// 应答（Accept 不返回），TLS 连接送入通道供断言。通道不 drain——Accept 依赖
// base.Close 退出，而 Cleanup 后进先出要求 base.Close 先于任何读取方收尾；
// 遗留 goroutine 随测试进程退出回收。
func startAccept(t *testing.T, ln net.Listener) <-chan net.Conn {
	t.Helper()
	tlsCh := make(chan net.Conn, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			tlsCh <- conn
		}
	}()
	return tlsCh
}

func dialRaw(t *testing.T, ln net.Listener) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func readResponse(t *testing.T, conn net.Conn) *http.Response {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp
}

func TestHTTPSRedirectSplit_tlsHandshakeBytesPassThroughWithReplay(t *testing.T) {
	ln := newRedirectSplitListener(t, 666, []string{"shop.example.test"})
	tlsCh := startAccept(t, ln)

	client := dialRaw(t, ln)
	hello := []byte{0x16, 0x03, 0x01, 0x00, 0x2f}
	if _, err := client.Write(hello); err != nil {
		t.Fatal(err)
	}

	var conn net.Conn
	select {
	case conn = <-tlsCh:
	case <-time.After(3 * time.Second):
		t.Fatal("TLS 连接未在超时内透传")
	}
	got := make([]byte, len(hello))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("replay read: %v", err)
	}
	for i := range hello {
		if got[i] != hello[i] {
			t.Fatalf("首字节重放失真: got=%v want=%v", got, hello)
		}
	}
}

func TestHTTPSRedirectSplit_whitelistedHostRedirects301(t *testing.T) {
	ln := newRedirectSplitListener(t, 666, []string{"shop.example.test"})
	startAccept(t, ln)

	client := dialRaw(t, ln)
	req, _ := http.NewRequest(http.MethodGet, "http://shop.example.test:666/page?x=1", nil)
	req.Host = "shop.example.test:666"
	if err := req.Write(client); err != nil {
		t.Fatal(err)
	}
	resp := readResponse(t, client)
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("status=%d, want 301", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "https://shop.example.test:666/page?x=1" {
		t.Fatalf("Location=%q, want https://shop.example.test:666/page?x=1（保留 path+query）", loc)
	}
}

func TestHTTPSRedirectSplit_nonWhitelistedHostRejects400(t *testing.T) {
	ln := newRedirectSplitListener(t, 666, []string{"shop.example.test"})
	startAccept(t, ln)

	client := dialRaw(t, ln)
	req, _ := http.NewRequest(http.MethodGet, "http://evil.example.test:666/", nil)
	req.Host = "evil.example.test:666"
	if err := req.Write(client); err != nil {
		t.Fatal(err)
	}
	resp := readResponse(t, client)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400（白名单外 Host 必须拒绝，不得反射开放重定向）", resp.StatusCode)
	}
}

// Host 未带端口（非浏览器客户端形态）：301 目标必须补 https 端口。
func TestHTTPSRedirectSplit_hostWithoutPortGetsPortAppended(t *testing.T) {
	ln := newRedirectSplitListener(t, 666, []string{"shop.example.test"})
	startAccept(t, ln)

	client := dialRaw(t, ln)
	req, _ := http.NewRequest(http.MethodGet, "http://shop.example.test/a", nil)
	req.Host = "shop.example.test"
	if err := req.Write(client); err != nil {
		t.Fatal(err)
	}
	resp := readResponse(t, client)
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("status=%d, want 301", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "https://shop.example.test:666/a" {
		t.Fatalf("Location=%q, want https://shop.example.test:666/a（Host 缺端口时补目标端口）", loc)
	}
}

// 模块名可解析守卫（v2.4.3-beta 首发缺陷回归钉）：listener wrapper 的 JSON
// wrapper 值必须是命名空间后缀（加载器自动加 caddy.listeners. 前缀）——
// 渲染全 ID（caddy.listeners.lb_https_redirect）会双重前缀 unknown module，
// 配置应用整单失败回滚。本钉经进程内 caddy 校验解析完整 listener_wrappers
// 形状，名称漂移即红（变异验证：全 ID 形态复现与线上完全一致的 unknown
// module 双重前缀错误）。
func TestSamePortWrapperModuleNameResolvable(t *testing.T) {
	wrapperJSON := `{
		"apps": {
			"http": {
				"http_port": 16660,
				"servers": {
					"http_16666": {
						"listen": ["127.0.0.1:16666"],
						"listener_wrappers": [
							{"wrapper": "lb_https_redirect", "https_port": 16666, "domains": ["resolve.example.test"]},
							{"wrapper": "tls"}
						],
						"routes": []
					}
				}
			},
			"tls": {
				"certificates": {"load_files": []},
				"automation": {"policies": [{"issuers": [{"module": "internal"}]}]}
			}
		}
	}`
	var cfg caddy.Config
	if err := caddy.StrictUnmarshalJSON([]byte(wrapperJSON), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := caddy.Validate(&cfg); err != nil {
		t.Fatalf("caddy 校验必须能解析 lb_https_redirect 包装器（模块名=命名空间后缀）: %v", err)
	}
}

// 静默客户端防饿死钉（整端口 DoS 回归）：Accept 首字节嗅探读必须有死线——
// connect 后不发字节的连接在死线内被关闭，后续真实 TLS 连接仍正常透传。
// 死线经包级变量缩窗到 150ms（防 CI 挂钟抖动；生产 5s）。
func TestHTTPSRedirectSplit_silentClientDoesNotStallPort(t *testing.T) {
	orig := acceptSniffDeadline
	acceptSniffDeadline = 150 * time.Millisecond
	t.Cleanup(func() { acceptSniffDeadline = orig })

	ln := newRedirectSplitListener(t, 666, []string{"shop.example.test"})
	tlsCh := startAccept(t, ln)

	// 静默客户端：连上不发任何字节。
	silent := dialRaw(t, ln)

	// 死线窗口内静默连接必须被服务端关闭（而非无限期阻塞 Accept）。
	deadline := time.Now().Add(2 * time.Second)
	closed := false
	for time.Now().Before(deadline) {
		if _, err := silent.Read(make([]byte, 1)); err != nil {
			closed = true // 读到错误（对端关闭/超时）= 连接已被服务端终止
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !closed {
		t.Fatal("静默连接未在死线窗口内被关闭（Accept 循环被饿死）")
	}

	// 后续 TLS 连接必须照常透传（端口未被拖死）。
	good := dialRaw(t, ln)
	hello := []byte{0x16, 0x03, 0x01, 0x00, 0x2f}
	if _, err := good.Write(hello); err != nil {
		t.Fatal(err)
	}
	select {
	case conn := <-tlsCh:
		got := make([]byte, len(hello))
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("replay read: %v", err)
		}
		for i := range hello {
			if got[i] != hello[i] {
				t.Fatalf("透传重放失真: got=%v want=%v", got, hello)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("后续 TLS 连接未在超时内透传（端口仍被静默连接拖死）")
	}
}

// 超大头明文请求必须被拒（内存受限钉）：http.ReadRequest 本身无头帽
// （Go 1.27.1 readRequest 以 math.MaxInt64 调 readMIMEHeader），servePlain
// 必须先以 io.LimitReader 封顶再解析——超过上限的请求按解析失败回 Go 标准
// 文案 400，不得把任意大小的头读进内存（主 server MaxHeaderBytes 同量级）。
func TestHTTPSRedirectSplit_oversizedHeaderRejected400(t *testing.T) {
	ln := newRedirectSplitListener(t, 666, []string{"shop.example.test"})
	startAccept(t, ln)

	client := dialRaw(t, ln)
	// 请求行合法 + 单个 2MiB 头值（超过 1MiB 帽）。
	head := "GET / HTTP/1.1\r\nHost: shop.example.test:666\r\nX-Big: "
	if _, err := client.Write([]byte(head)); err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 64<<10)
	for i := range chunk {
		chunk[i] = 'a'
	}
	for written := 0; written < 2<<20; written += len(chunk) {
		if _, err := client.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := client.Write([]byte("\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	resp := readResponse(t, client)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400（超大头必须被拒，不得无界读入内存）", resp.StatusCode)
	}
}

// 帽内大头回归形状：512KiB 头（<1MiB 帽）的白名单请求照常 301——
// 头帽不得误伤正常请求。
func TestHTTPSRedirectSplit_largeHeaderWithinCapStillRedirects(t *testing.T) {
	ln := newRedirectSplitListener(t, 666, []string{"shop.example.test"})
	startAccept(t, ln)

	client := dialRaw(t, ln)
	head := "GET /page HTTP/1.1\r\nHost: shop.example.test:666\r\nX-Big: "
	if _, err := client.Write([]byte(head)); err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 64<<10)
	for i := range chunk {
		chunk[i] = 'a'
	}
	for written := 0; written < 512<<10; written += len(chunk) {
		if _, err := client.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := client.Write([]byte("\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	resp := readResponse(t, client)
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("status=%d, want 301（帽内大头不得误伤）", resp.StatusCode)
	}
}

// 明文应答 goroutine 并发上限钉：每连接一个 goroutine 无上限会让慢客户端
// 洪峰无限堆积 goroutine/内存。信号量满时新明文连接直接关闭（fail-closed，
// 不排队），槽位释放后恢复应答。上限经包级变量缩窗到 2（生产 128，与
// cmd/server 协议嗅探 worker 上限同量级）。
func TestHTTPSRedirectSplit_plainWorkerConcurrencyBounded(t *testing.T) {
	orig := maxPlainRedirectWorkers
	maxPlainRedirectWorkers = 2
	t.Cleanup(func() { maxPlainRedirectWorkers = orig })

	ln := newRedirectSplitListener(t, 666, []string{"shop.example.test"})
	startAccept(t, ln)

	// 两条慢客户端：只发首字节后停住，各占一个 worker 槽（10s 读死线内
	// 不释放）。首字节非 0x16 → 明文路径。
	slow1 := dialRaw(t, ln)
	slow2 := dialRaw(t, ln)
	for _, c := range []net.Conn{slow1, slow2} {
		if _, err := c.Write([]byte("G")); err != nil {
			t.Fatal(err)
		}
	}
	// 等两个 worker 进入 servePlain（槽位占满）。
	waitPlainWorkers(t, 2)

	// 第三条明文连接：槽满必须被立即关闭（不得起第三个 goroutine）。
	overflow := dialRaw(t, ln)
	if _, err := overflow.Write([]byte("G")); err != nil {
		t.Fatal(err)
	}
	_ = overflow.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := overflow.Read(buf); err == nil {
		t.Fatal("槽满时新明文连接必须被关闭（读到数据=未被拒绝）")
	}

	// 释放一个槽（关闭慢客户端 → 其 servePlain 读到 EOF 退出）。
	_ = slow1.Close()
	waitPlainWorkers(t, 1)

	// 槽位释放后新明文连接恢复应答（白名单 Host → 301）。
	client := dialRaw(t, ln)
	req, _ := http.NewRequest(http.MethodGet, "http://shop.example.test:666/ok", nil)
	req.Host = "shop.example.test:666"
	if err := req.Write(client); err != nil {
		t.Fatal(err)
	}
	resp := readResponse(t, client)
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("status=%d, want 301（槽位释放后必须恢复应答）", resp.StatusCode)
	}
	_ = slow2.Close()
}

// waitPlainWorkers 轮询等待在役明文 worker 数达到目标值（信号量占用观测）。
func waitPlainWorkers(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if plainWorkersInFlight.Load() == int64(want) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("在役明文 worker=%d, want %d（2s 内未达目标）", plainWorkersInFlight.Load(), want)
}
