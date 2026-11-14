package caddygeoip

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// Go 标准库对「明文请求打到 HTTPS 端口」的既有应答文本（net/http TLS
// 握手失败路径）——非白名单 Host / 解析失败沿用同一文案，避免两套口径。
const plainHTTPOnTLSPortMessage = "Client sent an HTTP request to an HTTPS server."

func init() {
	caddy.RegisterModule(HTTPSRedirectSplitWrapper{})
}

// HTTPSRedirectSplitWrapper 同端口 http→https 跳转监听包装器：挂在 TLS
// 之前（listener_wrappers 首位，caddy.listeners.tls 占位符居后）逐连接嗅探
// 首字节——TLS 握手（0x16）连接原样透传给后续 TLS 包装器；明文连接由本
// 包装器以 301 应答到 https://同域名:同端口（保留原路径与查询串），永不
// 进入代理路由（fail-closed：明文流量不产生任何上游转发）。
//
// 安全约束（渲染侧与配置一一对应）：
//   - Domains 必须非空且为该端口全部跳转域名的归一小写集——301 的
//     Location 只回显命中白名单的 Host，任意 Host（反射型开放重定向）
//     与解析失败一律 Go 标准文案 400；
//   - HTTPSPort 必须 >0（跳转目标端口必须显式）。
//
// 渲染口径（services/caddy.go）：端口上任意 TLS 规则开启「HTTP→HTTPS 跳转」
// 即挂载本包装器，Domains=开启跳转规则域名的并集；未开启跳转的 TLS 端口
// 不挂载（明文姿态与既有行为一致）。
type HTTPSRedirectSplitWrapper struct {
	// HTTPSPort 是跳转目标 https 端口（=规则监听端口，渲染期注入）。
	HTTPSPort int `json:"https_port,omitempty"`

	// Domains 是允许跳转的域名集（归一小写；Host 限定白名单）。
	Domains []string `json:"domains,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (HTTPSRedirectSplitWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.lb_https_redirect",
		New: func() caddy.Module { return new(HTTPSRedirectSplitWrapper) },
	}
}

// Provision validates the wrapper config fail-closed.
func (p *HTTPSRedirectSplitWrapper) Provision(ctx caddy.Context) error {
	if p.HTTPSPort <= 0 {
		return fmt.Errorf("lb_https_redirect: https_port 必须 >0（跳转目标端口必须显式）")
	}
	if len(p.Domains) == 0 {
		return fmt.Errorf("lb_https_redirect: domains 必须非空（Host 白名单=防反射开放重定向）")
	}
	return nil
}

// Validate implements caddy.Validator.
func (p *HTTPSRedirectSplitWrapper) Validate() error { return p.Provision(caddy.Context{}) }

// WrapListener implements caddy.ListenerWrapper.
func (p *HTTPSRedirectSplitWrapper) WrapListener(ln net.Listener) net.Listener {
	allowed := make(map[string]struct{}, len(p.Domains))
	for _, d := range p.Domains {
		allowed[normalizeRedirectHost(d)] = struct{}{}
	}
	return &httpsRedirectListener{Listener: ln, cfg: p, allowed: allowed,
		plainSlots: make(chan struct{}, maxPlainRedirectWorkers)}
}

// acceptSniffDeadline 首字节嗅探读死线（生产 5s；测试经包级变量缩窗到毫秒
// 级防 CI 挂钟抖动）：静默客户端（connect 后不发字节）若无死线会让 Accept
// 单循环永久阻塞——该端口全部后续连接（含合法 TLS 握手）排队饿死（整端口
// DoS）。读到首字节后清死线再分发：TLS 握手节奏交还 caddy，明文路径由
// servePlain 自设 10s 双死线。超时/EOF 连接直接关闭（与既有 rerr 分支同构）。
var acceptSniffDeadline = 5 * time.Second

// maxPlainRedirectWorkers 是明文应答 goroutine 的并发上限（生产 128，与
// cmd/server 协议嗅探 worker 上限 maxProtocolSniffers 同量级；测试经包级
// 变量缩窗）。每连接一个 goroutine 无上限会让慢客户端洪峰无限堆积
// goroutine/内存；槽满时新明文连接直接关闭（fail-closed，不排队、不阻塞
// Accept——TLS 透传路径不受影响）。
var maxPlainRedirectWorkers = 128

// plainRedirectSlots 是明文 worker 信号量（容量=maxPlainRedirectWorkers，
// WrapListener 时按当前上限构造）。plainWorkersInFlight 仅测试观测在役数。
var plainWorkersInFlight atomic.Int64

// plainHeaderMaxBytes 是明文请求头的读取上限（1MiB，与主 server
// MaxHeaderBytes 同量级）。http.ReadRequest 本身无头帽（Go 1.27.1
// readRequest 以 math.MaxInt64 调 readMIMEHeader），必须先以 io.LimitReader
// 封顶再解析——超大头按解析失败回 400，不得把任意大小的头读进内存。
const plainHeaderMaxBytes = 1 << 20

// httpsRedirectListener 分类 Accept：TLS 连接透传，明文连接就地应答。
type httpsRedirectListener struct {
	net.Listener
	cfg     *HTTPSRedirectSplitWrapper
	allowed map[string]struct{}
	// plainSlots 明文 worker 信号量（容量=maxPlainRedirectWorkers）：
	// 非阻塞获取，槽满即关闭新明文连接（fail-closed）。
	plainSlots chan struct{}
}

// Accept 逐连接嗅探首字节：0x16=TLS ClientHello 透传（首字节经
// peekedConn 重放，TLS 握手完整）；其余字节=明文 HTTP，起 goroutine 应答
// （301/400 terminal，连接即闭）后继续 Accept。
func (l *httpsRedirectListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		// 首字节显式消费+重放：直接读 1 字节（消费）并由 peekedConn 重放。
		// 读前设死线（静默客户端防饿死整端口），读到后清死线再分发：TLS
		// 握手节奏交还 caddy（Go http 默认不设/不清握手死线——包装器遗留
		// 死线会成为握手唯一上界）。
		_ = conn.SetReadDeadline(time.Now().Add(acceptSniffDeadline))
		var firstBuf [1]byte
		nread, rerr := conn.Read(firstBuf[:])
		if rerr != nil || nread == 0 {
			_ = conn.Close()
			continue
		}
		_ = conn.SetReadDeadline(time.Time{})
		first := firstBuf[0]
		pc := &peekedConn{Conn: conn, first: first}
		if first == 0x16 {
			return pc, nil
		}
		select {
		case l.plainSlots <- struct{}{}:
			go l.servePlain(pc)
		default:
			// 槽满：不起新 goroutine、不排队，直接关闭（明文流量本就
			// fail-closed，丢跳转不产生上游转发；TLS 透传不受影响）。
			_ = pc.Close()
		}
	}
}

// servePlain 应答明文连接：解析请求 → Host 白名单 → 301 到 https 同端口
// （保留 path+query）；白名单外/解析失败 → Go 标准文案 400。pc 的首字节
// 重放保证请求行完整。
func (l *httpsRedirectListener) servePlain(pc *peekedConn) {
	plainWorkersInFlight.Add(1)
	defer func() {
		plainWorkersInFlight.Add(-1)
		<-l.plainSlots
		_ = pc.Close()
	}()
	_ = pc.SetReadDeadline(time.Now().Add(10 * time.Second))
	_ = pc.SetWriteDeadline(time.Now().Add(10 * time.Second))
	// 头帽先于解析：ReadRequest 无界（math.MaxInt64），LimitReader 把
	// 请求行+头总量封顶在 plainHeaderMaxBytes，超限按解析失败回 400。
	req, err := http.ReadRequest(bufio.NewReader(io.LimitReader(pc, plainHeaderMaxBytes)))
	if err != nil {
		l.respond(pc, 400, plainHTTPOnTLSPortMessage)
		return
	}
	hostOnly := req.Host
	if h, _, splitErr := net.SplitHostPort(req.Host); splitErr == nil {
		hostOnly = h
	}
	if _, ok := l.allowed[normalizeRedirectHost(hostOnly)]; !ok {
		l.respond(pc, 400, plainHTTPOnTLSPortMessage)
		return
	}
	// Location 目标：客户端 Host 原样保留（含其自带端口）；Host 未带端口
	// 且 https 端口非 443 时补端口——避免 666 端口规则漏写端口跳到 443。
	host := req.Host
	if !strings.Contains(host, ":") && l.cfg.HTTPSPort != 443 {
		host = net.JoinHostPort(host, strconv.Itoa(l.cfg.HTTPSPort))
	}
	l.respond(pc, 301, "", "https://"+host+req.RequestURI)
}

func (l *httpsRedirectListener) respond(conn net.Conn, status int, body string, location ...string) {
	switch status {
	case 301:
		fmt.Fprintf(conn, "HTTP/1.1 301 Moved Permanently\r\nLocation: %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", location[0])
	default:
		fmt.Fprintf(conn, "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	}
}

// normalizeRedirectHost 归一小写（域名匹配与白名单同一口径）。
func normalizeRedirectHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

// peekedConn 重放嗅探字节后直连（TLS 握手路径：首字节必须回到流首）。
type peekedConn struct {
	net.Conn
	first byte
	sent  bool
}

func (c *peekedConn) Read(p []byte) (int, error) {
	if !c.sent {
		if len(p) == 0 {
			return 0, nil
		}
		p[0] = c.first
		c.sent = true
		return 1, nil
	}
	return c.Conn.Read(p)
}

// Interface guards.
var (
	_ caddy.Module          = (*HTTPSRedirectSplitWrapper)(nil)
	_ caddy.ListenerWrapper = (*HTTPSRedirectSplitWrapper)(nil)
	_ caddy.Validator       = (*HTTPSRedirectSplitWrapper)(nil)
)
