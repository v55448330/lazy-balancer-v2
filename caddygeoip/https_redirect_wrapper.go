package caddygeoip

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
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
	return &httpsRedirectListener{Listener: ln, cfg: p, allowed: allowed}
}

// httpsRedirectListener 分类 Accept：TLS 连接透传，明文连接就地应答。
type httpsRedirectListener struct {
	net.Listener
	cfg     *HTTPSRedirectSplitWrapper
	allowed map[string]struct{}
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
		// 首字节显式消费+重放：bufio.ReadByte 会把字节从底层连接吞掉
		// （缓冲空时直读），TLS 握手首字节丢失——直接读 1 字节并由
		// peekedConn/oneBytePrefixReader 重放。
		var firstBuf [1]byte
		nread, rerr := conn.Read(firstBuf[:])
		if rerr != nil || nread == 0 {
			_ = conn.Close()
			continue
		}
		first := firstBuf[0]
		pc := &peekedConn{Conn: conn, first: first}
		if first == 0x16 {
			return pc, nil
		}
		go l.servePlain(pc)
	}
}

// servePlain 应答明文连接：解析请求 → Host 白名单 → 301 到 https 同端口
// （保留 path+query）；白名单外/解析失败 → Go 标准文案 400。pc 的首字节
// 重放保证请求行完整。
func (l *httpsRedirectListener) servePlain(pc *peekedConn) {
	defer func() { _ = pc.Close() }()
	_ = pc.SetReadDeadline(time.Now().Add(10 * time.Second))
	_ = pc.SetWriteDeadline(time.Now().Add(10 * time.Second))
	req, err := http.ReadRequest(bufio.NewReader(pc))
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

// sortedDomains 供渲染侧构造稳定顺序的域名集（同字节渲染幂等）。
func sortedDomains(domains map[string]struct{}) []string {
	out := make([]string, 0, len(domains))
	for d := range domains {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// Interface guards.
var (
	_ caddy.Module          = (*HTTPSRedirectSplitWrapper)(nil)
	_ caddy.ListenerWrapper = (*HTTPSRedirectSplitWrapper)(nil)
	_ caddy.Validator       = (*HTTPSRedirectSplitWrapper)(nil)
)
