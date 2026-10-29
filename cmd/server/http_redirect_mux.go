package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxProtocolSniffers = 128
const maxHTTPRedirectHeaderBytes = 16 << 10
const maxHTTPRedirectBodyDrainBytes = 8 << 10

// prefixConn replays the bytes Peek consumed so the TLS handshake is intact.
type prefixConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// httpRedirectMux accepts sockets independently from protocol detection so a
// silent client consumes one bounded worker instead of blocking all accepts.
type httpRedirectMux struct {
	net.Listener
	tlsConnections chan net.Conn
	slots          chan struct{}
	done           chan struct{}
	sleep          func(time.Duration)
	closeOnce      sync.Once
	errMu          sync.Mutex
	acceptErr      error
}

func newHTTPRedirectMux(listener net.Listener) *httpRedirectMux {
	return newHTTPRedirectMuxWithSleeper(listener, time.Sleep)
}

func newHTTPRedirectMuxWithSleeper(listener net.Listener, sleep func(time.Duration)) *httpRedirectMux {
	mux := &httpRedirectMux{
		Listener:       listener,
		tlsConnections: make(chan net.Conn),
		slots:          make(chan struct{}, maxProtocolSniffers),
		done:           make(chan struct{}),
		sleep:          sleep,
	}
	go mux.dispatch()
	return mux
}

func (m *httpRedirectMux) Accept() (net.Conn, error) {
	select {
	case connection := <-m.tlsConnections:
		return connection, nil
	case <-m.done:
		m.errMu.Lock()
		defer m.errMu.Unlock()
		return nil, m.acceptErr
	}
}

func (m *httpRedirectMux) Close() error {
	err := m.Listener.Close()
	m.finish(net.ErrClosed)
	return err
}

func (m *httpRedirectMux) dispatch() {
	var retryDelay time.Duration
	for {
		connection, err := m.Listener.Accept()
		if err != nil {
			// net.Error.Temporary() 自 Go 1.18 起弃用，
			// 但本判据行为已由 http_redirect_mux_test.go 钉死（Temporary()=true 且
			// Timeout()=false 类 accept 瞬时失败的退避实证）——保留弃用 API 换取
			// 行为稳定，不经判据改写发散；未来 accept 语义有明确替代再迁移。
			if netErr, ok := err.(net.Error); ok && (netErr.Timeout() || netErr.Temporary()) {
				if retryDelay == 0 {
					retryDelay = 5 * time.Millisecond
				} else {
					retryDelay *= 2
				}
				if maximum := time.Second; retryDelay > maximum {
					retryDelay = maximum
				}
				m.sleep(retryDelay)
				continue
			}
			m.finish(err)
			return
		}
		retryDelay = 0
		select {
		case m.slots <- struct{}{}:
			go m.sniff(connection)
		default:
			// 嗅探槽耗尽不得拒绝所有新连接——原实现直接 Close，
			// 攻击者维持 128 条不发首字节的连接（128/5s≈26 conn/s）即可让
			// 管理面板的全部新连接（含 TLS）在 sniff 前被静默断开。
			// 交 TLS 接受路径兜底：管理面板保持可用；纯 HTTP 客户端在握手
			// 阶段失败（丢 302 重定向，可接受降级）。http.Server 的
			// ReadHeaderTimeout 约束这类连接存活期；slots 仍为嗅探 worker
			// 上限（慢客户端不会无限堆积 goroutine）。
			select {
			case m.tlsConnections <- connection:
			case <-m.done:
				_ = connection.Close()
			}
		}
	}
}

func (m *httpRedirectMux) sniff(connection net.Conn) {
	defer func() { <-m.slots }()
	if err := connection.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		_ = connection.Close()
		return
	}
	reader := bufio.NewReader(connection)
	firstByte, err := reader.Peek(1)
	if err != nil {
		_ = connection.Close()
		return
	}
	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		_ = connection.Close()
		return
	}
	if firstByte[0] != 0x16 {
		redirectHTTP(reader, connection)
		return
	}
	select {
	case m.tlsConnections <- &prefixConn{Conn: connection, r: reader}:
	case <-m.done:
		_ = connection.Close()
	}
}

func (m *httpRedirectMux) finish(err error) {
	m.closeOnce.Do(func() {
		m.errMu.Lock()
		m.acceptErr = err
		m.errMu.Unlock()
		close(m.done)
	})
}

func redirectHTTP(reader *bufio.Reader, connection net.Conn) {
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(3 * time.Second))
	reader = bufio.NewReader(io.LimitReader(reader, maxHTTPRedirectHeaderBytes+1))
	remaining := maxHTTPRedirectHeaderBytes
	head, err := readRedirectHeaderLine(reader, &remaining)
	if err != nil {
		return
	}
	host := ""
	var contentLength int64
	location := "/"
	parts := strings.Fields(head)
	if len(parts) >= 2 {
		location = redirectLocation(parts[1])
	}
	for {
		line, err := readRedirectHeaderLine(reader, &remaining)
		if err != nil {
			return
		}
		if line == "\r\n" || line == "\n" {
			break
		}
		lowerLine := strings.ToLower(line)
		if strings.HasPrefix(lowerLine, "content-length:") {
			contentLength, _ = strconv.ParseInt(strings.TrimSpace(line[len("content-length:"):]), 10, 64)
		}
		if strings.HasPrefix(lowerLine, "host:") {
			host = strings.TrimSpace(line[len("host:"):])
			// Host 行内裸 CR 等控制字符不得反射进 Location：TrimSpace 只去首尾，
			// 中置 CR 曾原样进响应头。中置空格（0x20）同族——TrimSpace 同样剔
			// 不掉，畸形 Host 不得反射。含控制字符/空格（<=0x20 或 0x7f）即视为
			// 无效 Host，回退本地地址。
			if strings.ContainsFunc(host, func(r rune) bool { return r <= 0x20 || r == 0x7f }) {
				host = ""
			}
		}
	}
	if host == "" {
		// 无 Host（HTTP/1.0 或畸形头）时不得把监听地址反射进 Location
		//（net.Listen("tcp", ":port") 下是 https://0.0.0.0:port/，客户端无法
		// 使用）。按 HTTP 语义返回 400 并关闭——也不反射原始畸形 Host。
		_, _ = connection.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n"))
		return
	}
	if contentLength > 0 {
		drain := min(contentLength, int64(maxHTTPRedirectBodyDrainBytes))
		_, _ = io.CopyN(io.Discard, reader, drain)
	}
	response := fmt.Sprintf("HTTP/1.1 302 Found\r\nContent-Length: 0\r\nConnection: close\r\nLocation: https://%s%s\r\nCache-Control: no-store\r\n\r\n", host, location)
	_, _ = connection.Write([]byte(response))
}

func redirectLocation(requestTarget string) string {
	if !strings.HasPrefix(requestTarget, "/") && !strings.Contains(requestTarget, "://") {
		return "/"
	}
	parsed, err := url.ParseRequestURI(requestTarget)
	if err != nil {
		return "/"
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}
	return path
}

func readRedirectHeaderLine(reader *bufio.Reader, remaining *int) (string, error) {
	if *remaining <= 0 {
		return "", fmt.Errorf("HTTP redirect header exceeds %d bytes", maxHTTPRedirectHeaderBytes)
	}
	line, err := reader.ReadString('\n')
	*remaining -= len(line)
	if *remaining < 0 {
		return "", fmt.Errorf("HTTP redirect header exceeds %d bytes", maxHTTPRedirectHeaderBytes)
	}
	return line, err
}
