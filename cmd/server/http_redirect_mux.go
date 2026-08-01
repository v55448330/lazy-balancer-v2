package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

const maxProtocolSniffers = 128
const maxHTTPRedirectHeaderBytes = 16 << 10

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
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
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
			_ = connection.Close()
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
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			host = strings.TrimSpace(line[len("host:"):])
		}
	}
	if host == "" {
		host = connection.LocalAddr().String()
	}
	response := fmt.Sprintf("HTTP/1.1 301 Moved Permanently\r\nContent-Length: 0\r\nConnection: close\r\nLocation: https://%s%s\r\n\r\n", host, location)
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
