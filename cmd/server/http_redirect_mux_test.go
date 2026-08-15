package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type temporaryAcceptError struct{}

func (temporaryAcceptError) Error() string   { return "temporary accept error" }
func (temporaryAcceptError) Timeout() bool   { return true }
func (temporaryAcceptError) Temporary() bool { return true }

type acceptResult struct {
	connection net.Conn
	err        error
}

func TestRedirectHTTP_closesConnectionForOversizedRequestLine(t *testing.T) {
	assertOversizedRedirectRequestIsClosed(t, "GET /"+strings.Repeat("x", maxHTTPRedirectHeaderBytes)+" HTTP/1.1\r\nHost: example.com\r\n\r\n")
}

func TestRedirectHTTP_closesConnectionForOversizedHostHeader(t *testing.T) {
	assertOversizedRedirectRequestIsClosed(t, "GET / HTTP/1.1\r\nHost: "+strings.Repeat("x", maxHTTPRedirectHeaderBytes)+"\r\n\r\n")
}

func TestRedirectHTTP_absoluteFormUsesPathAndQuery(t *testing.T) {
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		redirectHTTP(bufio.NewReader(server), server)
		close(done)
	}()
	if _, err := client.Write([]byte("GET http://example.com/a%2Fb?q=1 HTTP/1.1\r\nHost: public.example\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if location := response.Header.Get("Location"); location != "https://public.example/a%2Fb?q=1" {
		t.Fatalf("Location=%q", location)
	}
	_ = response.Body.Close()
	_ = client.Close()
	<-done
}

func assertOversizedRedirectRequestIsClosed(t *testing.T, request string) {
	t.Helper()
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		redirectHTTP(bufio.NewReader(server), server)
		close(done)
	}()
	if _, err := client.Write([]byte(request)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1)
	if count, err := client.Read(buffer); count != 0 || err == nil {
		t.Fatalf("oversized request received %d response bytes with error %v", count, err)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("redirect handler did not close oversized connection")
	}
}

type fakeListener struct {
	results   chan acceptResult
	accepted  chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
}

func (l *fakeListener) Accept() (net.Conn, error) {
	select {
	case l.accepted <- struct{}{}:
	case <-l.closed:
		return nil, net.ErrClosed
	}
	select {
	case result := <-l.results:
		return result.connection, result.err
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *fakeListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *fakeListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestHTTPRedirectMux_TLSHandshakeCompletes_whenSilentConnectionsAreOpen(t *testing.T) {
	// Given
	certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := certificateServer.TLS.Certificates[0]
	certificateServer.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := newHTTPRedirectMux(listener)
	server := &http.Server{
		Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
		},
	}
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.ServeTLS(mux, "", "")
	}()
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("close server: %v", err)
		}
		if err := <-serveDone; err != nil && err != http.ErrServerClosed {
			t.Errorf("serve TLS: %v", err)
		}
	})

	silentConnections := make([]net.Conn, 8)
	for i := range silentConnections {
		silentConnections[i], err = net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, connection := range silentConnections {
			if err := connection.Close(); err != nil {
				t.Errorf("close silent connection: %v", err)
			}
		}
	})

	// When
	dialer := &net.Dialer{Timeout: time.Second}
	client, err := tls.DialWithDialer(dialer, "tcp", listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})

	// Then
	if err != nil {
		t.Fatalf("TLS handshake was blocked by silent connections: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close TLS client: %v", err)
	}
}

func TestHTTPRedirectMux_Accept_backsOffTemporaryErrorsAndResetsAfterSuccess(t *testing.T) {
	// Given
	listener := &fakeListener{
		results:  make(chan acceptResult, 12),
		accepted: make(chan struct{}, 12),
		closed:   make(chan struct{}),
	}
	serverConnection, clientConnection := net.Pipe()
	t.Cleanup(func() {
		_ = clientConnection.Close()
		_ = listener.Close()
	})
	for range 9 {
		listener.results <- acceptResult{err: temporaryAcceptError{}}
	}
	listener.results <- acceptResult{connection: serverConnection}
	listener.results <- acceptResult{err: temporaryAcceptError{}}
	listener.results <- acceptResult{err: errors.New("permanent accept error")}
	var delays []time.Duration
	mux := newHTTPRedirectMuxWithSleeper(listener, func(delay time.Duration) {
		delays = append(delays, delay)
	})

	// When
	select {
	case <-mux.done:
	case <-time.After(time.Second):
		t.Fatal("mux did not finish scripted accepts")
	}

	// Then
	want := []time.Duration{
		5 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond,
		40 * time.Millisecond, 80 * time.Millisecond, 160 * time.Millisecond,
		320 * time.Millisecond, 640 * time.Millisecond, time.Second,
		5 * time.Millisecond,
	}
	if len(delays) != len(want) {
		t.Fatalf("backoff delays=%v, want %v", delays, want)
	}
	for i := range want {
		if delays[i] != want[i] {
			t.Fatalf("backoff delays=%v, want %v", delays, want)
		}
	}
}
