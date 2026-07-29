package main

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type temporaryAcceptError struct{}

func (temporaryAcceptError) Error() string   { return "temporary accept error" }
func (temporaryAcceptError) Timeout() bool   { return false }
func (temporaryAcceptError) Temporary() bool { return true }

type acceptResult struct {
	connection net.Conn
	err        error
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

func TestHTTPRedirectMux_Accept_retriesTemporaryListenerError(t *testing.T) {
	// Given
	listener := &fakeListener{
		results:  make(chan acceptResult, 2),
		accepted: make(chan struct{}, 2),
		closed:   make(chan struct{}),
	}
	serverConnection, clientConnection := net.Pipe()
	t.Cleanup(func() {
		_ = clientConnection.Close()
		_ = listener.Close()
	})
	listener.results <- acceptResult{err: temporaryAcceptError{}}
	listener.results <- acceptResult{connection: serverConnection}
	mux := newHTTPRedirectMux(listener)

	writeDone := make(chan error, 1)
	go func() {
		_, err := clientConnection.Write([]byte{0x16})
		writeDone <- err
	}()
	acceptDone := make(chan acceptResult, 1)
	go func() {
		connection, err := mux.Accept()
		acceptDone <- acceptResult{connection: connection, err: err}
	}()

	// When
	var result acceptResult
	select {
	case result = <-acceptDone:
	case <-time.After(time.Second):
		t.Fatal("mux did not retry the temporary listener error")
	}

	// Then
	if result.err != nil {
		t.Fatalf("accept after temporary listener error: %v", result.err)
	}
	if result.connection == nil {
		t.Fatal("accept returned a nil connection")
	}
	if err := result.connection.Close(); err != nil {
		t.Fatalf("close accepted connection: %v", err)
	}
	if err := <-writeDone; err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write TLS prefix: %v", err)
	}
}
