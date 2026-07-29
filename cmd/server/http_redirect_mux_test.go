package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

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
