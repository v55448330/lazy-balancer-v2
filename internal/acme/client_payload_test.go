package acme

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

type failingRequestBody struct{}

func (failingRequestBody) Read([]byte) (int, error) {
	return 0, errors.New("injected body read failure")
}
func (failingRequestBody) Close() error { return nil }

func TestDecodeACMERequestPayload_returnsBodyReadError(t *testing.T) {
	request := httptest.NewRequest("POST", "http://example.test/account", nil)
	request.Body = failingRequestBody{}

	payload, err := decodeACMERequestPayload(request)
	if err == nil || !strings.Contains(err.Error(), "injected body read failure") {
		t.Fatalf("decode payload error=%v, want the body read cause", err)
	}
	if payload != "" {
		t.Fatalf("payload=%q, want empty after body read failure", payload)
	}
}
