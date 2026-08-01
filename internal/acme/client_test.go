package acme

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestACMEAccountKeyPath_includes_EAB_KID_and_full_hash(t *testing.T) {
	// Given
	directoryURL := "https://acme.example/directory"
	email := "admin@example.com"
	dataDir := t.TempDir()

	// When
	first := acmeAccountKeyPath(dataDir, directoryURL, email, "kid-a", []byte("secret-a"))
	repeated := acmeAccountKeyPath(dataDir, directoryURL, email, "kid-a", []byte("secret-a"))
	second := acmeAccountKeyPath(dataDir, directoryURL, email, "kid-b", []byte("secret-a"))

	// Then
	if first != repeated {
		t.Fatalf("stable account identity produced %q and %q", first, repeated)
	}
	if first == second {
		t.Fatalf("different EAB KIDs share account key path %q", first)
	}
	base := strings.TrimSuffix(filepath.Base(first), ".key")
	if len(base) != 64 {
		t.Fatalf("account hash length=%d, want 64", len(base))
	}
	if filepath.Dir(first) != filepath.Join(dataDir, "acme_accounts") {
		t.Fatalf("account directory=%q, want data directory", filepath.Dir(first))
	}
}

func TestACMEAccountKeyPath_changes_when_EAB_HMAC_changes(t *testing.T) {
	// Given
	dataDir := t.TempDir()
	directoryURL := "https://acme.example/directory"
	email := "admin@example.com"

	// When
	first := acmeAccountKeyPath(dataDir, directoryURL, email, "same-kid", []byte("first-secret"))
	second := acmeAccountKeyPath(dataDir, directoryURL, email, "same-kid", []byte("second-secret"))

	// Then
	if first == second {
		t.Fatalf("different EAB HMAC keys share account key path %q", first)
	}
}

func TestClient_FetchCert_uses_certificate_downloaded_during_finalize(t *testing.T) {
	// Given
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests++
	}))
	defer server.Close()
	want := [][]byte{{1, 2, 3}, {4, 5, 6}}
	client := &Client{finalizedCerts: map[string][][]byte{server.URL + "/cert": want}}

	// When
	got, err := client.FetchCert(context.Background(), server.URL+"/cert")

	// Then
	if err != nil {
		t.Fatalf("fetch finalized certificate: %v", err)
	}
	if requests != 0 || len(got) != 2 || string(got[0]) != string(want[0]) || string(got[1]) != string(want[1]) {
		t.Fatalf("requests=%d certificate=%v, want cached %v", requests, got, want)
	}
}
