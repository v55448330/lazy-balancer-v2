package acme

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/acme"
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
	hmacSum := sha256.Sum256([]byte("first-secret"))
	identitySum := sha256.Sum256([]byte(directoryURL + "|" + email + "|same-kid|" + hex.EncodeToString(hmacSum[:])))
	want := filepath.Join(dataDir, "acme_accounts", hex.EncodeToString(identitySum[:])+".key")
	if first != want {
		t.Fatalf("account key path=%q, want full HMAC digest path %q", first, want)
	}
}

func TestClient_RegisterAccount_removes_stale_key_after_EAB_HMAC_rotation(t *testing.T) {
	// Given
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Replay-Nonce", "test-nonce")
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/directory":
			_, _ = writer.Write([]byte(`{"newNonce":"` + server.URL + `/nonce","newAccount":"` + server.URL + `/account","newOrder":"` + server.URL + `/order","revokeCert":"` + server.URL + `/revoke","keyChange":"` + server.URL + `/key-change"}`))
		case "/nonce":
			writer.WriteHeader(http.StatusOK)
		case "/account":
			writer.Header().Set("Location", server.URL+"/account/1")
			writer.WriteHeader(http.StatusCreated)
			_, _ = writer.Write([]byte(`{"status":"valid"}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)
	dataDir := t.TempDir()
	directoryURL := server.URL + "/directory"
	oldKeyPath := acmeAccountKeyPath(dataDir, directoryURL, "admin@example.com", "same-kid", []byte("old-secret"))
	if _, err := newClient(directoryURL, "admin@example.com", dataDir, &acme.ExternalAccountBinding{KID: "same-kid", Key: []byte("old-secret")}); err != nil {
		t.Fatalf("create old EAB client: %v", err)
	}
	client, err := newClient(directoryURL, "admin@example.com", dataDir, &acme.ExternalAccountBinding{KID: "same-kid", Key: []byte("new-secret")})
	if err != nil {
		t.Fatalf("create rotated EAB client: %v", err)
	}

	// When
	err = client.RegisterAccount(t.Context())

	// Then
	if err != nil {
		t.Fatalf("register rotated EAB account: %v", err)
	}
	if _, err := os.Stat(oldKeyPath); !os.IsNotExist(err) {
		t.Fatalf("stale account key stat error=%v, want not exists", err)
	}
	if _, err := os.Stat(acmeAccountKeyPath(dataDir, directoryURL, "admin@example.com", "same-kid", []byte("new-secret"))); err != nil {
		t.Fatalf("current account key missing: %v", err)
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
