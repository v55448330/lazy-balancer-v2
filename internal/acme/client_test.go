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
	"time"

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
	// 轮换前代密钥须闲置超 1h 才会被清理（R44-3 并发保护）：把旧密钥 mtime
	// 回拨 2h，模拟真正下线已久的轮换遗留密钥。
	idle := time.Now().Add(-2 * time.Hour)
	for _, path := range []string{oldKeyPath, oldKeyPath + ".json"} {
		if err := os.Chtimes(path, idle, idle); err != nil {
			t.Fatalf("backdate stale key %s: %v", path, err)
		}
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

// R44-3：EAB HMAC 轮换后，旧 HMAC 代密钥可能仍被在途签发任务使用（其内存 key
// 不受影响，但磁盘文件被删会导致重试/重启后重新生成、对同一账户反复换 key）。
// 元数据 mtime=最近使用时间，1h 内被使用的前代密钥不得清理。
func TestClient_RegisterAccount_keeps_recently_used_predecessor_key(t *testing.T) {
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

	// When：旧密钥刚被写入（mtime 新鲜，视同并发任务在途使用）
	if err := client.RegisterAccount(t.Context()); err != nil {
		t.Fatalf("register rotated EAB account: %v", err)
	}

	// Then：前代密钥及其元数据均保留
	for _, path := range []string{oldKeyPath, oldKeyPath + ".json"} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("recently used predecessor key %s was removed: %v", path, err)
		}
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
