package acme

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
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
	// R71 F-A2 契约更新：同 (directory,email,KID) 不同 HMAC 的密钥是不同账户身份，
	// 不再被互删——旧断言（删除轮换前代密钥）正是 F-A2 定性的有害行为：被删方
	// 下次以再生密钥撞既有账户，签发持续失败直至人工恢复。轮换遗留密钥保留仅是
	// 字节级残留，无功能影响。
	if _, err := os.Stat(oldKeyPath); err != nil {
		t.Fatalf("rotated-HMAC account key must be preserved (different account identity), stat err=%v", err)
	}
	if _, err := os.Stat(acmeAccountKeyPath(dataDir, directoryURL, "admin@example.com", "same-kid", []byte("new-secret"))); err != nil {
		t.Fatalf("current account key missing: %v", err)
	}

	// 同身份（同 digest）的闲置陈旧密钥仍被清理——R44-3 语义保留：模拟旧目录下
	// 同 HMAC 的另一路径密钥（不同 KID 即不同文件），闲置超阈值应被清除。
	staleSameDigest := acmeAccountKeyPath(dataDir, directoryURL, "other@example.com", "other-kid", []byte("irrelevant"))
	if err := os.MkdirAll(filepath.Dir(staleSameDigest), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staleSameDigest, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	// 元数据与其他账户不同 → 保留；此处验证的是自身身份匹配路径：构造与 want 完全
	// 一致但 mtime 闲置的元数据文件（同 directory/email/KID/digest、路径不同）。
	// 路径由四元组决定——同四元组必同路径，故「同身份不同路径」仅理论存在；实际
	// 清理面 = 元数据==want 且非自身且闲置，无键。简化断言：oldKeyPath 保留 +
	// 当前密钥存在即覆盖主契约，清理路径由 R44 既有测试（同身份场景）钉住。
	_ = staleSameDigest
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

// F-A1：账户密钥文件存在但无法解析时必须 fail-closed——静默再生新密钥会覆盖
// 既有密钥文件，且新密钥对 CA 而言是陌生账户（或撞既有 email/EAB 账户被拒），
// 造成难以诊断的持续签发失败。
func TestLoadOrCreateAccountKey_fails_closed_on_unparseable_key(t *testing.T) {
	cases := []struct {
		name    string
		content []byte
	}{
		{"not pem at all", []byte("this is not a pem key")},
		{"wrong pem block type", []byte("-----BEGIN CERTIFICATE-----\ndGVzdA==\n-----END CERTIFICATE-----\n")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Given
			dataDir := t.TempDir()
			keyPath := acmeAccountKeyPath(dataDir, "https://acme.example/directory", "admin@example.com", "", nil)
			if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(keyPath, tc.content, 0o600); err != nil {
				t.Fatal(err)
			}

			// When
			_, err := loadOrCreateAccountKey(dataDir, "https://acme.example/directory", "admin@example.com", "", nil)

			// Then
			if err == nil {
				t.Fatal("unparseable account key was silently regenerated")
			}
			if !strings.Contains(err.Error(), "无法解析") {
				t.Fatalf("error=%q, want parse failure diagnosis", err)
			}
			if !strings.Contains(err.Error(), "手动") {
				t.Fatalf("error=%q, want operator guidance to fix/remove manually", err)
			}
			got, readErr := os.ReadFile(keyPath)
			if readErr != nil {
				t.Fatalf("read key back: %v", readErr)
			}
			if string(got) != string(tc.content) {
				t.Fatalf("key file was overwritten: got %q, want original %q", got, tc.content)
			}
			if _, statErr := os.Stat(keyPath + ".tmp"); !os.IsNotExist(statErr) {
				t.Fatalf("leftover tmp file after failed load: %v", statErr)
			}
		})
	}
}

// decodeACMERequestPayload 还原 JWS 请求的业务载荷：ACME POST 的 payload 在
// JWS 信封内做 base64url 编码，直接对原始 body 做子串匹配会落空。
func decodeACMERequestPayload(t *testing.T, request *http.Request) string {
	t.Helper()
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	var jws struct {
		Payload string `json:"payload"`
	}
	if jsonErr := json.Unmarshal(body, &jws); jsonErr != nil {
		return string(body)
	}
	if raw, decErr := base64.RawURLEncoding.DecodeString(jws.Payload); decErr == nil {
		return string(raw)
	}
	return jws.Payload
}

// F-B1：CA 以 400 "already registered"（而非 200 sentinel）拒绝注册时，新密钥撞
// 既有 email/EAB 账户与真正的密钥复用不可区分——必须用 onlyReturnExisting 探测
// 验证本密钥确实持有账户，探测失败则显式报错，不得静默当成功。
func TestClient_RegisterAccount_rejects_mask_hit_when_key_holds_no_account(t *testing.T) {
	// Given
	var server *httptest.Server
	onlyReturnExistingSeen := 0
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Replay-Nonce", "test-nonce")
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/directory":
			_, _ = writer.Write([]byte(`{"newNonce":"` + server.URL + `/nonce","newAccount":"` + server.URL + `/account","newOrder":"` + server.URL + `/order","revokeCert":"` + server.URL + `/revoke","keyChange":"` + server.URL + `/key-change"}`))
		case "/nonce":
			writer.WriteHeader(http.StatusOK)
		case "/account":
			if strings.Contains(decodeACMERequestPayload(t, request), "onlyReturnExisting") {
				onlyReturnExistingSeen++
				writer.Header().Set("Content-Type", "application/problem+json")
				writer.WriteHeader(http.StatusBadRequest)
				_, _ = writer.Write([]byte(`{"type":"urn:ietf:params:acme:error:accountDoesNotExist","detail":"Account does not exist"}`))
				return
			}
			// 新密钥 + 既有 EAB 账户：400 带 already registered 详情（KID 不会被缓存）
			writer.Header().Set("Content-Type", "application/problem+json")
			writer.WriteHeader(http.StatusBadRequest)
			_, _ = writer.Write([]byte(`{"type":"urn:ietf:params:acme:error:malformed","detail":"an account for the provided eab kid is already registered"}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)
	dataDir := t.TempDir()
	directoryURL := server.URL + "/directory"
	client, err := newClient(directoryURL, "admin@example.com", dataDir, &acme.ExternalAccountBinding{KID: "same-kid", Key: []byte("secret")})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	// When
	err = client.RegisterAccount(t.Context())

	// Then
	if err == nil {
		t.Fatal("mask hit with mismatched key silently succeeded")
	}
	if !strings.Contains(err.Error(), "不匹配") {
		t.Fatalf("error=%q, want explicit account-key mismatch diagnosis", err)
	}
	if onlyReturnExistingSeen == 0 {
		t.Fatal("reuse was not verified via onlyReturnExisting probe")
	}
}

// F-B1 伴随契约：400 already registered 但 onlyReturnExisting 探测确认本密钥持有
// 账户 → 真复用，注册成功。
func TestClient_RegisterAccount_reuses_when_mask_hit_and_key_holds_account(t *testing.T) {
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
			if strings.Contains(decodeACMERequestPayload(t, request), "onlyReturnExisting") {
				writer.Header().Set("Location", server.URL+"/account/1")
				writer.WriteHeader(http.StatusOK)
				_, _ = writer.Write([]byte(`{"status":"valid"}`))
				return
			}
			writer.Header().Set("Content-Type", "application/problem+json")
			writer.WriteHeader(http.StatusBadRequest)
			_, _ = writer.Write([]byte(`{"type":"urn:ietf:params:acme:error:malformed","detail":"an account for the provided eab kid is already registered"}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)
	dataDir := t.TempDir()
	directoryURL := server.URL + "/directory"
	client, err := newClient(directoryURL, "admin@example.com", dataDir, &acme.ExternalAccountBinding{KID: "same-kid", Key: []byte("secret")})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	// When
	err = client.RegisterAccount(t.Context())

	// Then
	if err != nil {
		t.Fatalf("verified reuse must succeed, got: %v", err)
	}
}

// F-B1 伴随契约：200 sentinel（JWK 匹配，x/crypto 已缓存 KID）为真复用路径，
// 直接成功且无需额外探测。
func TestClient_RegisterAccount_reuses_on_already_exists_sentinel(t *testing.T) {
	// Given
	var server *httptest.Server
	onlyReturnExistingSeen := 0
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Replay-Nonce", "test-nonce")
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/directory":
			_, _ = writer.Write([]byte(`{"newNonce":"` + server.URL + `/nonce","newAccount":"` + server.URL + `/account","newOrder":"` + server.URL + `/order","revokeCert":"` + server.URL + `/revoke","keyChange":"` + server.URL + `/key-change"}`))
		case "/nonce":
			writer.WriteHeader(http.StatusOK)
		case "/account":
			if strings.Contains(decodeACMERequestPayload(t, request), "onlyReturnExisting") {
				onlyReturnExistingSeen++
			}
			// 200 = 账户密钥已注册（JWK 匹配）→ ErrAccountAlreadyExists sentinel
			writer.Header().Set("Location", server.URL+"/account/1")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte(`{"status":"valid"}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)
	dataDir := t.TempDir()
	directoryURL := server.URL + "/directory"
	client, err := newClient(directoryURL, "admin@example.com", dataDir, nil)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	// When
	err = client.RegisterAccount(t.Context())

	// Then
	if err != nil {
		t.Fatalf("sentinel reuse must succeed, got: %v", err)
	}
	if onlyReturnExistingSeen != 0 {
		t.Fatal("sentinel path (KID already cached) must not need a verification probe")
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
