package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

// 名称按现断言更名——轮换前代密钥是不同账户身份，必须保留
// （删除前代密钥会让被删方以再生密钥撞既有账户，签发持续失败）。
func TestClient_RegisterAccount_keeps_rotated_predecessor_key(t *testing.T) {
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
	// 轮换前代密钥须闲置超 1h 才会被清理：把旧密钥 mtime
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
	// 契约更新：同 (directory,email,KID) 不同 HMAC 的密钥是不同账户身份，
	// 不再被互删——旧断言（删除轮换前代密钥）正是定性的有害行为：被删方
	// 下次以再生密钥撞既有账户，签发持续失败直至人工恢复。轮换遗留密钥保留仅是
	// 字节级残留，无功能影响。
	if _, err := os.Stat(oldKeyPath); err != nil {
		t.Fatalf("rotated-HMAC account key must be preserved (different account identity), stat err=%v", err)
	}
	if _, err := os.Stat(acmeAccountKeyPath(dataDir, directoryURL, "admin@example.com", "same-kid", []byte("new-secret"))); err != nil {
		t.Fatalf("current account key missing: %v", err)
	}

}

// EAB HMAC 轮换后旧代的账户密钥必须保留：它是不同账户身份（目录/邮箱/KID 相同
// 但 HMAC 摘要不同），删掉会让旧账户身份无法恢复。这里断言的是「身份不同即
// 保留」，与 mtime 无关——清理删除分支（metadata==want 且 keyPath!=当前路径）
// 在当前路径公式下不可达，是路径公式变更时的迁移钩子（见
// removeStaleAccountKeys 注释），因此不能用 mtime 断言它的行为。
func TestClient_RegisterAccount_keeps_predecessor_identity_key(t *testing.T) {
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

	// When：以轮换后的 HMAC 完成注册（旧代密钥是不同账户身份）
	if err := client.RegisterAccount(t.Context()); err != nil {
		t.Fatalf("register rotated EAB account: %v", err)
	}

	// Then：前代身份密钥及其元数据均保留
	for _, path := range []string{oldKeyPath, oldKeyPath + ".json"} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("predecessor identity key %s was removed: %v", path, err)
		}
	}
}

// 账户密钥文件存在但无法解析时必须 fail-closed——静默再生新密钥会覆盖
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
func decodeACMERequestPayload(request *http.Request) (string, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return "", fmt.Errorf("read request body: %w", err)
	}
	var jws struct {
		Payload string `json:"payload"`
	}
	if jsonErr := json.Unmarshal(body, &jws); jsonErr != nil {
		return string(body), nil
	}
	if raw, decErr := base64.RawURLEncoding.DecodeString(jws.Payload); decErr == nil {
		return string(raw), nil
	}
	return jws.Payload, nil
}

// CA 以 400 "already registered"（而非 200 sentinel）拒绝注册时，新密钥撞
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
			payload, decodeErr := decodeACMERequestPayload(request)
			if decodeErr != nil {
				http.Error(writer, decodeErr.Error(), http.StatusBadRequest)
				return
			}
			if strings.Contains(payload, "onlyReturnExisting") {
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

// 伴随契约：400 already registered 但 onlyReturnExisting 探测确认本密钥持有
// 账户 → 真复用，注册成功。
func TestClient_RegisterAccount_reuses_when_mask_hit_and_key_holds_account(t *testing.T) {
	// Given
	var server *httptest.Server
	probeSeen := 0
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Replay-Nonce", "test-nonce")
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/directory":
			_, _ = writer.Write([]byte(`{"newNonce":"` + server.URL + `/nonce","newAccount":"` + server.URL + `/account","newOrder":"` + server.URL + `/order","revokeCert":"` + server.URL + `/revoke","keyChange":"` + server.URL + `/key-change"}`))
		case "/nonce":
			writer.WriteHeader(http.StatusOK)
		case "/account":
			payload, decodeErr := decodeACMERequestPayload(request)
			if decodeErr != nil {
				http.Error(writer, decodeErr.Error(), http.StatusBadRequest)
				return
			}
			if strings.Contains(payload, "onlyReturnExisting") {
				probeSeen++
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
	// 只断言 err==nil 时，跳过 onlyReturnExisting 探测直接把 400 当成功也会通过
	// ——后续签名请求会 403 accountDoesNotExist。
	if probeSeen != 1 {
		t.Fatalf("onlyReturnExisting probes=%d, want 1（复用前必须验证本密钥持有该账户）", probeSeen)
	}
}

// 伴随契约：200 sentinel（JWK 匹配，x/crypto 已缓存 KID）为真复用路径，
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
			payload, decodeErr := decodeACMERequestPayload(request)
			if decodeErr != nil {
				http.Error(writer, decodeErr.Error(), http.StatusBadRequest)
				return
			}
			if strings.Contains(payload, "onlyReturnExisting") {
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

// 非 429 重试走截断指数退避 1,2,4,8s、封顶 10s（对齐 x/crypto
// defaultBackoff 曲线）——固定 2s 会在 CA 5xx 过载时维持约 5 倍请求压力。
// x/crypto v0.55.0 语义：RetryBackoff 返回值即重试延迟本身（不与默认曲线或
// 叠加），≤0 立即放弃重试。429→0 保持不变：库内立即放弃，交由
// 上层 waiting_ca 记账按 CA 的统一退避。
func TestNewClientRetryBackoff_curve(t *testing.T) {
	// Given
	client, err := newClient("https://acme.example/directory", "admin@example.com", t.TempDir(), nil)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	backoff := client.acme.RetryBackoff
	if backoff == nil {
		t.Fatal("RetryBackoff not configured")
	}

	// When/Then：n 从 1 起跳（x/crypto 文档：首次失败 n=1）— 基线
	// 1,2,4,8,10,10,10 秒 + 0~1s 抖动（多规则并发签发不得在同一 CA
	// 5xx 窗口以相同延迟同步重试）。原测试从 n=0 起跳
	// 断言 1,2,4,8,10…，而生产首召即 n=1 → 曲线整体右移一档（2,4,8,10…）却
	// 恰好被 n=0 这一永不出现的档位掩蔽。
	assertCurve := func(n int, base time.Duration) {
		t.Helper()
		for range 20 {
			got := backoff(n, nil, nil)
			if got < base || got > base+time.Second {
				t.Fatalf("backoff(n=%d)=%v, want [%v, %v]（基线 + 0~1s 抖动）", n, got, base, base+time.Second)
			}
		}
	}
	bases := []time.Duration{
		1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		10 * time.Second, 10 * time.Second, 10 * time.Second,
	}
	for idx, base := range bases {
		assertCurve(idx+1, base)
	}
	// n<1 仅防御（生产不出现）：不得小于 1s 基线。
	assertCurve(0, 1*time.Second)
	// 抖动必须真实存在（否则多任务仍在同一 ms 同步重试）。
	distinct := map[time.Duration]struct{}{}
	for range 10 {
		distinct[backoff(1, nil, nil)] = struct{}{}
	}
	if len(distinct) < 2 {
		t.Fatal("backoff 无抖动：10 次采样恒等（thundering herd 未消除）")
	}
	if got := backoff(3, nil, &http.Response{StatusCode: http.StatusInternalServerError}); got < 4*time.Second || got > 5*time.Second {
		t.Fatalf("backoff(n=3, 500)=%v, want [4s,5s]（非 429 响应同样走指数曲线）", got)
	}

	// 429：返回 0 立即放弃库内重试（waiting_ca 记账语义，保持不变）
	if got := backoff(3, nil, &http.Response{StatusCode: http.StatusTooManyRequests}); got != 0 {
		t.Fatalf("backoff(n=3, 429)=%v, want 0", got)
	}
}

// 既有账户密钥可用时，元数据（卫生清理输入）写失败不得阻断签发。
func TestLoadOrCreateAccountKey_metadataWriteFailureDoesNotBlockIssuance(t *testing.T) {
	dir := t.TempDir()
	const directoryURL = "https://acme.example/directory"
	const email = "admin@example.com"
	keyPath := acmeAccountKeyPath(dir, directoryURL, email, "", nil)
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		t.Fatalf("create account dir: %v", err)
	}
	// 元数据路径被目录占用 → 元数据写必然失败（不依赖只读挂载/权限漂移）。
	if err := os.MkdirAll(keyPath+".json", 0o755); err != nil {
		t.Fatalf("occupy metadata path: %v", err)
	}

	// 首次：生成密钥（元数据写失败只记 warn）
	created, err := loadOrCreateAccountKey(dir, directoryURL, email, "", nil)
	if err != nil || created == nil {
		t.Fatalf("新密钥生成被元数据写失败连坐: key=%v err=%v", created, err)
	}
	// 既有密钥路径：加载成功，不得被元数据刷新失败阻断
	loaded, err := loadOrCreateAccountKey(dir, directoryURL, email, "", nil)
	if err != nil || loaded == nil {
		t.Fatalf("既有密钥加载被元数据写失败连坐: key=%v err=%v", loaded, err)
	}
	if !loaded.Equal(created) {
		t.Fatal("既有密钥路径返回了不同密钥（应复用已落盘账户密钥）")
	}
}

// finalizedCerts 必须有上限且失败路径可显式清理——此前无界 map，
// finalize 后的失败/取消路径留下的证书字节永不释放。
func TestClient_finalizedCertsCappedFIFO(t *testing.T) {
	client := &Client{}
	for i := 0; i < maxFinalizedCerts+5; i++ {
		client.rememberFinalizedCert(fmt.Sprintf("http://ca.test/cert/%d", i), [][]byte{{byte(i)}})
	}
	client.finalizedMu.Lock()
	n := len(client.finalizedCerts)
	_, oldestKept := client.finalizedCerts["http://ca.test/cert/5"]
	_, evicted := client.finalizedCerts["http://ca.test/cert/0"]
	client.finalizedMu.Unlock()
	if n > maxFinalizedCerts {
		t.Fatalf("finalizedCerts size=%d exceeds cap %d", n, maxFinalizedCerts)
	}
	if evicted || !oldestKept {
		t.Fatalf("FIFO eviction wrong: cert/0 present=%v, cert/5 present=%v", evicted, oldestKept)
	}
}

func TestClient_DiscardFinalizedCert_fallsBackToNetwork(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/directory" {
			w.Header().Set("Content-Type", "application/json")
			base := "http://" + r.Host
			_, _ = w.Write([]byte(`{"newNonce":"` + base + `/nonce","newAccount":"` + base + `/account","newOrder":"` + base + `/order"}`))
			return
		}
		if r.URL.Path == "/nonce" {
			w.Header().Set("Replay-Nonce", "test-nonce")
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path == "/cert" {
			requests++
		}
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write([]byte("-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n"))
	}))
	defer server.Close()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate account key: %v", err)
	}
	client := &Client{
		DirectoryURL:   server.URL + "/directory",
		acme:           &acme.Client{Key: key, HTTPClient: server.Client(), DirectoryURL: server.URL + "/directory"},
		finalizedCerts: map[string][][]byte{server.URL + "/cert": {{1, 2, 3}}},
	}
	client.DiscardFinalizedCert(server.URL + "/cert")
	if _, err := client.FetchCert(context.Background(), server.URL+"/cert"); err != nil {
		t.Fatalf("fetch after discard: %v", err)
	}
	if requests != 1 {
		t.Fatalf("requests=%d, want 1（丢弃缓存后回退网络下载）", requests)
	}
}

// 未知密钥类型必须 fail-loud（历史形态静默返回空串——空 keyPEM 会交给
// 部署层落成无私钥的规则）；RSA/ECDSA 分支保持有效 PEM 输出。
func TestEncodeKeyPEM_unknownTypeFailsLoudly(t *testing.T) {
	// Given/When/Then：未知类型
	if pemText, err := EncodeKeyPEM(nil); err == nil || pemText != "" {
		t.Fatalf("EncodeKeyPEM(nil)=(%q,%v), want 空串+错误", pemText, err)
	}
	// 回归形状：RSA 与 ECDSA 均产出可解码 PEM
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	rsaPEM, err := EncodeKeyPEM(rsaKey)
	if err != nil || !strings.Contains(rsaPEM, "RSA PRIVATE KEY") {
		t.Fatalf("EncodeKeyPEM(rsa)=(%q,%v), want RSA PEM", rsaPEM, err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	ecPEM, err := EncodeKeyPEM(ecKey)
	if err != nil || !strings.Contains(ecPEM, "EC PRIVATE KEY") {
		t.Fatalf("EncodeKeyPEM(ecdsa)=(%q,%v), want EC PEM", ecPEM, err)
	}
}

// 账户密钥落盘必须持久（fsync + 父目录同步）：落盘失败不得当作注册成功——
// 非持久写在掉电/硬杀窗口会留下不存在或截断的密钥（下次注册生成新账户，
// 或 fail-closed 到人工删除），而调用方会以为账户已可复用。
func TestLoadOrCreateAccountKey_failsWhenDurableWriteFails(t *testing.T) {
	original := accountKeyWrite
	accountKeyWrite = func(string, []byte, os.FileMode) error { return errors.New("simulated fsync failure") }
	t.Cleanup(func() { accountKeyWrite = original })

	_, err := loadOrCreateAccountKey(t.TempDir(), "https://acme.example/directory", "admin@example.com", "", nil)

	if err == nil || !strings.Contains(err.Error(), "写入 ACME 账户密钥") {
		t.Fatalf("error=%v, want 落盘持久化失败上抛", err)
	}
}
