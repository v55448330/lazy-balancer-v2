package acme

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// CERT44-3（第 44 轮审计）：RegisterAccount 尾部的失效账户密钥清理是卫生动作，
// 注册三分支已成功——清理失败（如账户目录被外部移除）此前连坐注册结果返回
// 错误，须降级为 warn 日志并返回 nil。
func TestCERT44_3_RegisterAccount_toleratesStaleCleanupFailure(t *testing.T) {
	// Given：可用的 CA directory（注册本身成功）
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
	client, err := newClient(server.URL+"/directory", "admin@example.com", dataDir, nil)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	// 账户目录在注册前被外部移除 → removeStaleAccountKeys 读取目录必失败
	if err := os.RemoveAll(filepath.Dir(client.accountKeyPath)); err != nil {
		t.Fatalf("remove account dir: %v", err)
	}
	var logBuf bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	// When
	err = client.RegisterAccount(t.Context())

	// Then：注册成功，清理失败仅记 warn
	if err != nil {
		t.Fatalf("RegisterAccount()=%v, want nil（清理失败不得连坐注册结果）", err)
	}
	if !strings.Contains(logBuf.String(), "清理失效账户密钥失败") {
		t.Fatalf("log=%q, want 清理失败 warn 留痕", logBuf.String())
	}
}
