package acme

// 签发错误路径的 DNS 清理只写任务日志文件，不改任务行状态。
//
// 根因：defer 清理块在失败返回时也经 Logger.Log("cleanup_dns", …) 推进
// cert_jobs 行——失败行被改写为 cleanup_dns（Downloaded 生命周期）后，services
// 侧的「材料在身部署生命周期」判据会把带旧材料的续签失败误判为部署失败折回
// issued。修复后：错误路径清理走 LogFileOnly（仅任务日志文件），成功路径清理
// 仍走 Log（生命周期推进 cleanup_dns → 部署）。

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	xacme "golang.org/x/crypto/acme"
)

// captureCleanupLogger 同时记录「生命周期推进日志（Log）」与「仅文件日志
// （LogFileOnly）」，供错误/成功路径分流断言。
type captureCleanupLogger struct {
	lifeCycle []string
	fileOnly  []string
}

func (l *captureCleanupLogger) Log(stage, message string) {
	l.lifeCycle = append(l.lifeCycle, stage+"|"+message)
}

func (l *captureCleanupLogger) LogFileOnly(stage, message string) {
	l.fileOnly = append(l.fileOnly, stage+"|"+message)
}

// newIssueFailingIssuer 构造一个在授权读取（GetAuthorization）阶段失败的 Issuer：
// 目录/nonce/订单创建正常、授权读取恒 400——失败点在错误路径 defer 清理块登记
// 之后，保证清理分流可被断言。
func newIssueFailingIssuer(t *testing.T, logger Logger) *Issuer {
	t.Helper()
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Replay-Nonce", "test-nonce")
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/directory":
			_, _ = fmt.Fprintf(response, `{"newNonce":%q,"newAccount":%q,"newOrder":%q}`, serverURL+"/nonce", serverURL+"/account", serverURL+"/new-order")
		case "/nonce":
			// nonce 端点正常供给——用例让授权读取阶段失败。
			response.WriteHeader(http.StatusOK)
		case "/new-order":
			// 订单创建成功（pending）：错误路径 defer 清理块在订单创建之后
			// 才登记——失败点必须在 defer 登记后（授权读取）才能覆盖清理分流。
			response.Header().Set("Location", serverURL+"/order/1")
			response.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(response, `{"status":"pending","authorizations":[%q],"finalize":%q}`, serverURL+"/auth/1", serverURL+"/finalize/1")
		default:
			// 400=不可重试的协议错误（429/5xx 会触发库内重试曲线拖慢用例）——
			// GetAuthorization 立即失败，错误路径 defer 清理块随之执行。
			http.Error(response, "authorization fetch rejected", http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	serverURL = server.URL
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate account key: %v", err)
	}
	client := &Client{
		DirectoryURL: serverURL + "/directory",
		Email:        "admin@example.com",
		acme: &xacme.Client{
			Key:          key,
			DirectoryURL: serverURL + "/directory",
			HTTPClient:   server.Client(),
		},
	}
	return &Issuer{Client: client, Logger: logger, AccountPreRegistered: true}
}

// TestIssue_errorPathCleanupLogFileOnly：签发失败时 defer 清理块只落
// LogFileOnly（任务日志文件），不产生 cleanup_dns 生命周期推进日志。
func TestIssue_errorPathCleanupLogFileOnly(t *testing.T) {
	logger := &captureCleanupLogger{}
	issuer := newIssueFailingIssuer(t, logger)

	_, _, err := issuer.Issue(context.Background(), []string{"cleanup-fail.example.com"})
	if err == nil {
		t.Fatal("Issue 应在订单创建阶段失败")
	}

	for _, entry := range logger.lifeCycle {
		if strings.HasPrefix(entry, "cleanup_dns|") || strings.HasPrefix(entry, "cleanup_warning|") {
			t.Fatalf("错误路径清理不得推进任务行状态（Log %q）——只允许写任务日志文件", entry)
		}
	}
	found := false
	for _, entry := range logger.fileOnly {
		if strings.HasPrefix(entry, "cleanup_dns|") {
			found = true
		}
	}
	if !found {
		t.Fatalf("错误路径清理必须以 LogFileOnly 留痕: %v", logger.fileOnly)
	}
}
