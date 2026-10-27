package handlers

import (
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 管理面板 HTTPS 双通道（multipart 表单 / JSON 对象）交叉输入门禁：
// 同一请求两处来源冲突、JSON 数值形态、单字段上限——三者都是「通道各写
// 一套语义」时最容易漂移的边界。

// newAdminTLSTestRouter 的 cfg.DataDir 必须指向隔离目录：启用态 selfsigned
// 探针会生成并落盘自签名证书对（admin_tls.crt/admin_tls.key），空 DataDir
// 等于把私钥写进测试进程的工作目录（包源码树）。
func newAdminTLSTestRouter(t *testing.T) (*gin.Engine, *Handlers) {
	t.Helper()
	handler := newAdminTLSHandlers(t)
	router := gin.New()
	router.POST("/admin-tls", handler.UpdateAdminTLS)
	return router, handler
}

// 自签名证书对的落点必须是 cfg.DataDir——测试夹具给空目录时探针会把材料写进
// 源码树（曾被 git add -A 扫进仓库）。
func TestUpdateAdminTLS_selfSignedProbeStaysInDataDir(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	oldExit := exitProcess
	exited := make(chan struct{}, 1)
	exitProcess = func(int) { exited <- struct{}{} }
	t.Cleanup(func() { exitProcess = oldExit })

	router, handler := newAdminTLSTestRouter(t)
	if handler.cfg.DataDir == "" {
		t.Fatal("测试夹具 DataDir 为空：探针会把自签名证书与私钥写进源码目录")
	}
	request := httptest.NewRequest(http.MethodPost, "/admin-tls", strings.NewReader(`{"enabled":true,"mode":"selfsigned"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	for _, name := range []string{"admin_tls.crt", "admin_tls.key"} {
		if _, err := os.Stat(filepath.Join(handler.cfg.DataDir, name)); err != nil {
			t.Fatalf("%s 未生成在 DataDir: %v", name, err)
		}
	}
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("restart was not scheduled")
	}
}

// multipart 通道只消费请求体：URL query 同名参数不得静默覆盖 enabled/mode，
// 否则 `?enabled=false&mode=upload` 会让已提交的 selfsigned 保存落成相反
// 状态或落到误导性材料错误。
func TestUpdateAdminTLS_multipartFieldsIgnoreURLQuery(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	oldExit := exitProcess
	exited := make(chan struct{}, 1)
	exitProcess = func(int) { exited <- struct{}{} }
	t.Cleanup(func() { exitProcess = oldExit })

	var body strings.Builder
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("enabled", "true"); err != nil {
		t.Fatalf("write enabled: %v", err)
	}
	if err := writer.WriteField("mode", "selfsigned"); err != nil {
		t.Fatalf("write mode: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	router, _ := newAdminTLSTestRouter(t)
	request := httptest.NewRequest(http.MethodPost, "/admin-tls?enabled=false&mode=upload", strings.NewReader(body.String()))
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（query 不得覆盖 body）", response.Code, response.Body.String())
	}
	var enabled bool
	var mode string
	if err := db.DB.QueryRow(`SELECT admin_tls_enabled, admin_tls_mode FROM global_config WHERE id=1`).Scan(&enabled, &mode); err != nil {
		t.Fatalf("read admin TLS config: %v", err)
	}
	if !enabled || mode != "selfsigned" {
		t.Fatalf("saved (enabled=%v,mode=%q), want (true,selfsigned)——URL query 不得参与取值", enabled, mode)
	}
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("restart was not scheduled")
	}
}

// JSON 通道 enabled 取值域与 multipart 同白名单：true/1/false/0 四种形态
// （布尔、字符串、数值字面量）都接受，其余数值显式 400 且文案与实现一致。
func TestUpdateAdminTLS_JSONNumericEnabledValues(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		wantCode  int
		wantSaved bool
	}{
		{name: "number-one", body: `{"enabled":1,"mode":"selfsigned"}`, wantCode: http.StatusOK, wantSaved: true},
		{name: "number-zero", body: `{"enabled":0,"mode":"selfsigned"}`, wantCode: http.StatusOK, wantSaved: false},
		{name: "string-one", body: `{"enabled":"1","mode":"selfsigned"}`, wantCode: http.StatusOK, wantSaved: true},
		{name: "boolean-true", body: `{"enabled":true,"mode":"selfsigned"}`, wantCode: http.StatusOK, wantSaved: true},
		{name: "out-of-range-number", body: `{"enabled":2}`, wantCode: http.StatusBadRequest},
		{name: "fractional-number", body: `{"enabled":1.5}`, wantCode: http.StatusBadRequest},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			initializeRuleFeatureTestDB(t)
			// 起始值取目标的反向（mode 恒 selfsigned），确保每个成功形态都是
			// 真实变更（否则落到「配置未变更，无需重启」短路，无法验证落库）。
			seedEnabled := 1
			if tt.wantSaved {
				seedEnabled = 0
			}
			if _, err := db.DB.Exec(`UPDATE global_config SET admin_tls_enabled=?, admin_tls_mode='selfsigned' WHERE id=1`, seedEnabled); err != nil {
				t.Fatalf("seed admin TLS config: %v", err)
			}
			oldExit := exitProcess
			exited := make(chan struct{}, 1)
			exitProcess = func(int) { exited <- struct{}{} }
			t.Cleanup(func() { exitProcess = oldExit })
			router, _ := newAdminTLSTestRouter(t)
			request := httptest.NewRequest(http.MethodPost, "/admin-tls", strings.NewReader(tt.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			if response.Code != tt.wantCode {
				t.Fatalf("status=%d body=%s, want %d", response.Code, response.Body.String(), tt.wantCode)
			}
			if tt.wantCode != http.StatusOK {
				// 错误文案与端点承诺的取值域一致（true/1/false/0）。
				if !strings.Contains(response.Body.String(), "enabled 仅支持 true、1、false 或 0") {
					t.Fatalf("body=%s, want whitelist message", response.Body.String())
				}
				return
			}
			var enabled bool
			var mode string
			if err := db.DB.QueryRow(`SELECT admin_tls_enabled, admin_tls_mode FROM global_config WHERE id=1`).Scan(&enabled, &mode); err != nil {
				t.Fatalf("read admin TLS config: %v", err)
			}
			if enabled != tt.wantSaved || mode != "selfsigned" {
				t.Fatalf("saved (enabled=%v,mode=%q), want (%v,selfsigned)", enabled, mode, tt.wantSaved)
			}
			select {
			case <-exited:
			case <-time.After(2 * time.Second):
				t.Fatal("restart was not scheduled")
			}
		})
	}
}

// JSON 单字段上限与 multipart 单文件同口径（1 MiB）：超限显式 400 且点名
// 字段，不落到「证书与私钥不匹配」这类误导性材料错误，也不落库。
func TestUpdateAdminTLS_JSONPerFieldSizeCap(t *testing.T) {
	oversized := strings.Repeat("A", maxAdminTLSFileBytes+1)
	cases := []struct {
		name      string
		cert      string
		key       string
		wantLabel string
	}{
		{name: "cert-too-large", cert: oversized, key: "key", wantLabel: "证书文件"},
		{name: "key-too-large", cert: "cert", key: oversized, wantLabel: "私钥文件"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			initializeRuleFeatureTestDB(t)
			oldExit := exitProcess
			exitProcess = func(int) { t.Error("rejected update must not schedule restart") }
			t.Cleanup(func() { exitProcess = oldExit })

			body, err := json.Marshal(map[string]string{"enabled": "true", "mode": "upload", "cert_file": tt.cert, "key_file": tt.key})
			if err != nil {
				t.Fatalf("marshal body: %v", err)
			}
			router, _ := newAdminTLSTestRouter(t)
			request := httptest.NewRequest(http.MethodPost, "/admin-tls", strings.NewReader(string(body)))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
			}
			want := tt.wantLabel + " 超过 1 MiB 上限"
			if !strings.Contains(response.Body.String(), want) {
				t.Fatalf("body=%s, want %q", response.Body.String(), want)
			}
			var mode string
			var cert string
			if err := db.DB.QueryRow(`SELECT COALESCE(admin_tls_mode,''), COALESCE(admin_tls_cert,'') FROM global_config WHERE id=1`).Scan(&mode, &cert); err != nil {
				t.Fatalf("read admin TLS config: %v", err)
			}
			if mode == "upload" || cert != "" {
				t.Fatalf("超限材料不得落库: mode=%q certLen=%d", mode, len(cert))
			}
		})
	}
}

// 同一请求的两处来源（multipart body 与 URL query）冲突时，body 胜出——
// 用另一方向（query mode=selfsigned / body mode=upload）复核不是单向巧合。
func TestUpdateAdminTLS_multipartQueryConflictBodyWinsBothDirections(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	certPEM, keyPEM, err := generateTestCert("query-conflict.example.com", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate cert pair: %v", err)
	}
	oldExit := exitProcess
	exited := make(chan struct{}, 1)
	exitProcess = func(int) { exited <- struct{}{} }
	t.Cleanup(func() { exitProcess = oldExit })

	var body strings.Builder
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("enabled", "true"); err != nil {
		t.Fatalf("write enabled: %v", err)
	}
	if err := writer.WriteField("mode", "upload"); err != nil {
		t.Fatalf("write mode: %v", err)
	}
	for field, value := range map[string]string{"cert_file": certPEM, "key_file": keyPEM} {
		part, err := writer.CreateFormFile(field, field+".pem")
		if err != nil {
			t.Fatalf("create form file %s: %v", field, err)
		}
		if _, err := part.Write([]byte(value)); err != nil {
			t.Fatalf("write form file %s: %v", field, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	router, _ := newAdminTLSTestRouter(t)
	query := url.Values{"enabled": {"false"}, "mode": {"selfsigned"}}.Encode()
	request := httptest.NewRequest(http.MethodPost, "/admin-tls?"+query, strings.NewReader(body.String()))
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var enabled bool
	var mode, cert string
	if err := db.DB.QueryRow(`SELECT admin_tls_enabled, admin_tls_mode, admin_tls_cert FROM global_config WHERE id=1`).Scan(&enabled, &mode, &cert); err != nil {
		t.Fatalf("read admin TLS config: %v", err)
	}
	if !enabled || mode != "upload" || cert != certPEM {
		t.Fatalf("saved (enabled=%v,mode=%q,certLen=%d), want (true,upload,%d)——query 的 selfsigned 不得覆盖 body", enabled, mode, len(cert), len(certPEM))
	}
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("restart was not scheduled")
	}
}
