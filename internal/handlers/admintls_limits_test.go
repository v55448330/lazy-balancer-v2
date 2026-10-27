package handlers

// 管理面板证书上传/保存的两个边界契约：
//   - 单文件超 1 MiB 显式 400「超过 1 MiB」，不得静默截断后让 tls.X509KeyPair
//     报「证书与私钥不匹配」（把大小问题伪装成材料问题）；
//   - 「值未变更」短路前仍跑形态校验：带外改库/坏导入留下的非法存量值，原样
//     提交不得以 200「未变更」固化且不给修复提示。

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestInspectAdminTLSCert_rejectsOversizedSingleFile(t *testing.T) {
	h := newBackupTestHandlers(t)
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	certPart, err := writer.CreateFormFile("cert_file", "cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := certPart.Write(bytes.Repeat([]byte("A"), 1<<20+1)); err != nil {
		t.Fatal(err)
	}
	keyPart, err := writer.CreateFormFile("key_file", "key.pem")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyPart.Write([]byte("placeholder")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/admin-tls/inspect", h.InspectAdminTLSCert)
	request := httptest.NewRequest(http.MethodPost, "/admin-tls/inspect", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, request)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "超过 1 MiB") {
		t.Fatalf("body=%s, want 点名「超过 1 MiB」（不得以「证书与私钥不匹配」伪装大小问题）", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "不匹配") {
		t.Fatalf("body=%s, 超限被截断后才进入配对校验（误导性文案）", rec.Body.String())
	}
}

func TestUpdateAdminTLS_unchangedSubmissionStillValidatesStoredConfig(t *testing.T) {
	h := newBackupTestHandlers(t)
	// Given：带外写入的非法存量值（启用 upload 但无证书材料）。
	if _, err := db.DB.Exec(`UPDATE global_config SET admin_tls_enabled=1, admin_tls_mode='upload', admin_tls_cert='', admin_tls_key='' WHERE id=1`); err != nil {
		t.Fatalf("seed invalid stored tls config: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/admin-tls", h.UpdateAdminTLS)
	// When：用户原样提交（空 JSON = 四值都不变）。
	request := httptest.NewRequest(http.MethodPost, "/admin-tls", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, request)

	// Then：不得 200「配置未变更」把非法存量固化，须 400 点名存量无效。
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（存量非法不得静默 200）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "当前已保存的管理面板 HTTPS 配置无效") {
		t.Fatalf("body=%s, want 点名存量配置无效并给出修复指引", rec.Body.String())
	}
	// 且库内值未被改写（失败不得落库）。
	var mode string
	if err := db.DB.QueryRow(`SELECT COALESCE(admin_tls_mode,'') FROM global_config WHERE id=1`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "upload" {
		t.Fatalf("admin_tls_mode=%q, want upload（校验失败不得落库）", mode)
	}
}

// padAdminTLSPEMToLimit 把单个 PEM 材料补到单文件/单字段上限（1 MiB）——
// 追加无 BEGIN 标记的填充行：PEM 解码在目标块之后找不到 BEGIN 即停止，
// 填充不参与证书/私钥解析。
func padAdminTLSPEMToLimit(t *testing.T, pemText string) string {
	t.Helper()
	if len(pemText) > maxAdminTLSFileBytes {
		t.Fatalf("PEM 基线 %d 字节已超单文件上限 %d", len(pemText), maxAdminTLSFileBytes)
	}
	return pemText + strings.Repeat("A", maxAdminTLSFileBytes-len(pemText))
}

// 单文件/单字段上限（1 MiB）与整体 body 上限必须同时可满足：两个满额材料
// 一起提交时净内容已等于 2 MiB，整体门若仍是 2 MiB，用户收到的会是「请求体
// 超过 2 MiB」而非单字段归因——两条对外契约自相矛盾。multipart 与 JSON
// 两通道同口径。
func TestUpdateAdminTLS_acceptsMaxSizePairOnBothChannels(t *testing.T) {
	certPEM, keyPEM, err := generateTestCert("max-size.example.com", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate cert pair: %v", err)
	}
	certPEM = padAdminTLSPEMToLimit(t, certPEM)
	keyPEM = padAdminTLSPEMToLimit(t, keyPEM)

	for _, channel := range []string{"json", "multipart"} {
		t.Run(channel, func(t *testing.T) {
			initializeRuleFeatureTestDB(t)
			oldExit := exitProcess
			exited := make(chan struct{}, 1)
			exitProcess = func(int) { exited <- struct{}{} }
			t.Cleanup(func() { exitProcess = oldExit })

			h := newAdminTLSHandlers(t)
			router := gin.New()
			router.PUT("/admin-tls", h.UpdateAdminTLS)
			var request *http.Request
			if channel == "json" {
				body, err := json.Marshal(map[string]any{"enabled": true, "mode": "upload", "cert_file": certPEM, "key_file": keyPEM})
				if err != nil {
					t.Fatalf("marshal body: %v", err)
				}
				request = httptest.NewRequest(http.MethodPut, "/admin-tls", bytes.NewReader(body))
				request.Header.Set("Content-Type", "application/json")
			} else {
				var body strings.Builder
				writer := multipart.NewWriter(&body)
				if err := writer.WriteField("enabled", "true"); err != nil {
					t.Fatal(err)
				}
				if err := writer.WriteField("mode", "upload"); err != nil {
					t.Fatal(err)
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
					t.Fatal(err)
				}
				request = httptest.NewRequest(http.MethodPut, "/admin-tls", strings.NewReader(body.String()))
				request.Header.Set("Content-Type", writer.FormDataContentType())
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s, want 200（两个满额材料必须可同时提交）", response.Code, response.Body.String())
			}
			var cert string
			if err := db.DB.QueryRow(`SELECT admin_tls_cert FROM global_config WHERE id=1`).Scan(&cert); err != nil {
				t.Fatalf("read admin TLS cert: %v", err)
			}
			if len(cert) != len(certPEM) {
				t.Fatalf("stored cert len=%d, want %d", len(cert), len(certPEM))
			}
			select {
			case <-exited:
			case <-time.After(2 * time.Second):
				t.Fatal("restart was not scheduled")
			}
		})
	}
}
