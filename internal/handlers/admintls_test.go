package handlers

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

// newAdminTLSHandlers admin TLS 测试单源夹具：恒带隔离 DataDir——空 DataDir 时
// 启用态 selfsigned 探针会把 admin_tls.crt/key 写进包源码树（曾被 git add -A
// 扫进仓库）。裸 Handlers 字面量一律经本 helper（源扫描钉测见
// TestAdminTLSTests_allFixturesCarryIsolatedDataDir）。
func newAdminTLSHandlers(t *testing.T) *Handlers {
	t.Helper()
	return &Handlers{cfg: &config.Config{Port: 8000, DataDir: t.TempDir()}}
}

func TestUpdateAdminTLS_disables_upload_mode_without_new_files(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET admin_tls_enabled=1,admin_tls_mode='upload',
		admin_tls_cert='existing cert',admin_tls_key='existing key' WHERE id=1`); err != nil {
		t.Fatalf("seed admin TLS config: %v", err)
	}
	oldExit := exitProcess
	exited := make(chan struct{}, 1)
	exitProcess = func(int) { exited <- struct{}{} }
	t.Cleanup(func() { exitProcess = oldExit })
	var body strings.Builder
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("enabled", "false"); err != nil {
		t.Fatalf("write enabled field: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	handler := newAdminTLSHandlers(t)
	router := gin.New()
	router.POST("/admin-tls", handler.UpdateAdminTLS)
	request := httptest.NewRequest(http.MethodPost, "/admin-tls", strings.NewReader(body.String()))
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var enabled bool
	var cert, key string
	if err := db.DB.QueryRow("SELECT admin_tls_enabled,admin_tls_cert,admin_tls_key FROM global_config WHERE id=1").Scan(&enabled, &cert, &key); err != nil {
		t.Fatalf("read admin TLS config: %v", err)
	}
	if enabled || cert != "existing cert" || key != "existing key" {
		t.Fatalf("saved config=(%v,%q,%q), want disabled with existing files", enabled, cert, key)
	}
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("restart was not scheduled")
	}
}

func TestInspectAdminTLSCertJSONBody_acceptsPEMStringFields(t *testing.T) {
	// Given：JSON 通道（MCP 转发）以 cert_file/key_file PEM 字符串入参，
	// 与 multipart 文件上传走同一校验链
	certPEM, keyPEM, err := generateTestCert("json-inspect.example.com", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate cert pair: %v", err)
	}
	body, err := json.Marshal(map[string]string{"cert_file": certPEM, "key_file": keyPEM})
	if err != nil {
		t.Fatalf("marshal inspect body: %v", err)
	}
	router := gin.New()
	router.POST("/admin-tls/inspect", (newAdminTLSHandlers(t)).InspectAdminTLSCert)
	request := httptest.NewRequest(http.MethodPost, "/admin-tls/inspect", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var payload struct {
		Data struct {
			Domain string `json:"domain"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if payload.Data.Domain != "json-inspect.example.com" {
		t.Fatalf("domain=%q, want json-inspect.example.com", payload.Data.Domain)
	}
}

func TestInspectAdminTLSCertJSONBody_rejectsInvalidPEMLikeMultipart(t *testing.T) {
	// Given：同一对不匹配的证书/私钥分别经 multipart 文件与 JSON 字符串提交
	certPEM, keyPEM, err := generateMismatchedCert()
	if err != nil {
		t.Fatalf("generate mismatched pair: %v", err)
	}
	jsonBody, err := json.Marshal(map[string]string{"cert_file": certPEM, "key_file": keyPEM})
	if err != nil {
		t.Fatalf("marshal json body: %v", err)
	}
	var formBody bytes.Buffer
	writer := multipart.NewWriter(&formBody)
	writeFile := func(field, content string) {
		part, err := writer.CreateFormFile(field, field+".pem")
		if err != nil {
			t.Fatalf("create form file %s: %v", field, err)
		}
		if _, err := part.Write([]byte(content)); err != nil {
			t.Fatalf("write form file %s: %v", field, err)
		}
	}
	writeFile("cert_file", certPEM)
	writeFile("key_file", keyPEM)
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	router := gin.New()
	router.POST("/admin-tls/inspect", (newAdminTLSHandlers(t)).InspectAdminTLSCert)

	// When：multipart 文件上传
	multipartRequest := httptest.NewRequest(http.MethodPost, "/admin-tls/inspect", bytes.NewReader(formBody.Bytes()))
	multipartRequest.Header.Set("Content-Type", writer.FormDataContentType())
	multipartResponse := httptest.NewRecorder()
	router.ServeHTTP(multipartResponse, multipartRequest)
	// And：JSON 通道
	jsonRequest := httptest.NewRequest(http.MethodPost, "/admin-tls/inspect", bytes.NewReader(jsonBody))
	jsonRequest.Header.Set("Content-Type", "application/json")
	jsonResponse := httptest.NewRecorder()
	router.ServeHTTP(jsonResponse, jsonRequest)

	// Then：两通道同为 400 且错误文案一致（无效 PEM 的同语义契约）
	if multipartResponse.Code != http.StatusBadRequest || jsonResponse.Code != http.StatusBadRequest {
		t.Fatalf("multipart=%d json=%d, want both 400", multipartResponse.Code, jsonResponse.Code)
	}
	if multipartResponse.Body.String() != jsonResponse.Body.String() {
		t.Fatalf("multipart body=%s json body=%s, want identical error contract", multipartResponse.Body.String(), jsonResponse.Body.String())
	}
	if !strings.Contains(jsonResponse.Body.String(), "证书与私钥不匹配") {
		t.Fatalf("json body=%s, want mismatch error", jsonResponse.Body.String())
	}
}

func TestUpdateAdminTLSJSONBody_savesUploadModeCertificate(t *testing.T) {
	// Given：JSON 通道提交 upload 模式证书（enabled/mode/cert_file/key_file
	// 字段名与 multipart 表单一致），走与文件上传相同的校验与落盘链路
	initializeRuleFeatureTestDB(t)
	certPEM, keyPEM, err := generateTestCert("json-update.example.com", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate cert pair: %v", err)
	}
	oldExit := exitProcess
	exited := make(chan struct{}, 1)
	exitProcess = func(int) { exited <- struct{}{} }
	t.Cleanup(func() { exitProcess = oldExit })
	body, err := json.Marshal(map[string]any{"enabled": true, "mode": "upload", "cert_file": certPEM, "key_file": keyPEM})
	if err != nil {
		t.Fatalf("marshal update body: %v", err)
	}
	handler := newAdminTLSHandlers(t)
	router := gin.New()
	router.PUT("/admin-tls", handler.UpdateAdminTLS)
	request := httptest.NewRequest(http.MethodPut, "/admin-tls", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：保存成功、落库内容与提交 PEM 一致、重启已排期
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var enabled bool
	var mode, cert, key string
	if err := db.DB.QueryRow("SELECT admin_tls_enabled,admin_tls_mode,admin_tls_cert,admin_tls_key FROM global_config WHERE id=1").Scan(&enabled, &mode, &cert, &key); err != nil {
		t.Fatalf("read admin TLS config: %v", err)
	}
	if !enabled || mode != "upload" || cert != certPEM || key != keyPEM {
		t.Fatalf("saved config=(%v,%q,cert match=%v,key match=%v), want enabled upload with submitted PEM", enabled, mode, cert == certPEM, key == keyPEM)
	}
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("restart was not scheduled")
	}
}

func TestUpdateAdminTLSJSONBody_rejectsMismatchedPairWithoutSaving(t *testing.T) {
	// Given：upload 模式提交不匹配证书对——校验层拦截，不落库不重启
	initializeRuleFeatureTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET admin_tls_enabled=0,admin_tls_mode='selfsigned',
		admin_tls_cert='',admin_tls_key='' WHERE id=1`); err != nil {
		t.Fatalf("seed admin TLS config: %v", err)
	}
	certPEM, keyPEM, err := generateMismatchedCert()
	if err != nil {
		t.Fatalf("generate mismatched pair: %v", err)
	}
	oldExit := exitProcess
	exitProcess = func(int) { t.Error("restart must not be scheduled for rejected update") }
	t.Cleanup(func() { exitProcess = oldExit })
	body, err := json.Marshal(map[string]any{"enabled": false, "mode": "upload", "cert_file": certPEM, "key_file": keyPEM})
	if err != nil {
		t.Fatalf("marshal update body: %v", err)
	}
	handler := newAdminTLSHandlers(t)
	router := gin.New()
	router.PUT("/admin-tls", handler.UpdateAdminTLS)
	request := httptest.NewRequest(http.MethodPut, "/admin-tls", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "证书与私钥不匹配") {
		t.Fatalf("status=%d body=%s, want 400 mismatch", response.Code, response.Body.String())
	}
	var cert, key string
	if err := db.DB.QueryRow("SELECT admin_tls_cert,admin_tls_key FROM global_config WHERE id=1").Scan(&cert, &key); err != nil {
		t.Fatalf("read admin TLS config: %v", err)
	}
	if cert != "" || key != "" {
		t.Fatalf("saved cert/key non-empty (cert=%v,key=%v), want unchanged", cert != "", key != "")
	}
}

// 整体 body 上限（4 MiB）超限须 413（原恒 400，与规则域
// 413 口径不一致）。JSON 通道两入口（保存/预检）同门。
func TestAdminTLSOversizedBodyReturns413(t *testing.T) {
	// Given：超过整体上限的 JSON 体（cert_file 承载超长 PEM 串）
	body := `{"mode":"selfsigned","cert_file":"` + strings.Repeat("a", maxAdminTLSBodyBytes+64) + `"}`
	newRouter := func(handler gin.HandlerFunc, method, path string) *gin.Engine {
		router := gin.New()
		router.Handle(method, path, handler)
		return router
	}
	send := func(router *gin.Engine, method, path string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}

	// When：保存与预检两入口各发一次超限请求
	updateResponse := send(newRouter((newAdminTLSHandlers(t)).UpdateAdminTLS, http.MethodPut, "/admin-tls"), http.MethodPut, "/admin-tls")
	inspectResponse := send(newRouter((newAdminTLSHandlers(t)).InspectAdminTLSCert, http.MethodPost, "/admin-tls/inspect"), http.MethodPost, "/admin-tls/inspect")

	// Then：均为 413（非 400）
	if updateResponse.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("PUT /admin-tls oversized status=%d body=%s, want 413", updateResponse.Code, updateResponse.Body.String())
	}
	if inspectResponse.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("POST /admin-tls/inspect oversized status=%d body=%s, want 413", inspectResponse.Code, inspectResponse.Body.String())
	}
}

// 审计 detail 须显式记录本次是否替换了证书材料——
// 仅启用/禁用 + 来源无法区分「只开关」与「换证书」。
func TestUpdateAdminTLS_auditDetailRecordsCertificateReplacement(t *testing.T) {
	newRouter := func(handler gin.HandlerFunc) *gin.Engine {
		router := gin.New()
		router.PUT("/admin-tls", handler)
		return router
	}
	latestDetail := func(t *testing.T) string {
		t.Helper()
		var detail string
		if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新' AND resource='基础设置' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
			t.Fatalf("read audit detail: %v", err)
		}
		return detail
	}
	sendJSON := func(t *testing.T, payload map[string]any) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		request := httptest.NewRequest(http.MethodPut, "/admin-tls", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		newRouter((newAdminTLSHandlers(t)).UpdateAdminTLS).ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
		}
		return response
	}

	t.Run("上传替换证书", func(t *testing.T) {
		initializeRuleFeatureTestDB(t)
		oldExit := exitProcess
		exited := make(chan struct{}, 1)
		exitProcess = func(int) { exited <- struct{}{} }
		t.Cleanup(func() { exitProcess = oldExit })
		if _, err := db.DB.Exec(`UPDATE global_config SET admin_tls_enabled=0,admin_tls_mode='selfsigned',
			admin_tls_cert='',admin_tls_key='' WHERE id=1`); err != nil {
			t.Fatalf("seed admin TLS config: %v", err)
		}
		certPEM, keyPEM, err := generateTestCert("u13-10-replace.example.com", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
		if err != nil {
			t.Fatalf("generate cert pair: %v", err)
		}

		sendJSON(t, map[string]any{"enabled": true, "mode": "upload", "cert_file": certPEM, "key_file": keyPEM})

		if detail := latestDetail(t); !strings.Contains(detail, "证书：已更换（来源 upload）") {
			t.Fatalf("audit detail=%q, want 含「证书：已更换（来源 upload）」", detail)
		}
		// 等待 restartProcess 的延迟退出 goroutine 在桩生效期内消费，避免清理
		// 还原 exitProcess 后被迟到的 os.Exit 打穿测试进程（同既有用例口径）。
		select {
		case <-exited:
		case <-time.After(time.Second):
			t.Fatal("restart was not scheduled")
		}
	})

	t.Run("仅开关未换证书", func(t *testing.T) {
		initializeRuleFeatureTestDB(t)
		oldExit := exitProcess
		exited := make(chan struct{}, 1)
		exitProcess = func(int) { exited <- struct{}{} }
		t.Cleanup(func() { exitProcess = oldExit })
		certPEM, keyPEM, err := generateTestCert("u13-10-toggle.example.com", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
		if err != nil {
			t.Fatalf("generate cert pair: %v", err)
		}
		if _, err := db.DB.Exec(`UPDATE global_config SET admin_tls_enabled=1,admin_tls_mode='upload',
			admin_tls_cert=?,admin_tls_key=? WHERE id=1`, certPEM, keyPEM); err != nil {
			t.Fatalf("seed admin TLS config: %v", err)
		}

		sendJSON(t, map[string]any{"enabled": false})

		detail := latestDetail(t)
		if !strings.Contains(detail, "证书：未更换") {
			t.Fatalf("audit detail=%q, want 含「证书：未更换」", detail)
		}
		if strings.Contains(detail, "已更换") {
			t.Fatalf("audit detail=%q, want 不应声称证书更换（本次仅切换启用态）", detail)
		}
		// 「未更换」不能只靠文案：库内证书材料必须逐字节保持原值（合并逻辑
		// 若用零值参与比较/写回，文案仍会写「未更换」而材料已被清空）。
		var storedCert, storedKey string
		if err := db.DB.QueryRow(`SELECT admin_tls_cert, admin_tls_key FROM global_config WHERE id=1`).Scan(&storedCert, &storedKey); err != nil {
			t.Fatalf("read admin TLS material: %v", err)
		}
		if storedCert != certPEM || storedKey != keyPEM {
			t.Fatalf("仅切换启用态改写了证书材料: certLen=%d/%d keyLen=%d/%d", len(storedCert), len(certPEM), len(storedKey), len(keyPEM))
		}
		select {
		case <-exited:
		case <-time.After(time.Second):
			t.Fatal("restart was not scheduled")
		}
	})
}

// upload → selfsigned 切换此前把已上传证书/私钥继续留在
// global_config（selfsigned 由 ResolveCertificate 自生成，残留 upload 材料无消费者，
// 且随备份/导入继续传播）。切换后必须清空；upload 模式禁用保留既有钉测已锁。
func TestUpdateAdminTLS_switchingToSelfsignedClearsUploadedMaterial(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET admin_tls_enabled=1,admin_tls_mode='upload',
		admin_tls_cert='existing cert',admin_tls_key='existing key' WHERE id=1`); err != nil {
		t.Fatalf("seed admin TLS config: %v", err)
	}
	oldExit := exitProcess
	exited := make(chan struct{}, 1)
	exitProcess = func(int) { exited <- struct{}{} }
	t.Cleanup(func() { exitProcess = oldExit })
	handler := newAdminTLSHandlers(t)
	router := gin.New()
	router.POST("/admin-tls", handler.UpdateAdminTLS)
	request := httptest.NewRequest(http.MethodPost, "/admin-tls",
		strings.NewReader(`{"enabled":true,"mode":"selfsigned"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var mode, cert, key string
	if err := db.DB.QueryRow("SELECT admin_tls_mode,admin_tls_cert,admin_tls_key FROM global_config WHERE id=1").Scan(&mode, &cert, &key); err != nil {
		t.Fatalf("read admin TLS config: %v", err)
	}
	if mode != "selfsigned" || cert != "" || key != "" {
		t.Fatalf("saved=(%q,%q,%q), want selfsigned 且证书材料清空", mode, cert, key)
	}
	// 清空是安全相关动作：审计必须与「只切来源、材料保留」可区分。
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新' AND resource='基础设置' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if !strings.Contains(detail, "证书：已清除") {
		t.Fatalf("audit detail=%q, want 含「证书：已清除（切换到 selfsigned）」", detail)
	}
	// 变更路径必重启——且须在本测试内收走 500ms 延迟的 exitProcess 调用，
	// 否则残留 goroutine 会打进后续测试的 stub（跨测试污染实证）。
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("restart was not scheduled")
	}
}

// 值未变更时 PUT /admin-tls 此前仍写库并触发进程重启
// （设置页重复保存=无谓停机）。未变更 → 200「未变更」、不写库、不重启。
// 「不写库」必须查 DB 终态：同值 UPDATE 也会刷新 updated_at，进而打断集群
// 版本/快照指纹的「无变化」判定链——仅断言响应文案与不重启无法发现退化。
func TestUpdateAdminTLS_unchangedConfigSkipsWriteAndRestart(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET admin_tls_enabled=1,admin_tls_mode='selfsigned',
		admin_tls_cert='',admin_tls_key='',updated_at='2000-01-01 00:00:00' WHERE id=1`); err != nil {
		t.Fatalf("seed admin TLS config: %v", err)
	}
	type adminTLSRow struct {
		enabled   bool
		mode      string
		cert      string
		key       string
		updatedAt string
	}
	readRow := func() adminTLSRow {
		t.Helper()
		var row adminTLSRow
		if err := db.DB.QueryRow(`SELECT admin_tls_enabled,admin_tls_mode,admin_tls_cert,admin_tls_key,
			COALESCE(updated_at,'') FROM global_config WHERE id=1`).
			Scan(&row.enabled, &row.mode, &row.cert, &row.key, &row.updatedAt); err != nil {
			t.Fatalf("read admin TLS config: %v", err)
		}
		return row
	}
	before := readRow()
	oldExit := exitProcess
	exited := make(chan struct{}, 1)
	exitProcess = func(int) { exited <- struct{}{} }
	t.Cleanup(func() { exitProcess = oldExit })
	handler := newAdminTLSHandlers(t)
	router := gin.New()
	router.POST("/admin-tls", handler.UpdateAdminTLS)
	request := httptest.NewRequest(http.MethodPost, "/admin-tls",
		strings.NewReader(`{"enabled":true,"mode":"selfsigned"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "未变更") {
		t.Fatalf("body=%s, want 未变更提示", response.Body.String())
	}
	if after := readRow(); after != before {
		t.Fatalf("未变更提交改写了库内终态: before=%+v after=%+v（同值 UPDATE 也会刷新 updated_at）", before, after)
	}
	select {
	case <-exited:
		t.Fatal("未变更配置不得触发重启")
	case <-time.After(800 * time.Millisecond):
	}
}

// 携带证书材料但生效来源不是 upload 时不得静默丢弃
// （旧行为可能回「配置未变更」200）——必须 400 点名正确做法且不落库。
func TestUpdateAdminTLSJSONBody_rejectsUploadPayloadWithoutUploadMode(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET admin_tls_enabled=0,admin_tls_mode='selfsigned',
		admin_tls_cert='',admin_tls_key='' WHERE id=1`); err != nil {
		t.Fatalf("seed admin TLS config: %v", err)
	}
	certPEM, keyPEM, err := generateTestCert("silent-drop.example.com", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate cert pair: %v", err)
	}
	oldExit := exitProcess
	exitProcess = func(int) { t.Error("rejected update must not schedule restart") }
	t.Cleanup(func() { exitProcess = oldExit })
	handler := newAdminTLSHandlers(t)
	router := gin.New()
	router.PUT("/admin-tls", handler.UpdateAdminTLS)

	for _, test := range []struct {
		name string
		body map[string]any
	}{
		{name: "mode omitted (keeps current selfsigned)", body: map[string]any{"enabled": false, "cert_file": certPEM, "key_file": keyPEM}},
		{name: "explicit non-upload mode", body: map[string]any{"enabled": false, "mode": "selfsigned", "cert_file": certPEM, "key_file": keyPEM}},
	} {
		payload, err := json.Marshal(test.body)
		if err != nil {
			t.Fatalf("marshal %s: %v", test.name, err)
		}
		request := httptest.NewRequest(http.MethodPut, "/admin-tls", bytes.NewReader(payload))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "证书来源不是 upload") {
			t.Fatalf("%s status=%d body=%s, want 400 upload-mode guidance", test.name, response.Code, response.Body.String())
		}
	}
	var mode, cert, key string
	if err := db.DB.QueryRow("SELECT admin_tls_mode,admin_tls_cert,admin_tls_key FROM global_config WHERE id=1").Scan(&mode, &cert, &key); err != nil {
		t.Fatalf("read admin TLS config: %v", err)
	}
	if mode != "selfsigned" || cert != "" || key != "" {
		t.Fatalf("saved config=(%q,%v,%v), want untouched selfsigned", mode, cert != "", key != "")
	}
}

// enabled 是安全开关，字符串值必须遵循 true/1/false/0 白名单；
// 非法拼写不得静默按 false 关闭 HTTPS 并触发重启，合法 "0" 保持回归。
func TestUpdateAdminTLS_enabledValueWhitelist(t *testing.T) {
	for _, tc := range []struct {
		name        string
		multipart   bool
		value       string
		wantStatus  int
		wantEnabled bool
		wantRestart bool
	}{
		{name: "JSON invalid uppercase", value: "TRUE", wantStatus: http.StatusBadRequest, wantEnabled: true},
		// 显式空串（脚本拼接/模板缺值）必须与 TRUE/on 同走白名单 400，不得被
		// 当作「未提交」而返回 200「配置未变更」。
		{name: "JSON explicit empty", value: "", wantStatus: http.StatusBadRequest, wantEnabled: true},
		{name: "multipart explicit empty", multipart: true, value: "", wantStatus: http.StatusBadRequest, wantEnabled: true},
		{name: "multipart invalid text", multipart: true, value: "on", wantStatus: http.StatusBadRequest, wantEnabled: true},
		{name: "JSON valid zero", value: "0", wantStatus: http.StatusOK, wantEnabled: false, wantRestart: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			initializeRuleFeatureTestDB(t)
			if _, err := db.DB.Exec(`UPDATE global_config SET admin_tls_enabled=1,admin_tls_mode='selfsigned',admin_tls_cert='',admin_tls_key='' WHERE id=1`); err != nil {
				t.Fatalf("seed admin TLS config: %v", err)
			}
			oldExit := exitProcess
			exited := make(chan struct{}, 1)
			exitProcess = func(int) { exited <- struct{}{} }
			t.Cleanup(func() { exitProcess = oldExit })
			handler := newAdminTLSHandlers(t)
			router := gin.New()
			router.PUT("/admin-tls", handler.UpdateAdminTLS)

			var request *http.Request
			if tc.multipart {
				var body strings.Builder
				writer := multipart.NewWriter(&body)
				if err := writer.WriteField("enabled", tc.value); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				request = httptest.NewRequest(http.MethodPut, "/admin-tls", strings.NewReader(body.String()))
				request.Header.Set("Content-Type", writer.FormDataContentType())
			} else {
				payload, err := json.Marshal(map[string]any{"enabled": tc.value})
				if err != nil {
					t.Fatal(err)
				}
				request = httptest.NewRequest(http.MethodPut, "/admin-tls", bytes.NewReader(payload))
				request.Header.Set("Content-Type", "application/json")
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != tc.wantStatus {
				t.Fatalf("status=%d body=%s, want %d", response.Code, response.Body.String(), tc.wantStatus)
			}
			var enabled bool
			if err := db.DB.QueryRow(`SELECT admin_tls_enabled FROM global_config WHERE id=1`).Scan(&enabled); err != nil {
				t.Fatal(err)
			}
			if enabled != tc.wantEnabled {
				t.Fatalf("enabled=%v, want %v", enabled, tc.wantEnabled)
			}
			if tc.wantRestart {
				select {
				case <-exited:
				case <-time.After(2 * time.Second):
					t.Fatal("合法状态变更未触发重启")
				}
			} else {
				select {
				case <-exited:
					t.Fatal("非法 enabled 触发了重启")
				case <-time.After(600 * time.Millisecond):
				}
			}
		})
	}
}

// 库内证书损坏/非 PEM（带外改库、旧版本导入）时，读路径
// 此前静默省略 cert_info——UI 只见 enabled=true 无证书信息、运维零信号。
// 现在必须显式暴露 cert_info_error（fail-visible，与写路径严格校验同口径）。
func TestGetAdminTLS_corruptStoredCertIsVisible(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET admin_tls_enabled=1, admin_tls_mode='upload',
		admin_tls_cert='not-a-pem', admin_tls_key='not-a-key' WHERE id=1`); err != nil {
		t.Fatalf("seed corrupt admin TLS cert: %v", err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/admin-tls", nil)
	(&Handlers{}).GetAdminTLS(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（读路径不得因损坏证书 500）", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Data struct {
			Enabled       bool   `json:"enabled"`
			CertInfo      any    `json:"cert_info"`
			CertInfoError string `json:"cert_info_error"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Data.Enabled {
		t.Fatalf("enabled=false body=%s, want true（保留库内开关原值）", recorder.Body.String())
	}
	if body.Data.CertInfo != nil {
		t.Fatalf("cert_info=%v, want null（解析失败不得给出伪造信息）", body.Data.CertInfo)
	}
	if body.Data.CertInfoError == "" {
		t.Fatalf("cert_info_error 为空：损坏证书必须显式暴露，body=%s", recorder.Body.String())
	}
}

// 管理面板 HTTPS 保存属高危设置——非法载荷（enabled 白名单）
// 与写库失败此前只回 400/500、不写审计，失败尝试不可回溯。沿用既有
// 「更新失败/基础设置」词条（同 UpdateConfig 失败留痕口径）。
func TestUpdateAdminTLS_failuresAreAudited(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	if err := db.InitializeAuditDB(t.TempDir()); err != nil {
		t.Fatalf("initialize audit db: %v", err)
	}
	handler := newAdminTLSHandlers(t)
	send := func(payload string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodPut, "/admin-tls", strings.NewReader(payload))
		ctx.Request.Header.Set("Content-Type", "application/json")
		handler.UpdateAdminTLS(ctx)
		return recorder
	}
	latestFailure := func() string {
		t.Helper()
		var detail string
		if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新失败' AND resource='基础设置' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
			t.Fatalf("read failure audit detail: %v", err)
		}
		return detail
	}

	// 形状一：enabled 非法拼写 → 400 + 审计
	if recorder := send(`{"enabled":"TRUE"}`); recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid enabled status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	if detail := latestFailure(); !strings.Contains(detail, "enabled") || !strings.Contains(detail, "结果：失败") {
		t.Fatalf("非法 enabled 未留痕：detail=%q", detail)
	}

	// 形状二：UPDATE 写库失败 → 500 + 审计（SQLite 触发器强制失败，避免依赖
	// 真实磁盘故障）。
	if _, err := db.DB.Exec(`UPDATE global_config SET admin_tls_enabled=1, admin_tls_mode='selfsigned', admin_tls_cert='', admin_tls_key='' WHERE id=1`); err != nil {
		t.Fatalf("seed admin TLS config: %v", err)
	}
	if _, err := db.DB.Exec(`CREATE TRIGGER fail_admin_tls_update BEFORE UPDATE ON global_config BEGIN SELECT RAISE(ABORT,'forced'); END`); err != nil {
		t.Fatalf("create failing trigger: %v", err)
	}
	if recorder := send(`{"enabled":false}`); recorder.Code != http.StatusInternalServerError {
		t.Fatalf("update failure status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
	if detail := latestFailure(); !strings.Contains(detail, "写入") {
		t.Fatalf("写库失败未留痕：detail=%q", detail)
	}
}

// 413 口径此前只测 JSON 通道——multipart 超整体体上限未覆盖，
// 表单解析错误须同样映射 413（respondAdminTLSBodyError 的 *http.MaxBytesError
// 分支）。两入口（保存/预检）同门。
func TestAdminTLSOversizedMultipartBodyReturns413(t *testing.T) {
	var body strings.Builder
	writer := multipart.NewWriter(&body)
	filePart, err := writer.CreateFormFile("cert_file", "cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := filePart.Write(bytes.Repeat([]byte("a"), maxAdminTLSBodyBytes+64)); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteField("mode", "selfsigned"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	newRouter := func(handler gin.HandlerFunc, method, path string) *gin.Engine {
		router := gin.New()
		router.Handle(method, path, handler)
		return router
	}
	send := func(router *gin.Engine, method, path string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body.String()))
		request.Header.Set("Content-Type", writer.FormDataContentType())
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}

	updateResponse := send(newRouter((newAdminTLSHandlers(t)).UpdateAdminTLS, http.MethodPut, "/admin-tls"), http.MethodPut, "/admin-tls")
	inspectResponse := send(newRouter((newAdminTLSHandlers(t)).InspectAdminTLSCert, http.MethodPost, "/admin-tls/inspect"), http.MethodPost, "/admin-tls/inspect")

	if updateResponse.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("PUT /admin-tls multipart oversized status=%d body=%s, want 413", updateResponse.Code, updateResponse.Body.String())
	}
	if inspectResponse.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("POST /admin-tls/inspect multipart oversized status=%d body=%s, want 413", inspectResponse.Code, inspectResponse.Body.String())
	}
}

// UpdateAdminTLS 是读改写（读 current → 合并四列 → 整体 UPDATE）。未持
// caddyOpMu 时并发保存会以各自基线整体覆盖，前一次变更
// 静默丢失。本测试钉住「锁被占用时保存必须等待」——修复前请求会立即完成。
func TestUpdateAdminTLS_serializesReadModifyWriteWithCaddyOpLock(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET admin_tls_enabled=1,admin_tls_mode='upload',
		admin_tls_cert='existing cert',admin_tls_key='existing key' WHERE id=1`); err != nil {
		t.Fatalf("seed admin TLS config: %v", err)
	}
	oldExit := exitProcess
	exited := make(chan struct{}, 1)
	exitProcess = func(int) { exited <- struct{}{} }
	t.Cleanup(func() { exitProcess = oldExit })

	var body strings.Builder
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("enabled", "false"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	handler := newAdminTLSHandlers(t)
	router := gin.New()
	router.POST("/admin-tls", handler.UpdateAdminTLS)
	request := httptest.NewRequest(http.MethodPost, "/admin-tls", strings.NewReader(body.String()))
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response := httptest.NewRecorder()

	handler.caddyOpMu.Lock()
	done := make(chan struct{})
	go func() {
		router.ServeHTTP(response, request)
		close(done)
	}()
	select {
	case <-done:
		handler.caddyOpMu.Unlock()
		t.Fatal("UpdateAdminTLS 在 caddyOpMu 被占用时仍完成——读改写未串行化，并发保存会互相覆盖")
	case <-time.After(150 * time.Millisecond):
	}
	handler.caddyOpMu.Unlock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("UpdateAdminTLS 在解锁后仍未完成（死锁或锁未释放）")
	}
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	// restartProcess 的延迟退出必须在桩生效期内消费，避免清理还原 exitProcess
	// 后被迟到的 os.Exit 打穿测试进程（既有用例同口径）。
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("restart was not scheduled after successful save")
	}
}

// 配置读失败必须显式披露：降级默认形态（未启用/自签名）与真实启用态相反，
// 静默展示会误导运维（DB 故障/迁移窗口）。
func TestGetAdminTLS_reportsConfigUnavailableOnReadFailure(t *testing.T) {
	old := db.DB
	db.DB = nil
	t.Cleanup(func() { db.DB = old })

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/admin-tls", nil)
	(&Handlers{}).GetAdminTLS(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d", recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, `"config_unavailable":true`) {
		t.Fatalf("body=%s, want config_unavailable=true", body)
	}
	if !strings.Contains(body, `"enabled":false`) {
		t.Fatalf("body=%s, want 降级 enabled=false", body)
	}
}

// admin TLS 测试的非空 Handlers 字面量只能位于 newAdminTLSHandlers 内，
// 并由该单源夹具提供隔离 DataDir。空 Handlers{} 仍可用于不触达文件系统的
// 只读端点。扫描命中数必须非零，避免 glob 或 AST 识别退化后门禁假绿。
func TestAdminTLSTests_allFixturesCarryIsolatedDataDir(t *testing.T) {
	files, err := filepath.Glob("admintls*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("admin TLS 夹具守卫未匹配任何测试文件")
	}
	checked := 0
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		count, violations, err := scanAdminTLSFixtureSource(file, raw)
		if err != nil {
			t.Fatal(err)
		}
		checked += count
		for _, violation := range violations {
			t.Error(violation)
		}
	}
	if checked == 0 {
		t.Fatal("admin TLS 夹具守卫未检查任何非空 Handlers 字面量")
	}
}

// scanAdminTLSFixtureSource 同时识别包内 Handlers 与限定名 pkg.Handlers。
// 返回值分别是非空字面量检查数和违反单源/隔离目录约定的描述。
func scanAdminTLSFixtureSource(file string, raw []byte) (int, []string, error) {
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, file, raw, 0)
	if err != nil {
		return 0, nil, err
	}
	checked := 0
	violations := make([]string, 0)
	ast.Inspect(parsed, func(node ast.Node) bool {
		composite, ok := node.(*ast.CompositeLit)
		if !ok || len(composite.Elts) == 0 {
			return true
		}
		typeName := ""
		switch typ := composite.Type.(type) {
		case *ast.Ident:
			typeName = typ.Name
		case *ast.SelectorExpr:
			typeName = typ.Sel.Name
		}
		if typeName != "Handlers" {
			return true
		}
		checked++
		startOffset := fset.Position(composite.Pos()).Offset
		endOffset := fset.Position(composite.End()).Offset
		literal := string(raw[startOffset:endOffset])
		functionName := ""
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && composite.Pos() >= fn.Pos() && composite.End() <= fn.End() {
				functionName = fn.Name.Name
				break
			}
		}
		if !strings.Contains(literal, "DataDir") || !strings.Contains(literal, "t.TempDir()") {
			violations = append(violations, file+":"+functionName+": Handlers 夹具缺少 t.TempDir() 隔离 DataDir（请改用 newAdminTLSHandlers）: "+literal)
			return true
		}
		if functionName != "newAdminTLSHandlers" {
			violations = append(violations, file+":"+functionName+": 非空 Handlers 字面量只能位于 newAdminTLSHandlers 单源夹具内: "+literal)
		}
		return true
	})
	return checked, violations, nil
}

func TestAdminTLSFixtureGuardDetectsUnsafeShapes(t *testing.T) {
	const source = `package p
func newAdminTLSHandlers(t *testing.T) *Handlers {
	return &Handlers{cfg: &config.Config{DataDir: t.TempDir()}}
}
func identFixture(t *testing.T) {
	_ = &Handlers{cfg: &config.Config{DataDir: t.TempDir()}}
	_ = &Handlers{}
}
func selectorFixture(t *testing.T) {
	_ = &fixture.Handlers{cfg: &config.Config{DataDir: t.TempDir()}}
	_ = &fixture.Handlers{}
}`
	checked, violations, err := scanAdminTLSFixtureSource("synthetic.go", []byte(source))
	if err != nil {
		t.Fatalf("parse synthetic fixtures: %v", err)
	}
	if checked != 3 {
		t.Fatalf("checked=%d, want 3（Ident/SelectorExpr 两种形态都必须计入）", checked)
	}
	if len(violations) != 2 {
		t.Fatalf("violations=%v, want identFixture 与 selectorFixture 各一处", violations)
	}
	for _, functionName := range []string{"identFixture", "selectorFixture"} {
		found := false
		for _, violation := range violations {
			if strings.Contains(violation, functionName) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("violations=%v, 缺少 %s 的反形状命中", violations, functionName)
		}
	}
}

func TestAdminTLSFixtureGuardRejectsEmptyDataDir(t *testing.T) {
	const source = `package p
func newAdminTLSHandlers(t *testing.T) *Handlers {
	return &Handlers{cfg: &config.Config{DataDir: ""}}
}`
	checked, violations, err := scanAdminTLSFixtureSource("synthetic.go", []byte(source))
	if err != nil {
		t.Fatalf("parse synthetic fixture: %v", err)
	}
	if checked != 1 || len(violations) != 1 {
		t.Fatalf("checked=%d violations=%v, want 1/1（空 DataDir 不得凭字段名存在而通过）", checked, violations)
	}
}
