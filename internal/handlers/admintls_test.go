package handlers

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

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

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
	handler := &Handlers{cfg: &config.Config{Port: 8000}}
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
	router.POST("/admin-tls/inspect", (&Handlers{cfg: &config.Config{}}).InspectAdminTLSCert)
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
	router.POST("/admin-tls/inspect", (&Handlers{cfg: &config.Config{}}).InspectAdminTLSCert)

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
	handler := &Handlers{cfg: &config.Config{Port: 8000}}
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
	handler := &Handlers{cfg: &config.Config{Port: 8000}}
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
