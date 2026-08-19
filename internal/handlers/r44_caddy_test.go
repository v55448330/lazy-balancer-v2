package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// R44 C1: v2.1.1（已发版）导出为「tables-only 校验和 + exported_at 非空」形态，
// R43 门控将其误判「篡改」整包拒绝。修复后报兼容性提示（仍拒绝导入——Config 区
// 不受旧校验和保护）；而真正篡改的新格式文件（两种校验和均不匹配）仍按篡改拒绝。
func TestValidateV2Backup_v211Shape_reportsCompatibilityNotTamper(t *testing.T) {
	var b configBackup
	if err := json.Unmarshal([]byte(legacyChecksummedBackup(t, 2, "2026-08-15T00:00:00Z", true)), &b); err != nil {
		t.Fatalf("unmarshal backup: %v", err)
	}

	usedLegacy, err := validateV2Backup(b)

	if err == nil {
		t.Fatal("v2.1.1 备份 Config 区不受旧校验和保护，不得放行导入")
	}
	if !strings.Contains(err.Error(), "v2.1.1 或更早版本导出") || !strings.Contains(err.Error(), "v2.1.2") {
		t.Fatalf("err=%q, want v2.1.1 兼容性提示并指引 v2.1.2+ 重新导出", err)
	}
	if strings.Contains(err.Error(), "篡改") {
		t.Fatalf("合法 v2.1.1 备份不得误报篡改: %q", err)
	}
	if usedLegacy {
		t.Fatal("v2.1.1 形态不得标记为旧格式校验和回退路径")
	}
}

func TestValidateV2Backup_tamperedNewFormat_stillRejectedAsTampered(t *testing.T) {
	// Given 一个新格式备份，校验和按 tables+config 计算后 Config 区被篡改
	var b configBackup
	if err := json.Unmarshal([]byte(legacyChecksummedBackup(t, 2, "2026-08-19T00:00:00Z", false)), &b); err != nil {
		t.Fatalf("unmarshal backup: %v", err)
	}
	b.Config["dns_credentials"] = "attacker-controlled"

	// When
	usedLegacy, err := validateV2Backup(b)

	// Then 两种校验和均不匹配 → 维持篡改指控
	if err == nil || !strings.Contains(err.Error(), "备份校验和不匹配，文件可能已被篡改或损坏") {
		t.Fatalf("validateV2Backup err=%v, want 篡改拒绝", err)
	}
	if usedLegacy {
		t.Fatal("篡改的新格式文件不得标记为旧格式校验和路径")
	}
}

func TestImportConfigBackup_v211Shape_returnsCompatibilityMessage(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(legacyChecksummedBackup(t, 2, "2026-08-15T00:00:00Z", true)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("import status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "v2.1.1 或更早版本导出") {
		t.Fatalf("import body=%s, want v2.1.1 兼容性提示", body)
	}
	if strings.Contains(body, "篡改") {
		t.Fatalf("import body=%s, 合法 v2.1.1 备份不得误报篡改", body)
	}
}
