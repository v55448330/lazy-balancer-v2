package handlers

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"

	"github.com/gin-gonic/gin"
)

// R69 B69-N3(a)：TestCertificateConfig 的 storage_corrupted 分支——存量凭证
// 「非空但不可解析」归 500（R68 B-F5），与空凭证的缺凭证 400（既有测试钉住）
// 分界。
func TestCertificateConfigStorageCorrupted(t *testing.T) {
	h := newBackupTestHandlers(t)
	result, err := db.DB.Exec("INSERT INTO certificate_configs (name, dns_provider, dns_credentials, enabled) VALUES ('corrupt', 'dnspod', '{bad json', 1)")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	id, _ := result.LastInsertId()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/certificate-configs/"+strconv.FormatInt(id, 10)+"/test", strings.NewReader(`{"domain":"example.com"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Params = gin.Params{{Key: "id", Value: strconv.FormatInt(id, 10)}}
	h.TestCertificateConfig(ctx)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（存储损坏 ≠ 凭证无效）", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "已损坏") {
		t.Fatalf("body=%s, want 损坏文案", recorder.Body.String())
	}
}

// R69 B69-N3(b)：UpdateSecurityCustomRule 的 storage_corrupted 分支（R69 B69-N1）
// 与指针合并语义在事务下的回归（R69 B69-N2 的行为面）。
func TestUpdateSecurityCustomRuleStorageCorrupted(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	ginRouter := newCustomRuleRouter(t)
	result, err := db.DB.Exec(`INSERT INTO security_custom_rules (name, conditions, action, score, enabled) VALUES ('corrupt', '{bad json', 'block', 5, 1)`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := result.LastInsertId()

	recorder := putJSON(t, ginRouter, "/security/custom-rules/"+strconv.FormatInt(id, 10), map[string]any{"name": "改名"})
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（存量条件损坏 ≠ 用户漏传条件）", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "已损坏") {
		t.Fatalf("body=%s, want 损坏文案", recorder.Body.String())
	}
}

// R69 B69-N3(b)：GetCRSRuleContent 的路径门与 404 基线（413 分支需 >1MB 实文件，
// 路径硬编码 /app 不可注入，钉住可测的两分支）。
func TestGetCRSRuleContentPathGateAndMissing(t *testing.T) {
	h := newBackupTestHandlers(t)

	get := func(filename string) int {
		t.Helper()
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/security/crs/rules/"+filename, nil)
		ctx.Params = gin.Params{{Key: "filename", Value: filename}}
		h.GetCRSRuleContent(ctx)
		return recorder.Code
	}
	if code := get("..%2Fevil"); code != http.StatusBadRequest {
		t.Fatalf("traversal filename status=%d, want 400", code)
	}
	if code := get("definitely-missing-9f1c2e.conf"); code != http.StatusNotFound {
		t.Fatalf("missing file status=%d, want 404", code)
	}
}
