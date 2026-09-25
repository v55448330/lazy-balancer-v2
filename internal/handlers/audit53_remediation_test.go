package handlers

// 第 53 轮审计修复 RED（用户裁定按建议处理）：
// ①policy_type 重推断改列必须落审计 delta（「实际变动的字段都记」原则的
//   系统性例外——部分更新触发 mixed→stageN 重推断时类型变更零留痕）；
// ②面板 HTTPS 禁用态不得落库白名单外 mode 值（校验此前仅在 enabled 分支）。

import (
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

func TestUpdateSecurityPolicy_reinferredPolicyTypeAudited(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if err := db.InitializeAuditDB(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	router := newSecurityRouter(t)
	// Given：存量 mixed 策略但内容仅剩阶段 1 特征（ACL）——部分更新会触发重推断
	res, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, policy_type, ip_acl_enabled, ip_acl_mode, ip_acl_list)
		VALUES ('重推断策略', 'off', 1, 'mixed', 1, 'deny', '["1.1.1.1"]')`)
	if err != nil {
		t.Fatal(err)
	}
	policyID, _ := res.LastInsertId()

	// When：部分更新（不带 policy_type）改动 ACL 名单——重推断 mixed→stage1
	r := putJSON(t, router, fmt.Sprintf("/security/policies/%d", policyID), map[string]any{"ip_acl_list": `["2.2.2.2"]`})
	if r.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", r.Code, r.Body.String())
	}

	// Then：列被重推断改写，且审计 delta 留痕（不得零留痕）
	var policyType string
	if err := db.DB.QueryRow(`SELECT policy_type FROM security_policies WHERE id=?`, policyID).Scan(&policyType); err != nil {
		t.Fatal(err)
	}
	if policyType != "stage1" {
		t.Fatalf("policy_type=%q, want stage1（重推断应命中——测试夹具失效）", policyType)
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新' AND resource='安全策略' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail, "策略类型：mixed→stage1") {
		t.Fatalf("detail=%q, want 含 策略类型：mixed→stage1（重推断改列必须留痕）", detail)
	}
}

func TestUpdateAdminTLS_disabledRejectsUnknownMode(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	oldExit := exitProcess
	exitProcess = func(int) {}
	t.Cleanup(func() { exitProcess = oldExit })
	handler := &Handlers{cfg: &config.Config{Port: 8000}}
	router := gin.New()
	router.POST("/admin-tls", handler.UpdateAdminTLS)

	// When：禁用态提交白名单外 mode
	var body strings.Builder
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("enabled", "false")
	_ = writer.WriteField("mode", "garbage")
	_ = writer.Close()
	request := httptest.NewRequest(http.MethodPost, "/admin-tls", strings.NewReader(body.String()))
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then：400 拒绝——白名单值域门与 enabled 状态无关（「只有合法形态可落库」）
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（禁用态落库垃圾 mode=值域门破口）", response.Code, response.Body.String())
	}
	var mode string
	if err := db.DB.QueryRow(`SELECT COALESCE(admin_tls_mode,'') FROM global_config WHERE id=1`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode == "garbage" {
		t.Fatal("垃圾 mode 已落库")
	}
}
