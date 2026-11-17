package handlers

// 锁内复核相位的回归钉：基础设施读失败必须映射 500 + 固定文案（与初检链
// 同口径），不得伪装成「实时数据已变化」竞态 400，也不得回显驱动原文；
// 真竞态（非 infra 类失败）保持 400 竞态语义。

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
)

func newLockedStageTestContext(t *testing.T) (*gin.Context, *httptest.ResponseRecorder, *configImportSession) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/config/import", nil)
	session := &configImportSession{h: newBackupTestHandlers(t)}
	return c, rec, session
}

func TestFailImportLockedStage_infraReadFailureMaps500FixedText(t *testing.T) {
	c, rec, session := newLockedStageTestContext(t)
	cause := importInfraReadFailure(fmt.Errorf("锁内读取规则引用视图失败: disk I/O error"))

	err := failImportLockedStage(c, session, "导入", "导入锁内实时依赖复核失败", cause, "导入期间依赖的实时数据已变化，已拒绝导入")
	if err == nil {
		t.Fatal("失败必须上抛供审计链消费")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("infra 读失败 status=%d, want 500（不得伪装竞态 400）", rec.Code)
	}
	var resp models.APIResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应非 JSON: %v (body=%s)", err, rec.Body.String())
	}
	if resp.Message != errImportInfraRead.Error() {
		t.Fatalf("响应文案=%q, want 固定文案 %q（禁回显驱动原文）", resp.Message, errImportInfraRead.Error())
	}
}

func TestFailImportLockedStage_raceKept400(t *testing.T) {
	c, rec, session := newLockedStageTestContext(t)
	cause := errors.New("security_policy_bindings 第 3 行引用了不存在的规则 \"r1\"（导入期间规则已被删除）")

	err := failImportLockedStage(c, session, "导入", "导入锁内实时依赖复核失败", cause, "导入期间依赖的实时数据已变化，已拒绝导入")
	if err == nil {
		t.Fatal("失败必须上抛")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("真竞态 status=%d, want 400（竞态语义保持）", rec.Code)
	}
	var resp models.APIResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应非 JSON: %v (body=%s)", err, rec.Body.String())
	}
	if resp.Message != "导入期间依赖的实时数据已变化，已拒绝导入，已回滚: "+cause.Error() {
		t.Fatalf("竞态文案=%q", resp.Message)
	}
}
