package handlers

// 提交后失败的两条事实通道必须各自可见（P3 收口）：
//   - 运行配置恢复结果 → 横幅两态标签（「旧配置已保留」/「运行配置状态未知」）；
//   - 附带失败（LKG 钉回 / 证书清理 / 未提交事务回滚）→ 独立「补偿失败」审计，
//     不得改写运行配置标签。
// 同时钉提交失败的失败对象文案：commit 失败 ≠ 配置应用失败。

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestPostCommitFailureBanner_commitObjectWording(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	handler := &Handlers{}

	handler.recordPostCommitRestoreFailure(commitSaveFailedSubject, errors.New("disk I/O error"), errors.New("恢复 /load 失败"), nil)
	got := bannerText(t)
	if !strings.Contains(got, "配置保存失败") || !strings.Contains(got, "数据库提交结果不确定") {
		t.Fatalf("横幅=%q, want 失败对象为提交（配置保存失败 + 提交结果不确定）", got)
	}
	if strings.Contains(got, "Caddy 配置应用失败") {
		t.Fatalf("横幅=%q, want 不得把提交失败归因为配置应用失败", got)
	}
	if !strings.Contains(got, caddyApplyRestoreFailedLabel) {
		t.Fatalf("横幅=%q, want 含「运行配置状态未知」", got)
	}
}

func TestPostCommitFailureBanner_sideEffectDoesNotFlipLabel(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	handler := &Handlers{}

	// 运行配置已恢复（runtimeErr=nil），只有附带失败：不得写失败横幅。
	handler.recordPostCommitRestoreFailure(commitSaveFailedSubject, errors.New("disk I/O error"), nil, errors.New("last-known-good 钉回失败"))
	if got := bannerText(t); got != "" {
		t.Fatalf("运行配置已恢复时不应写横幅: %q", got)
	}
	var rows int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='补偿失败'`).Scan(&rows); err != nil {
		t.Fatalf("read compensation audit: %v", err)
	}
	if rows == 0 {
		t.Fatal("附带失败必须独立留痕（补偿失败审计）")
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='补偿失败' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("read compensation detail: %v", err)
	}
	if !strings.Contains(detail, "last-known-good 钉回失败") {
		t.Fatalf("补偿失败审计 detail=%q, want 点名附带失败对象", detail)
	}
}

// 提交失败 + 恢复 /load 失败：横幅落提交口径的「状态未知」，且真实 /load
// 的「重载」审计不因随后失败缺席。
func TestCreateRule_commitFailureRestoreFailWritesCommitBanner(t *testing.T) {
	handler, _ := newCompensationLoadHandlers(t, false)
	forceCommitFailure(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(acmeCompensationRuleBody))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), commitUncertainLabel) {
		t.Fatalf("body=%s, want 含提交不确定文案", response.Body.String())
	}
	got := bannerText(t)
	if !strings.Contains(got, "配置保存失败") || !strings.Contains(got, caddyApplyRestoreFailedLabel) {
		t.Fatalf("横幅=%q, want 提交口径 + 运行配置状态未知", got)
	}
	if strings.Contains(got, "Caddy 配置应用失败") {
		t.Fatalf("横幅=%q, want 不得归因为配置应用失败", got)
	}
	assertReloadAuditPresent(t)
}

// 提交失败 + 恢复成功：不写横幅（库态与运行态一致），但重载审计必须在册。
func TestCreateRule_commitFailureRestoreOKNoBanner(t *testing.T) {
	handler, _ := newCompensationLoadHandlers(t, true)
	forceCommitFailure(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(acmeCompensationRuleBody))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	if got := bannerText(t); got != "" {
		t.Fatalf("恢复成功不应写失败横幅: %q", got)
	}
	assertReloadAuditPresent(t)
}

func forceCommitFailure(t *testing.T) {
	withIsolatedGlobal(t)
	t.Helper()
	previous := txCommitForTest
	txCommitForTest = func(tx *sql.Tx) error {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			return err
		}
		return errors.New("disk I/O error")
	}
	t.Cleanup(func() { txCommitForTest = previous })
}

func assertReloadAuditPresent(t *testing.T) {
	t.Helper()
	var rows int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='重载' AND resource='Caddy服务'`).Scan(&rows); err != nil {
		t.Fatalf("read reload audit: %v", err)
	}
	if rows == 0 {
		t.Fatal("真实 /load 已发生，提交失败分支不得吞掉「重载」审计")
	}
}

// 更新/删除/启用/禁用四个端点的「提交失败」双通道行为钉测——此前测试缝
// （commitTx）只接在创建与配置端点上，这四个端点的横幅/附带失败语义只有
// 源码结构门（审计存在性）覆盖，写反了仍然全绿。
// 两种形态逐端点各一例：
//   - 提交失败 + 恢复成功 = 库态/运行态一致 → 不写横幅，但「重载」审计在册；
//   - 提交失败 + 恢复失败 = 分叉 → 提交口径横幅 + 「运行配置状态未知」标签。
func TestRuleEndpoints_commitFailureDoubleChannels(t *testing.T) {
	type endpointCase struct {
		name       string
		caddyID    string
		suffix     string
		method     string
		body       string
		seedEnable bool
		failAction string
	}
	cases := []endpointCase{
		{"update", "lb_cf_upd", "", http.MethodPut, `{"name":"cf-upd-renamed"}`, true, "更新失败"},
		{"delete", "lb_cf_del", "", http.MethodDelete, "", true, "删除失败"},
		{"enable", "lb_cf_ena", "/enable", http.MethodPost, "", false, "启用失败"},
		{"disable", "lb_cf_dis", "/disable", http.MethodPost, "", true, "禁用失败"},
	}
	for _, tc := range cases {
		for _, restoreSucceeds := range []bool{true, false} {
			name := tc.name + "/restore-fail"
			if restoreSucceeds {
				name = tc.name + "/restore-ok"
			}
			t.Run(name, func(t *testing.T) {
				handler, _ := newCompensationLoadHandlers(t, restoreSucceeds)
				seedAuditRule(t, tc.caddyID, tc.caddyID, strings.ReplaceAll(tc.caddyID, "_", "-")+".example.test", 18101, tc.seedEnable, "manual", false)
				seedAuditUpstream(t, tc.caddyID)
				forceCommitFailure(t)

				gin.SetMode(gin.TestMode)
				router := gin.New()
				switch tc.method {
				case http.MethodDelete:
					router.DELETE("/rules/:caddy_id", handler.DeleteRule)
				case http.MethodPut:
					router.PUT("/rules/:caddy_id", handler.UpdateRule)
				default:
					router.POST("/rules/:caddy_id/enable", handler.EnableRule)
					router.POST("/rules/:caddy_id/disable", handler.DisableRule)
				}

				request := httptest.NewRequest(tc.method, "/rules/"+tc.caddyID+tc.suffix, strings.NewReader(tc.body))
				request.Header.Set("Content-Type", "application/json")
				response := httptest.NewRecorder()
				router.ServeHTTP(response, request)

				if response.Code != http.StatusInternalServerError {
					t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
				}
				if !strings.Contains(response.Body.String(), commitUncertainLabel) {
					t.Fatalf("body=%s, want 含提交不确定文案", response.Body.String())
				}
				got := bannerText(t)
				if restoreSucceeds {
					if got != "" {
						t.Fatalf("恢复成功不应写失败横幅: %q", got)
					}
				} else {
					if !strings.Contains(got, "配置保存失败") || !strings.Contains(got, caddyApplyRestoreFailedLabel) {
						t.Fatalf("横幅=%q, want 提交口径 + 运行配置状态未知", got)
					}
					if strings.Contains(got, "Caddy 配置应用失败") {
						t.Fatalf("横幅=%q, want 不得归因为配置应用失败", got)
					}
				}
				assertReloadAuditPresent(t)
				var failureRows int
				if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action=? AND resource='负载规则' AND detail LIKE ?`,
					tc.failAction, "%"+tc.caddyID+"%").Scan(&failureRows); err != nil {
					t.Fatalf("read failure audit: %v", err)
				}
				if failureRows != 1 {
					t.Fatalf("%s 审计条数=%d, want 1（提交失败必须留痕）", tc.failAction, failureRows)
				}
			})
		}
	}
}
