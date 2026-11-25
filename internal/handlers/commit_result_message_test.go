package handlers

// 事务提交失败的表述契约：SQLite 在 Commit 返回错误时无法区分「未提交」与
// 「已提交但确认丢失」。响应与审计必须如实表述为「数据库提交结果不确定」，
// 不得断言「提交事务失败/未生效」——否则操作者据审计重试会产生重复创建与重复
// 审计行（审计不得出现与事实相反的记录）。导入协调器（importPhaseCommit）已按
// 该口径裁定，本钉子要求事务收尾家族同口径且文案单源。

import (
	"lazy-balancer-v2/internal/i18n"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func TestFinishTxApply_commitFailureReportsUncertainOutcome(t *testing.T) {
	h := newBackupTestHandlers(t)
	// Given：延迟约束在 COMMIT 阶段才失败（模拟 IO/确认丢失型提交错误）。
	if _, err := db.DB.Exec(`PRAGMA foreign_keys=ON;
		CREATE TABLE commit_parent(id INTEGER PRIMARY KEY);
		CREATE TABLE commit_guard(parent_id INTEGER, FOREIGN KEY(parent_id) REFERENCES commit_parent(id) DEFERRABLE INITIALLY DEFERRED)`); err != nil {
		t.Fatalf("install deferred constraint: %v", err)
	}
	tx, err := db.DB.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO commit_guard(parent_id) VALUES (999)`); err != nil {
		t.Fatalf("stage deferred violation: %v", err)
	}
	rec := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(rec)
	ginCtx.Request = httptest.NewRequest(http.MethodPost, "/ctrlf", nil)

	// When
	h.finishTxApply(ginCtx, tx, txApplyFinish{
		Resource:    "规则",
		AuditAction: "创建",
		AuditDetail: services.FormatAuditDetail(services.AuditRawPart("规则 lb_uncertain"), services.AuditResultPart("success")).Text(),
		SuccessMsg:  "创建成功",
	})

	// Then：响应 500 且表述「结果不确定」，不断言未生效。
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "提交结果不确定") || !strings.Contains(rec.Body.String(), "可能已生效") {
		t.Fatalf("提交失败响应未表述结果不确定: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "提交事务失败") {
		t.Fatalf("提交失败响应仍断言「提交事务失败」: %s", rec.Body.String())
	}

	// Then：审计（失败行）同口径，且不留确定性断言。
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='创建失败' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("读取创建失败审计: %v", err)
	}
	if !strings.Contains(detail, "提交结果不确定") {
		t.Fatalf("审计 detail=%q, want 提交结果不确定口径", detail)
	}
	if strings.Contains(detail, "提交事务失败") {
		t.Fatalf("审计 detail=%q 仍断言「提交事务失败」", detail)
	}
}

func TestCommitFailureWordingHasSingleSource(t *testing.T) {
	// 事务收尾家族（finishTxApply、IP 名单热路径、规则五端点、DuplicateRule、
	// Caddy 配置逃生口）共用同一常量，禁止各写文案。
	// caddy.go 的响应与审计都已词条化（apimsg common.commitResultUncertain… /
	// audit.commitUncertain），源码不再引用常量——要求 0 处并靠下方词条相等性
	// 与 apimsg 词条守卫兜住单源。
	for file, wantUses := range map[string]int{"handlers.go": 1, "securityiplists.go": 1, "rules.go": 1, "caddy.go": 0} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		source := string(raw)
		for _, forbidden := range []string{`"提交事务失败"`, `"提交复制事务失败"`, `"提交 Caddy 配置失败"`} {
			if strings.Contains(source, forbidden) {
				t.Errorf("%s 仍存在 %s（提交错误结果不可判定，须用 commitUncertainLabel）", file, forbidden)
			}
		}
		// 审计侧文案已键化（方案 C 第 2/3 步）：审计用 audit.commitUncertain
		// 词条，其母本必须与本常量逐字相等（下方断言），因此本文件只需在响应
		// 面继续引用常量（>=1）；两处文案由词条相等性钉住，不再各写一份。
		if got := strings.Count(source, "commitUncertainLabel"); got < wantUses {
			t.Errorf("%s 使用 commitUncertainLabel %d 处, want >=%d（响应面必须引用单源常量）", file, got, wantUses)
		}
	}
	// 审计词条母本与响应常量逐字相等（单源跨栈约束）
	if got := i18n.T("audit.commitUncertain"); got != commitUncertainLabel {
		t.Errorf("audit.commitUncertain 母本=%q, 响应常量=%q（必须逐字相等）", got, commitUncertainLabel)
	}
	if strings.Contains(commitUncertainLabel, "失败") {
		t.Fatalf("commitUncertainLabel=%q 不得含「失败」断言", commitUncertainLabel)
	}
}
