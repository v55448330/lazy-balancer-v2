package handlers

// /load 传输失败的 *url.Error 文本恒含
// 「Post "http://<admin>/load"」与「dial tcp <admin>」——横幅（caddy_apply_error）
// 与操作审计是全员可见面（含只读 API Key），端点地址只能留在服务端日志。
// 此前只有 writeApplyFailureBanner 做了端点剥离，退化提交横幅
// （recordCaddyApplySavedNotLive）与各区失败审计 detail 直接落原文。

import (
	"errors"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

const caddyAdminTransportErrorText = `Post "http://10.20.30.40:2019/load": dial tcp 10.20.30.40:2019: connect: connection refused`

func assertNoCaddyAdminEndpoint(t *testing.T, surface, text string) {
	t.Helper()
	if strings.Contains(text, "10.20.30.40") || strings.Contains(text, "2019") {
		t.Fatalf("%s=%q, want 不含 Caddy admin 端点地址/端口", surface, text)
	}
	if !strings.Contains(text, "<Caddy admin 端点>") {
		t.Fatalf("%s=%q, want 地址替换为占位短语（保留「发生了什么」）", surface, text)
	}
	if !strings.Contains(text, "connection refused") {
		t.Fatalf("%s=%q, want 保留底层错误原因", surface, text)
	}
}

// 退化提交（DB 已提交、运行配置可能未生效）横幅同样全员可见。
func TestRecordCaddyApplySavedNotLive_redactsAdminEndpoint(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	handler := &Handlers{}

	handler.recordCaddyApplySavedNotLive(errors.New(caddyAdminTransportErrorText))

	assertNoCaddyAdminEndpoint(t, "退化提交横幅", bannerText(t))
}

// 规则域 apply 失败审计（respondRuleApplyError）与运行配置快照失败审计
// （respondRuleSnapshotError）的 detail 同样是全员可见面。
func TestRuleApplyFailureAudits_redactAdminEndpoint(t *testing.T) {
	handler := newBackupTestHandlers(t)
	transportErr := errors.New(caddyAdminTransportErrorText)

	readLatestRuleFailureDetail := func(t *testing.T) string {
		t.Helper()
		var detail string
		if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新失败' AND resource='负载规则' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
			t.Fatalf("读取规则失败审计: %v", err)
		}
		return detail
	}

	// Given/When：apply 失败收尾（横幅 + 操作审计）
	c, _ := newApplyTestContext()
	handler.respondRuleApplyError(c, transportErr, nil, nil, "更新")

	// Then
	assertNoCaddyAdminEndpoint(t, "规则 apply 失败审计 detail", readLatestRuleFailureDetail(t))

	// Given/When：运行配置快照失败收尾（同一可见面，另一写点）
	c, _ = newApplyTestContext()
	handler.respondRuleSnapshotError(c, "更新", transportErr)

	// Then
	assertNoCaddyAdminEndpoint(t, "规则快照失败审计 detail", readLatestRuleFailureDetail(t))
}
