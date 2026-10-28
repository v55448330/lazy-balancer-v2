package handlers

// 失败横幅不得对运行配置做与事实相反的确定断言：
//   - 恢复失败 ⇒ 「状态未知」，不得与「旧配置已保留」并列；
//   - 退化提交（DB 已提交、/load 传输失败）⇒ 「可能未生效」，不得宣称「未生效」
//     （请求超时/响应丢失可能发生在 Caddy 已 provision 之后）。

import (
	"errors"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func bannerText(t *testing.T) string {
	t.Helper()
	var text string
	if err := db.DB.QueryRow(`SELECT COALESCE(caddy_apply_error,'') FROM global_config WHERE id=1`).Scan(&text); err != nil {
		t.Fatalf("read caddy_apply_error: %v", err)
	}
	return text
}

func TestCaddyApplyFailureBanner_twoStateWording(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	handler := &Handlers{}

	// 恢复成功：断言「旧配置已保留」是事实。
	handler.recordCaddyApplyFailure(errors.New("admin 4xx"), nil)
	if got := bannerText(t); !strings.Contains(got, caddyApplyOldConfigKeptLabel) || strings.Contains(got, "状态未知") {
		t.Fatalf("恢复成功横幅=%q, want 含「旧配置已保留」且不含「状态未知」", got)
	}

	// 恢复失败：双失败形态，运行配置可能停留候选态。
	handler.recordCaddyApplyFailure(errors.New("admin 4xx"), errors.New("恢复 /load 失败"))
	if got := bannerText(t); !strings.Contains(got, caddyApplyRestoreFailedLabel) || strings.Contains(got, caddyApplyOldConfigKeptLabel) {
		t.Fatalf("恢复失败横幅=%q, want 含「状态未知」且不含「旧配置已保留」", got)
	}

	// 退化提交：不确定口径。
	handler.recordCaddyApplySavedNotLive(errors.New("请求超时"))
	if got := bannerText(t); !strings.Contains(got, "可能未生效") || !strings.Contains(got, "请核对后重试") {
		t.Fatalf("退化提交横幅=%q, want 「可能未生效，请核对后重试」", got)
	}
	if got := bannerText(t); strings.Contains(got, "运行配置未生效）：") {
		t.Fatalf("退化提交横幅=%q, want 不得断言「运行配置未生效」", got)
	}

	// 默认失败写点（无恢复上下文）同样走两态函数，值为「旧配置已保留」。
	handler.recordCaddyApplyResult(errors.New("保存前校验失败"))
	if got := bannerText(t); !strings.Contains(got, caddyApplyOldConfigKeptLabel) {
		t.Fatalf("默认失败横幅=%q, want 含「旧配置已保留」", got)
	}
}

// 横幅（全员可见）不得内嵌 Caddy admin 端点地址：/load 传输失败的错误文本恒含
// 「Post "http://<admin>/load"」，自定义 caddy_admin_url 时等于把内部控制面
// 地址+端口披露给任意登录用户（含只读 API Key）。服务端日志保留原文。
func TestCaddyApplyFailureBanner_redactsAdminEndpoint(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	handler := &Handlers{}

	transportErr := errors.New(`failed to apply config: Post "http://10.20.30.40:2019/load": dial tcp 10.20.30.40:2019: connect: connection refused`)
	handler.recordCaddyApplyFailure(transportErr, nil)

	got := bannerText(t)
	if strings.Contains(got, "10.20.30.40") || strings.Contains(got, "2019") {
		t.Fatalf("横幅=%q, want 不含 admin 端点地址/端口", got)
	}
	if !strings.Contains(got, "<Caddy admin 端点>") {
		t.Fatalf("横幅=%q, want 保留「发生了什么」（地址替换为占位短语）", got)
	}
	// 正向控制：占位替换不得吃掉其余诊断信息（连接失败原因必须保留）。
	if !strings.Contains(got, "connection refused") {
		t.Fatalf("横幅=%q, want 保留底层错误原因", got)
	}
	// 纯文本错误不得被改写。
	if redacted := services.RedactCaddyAdminEndpoint("Caddy 配置应用失败（旧配置已保留）：配置被拒绝"); redacted != "Caddy 配置应用失败（旧配置已保留）：配置被拒绝" {
		t.Fatalf("无地址文本不得被改写: %q", redacted)
	}
}

func TestCaddyApplyFailureLabel_shapes(t *testing.T) {
	if got := caddyApplyFailureLabel(nil); got != caddyApplyOldConfigKeptLabel {
		t.Fatalf("label(nil)=%q", got)
	}
	if got := caddyApplyFailureLabel(errors.New("x")); got != caddyApplyRestoreFailedLabel {
		t.Fatalf("label(err)=%q", got)
	}
}
