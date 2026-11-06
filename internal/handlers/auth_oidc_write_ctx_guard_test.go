package handlers

// OIDC 配置写路径取消传播的源码契约守卫（技法同 autobackup_read_ctx_guard_test.go）：
// 保存（含 issuer 归一迁移事务）与删除清空两个写点此前用无 ctx 的
// Exec/Begin——客户端断开后写事务仍无主跑完，「取消即中止」退化为逐点
// 人工核对的不变量。这里按函数体扫描把 ctx-less 写访问钉成确定性失败。

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestOIDCConfigWritesConsumeRequestContext(t *testing.T) {
	ctxless := regexp.MustCompile(`db\.DB\.(Exec|Begin)\(`)
	tests := []struct {
		fn      string
		markers []string
	}{
		{
			// 单点写契约：语句消费调用方传入的请求 ctx（取消即中止、零副作用）。
			fn:      "func saveOIDCConfig(ctx context.Context, cfg OIDCConfig) error {",
			markers: []string{"ExecContext(ctx"},
		},
		{
			// 契约=「事务开启消费请求 ctx」（BeginTx 排锁/迁移读取阶段取消即
			// 中止）；配置写回与身份行迁移全有或全无，未提交事务由 committed
			// 标记 defer 回滚兜住。marker 只钉开启点。
			fn:      "func saveOIDCConfigWithIssuerMigration(ctx context.Context, cfg OIDCConfig, migrateFrom string) (oidcIssuerMigration, error) {",
			markers: []string{"BeginTx(ctx"},
		},
	}
	for _, test := range tests {
		source, err := os.ReadFile("auth_oidc.go")
		if err != nil {
			t.Fatal(err)
		}
		body, ok := handlerFunctionBody(string(source), test.fn)
		if !ok {
			t.Fatalf("auth_oidc.go 中未找到 %q（函数改名会让本守卫失效）", test.fn)
		}
		if hit := ctxless.FindString(body); hit != "" {
			t.Fatalf("%s 仍有无 ctx 的 %s（客户端断开后写事务继续跑；须改 *Context 系列）", test.fn, hit)
		}
		marked := false
		for _, marker := range test.markers {
			if strings.Contains(body, marker) {
				marked = true
				break
			}
		}
		if !marked {
			t.Fatalf("%s 未出现任何 ctx 透传形态（%v），扫描面可能失效", test.fn, test.markers)
		}
	}
}

// 两个 HTTP 写点必须把请求 ctx 传入保存入口（签名收敛后调用侧的 ctx 透传
// 同样钉死，防止后续改回 Background 假贯通）。
func TestOIDCConfigSaveHandlersPassRequestContext(t *testing.T) {
	source, err := os.ReadFile("auth_oidc.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"saveOIDCConfigWithIssuerMigration(c.Request.Context(), cfg, migrateFrom)",
		"saveOIDCConfig(c.Request.Context(), OIDCConfig{})",
	} {
		if !strings.Contains(string(source), want) {
			t.Fatalf("OIDC 配置写点必须把请求 ctx 传入保存入口，缺少: %q", want)
		}
	}
}
