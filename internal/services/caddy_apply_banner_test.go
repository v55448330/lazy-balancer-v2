package services

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 后台强制重载成功必须清除陈旧的「配置应用失败」横幅：此前只有 handler 写路径
// 经 recordCaddyApplyResult 清，后台数据类重载（证书/CRS/IP 库/威胁库/自动封禁）
// 成功后面板横幅仍挂在一次早已被后续配置覆盖的失败上。
func TestForcedReloadClearsStaleApplyBanner(t *testing.T) {
	// 进程级渲染降级状态隔离：本用例依赖「无降级」，不得受执行顺序影响。
	setLastRenderDegradation("")
	t.Cleanup(func() { setLastRenderDegradation("") })
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET caddy_apply_error='上一次写路径失败：旧横幅' WHERE id=1`); err != nil {
		t.Fatalf("seed stale banner: %v", err)
	}

	loads := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			loads++
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	service := NewCaddyService(server.URL)

	if err := service.GenerateAndApplyConfigForceInLock(); err != nil {
		t.Fatalf("强制重载失败: %v", err)
	}
	if loads != 1 {
		t.Fatalf("/load 次数=%d, want 1", loads)
	}
	var banner string
	if err := database.QueryRow(`SELECT COALESCE(caddy_apply_error,'') FROM global_config WHERE id=1`).Scan(&banner); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if banner != "" {
		t.Fatalf("后台强制重载成功后陈旧横幅未清除: %q", banner)
	}
	// 后台失败面：先清空，再登记一次失败确认横幅随登记出现（恒真的「清空后
	// 为空」断言无法拦住登记逻辑回归），最后清除恢复空态。
	resetBackgroundApplyFailures(t)
	RecordBackgroundApplyFailure(BackgroundApplyCRS, errors.New("crs reload failed"))
	if got := BackgroundApplyFailureBanner(); !strings.Contains(got, "crs reload failed") {
		t.Fatalf("后台失败横幅未随登记出现: %q", got)
	}
	ClearBackgroundApplyFailure(BackgroundApplyCRS)
	if got := BackgroundApplyFailureBanner(); got != "" {
		t.Fatalf("后台失败横幅=%q, want 空", got)
	}
}

// 本轮渲染自身发生降级时，强制重载成功只能保留降级横幅，不能被陈旧横幅清理门
// 随后覆盖为空；否则面板会隐藏「配置已应用但部分安全能力未生效」的事实。
func TestForcedReloadPreservesCurrentDegradationBanner(t *testing.T) {
	setLastRenderDegradation("")
	t.Cleanup(func() { setLastRenderDegradation("") })
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET caddy_apply_error='上一次写路径失败：旧横幅' WHERE id=1`); err != nil {
		t.Fatalf("seed stale banner: %v", err)
	}

	loads := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			loads++
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	service := NewCaddyService(server.URL)
	const degraded = "受信代理设置读取失败：按未启用渲染"

	if err := service.applyConfigLockedOpt(map[string]interface{}{caddyConfigDegradationKey: degraded}, true, true); err != nil {
		t.Fatalf("强制重载失败: %v", err)
	}
	if loads != 1 {
		t.Fatalf("/load 次数=%d, want 1", loads)
	}
	var banner string
	if err := database.QueryRow(`SELECT COALESCE(caddy_apply_error,'') FROM global_config WHERE id=1`).Scan(&banner); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if !strings.Contains(banner, "受信代理") {
		t.Fatalf("降级横幅被强制重载成功清除: %q", banner)
	}
}
