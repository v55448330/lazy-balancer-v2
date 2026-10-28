package services

// 受信代理配置读取或解析失败采用降级渲染（可用性优先，不 fail-visible），但
//「面板显示启用、实际渲染分叉」必须可见：apply 成功后落审计行与
// caddy_apply_error 横幅，LastRenderDegradation 抑制 handlers 侧成功清除，
// 直至下次干净渲染恢复常规语义。

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestTrustedProxyDegradation_bannerRecordsOnApply：畸形网段 JSON + 启用态
// → 渲染成功（不 fail-visible）+ 横幅写入 + 降级状态置位；干净渲染成功应用
// 后状态归空（横幅清除恢复常规语义）。
func TestTrustedProxyDegradation_bannerRecordsOnApply(t *testing.T) {
	stubSecurityLibsAvailable(t)
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb-d3", false)
	if _, err := database.Exec(`UPDATE global_config SET trusted_proxy_enabled=1, trusted_proxy_ranges='{bad'`); err != nil {
		t.Fatalf("seed degraded trusted proxy: %v", err)
	}

	applied := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/config/" {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		// 拒未知顶层字段返 400。旧桩恒 200 掩盖了内部键 __lazy_balancer_*
		// 漏进载荷导致降级配置被硬拒的缺陷。
		body, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"read body failed"}`))
			return
		}
		var payload map[string]json.RawMessage
		if err := json.Unmarshal(body, &payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"json decode failed"}`))
			return
		}
		for key := range payload {
			switch key {
			case "admin", "apps", "logging", "storage": // Caddy Config 已知顶层字段
			default:
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(fmt.Sprintf(`{"error":"unknown field %q"}`, key)))
				return
			}
		}
		_, _ = w.Write([]byte(`{}`))
		applied <- r.URL.Path
	}))
	t.Cleanup(server.Close)
	service := NewCaddyService(server.URL)

	if err := service.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("degraded render must still apply (不 fail-visible): %v", err)
	}
	select {
	case <-applied:
	case <-time.After(5 * time.Second):
		t.Fatal("apply 请求未在 5s 内到达 Caddy（挂起或接线丢失）")
	}
	var banner string
	if err := database.QueryRow(`SELECT COALESCE(caddy_apply_error,'') FROM global_config WHERE id=1`).Scan(&banner); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if !strings.Contains(banner, "受信代理网段配置解析失败") || !strings.Contains(banner, "真实 IP 还原失效") {
		t.Fatalf("degraded apply must leave a visible banner, got %q", banner)
	}
	if got := LastRenderDegradation(); !strings.Contains(got, "受信代理") {
		t.Fatalf("LastRenderDegradation must carry the degradation, got %q", got)
	}

	// 干净渲染（停用受信代理）+ 强制应用 → 状态归空。
	if _, err := database.Exec(`UPDATE global_config SET trusted_proxy_enabled=0`); err != nil {
		t.Fatalf("disable trusted proxy: %v", err)
	}
	cfg := GenerateCaddyConfig()
	if err := service.ApplyConfigForce(cfg); err != nil {
		t.Fatalf("clean apply: %v", err)
	}
	if got := LastRenderDegradation(); got != "" {
		t.Fatalf("clean render+apply must clear degradation state, got %q", got)
	}
	// 横幅清除完全依赖强制重载成功分支（applyRenderDegradationState 空值早退，
	// 不清库）——必须显式断言，否则「横幅滞留」回归全绿。
	var bannerAfterClean string
	if err := database.QueryRow(`SELECT COALESCE(caddy_apply_error,'') FROM global_config WHERE id=1`).Scan(&bannerAfterClean); err != nil {
		t.Fatalf("read banner after clean apply: %v", err)
	}
	if bannerAfterClean != "" {
		t.Fatalf("干净强制应用必须清除 caddy_apply_error，实际残留 %q", bannerAfterClean)
	}
}

// TestTrustedProxyDegradation_shortCircuitStillRecordsBanner：启用特性但本轮
// 渲染降级、产物又与运行配置同字节（短路出口）时，降级横幅/状态同样必须落
// ——否则「保存成功、面板显示已启用、实际未生效且零横幅」可观测性缺陷复发。
func TestTrustedProxyDegradation_shortCircuitStillRecordsBanner(t *testing.T) {
	stubSecurityLibsAvailable(t)
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb-d3-short", false)
	setLastRenderDegradation("")
	t.Cleanup(func() { setLastRenderDegradation("") })

	var mu sync.Mutex
	running := []byte(`{}`)
	loads := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/config/" {
			mu.Lock()
			body := append([]byte(nil), running...)
			mu.Unlock()
			_, _ = w.Write(body)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			body, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			mu.Lock()
			running = body
			loads++
			mu.Unlock()
			_, _ = w.Write([]byte(`{}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)
	service := NewCaddyService(server.URL)

	// 先下发干净渲染（强制）建立「运行配置=当前字节」基线。
	if err := service.ApplyConfigForce(GenerateCaddyConfig()); err != nil {
		t.Fatalf("clean forced apply: %v", err)
	}
	mu.Lock()
	baselineLoads := loads
	mu.Unlock()

	// 启用受信代理 + 畸形网段 → 渲染降级（按未启用渲染）且与基线同字节。
	if _, err := database.Exec(`UPDATE global_config SET trusted_proxy_enabled=1, trusted_proxy_ranges='{bad'`); err != nil {
		t.Fatalf("seed degraded trusted proxy: %v", err)
	}
	_, loaded, err := service.ApplyConfigReportingForCommit(GenerateCaddyConfig())
	if err != nil {
		t.Fatalf("short-circuit apply: %v", err)
	}
	if loaded {
		t.Fatal("降级产物与运行配置同字节时必须走短路出口（不发生 /load）")
	}
	mu.Lock()
	gotLoads := loads
	mu.Unlock()
	if gotLoads != baselineLoads {
		t.Fatalf("/load 次数=%d, want %d（短路出口不得发请求）", gotLoads, baselineLoads)
	}
	if got := LastRenderDegradation(); !strings.Contains(got, "受信代理") {
		t.Fatalf("短路出口必须收敛降级状态，got %q", got)
	}
	var banner string
	if err := database.QueryRow(`SELECT COALESCE(caddy_apply_error,'') FROM global_config WHERE id=1`).Scan(&banner); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if !strings.Contains(banner, "受信代理") {
		t.Fatalf("短路出口必须持久化降级横幅，got %q", banner)
	}
}

// TestTrustedProxyDegradation_transactionalApplyKeepsBanner：事务内 apply
// （persist=false）在 commit 前不得清横幅——否则 commit 失败会留下「看起来
// 已恢复」的假象；清除只属于强制且持久化的成功路径。
func TestTrustedProxyDegradation_transactionalApplyKeepsBanner(t *testing.T) {
	stubSecurityLibsAvailable(t)
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb-d3-tx", false)
	if _, err := database.Exec(`UPDATE global_config SET trusted_proxy_enabled=0, caddy_apply_error='上一次应用失败'`); err != nil {
		t.Fatalf("seed banner: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)
	service := NewCaddyService(server.URL)

	cfg := GenerateCaddyConfig()
	service.mu.Lock()
	err := service.applyConfigLockedOpt(cfg, true, false)
	service.mu.Unlock()
	if err != nil {
		t.Fatalf("transactional apply: %v", err)
	}

	var banner string
	if err := database.QueryRow(`SELECT COALESCE(caddy_apply_error,'') FROM global_config WHERE id=1`).Scan(&banner); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if banner != "上一次应用失败" {
		t.Fatalf("事务内 apply 不得清除横幅，实际 %q", banner)
	}
}

// TestTrustedProxyDegradation_disabledIsNotDegraded：enabled=false 是「未启用」
// 非降级——零横幅零状态（防止把正常关闭误报成分叉）。
func TestTrustedProxyDegradation_disabledIsNotDegraded(t *testing.T) {
	stubSecurityLibsAvailable(t)
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb-d3-clean", false)
	if _, err := database.Exec(`UPDATE global_config SET trusted_proxy_enabled=0, trusted_proxy_ranges='{bad'`); err != nil {
		t.Fatalf("seed disabled trusted proxy: %v", err)
	}
	fields, degraded := trustedProxyServerFields(database)
	if fields != nil || degraded != "" {
		t.Fatalf("disabled state must be (nil, \"\"), got (%v, %q)", fields, degraded)
	}
}
