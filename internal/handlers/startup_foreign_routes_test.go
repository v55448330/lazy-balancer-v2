package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// C 加固（2026-09-25 漂移根因裁定）：外来实例经默认 admin 地址（localhost:2019,
// host 网络共享）把自身配置 /load 进生产 Caddy 的两次实证事故（09-18 多余路由、
// 09-24 清空路由）。F49-15 守卫只覆盖「零用户空库」启动；本组测试钉住扩展守卫——
// 启动应用前发现运行配置含非本库规则路由时记响亮「启动警告」审计（双方实例下
// 次启动都会留痕），应用照常执行（生产恢复路径不可阻断）。

// foreignRoutesFakeAdmin 返回按 runningIDs 构造 /config/ 响应、/load 放行的假
// admin，并记录 /load 命中次数。
func foreignRoutesFakeAdmin(t *testing.T, runningIDs []string) (*httptest.Server, *int) {
	t.Helper()
	var mu sync.Mutex
	loadCount := 0
	var sb strings.Builder
	sb.WriteString(`{"apps":{"http":{"servers":{"web":{"routes":[`)
	for i, id := range runningIDs {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"@id":%q,"handle":[{"handler":"subroute"}]}`, id)
	}
	sb.WriteString(`]}}}}}}`)
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			mu.Lock()
			loadCount++
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sb.String()))
	}))
	t.Cleanup(fake.Close)
	return fake, &loadCount
}

func seedStartupRule(t *testing.T, caddyID string) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, domain, listen_port, strategy, enabled) VALUES (?, '启动规则', 'http', 'startup.example.com', 14443, 'round_robin', 1)`, caddyID); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
}

func countStartupForeignWarnings(t *testing.T) int {
	t.Helper()
	var n int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='启动警告' AND detail LIKE '%非本库规则路由%'`).Scan(&n); err != nil {
		t.Fatalf("count startup warnings: %v", err)
	}
	return n
}

func TestApplyConfigOnStartup_warnsOnForeignRuleRoutes(t *testing.T) {
	// Given 本库一条启用规则 lb_own123；运行配置含本规则路由+其子路由+外来路由
	h := newBackupTestHandlers(t)
	seedStartupRule(t, "lb_own123")
	fake, loadCount := foreignRoutesFakeAdmin(t, []string{"lb_own123", "lb_own123_path_0", "lb_foreign999"})
	h.cfg = &config.Config{CaddyAdminURL: fake.URL}
	h.caddyService = services.NewCaddyService(fake.URL)

	// When 启动应用
	if err := h.ApplyConfigOnStartup(); err != nil {
		t.Fatalf("ApplyConfigOnStartup: %v", err)
	}

	// Then ①记一条「非本库规则路由」启动警告且点名 lb_foreign999
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='启动警告' AND detail LIKE '%非本库规则路由%' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("启动警告未记录: %v", err)
	}
	if !strings.Contains(detail, "lb_foreign999") {
		t.Fatalf("警告未点名外来路由: %s", detail)
	}
	// ②子路由（lb_own123_path_0）归主规则认领，不得误报为外来
	if strings.Contains(detail, "lb_own123_path_0") {
		t.Fatalf("子路由被误报为外来: %s", detail)
	}
	// ③应用照常执行（恢复路径不可阻断）
	if *loadCount == 0 {
		t.Fatal("启动应用未执行 /load——外来路由告警不得阻断恢复性收敛")
	}
}

func TestApplyConfigOnStartup_noWarningWhenRoutesAllOwn(t *testing.T) {
	// Given 本库一条启用规则；运行配置只有本规则路由与子路由
	h := newBackupTestHandlers(t)
	seedStartupRule(t, "lb_own123")
	fake, _ := foreignRoutesFakeAdmin(t, []string{"lb_own123", "lb_own123_redirect"})
	h.cfg = &config.Config{CaddyAdminURL: fake.URL}
	h.caddyService = services.NewCaddyService(fake.URL)

	// When
	if err := h.ApplyConfigOnStartup(); err != nil {
		t.Fatalf("ApplyConfigOnStartup: %v", err)
	}

	// Then 零外来路由警告
	if n := countStartupForeignWarnings(t); n != 0 {
		t.Fatalf("全部自有路由不应告警,实际 %d 条", n)
	}
}
