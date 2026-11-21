package handlers

// audit152 通知事件契约钉测（真实 SQLite + 直连 handler）：
//   - FE-152-01：规则伪行的 events=「已启用订阅子集」，组内全量选项仍在
//     event_titles 键集；无启用行=[]（不是 null）。
//   - SYSH-152-02：订阅矩阵三态（启用行/停用行/无行）与 min_level 口径。
//   - SYSH-152-01：GET /notification/daily/targets 非管理员按本人收窄（此前
//     拼了 WHERE 却没传参 → 恒 500）。
//   - SYSH-152-17：API Key 启停事件只在启用态真实翻转时发布。
//   - SYSH-152-15：写端点 → 通知事件的机械映射（源码级，抓「静默漏发」）。
//   - SYSH-152-10：备份单飞抢锁必须早于失败通知登记（结构守卫）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/notify"
)

// findRule 在 GET /notification/rules 响应里按 id 取规则。
func findRule(t *testing.T, data map[string]any, id string) map[string]any {
	t.Helper()
	rules, _ := data["rules"].([]any)
	for _, raw := range rules {
		rule, _ := raw.(map[string]any)
		if rule["id"] == id {
			return rule
		}
	}
	t.Fatalf("规则 %s 不在响应中: %v", id, data["rules"])
	return nil
}

// jsonStrings 把 []any 收成 []string（顺带区分 null 与 []：null 解码为 nil）。
func jsonStrings(t *testing.T, v any) []string {
	t.Helper()
	if v == nil {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		t.Fatalf("期望数组，得到 %T", v)
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		s, _ := item.(string)
		out = append(out, s)
	}
	return out
}

func TestGetNotificationRules_eventsAreEnabledSubscriptionSubset(t *testing.T) {
	h := newBackupTestHandlers(t)
	gid := certGroupID(t)

	// Given：证书组内 cert.failed=启用行、cert.issued=停用行、cert.expiry_warning=无行。
	if _, err := db.DB.Exec(`INSERT INTO notification_subscriptions (user_id, event_type, min_level, enabled) VALUES
		(7, 'cert.failed', 'warn', 1), (7, 'cert.issued', 'critical', 0)`); err != nil {
		t.Fatalf("seed subscriptions: %v", err)
	}
	r := newRulesTestRouter(h, 7, "user")

	// When：读规则聚合视图。
	status, out := doNotifyRequest(t, r, http.MethodGet, "/notification/rules", "")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, out)
	}
	data, _ := out["data"].(map[string]any)
	rule := findRule(t, data, gid)

	// Then：events=仅启用行（停用行与无行事件都不算订阅态）。
	events := jsonStrings(t, rule["events"])
	if len(events) != 1 || events[0] != "cert.failed" {
		t.Fatalf("events=%v, want [cert.failed]（停用行/无行事件不得计入订阅态）", events)
	}
	// 选项源仍是组内全量：event_titles 必须覆盖同组全部事件（含停用/未订阅）。
	titles, _ := rule["event_titles"].(map[string]any)
	for _, ev := range []string{"cert.failed", "cert.issued", "cert.expiry_warning"} {
		if _, ok := titles[ev]; !ok {
			t.Fatalf("event_titles 缺少组内事件 %s（选项源不得随订阅态收窄）: %v", ev, titles)
		}
	}

	// 无启用行（另一用户）：events 必须是 []（前端显示全不选），不是 null。
	r9 := newRulesTestRouter(h, 9, "user")
	status, out = doNotifyRequest(t, r9, http.MethodGet, "/notification/rules", "")
	if status != http.StatusOK {
		t.Fatalf("user9 status=%d body=%v", status, out)
	}
	data9, _ := out["data"].(map[string]any)
	rule9 := findRule(t, data9, gid)
	if raw, ok := rule9["events"]; !ok || raw == nil {
		t.Fatalf("无启用行时 events 必须为 [] 而非 null: %v", rule9["events"])
	}
	if got := jsonStrings(t, rule9["events"]); len(got) != 0 {
		t.Fatalf("无启用行时 events=%v, want 空数组", got)
	}
	if enabled, _ := rule9["enabled"].(bool); enabled {
		t.Fatalf("无启用行时规则 enabled 应为 false")
	}
}

func TestListNotificationSubscriptions_disabledRowIsUnsubscribed(t *testing.T) {
	h := newBackupTestHandlers(t)
	// Given：启用行（cert.failed）、停用行（auth.login_success，带旧级别）。
	if _, err := db.DB.Exec(`INSERT INTO notification_subscriptions (user_id, event_type, min_level, enabled) VALUES
		(7, 'cert.failed', 'warn', 1), (7, 'auth.login_success', 'critical', 0)`); err != nil {
		t.Fatalf("seed subscriptions: %v", err)
	}
	r := newNotificationTestRouter(h, 7, "user")

	status, out := doNotifyRequest(t, r, http.MethodGet, "/notification/subscriptions", "")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, out)
	}
	data, _ := out["data"].(map[string]any)

	// Then：启用行=subscribed/enabled 真，disabled 假，min_level 回显。
	on := notifySubRow(t, data, "cert.failed")
	if on["subscribed"] != true || on["enabled"] != true || on["disabled"] != false {
		t.Fatalf("启用行三态错误: %v", on)
	}
	if on["min_level"] != "warn" {
		t.Fatalf("启用行 min_level=%v, want warn", on["min_level"])
	}

	// 停用行：subscribed=false（此前恒 true——停用行被当成已订阅），
	// disabled=true 披露 opt-out，min_level 不误导性回显。
	off := notifySubRow(t, data, "auth.login_success")
	if off["subscribed"] != false || off["enabled"] != false || off["disabled"] != true {
		t.Fatalf("停用行三态错误: %v", off)
	}
	if off["min_level"] != "" {
		t.Fatalf("停用行 min_level=%v, want 空（停用态级别对投递无意义）", off["min_level"])
	}

	// 无行：三态全假（默认态按 default_subscribed 兜底）。
	none := notifySubRow(t, data, "cert.expiry_warning")
	if none["subscribed"] != false || none["enabled"] != false || none["disabled"] != false {
		t.Fatalf("无行三态错误: %v", none)
	}
}

func TestGetDailyTargets_nonAdminNarrowsToSelf(t *testing.T) {
	h := newBackupTestHandlers(t)
	// Given：两个启用日报的用户（id 1/2）+ 各自启用通道。
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO users (id, username, password_hash, role) VALUES
		(1, 'alice', 'x', 'user'), (2, 'bob', 'x', 'user')`); err != nil {
		t.Fatalf("seed users: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO notification_daily (user_id, config) VALUES
		(1, '{"enabled":true}'), (2, '{"enabled":true}')`); err != nil {
		t.Fatalf("seed daily: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO notification_channels (user_id, type, name, target, style_config, enabled, created_at, updated_at) VALUES
		(1, 'webhook', 'alice-hook', '{"url":"https://example.com/a"}', '{}', 1, datetime('now'), datetime('now')),
		(2, 'webhook', 'bob-hook', '{"url":"https://example.com/b"}', '{}', 1, datetime('now'), datetime('now'))`); err != nil {
		t.Fatalf("seed channels: %v", err)
	}
	router := func(uid int64, role string) *gin.Engine {
		gin.SetMode(gin.TestMode)
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Set("user_id", uid)
			c.Set("role", role)
			c.Set("username", "tester")
			c.Next()
		})
		r.GET("/notification/daily/targets", h.GetDailyTargets)
		return r
	}
	names := func(r *gin.Engine) []string {
		t.Helper()
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/notification/daily/targets", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s（非管理员查询曾因 Query 缺参恒 500）", rec.Code, rec.Body.String())
		}
		var out struct {
			Data struct {
				Targets []struct {
					Username string `json:"username"`
				} `json:"targets"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v body=%s", err, rec.Body.String())
		}
		got := make([]string, 0, len(out.Data.Targets))
		for _, tg := range out.Data.Targets {
			got = append(got, tg.Username)
		}
		return got
	}

	// 非管理员：只看自己。
	if got := names(router(1, "user")); len(got) != 1 || got[0] != "alice" {
		t.Fatalf("非管理员 targets=%v, want [alice]", got)
	}
	// 管理员：全量。
	if got := names(router(1, "admin")); len(got) != 2 {
		t.Fatalf("管理员 targets=%v, want 2 用户", got)
	}
}

func TestUpdateAPIKeyStatus_publishesOnlyOnRealToggle(t *testing.T) {
	h := newBackupTestHandlers(t)
	// Given：只读 Key（启停不构成特权变更，测试不触发 step-up）。
	if _, err := db.DB.Exec(`INSERT INTO users (id, username, password_hash, role) VALUES (1, 'admin', 'x', 'admin')`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	res, err := db.DB.Exec(`INSERT INTO api_keys (name, key_hash, key_prefix, created_by, is_enabled, read_only, api_read_only, mcp_read_only)
		VALUES ('ops-key', 'hash', 'lb_prefix', 1, 1, 1, 1, 1)`)
	if err != nil {
		t.Fatalf("seed api key: %v", err)
	}
	id, _ := res.LastInsertId()

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", int64(1))
		c.Set("role", "admin")
		c.Set("username", "admin")
		c.Next()
	})
	r.PATCH("/api-keys/:id/status", h.UpdateAPIKeyStatus)

	patch := func(body string) int64 {
		t.Helper()
		before := notify.DroppedCount()
		req := httptest.NewRequest(http.MethodPatch, "/api-keys/"+itoa64(id)+"/status", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		return notify.DroppedCount() - before
	}

	// 无变化提交（is_enabled=true 而当前已启用）：不得发启停事件。
	if delta := patch(`{"is_enabled":true}`); delta != 0 {
		t.Fatalf("无变化提交发布了 %d 条事件, want 0（假「又启用了一次」通知）", delta)
	}
	// 真实禁用：恰好一条启停事件。
	if delta := patch(`{"is_enabled":false}`); delta != 1 {
		t.Fatalf("真实禁用发布 %d 条事件, want 1", delta)
	}
}

// srcOf 读 handler 源文件（包内工作目录=internal/handlers）。
func srcOf(t *testing.T, file string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(".", file))
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	return string(b)
}

// bodyOf 用既有 handlerFuncBody（截到下一个顶格 func）取指定函数体，
// 空结果即锚点漂移——响亮失败，不让「找不到=不检查」假绿。
func bodyOf(t *testing.T, src, anchor string) string {
	t.Helper()
	body := handlerFuncBody(src, anchor)
	if strings.TrimSpace(body) == "" {
		t.Fatalf("源码锚点未命中: %q（handler 改名/签名变化时须同步本表）", anchor)
	}
	return body
}

// TestWriteEndpointsPublishNotificationEvents 主写端点 → 事件常量的机械映射。
// 源码级守卫：新增/迁移 handler 时漏发通知（或事件被删）立即红，不依赖人工
// 逐条 review；handler 内必须出现对应 notify.EvtXxx 引用。
func TestWriteEndpointsPublishNotificationEvents(t *testing.T) {
	cases := []struct{ file, anchor, evt string }{
		// 任务手动操作（触发/启停/取消/控制）
		{"taskmonitor.go", "func (h *Handlers) TriggerSystemTask(", "EvtTaskManualAction"},
		{"taskmonitor.go", "func (h *Handlers) ToggleSystemTask(", "EvtTaskManualAction"},
		{"taskmonitor.go", "func (h *Handlers) CancelSystemTask(", "EvtTaskManualAction"},
		{"taskmonitor.go", "func (h *Handlers) ControlSystemTask(", "EvtTaskManualAction"},
		// Caddy 启停（成功与失败都要发）
		{"caddy.go", "func (h *Handlers) StartCaddy(", "EvtCaddyLifecycle"},
		{"caddy.go", "func (h *Handlers) StopCaddy(", "EvtCaddyLifecycle"},
		{"caddy.go", "func (h *Handlers) RestartCaddy(", "EvtCaddyLifecycle"},
		// 集群节点管理（令牌/站点/访问地址/证书指纹）
		{"cluster_registration.go", "func (h *Handlers) GenerateClusterRegisterToken(", "EvtClusterNodeSettings"},
		{"cluster_registration.go", "func (h *Handlers) UpdateClusterNodeSiteCoordinates(", "EvtClusterNodeSettings"},
		{"cluster_registration.go", "func (h *Handlers) UpdateClusterNodeAccessURL(", "EvtClusterNodeSettings"},
		{"cluster_sync.go", "func (h *Handlers) ForgetClusterPins(", "EvtClusterNodeSettings"},
		{"cluster_sync.go", "func (h *Handlers) ForgetClusterNodePin(", "EvtClusterNodeSettings"},
		{"cluster_ticket.go", "func (h *Handlers) GenerateClusterLoginTicket(", "EvtClusterLoginTicket"},
		// 通知通道 / 规则
		{"notification_channels.go", "func (h *Handlers) CreateNotificationChannel(", "EvtNotifyChannelChanged"},
		{"notification_channels.go", "func (h *Handlers) UpdateNotificationChannel(", "EvtNotifyChannelChanged"},
		{"notification_channels.go", "func (h *Handlers) DeleteNotificationChannel(", "EvtNotifyChannelChanged"},
		{"notification_rules.go", "func (h *Handlers) UpdateNotificationRule(", "EvtNotifyRuleChanged"},
		// 备份 / API Key / MFA / OIDC / CA 提供商
		{"autobackup.go", "func (h *Handlers) RunAutoBackupOnce(", "EvtBackupFailed"},
		{"apikeys.go", "func updateAPIKeyStatus(", "EvtAPIKeyToggled"},
		{"mfa.go", "func (h *Handlers) MFAResetByAdmin(", "EvtMFAChanged"},
		{"auth_oidc.go", "func (h *Handlers) OIDCSettingsDelete(", "EvtOIDCChanged"},
		{"caproviders.go", "func (h *Handlers) UpdateCAProvider(", "EvtCAProviderChanged"},
	}
	cache := map[string]string{}
	for _, tc := range cases {
		src, ok := cache[tc.file]
		if !ok {
			src = srcOf(t, tc.file)
			cache[tc.file] = src
		}
		body := bodyOf(t, src, tc.anchor)
		if !strings.Contains(body, "notify."+tc.evt) {
			t.Errorf("%s:%s 未发布 notify.%s——该写操作会静默漏发通知", tc.file, tc.anchor, tc.evt)
		}
	}
}

// TestNotificationEventParamAndBranchGuards 事件参数与分支级守卫：
//   - Caddy 失败分支也发事件（结果=失败）；
//   - 任务启停/控制双分支均发（启停恢复分支曾漏发）；
//   - API Key 启停事件受「真实翻转」条件约束；
//   - 备份单飞抢锁早于失败通知登记（争用≠备份失败）。
func TestNotificationEventParamAndBranchGuards(t *testing.T) {
	count := func(s, sub string) int { return strings.Count(s, sub) }
	idx := func(t *testing.T, body, sub, where string) int {
		t.Helper()
		i := strings.Index(body, sub)
		if i < 0 {
			t.Fatalf("%s 缺少 %q", where, sub)
		}
		return i
	}

	caddy := srcOf(t, "caddy.go")
	start := bodyOf(t, caddy, "func (h *Handlers) StartCaddy(")
	if count(start, "notify.EvtCaddyLifecycle") < 2 || !strings.Contains(start, `"3": "失败"`) {
		t.Fatalf("StartCaddy 必须成功+失败双分支发事件（失败结果=失败）")
	}
	restart := bodyOf(t, caddy, "func (h *Handlers) RestartCaddy(")
	if count(restart, "notify.EvtCaddyLifecycle") < 3 || !strings.Contains(restart, `"3": "失败"`) {
		t.Fatalf("RestartCaddy 三条失败路径与成功路径都要发事件")
	}
	stop := bodyOf(t, caddy, "func (h *Handlers) StopCaddy(")
	if count(stop, "notify.EvtCaddyLifecycle") < 2 || !strings.Contains(stop, `"3": "失败"`) {
		t.Fatalf("StopCaddy 失败分支也要发事件")
	}

	tm := srcOf(t, "taskmonitor.go")
	toggle := bodyOf(t, tm, "func (h *Handlers) ToggleSystemTask(")
	if count(toggle, "notify.EvtTaskManualAction") < 2 {
		t.Fatalf("ToggleSystemTask 恢复/停止两分支都要发事件（恢复分支曾漏发）: %d 处", count(toggle, "notify.EvtTaskManualAction"))
	}
	control := bodyOf(t, tm, "func (h *Handlers) ControlSystemTask(")
	if count(control, "notify.EvtTaskManualAction") < 3 {
		t.Fatalf("ControlSystemTask start/stop/restart 三分支都要发事件: %d 处", count(control, "notify.EvtTaskManualAction"))
	}
	// 任务事件第二参=任务可读名（m.Name），不得回退裸 #id。
	if strings.Contains(toggle, `Sprintf("#%s"`) || strings.Contains(control, `Sprintf("#%s"`) {
		t.Fatalf("任务事件参数不得用裸 #id（应使用 m.Name 可读名）")
	}

	keys := srcOf(t, "apikeys.go")
	upd := bodyOf(t, keys, "func updateAPIKeyStatus(")
	condIdx := idx(t, upd, "*req.IsEnabled != (beforeEnabled == 1)", "apikeys.go:updateAPIKeyStatus")
	pubIdx := idx(t, upd, "notify.EvtAPIKeyToggled", "apikeys.go:updateAPIKeyStatus")
	if condIdx > pubIdx {
		t.Fatalf("API Key 启停事件必须受「真实翻转」条件约束（条件出现在发布之后）")
	}

	backup := srcOf(t, "autobackup.go")
	run := bodyOf(t, backup, "func (h *Handlers) RunAutoBackupOnce(")
	lockIdx := idx(t, run, "autoBackupRunMu.TryLock()", "autobackup.go:RunAutoBackupOnce")
	failIdx := idx(t, run, "notify.EvtBackupFailed", "autobackup.go:RunAutoBackupOnce")
	if lockIdx > failIdx {
		t.Fatalf("TryLock 必须早于 backup.failed 发布登记——争用是「未执行」不是「备份失败」")
	}
}
