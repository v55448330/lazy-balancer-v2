package handlers

// 通知投递/规则/通道语义回归（2026-11-19 通知重构）：
//   - 投递 DTO is_test + status=partial 过滤白名单
//   - 重发 failed_only body 解析（partial→retry_channel_ids 仅失败通道）+
//     审计详情=投递标题+通道名（禁「投递 #id」）
//   - 规则修改/规则测试/通道测试 Explicit 审计（名称+结果，单条不双记）
//   - 概览/趋势成功率口径接受 partial（sent+partial）

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func newNotificationSemanticsRouter(h *Handlers, uid int64, role string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", uid)
		c.Set("role", role)
		c.Set("username", "tester")
		c.Next()
	})
	r.GET("/notification/deliveries", h.ListNotificationDeliveries)
	r.POST("/notification/deliveries/:id/resend", h.ResendNotificationDelivery)
	r.POST("/notification/rules/:id", h.UpdateNotificationRule)
	r.POST("/notification/rules/:id/test", h.TestNotificationRule)
	r.POST("/notification/channels/:id/test", h.TestNotificationChannel)
	r.GET("/notification/admin/overview", h.GetAdminNotificationOverview)
	r.GET("/notification/delivery-trend", h.GetDeliveryTrend)
	return r
}

// seedSemanticsDelivery 落一行指定状态/测试标记的投递（标题固定可断言）。
func seedSemanticsDelivery(t *testing.T, userID int64, status string, isTest int) int64 {
	t.Helper()
	res, err := db.DB.Exec(`INSERT INTO notification_deliveries
		(user_id, event_type, level, title, body, status, attempts, error, is_test, created_at)
		VALUES (?,?,?,?,?,?,0,'',?,datetime('now'))`,
		userID, "cert.failed", "critical", "证书签发失败", "正文", status, isTest)
	if err != nil {
		t.Fatalf("seed delivery: %v", err)
	}
	id, _ := res.LastInsertId()
	return id
}

func seedChannelResult(t *testing.T, deliveryID, channelID int64, name, typ, status string) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO notification_delivery_channels
		(delivery_id, user_id, channel_id, channel_name, channel_type, event_type, status, created_at)
		VALUES (?,?,?,?,?,?,?,datetime('now'))`,
		deliveryID, 7, channelID, name, typ, "cert.failed", status); err != nil {
		t.Fatalf("seed channel result: %v", err)
	}
}

func auditRows(t *testing.T, action, resource string) []string {
	t.Helper()
	rows, err := db.AuditDB.Query(`SELECT detail FROM audit_log WHERE action=? AND resource=? ORDER BY id`, action, resource)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			t.Fatal(err)
		}
		out = append(out, d)
	}
	return out
}

func TestNotificationDeliveries_isTestFieldAndPartialFilter(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedSemanticsDelivery(t, 7, "partial", 0)
	seedSemanticsDelivery(t, 7, "sent", 1)
	r := newNotificationSemanticsRouter(h, 7, "user")

	status, out := doNotifyRequest(t, r, http.MethodGet, "/notification/deliveries?status=partial", "")
	if status != http.StatusOK {
		t.Fatalf("status=partial 过滤 status=%d body=%v", status, out)
	}
	deliveries, _ := out["data"].(map[string]any)["deliveries"].([]any)
	if len(deliveries) != 1 {
		t.Fatalf("partial 行数=%d, want 1", len(deliveries))
	}
	row := deliveries[0].(map[string]any)
	if row["is_test"] != false {
		t.Fatalf("partial 行 is_test=%v, want false", row["is_test"])
	}

	_, out = doNotifyRequest(t, r, http.MethodGet, "/notification/deliveries?status=sent", "")
	deliveries, _ = out["data"].(map[string]any)["deliveries"].([]any)
	if len(deliveries) != 1 || deliveries[0].(map[string]any)["is_test"] != true {
		t.Fatalf("sent 测试行 is_test 标记缺失: %v", deliveries)
	}

	// 非法状态仍 400（白名单扩容不放松校验）
	status, out = doNotifyRequest(t, r, http.MethodGet, "/notification/deliveries?status=bogus", "")
	if status != http.StatusBadRequest || out["message_key"] != "k_0d569dd0" {
		t.Fatalf("非法 status status=%d body=%v", status, out)
	}
}

func TestResendNotificationDelivery_failedOnlyAndAuditDetail(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO notification_channels (id, user_id, type, name, target, enabled) VALUES
		(101, 7, 'webhook', '运维群', '{"url":"https://ok.example.com"}', 1),
		(102, 7, 'email', '邮件告警', '{"email":"a@b.c"}', 1)`); err != nil {
		t.Fatal(err)
	}
	id := seedSemanticsDelivery(t, 7, "partial", 0)
	seedChannelResult(t, id, 101, "运维群", "webhook", "sent")
	seedChannelResult(t, id, 102, "邮件告警", "email", "failed")
	r := newNotificationSemanticsRouter(h, 7, "user")

	// failed_only=true 且 partial → 仅失败通道入 retry_channel_ids
	status, out := doNotifyRequest(t, r, http.MethodPost, fmt.Sprintf("/notification/deliveries/%d/resend", id), `{"failed_only":true}`)
	if status != http.StatusOK || out["message_key"] != "k_07b47533" {
		t.Fatalf("failed_only resend status=%d body=%v", status, out)
	}
	var retryIDs, dbStatus string
	if err := db.DB.QueryRow(`SELECT retry_channel_ids, status FROM notification_deliveries WHERE id=?`, id).Scan(&retryIDs, &dbStatus); err != nil {
		t.Fatal(err)
	}
	if retryIDs != "[102]" || dbStatus != "pending" {
		t.Fatalf("retry_channel_ids=%q status=%q, want [102]/pending", retryIDs, dbStatus)
	}
	details := auditRows(t, "重发", "通知投递")
	if len(details) != 1 {
		t.Fatalf("重发审计行数=%d, want 1", len(details))
	}
	d := details[0]
	if !strings.Contains(d, "证书签发失败") || !strings.Contains(d, "邮件告警") {
		t.Fatalf("审计详情缺标题/失败通道名: %q", d)
	}
	if strings.Contains(d, "运维群") {
		t.Fatalf("failed_only 审计不应含成功通道: %q", d)
	}
	if strings.Contains(d, "#") || strings.Contains(d, "https://") {
		t.Fatalf("审计详情禁 ID/URL 形态: %q", d)
	}

	// 空 body（旧客户端形态）=全量重发，清过滤；审计含全部通道名
	id2 := seedSemanticsDelivery(t, 7, "partial", 0)
	seedChannelResult(t, id2, 101, "运维群", "webhook", "sent")
	seedChannelResult(t, id2, 102, "邮件告警", "email", "failed")
	status, _ = doNotifyRequest(t, r, http.MethodPost, fmt.Sprintf("/notification/deliveries/%d/resend", id2), "")
	if status != http.StatusOK {
		t.Fatalf("空 body resend status=%d, want 200", status)
	}
	_ = db.DB.QueryRow(`SELECT retry_channel_ids FROM notification_deliveries WHERE id=?`, id2).Scan(&retryIDs)
	if retryIDs != "" {
		t.Fatalf("全量重发 retry_channel_ids=%q, want 空", retryIDs)
	}
	details = auditRows(t, "重发", "通知投递")
	if len(details) != 2 || !strings.Contains(details[1], "运维群") || !strings.Contains(details[1], "邮件告警") {
		t.Fatalf("全量重发审计应含全部通道名: %v", details)
	}

	// 非法 body → 400
	status, _ = doNotifyRequest(t, r, http.MethodPost, fmt.Sprintf("/notification/deliveries/%d/resend", id2), `{bad`)
	if status != http.StatusBadRequest {
		t.Fatalf("非法 body status=%d, want 400", status)
	}
}

func TestNotificationRuleAudit_nameAndResult(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO notification_channels (id, user_id, type, name, target, enabled) VALUES (101, 7, 'webhook', '运维群', '{"url":"http://127.0.0.1:1"}', 1)`); err != nil {
		t.Fatal(err)
	}
	r := newNotificationSemanticsRouter(h, 7, "user")

	// 规则修改：单条审计，规则名+结果
	status, out := doNotifyRequest(t, r, http.MethodPost, "/notification/rules/"+certGroupID(t), `{"min_level":"warn"}`)
	if status != http.StatusOK || out["code"].(float64) != 0 {
		t.Fatalf("规则更新 status=%d body=%v", status, out)
	}
	details := auditRows(t, "修改", "通知规则")
	if len(details) != 1 {
		t.Fatalf("规则修改审计行数=%d, want 1（Explicit 单记）", len(details))
	}
	if !strings.Contains(details[0], "证书") || !strings.Contains(details[0], "结果：成功") {
		t.Fatalf("规则修改审计缺名称/结果: %q", details[0])
	}

	// 规则测试：入队成功单条审计
	status, out = doNotifyRequest(t, r, http.MethodPost, "/notification/rules/"+certGroupID(t)+"/test", "")
	if status != http.StatusOK {
		t.Fatalf("规则测试 status=%d body=%v", status, out)
	}
	details = auditRows(t, "测试", "通知规则")
	if len(details) != 1 || !strings.Contains(details[0], "证书") || !strings.Contains(details[0], "结果：成功") {
		t.Fatalf("规则测试审计=%v, want 单条含规则名+成功", details)
	}

	// 不存在组：404 不留审计（4xx 请求未生效口径）
	status, _ = doNotifyRequest(t, r, http.MethodPost, "/notification/rules/group:不存在/test", "")
	if status != http.StatusNotFound {
		t.Fatalf("不存在组 status=%d, want 404", status)
	}
	if details = auditRows(t, "测试", "通知规则"); len(details) != 1 {
		t.Fatalf("404 不应新增审计: %v", details)
	}
}

func TestNotificationChannelAudit_nameAndResult(t *testing.T) {
	h := newBackupTestHandlers(t)
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer okSrv.Close()
	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	badURL := badSrv.URL
	badSrv.Close() // 连接拒绝 → 测试失败路径
	if _, err := db.DB.Exec(`INSERT INTO notification_channels (id, user_id, type, name, target, enabled) VALUES
		(101, 7, 'webhook', '运维群', ?, 1), (102, 7, 'webhook', '坏通道', ?, 1)`,
		`{"url":"`+okSrv.URL+`"}`, `{"url":"`+badURL+`"}`); err != nil {
		t.Fatal(err)
	}
	r := newNotificationSemanticsRouter(h, 7, "user")

	status, _ := doNotifyRequest(t, r, http.MethodPost, "/notification/channels/101/test", "")
	if status != http.StatusOK {
		t.Fatalf("通道测试 status=%d, want 200", status)
	}
	details := auditRows(t, "测试", "通知通道")
	if len(details) != 1 || !strings.Contains(details[0], "运维群") || !strings.Contains(details[0], "结果：成功") {
		t.Fatalf("通道测试成功审计=%v, want 单条含通道名+成功", details)
	}
	if strings.Contains(details[0], "#") || strings.Contains(details[0], "http") {
		t.Fatalf("通道测试审计禁 ID/URL: %q", details[0])
	}

	status, _ = doNotifyRequest(t, r, http.MethodPost, "/notification/channels/102/test", "")
	if status != http.StatusBadGateway {
		t.Fatalf("坏通道测试 status=%d, want 502", status)
	}
	details = auditRows(t, "测试", "通知通道")
	if len(details) != 2 || !strings.Contains(details[1], "坏通道") || !strings.Contains(details[1], "结果：失败") {
		t.Fatalf("通道测试失败审计=%v, want 含通道名+失败", details)
	}
}

func TestNotificationStats_partialCountsAsSuccess(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedSemanticsDelivery(t, 7, "sent", 0)
	seedSemanticsDelivery(t, 7, "partial", 0)
	seedSemanticsDelivery(t, 7, "failed", 0)

	adminRouter := newNotificationSemanticsRouter(h, 1, "admin")
	status, out := doNotifyRequest(t, adminRouter, http.MethodGet, "/notification/admin/overview", "")
	if status != http.StatusOK {
		t.Fatalf("overview status=%d body=%v", status, out)
	}
	stats := out["data"].(map[string]any)["stats"].(map[string]any)
	if stats["deliveries"].(float64) != 3 {
		t.Fatalf("deliveries=%v, want 3", stats["deliveries"])
	}
	if rate := stats["success_rate"].(float64); rate < 0.66 || rate > 0.67 {
		t.Fatalf("success_rate=%v, want 2/3（sent+partial）", rate)
	}

	userRouter := newNotificationSemanticsRouter(h, 7, "user")
	status, out = doNotifyRequest(t, userRouter, http.MethodGet, "/notification/delivery-trend", "")
	if status != http.StatusOK {
		t.Fatalf("trend status=%d body=%v", status, out)
	}
	trend, _ := out["data"].(map[string]any)["trend"].([]any)
	last := trend[len(trend)-1].(map[string]any)
	if last["total"].(float64) != 3 || last["sent"].(float64) != 2 {
		t.Fatalf("今日趋势 total=%v sent=%v, want 3/2（partial 计成功）", last["total"], last["sent"])
	}
}

func TestNotificationDeliveryTrend_adminSeesAllUsers(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedSemanticsDelivery(t, 7, "sent", 0)
	seedSemanticsDelivery(t, 8, "failed", 0)

	adminRouter := newNotificationSemanticsRouter(h, 1, "admin")
	status, out := doNotifyRequest(t, adminRouter, http.MethodGet, "/notification/delivery-trend", "")
	if status != http.StatusOK {
		t.Fatalf("admin trend status=%d body=%v", status, out)
	}
	trend, _ := out["data"].(map[string]any)["trend"].([]any)
	last := trend[len(trend)-1].(map[string]any)
	if last["total"].(float64) != 2 {
		t.Fatalf("admin 趋势 total=%v, want 2（全平台口径，与统计卡一致）", last["total"])
	}
}

// 从节点「规则测试/日报测试」必须显式拒绝（403 master_required）。
// 从节点不存在 pending 消费方（投递 Daemon 仅主节点运行），放行=API 成功但
// 消息永不投递的假成功。
func TestNotificationTestEndpointsRejectSlave(t *testing.T) {
	h := newBackupTestHandlers(t)
	r := newNotificationSemanticsRouter(h, 7, "user")
	r.POST("/notification/daily/test", h.TestNotificationDaily)
	// 主节点路径需要可用通道（规则测试入队前置：无启用通道=502）。
	if _, err := db.DB.Exec(`INSERT INTO notification_channels (id, user_id, type, name, target, enabled) VALUES (121, 7, 'webhook', '运维群', '{"url":"http://127.0.0.1:1"}', 1)`); err != nil {
		t.Fatalf("seed channel: %v", err)
	}

	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatalf("切换从节点角色失败: %v", err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`) })

	status, out := doNotifyRequest(t, r, http.MethodPost, "/notification/rules/"+certGroupID(t)+"/test", "")
	if status != http.StatusForbidden {
		t.Fatalf("从节点规则测试 status=%d body=%v, want 403", status, out)
	}
	if msg, _ := out["message"].(string); !strings.Contains(msg, "通知配置仅主节点生效") {
		t.Fatalf("从节点规则测试提示=%q, want 通知配置仅主节点生效", msg)
	}

	status, out = doNotifyRequest(t, r, http.MethodPost, "/notification/daily/test", "")
	if status != http.StatusForbidden {
		t.Fatalf("从节点日报测试 status=%d body=%v, want 403", status, out)
	}
	if msg, _ := out["message"].(string); !strings.Contains(msg, "通知配置仅主节点生效") {
		t.Fatalf("从节点日报测试提示=%q, want 通知配置仅主节点生效", msg)
	}

	// 不产生永不消费的 pending 投递行（假成功的实体面）。
	var pending int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM notification_deliveries WHERE status='pending' AND is_test=1`).Scan(&pending); err != nil {
		t.Fatalf("count pending: %v", err)
	}
	if pending != 0 {
		t.Fatalf("从节点被拒后仍落 pending 投递行 %d 条（假成功）", pending)
	}

	// 恢复主节点后放行（同一进程角色切换后门跟着走）。
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`); err != nil {
		t.Fatalf("恢复主节点角色失败: %v", err)
	}
	status, out = doNotifyRequest(t, r, http.MethodPost, "/notification/rules/"+certGroupID(t)+"/test", "")
	if status != http.StatusOK {
		t.Fatalf("主节点规则测试 status=%d body=%v, want 200", status, out)
	}
}

func TestNotificationDeliveries_channelsCollapseToLatestPerChannel(t *testing.T) {
	h := newBackupTestHandlers(t)
	r := newNotificationSemanticsRouter(h, 7, "user")
	id := seedSemanticsDelivery(t, 7, "partial", 0)
	// 同一通道先失败后成功（重试/重发追加行）：列表必须只回最新一行。
	seedChannelResult(t, id, 501, "邮件A", "email", "failed")
	seedChannelResult(t, id, 501, "邮件A", "email", "sent")

	status, out := doNotifyRequest(t, r, http.MethodGet, "/notification/deliveries", "")
	if status != http.StatusOK {
		t.Fatalf("list status=%d body=%v", status, out)
	}
	items := out["data"].(map[string]any)["deliveries"].([]any)
	if len(items) != 1 {
		t.Fatalf("deliveries=%d, want 1", len(items))
	}
	chs := items[0].(map[string]any)["channels"].([]any)
	if len(chs) != 1 {
		t.Fatalf("channels=%d（历史结果行混入）, want 1（每通道最新）", len(chs))
	}
	if got := chs[0].(map[string]any)["status"]; got != "sent" {
		t.Fatalf("channel status=%v, want sent（最新行）", got)
	}
}
