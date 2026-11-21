package handlers

// 人机事件直写通道的输入契约（绕过 WAF 管线但单行体积/时间与身份准入不变）：
//   - ts<=0 或 client_ip 空 → 跳过不落库（否则 1970 时间与空 IP 进入事件日志，
//     污染排序/按日统计/自动封禁身份）；
//   - 被跳过的行不得再发通知/喂入（旧实现在通知与喂入循环只跳 pass）；
//   - uri 按 WAF 管线路同源上限截断（单行体积披露「约 64KiB」不失真）。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/notify"
	"lazy-balancer-v2/internal/services"
)

func TestHandleIngestHuman_missingTSOrIPNotPersisted(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb-valid','有效规则','http','valid.test',8443,1)`); err != nil {
		t.Fatal(err)
	}
	h := &SecurityEventsIPCServer{}
	ts := time.Now().UnixMilli()
	body := fmt.Sprintf(`[
		{"ts":0,"rule_id":"lb-valid","client_ip":"203.0.113.71","method":"GET","uri":"/a","kind":"challenge"},
		{"ts":%d,"rule_id":"lb-valid","client_ip":"","method":"GET","uri":"/b","kind":"challenge"},
		{"ts":%d,"rule_id":"lb-valid","client_ip":"203.0.113.72","method":"GET","uri":"/ok","kind":"challenge"}
	]`, ts, ts)
	req := httptest.NewRequest(http.MethodPost, services.SecurityEventsIPCIngestHumanPath, strings.NewReader(body))
	rec := httptest.NewRecorder()
	http.HandlerFunc(h.ingestRouter).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var n int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events WHERE event_type='human'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("缺 ts/空 IP 行必须跳过（仅合法行落库），实际 %d 行", n)
	}
	var ip, eventTime string
	if err := db.MetricsDB.QueryRow(`SELECT client_ip, event_time FROM security_events WHERE event_type='human'`).Scan(&ip, &eventTime); err != nil {
		t.Fatal(err)
	}
	if ip != "203.0.113.72" {
		t.Fatalf("落库行 ip=%q, want 合法行 203.0.113.72", ip)
	}
	if strings.HasPrefix(eventTime, "1970") {
		t.Fatalf("落库时间=%q，缺 ts 行不得以 1970 时间入库", eventTime)
	}
}

// 未知 kind（带外脏数据/旧版本残余）不得发 CC 触发通知：旧实现只在落库/喂入
// 循环跳过 pass，通知循环仍会对 reason 非空的未知 kind 发布事件（指向不存在
// 的事件）。通知可观测面：总线未装配时 Publish 走丢弃计数（notify.DroppedCount）。
func TestHandleIngestHuman_unknownKindDoesNotPublishNotification(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	ts := time.Now().UnixMilli()
	before := notify.DroppedCount()
	h := &SecurityEventsIPCServer{}
	body := fmt.Sprintf(`[{"ts":%d,"rule_id":"lb-unknown-notify","client_ip":"203.0.113.81","method":"GET","uri":"/u","kind":"garbage","reason":"rps_spike"}]`, ts)
	req := httptest.NewRequest(http.MethodPost, services.SecurityEventsIPCIngestHumanPath, strings.NewReader(body))
	rec := httptest.NewRecorder()
	http.HandlerFunc(h.ingestRouter).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := notify.DroppedCount(); got != before {
		t.Fatalf("未知 kind 不得发布通知：dropped %d→%d", before, got)
	}
}

// 对照：已知 rate_reject（带 reason）必须发布（阻断聚合首条立即发出），
// 证明上面的探针有判别力。
func TestHandleIngestHuman_knownKindPublishesNotification(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	ts := time.Now().UnixMilli()
	before := notify.DroppedCount()
	h := &SecurityEventsIPCServer{}
	body := fmt.Sprintf(`[{"ts":%d,"rule_id":"lb-known-notify","client_ip":"198.51.100.240","method":"GET","uri":"/u","kind":"rate_reject","reason":"rps_spike"}]`, ts)
	req := httptest.NewRequest(http.MethodPost, services.SecurityEventsIPCIngestHumanPath, strings.NewReader(body))
	rec := httptest.NewRecorder()
	http.HandlerFunc(h.ingestRouter).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := notify.DroppedCount(); got <= before {
		t.Fatalf("已知拦截事件必须发布通知：dropped %d→%d", before, got)
	}
}

// uri 超限按 WAF 管线路同源上限（8KiB）截断并追加标记：直写不得让单行体积
// 突破保留摘要披露的「单行最大约 64KiB」。
func TestHandleIngestHuman_uriTruncatedToPipelineCap(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	ts := time.Now().UnixMilli()
	longURI := "/" + strings.Repeat("a", 12000)
	body := fmt.Sprintf(`[{"ts":%d,"rule_id":"lb-long-uri","client_ip":"203.0.113.90","method":"GET","uri":"%s","kind":"challenge"}]`, ts, longURI)
	h := &SecurityEventsIPCServer{}
	req := httptest.NewRequest(http.MethodPost, services.SecurityEventsIPCIngestHumanPath, strings.NewReader(body))
	rec := httptest.NewRecorder()
	http.HandlerFunc(h.ingestRouter).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var stored string
	if err := db.MetricsDB.QueryRow(`SELECT uri FROM security_events WHERE event_type='human'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) >= len(longURI) {
		t.Fatalf("uri 未截断：落库 %d 字节（输入 %d）", len(stored), len(longURI))
	}
	if !strings.Contains(stored, "[TRUNCATED]") {
		t.Fatal("截断必须携带 [TRUNCATED] 标记（不静默裁剪）")
	}
	if len(stored) > 8192+64 {
		t.Fatalf("uri 落库 %d 字节，超出 8KiB 上限+标记", len(stored))
	}
}
