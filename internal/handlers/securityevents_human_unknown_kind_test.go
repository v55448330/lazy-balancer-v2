package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// IPC 未知 kind（带外脏数据/旧版本残余形态）不得静默落 challenged 污染事件
// 日志与自动封禁喂入——与 pass 同口径跳过（仅已知 challenge/fail/rate_reject
// 落库），未知 kind 响亮 warn 留痕。已知 kind 同批不受影响。
func TestHandleIngestHuman_unknownKindNotPersisted(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb-unk','未知规则','http','unk.test',8443,1)`); err != nil {
		t.Fatal(err)
	}
	h := &SecurityEventsIPCServer{}
	// 未知 kind（garbage）+ 已知 challenge 同批：未知跳过，已知照常落库。
	body := `[{"ts":1786447300123,"rule_id":"lb-unk","client_ip":"203.0.113.92","method":"GET","uri":"/u","ua":"U/1.0","kind":"garbage"},{"ts":1786447300456,"rule_id":"lb-unk","client_ip":"203.0.113.93","method":"GET","uri":"/c","ua":"U/1.0","kind":"challenge"}]`
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
		t.Fatalf("未知 kind 不得落库（仅已知 challenge 落 1 行），实际 %d 行", n)
	}
	var rule string
	if err := db.MetricsDB.QueryRow(`SELECT rule_triggered FROM security_events WHERE event_type='human'`).Scan(&rule); err != nil {
		t.Fatal(err)
	}
	if rule != "human_challenge" {
		t.Fatalf("落库行必须是已知 challenge，实际 rule=%q", rule)
	}
}

// 未知 kind 的「响亮 warn 留痕」是契约另一半：跳过不落库已有钉，但 warn
// 缺失时带外脏数据/旧版本残余形态将完全不可见（契约一半无判别力）。
func TestHandleIngestHuman_unknownKindWarns(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	logs := captureHandlerLog(t)
	h := &SecurityEventsIPCServer{}
	body := `[{"ts":1786447300123,"rule_id":"lb-unk-w","client_ip":"203.0.113.94","method":"GET","uri":"/u","ua":"U/1.0","kind":"garbage"}]`
	req := httptest.NewRequest(http.MethodPost, services.SecurityEventsIPCIngestHumanPath, strings.NewReader(body))
	rec := httptest.NewRecorder()
	http.HandlerFunc(h.ingestRouter).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	out := logs.String()
	if !strings.Contains(out, "未知 kind") || !strings.Contains(out, `kind="garbage"`) || !strings.Contains(out, "203.0.113.94") {
		t.Fatalf("未知 kind 必须响亮 warn 留痕（kind/rule/ip 可定位），logs=%q", out)
	}
}

// 未知 kind 不得喂入自动封禁计数：垃圾行与已知 challenge 同 IP 同批
// （阈值 2）——若未知 kind 被计入，单条合法挑战即达阈值出候选；
// 正确行为=仅 challenge 计 1 次，tracked_ips=1 且无候选。
func TestHandleIngestHuman_unknownKindNotFedToAutoban(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	installHumanObserveMasterEngine(t)
	if err := services.SetAutobanConfig(services.AutobanConfig{Enabled: true, Threshold: 2, WindowMinutes: 5, Duration: "1h", Scope: services.AutobanScopeChallengeIssued, DryRun: true}); err != nil {
		t.Fatalf("enable autoban: %v", err)
	}
	services.ResetAutobanCounters()
	t.Cleanup(services.ResetAutobanCounters)
	ts := time.Now().UnixMilli()
	body := fmt.Sprintf(`[{"ts":%d,"rule_id":"lb-unk-f","client_ip":"45.33.32.91","method":"GET","uri":"/u","ua":"U/1.0","kind":"garbage"},{"ts":%d,"rule_id":"lb-unk-f","client_ip":"45.33.32.91","method":"GET","uri":"/c","ua":"U/1.0","kind":"challenge"}]`, ts, ts+1)
	postHumanObserveBatch(t, body)
	if got := services.AutobanTrackedIPs(); got != 1 {
		t.Fatalf("tracked_ips=%d, want 1（仅已知 challenge 计入）", got)
	}
	if got := services.AutobanSuggestions(); len(got) != 0 {
		t.Fatalf("未知 kind 不得喂入计数（阈值 2 不应达成），建议=%+v", got)
	}
}
