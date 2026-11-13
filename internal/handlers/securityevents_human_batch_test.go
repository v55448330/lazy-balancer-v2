package handlers

// 人机事件批量摄入的自动封禁喂入契约：一批 N 条事件只允许一次 autoban
// 配置读取（与 WAF 批路径同构），喂入语义（发放/失败计入、通过永不计、
// 禁用不计）不随批量化改变。语句计数用真实 SQLite 计数连接（countingMainDB），
// 不按源码字面量估算。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

// autobanConfigReadMatch 命中 autoban 六列配置单行读（GetAutobanConfig 的
// SELECT 形态）。
func autobanConfigReadMatch(query string) bool {
	return strings.Contains(query, "COALESCE(autoban_enabled")
}

// installHumanObserveMasterEngine 装配主节点任务引擎（autoban 喂入门=引擎
// 角色；无引擎时主节点门拒绝，计数路径整体不可达）。
func installHumanObserveMasterEngine(t *testing.T) {
	t.Helper()
	services.StopTaskEngine()
	te := taskengine.NewEngine(taskengine.Options{TickInterval: time.Hour})
	services.SetTaskEngineForTest(te)
	t.Cleanup(services.StopTaskEngine)
}

// seedHumanObserveAutobanConfig 直写六列（绕过保存侧校验/重置副作用）。
func seedHumanObserveAutobanConfig(t *testing.T, enabled bool, scope string) {
	t.Helper()
	ei := 0
	if enabled {
		ei = 1
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET autoban_enabled=?, autoban_threshold=100, autoban_window_minutes=60, autoban_duration='1h', autoban_scope=?, autoban_dry_run=0 WHERE id=1`,
		ei, scope); err != nil {
		t.Fatalf("seed autoban config: %v", err)
	}
}

// humanObserveBatchBody 构造 n 条同 IP 人机事件 JSON（kind 按循环序轮换）。
func humanObserveBatchBody(ip string, ts int64, kinds ...string) string {
	rows := make([]string, 0, len(kinds))
	for i, kind := range kinds {
		rows = append(rows, fmt.Sprintf(`{"ts":%d,"rule_id":"lb-batch","client_ip":%q,"method":"GET","uri":"/b","ua":"Batch/1.0","kind":%q}`, ts+int64(i), ip, kind))
	}
	return "[" + strings.Join(rows, ",") + "]"
}

func postHumanObserveBatch(t *testing.T, body string) {
	t.Helper()
	h := &SecurityEventsIPCServer{}
	req := httptest.NewRequest(http.MethodPost, services.SecurityEventsIPCIngestHumanPath, strings.NewReader(body))
	rec := httptest.NewRecorder()
	http.HandlerFunc(h.ingestRouter).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// Given 主节点+自动封禁启用（发放/失败两维度在口径内），一批 6 条事件。
// When 摄入提交后喂入自动封禁。
// Then 全部事件计入（tracked_ips=1），且整批配置读取恰 1 次——逐事件 SELECT
// 是热路径 O(事件) 库查询，洪峰下读放大。
func TestHandleIngestHuman_batchLoadsAutobanConfigOnce(t *testing.T) {
	recorder := countingMainDB(t)
	installHumanObserveMasterEngine(t)
	seedHumanObserveAutobanConfig(t, true, "challenge_issued,challenge_failed")
	services.ResetAutobanCounters()
	t.Cleanup(services.ResetAutobanCounters)

	ts := time.Now().UnixMilli()
	body := humanObserveBatchBody("203.0.113.201", ts, "challenge", "fail", "challenge", "fail", "challenge", "fail")
	recorder.reset()
	postHumanObserveBatch(t, body)

	if got := services.AutobanTrackedIPs(); got != 1 {
		t.Fatalf("tracked_ips=%d, want 1（批内事件必须喂入计数器）", got)
	}
	if got := recorder.count(autobanConfigReadMatch); got != 1 {
		t.Fatalf("整批 autoban 配置读取=%d 次, want 1（每批一次，不得逐事件 SELECT）", got)
	}
}

// Given 同上夹具，批内混入 pass 行。
// When 摄入提交。
// Then pass 不落库、不喂入（仅 challenge/fail 计数），配置仍整批一次。
func TestHandleIngestHuman_batchPassNeverFed(t *testing.T) {
	recorder := countingMainDB(t)
	installHumanObserveMasterEngine(t)
	seedHumanObserveAutobanConfig(t, true, "challenge_issued,challenge_failed")
	services.ResetAutobanCounters()
	t.Cleanup(services.ResetAutobanCounters)

	ts := time.Now().UnixMilli()
	body := humanObserveBatchBody("203.0.113.202", ts, "pass", "challenge", "pass", "fail")
	recorder.reset()
	postHumanObserveBatch(t, body)

	var n int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events WHERE event_type='human'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("human 事件落库=%d 行, want 2（pass 不得落库）", n)
	}
	if got := services.AutobanTrackedIPs(); got != 1 {
		t.Fatalf("tracked_ips=%d, want 1（challenge/fail 计入）", got)
	}
	if got := recorder.count(autobanConfigReadMatch); got != 1 {
		t.Fatalf("整批 autoban 配置读取=%d 次, want 1", got)
	}
}

// Given 主节点但自动封禁禁用。
// When 摄入一批 challenge/fail。
// Then 事件照常落库，但不喂入计数器；禁用门并入同一行读取（整批仍恰 1 次）。
func TestHandleIngestHuman_disabledAutobanSkipsFeedWithSingleRead(t *testing.T) {
	recorder := countingMainDB(t)
	installHumanObserveMasterEngine(t)
	seedHumanObserveAutobanConfig(t, false, "challenge_issued,challenge_failed")
	services.ResetAutobanCounters()
	t.Cleanup(services.ResetAutobanCounters)

	ts := time.Now().UnixMilli()
	body := humanObserveBatchBody("203.0.113.203", ts, "challenge", "fail", "challenge")
	recorder.reset()
	postHumanObserveBatch(t, body)

	var n int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events WHERE event_type='human'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("human 事件落库=%d 行, want 3（禁用自动封禁不影响事件落库）", n)
	}
	if got := services.AutobanTrackedIPs(); got != 0 {
		t.Fatalf("tracked_ips=%d, want 0（禁用不得喂入）", got)
	}
	if got := recorder.count(autobanConfigReadMatch); got != 1 {
		t.Fatalf("整批 autoban 配置读取=%d 次, want 1（禁用门并入同一行读取）", got)
	}
}
