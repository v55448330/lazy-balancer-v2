package services

// 摄取期请求级去重：多策略绑定下同一请求会被每个绑定策略的 coraza 实例各写
// 一条审计事务（transaction_id 各不相同），必须归并为一条事件，否则事件列表
// 成对重复、计数与自动封禁阈值按引擎数放大。

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// securityEventsDedupeFixture 生成一条最小 Coraza 审计事务。
// timingID 为空=旧版本审计日志（无请求级计时头），走指纹回退路径。
func securityEventsDedupeFixture(txID, timingID, uri, action string, ruleID int) string {
	headers := `"host": ["go029.com"]`
	if timingID != "" {
		headers += fmt.Sprintf(`, "X-Lb-Security-Timing-Id": [%q]`, timingID)
	}
	msg := fmt.Sprintf("dedupe rule %d", ruleID)
	if action == "blocked" {
		msg = fmt.Sprintf("Inbound Anomaly Score Exceeded (Total Score: 5) rule %d", ruleID)
	}
	return fmt.Sprintf(`{
  "transaction": {
    "unix_timestamp": 1786447017841320426,
    "id": %q,
    "client_ip": "45.33.32.9",
    "server_id": "go029.com",
    "request": { "method": "GET", "uri": %q, "headers": { %s } },
    "is_interrupted": %t
  },
  "messages": [ { "message": %q, "data": { "id": %d, "raw": "id:%d,phase:2,deny,log" } } ]
}`, txID, uri, headers, action == "blocked", msg, ruleID, ruleID)
}

func isolateSecurityEventsSharedDedupe(t *testing.T) {
	t.Helper()
	old := securityEventsSharedDedupe
	securityEventsSharedDedupe = &securityEventsRequestDeduper{}
	t.Cleanup(func() { securityEventsSharedDedupe = old })
}

// seedSecurityEventsDedupeDB 写入规则/策略/绑定，返回审计日志与偏移路径。
func seedSecurityEventsDedupeDB(t *testing.T) (logPath, offsetPath string) {
	t.Helper()
	isolateSecurityEventsSharedDedupe(t)
	dataDir := t.TempDir()
	if err := initSecurityEventsTestDB(t, dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_rule1','test rule','http','go029.com',443,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,enabled,mode,custom_rules,crs_rule_groups) VALUES (7,'policy-seven',1,'blocking','[]','[]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_rule1',7)`); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	return filepath.Join(dir, "audit.log"), filepath.Join(dir, "security_events.offset")
}

func writeSecurityEventsDedupeLog(t *testing.T, logPath string, docs ...string) {
	t.Helper()
	if err := os.WriteFile(logPath, []byte(strings.Join(docs, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// runSecurityEventsDedupeTick 跑一轮摄取（失败即终止用例）。
func runSecurityEventsDedupeTick(t *testing.T, tailer *securityEventsTailer) {
	t.Helper()
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("tick: %v", err)
	}
}

func readSecurityEventsRows(t *testing.T) []struct {
	id, policyID, score                         int
	action, triggered, transactionID, ruleCaddy string
} {
	t.Helper()
	rows, err := db.MetricsDB.Query(`SELECT id, COALESCE(policy_id,0), anomaly_score, action, COALESCE(rule_triggered,''), COALESCE(transaction_id,''), COALESCE(rule_caddy_id,'') FROM security_events ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []struct {
		id, policyID, score                         int
		action, triggered, transactionID, ruleCaddy string
	}
	for rows.Next() {
		var r struct {
			id, policyID, score                         int
			action, triggered, transactionID, ruleCaddy string
		}
		if err := rows.Scan(&r.id, &r.policyID, &r.score, &r.action, &r.triggered, &r.transactionID, &r.ruleCaddy); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// 同一请求（共享请求级计时头）的检测事务后跟拦截事务：只落一条事件，
// 且结论、触发规则与评分按拦截引擎改判。
func TestSecurityEventsTick_mergesMultiEngineTransactionsPerRequest(t *testing.T) {
	logPath, offsetPath := seedSecurityEventsDedupeDB(t)
	writeSecurityEventsDedupeLog(t, logPath,
		securityEventsDedupeFixture("tx-engine-a", "6f1c0d9a2b3e4f57", "/api/orders", "logged", 942100),
		securityEventsDedupeFixture("tx-engine-b", "6f1c0d9a2b3e4f57", "/api/orders", "blocked", 949110),
	)
	tailer := securityEventsNewTailer(logPath, offsetPath)
	runSecurityEventsDedupeTick(t, tailer)

	rows := readSecurityEventsRows(t)
	if len(rows) != 1 {
		t.Fatalf("rows=%d, want 1 (one event per request): %+v", len(rows), rows)
	}
	got := rows[0]
	if got.transactionID != "tx-engine-a" {
		t.Errorf("transaction_id=%q, want tx-engine-a (首次落库行的幂等键)", got.transactionID)
	}
	if got.action != "blocked" || got.triggered != "949110" || got.score != 5 {
		t.Errorf("row=(%s,%s,%d), want blocked/949110/5（拦截结论覆盖检测结论）", got.action, got.triggered, got.score)
	}
	if got.policyID != 7 || got.ruleCaddy != "lb_rule1" {
		t.Errorf("attribution=(%d,%s), want (7,lb_rule1)", got.policyID, got.ruleCaddy)
	}
	if tailer.lastIngested != 1 {
		t.Errorf("lastIngested=%d, want 1（归并的事务不计入摄取条数）", tailer.lastIngested)
	}

	// 重放同一份日志（offset 归零）=幂等：不新增行、不改判出第二条。
	if _, _, err := securityEventsIngestDeltaFrom(logPath, 0, true); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if rows := readSecurityEventsRows(t); len(rows) != 1 {
		t.Fatalf("rows after replay=%d, want 1", len(rows))
	}
}

// 拦截事务先写、检测事务后写：后到的弱结论不得把已落库的拦截行降级。
func TestSecurityEventsTick_mergeKeepsBlockedWhenLoggedArrivesLater(t *testing.T) {
	logPath, offsetPath := seedSecurityEventsDedupeDB(t)
	writeSecurityEventsDedupeLog(t, logPath,
		securityEventsDedupeFixture("tx-first", "aa11bb22cc33dd44", "/search", "blocked", 949110),
		securityEventsDedupeFixture("tx-second", "aa11bb22cc33dd44", "/search", "logged", 942100),
	)
	runSecurityEventsDedupeTick(t, securityEventsNewTailer(logPath, offsetPath))

	rows := readSecurityEventsRows(t)
	if len(rows) != 1 {
		t.Fatalf("rows=%d, want 1: %+v", len(rows), rows)
	}
	if rows[0].action != "blocked" || rows[0].triggered != "949110" {
		t.Errorf("row=(%s,%s), want blocked/949110（弱结论不降级）", rows[0].action, rows[0].triggered)
	}
}

// 不同请求（计时头不同）即使落在同一秒、同一 URI、同一规则也各落一条。
func TestSecurityEventsTick_keepsDistinctRequestsWithDifferentTimingIDs(t *testing.T) {
	logPath, offsetPath := seedSecurityEventsDedupeDB(t)
	writeSecurityEventsDedupeLog(t, logPath,
		securityEventsDedupeFixture("tx-req-1", "1111222233334444", "/api/orders", "blocked", 949110),
		securityEventsDedupeFixture("tx-req-2", "5555666677778888", "/api/orders", "blocked", 949110),
	)
	runSecurityEventsDedupeTick(t, securityEventsNewTailer(logPath, offsetPath))

	if rows := readSecurityEventsRows(t); len(rows) != 2 {
		t.Fatalf("rows=%d, want 2（不同请求不得归并）: %+v", len(rows), rows)
	}
}

// 同一请求的两个引擎事务被 tick 边界拆开（第二个事务在下一轮才写全）：
// 归并记忆跨 pass 保留，仍只落一条事件，且结论按后到的拦截改判。
func TestSecurityEventsTick_mergesAcrossPassesForSameRequest(t *testing.T) {
	logPath, offsetPath := seedSecurityEventsDedupeDB(t)
	writeSecurityEventsDedupeLog(t, logPath,
		securityEventsDedupeFixture("tx-split-a", "9988776655443322", "/split", "logged", 942100),
	)
	tailer := securityEventsNewTailer(logPath, offsetPath)
	runSecurityEventsDedupeTick(t, tailer)

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(securityEventsDedupeFixture("tx-split-b", "9988776655443322", "/split", "blocked", 949110) + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	runSecurityEventsDedupeTick(t, tailer)

	rows := readSecurityEventsRows(t)
	if len(rows) != 1 {
		t.Fatalf("rows=%d, want 1（跨 pass 同一请求仍归并）: %+v", len(rows), rows)
	}
	if rows[0].action != "blocked" {
		t.Errorf("action=%q, want blocked（后到拦截改判）", rows[0].action)
	}
}

// 旧版本审计行（无请求级计时头）没有请求级自然键：按原样逐条入库，
// 绝不按「秒+四元组」指纹猜测归并（独立请求会被误并）。
func TestSecurityEventsTick_keepsLegacyTransactionsWithoutTimingHeader(t *testing.T) {
	logPath, offsetPath := seedSecurityEventsDedupeDB(t)
	writeSecurityEventsDedupeLog(t, logPath,
		securityEventsDedupeFixture("tx-legacy-a", "", "/legacy", "logged", 942100),
		securityEventsDedupeFixture("tx-legacy-b", "", "/legacy", "logged", 942100),
		securityEventsDedupeFixture("tx-legacy-c", "", "/legacy-other", "logged", 942100),
	)
	runSecurityEventsDedupeTick(t, securityEventsNewTailer(logPath, offsetPath))

	rows := readSecurityEventsRows(t)
	if len(rows) != 3 {
		t.Fatalf("rows=%d, want 3（无请求级键不得归并）: %+v", len(rows), rows)
	}
}

// securityEventsDedupeNowFixture 同 dedupe 夹具，但事件时间取当前时钟——
// 自动封禁只统计当前窗口内的事件（积压回放不计），旧固定时间戳会被窗口门
// 拒绝，断言恒 0。
func securityEventsDedupeNowFixture(txID, timingID, uri, action string, ruleID int) string {
	now := time.Now().UTC().UnixNano()
	return strings.Replace(securityEventsDedupeFixture(txID, timingID, uri, action, ruleID), "1786447017841320426", fmt.Sprintf("%d", now), 1)
}

// installDedupeAutobanFixture 打开主节点门并清空计数器（真 metrics/主库由
// seedSecurityEventsDedupeDB 建好）。
func installDedupeAutobanFixture(t *testing.T) {
	t.Helper()
	oldMaster := autobanIsMaster
	autobanIsMaster = func() bool { return true }
	resetAutobanStateForTest()
	t.Cleanup(func() {
		autobanIsMaster = oldMaster
		resetAutobanStateForTest()
	})
}

// appendDedupeLogDoc 追加一条审计事务并跑一轮 tick（模拟跨 pass 形态）。
func appendDedupeLogDoc(t *testing.T, logPath string, tailer *securityEventsTailer, doc string) {
	t.Helper()
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(doc + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	runSecurityEventsDedupeTick(t, tailer)
}

// 跨 pass 改判必须喂自动封禁：scope=blocked 下首轮的 logged 不计入，若改判
// 不补喂，攻击请求永远达不到阈值（库内事件显示 blocked，计数却为 0）。
func TestSecurityEventsTick_crossPassUpgradeFeedsAutobanUnderBlockedScope(t *testing.T) {
	logPath, offsetPath := seedSecurityEventsDedupeDB(t)
	installDedupeAutobanFixture(t)
	setAutobanConfigRaw(t, true, 1, 60, "1h", "blocked", false)

	writeSecurityEventsDedupeLog(t, logPath,
		securityEventsDedupeNowFixture("tx-pass-a", "0011aabbccddeeff", "/split", "logged", 942100))
	tailer := securityEventsNewTailer(logPath, offsetPath)
	runSecurityEventsDedupeTick(t, tailer)
	if got := autobanCountForTest("45.33.32.9"); got != 0 {
		t.Fatalf("logged 不计入 scope=blocked，首轮 count=%d, want 0", got)
	}

	appendDedupeLogDoc(t, logPath, tailer, securityEventsDedupeNowFixture("tx-pass-b", "0011aabbccddeeff", "/split", "blocked", 949110))
	if got := autobanCountForTest("45.33.32.9"); got != 1 {
		t.Fatalf("跨 pass 改判 blocked 必须喂一次自动封禁，count=%d, want 1", got)
	}
}

// scope=all 下首轮 logged 已计 1：跨 pass 改判不得再喂第二条（一请求一次）。
func TestSecurityEventsTick_crossPassUpgradeDoesNotDoubleCountUnderAllScope(t *testing.T) {
	logPath, offsetPath := seedSecurityEventsDedupeDB(t)
	installDedupeAutobanFixture(t)
	setAutobanConfigRaw(t, true, 1, 60, "1h", "all", false)

	writeSecurityEventsDedupeLog(t, logPath,
		securityEventsDedupeNowFixture("tx-all-a", "0022aabbccddeeff", "/split", "logged", 942100))
	tailer := securityEventsNewTailer(logPath, offsetPath)
	runSecurityEventsDedupeTick(t, tailer)
	if got := autobanCountForTest("45.33.32.9"); got != 1 {
		t.Fatalf("首轮 logged count=%d, want 1", got)
	}

	appendDedupeLogDoc(t, logPath, tailer, securityEventsDedupeNowFixture("tx-all-b", "0022aabbccddeeff", "/split", "blocked", 949110))
	if got := autobanCountForTest("45.33.32.9"); got != 1 {
		t.Fatalf("跨 pass 改判不得重复计数，count=%d, want 1", got)
	}
}

// 跨批「阶段 1 logged → WAF blocked」在 scope=all 下必须补喂：阶段 1 预检
// 事件被自动封禁的阶段门剔除、从未计数，账目若把它记成「logged 已计」，
// 跨批改判时会据账目判「已计」而跳过补喂——WAF 拦截永不计数（库内事件显示
// blocked，计数为 0，UI 无迹可查）。
func TestSecurityEventsTick_crossPassUpgradeFeedsAutobanAfterStageFilteredLogged(t *testing.T) {
	logPath, offsetPath := seedSecurityEventsDedupeDB(t)
	installDedupeAutobanFixture(t)
	setAutobanConfigRaw(t, true, 1, 60, "1h", "all", false)

	// 800123 属 GeoIP 预检段（阶段 1）：logged 随批喂入但被阶段门剔除。
	writeSecurityEventsDedupeLog(t, logPath,
		securityEventsDedupeNowFixture("tx-stage-a", "0077aabbccddeeff", "/split", "logged", 800123))
	tailer := securityEventsNewTailer(logPath, offsetPath)
	runSecurityEventsDedupeTick(t, tailer)
	if got := autobanCountForTest("45.33.32.9"); got != 0 {
		t.Fatalf("阶段 1 logged 被阶段门剔除，count=%d, want 0", got)
	}

	// 同一请求（共享计时头）在下一批被 WAF 拦截改判：必须补喂计数。
	appendDedupeLogDoc(t, logPath, tailer, securityEventsDedupeNowFixture("tx-stage-b", "0077aabbccddeeff", "/split", "blocked", 949110))
	if got := autobanCountForTest("45.33.32.9"); got != 1 {
		t.Fatalf("阶段 1 logged 后的 WAF blocked 改判必须补喂计数，count=%d, want 1", got)
	}
}

// 同批形态与跨批一致：阶段 1 logged 与 WAF blocked 落在同一批时同样恰好计 1
// （两条喂入路径的口径不得分叉）。
func TestSecurityEventsTick_samePassUpgradeFeedsAutobanAfterStageFilteredLogged(t *testing.T) {
	for _, scope := range []string{"all", "blocked"} {
		t.Run(scope, func(t *testing.T) {
			logPath, offsetPath := seedSecurityEventsDedupeDB(t)
			installDedupeAutobanFixture(t)
			setAutobanConfigRaw(t, true, 1, 60, "1h", scope, false)
			writeSecurityEventsDedupeLog(t, logPath,
				securityEventsDedupeNowFixture("tx-stage-same-a", "0088aabbccddeeff", "/same", "logged", 800123),
				securityEventsDedupeNowFixture("tx-stage-same-b", "0088aabbccddeeff", "/same", "blocked", 949110))
			runSecurityEventsDedupeTick(t, securityEventsNewTailer(logPath, offsetPath))
			if got := autobanCountForTest("45.33.32.9"); got != 1 {
				t.Fatalf("scope=%s 同批阶段过滤改判 count=%d, want 1", scope, got)
			}
		})
	}
}

// 受信 IP 的 logged 被豁免（未计数）：随后非信任的 blocked 改判必须补喂
// （scope=all 下同样如此——此前被豁免 ≠ 已计数）。
func TestSecurityEventsTick_crossPassUpgradeFeedsBlockedAfterTrustExemptLogged(t *testing.T) {
	logPath, offsetPath := seedSecurityEventsDedupeDB(t)
	installDedupeAutobanFixture(t)
	setAutobanConfigRaw(t, true, 1, 60, "1h", "all", false)
	if _, err := db.DB.Exec(`UPDATE security_policies SET ip_whitelist_enabled=1, ip_whitelist='["45.33.32.9"]' WHERE id=7`); err != nil {
		t.Fatal(err)
	}

	writeSecurityEventsDedupeLog(t, logPath,
		securityEventsDedupeNowFixture("tx-trust-a", "0033aabbccddeeff", "/split", "logged", 942100))
	tailer := securityEventsNewTailer(logPath, offsetPath)
	runSecurityEventsDedupeTick(t, tailer)
	if got := autobanCountForTest("45.33.32.9"); got != 0 {
		t.Fatalf("信任豁免的 logged count=%d, want 0", got)
	}

	appendDedupeLogDoc(t, logPath, tailer, securityEventsDedupeNowFixture("tx-trust-b", "0033aabbccddeeff", "/split", "blocked", 949110))
	if got := autobanCountForTest("45.33.32.9"); got != 1 {
		t.Fatalf("被豁免的 logged 之后的 blocked 改判必须计数，count=%d, want 1", got)
	}
}

// 同批改判必须同步攻击光流条目：大屏光流按 action 着色/计拦截，保留首次写入
// 的 logged 会让同一请求在光流显示「检测」而事件列表显示「拦截」。
func TestSecurityEventsTick_samePassUpgradeUpdatesAttackFlowAction(t *testing.T) {
	logPath, offsetPath := seedSecurityEventsDedupeDB(t)
	enableAttackFlowSampling(t)
	writeSecurityEventsDedupeLog(t, logPath,
		securityEventsDedupeNowFixture("tx-flow-a", "0055aabbccddeeff", "/flow-upgrade", "logged", 942100),
		securityEventsDedupeNowFixture("tx-flow-b", "0055aabbccddeeff", "/flow-upgrade", "blocked", 949110))
	runSecurityEventsDedupeTick(t, securityEventsNewTailer(logPath, offsetPath))

	events, _, _ := ThreatScreenAttackFlowSnapshot(0, 0)
	var matched []string
	for _, ev := range events {
		if ev.ClientIP == "45.33.32.9" {
			matched = append(matched, ev.Action+"|"+ev.RuleTriggered)
		}
	}
	if len(matched) != 1 {
		t.Fatalf("同批改判后光流条目数=%d, want 1: %v", len(matched), matched)
	}
	if matched[0] != "blocked|949110" {
		t.Fatalf("光流条目=%q, want blocked|949110（与事件行/库内改判一致）", matched[0])
	}
}

// 跨批改判（首轮 logged 属爬虫放行族=不计攻击，未入光流）后收到 blocked：
// 光流必须补入该拦截弧——同屏事件行/拦截率按 blocked 计，光流不得永久缺弧。
func TestSecurityEventsTick_crossPassUpgradeAppendsAttackFlow(t *testing.T) {
	logPath, offsetPath := seedSecurityEventsDedupeDB(t)
	enableAttackFlowSampling(t)
	// 810017 属爬虫放行族（豁免段 [810016,850000)）：logged 不计攻击，首轮不入环。
	writeSecurityEventsDedupeLog(t, logPath,
		securityEventsDedupeNowFixture("tx-flow-cross-a", "0066aabbccddeeff", "/flow-cross", "logged", 810017))
	tailer := securityEventsNewTailer(logPath, offsetPath)
	runSecurityEventsDedupeTick(t, tailer)
	if events, _, _ := ThreatScreenAttackFlowSnapshot(0, 0); len(events) != 0 {
		t.Fatalf("爬虫放行族 logged 不得入光流，got %+v", events)
	}

	appendDedupeLogDoc(t, logPath, tailer, securityEventsDedupeNowFixture("tx-flow-cross-b", "0066aabbccddeeff", "/flow-cross", "blocked", 949110))
	events, _, _ := ThreatScreenAttackFlowSnapshot(0, 0)
	var matched []string
	for _, ev := range events {
		if ev.ClientIP == "45.33.32.9" {
			matched = append(matched, ev.Action+"|"+ev.RuleTriggered)
		}
	}
	if len(matched) != 1 {
		t.Fatalf("跨批改判后光流条目数=%d, want 1: %v", len(matched), matched)
	}
	if matched[0] != "blocked|949110" {
		t.Fatalf("光流条目=%q, want blocked|949110（与事件行/库内改判一致）", matched[0])
	}
}

func TestSecurityEventsTick_samePassUpgradeFeedsAutobanOnce(t *testing.T) {
	for _, scope := range []string{"all", "blocked"} {
		t.Run(scope, func(t *testing.T) {
			logPath, offsetPath := seedSecurityEventsDedupeDB(t)
			installDedupeAutobanFixture(t)
			setAutobanConfigRaw(t, true, 1, 60, "1h", scope, false)
			writeSecurityEventsDedupeLog(t, logPath,
				securityEventsDedupeNowFixture("tx-same-a", "0044aabbccddeeff", "/same", "logged", 942100),
				securityEventsDedupeNowFixture("tx-same-b", "0044aabbccddeeff", "/same", "blocked", 949110))
			runSecurityEventsDedupeTick(t, securityEventsNewTailer(logPath, offsetPath))
			if got := autobanCountForTest("45.33.32.9"); got != 1 {
				t.Fatalf("scope=%s 同批改判 count=%d, want 1", scope, got)
			}
		})
	}
}

// 回退钩子的来源必须可区分：普通插入只报最旧分钟（实现方保留分钟高水位、走
// 增量合并即可）；原地改判（跨 pass 改判 logged→blocked，行 UPDATE 不改 id）
// 必须同时上报该分钟——增量重扫看不到改判行，实现方需对该分钟全量重算。
func TestSecurityEventsTick_rewindHookReportsReclassifyMinutes(t *testing.T) {
	logPath, offsetPath := seedSecurityEventsDedupeDB(t)
	var oldestMinutes []time.Time
	var reclassifyMinutes []time.Time
	SetSecurityEventsRollupRewrite(func(minute time.Time, reclassify []time.Time) {
		if !minute.IsZero() {
			oldestMinutes = append(oldestMinutes, minute)
		}
		reclassifyMinutes = append(reclassifyMinutes, reclassify...)
	})
	t.Cleanup(func() { SetSecurityEventsRollupRewrite(nil) })

	// Given 首个 pass 只有普通插入。
	writeSecurityEventsDedupeLog(t, logPath,
		securityEventsDedupeFixture("tx-source-a", "0011223344556677", "/source", "logged", 942100))
	tailer := securityEventsNewTailer(logPath, offsetPath)
	runSecurityEventsDedupeTick(t, tailer)
	if len(oldestMinutes) != 1 {
		t.Fatalf("普通插入 pass 的回退通知次数=%d, want 1", len(oldestMinutes))
	}
	if len(reclassifyMinutes) != 0 {
		t.Fatalf("普通插入不得上报原地改判分钟: %v", reclassifyMinutes)
	}

	// When 第二个 pass 把同一请求改判为拦截（既有行 UPDATE，id 不变）。
	appendDedupeLogDoc(t, logPath, tailer,
		securityEventsDedupeFixture("tx-source-b", "0011223344556677", "/source", "blocked", 949110))

	// Then 改判分钟被单独上报，且与事件分钟一致。
	if len(oldestMinutes) != 2 {
		t.Fatalf("改判 pass 的回退通知次数=%d, want 2", len(oldestMinutes))
	}
	if len(reclassifyMinutes) != 1 {
		t.Fatalf("原地改判分钟上报=%v, want 恰好 1 个（缺报会让该分钟增量重扫看不到改判行）", reclassifyMinutes)
	}
	var eventTime string
	if err := db.MetricsDB.QueryRow(`SELECT event_time FROM security_events WHERE transaction_id='tx-source-a'`).Scan(&eventTime); err != nil {
		t.Fatal(err)
	}
	parsed, err := time.ParseInLocation("2006-01-02 15:04:05", eventTime, time.UTC)
	if err != nil {
		parsed, err = time.Parse(time.RFC3339, eventTime)
	}
	if err != nil {
		t.Fatal(err)
	}
	wantMinute := parsed.Truncate(time.Minute)
	if !reclassifyMinutes[0].Equal(wantMinute) {
		t.Fatalf("原地改判分钟=%s, want %s", reclassifyMinutes[0], wantMinute)
	}
	if !oldestMinutes[1].Equal(wantMinute) {
		t.Fatalf("改判 pass 的最旧分钟=%s, want %s", oldestMinutes[1], wantMinute)
	}
}

// 去重表跨路径共享必须覆盖标量状态（清扫水位/告警标志）：按值副本只共享
// map，补采路径推进的 maxSec 停在副本上 → live 侧清扫切点滞后（陈旧键延后
// 清理）、容量告警重复。指针共享后才与注释声明一致。
func TestSecurityEventsLiveDedupe_sharesScalarStateWithArchivePath(t *testing.T) {
	isolateSecurityEventsSharedDedupe(t)
	live := securityEventsNewTailer("live.log", "live.offset")
	securityEventsPollState.Lock()
	old := securityEventsPollState.tailer
	securityEventsPollState.tailer = live
	securityEventsPollState.Unlock()
	t.Cleanup(func() {
		securityEventsPollState.Lock()
		securityEventsPollState.tailer = old
		securityEventsPollState.Unlock()
	})

	archive := securityEventsNewTailer("archive.log", "archive.offset")
	archive.dedupe = securityEventsLiveDedupe()
	if archive.dedupe != live.deduper() {
		t.Fatal("补采路径必须引用 live 去重表实例（指针共享），而不是按值副本")
	}

	archive.deduper().record(1, securityEventsDedupeEntry{atSec: 100})
	if got := live.deduper().maxSec; got != 100 {
		t.Fatalf("live 表清扫水位=%d, want 100（标量状态必须跨路径共享）", got)
	}
	live.deduper().record(2, securityEventsDedupeEntry{atSec: 200})
	if _, ok := archive.deduper().lookup(2, 200); !ok {
		t.Fatal("live 侧新登记必须在补采路径可见（同一实例）")
	}
}

// 改判不得用「空归因」覆盖既有非空归因：第二引擎事务缺少 X-LB-Rule-ID /
// host 映射时，rule_caddy_id/rule_name/policy_id/policy_name 必须保留首行值，
// 否则事件变成「blocked + 无规则 + 无策略」并从按策略/规则的 24h 计数与检索
// 中消失。结论列（action/评分）照常覆盖。
func TestUpgradeDedupedEvent_preservesAttributionWhenNewAttributionEmpty(t *testing.T) {
	dataDir := t.TempDir()
	if err := initSecurityEventsTestDB(t, dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events
		(event_time, rule_caddy_id, policy_id, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, anomaly_score, rule_name, policy_name, transaction_id, duration_us, precheck_us, request_headers, request_body)
		VALUES ('2026-10-14 10:00:00','lb_rule1',7,'45.33.32.9','GET','/x','1','score rule','score msg','logged',5,'rule name','policy-seven','tid-1',10,20,'','')`); err != nil {
		t.Fatal(err)
	}

	// 空归因改判（第二引擎事务无规则头且 host 不可映射）
	tx, err := db.MetricsDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	rec := &securityEventRecord{Action: "blocked", AnomalyScore: 9, RuleTriggered: "blocked-rule", DurationUs: 30, PrecheckUs: 40}
	if err := securityEventsUpgradeDedupedEvent(tx, "tid-1", rec, securityEventsRuleRef{}, 0, ""); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var action, ruleID, ruleName, policyName string
	var policyID int
	if err := db.MetricsDB.QueryRow(`SELECT action, COALESCE(rule_caddy_id,''), COALESCE(policy_id,0), COALESCE(rule_name,''), COALESCE(policy_name,'') FROM security_events WHERE transaction_id='tid-1'`).
		Scan(&action, &ruleID, &policyID, &ruleName, &policyName); err != nil {
		t.Fatal(err)
	}
	if action != "blocked" {
		t.Fatalf("action=%q, want blocked（结论必须覆盖）", action)
	}
	if ruleID != "lb_rule1" || policyID != 7 || ruleName != "rule name" || policyName != "policy-seven" {
		t.Fatalf("归因被空值覆盖: rule=%q policy=%d ruleName=%q policyName=%q", ruleID, policyID, ruleName, policyName)
	}

	// 有归因时照常覆盖（拦截引擎的归因优先）。
	tx, err = db.MetricsDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := securityEventsUpgradeDedupedEvent(tx, "tid-1", rec, securityEventsRuleRef{caddyID: "lb_rule2", name: "rule two"}, 8, "policy-eight"); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := db.MetricsDB.QueryRow(`SELECT COALESCE(rule_caddy_id,''), COALESCE(policy_id,0), COALESCE(rule_name,''), COALESCE(policy_name,'') FROM security_events WHERE transaction_id='tid-1'`).
		Scan(&ruleID, &policyID, &ruleName, &policyName); err != nil {
		t.Fatal(err)
	}
	if ruleID != "lb_rule2" || policyID != 8 || ruleName != "rule two" || policyName != "policy-eight" {
		t.Fatalf("非空归因必须覆盖: rule=%q policy=%d ruleName=%q policyName=%q", ruleID, policyID, ruleName, policyName)
	}
}

// Given 去重表里同时存在窗口内、恰在窗口边界、窗口外三类条目。
// When 触发清扫。
// Then 只丢窗口外条目（边界键仍可用于归并），清扫计数归零——丢弃边界键会
// 让仍在窗口内的同一请求重新入库成第二条事件。
func TestSecurityEventsRequestDeduper_sweepDropsOnlyOutOfWindowEntries(t *testing.T) {
	const nowSec = int64(7_000_000)
	d := &securityEventsRequestDeduper{
		entries: map[uint64]securityEventsDedupeEntry{
			1: {atSec: nowSec},
			2: {atSec: nowSec - securityEventsDedupeWindowSec},
			3: {atSec: nowSec - securityEventsDedupeWindowSec - 1},
		},
		maxSec:     nowSec,
		sinceSweep: 3,
	}

	d.sweep()

	if d.sinceSweep != 0 {
		t.Fatalf("sinceSweep=%d, want 0（清扫后必须重新计插入间隔，否则每轮 record 都全表扫）", d.sinceSweep)
	}
	if len(d.entries) != 2 {
		t.Fatalf("清扫后条目数=%d, want 2（只丢窗口外）: %+v", len(d.entries), d.entries)
	}
	if _, ok := d.entries[3]; ok {
		t.Fatal("窗口外条目必须被丢弃（否则长跑进程的去重表无界增长）")
	}
	if _, ok := d.entries[2]; !ok {
		t.Fatal("恰在窗口边界的条目必须保留（丢掉会让窗口内的同一请求重复入库）")
	}
	if _, ok := d.lookup(1, nowSec); !ok {
		t.Fatal("窗口内条目清扫后仍须可归并")
	}
}

// Given 去重表已积压陈旧条目，插入计数差一次达到清扫间隔。
// When 再登记一条新键。
// Then record 内部触发清扫（陈旧条目消失、新键可查），计数归零——
// 清扫必须由插入摊销驱动，不能只在显式调用点发生。
func TestSecurityEventsRequestDeduper_recordTriggersSweepAtInterval(t *testing.T) {
	const nowSec = int64(7_000_000)
	d := &securityEventsRequestDeduper{
		entries: map[uint64]securityEventsDedupeEntry{
			9: {atSec: nowSec - securityEventsDedupeWindowSec - 5},
		},
		maxSec:     nowSec - 1,
		sinceSweep: securityEventsDedupeSweepEvery - 1,
	}

	d.record(10, securityEventsDedupeEntry{atSec: nowSec})

	if d.sinceSweep != 0 {
		t.Fatalf("sinceSweep=%d, want 0（达到插入间隔必须触发清扫）", d.sinceSweep)
	}
	if _, ok := d.entries[9]; ok {
		t.Fatalf("陈旧条目未被清扫: %+v", d.entries)
	}
	if _, ok := d.lookup(10, nowSec); !ok {
		t.Fatalf("新登记的键必须可归并: %+v", d.entries)
	}
	if _, ok := d.lookup(9, nowSec); ok {
		t.Fatal("已清扫的陈旧键不得再命中窗口")
	}
}
