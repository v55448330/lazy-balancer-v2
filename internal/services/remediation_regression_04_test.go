package services

//   caddyPayload 按 __lazy_balancer_ 前缀整体剔除内部键——降级标记
//     （degradation）/生成错误（generation_error）/证书快照（cert_files_snapshot）
//     及未来新增内部键一律不得进 Caddy 载荷（真 Caddy StrictUnmarshalJSON 拒
//     未知顶层字段，内部键漏网会让降级配置被 400 硬拒，可用性优先被反转）。
//   autobanCandidates 先评估后修剪——窗口到期但桶内计数已跨阈值的 IP
//     必须并入候选执行封禁并留审计（旧行为先修剪后评估，桶尾跨阈值 IP 永不
//     封禁，threshold 日志宣称达标却无处置）。

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// TestCaddyPayload_stripsAllInternalKeys：携带全部内部键的 conf 经 caddyPayload
// 编码后，产物不得含任何 __lazy_balancer_ 前缀键，合法顶层键原样保留。
func TestCaddyPayload_stripsAllInternalKeys(t *testing.T) {
	conf := map[string]interface{}{
		"admin":                       map[string]interface{}{"disabled": true},
		"apps":                        map[string]interface{}{"http": map[string]interface{}{}},
		"logging":                     map[string]interface{}{},
		caddyConfigDegradationKey:     "受信代理网段配置解析失败，按未启用渲染",
		caddyConfigGenerationErrorKey: "boom",
		caddyCertFilesSnapshotKey:     CertFilesSnapshot{"/tmp/cert.pem": {}},
	}
	data, err := json.Marshal(caddyPayload(conf))
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	for key := range out {
		if strings.HasPrefix(key, "__lazy_balancer_") {
			t.Fatalf("内部键 %s 不得进 Caddy 载荷（真 Caddy 严格解码会 400）", key)
		}
	}
	for _, legit := range []string{"admin", "apps", "logging"} {
		if _, ok := out[legit]; !ok {
			t.Fatalf("合法顶层键 %s 不得被剔除，载荷=%s", legit, data)
		}
	}
}

// TestAutobanRunCycle_expiredBucketStillBans：feed 跨阈值后未再触发新
// 事件，跨过一个调度 tick（窗口到期）再跑一轮——桶尾跨阈值形态必须照样封禁
// 并落「自动封禁」审计（旧行为先修剪后评估会把整桶丢弃，永不封禁）。
func TestAutobanRunCycle_expiredBucketStillBans(t *testing.T) {
	f := installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 2, 5, "1h", "blocked,logged", false)
	reloads := 0
	oldFn := autobanReloader
	autobanReloader = func() error { reloads++; return nil }
	t.Cleanup(func() { autobanReloader = oldFn })
	autobanObserveEvent("203.0.113.9", "blocked", "942100")
	autobanObserveEvent("203.0.113.9", "blocked", "942100")
	// 越过一个 tick（60s 循环）：窗口（5min）已到期、无新事件喂入。
	f.Advance(6 * time.Minute)

	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("RunAutobanCycle: %v", err)
	}
	entries := presetEntries(t)
	if len(entries) != 1 || entries[0].Value != "203.0.113.9" {
		t.Fatalf("窗口到期但已跨阈值的 IP 必须落名单（先评估后修剪），得到 %+v", entries)
	}
	var n int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE username='system' AND action='自动封禁' AND detail LIKE '%203.0.113.9%'`).Scan(&n); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if n != 1 {
		t.Fatalf("封禁必须留审计在案，命中 %d 条", n)
	}
}
