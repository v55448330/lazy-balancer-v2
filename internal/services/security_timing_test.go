package services

import (
	"os"
	"path/filepath"
	"testing"
)

// Given: 耗时侧车文件含合法/畸形/空白混合行
// When: securityTimingLoad 全量读入
// Then: 合法行进 map、畸形行跳过、文件被截断为 0
func TestSecurityTimingLoad_parsesAndTruncates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "security-timing.log")
	content := "abc12345 42\ndef67890 7\n\nbadline\nid_only\nneg -5\nzzz99999 0\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	origPath := securityTimingLogPath
	securityTimingLogPath = path
	// SEC-B-GAP-U6（第 69 轮）：隔离闭环——map 跨 load 保活（合并语义），
	// 残留键会泄漏给后续用例；与 missingFile/stageDuration 三例同型归零。
	defer func() { securityTimingLogPath = origPath; securityTimingTickMap = nil }()

	securityTimingLoad()

	// 合法行命中
	if v, ok := securityTimingLookup("abc12345"); !ok || v != 42 {
		t.Errorf("lookup(abc12345) = %d,%v; want 42,true", v, ok)
	}
	if v, ok := securityTimingLookup("def67890"); !ok || v != 7 {
		t.Errorf("lookup(def67890) = %d,%v; want 7,true", v, ok)
	}
	if v, ok := securityTimingLookup("zzz99999"); !ok || v != 0 {
		t.Errorf("lookup(zzz99999) = %d,%v; want 0,true (0ms is valid)", v, ok)
	}
	// 畸形行 miss
	if _, ok := securityTimingLookup("badline"); ok {
		t.Error("lookup(badline) should miss")
	}
	if _, ok := securityTimingLookup("id_only"); ok {
		t.Error("lookup(id_only) should miss")
	}
	if _, ok := securityTimingLookup("neg"); ok {
		t.Error("lookup(neg) should miss (negative rejected)")
	}

	// 文件截断为 0
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != 0 {
		t.Errorf("timing file size after load = %d; want 0 (truncated)", st.Size())
	}
}

// Given: 侧车文件不存在(首启动/无安全流量)
// When: securityTimingLoad
// Then: 静默降级——map 为 nil、lookup 全 miss、不 panic
func TestSecurityTimingLoad_missingFileSilentDegradation(t *testing.T) {
	origPath := securityTimingLogPath
	securityTimingLogPath = filepath.Join(t.TempDir(), "nonexistent.log")
	securityTimingTickMap = nil // 隔离前测残留(合并语义下 map 跨 load 保活)
	defer func() { securityTimingLogPath = origPath; securityTimingTickMap = nil }()

	securityTimingLoad()

	// 合并语义(2026-09-27):首启动即建空 map(非 nil),查表 miss 即耗时 0
	if securityTimingTickMap == nil || len(securityTimingTickMap) != 0 {
		t.Errorf("tick map = %v; want empty non-nil map on missing file", securityTimingTickMap)
	}
	if _, ok := securityTimingLookup("anything"); ok {
		t.Error("lookup should miss on nil map")
	}
}

// Given: 审计条目请求头含 timing ID 且耗时表有该 ID
// When: securityEventsParseTransaction
// Then: DurationUs 命中写入 record
func TestSecurityEventsParseTransaction_durationFromTimingHeader(t *testing.T) {
	const auditJSON = `{"transaction":{"unix_timestamp":1790452183279764883,"id":"ABtibGJndZlGPDP1","client_ip":"::1","server_id":"test.example.com","request":{"method":"GET","uri":"/","headers":{"host":["test.example.com"],"x-lb-rule-id":["lb_test"],"x-lb-security-timing-id":["abc12345"]}},"is_interrupted":true},"messages":[{"message":"test","data":{"id":"942100","raw":""}}]}`

	dir := t.TempDir()
	path := filepath.Join(dir, "security-timing.log")
	if err := os.WriteFile(path, []byte("abc12345:pre 100\nabc12345:end 5000\n"), 0644); err != nil {
		t.Fatal(err)
	}
	origPath := securityTimingLogPath
	securityTimingLogPath = path
	defer func() { securityTimingLogPath = origPath; securityTimingTickMap = nil }() // SEC-B-GAP-U6：隔离闭环（同前例）
	securityTimingLoad()

	rec, err := securityEventsParseTransaction([]byte(auditJSON))
	if err != nil {
		t.Fatal(err)
	}
	// 审计条目规则 942100=WAF 段→end-pre=5000-100=4900
	if rec.DurationUs != 4900 {
		t.Errorf("DurationUs = %d; want 4900 (end 5000 - pre 100, WAF 段隔离)", rec.DurationUs)
	}
	if rec.Action != "blocked" {
		t.Errorf("Action = %q; want blocked", rec.Action)
	}
}

// Given: 审计条目无 timing 头(历史条目/Caddy 旧版本)
// When: securityEventsParseTransaction
// Then: DurationUs 保持 0(不报错)
func TestSecurityEventsParseTransaction_noTimingHeaderZeroDuration(t *testing.T) {
	const auditJSON = `{"transaction":{"unix_timestamp":1790452183279764883,"id":"ABtibGJndZlGPDP1","client_ip":"::1","server_id":"test.example.com","request":{"method":"GET","uri":"/","headers":{"host":["test.example.com"]}},"is_interrupted":true},"messages":[{"message":"test","data":{"id":"942100","raw":""}}]}`

	rec, err := securityEventsParseTransaction([]byte(auditJSON))
	if err != nil {
		t.Fatal(err)
	}
	if rec.DurationUs != 0 {
		t.Errorf("DurationUs = %d; want 0 (no header)", rec.DurationUs)
	}
}

// Given: 预检段规则(id:2 IP ACL)事件 + 侧车 :pre/:end 并存
// When: securityEventsStageDuration
// Then: 预检段取 :pre(100),不取 :end(5000)
func TestSecurityEventsStageDuration_precheckRuleTakesPre(t *testing.T) {
	securityTimingTickMap = map[string]int64{
		"tid1:pre": 100,
		"tid1:end": 5000,
	}
	defer func() { securityTimingTickMap = nil }()
	if v := securityEventsStageDuration("tid1", "2"); v != 100 {
		t.Errorf("precheck rule duration = %d; want 100 (:pre)", v)
	}
	if v := securityEventsStageDuration("tid1", "942100"); v != 4900 {
		t.Errorf("WAF rule duration = %d; want 4900 (:end-:pre)", v)
	}
}

// Given: 预检拦截(:pre 未写,仅 :end)——预检段规则回退 :end
func TestSecurityEventsStageDuration_precheckBlockFallback(t *testing.T) {
	securityTimingTickMap = map[string]int64{"tid2:end": 350}
	defer func() { securityTimingTickMap = nil }()
	if v := securityEventsStageDuration("tid2", "2"); v != 350 {
		t.Errorf("precheck block duration = %d; want 350 (:end fallback)", v)
	}
}

// Given: WAF 段事件 :pre 竞态 miss——回退 :end 全链值
func TestSecurityEventsStageDuration_wafPreMissFallback(t *testing.T) {
	securityTimingTickMap = map[string]int64{"tid3:end": 6475}
	defer func() { securityTimingTickMap = nil }()
	if v := securityEventsStageDuration("tid3", "942100"); v != 6475 {
		t.Errorf("WAF pre-miss duration = %d; want 6475 (:end fallback)", v)
	}
}
