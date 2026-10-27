package ownership

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// 账本保留期：超过 OwnershipRetention 的已归属条目在下一次写入时退役，
// 避免历史域名/失败中断的条目永久滞留；无法证明年龄的 legacy 条目保留。
func TestStore_saveRetiresExpiredEntries(t *testing.T) {
	dir := t.TempDir()
	store, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	// 用 Replace 预置「已落盘」的存量（Add 写入期也会剪枝，无法构造该前提）。
	snapshot := `{"version":1,"records":[
		{"provider":"dnspod","zone":"example.com","fqdn":"_acme-challenge.example.com","value":"v1","record_id":"1","created_at":"` +
		time.Now().Add(-OwnershipRetention-time.Hour).UTC().Format(time.RFC3339) + `"},
		{"provider":"dnspod","zone":"example.com","fqdn":"_acme-challenge.example.com","value":"v3","record_id":"3"}
	]}`
	if err := Replace(dir, []byte(snapshot)); err != nil {
		t.Fatal(err)
	}
	if err := store.Add(Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com", Value: "v2", RecordID: "2"}); err != nil {
		t.Fatal(err)
	}
	matching, err := store.Matching("dnspod", "example.com", "_acme-challenge.example.com")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, rec := range matching {
		seen[rec.Value] = true
	}
	if seen["v1"] {
		t.Fatal("超过保留期的存量条目应退役")
	}
	for _, want := range []string{"v2", "v3"} {
		if !seen[want] {
			t.Fatalf("条目 %s 不应被退役（seen=%v）", want, seen)
		}
	}
}

// 退役必须有日志：账本条目消失属于「数据被删」，运维需要可见（单行、含条数）。
func TestStore_saveLogsRetiredEntryCount(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var lines []string
	prev := logf
	SetLogf(func(level, format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, level+" "+fmt.Sprintf(format, args...))
	})
	t.Cleanup(func() { SetLogf(prev) })

	// 写入一个已超保留期的条目：写入期剪枝即触发退役日志。
	old := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com", Value: "v1", RecordID: "1", CreatedAt: time.Now().Add(-OwnershipRetention - time.Hour)}
	if err := store.Add(old); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "退役 1 条") {
		t.Fatalf("退役日志缺失或条数不符: %q", joined)
	}
	if !strings.Contains(joined, "info") {
		t.Fatalf("退役日志级别应为 info: %q", joined)
	}
}

// 保留期边界精度：只测「超期 1h」时把 `>` 改成 `>=`、或把阈值写成 30 天 ±
// 数小时都不会红。这里以「保留期 -1 分钟」与「保留期 +1 分钟」夹住阈值，
// 并同时确认零 CreatedAt 的 legacy 条目（无法证明年龄）继续保留。
func TestStore_saveRetiresOnlyBeyondRetentionBoundary(t *testing.T) {
	dir := t.TempDir()
	store, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	within := time.Now().Add(-OwnershipRetention + time.Minute).UTC().Format(time.RFC3339)
	beyond := time.Now().Add(-OwnershipRetention - time.Minute).UTC().Format(time.RFC3339)
	snapshot := `{"version":1,"records":[
		{"provider":"dnspod","zone":"example.com","fqdn":"_acme-challenge.example.com","value":"within","record_id":"1","created_at":"` + within + `"},
		{"provider":"dnspod","zone":"example.com","fqdn":"_acme-challenge.example.com","value":"beyond","record_id":"2","created_at":"` + beyond + `"},
		{"provider":"dnspod","zone":"example.com","fqdn":"_acme-challenge.example.com","value":"legacy","record_id":"3"}
	]}`
	if err := Replace(dir, []byte(snapshot)); err != nil {
		t.Fatal(err)
	}

	if err := store.Add(Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com", Value: "fresh", RecordID: "4"}); err != nil {
		t.Fatal(err)
	}
	matching, err := store.Matching("dnspod", "example.com", "_acme-challenge.example.com")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, rec := range matching {
		seen[rec.Value] = true
	}
	if seen["beyond"] {
		t.Fatal("超过保留期 1 分钟的条目应退役")
	}
	for _, want := range []string{"within", "legacy", "fresh"} {
		if !seen[want] {
			t.Fatalf("条目 %s 不应被退役（seen=%v）", want, seen)
		}
	}
}

// 退役的运维含义必须在日志里说清：能留在账本里超过保留期的条目，按构造都是
// 「删除未确认」的（成功删除的条目早被 Remove）——退役只动本地文件，远端
// `_acme-challenge` TXT 可能继续存在。日志只说「退役 N 条」会让运维误以为远端
// 已回收，30 天累积后区里留下同域多条 TXT 增加排障成本。
func TestStore_saveRetirementLogStatesRemoteResidue(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var lines []string
	prev := logf
	SetLogf(func(level, format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, level+" "+fmt.Sprintf(format, args...))
	})
	t.Cleanup(func() { SetLogf(prev) })

	old := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com", Value: "v1", RecordID: "1", CreatedAt: time.Now().Add(-OwnershipRetention - time.Hour)}
	if err := store.Add(old); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "退役 1 条") {
		t.Fatalf("退役日志缺失或条数不符: %q", joined)
	}
	if !strings.Contains(joined, "残留") {
		t.Fatalf("退役日志未说明远端记录可能残留: %q", joined)
	}
	// 仍不得扩散用户数据（FQDN/记录 ID/值）。
	for _, leak := range []string{"_acme-challenge.example.com", "record_id", "v1"} {
		if strings.Contains(joined, leak) {
			t.Fatalf("退役日志扩散了用户数据 %q: %q", leak, joined)
		}
	}
}
