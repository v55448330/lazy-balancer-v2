package ownership

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	return store
}

// writeRawStore persists a raw ownership file, simulating records written by
// an older binary (no value / created_at fields).
func writeRawStore(t *testing.T, store *Store, records []map[string]any) {
	t.Helper()
	payload := map[string]any{"version": 1, "records": records}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal raw store: %v", err)
	}
	if err := os.WriteFile(store.path, data, 0600); err != nil {
		t.Fatalf("write raw store: %v", err)
	}
}

func readStoreRecords(t *testing.T, store *Store) []Record {
	t.Helper()
	data, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	var current state
	if err := json.Unmarshal(data, &current); err != nil {
		t.Fatalf("decode store: %v", err)
	}
	return current.Records
}

func TestStore_MatchingValue_spares_concurrent_same_name_value(t *testing.T) {
	// Given: two concurrent issuances presented different values for the
	// same challenge name
	store := newStore(t)
	alpha := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.", Value: "alpha", RecordID: "200"}
	beta := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.", Value: "beta", RecordID: "201"}
	if err := store.Add(alpha); err != nil {
		t.Fatalf("add alpha: %v", err)
	}
	if err := store.Add(beta); err != nil {
		t.Fatalf("add beta: %v", err)
	}

	// When: the alpha issuance looks up the records it may clean
	matching, err := store.MatchingValue("dnspod", "example.com", "_acme-challenge.example.com.", "alpha")
	if err != nil {
		t.Fatalf("matching value: %v", err)
	}

	// Then: only alpha's record is returned; beta's live record is spared
	if len(matching) != 1 {
		t.Fatalf("matching=%v, want only alpha", matching)
	}
	if matching[0].Value != "alpha" || matching[0].RecordID != "200" {
		t.Fatalf("matching[0]=%+v, want alpha/200", matching[0])
	}
}

func TestStore_MatchingValue_includes_legacy_entries_best_effort(t *testing.T) {
	// Given: a legacy file from before value tracking, plus a live record
	// with a known value
	store := newStore(t)
	writeRawStore(t, store, []map[string]any{
		{"provider": "dnspod", "zone": "example.com", "fqdn": "_acme-challenge.example.com.", "record_id": "100"},
	})
	live := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.", Value: "beta", RecordID: "201"}
	if err := store.Add(live); err != nil {
		t.Fatalf("add live: %v", err)
	}

	// When
	matching, err := store.MatchingValue("dnspod", "example.com", "_acme-challenge.example.com.", "alpha")
	if err != nil {
		t.Fatalf("matching value: %v", err)
	}

	// Then: the legacy entry (empty value) is included best-effort; the live
	// beta record is not
	if len(matching) != 1 {
		t.Fatalf("matching=%v, want legacy entry only", matching)
	}
	if matching[0].RecordID != "100" || matching[0].Value != "" {
		t.Fatalf("matching[0]=%+v, want legacy 100", matching[0])
	}
}

func TestStore_MatchingValue_includes_stale_but_spares_recent(t *testing.T) {
	// Given: a provably stale record (older than any live issuance budget),
	// a recent record of another value, and our own record
	store := newStore(t)
	stale := Record{
		Provider:  "dnspod",
		Zone:      "example.com",
		FQDN:      "_acme-challenge.example.com.",
		Value:     "abandoned-order",
		RecordID:  "100",
		CreatedAt: time.Now().Add(-(StaleOwnershipAge + time.Minute)),
	}
	if err := store.Add(stale); err != nil {
		t.Fatalf("add stale: %v", err)
	}
	recent := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.", Value: "beta", RecordID: "201"}
	if err := store.Add(recent); err != nil {
		t.Fatalf("add recent: %v", err)
	}
	mine := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.", Value: "alpha", RecordID: "202"}
	if err := store.Add(mine); err != nil {
		t.Fatalf("add mine: %v", err)
	}

	// When
	matching, err := store.MatchingValue("dnspod", "example.com", "_acme-challenge.example.com.", "alpha")
	if err != nil {
		t.Fatalf("matching value: %v", err)
	}

	// Then: mine and the stale record are cleanable; beta's recent record
	// may belong to a live concurrent challenge and is spared
	byID := make(map[string]bool)
	for _, record := range matching {
		byID[record.RecordID] = true
	}
	if !byID["202"] || !byID["100"] {
		t.Fatalf("matching IDs=%v, want 202 (mine) and 100 (stale)", byID)
	}
	if byID["201"] {
		t.Fatalf("matching IDs=%v, recent concurrent record 201 must be spared", byID)
	}
}

func TestStore_MatchingValue_empty_value_falls_back_to_name_match(t *testing.T) {
	// Given: two records with different values under the same name
	store := newStore(t)
	if err := store.Add(Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.", Value: "alpha", RecordID: "200"}); err != nil {
		t.Fatalf("add alpha: %v", err)
	}
	if err := store.Add(Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.", Value: "beta", RecordID: "201"}); err != nil {
		t.Fatalf("add beta: %v", err)
	}

	// When: no value filter
	matching, err := store.MatchingValue("dnspod", "example.com", "_acme-challenge.example.com.", "")
	if err != nil {
		t.Fatalf("matching value: %v", err)
	}

	// Then: legacy name-based semantics return both
	if len(matching) != 2 {
		t.Fatalf("matching=%v, want both records", matching)
	}
}

func TestStore_Add_timestamps_new_records(t *testing.T) {
	// Given
	store := newStore(t)
	record := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.", Value: "alpha", RecordID: "200"}

	// When
	if err := store.Add(record); err != nil {
		t.Fatalf("add: %v", err)
	}

	// Then: new writes carry created_at so future staleness decisions work
	records := readStoreRecords(t, store)
	if len(records) != 1 || records[0].CreatedAt.IsZero() {
		t.Fatalf("records=%+v, want created_at persisted", records)
	}
}

func TestStore_Remove_missing_record_is_idempotent(t *testing.T) {
	// Given
	store := newStore(t)
	present := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.", Value: "alpha", RecordID: "200"}
	if err := store.Add(present); err != nil {
		t.Fatalf("add: %v", err)
	}
	neverAdded := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.", Value: "ghost", RecordID: "999"}

	// When: cleanup deletes a record that is no longer tracked
	if err := store.Remove(neverAdded); err != nil {
		t.Fatalf("remove missing record: %v", err)
	}
	if err := store.Remove(neverAdded); err != nil {
		t.Fatalf("remove missing record twice: %v", err)
	}

	// Then: the file is unchanged and the present record survives
	records := readStoreRecords(t, store)
	if len(records) != 1 || records[0].RecordID != "200" {
		t.Fatalf("records=%+v, want only record 200", records)
	}
}

func TestStore_loads_legacy_file_without_value_fields(t *testing.T) {
	// Given: a file written by the previous format
	store := newStore(t)
	writeRawStore(t, store, []map[string]any{
		{"provider": "dnspod", "zone": "example.com", "fqdn": "_acme-challenge.example.com.", "record_id": "100"},
	})

	// When
	matching, err := store.Matching("dnspod", "example.com", "_acme-challenge.example.com.")
	if err != nil {
		t.Fatalf("matching: %v", err)
	}

	// Then
	if len(matching) != 1 || matching[0].RecordID != "100" || matching[0].Value != "" {
		t.Fatalf("matching=%+v, want legacy record 100", matching)
	}
}

func TestStore_ownership_file_name(t *testing.T) {
	// Given/When
	dir := t.TempDir()
	store, err := New(dir)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	// Then: stable file name so existing deployments keep their ownership data
	if store.path != filepath.Join(dir, ownershipFileName) {
		t.Fatalf("path=%s, want %s", store.path, filepath.Join(dir, ownershipFileName))
	}
}

func TestStore_quarantines_undecodable_state_file(t *testing.T) {
	// Given: an undecodable ownership file (e.g. truncated by a crash) that
	// would otherwise brick every Add/MatchingValue/Remove
	store := newStore(t)
	corrupt := `{"version":1,"records":[{`
	if err := os.WriteFile(store.path, []byte(corrupt), 0600); err != nil {
		t.Fatalf("seed corrupt store: %v", err)
	}

	// When: the next operation needs the state
	fresh := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.", Value: "alpha", RecordID: "200"}
	if err := store.Add(fresh); err != nil {
		t.Fatalf("add after corruption: %v", err)
	}

	// Then: the corrupt bytes are preserved under .corrupt-* for inspection
	// and the state file was rewritten clean with only the new record
	quarantined, err := filepath.Glob(store.path + ".corrupt-*")
	if err != nil {
		t.Fatalf("glob quarantined files: %v", err)
	}
	if len(quarantined) != 1 {
		t.Fatalf("quarantined files=%v, want exactly one", quarantined)
	}
	original, err := os.ReadFile(quarantined[0])
	if err != nil {
		t.Fatalf("read quarantined file: %v", err)
	}
	if string(original) != corrupt {
		t.Fatalf("quarantined content=%q, want original corrupt bytes %q", original, corrupt)
	}
	records := readStoreRecords(t, store)
	if len(records) != 1 || records[0].RecordID != "200" {
		t.Fatalf("records=%+v, want fresh record 200 only", records)
	}
}

func TestStore_quarantines_unsupported_version_state_file(t *testing.T) {
	// Given: a state file written by a future binary (unknown version)
	store := newStore(t)
	if err := os.WriteFile(store.path, []byte(`{"version":2,"records":[]}`), 0600); err != nil {
		t.Fatalf("seed future-version store: %v", err)
	}

	// When: reads keep working and a later write republishes a clean file
	if _, err := store.MatchingValue("dnspod", "example.com", "_acme-challenge.example.com.", "alpha"); err != nil {
		t.Fatalf("matching after version mismatch: %v", err)
	}
	if err := store.Add(Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.", Value: "alpha", RecordID: "200"}); err != nil {
		t.Fatalf("add after version mismatch: %v", err)
	}

	// Then: the future-version file was quarantined, not silently reset
	quarantined, err := filepath.Glob(store.path + ".corrupt-*")
	if err != nil {
		t.Fatalf("glob quarantined files: %v", err)
	}
	if len(quarantined) != 1 {
		t.Fatalf("quarantined files=%v, want exactly one", quarantined)
	}
	if records := readStoreRecords(t, store); len(records) != 1 || records[0].RecordID != "200" {
		t.Fatalf("records=%+v, want fresh record 200 only", records)
	}
}

// 隔离文件名原为秒级时间戳——同一秒内二次损坏时
// os.Rename 覆盖上一份隔离文件（POSIX rename 语义），取证样本丢失。判定用
// 固定时钟（corruptClock 接缝）制造同刻碰撞：两轮损坏必须留下两份独立样本。
func TestStore_quarantineKeepsDistinctSamplesOnClockCollision(t *testing.T) {
	original := corruptClock
	corruptClock = func() time.Time { return time.Unix(1700000000, 0) }
	t.Cleanup(func() { corruptClock = original })

	store := newStore(t)
	corrupt := `{"version":1,"records":[{`
	for round := range 2 {
		if err := os.WriteFile(store.path, []byte(corrupt), 0600); err != nil {
			t.Fatalf("seed corrupt store (round %d): %v", round, err)
		}
		if err := store.Add(Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.",
			Value: "alpha", RecordID: strconv.Itoa(200 + round)}); err != nil {
			t.Fatalf("add after corruption (round %d): %v", round, err)
		}
	}

	quarantined, err := filepath.Glob(store.path + ".corrupt-*")
	if err != nil {
		t.Fatalf("glob quarantined files: %v", err)
	}
	if len(quarantined) != 2 {
		t.Fatalf("quarantined files=%v, want two distinct samples（同秒碰撞不得互相覆盖）", quarantined)
	}
	for _, path := range quarantined {
		original, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read quarantined %s: %v", path, readErr)
		}
		if string(original) != corrupt {
			t.Fatalf("quarantined %s content=%q, want corrupt bytes %q", path, original, corrupt)
		}
	}
}

func TestStore_concurrent_stores_mixed_operations(t *testing.T) {
	// Given: two Store instances over the same file (writer plus a
	// restarted reader) and concurrent goroutines mixing Add / Remove /
	// MatchingValue; the package-level fileMu must serialize every access
	dir := t.TempDir()
	storeA, err := New(dir)
	if err != nil {
		t.Fatalf("create store A: %v", err)
	}
	storeB, err := New(dir)
	if err != nil {
		t.Fatalf("create store B: %v", err)
	}

	const goroutines = 8
	const iterations = 25
	fqdn := "_acme-challenge.example.com."
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			store := storeA
			if g%2 == 1 {
				store = storeB
			}
			for i := 0; i < iterations; i++ {
				record := Record{
					Provider:  "dnspod",
					Zone:      "example.com",
					FQDN:      fqdn,
					Value:     fmt.Sprintf("v-%d-%d", g, i),
					RecordID:  strconv.Itoa(g*1000 + i),
					CreatedAt: time.Now(),
				}
				if err := store.Add(record); err != nil {
					t.Errorf("goroutine %d add %d: %v", g, i, err)
					return
				}
				if i%2 == 0 {
					// Remove must receive the disk-round-tripped record (as
					// the providers do via MatchingValue): the local struct's
					// CreatedAt keeps nanosecond precision and would not
					// compare equal after the JSON round trip
					matching, err := store.MatchingValue("dnspod", "example.com", fqdn, record.Value)
					if err != nil {
						t.Errorf("goroutine %d matching %d: %v", g, i, err)
						return
					}
					found := false
					for _, candidate := range matching {
						if candidate.RecordID == record.RecordID {
							found = true
							if err := store.Remove(candidate); err != nil {
								t.Errorf("goroutine %d remove %d: %v", g, i, err)
								return
							}
						}
					}
					if !found {
						t.Errorf("goroutine %d: added record %d not visible to matching", g, i)
						return
					}
				}
			}
		}(g)
	}
	wg.Wait()

	// Then: the final file decodes and holds exactly the never-removed
	// records — odd iterations of every goroutine, each exactly once
	records := readStoreRecords(t, storeA)
	got := make(map[string]int, len(records))
	for _, record := range records {
		got[record.RecordID]++
	}
	if len(records) != goroutines*(iterations/2) {
		t.Fatalf("records=%d, want %d", len(records), goroutines*(iterations/2))
	}
	for g := 0; g < goroutines; g++ {
		for i := 0; i < iterations; i++ {
			count := got[strconv.Itoa(g*1000+i)]
			if i%2 == 0 && count != 0 {
				t.Fatalf("removed record %d-%d still present %d time(s)", g, i, count)
			}
			if i%2 == 1 && count != 1 {
				t.Fatalf("record %d-%d present %d time(s), want exactly 1", g, i, count)
			}
		}
	}
}

// Remove 的相等判定必须按语义（CreatedAt.Equal）——
// Record 内联 == 比较含 time.Time 的表示细节（monotonic 位、loc 指针），
// 语义相同的记录被判不等 → Remove 静默 no-op，记录永久残留两种真实形态：
//  1. 调用方持有写入时的原值（time.Now() 带 monotonic）与文件读回值比较；
//  2. 文件记录时区与当前进程 Local 不同（时区设置变更后重启）——两侧各
//     解析出独立 FixedZone 指针。
func TestStore_Remove_semantic_match_after_reload(t *testing.T) {
	for _, tc := range []struct {
		name      string
		createdAt time.Time
	}{
		{"in_memory_original_with_monotonic", time.Now()},
		{"non_local_fixed_zone", time.Now().Add(-time.Minute).In(time.FixedZone("legacy", 3600))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newStore(t)
			record := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.",
				Value: "alpha", RecordID: "200", CreatedAt: tc.createdAt}
			if err := store.Add(record); err != nil {
				t.Fatalf("add: %v", err)
			}
			// When：持有写入原值 Remove（Add 保留调用方时间戳——CreatedAt 非零
			// 时不重写；形态 2 的 FixedZone 与形态 1 的 monotonic 均在此）。
			if err := store.Remove(record); err != nil {
				t.Fatalf("remove: %v", err)
			}
			// Then：语义相等的记录必须被删除（旧内联 == 比较 no-op 残留）。
			if records := readStoreRecords(t, store); len(records) != 0 {
				t.Fatalf("语义相等的记录未被删除（Remove no-op）：%+v", records)
			}
		})
	}
}

func TestReplace_sharesStoreLockAndPreservesStateOnInvalidSnapshot(t *testing.T) {
	// Given：一个由集群快照携带的合法 ownership 状态。
	dir := t.TempDir()
	initial := []byte(`{"version":1,"records":[]}`)
	if err := Replace(dir, initial); err != nil {
		t.Fatalf("replace initial snapshot: %v", err)
	}
	path := filepath.Join(dir, ownershipFileName)
	if got, err := os.ReadFile(path); err != nil || string(got) != string(initial) {
		t.Fatalf("initial snapshot=(%q,%v), want exact raw bytes", got, err)
	}

	// When：Store 的读写锁被持有时，快照替换必须等待同一把锁。
	// 旧形态靠固定墙钟窗口判定「goroutine 尚未返回」：负载高时 goroutine
	// 根本没被调度到 fileMu.Lock()，断言就在「什么都没观察到」的情况下通过
	// （真空断言）。现改用两个确定性测试缝，不再依赖调度时序：
	//   ① beforeReplaceWrite 在持锁写盘的瞬间触发，缝内 TryLock 探测——
	//      若 Replace 丢掉 fileMu.Lock()，探测成功（=无人持锁）即记违纪，
	//      与 goroutine 何时被调度无关；
	//   ② beforeReplaceLock 在取锁前触发，据此得知「Replace 已到加锁点」，
	//      用它作争用屏障而不是 sleep。
	replacement := []byte(`{"version":1,"records":[{"provider":"dnspod","zone":"example.com","fqdn":"_acme-challenge.example.com.","value":"token","record_id":"200"}]}`)
	t.Cleanup(func() { beforeReplaceLock, beforeReplaceWrite = func() {}, func() {} })
	wroteWithoutLock := false
	beforeReplaceWrite = func() {
		if fileMu.TryLock() {
			fileMu.Unlock()
			wroteWithoutLock = true
		}
	}
	if err := Replace(dir, replacement); err != nil {
		t.Fatalf("replace replacement snapshot: %v", err)
	}
	if wroteWithoutLock {
		t.Fatal("Replace 写盘时未持有 Store 的 fileMu（锁共享契约被破坏）")
	}

	contended := []byte(`{"version":1,"records":[{"provider":"dnspod","zone":"example.com","fqdn":"_acme-challenge.example.com.","value":"contended","record_id":"202"}]}`)
	fileMu.Lock()
	atLockPoint := make(chan struct{})
	beforeReplaceLock = func() { close(atLockPoint) }
	done := make(chan error, 1)
	go func() { done <- Replace(dir, contended) }()
	<-atLockPoint // 屏障：Replace 已到 fileMu.Lock()，不再猜时间窗
	beforeReplaceLock = func() {}
	if got, readErr := os.ReadFile(path); readErr != nil || string(got) != string(replacement) {
		fileMu.Unlock()
		t.Fatalf("Replace wrote the file while store fileMu was held: content=%q err=%v", got, readErr)
	}
	fileMu.Unlock()
	if err := <-done; err != nil {
		t.Fatalf("replace after store lock release: %v", err)
	}
	if got, readErr := os.ReadFile(path); readErr != nil || string(got) != string(contended) {
		t.Fatalf("replace did not apply the snapshot after lock release: content=%q err=%v", got, readErr)
	}

	// Then：非法快照不得破坏已提交状态；普通 Store.Add 仍可继续复用同一文件。
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read committed replacement: %v", err)
	}
	for _, invalid := range [][]byte{[]byte(`{"version":`), []byte(`{"version":2,"records":[]}`), []byte(`{"version":1}`)} {
		if err := Replace(dir, invalid); err == nil {
			t.Fatalf("Replace accepted invalid snapshot %q", invalid)
		}
		after, readErr := os.ReadFile(path)
		if readErr != nil || string(after) != string(before) {
			t.Fatalf("invalid snapshot changed committed state: after=%q err=%v", after, readErr)
		}
	}
	store, err := New(dir)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	if err := store.Add(Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.", Value: "second", RecordID: "201"}); err != nil {
		t.Fatalf("add after snapshot replacement: %v", err)
	}
	if records := readStoreRecords(t, store); len(records) != 2 {
		t.Fatalf("records=%+v, want replacement plus newly added record", records)
	}
}

// Account 是 Remove 相等判定的一部分——同一 name/value/
// record_id 但账户不同的两条记录（换凭据后的历史残留 vs 当前账户条目）必须
// 各自可独立移除，丢弃一条不得连带删掉另一条。
func TestStore_Remove_keepsOtherAccountEntryWithSameRecordID(t *testing.T) {
	store := newStore(t)
	createdAt := time.Now().Add(-2 * time.Hour)
	legacy := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.",
		Value: "alpha", RecordID: "500", CreatedAt: createdAt}
	current := legacy
	current.Account = AccountDigest("id,token")
	for _, record := range []Record{legacy, current} {
		if err := store.Add(record); err != nil {
			t.Fatalf("add %+v: %v", record, err)
		}
	}

	// When：丢弃他账户条目（legacy）
	if err := store.Remove(legacy); err != nil {
		t.Fatalf("remove legacy: %v", err)
	}

	// Then：本账户条目仍在
	records := readStoreRecords(t, store)
	if len(records) != 1 || records[0].Account != AccountDigest("id,token") {
		t.Fatalf("records=%+v, want 仅保留本账户条目", records)
	}
}

// 账户归属判定表（dnspod/tencent 两厂商共用单源）。
func TestDecideRemoval_table(t *testing.T) {
	now := time.Now()
	stale := now.Add(-2 * time.Hour)
	recent := now.Add(-time.Minute)
	const mine = "mine0000"
	for _, tc := range []struct {
		name   string
		record Record
		want   Disposition
	}{
		{"本账户新条目可删", Record{Account: mine, CreatedAt: recent}, DispositionDelete},
		{"本账户陈旧条目可删", Record{Account: mine, CreatedAt: stale}, DispositionDelete},
		{"他账户条目只丢弃", Record{Account: "other000", CreatedAt: stale}, DispositionDrop},
		{"他账户新条目同样只丢弃", Record{Account: "other000", CreatedAt: recent}, DispositionDrop},
		{"legacy 在途条目保持删除语义", Record{CreatedAt: recent}, DispositionDelete},
		{"legacy 陈旧条目只丢弃", Record{CreatedAt: stale}, DispositionDrop},
		{"零值时间 legacy 不判陈旧", Record{}, DispositionDelete},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := DecideRemoval(tc.record, mine, now); got != tc.want {
				t.Fatalf("DecideRemoval = %v, want %v", got, tc.want)
			}
		})
	}
	// 调用方未声明账户：legacy 宽松、带账户条目无法证明归属
	if got := DecideRemoval(Record{Account: mine, CreatedAt: recent}, "", now); got != DispositionDrop {
		t.Fatalf("未声明账户时带账户条目处置=%v, want Drop", got)
	}
}

// 账户摘要不落凭据明文且同凭据稳定（所有权文件是明文 JSON）。
func TestAccountDigest_stableAndOpaque(t *testing.T) {
	first := AccountDigest("id,token")
	if first != AccountDigest("id,token") {
		t.Fatal("同一凭据的摘要不稳定")
	}
	if first == AccountDigest("id,othertoken") {
		t.Fatal("不同凭据得到相同摘要")
	}
	if strings.Contains(first, "token") || len(first) != 16 {
		t.Fatalf("digest=%q, want 16 位十六进制且不含凭据明文", first)
	}
}

// RemoveMany 批量语义：一次调用移除多条记录（单次全量重写），未命中条目
// 静默忽略；零命中时不重写文件（省一次全量 fsync，账本字节零漂移）。
func TestStore_RemoveMany(t *testing.T) {
	store := newStore(t)
	now := time.Now()
	// CreatedAt 显式赋值——Add 会回填零值时间戳，持有原值的调用方与
	// 读回记录靠 sameRecord（CreatedAt.Equal）匹配。
	alpha := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.", Value: "alpha", RecordID: "200", CreatedAt: now}
	beta := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.", Value: "beta", RecordID: "201", CreatedAt: now}
	gamma := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.other.example.com.", Value: "gamma", RecordID: "202", CreatedAt: now}
	for _, record := range []Record{alpha, beta, gamma} {
		if err := store.Add(record); err != nil {
			t.Fatalf("add %+v: %v", record, err)
		}
	}
	if err := store.RemoveMany([]Record{alpha, beta}); err != nil {
		t.Fatalf("remove many: %v", err)
	}
	left := readStoreRecords(t, store)
	if len(left) != 1 || left[0].RecordID != "202" {
		t.Fatalf("records=%+v, want 仅保留 gamma", left)
	}

	// 零命中：文件字节必须原样（无写盘）
	before, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	ghost := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.ghost.example.com.", Value: "ghost", RecordID: "999"}
	if err := store.RemoveMany([]Record{ghost}); err != nil {
		t.Fatalf("zero-hit remove many: %v", err)
	}
	after, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatalf("re-read store: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("零命中 RemoveMany 不得重写账本文件")
	}
	// 空输入快速返回
	if err := store.RemoveMany(nil); err != nil {
		t.Fatalf("empty remove many: %v", err)
	}
}

// 空 dataDir 必须显式拒绝：静默使用当前目录会把账本写进进程工作目录
// （容器里可能是 /app，随镜像重建丢失所有权追踪）。
func TestNew_rejectsEmptyDataDir(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Fatal("New(\"\") 必须报错")
	}
}

func TestStore_writeAtomicUsesSharedPrimitive(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "store.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	fn := ownershipFuncDeclForTest(file, "writeAtomic")
	if fn == nil {
		t.Fatal("writeAtomic not found")
	}
	usesSharedPrimitive := false
	ast.Inspect(fn, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "WriteAtomic" {
			return true
		}
		if pkg, ok := selector.X.(*ast.Ident); ok && pkg.Name == "atomicfile" {
			usesSharedPrimitive = true
		}
		return true
	})
	if !usesSharedPrimitive {
		t.Fatal("ownership persistence must delegate temporary-file cleanup and durability to atomicfile.WriteAtomic")
	}
}

func ownershipFuncDeclForTest(file *ast.File, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}
