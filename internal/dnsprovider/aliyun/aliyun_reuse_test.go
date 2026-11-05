package aliyun

// 同值复用（与 cloudflare/dnspod/tencent 侧同构）：Present 在创建前按
// DescribeDomainRecords 同名 TXT 内容精确匹配复用既有记录 ID——并发/重试双
// 签发不再产生重复 TXT；同名不同值照常创建。复用 ID 与新建 ID 共用同一条
// 登记路径（内存兜底表 / ownership 账本），清理语义不变。

import (
	"testing"

	"lazy-balancer-v2/internal/dnsprovider/ownership"
)

// 同名同值已存在：不调 AddDomainRecord、复用既有记录 ID、内存兜底表登记。
func TestProvider_Present_reusesExistingSameValueRecord(t *testing.T) {
	fake := newFakeAlidns()
	fake.mu.Lock()
	fake.records[777] = fakeRecord{rr: accountMatch, value: testValue}
	fake.mu.Unlock()
	server := newFakeServer(t, fake)
	provider := newFakeProvider(t, server.URL, 3)

	if err := provider.Present(t.Context(), testZone, testFQDN, testValue, 600); err != nil {
		t.Fatalf("present same value: %v", err)
	}

	if got := fake.attempts("AddDomainRecord"); got != 0 {
		t.Fatalf("AddDomainRecord attempts=%d, want 0（同值已存在必须复用既有记录）", got)
	}
	if !fake.alive(777) {
		t.Fatal("复用路径不得删除既有记录")
	}
	provider.mu.Lock()
	entries := append([]ownedRecord(nil), provider.owned["example.com|"+accountMatch]...)
	provider.mu.Unlock()
	if len(entries) != 1 || entries[0].recordID != 777 || entries[0].value != testValue {
		t.Fatalf("兜底表条目=%+v, want 777/%s（复用 ID 入账）", entries, testValue)
	}
}

// 复用 ID 同样登记 ownership 账本：并发签发的清理（CleanUpValue）能按值收回。
func TestProvider_Present_reuseRegistersOwnershipLedger(t *testing.T) {
	dataDir := t.TempDir()
	fake := newFakeAlidns()
	fake.mu.Lock()
	fake.records[777] = fakeRecord{rr: accountMatch, value: testValue}
	fake.mu.Unlock()
	server := newFakeServer(t, fake)
	provider, err := NewPersistent("test-access-key-id", "test-access-key-secret", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.endpoint = server.URL

	if err := provider.Present(t.Context(), testZone, testFQDN, testValue, 600); err != nil {
		t.Fatalf("present same value: %v", err)
	}

	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	records, err := store.MatchingValue("aliyun", testZone, testFQDN, testValue)
	if err != nil {
		t.Fatalf("matching value: %v", err)
	}
	if len(records) != 1 || records[0].RecordID != "777" {
		t.Fatalf("ledger records=%+v, want 复用 ID 777 登记", records)
	}
}

// 同名不同值：照常创建（复用只按内容精确匹配，不抑制新值挑战）。
func TestProvider_Present_createsWhenOnlyDifferentValueExists(t *testing.T) {
	fake := newFakeAlidns()
	fake.mu.Lock()
	fake.records[777] = fakeRecord{rr: accountMatch, value: "other-value"}
	fake.mu.Unlock()
	server := newFakeServer(t, fake)
	provider := newFakeProvider(t, server.URL, 3)

	if err := provider.Present(t.Context(), testZone, testFQDN, testValue, 600); err != nil {
		t.Fatalf("present new value: %v", err)
	}

	if got := fake.attempts("AddDomainRecord"); got != 1 {
		t.Fatalf("AddDomainRecord attempts=%d, want 1（不同值照常创建）", got)
	}
	if !fake.alive(777) {
		t.Fatal("复用扫描不得误删不同值的既有记录")
	}
}
