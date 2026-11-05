package dnspod

// 同值复用（与 cloudflare 侧 TestProvider_Present_reusesExistingSameValueRecord
// 同构）：Present 在创建前按 Record.List 同名 TXT 内容精确匹配复用既有记录
// ID——并发/重试双签发不再产生重复 TXT；同名不同值照常创建。复用 ID 与新建
// ID 共用同一条登记路径（内存兜底表 / ownership 账本），清理语义不变。

import (
	"testing"

	"lazy-balancer-v2/internal/dnsprovider/ownership"
)

// 同名同值已存在：不调 Record.Create、复用既有记录 ID、内存兜底表登记。
func TestProvider_Present_reusesExistingSameValueRecord(t *testing.T) {
	transport := &drainAwareTransport{
		dnsPodRecordTransport: dnsPodRecordTransport{records: map[string]string{"777": "v-dup"}},
		names:                 map[string]string{"777": "_acme-challenge"},
	}
	provider := New("id,token")
	provider.client.Transport = transport

	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "v-dup", 600); err != nil {
		t.Fatalf("present same value: %v", err)
	}

	transport.mu.Lock()
	creates := append([]dnsPodCreateRequest(nil), transport.creates...)
	_, recordAlive := transport.records["777"]
	transport.mu.Unlock()
	if len(creates) != 0 {
		t.Fatalf("Record.Create calls=%d, want 0（同值已存在必须复用既有记录）", len(creates))
	}
	if !recordAlive {
		t.Fatal("复用路径不得删除既有记录")
	}
	provider.mu.Lock()
	entries := append([]ownedRecord(nil), provider.owned["1|_acme-challenge"]...)
	provider.mu.Unlock()
	if len(entries) != 1 || entries[0].recordID != "777" || entries[0].value != "v-dup" {
		t.Fatalf("兜底表条目=%+v, want 777/v-dup（复用 ID 入账）", entries)
	}
}

// 复用 ID 同样登记 ownership 账本：并发签发的清理（CleanUpValue）能按值收回。
func TestProvider_Present_reuseRegistersOwnershipLedger(t *testing.T) {
	dataDir := t.TempDir()
	transport := &drainAwareTransport{
		dnsPodRecordTransport: dnsPodRecordTransport{records: map[string]string{"777": "v-dup"}},
		names:                 map[string]string{"777": "_acme-challenge"},
	}
	provider, err := NewPersistent("id,token", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.client.Transport = transport

	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "v-dup", 600); err != nil {
		t.Fatalf("present same value: %v", err)
	}

	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	records, err := store.MatchingValue("dnspod", "example.com", "_acme-challenge.example.com.", "v-dup")
	if err != nil {
		t.Fatalf("matching value: %v", err)
	}
	if len(records) != 1 || records[0].RecordID != "777" {
		t.Fatalf("ledger records=%+v, want 复用 ID 777 登记", records)
	}
}

// 同名不同值：照常创建（复用只按内容精确匹配，不抑制新值挑战）。
func TestProvider_Present_createsWhenOnlyDifferentValueExists(t *testing.T) {
	transport := &drainAwareTransport{
		dnsPodRecordTransport: dnsPodRecordTransport{records: map[string]string{"777": "v-other"}},
		names:                 map[string]string{"777": "_acme-challenge"},
	}
	provider := New("id,token")
	provider.client.Transport = transport

	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "v-dup", 600); err != nil {
		t.Fatalf("present new value: %v", err)
	}

	transport.mu.Lock()
	creates := append([]dnsPodCreateRequest(nil), transport.creates...)
	_, recordAlive := transport.records["777"]
	transport.mu.Unlock()
	if len(creates) != 1 || creates[0].Value != "v-dup" || creates[0].SubDomain != "_acme-challenge" {
		t.Fatalf("Record.Create=%+v, want 1 次新值创建（sub_domain 精确）", creates)
	}
	if !recordAlive {
		t.Fatal("复用扫描不得误删不同值的既有记录")
	}
}
