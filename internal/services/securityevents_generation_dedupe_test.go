package services

import (
	"path/filepath"
	"testing"
	"time"
)

// 库代际切换后，请求级去重表必须清空「共享实例」而不是给 live tailer 换一张
// 私有新表：IPC 批摄取（securityEventsBatchIngestState 持有共享实例指针）、
// spool 补采与归档补采都经同一实例去重。换指针会让这些通道继续用旧代键把
// 新库重放当重复丢弃（新库永久缺这些行），之后 live 侧新登记的事件对其它
// 通道也不可见（跨通道重复重新分裂）。
func TestSecurityEventsGenerationSwitch_clearsSharedDedupeInPlace(t *testing.T) {
	isolateSecurityEventsSharedDedupe(t)
	atSec := time.Now().Unix()

	// Given 旧库时代已在共享表登记了请求键，且本 tailer 使用共享实例
	//（生产装配：securityEventsNewTailer 默认挂共享表）。
	securityEventsSharedDedupe.record(0xAA, securityEventsDedupeEntry{transactionID: "old-tx", atSec: atSec})
	tailer := securityEventsNewTailer(filepath.Join(t.TempDir(), "audit.log"), filepath.Join(t.TempDir(), "offset"))
	if tailer.deduper() != securityEventsSharedDedupe {
		t.Fatal("装配前提不成立：tailer 未使用共享去重表")
	}
	offsetPath := tailer.offsetPath

	// When 库代际变化触发复位。
	got, err := tailer.securityEventsSwitchMetricsGeneration("gen-2", 1234)
	if err != nil {
		t.Fatalf("代际复位返回错误: %v", err)
	}

	// Then offset 从头摄取。
	if got != 0 {
		t.Fatalf("offset=%d，want 0（新库必须从头重摄取）", got)
	}
	// Then 共享表的旧代键被清空（其它通道看到的是同一张空表）。
	if _, ok := securityEventsSharedDedupe.lookup(0xAA, atSec); ok {
		t.Fatal("共享去重表仍持有旧库代键——IPC/spool 通道会把新库重放当重复丢弃")
	}
	// Then 本 tailer 仍挂在共享实例上（不得退化成私有表，否则跨通道去重再次分裂）。
	if tailer.deduper() != securityEventsSharedDedupe {
		t.Fatal("代际复位后 tailer 不再共享去重表，跨通道去重分裂")
	}
	// Then offset 落盘同样归零。
	if off, err := securityEventsReadOffset(offsetPath); err != nil || off != 0 {
		t.Fatalf("持久化 offset=%d err=%v，want 0", off, err)
	}
}

// 私有表形态（测试/嵌入注入）同样要在代际切换时清空——复位覆盖面按「本
// tailer 实际使用的表」判定，不只清共享实例。
func TestSecurityEventsGenerationSwitch_clearsPrivateDedupeToo(t *testing.T) {
	isolateSecurityEventsSharedDedupe(t)
	atSec := time.Now().Unix()

	tailer := securityEventsNewTailer(filepath.Join(t.TempDir(), "audit.log"), filepath.Join(t.TempDir(), "offset"))
	private := &securityEventsRequestDeduper{}
	tailer.dedupe = private
	private.record(0xBB, securityEventsDedupeEntry{transactionID: "old-tx", atSec: atSec})
	// 共享表里也残留一条旧代键。
	securityEventsSharedDedupe.record(0xCC, securityEventsDedupeEntry{transactionID: "old-tx-2", atSec: atSec})

	if _, err := tailer.securityEventsSwitchMetricsGeneration("gen-2", 1); err != nil {
		t.Fatalf("代际复位返回错误: %v", err)
	}
	if _, ok := private.lookup(0xBB, atSec); ok {
		t.Fatal("本 tailer 使用的私有去重表未被清空")
	}
	if _, ok := securityEventsSharedDedupe.lookup(0xCC, atSec); ok {
		t.Fatal("共享去重表未被清空")
	}
}
