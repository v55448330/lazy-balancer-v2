package services

// 容量挤出的复杂度钉子：挤出序一次预计算（排序）后批量删，不再每挤出一个
// 就全表扫描并重新 time.Parse 全部条目。行为等价由「挤出优先级逐项对齐 +
// 最终名单集合/顺序」双重断言，复杂度由 time.Parse 调用计数上界断言。

import (
	"fmt"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestAutobanMerge_evictionPrecomputedOrderAndParseBound(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	oldCap := AutobanListEntryCap
	AutobanListEntryCap = 30
	t.Cleanup(func() { AutobanListEntryCap = oldCap })

	const (
		manualCount = 20
		expiring    = 60
		permanent   = 10
		newBanned   = 10
	)
	var seeded []models.IPListEntry
	var wantExpiringOrder []string
	var wantPermanentOrder []string
	for i := range manualCount {
		seeded = append(seeded, models.IPListEntry{
			Value: fmt.Sprintf("192.0.2.%d", i+1), Remark: "事件处置",
		})
	}
	// 到期时间倒序写入（最早到期排在名单末尾）：挤出序必须按到期升序，
	// 而非名单顺序。
	for i := range expiring {
		value := fmt.Sprintf("198.51.100.%d", i+1)
		expires := fmt.Sprintf("2026-10-14 11:%02d:00", expiring-1-i)
		seeded = append(seeded, models.IPListEntry{
			Value: value, Remark: autobanEntryRemark, ExpiresAt: expires,
		})
		wantExpiringOrder = append([]string{value}, wantExpiringOrder...)
	}
	// 永久条目：created_at 升序者先挤（created_at 递减写入，期望顺序即反向）。
	for i := range permanent {
		value := fmt.Sprintf("203.0.113.%d", i+1)
		seeded = append(seeded, models.IPListEntry{
			Value: value, Remark: autobanEntryRemark,
			CreatedAt: fmt.Sprintf("2026-10-10 00:00:%02d", permanent-i),
		})
		wantPermanentOrder = append([]string{value}, wantPermanentOrder...)
	}
	seedPresetEntries(t, seeded)

	candidates := make([]AutobanSuggestion, 0, newBanned)
	for i := range newBanned {
		candidates = append(candidates, AutobanSuggestion{IP: fmt.Sprintf("10.10.0.%d", i+1), Count: 100 - i})
	}

	baseParses := autobanEntryTimeParses.Load()
	out, err := autobanMergeEntries(AutobanConfig{
		Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "1h", Scope: "blocked,logged", DryRun: false,
	}, candidates)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	parses := autobanEntryTimeParses.Load() - baseParses

	// 行为等价①：挤出数与顺序 = 到期升序（60）→ 永久 created_at 升序（10）。
	if out.Evicted != expiring+permanent {
		t.Fatalf("evicted=%d, want %d", out.Evicted, expiring+permanent)
	}
	if out.DroppedNew != 0 {
		t.Fatalf("dropped_new=%d, want 0（自动条目足够挤出）", out.DroppedNew)
	}
	want := append(append([]string{}, wantExpiringOrder...), wantPermanentOrder...)
	if len(out.EvictedIPs) != len(want) {
		t.Fatalf("EvictedIPs 条数=%d, want %d", len(out.EvictedIPs), len(want))
	}
	for i := range want {
		if out.EvictedIPs[i] != want[i] {
			t.Fatalf("挤出序第 %d 项=%s, want %s（优先级与逐次挑选必须一致）", i, out.EvictedIPs[i], want[i])
		}
	}

	// 行为等价②：最终名单 = 全部手动条目 + 本轮新封，顺序保持原相对次序。
	final := presetEntries(t)
	if len(final) != AutobanListEntryCap {
		t.Fatalf("条目数=%d, want %d", len(final), AutobanListEntryCap)
	}
	for i := range manualCount {
		wantValue := fmt.Sprintf("192.0.2.%d", i+1)
		if final[i].Value != wantValue || final[i].Remark != "事件处置" {
			t.Fatalf("第 %d 条=%+v, want 手动条目 %s", i, final[i], wantValue)
		}
	}
	for i := range newBanned {
		wantValue := fmt.Sprintf("10.10.0.%d", i+1)
		got := final[manualCount+i]
		if got.Value != wantValue || got.Remark != autobanEntryRemark {
			t.Fatalf("新封第 %d 条=%+v, want %s", i, got, wantValue)
		}
	}

	// 复杂度：时间解析次数与条目数线性相关（旧实现每挤出一个全表重解析，
	// 本例约 70 次挤出 × 平均 55 条 ≈ 4000 次）。
	// 下界是断言的另一半：计数缝若被删除/自增点丢失，parses=0 会让「≤ 上界」
	// 恒过；期望实现至少对每条种入条目解析一次（到期清点 1 次/条 + 挤出序
	// 预计算 2 次/自动条），故线性下界取 len(seeded)。
	if parses < int64(len(seeded)) {
		t.Fatalf("time.Parse 次数=%d, 低于每条目至少一次的下界 %d（计数缝失效或条目未经时间解析）", parses, len(seeded))
	}
	upperBound := int64(3 * (len(seeded) + newBanned + 8))
	if parses > upperBound {
		t.Fatalf("time.Parse 次数=%d, 超过线性上界 %d（挤出仍为 O(n²) 逐次重解析）", parses, upperBound)
	}
}

// 挤出序畸形形状钉测：畸形/空 expires_at 视为永久（到期过滤同口径——畸形
// 保留不误删，挤出序排在所有有到期者之后）；永久条目间畸形/空 created_at
// 视为零值排最后，同值按键序（先出现先挤，稳定序）。
func TestAutobanMerge_evictionOrderMalformedTimestamps(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	oldCap := AutobanListEntryCap
	AutobanListEntryCap = 3
	t.Cleanup(func() { AutobanListEntryCap = oldCap })

	seeded := []models.IPListEntry{
		{Value: "192.0.2.1", Remark: "事件处置"}, // 手动条目：永不挤出
		{Value: "192.0.2.2", Remark: "手动封禁"},
		// 有到期者按到期升序先挤。
		{Value: "198.51.100.11", Remark: autobanEntryRemark, ExpiresAt: "2026-10-14 10:30:00"},
		{Value: "198.51.100.12", Remark: autobanEntryRemark, ExpiresAt: "2026-10-14 11:00:00"},
		// 畸形/空 expires_at → 永久档；档内按 created_at 升序。
		{Value: "198.51.100.13", Remark: autobanEntryRemark, ExpiresAt: "not-a-timestamp", CreatedAt: "2026-10-14 09:00:00"},
		{Value: "198.51.100.14", Remark: autobanEntryRemark, ExpiresAt: "", CreatedAt: "2026-10-14 09:30:00"},
		// 永久档内畸形/空 created_at → 零值排最后（同零值保持写入序）。
		{Value: "198.51.100.15", Remark: autobanEntryRemark, ExpiresAt: "2026-13-99 99:99:99", CreatedAt: "garbage"},
		{Value: "198.51.100.16", Remark: autobanEntryRemark, CreatedAt: ""},
	}
	seedPresetEntries(t, seeded)

	out, err := autobanMergeEntries(AutobanConfig{
		Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "1h", Scope: "blocked,logged", DryRun: false,
	}, []AutobanSuggestion{{IP: "10.10.0.1", Count: 9}})
	if err != nil {
		t.Fatalf("merge: %v", err)
	}

	// 总量 8+1=9，容量 3 → 挤出 6（全部自动条目），顺序=到期升序 → 永久
	// created_at 升序 → 畸形 created_at（零值，写入序）。
	want := []string{
		"198.51.100.11", "198.51.100.12",
		"198.51.100.13", "198.51.100.14",
		"198.51.100.15", "198.51.100.16",
	}
	if out.Evicted != len(want) || len(out.EvictedIPs) != len(want) {
		t.Fatalf("evicted=%d EvictedIPs=%v, want %d 条", out.Evicted, out.EvictedIPs, len(want))
	}
	for i := range want {
		if out.EvictedIPs[i] != want[i] {
			t.Fatalf("挤出序第 %d 项=%s, want %s（畸形 expires_at→永久档；畸形 created_at→档内最后）", i, out.EvictedIPs[i], want[i])
		}
	}
	// 畸形 expires_at 条目未被「到期过滤」误删——它们全部经挤出离场（=被
	// 计入名单容量），最终名单=2 手动+1 新封。
	final := presetEntries(t)
	if len(final) != 3 || final[0].Value != "192.0.2.1" || final[1].Value != "192.0.2.2" || final[2].Value != "10.10.0.1" {
		t.Fatalf("最终名单=%+v, want [192.0.2.1 192.0.2.2 10.10.0.1]", final)
	}
}
