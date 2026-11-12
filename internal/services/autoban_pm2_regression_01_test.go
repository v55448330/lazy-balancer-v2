package services

//
// 候选 TOCTOU：候选评估（autobanCandidates，含过期桶先评估再删）
// 必须与 merge 同一 CaddyOpLock 临界区。旧实现候选在锁外评估、进锁 merge 用
// 陈旧候选——handlers 解封（持 CaddyOpLock 的读改写+AutobanForgetIPs 清桶）
// 落在「候选已评估」与「进锁 merge」之间时，merge 把刚解封的 IP 加回名单，
// 解封被 ≤1 tick（自限 120s 调度）撤销。
//
// 钉法：临界区预持（模拟解封写路径半程——handler 已取锁），候选 IP 用「已过期
// 且达阈值」桶（候选评估会将其修剪删除=可观测 barrier：tracked 1→0 证明旧实现
// 已越过锁外候选点）；持锁方在释放前完成解封清桶（临界区终态=解封已生效）后
// 放行。候选若在锁外已定，merge 必把该 IP 加回=红；候选移入临界区后，评估发生
// 在解封之后、候选为空，名单不动=绿。
//
// 解封展示残留：AutobanForgetIPs 同步清 autobanSuggestions 对应 IP——
// dry-run 建议列表是上一轮观察快照，解封后仍展示该 IP 是 ≤1 tick 展示残留。

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/taskengine"
)

func TestAutobanRunCycle_candidatesEvaluatedInsideCaddyOpLock(t *testing.T) {
	clock := installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 1, 5, "1h", "blocked,logged", false)

	// 候选 IP：达阈值且窗口已过期（桶先评估再删——形态，兼作 barrier）
	autobanObserveEvent("198.51.100.7", "blocked", "949110")
	clock.Advance(2 * time.Hour)
	if got := AutobanTrackedIPs(); got != 1 {
		t.Fatalf("前置计数桶=%d, want 1", got)
	}

	CaddyOpLock.Lock()
	cycleDone := make(chan error, 1)
	go func() { cycleDone <- RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}) }()

	// barrier：等待候选评估点被越过（过期桶被修剪 tracked 1→0）。候选移入
	// 临界区的实现下，本轮阻塞于进锁、桶不动，轮询自然超时（非断言）。
	deadline := time.Now().Add(2 * time.Second)
	for AutobanTrackedIPs() == 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	// 持锁期间完成解封清桶（解封写路径临界区内的终态）
	AutobanForgetIPs([]string{"198.51.100.7"})
	CaddyOpLock.Unlock()

	select {
	case err := <-cycleDone:
		if err != nil {
			t.Fatalf("autoban cycle: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("autoban cycle 未在释放临界区后完成")
	}

	entries, _, err := AutobanListEntries()
	if err != nil {
		t.Fatalf("read preset list: %v", err)
	}
	for _, e := range entries {
		if e.Value == "198.51.100.7" {
			t.Fatal("解封落在候选评估与 merge 之间时不得回封 198.51.100.7（候选在锁外评估=陈旧候选进 merge 的 TOCTOU）")
		}
	}
	if got := AutobanTrackedIPs(); got != 0 {
		t.Fatalf("轮后计数桶=%d, want 0（过期桶已修剪/解封已清）", got)
	}
}

// Given dry-run 建议列表含两个 IP。
// When 解封其中一个（AutobanForgetIPs）。
// Then 建议列表同步剔除该 IP（展示残留 ≤1 tick 的口子封死），另一 IP 保留。
func TestAutobanForgetIPs_scrubsSuggestions(t *testing.T) {
	resetAutobanStateForTest()
	t.Cleanup(resetAutobanStateForTest)

	autobanSetSuggestions([]AutobanSuggestion{
		{IP: "198.51.100.7", Count: 3},
		{IP: "203.0.113.9", Count: 2},
	})
	AutobanForgetIPs([]string{"198.51.100.7"})

	out := AutobanSuggestions()
	if len(out) != 1 || out[0].IP != "203.0.113.9" {
		t.Fatalf("解封后建议列表=%v, want 仅 203.0.113.9（AutobanForgetIPs 未同步清 autobanSuggestions）", out)
	}

	// 解封全部 → 建议列表清空
	AutobanForgetIPs([]string{"203.0.113.9"})
	if out := AutobanSuggestions(); len(out) != 0 {
		t.Fatalf("全量解封后建议列表=%v, want 空", out)
	}
}
