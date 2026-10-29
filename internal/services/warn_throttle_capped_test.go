package services

// 告警限频「窗口判定 + 回收 + 上限重置 + 记录」的单源。审计轮转失败日志此前
// 是 throttleWarnAllowed 的手写副本（额外带键数上限），两处顺序一旦分叉
// （先重置后判重 → 被抑制的消息也触发清扫），限频语义在两族告警间不一致。

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestThrottleWarnAllowedCapped_resetsWhenOverCap(t *testing.T) {
	now := time.Unix(1700000000, 0)
	seen := map[string]time.Time{}
	// When：同一时刻放行 4 条互异消息，上限 2（清扫后 len 超上限才重置，
	// 阈值判定发生在插入之前——与审计轮转族原实现同序）
	for i := range 4 {
		if !throttleWarnAllowedCapped(&seen, fmt.Sprintf("k%d", i), now, time.Minute, time.Minute, 2) {
			t.Fatalf("新消息 k%d 必须放行", i)
		}
	}
	// Then：超限整体重置（旧键全丢），仅保留当前键。
	if len(seen) != 1 {
		t.Fatalf("map 大小=%d, want 1（超限后整体重置）: %v", len(seen), seen)
	}
	if _, ok := seen["k3"]; !ok {
		t.Fatal("重置必须保留当前键")
	}
	// 窗口内重复仍被抑制，且被抑制的消息不触发清扫/重置。
	if throttleWarnAllowedCapped(&seen, "k3", now, time.Minute, time.Minute, 2) {
		t.Fatal("窗口内同一消息必须被抑制")
	}
	if len(seen) != 1 {
		t.Fatalf("被抑制的消息不得改动限频状态: map 大小=%d", len(seen))
	}
}

func TestThrottleWarnAllowedCapped_evictsBeforeCapCheck(t *testing.T) {
	now := time.Unix(1700000000, 0)
	seen := map[string]time.Time{}
	// 窗口/回收同为 1 分钟：先放行 a、b，再越过窗口放行 c——a/b 已被回收，
	// 此时未超上限，不得触发整体重置（旧键自然过期与超限重置是两件事）。
	for _, key := range []string{"a", "b"} {
		if !throttleWarnAllowedCapped(&seen, key, now, time.Minute, time.Minute, 2) {
			t.Fatalf("首个 %s 必须放行", key)
		}
	}
	now = now.Add(2 * time.Minute)
	if !throttleWarnAllowedCapped(&seen, "c", now, time.Minute, time.Minute, 2) {
		t.Fatal("窗口后的新消息必须放行")
	}
	if len(seen) != 1 {
		t.Fatalf("过期键应被回收而非整体重置: map 大小=%d", len(seen))
	}
}

// cap=0 表示无上限：与 throttleWarnAllowed 的既有语义逐位一致（哨兵值不被
// 当作「立即重置」，否则每个非审计族都会退化为不限频）。
func TestThrottleWarnAllowedCapped_zeroCapKeepsAllKeys(t *testing.T) {
	now := time.Unix(1700000000, 0)
	seen := map[string]time.Time{}
	if !throttleWarnAllowed(seen, "x", now, time.Minute, time.Minute) {
		t.Fatal("throttleWarnAllowed 首个必须放行")
	}
	if !throttleWarnAllowedCapped(&seen, "y", now, time.Minute, time.Minute, 0) {
		t.Fatal("cap=0（无上限）新消息必须放行")
	}
	if len(seen) != 2 {
		t.Fatalf("map 大小=%d, want 2（cap=0 不得重置）", len(seen))
	}
}

// 委托关系不得回退成手写副本：审计轮转失败日志若重新内联窗口判定/回收/重置，
// 限频语义就又有了第二份实现（此前正是这样：注释声称复用同源，实际只借用了
// 回收段，顺序与其它告警族分叉）。
func TestAuditFailureShouldLog_delegatesToCappedThrottle(t *testing.T) {
	source, err := os.ReadFile("auditlog_rotation.go")
	if err != nil {
		t.Fatalf("read auditlog_rotation.go: %v", err)
	}
	text := string(source)
	start := strings.Index(text, "func auditFailureShouldLog(")
	if start < 0 {
		t.Fatal("auditFailureShouldLog 已不存在——审计失败限流的调用面变了")
	}
	end := strings.Index(text[start:], "\n}\n")
	if end < 0 {
		t.Fatal("无法定位 auditFailureShouldLog 函数体")
	}
	body := text[start : start+end]
	if !strings.Contains(body, "throttleWarnAllowedCapped") {
		t.Fatalf("auditFailureShouldLog 必须委托 limit 单源:\n%s", body)
	}
	for _, handCopy := range []string{"throttleWarnEvict(", "make(map[string]time.Time)"} {
		if strings.Contains(body, handCopy) {
			t.Fatalf("auditFailureShouldLog 重新内联了手写副本（%s），限频语义出现第二份实现:\n%s", handCopy, body)
		}
	}
}
