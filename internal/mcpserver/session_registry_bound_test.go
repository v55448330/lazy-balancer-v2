package mcpserver

import (
	"fmt"
	"testing"
)

// 强制断开的会话 ID 只增不删会让进程生命周期内的内存按累计断开数增长。
// 终止标记保留最近 terminatedSessionRetention 个（FIFO 淘汰最旧）：内存有界，
// 近期被强制断开的会话仍被拒绝。
func TestTerminatingSessionManager_boundedRetention(t *testing.T) {
	m := newTerminatingSessionManager()
	id := func(i int) string { return fmt.Sprintf("mcp-session-%08x", i) }

	evicted := 10
	total := terminatedSessionRetention + evicted
	for i := range total {
		if _, err := m.Terminate(id(i)); err != nil {
			t.Fatalf("terminate %d: %v", i, err)
		}
	}
	if got := m.terminatedCount(); got != terminatedSessionRetention {
		t.Fatalf("terminated=%d want %d（保留集必须有界）", got, terminatedSessionRetention)
	}
	// 最旧的 evicted 个已被淘汰（不再被终止标记拒绝）。
	for i := range evicted {
		if terminated, _ := m.Validate(id(i)); terminated {
			t.Fatalf("第 %d 个（最旧）应已被淘汰", i)
		}
	}
	// 最近 retention 个仍被拒绝。
	for i := evicted; i < total; i++ {
		if terminated, _ := m.Validate(id(i)); !terminated {
			t.Fatalf("第 %d 个（最近）必须仍被终止标记拒绝", i)
		}
	}
	// 重复终止幂等，不占新额度、不改插入序。
	if _, err := m.Terminate(id(total - 1)); err != nil {
		t.Fatal(err)
	}
	if got := m.terminatedCount(); got != terminatedSessionRetention {
		t.Fatalf("重复终止后 terminated=%d want %d", got, terminatedSessionRetention)
	}

	// 多圈绕环：再写满两圈，保留集仍只有最近 retention 个。
	for lap := 1; lap <= 2; lap++ {
		for i := range terminatedSessionRetention {
			if _, err := m.Terminate(id(total + (lap-1)*terminatedSessionRetention + i)); err != nil {
				t.Fatalf("terminate lap %d i %d: %v", lap, i, err)
			}
		}
	}
	if got := m.terminatedCount(); got != terminatedSessionRetention {
		t.Fatalf("多圈绕环后 terminated=%d want %d", got, terminatedSessionRetention)
	}
	last := total + 2*terminatedSessionRetention
	for i := last - terminatedSessionRetention; i < last; i++ {
		if terminated, _ := m.Validate(id(i)); !terminated {
			t.Fatalf("绕环后第 %d 个（最近一圈）必须仍被拒绝", i)
		}
	}
	for i := total; i < last-terminatedSessionRetention; i++ {
		if terminated, _ := m.Validate(id(i)); terminated {
			t.Fatalf("绕环后第 %d 个（上一圈）应已被淘汰", i)
		}
	}

	// 淘汰后重新终止：重新进入保留集，只占一个额度。
	if _, err := m.Terminate(id(0)); err != nil {
		t.Fatal(err)
	}
	if terminated, _ := m.Validate(id(0)); !terminated {
		t.Fatal("淘汰后重新终止的 ID 必须重新被拒绝")
	}
	if got := m.terminatedCount(); got != terminatedSessionRetention {
		t.Fatalf("淘汰后重终止 terminated=%d want %d", got, terminatedSessionRetention)
	}
	// 重终止挤掉了当时最旧的 last-retention；此刻最旧者是 last-retention+1。
	// 满员后的下一次淘汰拿走的必须仍是它，而不是刚重终止的 ID。
	if _, err := m.Terminate(id(last)); err != nil {
		t.Fatal(err)
	}
	if terminated, _ := m.Validate(id(last - terminatedSessionRetention + 1)); terminated {
		t.Fatal("满员后必须淘汰最旧的标记")
	}
	if terminated, _ := m.Validate(id(last - terminatedSessionRetention + 2)); !terminated {
		t.Fatal("次旧者不得被误淘汰")
	}
	if terminated, _ := m.Validate(id(0)); !terminated {
		t.Fatal("刚重终止的 ID 不得被误淘汰")
	}
	if got := m.terminatedCount(); got != terminatedSessionRetention {
		t.Fatalf("再次满员淘汰后 terminated=%d want %d", got, terminatedSessionRetention)
	}
}
