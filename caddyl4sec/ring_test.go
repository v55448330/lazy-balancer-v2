package caddyl4sec

// 覆写环形缓冲（方案③，用户裁定）：入队永不阻塞连接路径——队列满时覆写最旧
// 事件（newest-wins），丢弃计数照记。替代 chan+2s 等待（风暴下每条被拒连接
// 挂 2s 放大 fd/goroutine 驻留）。
import (
	"testing"
	"time"
)

// TestEnqueueSaturationNeverBlocks 饱和管线上连续入队必须在亚秒级返回——
// 现状实现（chan 容量 1 + 2s 等待）第 2、3 次入队各挂 2s，总计 >2s 即 RED。
func TestEnqueueSaturationNeverBlocks(t *testing.T) {
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", "")
	resetConnStatsForTest()
	defer restoreTunables(setTunablesForTest(1, 1<<20, 10*time.Millisecond))
	p := acquirePipelineForTest()
	defer p.resetForTest()
	p.blockDrainForTest(true) // 消费暂停 = 饱和形态确定

	line := []byte(`{"transaction":{"id":"x"}}`)
	start := time.Now()
	for i := 0; i < 3; i++ {
		p.enqueueEvent(line)
	}
	elapsed := time.Since(start)
	p.blockDrainForTest(false) // 先恢复消费再收尾（resetForTest 的 quiesce 不被暂停拖满超时）
	if elapsed > 2*time.Second {
		t.Fatalf("饱和管线上 3 次入队耗时 %v（>2s = 连接路径被阻塞）", elapsed)
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("饱和管线上 3 次入队耗时 %v（>100ms = 非零阻塞残留）", elapsed)
	}
}

// TestRingOverwriteKeepsNewest 覆写语义：满环再入队 → 最旧被逐出（dropped
// 计数），环内保留最新；消费序=先进先出的存活子序列。
func TestRingOverwriteKeepsNewest(t *testing.T) {
	r := newL4Ring(2, 1<<10)
	pushLine := func(tag string) []byte {
		line := []byte(tag)
		r.push(line)
		return line
	}
	pushLine("a")
	pushLine("b")
	evicted := r.push([]byte("c"))
	if evicted != 1 {
		t.Fatalf("evicted=%d, want 1（满环覆写逐出最旧）", evicted)
	}
	var got []string
	for {
		line, ok := r.pop()
		if !ok {
			break
		}
		got = append(got, string(line))
	}
	if len(got) != 2 || got[0] != "b" || got[1] != "c" {
		t.Fatalf("ring=%v, want [b c]（最新保留、最旧逐出）", got)
	}
	if r.depth() != 0 {
		t.Fatalf("depth=%d, want 0（消费后清空）", r.depth())
	}
}

// TestRingSlotGrowth 槽按需增长：小槽环接受超初始槽的行（上限由单行上限
// 把守，环内不存在超界行），后续小行复用槽不再缩容。
func TestRingSlotGrowth(t *testing.T) {
	r := newL4Ring(2, 4)
	big := make([]byte, 100)
	for i := range big {
		big[i] = 'y'
	}
	if evicted := r.push(big); evicted != 0 {
		t.Fatalf("evicted=%d, want 0", evicted)
	}
	if evicted := r.push([]byte("ok")); evicted != 0 {
		t.Fatalf("evicted=%d, want 0", evicted)
	}
	if r.depth() != 2 {
		t.Fatalf("depth=%d, want 2", r.depth())
	}
	// 覆写后大行被逐出、新行保留
	if evicted := r.push([]byte("new")); evicted != 1 {
		t.Fatalf("evicted=%d, want 1（满环覆写）", evicted)
	}
	line, ok := r.pop()
	if !ok || string(line) != "ok" {
		t.Fatalf("pop=%q ok=%v, want ok（FIFO 存活子序列）", string(line), ok)
	}
}
