package caddyl4sec

// 覆写环形缓冲（方案③，用户裁定）：入队永不阻塞连接路径——队列满时覆写最旧
// 事件（newest-wins），丢弃计数照记。替代 chan+2s 等待（风暴下每条被拒连接
// 挂 2s 放大 fd/goroutine 驻留）。
import (
	"strconv"
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

// TestRingQueuedBytesSumsEffectiveLengths queue_bytes 必须是环内有效行的真实
// 字节合计（逐槽 lens 求和），不是槽容量×深度——槽预分配远大于实际行时
// 容量口径会把队列体量放大数十倍。覆写逐出后只计存活行。
func TestRingQueuedBytesSumsEffectiveLengths(t *testing.T) {
	// Given：槽容量 1KiB 远大于实际行，环容量 3。
	r := newL4Ring(3, 1<<10)
	if got := r.queuedBytes(); got != 0 {
		t.Fatalf("空环 queuedBytes=%d, want 0", got)
	}
	// When：入队三条不等长行。
	r.push([]byte("aa"))     // 2
	r.push([]byte("bbbb"))   // 4
	r.push([]byte("cccccc")) // 6
	// Then：合计=2+4+6=12，而非槽容量×深度（3×1024）。
	if got := r.queuedBytes(); got != 12 {
		t.Fatalf("queuedBytes=%d, want 12（Σ有效长度，非槽容量×深度）", got)
	}
	// When：满环覆写逐出最旧 "aa"，入队 "d"（1 字节）。
	if evicted := r.push([]byte("d")); evicted != 1 {
		t.Fatalf("evicted=%d, want 1", evicted)
	}
	// Then：存活 bbbb+cccccc+d = 4+6+1 = 11。
	if got := r.queuedBytes(); got != 11 {
		t.Fatalf("覆写后 queuedBytes=%d, want 11（只计存活行）", got)
	}
	// When：消费清空。
	for {
		if _, ok := r.pop(); !ok {
			break
		}
	}
	if got := r.queuedBytes(); got != 0 {
		t.Fatalf("消费后 queuedBytes=%d, want 0", got)
	}
}

// 原子快照对：depthAndBytes 一次锁内取两值——与逐值读取同口径（空环/
// 非空/覆写后），观测端点据此不再出现 len/bytes 跨时刻瞬态对。
func TestL4Ring_depthAndBytesAtomicPair(t *testing.T) {
	r := newL4Ring(2, 1<<10)
	if d, b := r.depthAndBytes(); d != 0 || b != 0 {
		t.Fatalf("empty ring pair=(%d,%d), want (0,0)", d, b)
	}
	r.push([]byte("aa"))
	r.push([]byte("bbbb"))
	if d, b := r.depthAndBytes(); d != 2 || b != 6 {
		t.Fatalf("pair=(%d,%d), want (2,6)", d, b)
	}
	r.push([]byte("c")) // 满环覆写最旧 "aa"
	if d, b := r.depthAndBytes(); d != 2 || b != 5 {
		t.Fatalf("after overwrite pair=(%d,%d), want (2,5)", d, b)
	}
	// 与独立读取同值（同一静止态）。
	if d, b := r.depthAndBytes(); d != r.depth() || b != r.queuedBytes() {
		t.Fatalf("pair=(%d,%d) disagrees with depth/queuedBytes=(%d,%d)", d, b, r.depth(), r.queuedBytes())
	}
}

// 并发形状：持续 push/pop 时快照对读不竞争（-race），且每对内部自洽
// （bytes ≤ depth×单行上限的松界；静止态精确相等由上一用例钉住）。
func TestL4Ring_depthAndBytesConcurrent(t *testing.T) {
	r := newL4Ring(8, 1<<10)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 2000 {
			r.push([]byte("line-" + strconv.Itoa(i)))
			if i%3 == 0 {
				r.pop()
			}
		}
	}()
	for {
		select {
		case <-done:
			return
		default:
		}
		d, b := r.depthAndBytes()
		if d < 0 || b < 0 || d > 8 {
			t.Fatalf("invalid pair=(%d,%d)", d, b)
		}
	}
}
