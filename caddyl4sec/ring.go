package caddyl4sec

// l4Ring 覆写环形缓冲（方案③）：固定容量、槽预分配、newest-wins——入队
// 永不阻塞（满环覆写最旧），内存精确上界=容量×槽字节。与攻击光流环形缓冲
// 同构（全系统 newest-wins 口径一致）。
//
// 生命周期安全：纯内存结构，无 goroutine、无 channel send——任何 Cleanup
// /负载切换路径都不可能因它阻塞（上游 remote_ip_list 死锁的同型缺陷在此
// 结构性不存在）。

import "sync"

type l4Ring struct {
	mu          sync.Mutex
	slots       [][]byte // 预分配槽数据（容量=slotBytes；写入复用缓冲，零增量分配）
	lens        []int    // 各槽有效长度
	count       int      // 有效条目数（≤容量）
	head        int      // 最旧条目位
	write       int      // 下一写入位
	overwritten uint64   // 满环覆写逐出的最旧事件累计（丢弃可观测）

	// 容量/槽字节为构造期参数（测试经 newL4Ring 收窄），运行期不可变。
	capacity  int
	slotBytes int
}

func newL4Ring(capacity, slotBytes int) *l4Ring {
	if capacity < 1 {
		capacity = 1
	}
	if slotBytes < 1 {
		slotBytes = 1
	}
	r := &l4Ring{
		capacity:  capacity,
		slotBytes: slotBytes,
	}
	r.slots = make([][]byte, capacity)
	r.lens = make([]int, capacity)
	for i := range r.slots {
		r.slots[i] = make([]byte, 0, slotBytes)
	}
	return r
}

// push 写入一行：满环覆写最旧（返回 evicted=1）。槽按需增长（上限由调用方
// 的单行上限把守）——容量内行复用预分配缓冲（零增量分配），超槽行一次性
// 扩容后槽保持（实际行 ~300B，增长在实践中不发生）。
func (r *l4Ring) push(line []byte) (evicted uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.count == r.capacity {
		// 覆写最旧：head 即最旧位，写入位与其重合（环满时 write==head）。
		r.head = (r.head + 1) % r.capacity
		r.count--
		evicted = 1
	}
	write := (r.head + r.count) % r.capacity
	if cap(r.slots[write]) < len(line) {
		r.slots[write] = make([]byte, len(line))
	}
	r.slots[write] = r.slots[write][:len(line)]
	copy(r.slots[write], line)
	r.lens[write] = len(line)
	if r.count < r.capacity {
		r.count++
	}
	return evicted
}

// pop 弹出最旧一行（拷贝到调用方提供的缓冲语义：返回槽切片的副本——槽会被
// 后续 push 复用，调用方不得持有）。空环返回 ok=false。
func (r *l4Ring) pop() ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.count == 0 {
		return nil, false
	}
	line := make([]byte, r.lens[r.head])
	copy(line, r.slots[r.head])
	r.head = (r.head + 1) % r.capacity
	r.count--
	return line, true
}

// depth 当前有效条目数（收尾刷盘/测试断言用）。
func (r *l4Ring) depth() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}
