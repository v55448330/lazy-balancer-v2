package caddyl4sec

import "time"

// —— 测试缝（仅测试编译进插件测试二进制；生产零调用面）——
// auditwriter 同形态：管线/计数注册表是进程级单例，测试以「重建 + 保存恢复」
// 获得隔离，不引入生产分支。

// setTunablesForTest 收窄队列/入队超时（返回快照供 restoreTunables 恢复）。
func setTunablesForTest(queueSize int, byteBudget int64, enqueueTimeout time.Duration) []any {
	saved := []any{l4QueueSize, l4QueueByteBudget, l4EnqueueTimeout}
	l4QueueSize = queueSize
	l4QueueByteBudget = byteBudget
	l4EnqueueTimeout = enqueueTimeout
	return saved
}

// restoreTunables 恢复 setTunablesForTest 快照。
func restoreTunables(saved []any) {
	l4QueueSize = saved[0].(int)
	l4QueueByteBudget = saved[1].(int64)
	l4EnqueueTimeout = saved[2].(time.Duration)
}

// setSampleCountryLookuperForTest 重定向采样查库缝（save/restore）。
func setSampleCountryLookuperForTest(fn func(ip string) (string, bool)) (restore func()) {
	saved := l4SampleLookup
	l4SampleLookup = func(xdbPath, ip string) (string, bool) { return fn(ip) }
	return func() { l4SampleLookup = saved }
}

// acquirePipelineForTest 重建进程级管线（先排掉旧实例——含 shipper.close 封存
// spool），再按当前 env/包级变量构造并启动新实例。
func acquirePipelineForTest() *l4Pipeline {
	l4PipelineMu.Lock()
	defer l4PipelineMu.Unlock()
	teardownPipelineLocked()
	p := newL4Pipeline()
	l4GlobalPipeline = p
	p.start()
	return p
}

// teardownPipelineLocked 排空并停掉当前全局管线（持锁调用）。
func teardownPipelineLocked() {
	if l4GlobalPipeline == nil {
		return
	}
	p := l4GlobalPipeline
	l4GlobalPipeline = nil
	p.flushQuiesced(2 * time.Second)
	close(p.stopCh)
	<-p.done
}

// (p) resetForTest = 冲刷排空 + 停 drain + 清全局引用（下一个 acquire 重建）。
func (p *l4Pipeline) resetForTest() {
	p.flushQuiescedForTest()
	l4PipelineMu.Lock()
	defer l4PipelineMu.Unlock()
	if l4GlobalPipeline == p {
		l4GlobalPipeline = nil
	}
	close(p.stopCh)
	<-p.done
}

// (p) stopAndCloseForTest 收尾形态（TestShipperFailureSpools 断言 close 后
// 目录只剩 sealed）：冲刷 + 停 drain（drain 内部完成 shipper.close 封存）。
func (p *l4Pipeline) stopAndCloseForTest() error {
	p.flushQuiescedForTest()
	l4PipelineMu.Lock()
	if l4GlobalPipeline == p {
		l4GlobalPipeline = nil
	}
	l4PipelineMu.Unlock()
	close(p.stopCh)
	<-p.done
	return nil
}

// (p) flushQuiescedForTest 等待已准入行全部处理完并冲刷残留批。
func (p *l4Pipeline) flushQuiescedForTest() {
	p.flushQuiesced(2 * time.Second)
}

// (p) blockDrainForTest 暂停/恢复 drain 消费（制造队列满的确定性形态）。
func (p *l4Pipeline) blockDrainForTest(blocked bool) {
	p.paused.Store(blocked)
}

// (p) setSubmitSinkForTest 重定向 drain submit 落点（全链形状断言）。
func (p *l4Pipeline) setSubmitSinkForTest(fn func([]byte)) {
	p.sinkMu.Lock()
	p.sink = fn
	p.sinkMu.Unlock()
}

// resetConnStatsForTest 清空计数注册表（含载次身份）。
func resetConnStatsForTest() {
	connStats.mu.Lock()
	defer connStats.mu.Unlock()
	connStats.loadCtx = nil
	connStats.rules = map[string]*ruleConnCounters{}
}

// ctxKeyLoad 是测试造不同载次身份的 context 键。
type ctxKeyLoad struct{}
