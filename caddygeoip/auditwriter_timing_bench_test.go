package caddygeoip

import (
	"sync/atomic"
	"testing"
	"time"
)

// BenchmarkTimingRegister 模拟高并发「注册+关闭」稳态热路径：每操作
// pre/end 两段写入 + 终态 close（与每请求 blocked_counter 收点同形）。
// id 空间按 worker 局部循环复用，TTL 收窄到 1ms 使复用大多落到
// 「过期重建」分支——注册表稳态有界（≤workers×4096 ≈ 50k 条目，远低于
// auditTimingMaxEntries=100k，上限拒绝路径不污染测量）。
// before/after 各跑 5s（-benchtime=5s），对比 ns/op 与 allocs/op。
func BenchmarkTimingRegister(b *testing.B) {
	origTTL := auditTimingEntryTTLNs.Swap(int64(time.Millisecond))
	origSweep := auditTimingSweepIntervalNs.Swap(int64(200 * time.Millisecond))
	b.Cleanup(func() {
		auditTimingEntryTTLNs.Store(origTTL)
		auditTimingSweepIntervalNs.Store(origSweep)
	})

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		// 每 worker 一组 4096 个合法 16-hex id（互不重叠：worker 序号进高位）。
		worker := benchWorkerSeq.Add(1)
		const idsPerWorker = 4096
		ids := make([]string, idsPerWorker)
		var raw [8]byte
		for i := range ids {
			raw[0], raw[1] = byte(worker>>8), byte(worker)
			raw[2], raw[3], raw[4], raw[5], raw[6], raw[7] =
				byte(i>>8), byte(i), byte(i>>16), byte(i>>24), byte(i>>32), byte(i>>40)
			ids[i] = hexString16(raw)
		}
		i := 0
		for pb.Next() {
			id := ids[i&(idsPerWorker-1)]
			i++
			auditTimingRecord(id, timingSegmentPre, 123)
			auditTimingRecord(id, timingSegmentEnd, 456)
			auditTimingClose(id)
		}
	})
}

// BenchmarkTimingLoggedLookup 是读路径对照（blocked_counter 收点的
// auditTimingLogged 查表）：预建带 logged 标记的条目后循环读，TTL 默认
// （30s，5s 基准内条目不过期）——隔离出纯查表+锁成本。
func BenchmarkTimingLoggedLookup(b *testing.B) {
	const ids = 4096
	ids0 := make([]string, ids)
	for i := range ids0 {
		ids0[i] = fmt16(i)
		auditTimingRecord(ids0[i], timingSegmentLogged, 0)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			auditTimingLogged(ids0[i&(ids-1)])
			i++
		}
	})
}

var benchWorkerSeq atomic.Uint64

// hexString16 把 8 字节编码为 16 字符小写 hex（不引入 fmt 分配）。
func hexString16(raw [8]byte) string {
	const hexdigits = "0123456789abcdef"
	var out [16]byte
	for i, v := range raw {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0f]
	}
	return string(out[:])
}

// fmt16 生成 %016x 形态的 16-hex id（基准预热用，量小允许 fmt 分配）。
func fmt16(v int) string {
	const hexdigits = "0123456789abcdef"
	var out [16]byte
	for i := 15; i >= 0; i-- {
		out[i] = hexdigits[v&0xf]
		v >>= 4
	}
	return string(out[:])
}
