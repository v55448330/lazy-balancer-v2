package wafiplist

import (
	"fmt"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// 运行期韧性（fail-stale）：文件被删/被写坏时，在役名单不清空——继续按
// 最近一次成功加载的集合判定（原子投影器保证写入侧无半截文件；删除/损坏
// 属运维事故，清空拒绝面比陈旧更危险）。
func TestIPListFast_servesStaleOnRuntimeDelete(t *testing.T) {
	dir := useAllowedDir(t)
	path := writeListFile(t, dir, "stale.txt", []string{"203.0.113.7"})
	op := newOp(t, path)
	if !op.Evaluate(nil, "203.0.113.7") {
		t.Fatal("初始加载判定错误")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if !op.Evaluate(nil, "203.0.113.7") {
		t.Fatal("文件删除后必须按最后一次成功加载判定（fail-stale）")
	}
}

func TestIPListFast_servesStaleOnCorruptReload(t *testing.T) {
	dir := useAllowedDir(t)
	path := writeListFile(t, dir, "corrupt.txt", []string{"203.0.113.7"})
	op := newOp(t, path)
	// 写坏内容并推进 mtime（触发重建路径）
	if err := os.WriteFile(path, []byte("garbage-not-an-ip\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	if !op.Evaluate(nil, "203.0.113.7") {
		t.Fatal("重建失败（坏行）必须回退到旧集合（fail-stale），不得清空")
	}
}

// 4in6 映射形态（::ffff:1.2.3.4）必须命中 v4 前缀——netip 的 v4 前缀
// 不含 4in6 地址（实测），Evaluate 须 Unmap。
func TestIPListFast_unmaps4in6(t *testing.T) {
	dir := useAllowedDir(t)
	path := writeListFile(t, dir, "mapped.txt", []string{"1.2.3.0/24"})
	op := newOp(t, path)
	if !op.Evaluate(nil, "::ffff:1.2.3.4") {
		t.Fatal("4in6 映射地址须命中 v4 前缀")
	}
}

// 体积/条目上限：超限文件构建期拒绝（fail-closed），防异常文件拖垮内存。
func TestIPListFast_loadCaps(t *testing.T) {
	dir := useAllowedDir(t)
	oldBytes, oldEntries := MaxFileBytes, MaxEntries
	MaxFileBytes = 1024
	MaxEntries = 8
	t.Cleanup(func() { MaxFileBytes, MaxEntries = oldBytes, oldEntries })

	big := writeListFile(t, dir, "big.txt", []string{"203.0.113.7"})
	if err := os.Truncate(big, 2048); err != nil { // 稀疏扩容超过 cap
		t.Fatal(err)
	}
	if _, err := newIPListFast(plugintypes.OperatorOptions{Arguments: big}); err == nil {
		t.Fatal("超体积上限文件必须拒绝")
	}
	// 新前缀目录避免缓存干扰
	dir2 := useAllowedDir(t)
	var many []string
	for i := range 9 {
		many = append(many, fmt.Sprintf("10.0.0.%d", i+1))
	}
	manyPath := writeListFile(t, dir2, "many.txt", many)
	if _, err := newIPListFast(plugintypes.OperatorOptions{Arguments: manyPath}); err == nil {
		t.Fatal("超条目上限文件必须拒绝")
	}
}

// stat 节流：StatCheckInterval>0 时间隔内 Evaluate 不重复 stat（热路径
// 每请求一 syscall 的成本消除）；0=每次都查（测试与构建期语义）。
func TestIPListFast_statThrottle(t *testing.T) {
	dir := useAllowedDir(t)
	path := writeListFile(t, dir, "throttle.txt", []string{"203.0.113.7"})
	old := StatCheckInterval
	StatCheckInterval = time.Hour // 窗口内不复查
	t.Cleanup(func() { StatCheckInterval = old })
	op := newOp(t, path)

	// 文件变更但节流窗口内：仍按缓存判定
	if err := os.WriteFile(path, []byte("198.51.100.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !op.Evaluate(nil, "203.0.113.7") {
		t.Fatal("节流窗口内应按缓存判定")
	}
	// 节流关闭后立即感知
	StatCheckInterval = 0
	if op.Evaluate(nil, "203.0.113.7") || !op.Evaluate(nil, "198.51.100.9") {
		t.Fatal("节流关闭后必须立即感知文件变化")
	}
}

// 聚合产出不变式：升序 + 两两不相交（二分正确性依赖）。
func TestAggregatePrefixes_sortedAndDisjoint(t *testing.T) {
	entries := []string{
		"10.0.0.0/25", "10.0.0.128/25", // 兄弟归并
		"203.0.113.0/24", "203.0.113.7", // 覆盖剔除
		"2001:db8::/64", "2001:db8::1", // v6 覆盖
		"192.0.2.0/25",
	}
	got := AggregatePrefixes(entries)
	for i := 1; i < len(got); i++ {
		if got[i-1].Addr().Compare(got[i].Addr()) >= 0 {
			t.Fatalf("非升序: %v", got)
		}
		if got[i-1].Contains(got[i].Addr()) || got[i].Contains(got[i-1].Addr()) {
			t.Fatalf("相交前缀: %v 与 %v", got[i-1], got[i])
		}
	}
	// 等价性抽查
	for _, probe := range []string{"10.0.0.200", "203.0.113.7", "203.0.114.1", "2001:db8::5", "192.0.2.99"} {
		addr := netip.MustParseAddr(probe)
		in := false
		for _, p := range got {
			if p.Contains(addr) {
				in = true
				break
			}
		}
		want := probe != "203.0.114.1"
		if in != want {
			t.Fatalf("probe %s: got=%v want=%v", probe, in, want)
		}
	}
}

// 边界探针：每个前缀的首地址/末地址/界外 ±1 逐点判定。
func TestIPListFast_boundaryProbes(t *testing.T) {
	dir := useAllowedDir(t)
	path := writeListFile(t, dir, "boundary.txt", []string{"10.9.0.0/24", "2001:db8:abcd::/48"})
	op := newOp(t, path)
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"10.9.0.0", true},      // 首地址
		{"10.9.0.255", true},    // 末地址
		{"10.9.1.0", false},     // 末地址+1
		{"10.8.255.255", false}, // 首地址-1
		{"2001:db8:abcd::", true},
		{"2001:db8:abcd:ffff:ffff:ffff:ffff:ffff", true},
		{"2001:db8:abce::", false},
		{"2001:db8:abcc:ffff:ffff:ffff:ffff:ffff", false},
	} {
		if got := op.Evaluate(nil, tc.ip); got != tc.want {
			t.Fatalf("Evaluate(%q)=%v, want %v", tc.ip, got, tc.want)
		}
	}
}

// 并发判定 + 并发重建（-race 下运行）：无 data race、无 panic。
func TestIPListFast_concurrentEvaluateAndReload(t *testing.T) {
	dir := useAllowedDir(t)
	path := writeListFile(t, dir, "race.txt", []string{"203.0.113.7"})
	old := StatCheckInterval
	StatCheckInterval = 0
	t.Cleanup(func() { StatCheckInterval = old })
	op := newOp(t, path)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					op.Evaluate(nil, "203.0.113.7")
					op.Evaluate(nil, "203.0.113.8")
				}
			}
		}()
	}
	// 并发重写文件（合法内容，mtime 推进）
	for i := range 20 {
		if err := os.WriteFile(path, []byte(fmt.Sprintf("203.0.113.%d\n", i%250+1)), 0o644); err != nil {
			t.Fatal(err)
		}
		f := time.Now().Add(time.Duration(i+10) * time.Second)
		if err := os.Chtimes(path, f, f); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
}

// 构建期去重（v2.3.x 强化）：同一文件被多个规则引用时，一次 Caddy reload 内
// N 个算子工厂调用共享同一份检索结构——stat 形态（mtime+size）命中即复用
// （策略名单内容寻址：同路径=同内容；威胁库原子换名 mtime 必变）。
func TestIPListFast_factoryDedupSharedState(t *testing.T) {
	dir := useAllowedDir(t)
	path := writeListFile(t, dir, "dedup.txt", []string{"203.0.113.7"})

	before := parseCountForTest.Load()
	op1 := newOp(t, path)
	op2 := newOp(t, path)
	op3 := newOp(t, path)
	if got := parseCountForTest.Load() - before; got != 1 {
		t.Fatalf("三次工厂调用解析次数=%d, want 1（共享去重）", got)
	}
	_ = op1
	_ = op2
	_ = op3

	// 内容变化（mtime 推进）后新工厂必须拿到新集合
	if err := os.WriteFile(path, []byte("198.51.100.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	before = parseCountForTest.Load()
	op4 := newOp(t, path)
	if got := parseCountForTest.Load() - before; got != 1 {
		t.Fatalf("内容变化后工厂须重建, 解析次数增量=%d", got)
	}
	old := StatCheckInterval
	StatCheckInterval = 0
	t.Cleanup(func() { StatCheckInterval = old })
	if op4.Evaluate(nil, "203.0.113.7") || !op4.Evaluate(nil, "198.51.100.9") {
		t.Fatal("内容变化后新算子判定未更新")
	}
}
