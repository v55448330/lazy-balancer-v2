package wafiplist

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// disableStatThrottle 关闭 Evaluate 侧 stat 节流（默认 1s）。fail-stale 用例
// 必须在文件变化后真正走一次 stat+重建，否则第二次 Evaluate 落在节流窗内
// 直接返回缓存——「重建失败回退旧集合」分支根本不执行，断言恒绿。
func disableStatThrottle(t *testing.T) {
	t.Helper()
	prev := StatCheckInterval
	StatCheckInterval = 0
	t.Cleanup(func() { StatCheckInterval = prev })
}

// 运行期韧性：文件被删/被写坏时，在役名单不清空——继续按
// 最近一次成功加载的集合判定（原子投影器保证写入侧无半截文件；删除/损坏
// 属运维事故，清空拒绝面比陈旧更危险）。
func TestIPListFast_servesStaleOnRuntimeDelete(t *testing.T) {
	disableStatThrottle(t)
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
	disableStatThrottle(t)
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

// ParseIPEntry 4in6 归一：名单条目写作 4in6 映射形态（::ffff:a.b.c.d
// 裸 IP 或 ::ffff:a.b.c.d/120 前缀）时必须 Unmap 归一为 v4 前缀——netip 的 v4
// 前缀不含 4in6 地址，不归一则条目落入 v6 集、v4 查询恒不命中（名单静默失效）。
func TestParseIPEntry_unmaps4in6Entries(t *testing.T) {
	// 裸 4in6 → v4 /32
	p, err := ParseIPEntry("::ffff:1.2.3.4")
	if err != nil {
		t.Fatalf("parse bare 4in6: %v", err)
	}
	if want := netip.MustParsePrefix("1.2.3.4/32"); p != want {
		t.Fatalf("bare 4in6 = %s, want %s", p, want)
	}
	// 4in6 前缀 → v4 /24
	p, err = ParseIPEntry("::ffff:1.2.3.0/120")
	if err != nil {
		t.Fatalf("parse 4in6 prefix: %v", err)
	}
	if want := netip.MustParsePrefix("1.2.3.0/24"); p != want {
		t.Fatalf("4in6 prefix = %s, want %s", p, want)
	}
	// 回归：纯 v6 与纯 v4 形状不漂移
	if p, err = ParseIPEntry("2001:db8::/48"); err != nil || p != netip.MustParsePrefix("2001:db8::/48") {
		t.Fatalf("pure v6 drift: %s err=%v", p, err)
	}
	if p, err = ParseIPEntry("10.0.0.0/8"); err != nil || p != netip.MustParsePrefix("10.0.0.0/8") {
		t.Fatalf("pure v4 drift: %s err=%v", p, err)
	}
}

// 算子级端到端：4in6 裸 IP 与 /120 前缀两条目对被 Unmap 后的 v4
// 查询命中（修复前条目落入 v6 集，v4 查询恒不命中）。
func TestIPListFast_4in6EntriesHitV4Queries(t *testing.T) {
	dir := useAllowedDir(t)
	path := writeListFile(t, dir, "mapped-entries.txt", []string{"::ffff:203.0.113.7", "::ffff:198.51.100.0/120"})
	op := newOp(t, path)
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"203.0.113.7", true},   // 4in6 裸 IP 条目
		{"198.51.100.9", true},  // 4in6 /120 前缀条目（=v4 /24）
		{"198.51.101.9", false}, // 前缀外
		{"203.0.113.8", false},  // 裸条目相邻未命中
	} {
		if got := op.Evaluate(nil, tc.value); got != tc.want {
			t.Fatalf("Evaluate(%q)=%v, want %v", tc.value, got, tc.want)
		}
	}
}

// EvictIPListCache：淘汰后同路径下次加载重新读盘解析——
// services 侧删除孤儿文件后，fail-stale 不得把旧集合无限期留在内存。
func TestIPListFast_evictCacheForcesReparse(t *testing.T) {
	dir := useAllowedDir(t)
	path := writeListFile(t, dir, "evict.txt", []string{"203.0.113.0/24"})
	_ = newOp(t, path) // 构建期加载 → 缓存
	before := parseCountForTest.Load()
	// stat 未变 → 命中缓存不重新解析
	if _, err := loadIPListFileFresh(path); err != nil {
		t.Fatal(err)
	}
	if got := parseCountForTest.Load(); got != before {
		t.Fatalf("stat 命中不应重新解析: parses %d→%d", before, got)
	}
	// 淘汰 → 下次加载重新读盘解析
	if evicted := EvictIPListCache(path); evicted != 1 {
		t.Fatalf("EvictIPListCache=%d, want 1", evicted)
	}
	if _, err := loadIPListFileFresh(path); err != nil {
		t.Fatal(err)
	}
	if got := parseCountForTest.Load(); got != before+1 {
		t.Fatalf("淘汰后须重新解析: parses %d→%d, want %d", before, got, before+1)
	}
}

func TestIPListFast_evictWaitsForInFlightParse(t *testing.T) {
	dir := useAllowedDir(t)
	path := writeListFile(t, dir, "evict-inflight.txt", []string{"203.0.113.0/24"})
	_ = newOp(t, path)

	unlock := lockIPListLoad(path) // 模拟解析持锁、尚未写回缓存的窗口
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()
	done := make(chan int, 1)
	go func() { done <- EvictIPListCache(path) }()
	select {
	case got := <-done:
		unlock()
		unlock = nil
		t.Fatalf("eviction returned %d while the path parse lock was held; in-flight state can be revived", got)
	case <-time.After(50 * time.Millisecond):
		// 预期：淘汰必须等本代解析落定后再删除。
	}
	unlock()
	unlock = nil
	if got := <-done; got != 1 {
		t.Fatalf("EvictIPListCache=%d, want 1", got)
	}
	ipListCache.RLock()
	left := ipListCache.states[path]
	ipListCache.RUnlock()
	if left != nil {
		t.Fatal("completed eviction must not leave the old generation cached")
	}
}

// 体积/条目上限：超限文件构建期拒绝，防异常文件拖垮内存。
func TestIPListFast_loadCaps(t *testing.T) {
	dir := useAllowedDir(t)
	oldBytes, oldEntries := maxFileBytes, maxEntries
	maxFileBytes = 1024
	maxEntries = 8
	t.Cleanup(func() { maxFileBytes, maxEntries = oldBytes, oldEntries })

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

// 满量标尺不变式（2026-09-24 用户裁定「最大限度确保性能和可靠性」）：
// 20 万条（威胁库下载上限形态）混合名单经加载后——v4/v6 各自升序不相交
// （二分判定正确性前提），且对原始条目逐点命中、界外不命中（聚合前后
// 匹配集合逐点相等的大规模实证）。
func TestIPListFast_scaleInvariants200k(t *testing.T) {
	dir := useAllowedDir(t)
	const n = 200000
	entries := make([]string, 0, n)
	for i := range n {
		switch i % 3 {
		case 0:
			entries = append(entries, fmt.Sprintf("%d.%d.%d.0/24", 1+(i%220), (i*53)%256, (i*97)%256))
		case 1:
			entries = append(entries, fmt.Sprintf("%d.%d.%d.%d", 1+(i%220), (i*53)%256, (i*97)%256, (i*13)%250+1))
		default:
			entries = append(entries, fmt.Sprintf("2001:db8:%x::/48", i%0xffff))
		}
	}
	path := writeListFile(t, dir, "scale.txt", entries)
	op := newOp(t, path)

	state, err := resolveIPListFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, set := range [][]netip.Prefix{state.v4, state.v6} {
		if len(set) == 0 {
			t.Fatal("满量名单不应有空族")
		}
		for i := 1; i < len(set); i++ {
			if set[i-1].Addr().Compare(set[i].Addr()) >= 0 {
				t.Fatalf("非升序 at %d: %v vs %v", i, set[i-1], set[i])
			}
			if set[i-1].Contains(set[i].Addr()) || set[i].Contains(set[i-1].Addr()) {
				t.Fatalf("相交前缀 at %d: %v 与 %v", i, set[i-1], set[i])
			}
		}
	}
	// 命中抽查（按生成器实际产出：i=0 → 1.0.0.0/24；i=1 → 2.53.97.14；
	// i=131069 → 2001:db8:fffe::/48）
	for _, hit := range []string{"1.0.0.0", "1.0.0.255", "2.53.97.14", "2001:db8:fffe::1"} {
		if !op.Evaluate(nil, hit) {
			t.Fatalf("Evaluate(%q)=false, want true（满量名单命中）", hit)
		}
	}
	// 界外抽查
	for _, miss := range []string{"240.1.2.3", "203.0.113.99", "2001:db9::1", "1.0.1.0"} {
		if op.Evaluate(nil, miss) {
			t.Fatalf("Evaluate(%q)=true, want false（界外误判）", miss)
		}
	}
}

// 构建期去重（v2.3.x 强化）：同一文件被多个规则引用时，一次 Caddy reload 内
// N 个算子工厂调用共享同一份检索结构——stat 形态（mtime+size）命中即复用
// （策略名单稳定命名同字节跳写 mtime 不变；热路径原子重写/威胁库换名 mtime 必变）。
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

// 体积上限必须是**读侧**硬上限：调用方与本次读之间有窗口（tmp+rename
// 原子替换任意大小文件），只按判限等于没判——这里绕过 loadIPListFile
// 直接喂解析器，模拟「stat 见小、实际读到超大」的形态。
func TestParseIPListFile_enforcesMaxFileBytesAfterRead(t *testing.T) {
	dir := useAllowedDir(t)
	oldBytes := maxFileBytes
	maxFileBytes = 16
	t.Cleanup(func() { maxFileBytes = oldBytes })

	path := writeListFile(t, dir, "grew.txt", []string{"203.0.113.7", "198.51.100.0/24", "2001:db8::/32"})
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() <= maxFileBytes {
		t.Fatalf("fixture too small: %d bytes", info.Size())
	}
	if _, err := parseIPListFile(path); err == nil {
		t.Fatal("超过 maxFileBytes 的内容必须在读侧被拒绝（pre-stat 判限不构成硬上限）")
	}
}

// 代际元数据必须取自**实际读到的内容**：调用方 stat 之后文件被原子替换时，
// 解析结果与其 (mtime,size) 必须同代际——否则缓存命中判据会把上一代的
// stat 形态贴到新内容上。
func TestParseIPListFile_stampsGenerationFromReadContent(t *testing.T) {
	dir := useAllowedDir(t)
	path := writeListFile(t, dir, "gen.txt", []string{"203.0.113.7"})
	oldInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	// 模拟 stat→读 之间被 tmp+rename 替换为另一代际（尺寸不同）。
	time.Sleep(10 * time.Millisecond) // 保证 mtime 可辨
	if err := os.WriteFile(path, []byte("203.0.113.7\n198.51.100.0/24\n2001:db8::/32\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	newInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	state, err := parseIPListFile(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if state.size != newInfo.Size() {
		t.Fatalf("state.size=%d, want %d (读取内容的尺寸，而非 pre-stat 的 %d)",
			state.size, newInfo.Size(), oldInfo.Size())
	}
	if !state.mtime.Equal(newInfo.ModTime()) {
		t.Fatalf("state.mtime=%v, want %v (读取内容的 mtime，而非 pre-stat 的 %v)",
			state.mtime, newInfo.ModTime(), oldInfo.ModTime())
	}
}

// staleStatSource 模拟「stat 与读之间文件被原位改写」：第一次 Stat 返回改写
// 前的小尺寸形态，Read 从真实 inode 流式读（因此可读到改写后的内容），
// 第二次 Stat 返回当前真实形态——boundedReadSource 的替身注入点。
type staleStatSource struct {
	file  *os.File
	stale os.FileInfo
	stats int
	read  int64
}

func (s *staleStatSource) Stat() (os.FileInfo, error) {
	s.stats++
	if s.stats == 1 {
		return s.stale, nil
	}
	return s.file.Stat()
}

func (s *staleStatSource) Read(p []byte) (int, error) {
	n, err := s.file.Read(p)
	s.read += int64(n)
	return n, err
}

// 有界代际读（名单加载器与爬虫段快照加载器共用同一原语）：
//   - 定长读以 pre-stat 尺寸为准，stat 与读之间被原位追加不得放大读入量；
//   - 读后复核同一 inode，形态变化（追加/截断/同尺寸改写）必须放弃本次
//     加载——混合字节不能当作一代内容落定。
func TestReadBoundedFile_boundedGenerationRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(path, []byte("203.0.113.7\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("追加不放大读入量且拒绝混合代际", func(t *testing.T) {
		fd, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer fd.Close()
		before, err := fd.Stat()
		if err != nil {
			t.Fatal(err)
		}
		appendFd, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := appendFd.WriteString(strings.Repeat("# pad\n", 4096)); err != nil {
			appendFd.Close()
			t.Fatal(err)
		}
		if err := appendFd.Close(); err != nil {
			t.Fatal(err)
		}

		src := &staleStatSource{file: fd, stale: before}
		raw, _, err := readBoundedFrom(src, path, 1<<20)
		if !errors.Is(err, ErrFileRewriteDuringRead) {
			t.Fatalf("err=%v, want ErrFileRewriteDuringRead（读后形态变化必须拒绝）", err)
		}
		if raw != nil {
			t.Fatal("拒绝的读取不得返回内容")
		}
		if src.read != before.Size() {
			t.Fatalf("实际读入 %d 字节, want %d（定长读不得被追加放大）", src.read, before.Size())
		}
	})

	t.Run("未改写读取成功且形态取自同一 inode", func(t *testing.T) {
		raw, info, err := ReadBoundedFile(path, 1<<20)
		if err != nil {
			t.Fatalf("readBoundedFile: %v", err)
		}
		if int64(len(raw)) != info.Size() {
			t.Fatalf("读入 %d 字节, stat %d 字节（同一代际）", len(raw), info.Size())
		}
	})

	t.Run("超限拒绝", func(t *testing.T) {
		if _, _, err := ReadBoundedFile(path, 4); !errors.Is(err, ErrFileSizeLimit) {
			t.Fatalf("err=%v, want ErrFileSizeLimit", err)
		}
	})
}

// 缓存被淘汰 + 文件消失（上次 reload 失败、运行配置仍旧）时 Evaluate 按未命中
// 处理——黑名单方向 fail-open，且旧实现完全静默。该形态必须按路径节流上报，
// 否则静默放行直到 reload 成功无任何痕迹。
func TestIPListFast_reportsUnavailableWhenCacheEvictedAndFileGone(t *testing.T) {
	disableStatThrottle(t)
	dir := useAllowedDir(t)
	path := writeListFile(t, dir, "unavailable.txt", []string{"203.0.113.7"})
	op := newOp(t, path)
	if !op.Evaluate(nil, "203.0.113.7") {
		t.Fatal("初始加载判定错误")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	EvictIPListCache(path)

	var calls int
	oldHook, oldInterval := OnListUnavailableServe, staleServeLogInterval
	OnListUnavailableServe = func(string, error) { calls++ }
	staleServeLogInterval = time.Minute
	t.Cleanup(func() {
		OnListUnavailableServe, staleServeLogInterval = oldHook, oldInterval
		clearStaleReport(path)
	})

	if op.Evaluate(nil, "203.0.113.7") {
		t.Fatal("无缓存且文件消失必须按未命中（fail-open 方向）")
	}
	if op.Evaluate(nil, "203.0.113.7") {
		t.Fatal("第二次判定仍按未命中")
	}
	if calls != 1 {
		t.Fatalf("不可读告警次数=%d, want 1（按路径节流，不逐请求刷屏）", calls)
	}
}

// 白名单内的符号链接指向白名单外：构建期（Provision/算子构建）必须拒绝。
// Clean+前缀只防 `..` 穿越，symlink 可绕过；运行期热路径不做 EvalSymlinks
// （每请求 syscall），故硬边界落在归一入口。白名单内的链接指向白名单内
// 目标仍合法。
func TestIPListFast_symlinkEscapeRejected(t *testing.T) {
	dir := useAllowedDir(t)
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "outside.txt")
	if err := os.WriteFile(outside, []byte("203.0.113.7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	escape := filepath.Join(dir, "escape.txt")
	if err := os.Symlink(outside, escape); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if _, err := newIPListFast(plugintypes.OperatorOptions{Arguments: escape}); err == nil {
		t.Fatal("白名单内 symlink 指向白名单外必须在构建期被拒绝")
	}

	// 白名单内链接（相对目标）合法。
	inside := writeListFile(t, dir, "inside.txt", []string{"203.0.113.8"})
	friendly := filepath.Join(dir, "inside-link.txt")
	if err := os.Symlink(filepath.Base(inside), friendly); err != nil {
		t.Fatalf("create inside symlink: %v", err)
	}
	op := newOp(t, friendly)
	if !op.Evaluate(nil, "203.0.113.8") {
		t.Fatal("白名单内 symlink 指向白名单内目标必须正常加载")
	}
}

// 预分配容量必须被 initialPrefixCapacity 封顶：注释/空行密集的大文件
// （带外写入、损坏残留）按 len/12 预估会一次申请 32MiB（每项 32B）却几乎全空。
func TestPrefixCapHint_boundedOnCommentHeavyFiles(t *testing.T) {
	cases := []struct {
		name string
		size int
		want int
	}{
		{"empty", 0, 1},
		{"small list", 12*100 + 1, 101},
		{"at cap", initialPrefixCapacity * 12, initialPrefixCapacity},
		{"64MiB comment-only file", 64 << 20, initialPrefixCapacity},
		{"zero size", 0, 1},
	}
	for _, tc := range cases {
		if got := prefixCapHint(tc.size); got != tc.want {
			t.Errorf("%s: prefixCapHint(%d)=%d, want %d", tc.name, tc.size, got, tc.want)
		}
	}
	// 上界与 maxEntries 语义无关：即便 maxEntries 被测试收窄到极小值，
	// 预分配也不得超过条目硬上限。
	oldEntries := maxEntries
	maxEntries = 4
	t.Cleanup(func() { maxEntries = oldEntries })
	if got := prefixCapHint(64 << 20); got > maxEntries+1 {
		t.Fatalf("预分配 %d 超过条目硬上限 %d", got, maxEntries+1)
	}
}
