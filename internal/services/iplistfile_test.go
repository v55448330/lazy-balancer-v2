package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/wafiplist"
)

// TestMain：全包共享一个临时 IP 名单目录——@ipListFast 渲染改造后，凡含
// IP 名单的策略渲染都会经 writeIPListFile 落盘（fail-closed：写失败=渲染
// 报错）；默认 /app/waf/ip-lists 在开发机不可写，统一改指临时目录并把
// 算子白名单前缀对齐（算子构建期会真实读文件）。
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "lb-iplists-test")
	if err != nil {
		panic(err)
	}
	IPListDataDir = dir
	wafiplist.AllowedPathPrefix = dir + string(filepath.Separator)
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// readRenderedIPList 从渲染产物中抽取含 scopeMarker 的 @ipListFast 文件名
// 并读回文件内容——形状断言（id/动作/链结构）之外的名单内容断言入口，
// 取代旧内联 @ipMatch 的文本钉。
func readRenderedIPList(t *testing.T, directives, scopeMarker string) string {
	t.Helper()
	for _, line := range strings.Split(directives, "\n") {
		idx := strings.Index(line, "@ipListFast ")
		if idx < 0 || !strings.Contains(line, scopeMarker) {
			continue
		}
		rest := line[idx+len("@ipListFast "):]
		end := strings.IndexAny(rest, "\" \t")
		if end < 0 {
			end = len(rest)
		}
		content, err := os.ReadFile(rest[:end])
		if err != nil {
			t.Fatalf("读回渲染名单文件失败: %v", err)
		}
		return string(content)
	}
	t.Fatalf("渲染产物中未找到 scope=%s 的 @ipListFast 规则:\n%s", scopeMarker, directives)
	return ""
}

// writeIPListFile（2026-10-15 热路径改造）：稳定命名 <scope>.txt（scope 字符串
// 本身即投影实例身份——策略 id/并集描述符；名单改名/内容变化都不改变文件名）、
// 聚合后落盘、原子写（tmp+rename）、同字节跳写（全量渲染重投影 stat 命中且
// 内容一致 → 不重写，mtime 保持）、内容变化 → 同路径原子换内容（配置字节
// 不变，@ipListFast 匹配器 ≤1s stat 热感知）、空集合投影空文件并返回路径。
func TestWriteIPListFile_stableNaming(t *testing.T) {
	// Given
	entries := []string{"10.0.0.128/25", "10.0.0.0/25", "203.0.113.7", "203.0.113.7"}

	// When
	path1, err := writeIPListFile("u-bl", entries)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	// Then：文件名恰为 <scope>.txt，内容聚合（兄弟归并 10.0.0.0/24 + 归一 /32）
	if base := filepath.Base(path1); base != "u-bl.txt" {
		t.Fatalf("文件名 %q, want 恰为 u-bl.txt（稳定命名）", base)
	}
	content, err := os.ReadFile(path1)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "10.0.0.0/24\n203.0.113.7/32\n" {
		t.Fatalf("文件内容=%q, want 聚合排序形态", content)
	}
	// 幂等：同内容同路径
	path2, err := writeIPListFile("u-bl", entries)
	if err != nil || path2 != path1 {
		t.Fatalf("幂等写 path=%q err=%v, want %q", path2, err, path1)
	}
	// 原子写：无 .tmp 残留
	if leftovers, _ := filepath.Glob(filepath.Join(IPListDataDir, "*.tmp")); len(leftovers) > 0 {
		t.Fatalf("tmp 残留: %v", leftovers)
	}
	// 不同 scope 同内容 → 不同文件
	path3, err := writeIPListFile("p1-trust", entries)
	if err != nil || path3 == path1 || filepath.Base(path3) != "p1-trust.txt" {
		t.Fatalf("scope 隔离失败: %q vs %q", path3, path1)
	}

	// 内容变化 → 同路径原子换内容（稳定命名的核心契约：名单内容变化不得
	// 改变文件名/配置字节）
	newEntries := []string{"192.0.2.44", "203.0.113.7"}
	path4, err := writeIPListFile("u-bl", newEntries)
	if err != nil || path4 != path1 {
		t.Fatalf("内容变化应复用同一路径: path=%q err=%v, want %q", path4, err, path1)
	}
	content4, err := os.ReadFile(path1)
	if err != nil {
		t.Fatal(err)
	}
	if string(content4) != "192.0.2.44/32\n203.0.113.7/32\n" {
		t.Fatalf("内容变化后文件内容=%q, want 新集合聚合形态", content4)
	}
}

// 同字节跳写：内容一致的重投影（全量渲染重投影不动）不得重写文件——mtime
// 保持不变（wafiplist stat 形态缓存命中，运行期匹配器零重建）。
func TestWriteIPListFile_identicalContentSkipsWrite(t *testing.T) {
	entries := []string{"203.0.113.9"}
	path, err := writeIPListFile("u-skip", entries)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	first, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// When：同内容重投影
	if _, err := writeIPListFile("u-skip", entries); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	// Then：mtime 未变（未发生重写）
	second, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !first.ModTime().Equal(second.ModTime()) {
		t.Fatalf("同内容重投影不应重写文件: mtime %v → %v", first.ModTime(), second.ModTime())
	}
}

// 空集合投影空文件（2026-10-15 始终发射裁定）：不再返回空串不写文件——稳定
// 命名空文件照常落盘、路径照常返回，调用方恒发射 @ipListFast（空集永不命中
// =与无规则语义等价），空↔非空由此降为纯内容变化全走投影热路径。
func TestWriteIPListFile_emptyProjectsStableEmptyFile(t *testing.T) {
	path, err := writeIPListFile("u-empty", nil)
	if err != nil || path == "" {
		t.Fatalf("空集合 path=%q err=%v, want 非空路径（空文件投影）", path, err)
	}
	if base := filepath.Base(path); base != "u-empty.txt" {
		t.Fatalf("文件名 %q, want u-empty.txt（稳定命名）", base)
	}
	content, err := os.ReadFile(path)
	if err != nil || len(content) != 0 {
		t.Fatalf("空投影文件内容=%q err=%v, want 0 字节空文件", content, err)
	}
	// 幂等：同空内容重投影同路径（同字节跳写契约对空文件同样成立）
	path2, err := writeIPListFile("u-empty", nil)
	if err != nil || path2 != path {
		t.Fatalf("空内容幂等写 path=%q err=%v, want %q", path2, err, path)
	}
}

// ipListRuleOperand（2026-10-15 始终发射裁定）：空名单不再返回空串——投影空
// 文件后恒返回 @ipListFast 算子（negated 前缀 !），空↔非空纯内容变化走热路径。
func TestIPListRuleOperand_emptyListAlwaysEmits(t *testing.T) {
	operand, err := ipListRuleOperand("u-operand-empty", nil, false)
	if err != nil || operand == "" {
		t.Fatalf("空名单 operand=%q err=%v, want 恒发射非空算子", operand, err)
	}
	wantPath := filepath.Join(IPListDataDir, "u-operand-empty.txt")
	if operand != "@ipListFast "+wantPath {
		t.Fatalf("operand=%q, want @ipListFast %s", operand, wantPath)
	}
	if content, err := os.ReadFile(wantPath); err != nil || len(content) != 0 {
		t.Fatalf("空投影文件内容=%q err=%v, want 空文件已落盘", content, err)
	}
	negated, err := ipListRuleOperand("u-operand-empty", nil, true)
	if err != nil || negated != "!"+operand {
		t.Fatalf("negated operand=%q err=%v, want !%s", negated, err, operand)
	}
}

// gcStaleIPListFiles（F49-3 文件+缓存 GC）：成功投影后按「近期渲染引用的
// 文件集」差集清理——超龄（mtime 早于 24h）且未引用的投影命名文件被删
// （含旧内容寻址形态：迁移过渡分支）；引用中的文件与重载窗口内（mtime 新）
// 的未引用文件不动；非投影命名文件不碰。
func TestGCStaleIPListFiles_removesOldUnreferencedOnly(t *testing.T) {
	// Given：投影 A（引用中）与 B（将被遗弃，新稳定命名 u- 形态）；另造超龄
	// 未引用文件 C（旧内容寻址形态——迁移期 GC 自然回收钉）、新鲜未引用文件
	// D、非投影命名文件 E
	pathA, err := writeIPListFile("u-gckeep", []string{"203.0.113.1"})
	if err != nil {
		t.Fatalf("write A: %v", err)
	}
	pathB, err := writeIPListFile("u-gcdrop", []string{"198.51.100.1"})
	if err != nil {
		t.Fatalf("write B: %v", err)
	}
	old := time.Now().Add(-48 * time.Hour)
	for _, p := range []string{pathA, pathB} {
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	// B 从引用集中剔除（模拟本轮渲染不再引用）
	forgetIPListRenderRefForTest(pathB)
	pathC := filepath.Join(IPListDataDir, "orphan-deadbeef0012.txt")
	if err := os.WriteFile(pathC, []byte("192.0.2.1/32\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(pathC, old, old); err != nil {
		t.Fatal(err)
	}
	pathD, err := writeIPListFile("u-gcfresh", []string{"192.0.2.9"})
	if err != nil {
		t.Fatalf("write D: %v", err)
	}
	forgetIPListRenderRefForTest(pathD) // 未引用但 mtime 新（重载窗口保护）
	pathE := filepath.Join(IPListDataDir, "notes.txt")
	if err := os.WriteFile(pathE, []byte("not a projection\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(pathE, old, old); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(pathC); _ = os.Remove(pathE) })

	// When
	removed := gcStaleIPListFiles(time.Now(), 24*time.Hour)

	// Then：B/C 删除，A/D/E 保留
	for _, p := range []string{pathB, pathC} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("超龄未引用文件 %s 应被删除, stat err=%v", filepath.Base(p), err)
		}
	}
	for _, p := range []string{pathA, pathD, pathE} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("文件 %s 应保留: %v", filepath.Base(p), err)
		}
	}
	if removed != 2 {
		t.Fatalf("removed=%d, want 2", removed)
	}
}

// P5-19（第 50 轮审计）：gcStaleIPListFiles 顺带 prune lastRef 中早于 maxAge
// 的引用条目——否则引用集只增不删（孤儿文件的引用记录永久驻留内存）；
// 未超龄条目保留（prune 不依赖文件是否存在）。
func TestGCStaleIPListFiles_prunesStaleRefEntries(t *testing.T) {
	stale := filepath.Join(IPListDataDir, "stale-deadbeef00aa.txt")
	fresh := filepath.Join(IPListDataDir, "fresh-deadbeef00bb.txt")
	ipListRenderRefs.Lock()
	ipListRenderRefs.lastRef[stale] = time.Now().Add(-48 * time.Hour)
	ipListRenderRefs.lastRef[fresh] = time.Now()
	ipListRenderRefs.Unlock()
	t.Cleanup(func() { forgetIPListRenderRefForTest(stale); forgetIPListRenderRefForTest(fresh) })

	// When
	gcStaleIPListFiles(time.Now(), 24*time.Hour)

	// Then：超龄条目被 prune，未超龄保留
	ipListRenderRefs.Lock()
	_, staleOK := ipListRenderRefs.lastRef[stale]
	_, freshOK := ipListRenderRefs.lastRef[fresh]
	ipListRenderRefs.Unlock()
	if staleOK {
		t.Fatal("超龄引用条目未被 prune（lastRef 只增不删）")
	}
	if !freshOK {
		t.Fatal("未超龄引用条目被误 prune")
	}
}

// GC regex 形态（2026-10-15 热路径改造；第 77 轮 HP77-2/HP77-4 收口）：新稳定
// 命名（<scope>.txt——u- 并集描述符 / p<id>-角色 白名单形态）、crsxc 组合键
// 哈希形态（HP77-4）与旧内容寻址形态（scope-sha256[:12].txt——迁移期 GC 自然
// 回收）都命中；大写/含点 rule id 形态命中（HP77-2：v2 导入可携带，旧字符类
// 使孤儿永不回收）；用户手放文件（非投影命名形态）不碰。
func TestIPListProjectedFileName_forms(t *testing.T) {
	matched := []string{
		"u-deny.txt", "u-trust.txt", "u-trust12.txt", "u-bl.txt", "u-allow.txt", "u-allow-exempt.txt",
		"p12-acl.txt", "p7-trust.txt", "p3-bl.txt",
		"u-gcdrop.txt",             // 测试注入的 u- 描述符形态
		"u-deny-abc123def456.txt",  // 旧内容寻址形态（迁移期回收）
		"p12-acl-0123456789ab.txt", // 旧形态（策略 scope）
		"orphan-deadbeef0012.txt",  // 旧形态（任意 scope 前缀，精确 12 位 hex）
		// 第 76 轮 HP-1 新形态：u-<kind>-<ruleCaddyID>（CaddyID 含下划线）
		"u-deny-lb_2r8dosptk1.txt", "u-trust12-lb_2r8dosptk1.txt", "u-allow-exempt-lb_ab12cd34ef56.txt",
		"p5-crsxc-0.txt",            // 第 76 轮 SEC-1 序号形态（HP77-4 后存量，GC 过渡回收）
		"p5-crsxc-0123456789ab.txt", // 第 77 轮 HP77-4 组合键哈希形态
		// 第 77 轮 HP77-2：导入可携带大写/含点 rule id——孤儿必须可回收
		"u-deny-lb_2R8d.ptk1.txt", "u-bl-My_Rule.1.txt", "u-trust-lbUPPER123.txt",
	}
	for _, name := range matched {
		if !ipListProjectedFileName.MatchString(name) {
			t.Fatalf("投影命名 %q 应命中 GC regex", name)
		}
	}
	unmatched := []string{
		"notes.txt",                 // 用户手放
		"backup.txt",                // 用户手放
		"deny-list.txt",             // 非投影形态
		"u-deny.TXT",                // 扩展名大小写不匹配（.txt 规范形态）
		"p12-acl.txt.tmp",           // 投影临时文件（由 .tmp 清理支线处理）
		"orphan-deadbeef001200.txt", // 13 位 hex ≠ 旧 12 位形态（hash 过渡分支精确 12 位）
		"acl.txt",                   // 缺策略 id 前缀
		"x12-acl.txt",               // 非 p<数字> 前缀
		"p5-crsxc-ab12.txt",         // crsxc 非 12 位 hex（非序号非哈希形态）
		"u-.txt",                    // u- 后无身份段（首字符须字母数字——无路径逃逸面）
	}
	for _, name := range unmatched {
		if ipListProjectedFileName.MatchString(name) {
			t.Fatalf("非投影命名 %q 不应命中 GC regex（用户手放文件不碰）", name)
		}
	}
}

// 第 59 轮 R59-P3（U5-1）：writeIPListFile 不得使用确定性 .tmp 路径——并发渲染
// 同一 (scope,内容) 时 WriteFile(O_TRUNC)+Rename 交错会把半截文件暴露到正式
// 路径。确定性 RED：预占旧确定性 tmp 路径为目录（WriteFile 恒失败），修复后
// （CreateTemp 唯一临时名）不受占位影响照常成功。
func TestWriteIPListFile_uniqueTempNotBlockedByStalePath(t *testing.T) {
	entries := []string{"198.51.100.9"}
	stalePath := filepath.Join(IPListDataDir, "r59tmp.txt.tmp")
	if err := os.MkdirAll(stalePath, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stalePath) })

	path, err := writeIPListFile("r59tmp", entries)
	if err != nil {
		t.Fatalf("旧确定性 tmp 被占位不应阻塞写入（唯一临时名）: %v", err)
	}
	if base := filepath.Base(path); base != "r59tmp.txt" {
		t.Fatalf("正式路径 %q, want r59tmp.txt（稳定命名）", base)
	}
	content, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(content), "198.51.100.9") {
		t.Fatalf("正式路径内容不完整: %v %q", err, content)
	}
	// 成功路径不得遗留 .tmp 文件（占位目录本身不计）
	matches, _ := filepath.Glob(filepath.Join(IPListDataDir, "r59tmp*.tmp"))
	for _, m := range matches {
		if info, err := os.Stat(m); err == nil && !info.IsDir() {
			t.Fatalf("成功写入不得遗留 tmp: %v", matches)
		}
	}
}

// ---- 第 78 轮 A 域：RG-SEC-IPLIST-GC-OWNERSHIP（U01-F07）----

func TestIPListGC_tempOwnershipBothWays(t *testing.T) {
	now := time.Now()
	seed := func(name string, age time.Duration) string {
		t.Helper()
		p := filepath.Join(IPListDataDir, name)
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		stamp := now.Add(-age)
		if err := os.Chtimes(p, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(p) })
		return p
	}
	staleOwned := seed("p1-acl-12345.tmp", 48*time.Hour)
	staleOwnedUnion := seed("u-bl-42.tmp", 48*time.Hour)
	freshOwned := seed("u-deny-lb_x-777.tmp", time.Minute)
	unrelated := seed("ops-notes.tmp", 48*time.Hour)

	gcStaleIPListFiles(now, 24*time.Hour)

	if _, err := os.Stat(staleOwned); !os.IsNotExist(err) {
		t.Errorf("超龄投影残留 %s 应被回收（err=%v）", staleOwned, err)
	}
	if _, err := os.Stat(staleOwnedUnion); !os.IsNotExist(err) {
		t.Errorf("超龄 u-* 投影残留 %s 应被回收（err=%v）", staleOwnedUnion, err)
	}
	if _, err := os.Stat(freshOwned); err != nil {
		t.Errorf("新鲜临时文件必须保留（在役写保护）：%v", err)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Errorf("无关超龄 .tmp 不得被删除：%v", err)
	}
}
