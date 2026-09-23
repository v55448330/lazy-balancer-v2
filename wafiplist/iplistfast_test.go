package wafiplist

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// 测试用白名单前缀（生产=/app/waf/，测试指向临时目录）。
func useAllowedDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := AllowedPathPrefix
	AllowedPathPrefix = dir + string(filepath.Separator)
	t.Cleanup(func() { AllowedPathPrefix = old })
	return dir
}

func writeListFile(t *testing.T, dir, name string, lines []string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func newOp(t *testing.T, path string) plugintypes.Operator {
	t.Helper()
	op, err := newIPListFast(plugintypes.OperatorOptions{Arguments: path})
	if err != nil {
		t.Fatalf("newIPListFast: %v", err)
	}
	return op
}

func TestIPListFast_hitMissCIDRv4v6(t *testing.T) {
	dir := useAllowedDir(t)
	path := writeListFile(t, dir, "basic.txt", []string{
		"# 注释行", "", "; 分号注释",
		"203.0.113.7", "10.8.0.0/16", "2001:db8::/48",
	})
	op := newOp(t, path)

	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"203.0.113.7", true},  // 裸 IP
		{"10.8.3.4", true},     // CIDR 内
		{"10.9.0.1", false},    // CIDR 外
		{"2001:db8::1", true},  // v6 CIDR 内
		{"2001:db9::1", false}, // v6 CIDR 外
		{"203.0.113.8", false}, // 裸 IP 相邻未命中
		{"not-an-ip", false},   // 不可解析输入
	} {
		if got := op.Evaluate(nil, tc.value); got != tc.want {
			t.Fatalf("Evaluate(%q)=%v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestIPListFast_strictParseError(t *testing.T) {
	dir := useAllowedDir(t)
	path := writeListFile(t, dir, "bad.txt", []string{"10.0.0.0/8", "garbage-line"})
	if _, err := newIPListFast(plugintypes.OperatorOptions{Arguments: path}); err == nil {
		t.Fatal("不可解析行必须报错（严格解析，不静默跳过）")
	}
}

func TestIPListFast_rejectsNonWhitelistedPath(t *testing.T) {
	_ = useAllowedDir(t)
	for _, path := range []string{
		"/etc/passwd", "relative/path.txt", "/tmp/evil.txt",
	} {
		if _, err := newIPListFast(plugintypes.OperatorOptions{Arguments: path}); err == nil {
			t.Fatalf("路径 %q 必须被白名单拒绝", path)
		}
	}
}

func TestIPListFast_missingFileFailsClosed(t *testing.T) {
	dir := useAllowedDir(t)
	if _, err := newIPListFast(plugintypes.OperatorOptions{Arguments: filepath.Join(dir, "missing.txt")}); err == nil {
		t.Fatal("缺失文件必须报错（构建期 fail-closed → Caddy 校验拒绝）")
	}
}

func TestIPListFast_reloadsOnMtimeChange(t *testing.T) {
	old := StatCheckInterval
	StatCheckInterval = 0 // 逐次复查（否则默认 1s 节流窗口内按缓存判定）
	t.Cleanup(func() { StatCheckInterval = old })
	dir := useAllowedDir(t)
	path := writeListFile(t, dir, "reload.txt", []string{"203.0.113.1"})
	op := newOp(t, path)
	if !op.Evaluate(nil, "203.0.113.1") || op.Evaluate(nil, "203.0.113.2") {
		t.Fatal("初始名单判定错误")
	}
	// 重写内容并推进 mtime（同秒粒度兜底：显式 Chtimes 到未来）
	if err := os.WriteFile(path, []byte("203.0.113.2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	if op.Evaluate(nil, "203.0.113.1") || !op.Evaluate(nil, "203.0.113.2") {
		t.Fatal("mtime 变更后必须重建检索结构")
	}
}

// 等价探针：同一 200 条名单分别用 @ipMatch 与 @ipListFast 构建两个真实
// coraza WAF，随机 50 个 IP 各跑事务，判定（是否中断）逐点一致。
func TestIPMatchVsIPListFast_equivalenceProbe(t *testing.T) {
	dir := useAllowedDir(t)
	rng := rand.New(rand.NewPCG(7, 0))
	entries := make([]string, 0, 200)
	for range 200 {
		switch rng.IntN(4) {
		case 0:
			entries = append(entries, fmt.Sprintf("10.%d.%d.0/24", rng.IntN(10), rng.IntN(10)))
		case 1:
			entries = append(entries, fmt.Sprintf("203.0.%d.%d", rng.IntN(5), rng.IntN(256)))
		case 2:
			entries = append(entries, fmt.Sprintf("2001:db8:%x::/64", rng.IntN(4)))
		case 3:
			entries = append(entries, fmt.Sprintf("198.51.%d.0/25", rng.IntN(4)))
		}
	}
	path := writeListFile(t, dir, "probe.txt", entries)

	buildWAF := func(t *testing.T, directives string) coraza.WAF {
		t.Helper()
		waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
		if err != nil {
			t.Fatalf("NewWAF: %v", err)
		}
		return waf
	}
	matchWAF := buildWAF(t, fmt.Sprintf("SecRuleEngine On\nSecRule REMOTE_ADDR \"@ipMatch %s\" \"id:1,phase:1,deny\"\n", strings.Join(entries, ",")))
	fastWAF := buildWAF(t, fmt.Sprintf("SecRuleEngine On\nSecRule REMOTE_ADDR \"@ipListFast %s\" \"id:2,phase:1,deny\"\n", path))

	blocked := func(waf coraza.WAF, ip string) bool {
		tx := waf.NewTransaction()
		defer func() { _ = tx.Close() }()
		tx.ProcessConnection(ip, 12345, "127.0.0.1", 443)
		tx.ProcessURI("/", "GET", "HTTP/1.1")
		it := tx.ProcessRequestHeaders()
		return it != nil
	}
	for range 50 {
		var ip string
		if rng.IntN(2) == 0 {
			ip = fmt.Sprintf("%d.%d.%d.%d", []int{10, 203, 198}[rng.IntN(3)], rng.IntN(256), rng.IntN(256), rng.IntN(256))
		} else {
			ip = fmt.Sprintf("2001:db8:%x::%x", rng.IntN(8), rng.IntN(65536))
		}
		if blocked(matchWAF, ip) != blocked(fastWAF, ip) {
			t.Fatalf("探针 %s: @ipMatch=%v @ipListFast=%v — 判定不一致", ip, blocked(matchWAF, ip), blocked(fastWAF, ip))
		}
	}
}
