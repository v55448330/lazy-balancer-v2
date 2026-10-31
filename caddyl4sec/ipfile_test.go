package caddyl4sec

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
)

// mustCompleteWithin 钉死生命周期无阻塞：fn 超过 d 未返回即失败（上游
// remote_ip_list Cleanup 无缓冲 send 挂死的回归钉）。
func mustCompleteWithin(t *testing.T, d time.Duration, name string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not complete within %s (blocked lifecycle)", name, d)
	}
}

func newIPFileMatcherForTest(t *testing.T, file string) *L4IPFileMatcher {
	t.Helper()
	m := &L4IPFileMatcher{File: file}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("provision: %v", err)
	}
	t.Cleanup(func() {
		mustCompleteWithin(t, 2*time.Second, "Cleanup", func() { _ = m.Cleanup() })
	})
	return m
}

func ipFileMatch(t *testing.T, m *L4IPFileMatcher, ip string) (bool, error) {
	t.Helper()
	return m.Match(newTestConn(ip))
}

// TestIPFileModuleID 锁定模块 ID 与 ConnMatcher 接口（渲染侧切换的契约名）。
func TestIPFileModuleID(t *testing.T) {
	m := &L4IPFileMatcher{}
	if id := m.CaddyModule().ID; id != "layer4.matchers.lb_ipfile" {
		t.Fatalf("module ID = %q, want layer4.matchers.lb_ipfile", id)
	}
	var _ layer4.ConnMatcher = m
}

// TestIPFileProvisionValidation 畸形 config 显性报错（空 file 是渲染缺陷，
// 不得静默成「永不在场」的空匹配器）。
func TestIPFileProvisionValidation(t *testing.T) {
	m := &L4IPFileMatcher{}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := m.Provision(ctx); err == nil {
		t.Fatal("Provision() = nil, want error for empty file")
	}
}

// TestIPFileMatchMatrix 行解析与匹配语义与上游 remote_ip_list 对齐：
// CIDR/裸 IP（/32、/128）命中、非法行忽略、空文件恒不命中；对端不可解析
// 时 (true, err)（上游同款，MatcherSet 语境下等效不匹配）。
func TestIPFileMatchMatrix(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "deny.txt")
	lines := "192.168.1.0/24\n10.0.0.7\n# comment\n\nnot-an-ip\n2001:db8::/32\n203.0.113.5\n"
	if err := os.WriteFile(file, []byte(lines), 0o640); err != nil {
		t.Fatal(err)
	}
	m := newIPFileMatcherForTest(t, file)

	cases := []struct {
		ip     string
		want   bool
		wantEr bool
	}{
		{"192.168.1.55", true, false},  // CIDR v4 命中
		{"192.168.2.55", false, false}, // CIDR v4 未命中
		{"10.0.0.7", true, false},      // 裸 IP /32 命中
		{"10.0.0.8", false, false},
		{"2001:db8::1", true, false},  // CIDR v6 命中
		{"2001:db9::1", false, false}, // v6 未命中
		{"203.0.113.5", true, false},  // 尾行（无换行符也收录）
		{"bogus", true, true},         // 上游同款：不可解析对端 (true, err)
		{"", true, true},              // 空对端同上
		{" unix ", true, true},        // unix addr 字符串不可解析
	}
	for _, tc := range cases {
		got, err := ipFileMatch(t, m, tc.ip)
		if (err != nil) != tc.wantEr {
			t.Fatalf("Match(%q) err = %v, wantErr %v", tc.ip, err, tc.wantEr)
		}
		if got != tc.want {
			t.Fatalf("Match(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

// TestIPFileEmptyFile 空文件 = 空集（渲染侧内容门保证 deny 空文件不发射；
// 语义上空文件恒不命中）。
func TestIPFileEmptyFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "deny.txt")
	if err := os.WriteFile(file, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	m := newIPFileMatcherForTest(t, file)
	if got, err := ipFileMatch(t, m, "203.0.113.9"); err != nil || got {
		t.Fatalf("Match = %v/%v, want false/nil", got, err)
	}
}

// TestIPFileMissingFileDegrades 文件缺失 = 空集降级（Provision 不拒绝配置
// ——投影文件未就绪由热载路径自愈，拒绝整份配置比空集更伤）。
func TestIPFileMissingFileDegrades(t *testing.T) {
	m := newIPFileMatcherForTest(t, filepath.Join(t.TempDir(), "absent.txt"))
	if got, err := ipFileMatch(t, m, "203.0.113.9"); err != nil || got {
		t.Fatalf("Match = %v/%v, want false/nil（缺文件降级空集）", got, err)
	}
}

// TestIPFileHotReloadWrite fsnotify Write 路径：追加条目后无需重载配置即命中。
func TestIPFileHotReloadWrite(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "deny.txt")
	if err := os.WriteFile(file, []byte("203.0.113.1\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	m := newIPFileMatcherForTest(t, file)
	if got, _ := ipFileMatch(t, m, "198.51.100.9"); got {
		t.Fatal("setup: unexpected hit before append")
	}
	if err := os.WriteFile(file, []byte("203.0.113.1\n198.51.100.9\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	waitForMatch(t, m, "198.51.100.9", true, 3*time.Second)
}

// TestIPFileHotReloadRename tmp+rename 原子替换（生产写侧形态）：Create 事件
// 路径同样热载。
func TestIPFileHotReloadRename(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "deny.txt")
	if err := os.WriteFile(file, []byte("203.0.113.1\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	m := newIPFileMatcherForTest(t, file)
	tmp := filepath.Join(dir, "deny.txt.tmp")
	if err := os.WriteFile(tmp, []byte("198.51.100.7\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, file); err != nil {
		t.Fatal(err)
	}
	waitForMatch(t, m, "198.51.100.7", true, 3*time.Second)
	// 旧条目随整文件替换消失
	waitForMatch(t, m, "203.0.113.1", false, 3*time.Second)
}

// TestIPFileStatFallback watcher 失效形态（整目录被删重建）：1s mtime/size
// 节流兜底必须自愈（fsnotify 对已删除目录的事件永不抵达）。
func TestIPFileStatFallback(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "deny.txt")
	if err := os.WriteFile(file, []byte("203.0.113.1\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	m := newIPFileMatcherForTest(t, file)

	// 删除整目录再重建（watcher 死亡），换新内容落盘
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("198.51.100.7\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	waitForMatch(t, m, "198.51.100.7", true, 6*time.Second)
}

// TestIPFileStatFallbackAfterReadFailure 初载读取失败（权限）后的自愈回归钉：
// 权限修复（chmod）不改变文件 mtime/size——若失败路径把失败时刻的文件形态记为
// stat 兜底基线，stat 兜底将永远判定「形态未变」而不再重读，名单恒空不自愈。
// 契约：错误路径基线必须记零值（mod 零值、size=-1），强制下一轮 stat 兜底重读。
func TestIPFileStatFallbackAfterReadFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 对 chmod 000 文件仍可读，权限形态用例仅在非 root 下可复现")
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "deny.txt")
	if err := os.WriteFile(file, []byte("203.0.113.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// 读失败形态：移除读权限（mtime/size 不变——chmod 不改 mtime）。
	if err := os.Chmod(file, 0o000); err != nil {
		t.Fatal(err)
	}
	oldInterval := l4IPFilePollInterval
	l4IPFilePollInterval = 50 * time.Millisecond
	t.Cleanup(func() { l4IPFilePollInterval = oldInterval })

	m := newIPFileMatcherForTest(t, file)
	// 前置确认：初载读失败 → 空集不命中。
	if ok, err := ipFileMatch(t, m, "203.0.113.1"); err != nil || ok {
		t.Fatalf("初载读失败后不应命中: ok=%v err=%v", ok, err)
	}
	// 修复权限（内容/mtime/size 全不变）→ stat 兜底必须检测形态差异并重读自愈。
	if err := os.Chmod(file, 0o600); err != nil {
		t.Fatal(err)
	}
	waitForMatch(t, m, "203.0.113.1", true, 6*time.Second)
}

// waitForMatch 轮询至期望状态或超时（热载异步性）。
func waitForMatch(t *testing.T, m *L4IPFileMatcher, ip string, want bool, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		got, _ := ipFileMatch(t, m, ip)
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Match(%q) never became %v within %s", ip, want, d)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestIPFileCleanupNeverBlocksAfterCtxDone P0 回归钉：monitor 提前退出（ctx
// done）后 Cleanup 必须立即返回——上游 `stop <- true` 无缓冲 send 永久阻塞
// 的形态在此必须不可能复现。100 次循环全量通过。
func TestIPFileCleanupNeverBlocksAfterCtxDone(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "deny.txt")
	if err := os.WriteFile(file, []byte("203.0.113.1\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	for i := range 100 {
		m := &L4IPFileMatcher{File: file}
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		if err := m.Provision(ctx); err != nil {
			t.Fatalf("round %d: provision: %v", i, err)
		}
		cancel() // monitor 提前退出路径
		mustCompleteWithin(t, 2*time.Second, fmt.Sprintf("round %d: Cleanup after ctx done", i), func() {
			_ = m.Cleanup()
			_ = m.Cleanup() // 幂等：重复 Cleanup 同样不可阻塞/不可 panic
		})
	}
}

// TestIPFileCleanupStormWhileMatching 匹配与 Cleanup 并发压测：在途 Match 与
// Cleanup 竞争不阻塞、不 panic（快照读与生命周期解耦）。
func TestIPFileCleanupStormWhileMatching(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "deny.txt")
	if err := os.WriteFile(file, []byte("203.0.113.1\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	m := newIPFileMatcherForTest(t, file)
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
				}
				_, _ = ipFileMatch(t, m, "203.0.113.1")
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	mustCompleteWithin(t, 2*time.Second, "Cleanup during matches", func() { _ = m.Cleanup() })
	close(stop)
	wg.Wait()
}

// TestIPFileValidateShape integration：caddy 配置装载 8 个 lb_ipfile 实例
// （多 set OR 形状）+ 重复 Validate 20 次——Provision/Cleanup 生命周期在
// Caddy 配置管线下反复进出无阻塞、无失败。
func TestIPFileValidateShape(t *testing.T) {
	dir := t.TempDir()
	routes := make([]any, 0, 8)
	for i := range 8 {
		file := filepath.Join(dir, fmt.Sprintf("list-%d.txt", i))
		if err := os.WriteFile(file, []byte(fmt.Sprintf("10.1.%d.0/24\n", i)), 0o640); err != nil {
			t.Fatal(err)
		}
		routes = append(routes, map[string]any{
			"match":  []any{map[string]any{"lb_ipfile": map[string]any{"file": file}}},
			"handle": []any{map[string]any{"handler": "close"}},
		})
	}
	raw, err := json.Marshal(map[string]any{
		"admin": map[string]any{"disabled": true},
		"apps": map[string]any{
			"layer4": map[string]any{
				"servers": map[string]any{
					"lb4-ipfile": map[string]any{
						"listen": []string{"127.0.0.1:59995"},
						"routes": routes,
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for round := range 20 {
		var cfg caddy.Config
		if err := json.Unmarshal(raw, &cfg); err != nil {
			t.Fatal(err)
		}
		mustCompleteWithin(t, 10*time.Second, fmt.Sprintf("caddy validate round %d", round), func() {
			if err := caddy.Validate(&cfg); err != nil {
				t.Errorf("Validate round %d = %v", round, err)
			}
		})
	}
}

// TestIPFileNegativeControl 未知 matcher 名必须被 Caddy 拒绝（证明上面的
// validate 形状真消费了模块注册表）。
func TestIPFileNegativeControl(t *testing.T) {
	dir := t.TempDir()
	raw, err := json.Marshal(map[string]any{
		"admin": map[string]any{"disabled": true},
		"apps": map[string]any{
			"layer4": map[string]any{
				"servers": map[string]any{
					"s": map[string]any{
						"listen": []string{"127.0.0.1:59994"},
						"routes": []any{
							map[string]any{
								"match":  []any{map[string]any{"lb_ipfile_nope": map[string]any{"file": filepath.Join(dir, "x.txt")}}},
								"handle": []any{map[string]any{"handler": "close"}},
							},
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var cfg caddy.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if err := caddy.Validate(&cfg); err == nil {
		t.Fatal("Validate() = nil, want error for unknown matcher (negative control)")
	}
}

// 编译期引用防呆（net 仅用于注释性契约：Match 复用 clientIPFromConn 的
// SplitHostPort 语义，测试用 addrOnlyConn）。
var _ = net.ParseIP
