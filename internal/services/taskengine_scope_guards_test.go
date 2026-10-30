package services

// taskengine_scope_guards_test.go —— 任务引擎标准 v2.2 §0.6 机器守卫钉测：
//
// ①注册表断言：常驻（Daemon）任务的 Run 体必须经 taskengine.RunTicker 驱动，
//   或命中下方机器可查登记表（§0.2 形态②自管理阻塞循环）。登记表为常量清单，
//   与标准文档 §2/§6.4 逐字同步——新增常驻任务未登记即红。
// ②静态扫描：internal/{services,handlers,db,middleware} 的生产 .go 文件中
//   time.NewTicker / time.AfterFunc 命中必须带 //scope-exempt: <类别> 标注，
//   类别必须属于词表（与文档 §6.4 标注词表同步）；零命中同样判红（扫描路径
//   失效不得空转放行）。
// ③空载体契约：钩子未接线的 runtime daemon 以空载体阻塞至 ctx 停止——零
//   task_runs 噪音、不烧异常退出自愈预算（不得「立即净返回」触发
//   premature-exit 重拉/停调）。

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/taskengine"
)

// guardRepoRoot 守卫的仓库根（本文件位于 internal/services，测试 cwd=包目录）。
const guardRepoRoot = "../.."

// scopeExemptCategories scope-exempt 类别词表（机器可查常量清单；与标准文档
// §6.4 标注词表逐字同步——文档缺词或标注用词表外类别均判红）。
var scopeExemptCategories = []string{
	"daemon-run-body-loop",       // §0.2 形态②：daemon Run 体自管理阻塞循环（ctx 取消即退）
	"engine-reconciler",          // §6.4 引擎附属对账循环（代际停机 + 有界排空）
	"one-shot-deadline-callback", // §0.5 一次性延迟回调（canceled/deadline 收口，不跨调用自续）
	"one-shot-bounded-poll",      // §0.5 单次调用内有界轮询（deadline 收口）
}

// daemonRunTickerContracts Run 体必须经 taskengine.RunTicker 驱动的常驻任务
// （id → Run/委托体所在源文件，仓库相对路径）。验证口径：注册描述符窗口
// （ID 行→描述符闭合）内出现 taskengine.RunTicker(，或窗口内唯一的 run* 委托
// 工作体函数体含该调用。
var daemonRunTickerContracts = map[string]string{
	"metrics-collector":      "internal/services/taskengine_wire_runtime.go",
	"threat-rollup-warmer":   "internal/services/taskengine_wire_runtime.go",
	"caddy-restart-watcher":  "internal/services/taskengine_wire_runtime.go",
	"ratelimit-bucket-sweep": "internal/services/taskengine_wire_runtime.go",
	"runtime-log-threshold":  "internal/services/taskengine_wire_runtime.go",
	"runtime-tz-refresh":     "internal/services/taskengine_wire_runtime.go",
	"apikey-usage-flusher":   "internal/services/taskengine_wire_runtime.go", // 经 runAPIKeyUsageFlusher
	"cert-issuance":          "internal/services/taskengine_wire.go",
}

// daemonBlockingLoopRegistry §0.2 形态②（daemon Run 体自管理阻塞循环）登记表
// （id → 源文件:循环函数）。判据机器可识别：循环函数在登记的源文件中可定位，
// 且其 ticker 行带 //scope-exempt: daemon-run-body-loop 标注；存活期=Run ctx，
// 引擎 Stop/SetRole 取消 ctx 即退（代际停机）。
var daemonBlockingLoopRegistry = map[string]string{
	"security-events-ingestion": "internal/services/securityevents.go:runIngestionLoop",
	"cluster-sync":              "internal/services/cluster_masterserving.go:masterSyncServingLoop",
}

var (
	guardDescriptorAnchorRe = regexp.MustCompile(`ID:\s+\"(.+?)\"`)
	guardRunHelperRefRe     = regexp.MustCompile(`\b(run[A-Z]\w*)\(`)
	guardScopeExemptCatRe   = regexp.MustCompile(`//scope-exempt:\s*([a-z0-9-]+)`)
)

// guardReadRepoFile 守卫读取仓库内文本文件（失败即 Fatal——守卫不得在缺文件
// 时静默放行）。
func guardReadRepoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(guardRepoRoot, rel))
	if err != nil {
		t.Fatalf("守卫读取 %s 失败: %v", rel, err)
	}
	return string(b)
}

// guardSourceFuncBody 返回顶层函数的源码文本窗口（func <name>( 起、下一个
// 顶层 func 止）；找不到函数名返回 ok=false。
func guardSourceFuncBody(src, funcName string) (string, bool) {
	needle := "func " + funcName + "("
	i := strings.Index(src, needle)
	if i < 0 {
		return "", false
	}
	rest := src[i:]
	if j := strings.Index(rest[1:], "\nfunc "); j >= 0 {
		rest = rest[:j+1]
	}
	return rest, true
}

// TestGuard_DaemonRunsUseRunTickerOrRegisteredLoop 标准§0.6-1 注册表断言：
// DescribeAll 常驻全集与执行契约登记表（RunTicker 契约 + 形态②登记）互为
// 精确覆盖，且每条契约可在源码中机器验证。
func TestGuard_DaemonRunsUseRunTickerOrRegisteredLoop(t *testing.T) {
	te := newWireTestEngine(t)
	registered := map[string]bool{}
	for _, meta := range te.DescribeAll() {
		if meta.Kind == taskengine.KindDaemon {
			registered[meta.ID] = true
		}
	}

	covered := map[string]bool{}
	for id := range daemonRunTickerContracts {
		covered[id] = true
	}
	for id := range daemonBlockingLoopRegistry {
		if covered[id] {
			t.Errorf("常驻任务 %s 同时登记在 RunTicker 契约与形态②登记表", id)
		}
		covered[id] = true
	}
	for id := range registered {
		if !covered[id] {
			t.Errorf("常驻任务 %s 未登记执行契约（RunTicker 或 §6.4 形态②登记表）——标准 §0.6-1", id)
		}
	}
	for id := range covered {
		if !registered[id] {
			t.Errorf("登记表中的 %s 不在 DescribeAll——任务退役/改名须同步登记表与文档", id)
		}
	}

	// RunTicker 契约：描述符窗口（ID 行→首个描述符闭合「\n\t})」）内必须
	// 出现 taskengine.RunTicker(，或经唯一 run* 委托工作体间接持有。
	for id, file := range daemonRunTickerContracts {
		src := guardReadRepoFile(t, file)
		var at []int
		for _, m := range guardDescriptorAnchorRe.FindAllStringSubmatchIndex(src, -1) {
			if src[m[2]:m[3]] == id {
				at = m
				break
			}
		}
		if at == nil {
			t.Errorf("常驻任务 %s：源文件 %s 未找到注册锚点", id, file)
			continue
		}
		window := src[at[0]:]
		if j := strings.Index(window, "\n\t})"); j >= 0 {
			window = window[:j]
		}
		if strings.Contains(window, "taskengine.RunTicker(") {
			continue
		}
		m := guardRunHelperRefRe.FindStringSubmatch(window)
		if m == nil {
			t.Errorf("常驻任务 %s 的 Run 体既无 taskengine.RunTicker( 也无可验证的委托工作体（%s）", id, file)
			continue
		}
		body, ok := guardSourceFuncBody(src, m[1])
		if !ok || !strings.Contains(body, "taskengine.RunTicker(") {
			t.Errorf("常驻任务 %s 的委托工作体 %s 未调用 taskengine.RunTicker（%s）", id, m[1], file)
		}
	}

	// 形态②登记表：循环函数可定位，且 ticker 行带 daemon-run-body-loop 标注。
	for id, spec := range daemonBlockingLoopRegistry {
		parts := strings.SplitN(spec, ":", 2)
		src := guardReadRepoFile(t, parts[0])
		body, ok := guardSourceFuncBody(src, parts[1])
		if !ok {
			t.Errorf("形态②登记 %s：源文件 %s 未找到循环函数 %s", id, parts[0], parts[1])
			continue
		}
		if !strings.Contains(body, "//scope-exempt: daemon-run-body-loop") {
			t.Errorf("形态②登记 %s：循环函数 %s 的 ticker 缺 //scope-exempt: daemon-run-body-loop 标注", id, parts[1])
		}
	}

	// 文档同步：登记锚点与标注词表必须出现在标准文档（§2/§6.4）。
	doc := guardReadRepoFile(t, filepath.Join("docs", "task-engine-standard.md"))
	for _, anchor := range []string{"runIngestionLoop", "masterSyncServingLoop", "startRoleReconciler"} {
		if !strings.Contains(doc, anchor) {
			t.Errorf("标准文档缺登记锚点 %s——登记表与文档失同步", anchor)
		}
	}
	for _, cat := range scopeExemptCategories {
		if !strings.Contains(doc, cat) {
			t.Errorf("标准文档 §6.4 标注词表缺类别 %s", cat)
		}
	}
}

// TestGuard_NoUnannotatedTickerOrAfterFunc 标准§0.6-2 静态扫描：四个生产包的
// 生产 .go 文件中 time.NewTicker / time.AfterFunc 命中必须带
// //scope-exempt: <类别> 标注，且类别 ∈ 词表。零命中判红（扫描口径失效不得
// 假绿）。
func TestGuard_NoUnannotatedTickerOrAfterFunc(t *testing.T) {
	packages := []string{"internal/services", "internal/handlers", "internal/db", "internal/middleware"}
	var violations []string
	hits := 0
	for _, pkg := range packages {
		root := filepath.Join(guardRepoRoot, filepath.FromSlash(pkg))
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			name := d.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			lines := strings.Split(string(b), "\n")
			for i, line := range lines {
				if !strings.Contains(line, "time.NewTicker(") && !strings.Contains(line, "time.AfterFunc(") {
					continue
				}
				hits++
				if cat := guardScopeExemptCatRe.FindStringSubmatch(line); cat != nil {
					guardCheckCategory(t, cat[1], path, i+1)
					continue
				}
				if i > 0 {
					if cat := guardScopeExemptCatRe.FindStringSubmatch(lines[i-1]); cat != nil {
						guardCheckCategory(t, cat[1], path, i+1)
						continue
					}
				}
				rel, _ := filepath.Rel(guardRepoRoot, path)
				violations = append(violations, fmt.Sprintf("%s:%d 缺 //scope-exempt: <类别> 标注", rel, i+1))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("守卫扫描 %s 失败: %v", pkg, err)
		}
	}
	if hits == 0 {
		t.Fatal("scope 守卫零命中——扫描路径/口径失效，须修正守卫而非空转放行")
	}
	if len(violations) > 0 {
		t.Errorf("存在未标注的 ticker/AfterFunc（标准 §0.6-2）:\n%s", strings.Join(violations, "\n"))
	}
}

// guardCheckCategory 标注类别必须属于词表（词表外类别=变相豁免，判红）。
func guardCheckCategory(t *testing.T, cat, path string, line int) {
	t.Helper()
	for _, allowed := range scopeExemptCategories {
		if cat == allowed {
			return
		}
	}
	rel, _ := filepath.Rel(guardRepoRoot, path)
	t.Errorf("%s:%d scope-exempt 类别 %q 不在词表（允许：%v）", rel, line, cat, scopeExemptCategories)
}

// TestGuard_DescribeAllMatchesStandardSection2 注册全集与标准文档 §2 计数对照
// （全集逐项对账由 expectedTaskKinds 钉测承载，此处只钉「文档口径=注册表」）。
func TestGuard_DescribeAllMatchesStandardSection2(t *testing.T) {
	te := newWireTestEngine(t)
	const wantTotal = 27 // 定时 5 / 常驻 10 / 循环 11 / 触发 1
	if got := len(te.DescribeAll()); got != wantTotal {
		t.Fatalf("DescribeAll 总数=%d, want %d（与标准文档 §2 计数同步）", got, wantTotal)
	}
	doc := guardReadRepoFile(t, filepath.Join("docs", "task-engine-standard.md"))
	for _, heading := range []string{"任务清单（27 注册任务", "定时（5）", "常驻（10）", "循环（11）", "触发（1）"} {
		if !strings.Contains(doc, heading) {
			t.Errorf("标准文档 §2 缺 %q——注册表与文档计数失同步", heading)
		}
	}
}

// TestRuntimeLifecycleUnwiredHookCarrier_blocksQuietlyUntilStop 空载体契约：
// 钩子未接线时 daemon Run 阻塞至 ctx 停止——保持 Running、零额外执行行、
// 不耗自愈预算、不改变调度态。
func TestRuntimeLifecycleUnwiredHookCarrier_blocksQuietlyUntilStop(t *testing.T) {
	te := newRuntimeLifecycleTestEngine(t) // 钩子全 nil：空载体形态
	const id = "threat-rollup-warmer"
	waitForCond(t, 2*time.Second, func() bool {
		meta, ok := te.Lookup(id)
		return ok && meta.Running
	})
	runs := taskRunCountForTest(t, id)
	if runs < 1 {
		t.Fatalf("前置：%s 应已有启动行", id)
	}
	// 观察窗覆盖旧实现首轮 premature-exit 重拉（1s 退避）——空载体窗口内
	// 不得新增任何执行行（无 failed/重启噪音）。
	time.Sleep(1300 * time.Millisecond)
	if got := taskRunCountForTest(t, id); got != runs {
		t.Fatalf("未接线空载体执行行 %d != %d——premature-exit 噪音回归", got, runs)
	}
	meta, _ := te.Lookup(id)
	if !meta.Running {
		t.Fatal("未接线空载体必须保持 Running（阻塞至 ctx 取消，不得净返回）")
	}
	if !meta.LoopOn || meta.RestartExhausted {
		t.Fatalf("空载体不得改变调度态：loop_on=%v restart_exhausted=%v", meta.LoopOn, meta.RestartExhausted)
	}
	te.StopLoop(id)
	waitForCond(t, 2*time.Second, func() bool {
		m, _ := te.Lookup(id)
		return !m.Running
	})
	if got := taskRunCountForTest(t, id); got != runs {
		t.Fatalf("停止后执行行 %d != %d——空载体停止不得产生额外行", got, runs)
	}
}
