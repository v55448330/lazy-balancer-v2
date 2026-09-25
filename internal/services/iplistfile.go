package services

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/wafiplist"
)

// IPListDataDir 是策略名单投影目录（@ipListFast 算子读取侧）。生产容器默认
// /app/waf/ip-lists（DataDir=/app/data 同级）；本地开发经 ConfigureWafDirs
// 按 data_dir 同级 waf/ 派生。测试可改。
var IPListDataDir = "/app/waf/ip-lists"

// ConfigureWafDirs 按最终 data_dir 派生 WAF 文件目录（容器内 /app/data →
// /app/waf 与既有打包路径逐字节一致；本地开发落到数据目录同级，避免
// /app 只读文件系统写入失败）。算子白名单前缀同步对齐。
func ConfigureWafDirs(dataDir string) {
	if filepath.Dir(dataDir) == "/app" {
		return // 容器默认形态：保持 /app/waf/* 常量
	}
	wafDir := filepath.Join(filepath.Dir(dataDir), "waf")
	IPListDataDir = filepath.Join(wafDir, "ip-lists")
	wafiplist.AllowedPathPrefix = wafDir + string(filepath.Separator)
}

// EnsureIPListDir 启动期建目录（0755）。
func EnsureIPListDir() error {
	if err := os.MkdirAll(IPListDataDir, 0o755); err != nil {
		return fmt.Errorf("创建 IP 名单目录 %s 失败: %w", IPListDataDir, err)
	}
	return nil
}

// writeIPListFile 把聚合后的名单原子写入内容寻址文件（scope-sha256[:12].txt），
// 返回绝对路径；空集合返回空串不写文件（调用方据此不发射规则）。文件已存在
// 直接返回路径（幂等）；写失败返回 error——经渲染错误链路上报（保存侧事务
// 回滚，fail-closed）。成功投影的路径计入本轮渲染引用集（GC 差集口径）。
// GC 不在此触发（第 53 轮补充轮 P2-1）：渲染中途按上一轮陈旧引用集差集会误删
// 在役文件——统一由整轮渲染 apply 成功后触发（maybeGCStaleIPListFiles，引用集
// 落齐再差集；全部阈值为 time.Since 时长比较，无挂钟排程、与时区配置无关）。
func writeIPListFile(scope string, merged []string) (string, error) {
	merged = wafiplist.AggregateIPEntries(merged)
	if len(merged) == 0 {
		return "", nil
	}
	sum := sha256.Sum256([]byte(strings.Join(merged, "\n")))
	name := fmt.Sprintf("%s-%s.txt", scope, hex.EncodeToString(sum[:])[:12])
	path := filepath.Join(IPListDataDir, name)
	noteIPListRenderRef(path)
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	if err := EnsureIPListDir(); err != nil {
		return "", err
	}
	tmp := path + ".tmp"
	var sb strings.Builder
	for _, entry := range merged {
		sb.WriteString(entry)
		sb.WriteString("\n")
	}
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o644); err != nil {
		return "", fmt.Errorf("写入 IP 名单文件失败 %s: %w", name, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("原子替换 IP 名单文件失败 %s: %w", name, err)
	}
	return path, nil
}

// ---------- F49-3：@ipListFast 投影文件 + 运行期缓存 GC ----------

// ipListFileMaxAge 是 GC 删除未引用文件的超龄门槛（24h）：避开 Caddy 重载
// 窗口——新配置刚投影/换名的文件即使暂未进入引用集也不删。
const ipListFileMaxAge = 24 * time.Hour

// ipListGCInterval 是自动 GC 的最小间隔（每次成功投影后检查一次）。
const ipListGCInterval = time.Hour

// ipListProjectedFileName 匹配投影文件命名（scope-sha256[:12].txt）——差集
// 清理只碰该形态，目录内其他文件（运维投放/误放）一律不动。
var ipListProjectedFileName = regexp.MustCompile(`^.+-[0-9a-f]{12}\.txt$`)

// ipListRenderRefs 记录本进程渲染引用过的投影文件及最近引用时间：一次全量
// 配置渲染会重新投影全部在役名单（内容寻址，stat 命中也计引用），故「长期
// 未被引用 + 超龄」即孤儿（策略解绑/删除、威胁库内容换哈希后的旧文件）。
var ipListRenderRefs = struct {
	sync.Mutex
	lastRef map[string]time.Time
}{lastRef: make(map[string]time.Time)}

// ipListLastGC 上次自动 GC 时间；初始化为进程启动时刻——启动渲染尚未完成
// 引用集采集前不得触发首轮 GC。
var ipListLastGC = time.Now()

func noteIPListRenderRef(path string) {
	ipListRenderRefs.Lock()
	ipListRenderRefs.lastRef[path] = time.Now()
	ipListRenderRefs.Unlock()
}

// forgetIPListRenderRefForTest 从引用集中剔除路径（测试模拟「本轮渲染不再
// 引用」）。
func forgetIPListRenderRefForTest(path string) {
	ipListRenderRefs.Lock()
	delete(ipListRenderRefs.lastRef, path)
	ipListRenderRefs.Unlock()
}

// maybeGCStaleIPListFiles 整轮渲染 apply 成功后的节流 GC 入口（间隔
// ipListGCInterval）——此刻本轮渲染的全部在役名单引用已落齐，差集决策安全。
func maybeGCStaleIPListFiles() {
	if time.Since(ipListLastGC) < ipListGCInterval {
		return
	}
	ipListLastGC = time.Now()
	gcStaleIPListFiles(ipListLastGC, ipListFileMaxAge)
}

// gcStaleIPListFiles 差集清理：删除 IPListDataDir 下「本进程近 maxAge 内未
// 被渲染引用 且 mtime 早于 maxAge」的投影文件，并淘汰对应 wafiplist 运行期
// 缓存（fail-stale 不得把已删文件的集合无限期留在内存）。删除失败仅 warn
// ——孤儿文件不阻断渲染链路。返回删除数。
func gcStaleIPListFiles(now time.Time, maxAge time.Duration) (removed int) {
	entries, err := os.ReadDir(IPListDataDir)
	if err != nil {
		Logf("warn", "IP 名单 GC: 读取目录 %s 失败: %v", IPListDataDir, err)
		return 0
	}
	ipListRenderRefs.Lock()
	refs := make(map[string]time.Time, len(ipListRenderRefs.lastRef))
	for p, ts := range ipListRenderRefs.lastRef {
		refs[p] = ts
	}
	ipListRenderRefs.Unlock()
	var deleted []string
	for _, entry := range entries {
		if entry.IsDir() || !ipListProjectedFileName.MatchString(entry.Name()) {
			continue
		}
		full := filepath.Join(IPListDataDir, entry.Name())
		if ts, ok := refs[full]; ok && now.Sub(ts) < maxAge {
			continue // 近期渲染仍在引用
		}
		info, err := entry.Info()
		if err != nil || now.Sub(info.ModTime()) < maxAge {
			continue // 重载窗口保护：新文件不删
		}
		if err := os.Remove(full); err != nil {
			Logf("warn", "IP 名单 GC: 删除超龄未引用名单文件 %s 失败: %v", full, err)
			continue
		}
		deleted = append(deleted, full)
	}
	if len(deleted) > 0 {
		wafiplist.EvictIPListCache(deleted...)
		Logf("info", "IP 名单 GC: 清理 %d 个超龄未引用名单文件", len(deleted))
	}
	// P5-19（第 50 轮审计）：顺带 prune 引用集中早于 maxAge 的条目——文件已删
	// 或长期未再渲染的 lastRef 记录只增不删会无限驻留；再次渲染时
	// noteIPListRenderRef 会重建条目，prune 无正确性代价。
	ipListRenderRefs.Lock()
	for p, ts := range ipListRenderRefs.lastRef {
		if now.Sub(ts) >= maxAge {
			delete(ipListRenderRefs.lastRef, p)
		}
	}
	ipListRenderRefs.Unlock()
	return len(deleted)
}

// ipListRuleOperand 把策略名单投影为 @ipListFast 文件并返回 SecRule 算子
// 表达式（negated=true 时前缀 !）；空名单返回空串（调用方跳过发射，
// 维持现状零发射语义）。写失败返回 error 沿渲染链路上报。
func ipListRuleOperand(scope string, entries []string, negated bool) (string, error) {
	path, err := writeIPListFile(scope, entries)
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", nil
	}
	operand := "@ipListFast " + path
	if negated {
		operand = "!" + operand
	}
	return operand, nil
}
