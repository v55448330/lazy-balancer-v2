package services

import (
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
	wafDir = filepath.Join(filepath.Dir(dataDir), "waf")
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

// writeIPListFile 把聚合后的名单原子写入稳定命名文件（<scope>.txt——scope
// 字符串本身即投影实例身份：策略 id/并集描述符；名单改名/内容变化都不改变
// 文件名，2026-10-15 热路径改造取代旧内容寻址 scope-sha256[:12].txt），返回
// 绝对路径。空集合投影 0 字节空文件照常返回路径（2026-10-15 始终发射裁定：
// 调用方恒发射 @ipListFast，空集=匹配器永不命中与无规则语义等价——空↔非空
// 降为纯内容变化全走热路径；加载侧 wafiplist 空文件合法）。同路径同字节
// 跳写（全量渲染重投影不动，mtime 保持 → wafiplist stat 缓存命中零重建）；
// 内容变化同路径原子换内容（配置字节不变，@ipListFast 匹配器 ≤1s stat 热感
// 知——名单写路径零 /load 收敛的机制基础）。写失败返回 error——经渲染错误
// 链路上报（保存侧事务回滚，fail-closed）。成功投影的路径计入本轮渲染引用
// 集（GC 差集口径）。GC 不在此触发（第 53 轮补充轮 P2-1）：渲染中途按上一
// 轮陈旧引用集差集会误删在役文件——统一由整轮渲染 apply 成功后触发
// （maybeGCStaleIPListFiles，引用集落齐再差集；全部阈值为 time.Since 时长
// 比较，无挂钟排程、与时区配置无关）。
func writeIPListFile(scope string, merged []string) (string, error) {
	merged = wafiplist.AggregateIPEntries(merged)
	// 内容先于 stat 构建：稳定命名下「同路径」不再蕴含「同内容」——字节比对
	// 才是跳写判据（内容寻址时代的 stat 命中=同内容前提已随热路径改造失效）。
	// 空集合 content 为空串，空文件落盘/跳写与普通内容同路径。
	var sb strings.Builder
	for _, entry := range merged {
		sb.WriteString(entry)
		sb.WriteString("\n")
	}
	content := sb.String()
	name := scope + ".txt"
	path := filepath.Join(IPListDataDir, name)
	noteIPListRenderRef(path)
	if existing, err := os.ReadFile(path); err == nil && string(existing) == content {
		return path, nil // 同字节跳写
	}
	if err := EnsureIPListDir(); err != nil {
		return "", err
	}
	// 唯一临时名（第 59 轮 R59-P3）：并发渲染同一 scope 命中同一正式路径时，
	// CreateTemp 使每次写入独占临时文件，rename 串行原子生效。失败路径清理
	// 临时文件。
	tmp, err := os.CreateTemp(IPListDataDir, scope+"-*.tmp")
	if err != nil {
		return "", fmt.Errorf("创建 IP 名单临时文件失败 %s: %w", name, err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("写入 IP 名单文件失败 %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("关闭 IP 名单临时文件失败 %s: %w", name, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
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

// ipListProjectedFileName 匹配投影文件命名——差集清理只碰该形态，目录内其他
// 文件（运维投放/误放）一律不动。分支（2026-10-15 热路径改造；第 77 轮
// HP77-2/HP77-4 收口）：
//   - 新稳定命名 <scope>.txt：p[0-9]+-(acl|trust|bl|crsxc-…)（策略身份；
//     crsxc-<12位hex>=CRS 作用域排除匹配集投影（第 77 轮 HP77-4 组合键哈希），
//     crsxc-<纯数字>=第 76 轮首发序号形态（已被哈希取代，存量由 24h GC 过渡
//     回收））、tp（受信代理全局单份）、u-<kind>-<ruleCaddyID>（第 76 轮
//     HP-1：预检/引擎层 u-* 投影 scope 编入规则身份，如 u-deny-lb_2r8dosptk1
//     ——字符类收 `_`，并收大写与 `.`（第 77 轮 HP77-2：v2 导入可携带大写/
//     含点 rule id，旧字符类使这类孤儿永不回收；白名单仍不含路径分隔符，
//     纯单段文件名，无路径逃逸面）；升级前旧全局名 u-deny.txt 等同字符类
//     天然覆盖，由 24h GC 过渡回收）；精确白名单，用户手放文件不碰；
//   - 旧内容寻址 scope-sha256[:12].txt——迁移过渡分支：改造前落盘的旧哈希
//     文件由既有 24h GC 自然回收（不写迁移），旧文件清尽后该分支恒不命中，
//     自行失效。
var ipListProjectedFileName = regexp.MustCompile(`^(u-[A-Za-z0-9][A-Za-z0-9._-]*|p[0-9]+-(acl|trust|bl|crsxc-([0-9]+|[0-9a-f]{12}))|tp|.+-[0-9a-f]{12})\.txt$`)

// ipListTempFileName 匹配 writeIPListFile 的临时文件名形态
// （CreateTemp(IPListDataDir, scope+"-*.tmp")：<投影 scope>-<随机数字>.tmp）。
// U01-F07（第 78 轮）：GC 只委托删除本模块拥有的临时文件——目录内的无关
// .tmp（运维投放的 ops-notes.tmp 等）一律不动；24h 超龄门槛仍保护在役写入
// （在役 tmp 恒新鲜）。scope 白名单与 ipListProjectedFileName 同源。
var ipListTempFileName = regexp.MustCompile(`^(u-[A-Za-z0-9][A-Za-z0-9._-]*-[0-9]+|p[0-9]+-(acl|trust|bl|crsxc-([0-9]+|[0-9a-f]{12}))-[0-9]+|tp-[0-9]+|.+-[0-9a-f]{12}-[0-9]+)\.tmp$`)

// ipListRenderRefs 记录本进程渲染引用过的投影文件及最近引用时间：一次全量
// 配置渲染会重新投影全部在役名单（同字节跳写也计引用），故「长期
// 未被引用 + 超龄」即孤儿（策略解绑/删除、发射面变化后的旧文件）。
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
//
// OBS-1（第 77 轮，前提披露）：差集决策的前提是「渲染引用集=本进程在役投影
// 全集，且**无旧版本进程并发写者**」——滚动升级窗口内若新旧双实例并跑同一
// 数据卷，旧实例持有旧引用集，可能继续引用/重写本进程已判孤儿的文件，24h
// 超龄门槛是对该窗口的缓冲突界（正确部署形态=串行替换，不双跑）。
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
	// 第 59 轮 R59-P5：顺带清理超龄崩溃残留的投影临时文件（CreateTemp 半截
	// .tmp 无引用语义，超龄即可删；在役写入的 .tmp 恒新鲜，不受影响）。
	for _, entry := range entries {
		// U01-F07：名字形态门——只回收本模块 CreateTemp 产出的临时文件，
		// 无关 .tmp 不碰（旧实现仅按后缀匹配，会删除目录内任意超龄 .tmp）。
		if entry.IsDir() || !ipListTempFileName.MatchString(entry.Name()) {
			continue
		}
		tmpFull := filepath.Join(IPListDataDir, entry.Name())
		info, err := entry.Info()
		if err != nil || now.Sub(info.ModTime()) < maxAge {
			continue
		}
		if err := os.Remove(tmpFull); err == nil {
			deleted = append(deleted, tmpFull)
		}
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
// 表达式（negated=true 时前缀 !）。空名单投影空文件后恒返回算子（2026-10-15
// 始终发射裁定：空集=匹配器永不命中与无规则语义等价，空↔非空纯内容变化走
// 热路径；调用方「空串跳过发射」的内容门控对热路径可变名单随之收敛）。
// 写失败返回 error 沿渲染链路上报。
func ipListRuleOperand(scope string, entries []string, negated bool) (string, error) {
	path, err := writeIPListFile(scope, entries)
	if err != nil {
		return "", err
	}
	operand := "@ipListFast " + path
	if negated {
		operand = "!" + operand
	}
	return operand, nil
}
