package services

import (
	"bytes"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/wafiplist"
)

// init 装配 wafiplist 的观测钩子：运行期名单文件被删/写坏、重建失败而回退
// 旧集合（fail-stale）时，以及「名单不可读且无缓存集合」（fail-open/信任
// 无来源）时，按路径节流（wafiplist 的 staleServeLogInterval，默认 1 分钟）写
// WARN。wafiplist 的默认钩子只写 stderr（Caddy 进程内的形态）；本进程覆盖为
// 面板日志，级别过滤与落盘一致。两个钩子必须同时装配——只接 fail-stale 会
// 让「无旧集合可用」这一更危险的状态在面板日志中完全静默。
func init() {
	wafiplist.OnStaleServe = func(path string, err error) {
		Logf("warn", "IP 名单 %q 无法重建，继续按最近一次成功加载的集合判定（fail-stale）: %v", path, err)
	}
	wafiplist.OnListUnavailableServe = func(path string, err error) {
		Logf("warn", "IP 名单 %q 不可读且无缓存集合，本次判定按未命中处理（等待文件恢复或重载）: %v", path, err)
	}
}

// IPListDataDir 是策略名单投影目录（@ipListFast 算子读取侧）。生产容器默认
// /app/waf/ip-lists（DataDir=/app/data 同级）；本地开发经 ConfigureWafDirs
// 按 data_dir 同级 waf/ 派生。测试可改。
var IPListDataDir = "/app/waf/ip-lists"

// ConfigureWafDirs 按最终 data_dir 派生**全部** WAF 文件路径（
// 单点派生）：容器内 /app/data → 全部 /app/* 与既有打包路径逐字节一致；
// 本地开发/自定义挂载落到数据目录同级，避免 /app 只读文件系统写入失败。
// 此前只有 wafDir/IPListDataDir/白名单跟随 data_dir，CRS 树/快照/dist、
// xdb、指令目录与爬虫种子仍是独立硬编码真源——data_dir ≠ /app/data 时
// 播种/更新写出数据卷之外、SecurityLibraryStatus 恒 false（安全链静默
// 不渲染）。派生覆盖 CRSRuleIndexDir（索引读侧）与 crsDirectivesDir
// （渲染读侧），保证写读同源。算子白名单前缀同步对齐。
// 派生面同时含 Coraza 审计日志（<parent>/logs/waf-audit/audit.log）
// 与摄取 offset（<data_dir>/security_events.offset）——此前两者硬编码 /app，
// 非容器/自定义挂载部署会写到只读或错误的路径。
func ConfigureWafDirs(dataDir string) {
	// 判据必须是「data_dir == 容器默认 /app/data」，而不是「父目录 == /app」：
	// /app 的任意直接子目录（/app/custom、/app/vol 之外的 /app/xxx）此前也会
	// 命中早退，导致派生面全部留在 /app/*——CRS 快照与 xdb 写进镜像层（容器
	// 重建即丢）、审计日志/摄取 offset 落错位置、xdb 路径指向不存在的库。
	if dataDir == "/app/data" {
		return // 容器默认形态：保持 /app/* 常量（派生结果与之逐字节一致）
	}
	parent := filepath.Dir(dataDir)
	wafDir = filepath.Join(parent, "waf")
	wafDistDir = filepath.Join(parent, "waf.dist")
	IPListDataDir = filepath.Join(wafDir, "ip-lists")
	wafiplist.AllowedPathPrefix = wafDir + string(filepath.Separator)
	// CRS 活树/指令目录/索引目录同源（同一棵树的写侧与读侧）。
	crsLiveDir = filepath.Join(wafDir, "crs")
	crsDirectivesDir = crsLiveDir
	CRSRuleIndexDir = filepath.Join(crsLiveDir, "rules")
	// 快照在数据卷内，发行版在镜像相对目录。
	crsSnapshotDir = filepath.Join(dataDir, "crs")
	crsDistDir = filepath.Join(wafDistDir, "crs")
	ip2regionLivePath = filepath.Join(dataDir, "ip2region.xdb")
	ip2regionDistPath = filepath.Join(wafDistDir, "ip2region.xdb")
	crawlerDistSeedFile = filepath.Join(wafDistDir, "crawler-ip-lists.seed.json")
	// 爬虫运行快照（root 写、插件读的交换文件）同属数据卷
	// 派生面——默认 /app/data/crawler-ip-lists.json 与容器形态逐字节一致。
	crawlerIPListFile = filepath.Join(dataDir, "crawler-ip-lists.json")
	// 下载 TOFU 完整性基线同属数据卷派生面（与 ip2region.xdb、
	// security_events.offset 同域）。此前硬编码 /app/data：自定义 data_dir
	// 的非容器部署下基线持久化恒失败，且失败只降级为错误日志——每次下载都被
	// 当作「首次下载」重新定基线，代理投毒的内容不一致阻断分支永不触发。
	downloadIntegrityPath = filepath.Join(dataDir, ".download-integrity.json")
	// Coraza 审计日志与摄取 offset 同属「随 data_dir
	// 落数据卷/日志根」的路径域，必须与上列路径同批派生——此前硬编码 /app：
	// 自定义 data_dir 的非容器部署会继续读写 /app（常不可写）→ 摄取持续失败、
	// WAF 审计写入失败。日志根取数据目录同级的 logs/（与容器
	// /app/data→/app/logs 同构）；offset 落数据目录内（与 ip2region.xdb 同域）。
	auditLogPath = filepath.Join(parent, "logs", "waf-audit", "audit.log")
	securityEventsOffsetPath = filepath.Join(dataDir, "security_events.offset")
}

// CRSLiveDir 返回 CRS 活树目录（ConfigureWafDirs 派生后的当前值）。handlers
// 的规则文件读取测试缝以空值表示「按本函数派生」，避免同一条路径出现第二处
// 硬编码真源。
func CRSLiveDir() string { return crsLiveDir }

// IP2RegionLivePath 返回 ip2region.xdb 活库路径（ConfigureWafDirs 派生后的
// 当前值），与 CRSLiveDir 同源——备份导入的文件快照/回退必须与落盘侧读写
// 同一条路径，不得在 handlers 侧另派生。
func IP2RegionLivePath() string { return ip2regionLivePath }

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
// 集（GC 差集口径）。GC 不在此触发：渲染中途按上一
// 轮陈旧引用集差集会误删在役文件——统一由整轮渲染 apply 成功后触发
// （maybeGCStaleIPListFiles，引用集落齐再差集；全部阈值为 time.Since 时长
// 比较，无挂钟排程、与时区配置无关）。
func validIPListScope(scope string) bool {
	if scope == "" || len(scope) > 128 {
		return false
	}
	for _, r := range scope {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '-' && r != '.' {
			return false
		}
	}
	return true
}

// ipListProjectionMemo 进程级投影备忘：scope 路径 → (原始输入指纹, 落盘后
// mtime/size)。渲染按 (规则×策略) 对调用，同一 scope 的名单聚合（排序/合并）
// 与整文件读回会被逐对重复——大名单×多规则时是生成期的显性 CPU/IO 放大。
// 命中（输入指纹一致且文件 mtime/size 与落盘记录一致）即跳过聚合与读回。
// 残余风险披露：外部改写内容但保持 mtime+size 不变时不被检测（原整文件
// 读回可比对字节）——投影目录由本进程独占写入，该形态只可能来自刻意带外
// 构造；文件被删/mtime 漂移仍走完整重写路径。指纹为 FNV-1a 64 位非密码学
// 哈希（抗碰撞不是本判据的依赖）：陈旧命中需同时满足同指纹 + 同 size +
// 同 mtime，慢路径的字节比对才是内容判据，快路只跳过重复工作。
// RestoreIPListProjections 回滚重写文件后清空备忘（防陈旧命中跳过必要重写）。
var (
	ipListProjectionMemoMu sync.Mutex
	ipListProjectionMemo   = map[string]ipListProjectionMemoEntry{}
)

type ipListProjectionMemoEntry struct {
	inputHash uint64
	mtimeNano int64
	size      int64
}

// ipListProjectionPass 记录「本轮渲染新建」的投影文件（写前不存在），是回滚
// 删除的唯一判据。不能用「目录里有、快照里没有」判定：快照阶段的瞬时读失败/
// 目录列举失败会让在役投影缺项，按缺失判据回滚即把它当作渲染新增删除——运行
// 中 Caddy 的 @ipListFast 会读到文件不存在，allow/deny 名单同时失效。
// 生命周期：SnapshotIPListProjections 开启一轮，RestoreIPListProjections 或
// EndIPListProjectionPass 收尾（成功路径不删除任何文件，只释放清单）。
// 并发前提与 ipListRenderRefs 同款：渲染串行。
var ipListProjectionPass = struct {
	mu      sync.Mutex
	created map[string]struct{}
}{}

func beginIPListProjectionPass() map[string]struct{} {
	created := make(map[string]struct{})
	ipListProjectionPass.mu.Lock()
	ipListProjectionPass.created = created
	ipListProjectionPass.mu.Unlock()
	return created
}

func noteIPListProjectionCreated(path string) {
	ipListProjectionPass.mu.Lock()
	if ipListProjectionPass.created != nil {
		ipListProjectionPass.created[path] = struct{}{}
	}
	ipListProjectionPass.mu.Unlock()
}

// EndIPListProjectionPass 结束本轮渲染的新建清单跟踪（渲染成功后调用：新建的
// 投影已随配置提交，不得再被后续回滚删除）。
func EndIPListProjectionPass() {
	ipListProjectionPass.mu.Lock()
	ipListProjectionPass.created = nil
	ipListProjectionPass.mu.Unlock()
}

func ipListInputHash(entries []string) uint64 {
	h := fnv.New64a()
	for _, entry := range entries {
		_, _ = h.Write([]byte(entry))
		_, _ = h.Write([]byte{0})
	}
	return h.Sum64()
}

func writeIPListFile(scope string, merged []string) (string, error) {
	if !validIPListScope(scope) {
		return "", fmt.Errorf("IP 名单投影 scope 含非法字符或超出长度限制: %q", scope)
	}
	// 条目内嵌换行/回车必须在**聚合前**拒绝：投影是逐行文本协议，带换行的
	// 条目会把一条记录拆成两行——第二行成为未经校验的独立条目（如
	// "1.2.3.4\n0.0.0.0/0" 静默扩大名单）。聚合层 TrimSpace 会先剥掉条目首尾
	// 的 \r/\n（尾缀换行因而查不到），校验必须落在原始输入上。
	// 写失败经渲染错误链路上报（保存侧事务回滚）。
	for _, entry := range merged {
		if strings.ContainsAny(entry, "\r\n") {
			return "", fmt.Errorf("IP 名单投影条目含换行符（scope=%s）: %q", scope, entry)
		}
	}
	name := scope + ".txt"
	path := filepath.Join(IPListDataDir, name)
	noteIPListRenderRef(path)
	// memo 快路：同输入指纹 + 文件落盘态一致 → 跳过聚合与读回。
	inputHash := ipListInputHash(merged)
	ipListProjectionMemoMu.Lock()
	memo, memoOK := ipListProjectionMemo[path]
	ipListProjectionMemoMu.Unlock()
	if memoOK && memo.inputHash == inputHash {
		if st, err := os.Stat(path); err == nil && st.ModTime().UnixNano() == memo.mtimeNano && st.Size() == memo.size {
			// 快路同样必须归一权限：慢路的「同字节跳写」会 Chmod 0644 修
			// 「升级前 0600 投影 + Caddy 换 uid 读不到」，但 memo 只记
			// inputHash/mtime/size——进程内改过权限（或首个进程写出 0600）后
			// 内容/mtime/size 都没变，快路直接返回会让 Caddy 永远读不到该名单
			// （deny 方向静默 fail-open）。chmod 幂等且不改 mtime，不触发
			// wafiplist 重建。
			if err := os.Chmod(path, 0o644); err != nil {
				return "", fmt.Errorf("归一 IP 名单文件权限失败 %s: %w", name, err)
			}
			return path, nil
		}
	}
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
	// 记录备忘（同字节跳写与重写两条成功路径同点）——stat 失败时跳过记录，
	// 下轮走完整路径。
	recordMemo := func() {
		if st, err := os.Stat(path); err == nil {
			ipListProjectionMemoMu.Lock()
			ipListProjectionMemo[path] = ipListProjectionMemoEntry{inputHash: inputHash, mtimeNano: st.ModTime().UnixNano(), size: st.Size()}
			ipListProjectionMemoMu.Unlock()
		}
	}
	existing, readErr := os.ReadFile(path)
	if readErr == nil && string(existing) == content {
		// 同字节跳写仍须归一权限：存量投影由 os.CreateTemp 生成（恒 0600），
		// 内容不再变化的名单永远走不到重写路径，Caddy 换 uid 部署时读不到。
		// chmod 幂等且不改 mtime（内容未变，wafiplist 不重建）。
		if err := os.Chmod(path, 0o644); err != nil {
			return "", fmt.Errorf("归一 IP 名单文件权限失败 %s: %w", name, err)
		}
		recordMemo()
		return path, nil // 同字节跳写
	}
	if err := EnsureIPListDir(); err != nil {
		return "", err
	}
	// 唯一临时名：并发渲染同一 scope 命中同一正式路径时，
	// CreateTemp 使每次写入独占临时文件，rename 串行原子生效。失败路径清理
	// 临时文件。
	tmp, err := os.CreateTemp(IPListDataDir, scope+"-*.tmp")
	if err != nil {
		return "", fmt.Errorf("创建 IP 名单临时文件失败 %s: %w", name, err)
	}
	tmpName := tmp.Name()
	// CreateTemp 默认 0600，而回滚路径与 atomicwrite.writeFileAtomicSynced
	// 用 0644——@ipListFast 是跨进程读文件协议，正常渲染产出 0600、回滚后变
	// 0644 的形态分叉会在 Caddy 换 uid 部署时表现为名单读不到。显式对齐。
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("设置 IP 名单临时文件权限失败 %s: %w", name, err)
	}
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("写入 IP 名单文件失败 %s: %w", name, err)
	}
	// tmp+rename 缺 fsync 时掉电/内核崩溃可留下 0 字节投影文件——
	// wafiplist 对空文件按「永不命中」接受，deny/blacklist 语义即静默 fail-open。
	// 与 certstore 的原子写同口径：临时文件落盘 + 父目录 fsync 后 rename 生效。
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("同步 IP 名单文件失败 %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("关闭 IP 名单临时文件失败 %s: %w", name, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("原子替换 IP 名单文件失败 %s: %w", name, err)
	}
	// 写前不存在（读回仅报 ErrNotExist）＝本轮渲染新建：登记进回滚清单。
	// 权限/列举类错误不登记（无法判定文件是否本就有），回滚宁可少删。
	if readErr != nil && errors.Is(readErr, os.ErrNotExist) {
		noteIPListProjectionCreated(path)
	}
	if err := syncParentDir(path); err != nil {
		return "", fmt.Errorf("同步 IP 名单目录失败 %s: %w", name, err)
	}
	recordMemo()
	return path, nil
}

// IPListProjectionSnapshot 是渲染前投影目录的字节快照（仅 .txt 投影文件）与
// 「本轮渲染新建」清单。files 用于回写旧内容；created 是回滚删除的唯一判据。
type IPListProjectionSnapshot struct {
	files   map[string][]byte
	created map[string]struct{}
}

// SnapshotIPListProjections 开启一轮渲染并快照投影目录，供 CLI 预检失败时
// 自回滚。读目录或读任一投影失败即返回错误（不返回不完整快照）：调用方不得
// 在快照不完整的前提下渲染——回写缺项会让未提交内容留在投影目录，而旧口径
// 下缺失项还会被当作渲染新增删除，直接删掉在役名单。
func SnapshotIPListProjections() (IPListProjectionSnapshot, error) {
	created := beginIPListProjectionPass()
	snapshot := IPListProjectionSnapshot{files: map[string][]byte{}, created: created}
	entries, err := os.ReadDir(IPListDataDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// 首次保存：目录尚未创建＝没有任何在役投影可回滚。
			return snapshot, nil
		}
		EndIPListProjectionPass()
		return IPListProjectionSnapshot{}, fmt.Errorf("读取 IP 名单投影目录 %s: %w", IPListDataDir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".txt") {
			continue
		}
		path := filepath.Join(IPListDataDir, entry.Name())
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			EndIPListProjectionPass()
			return IPListProjectionSnapshot{}, fmt.Errorf("读取 IP 名单投影 %s: %w", path, rerr)
		}
		snapshot.files[path] = data
	}
	return snapshot, nil
}

// RestoreIPListProjections 删除本轮渲染新建的投影、回写快照内容，返回回滚
// 失败明细（nil=完整回滚）。
//
// 删除只认渲染清单（snapshot.created），不遍历目录做差集：快照缺项不代表
// 渲染新增，按差集删除会在快照读失败时删掉在役投影。回滚失败不得静默：预检
// 失败后投影目录若停留在「新内容」状态，稳定命名 + 热路径设计会让运行中的
// Caddy 在 ≤1s 内感知到未提交的名单内容；同时被删文件的 wafiplist 运行期
// 缓存必须与 GC 路径同口径淘汰（fail-stale 下继续用已删集合判定）。调用方
// 据此留痕（caddy CLI 预检回滚路径写 error 日志）。
func RestoreIPListProjections(snapshot IPListProjectionSnapshot) error {
	// 回滚直接重写/删除投影文件——备忘的落盘态记录随之失效，清空防陈旧
	// 命中跳过必要重写。
	ipListProjectionMemoMu.Lock()
	ipListProjectionMemo = map[string]ipListProjectionMemoEntry{}
	ipListProjectionMemoMu.Unlock()
	var errs []error
	var deleted []string
	for path := range snapshot.created {
		if rerr := os.Remove(path); rerr != nil {
			if errors.Is(rerr, os.ErrNotExist) {
				continue
			}
			errs = append(errs, fmt.Errorf("删除投影 %s: %w", path, rerr))
		} else {
			deleted = append(deleted, path)
		}
	}
	for path, data := range snapshot.files {
		// 内容相同的文件不重写：回滚会改写全部投影 inode/mtime，运行中 Caddy 的
		// @ipListFast stat 缓存在 ≤1s 内对所有名单重建（读盘放大 + 统计形态全变）。
		if current, rerr := os.ReadFile(path); rerr == nil && bytes.Equal(current, data) {
			continue
		}
		if werr := writeFileAtomicSynced(path, data, 0o644); werr != nil {
			errs = append(errs, fmt.Errorf("回写投影 %s: %w", path, werr))
		}
	}
	if len(deleted) > 0 {
		wafiplist.EvictIPListCache(deleted...)
	}
	EndIPListProjectionPass()
	return errors.Join(errs...)
}

// @ipListFast 投影文件 + 运行期缓存 GC ----------

// ipListFileMaxAge 是 GC 删除未引用文件的超龄门槛（24h）：避开 Caddy 重载
// 窗口——新配置刚投影/换名的文件即使暂未进入引用集也不删。
const ipListFileMaxAge = 24 * time.Hour

// ipListGCInterval 是自动 GC 的最小间隔（每次成功投影后检查一次）。
const ipListGCInterval = time.Hour

// ipListProjectedFileName 匹配投影文件命名——差集清理只碰该形态，目录内其他
// 文件（运维投放/误放）一律不动。分支（2026-10-15 热路径改造收口）：
//   - 新稳定命名 <scope>.txt：p[0-9]+-(acl|trust|bl|crsxc-…)（策略身份；
//     crsxc-<12位hex>=CRS 作用域排除匹配集投影，
//     crsxc-<纯数字>=历史首发序号形态（已被哈希取代，存量由 24h GC 过渡
//     回收））、tp（受信代理全局单份）、u-<kind>-<ruleCaddyID>（历史
//     预检/引擎层 u-* 投影 scope 编入规则身份，如 u-deny-lb_2r8dosptk1
//     字符类收 `_`，并收大写与 `.`（v2 导入可携带大写/
//     含点 rule id，旧字符类使这类孤儿永不回收；白名单仍不含路径分隔符，
//     纯单段文件名，无路径逃逸面）；升级前旧全局名 u-deny.txt 等同字符类
//     天然覆盖，由 24h GC 过渡回收）；精确白名单，用户手放文件不碰；
//   - 旧内容寻址 <已知 scope>-sha256[:12].txt——迁移过渡分支：改造前落盘的
//     旧哈希文件由既有 24h GC 自然回收（不写迁移）。后缀只允许
//     挂在上述已知 scope 形态之后——原 `|.+-[0-9a-f]{12}` 会把运维投放的
//     backup-deadbeef1234.txt 一律当作自身投影删除，且「旧文件清尽后自行
//     失效」的注释不成立（分支恒命中任意前缀）。旧文件清尽后该分支对已知
//     scope 仍可能命中（用户手放同形名），但不再吞未知前缀文件。
var ipListProjectedFileName = regexp.MustCompile(`^(u-[A-Za-z0-9][A-Za-z0-9._-]*|p[0-9]+-(acl|trust|bl|crsxc-([0-9]+|[0-9a-f]{12}))|tp)(-[0-9a-f]{12})?\.txt$`)

// ipListTempFileName 匹配 writeIPListFile 的临时文件名形态
// （CreateTemp(IPListDataDir, scope+"-*.tmp")：<投影 scope>-<随机数字>.tmp）。
// GC 只委托删除本模块拥有的临时文件——目录内的无关
// .tmp（运维投放的 ops-notes.tmp 等）一律不动；24h 超龄门槛仍保护在役写入
// （在役 tmp 恒新鲜）。scope 白名单与 ipListProjectedFileName 同源
// 同款收口：旧哈希后缀只挂已知 scope，不吞任意前缀）。
var ipListTempFileName = regexp.MustCompile(`^(u-[A-Za-z0-9][A-Za-z0-9._-]*|p[0-9]+-(acl|trust|bl|crsxc-([0-9]+|[0-9a-f]{12}))|tp)(-[0-9a-f]{12})?-[0-9]+\.tmp$`)

// ipListRenderRefs 记录本进程渲染引用过的投影文件及最近引用时间：一次全量
// 配置渲染会重新投影全部在役名单（同字节跳写也计引用），故「长期
// 未被引用 + 超龄」即孤儿（策略解绑/删除、发射面变化后的旧文件）。
var ipListRenderRefs = struct {
	sync.Mutex
	lastRef map[string]time.Time
}{lastRef: make(map[string]time.Time)}

// ipListLastGC 上次自动 GC 时间；初始化为进程启动时刻——启动渲染尚未完成
// 引用集采集前不得触发首轮 GC。
// 并发前提（调用方契约）：本变量无锁保护，正确性依赖「成功渲染串行」——
// maybeGCStaleIPListFiles 只在整轮渲染 apply 成功且引用集落齐后调用；若未来
// 出现并发渲染，差集会基于半落齐的引用集误删在役投影（allow 方向 403 风暴，
// deny 方向 fail-open）。新增并发渲染路径必须先把本状态收进带锁结构。
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

// ResetIPListProjectionStateForTest 清空进程级投影状态（投影备忘 + 渲染引用
// 集），等价于进程重启后的首轮渲染起点：生产重启天然是空表，同进程用例必须
// 显式清空，否则备忘快路可能掩盖「文件与库不一致 → 必须重写」的重写路径。
func ResetIPListProjectionStateForTest() {
	ipListProjectionMemoMu.Lock()
	ipListProjectionMemo = map[string]ipListProjectionMemoEntry{}
	ipListProjectionMemoMu.Unlock()
	ipListRenderRefs.Lock()
	ipListRenderRefs.lastRef = make(map[string]time.Time)
	ipListRenderRefs.Unlock()
}

// maybeGCStaleIPListFiles 整轮渲染 apply 成功后的节流 GC 入口（间隔
// ipListGCInterval）——此刻本轮渲染的全部在役名单引用已落齐，差集决策安全。
//
// （触发面披露）：唯一调用点在成功 /load 之后；2026-10-15 起的名单
// 热路径刻意零 /load，因此长期仅热路径收敛的系统里，孤儿投影（通常由策略/
// 规则删除产生，删除走全量链会触发本 GC）的回收会被推迟到下一次真实重载。
// 有界非泄漏（文件不增长、不参与渲染），接受该披露而不为零/load 路径新增
// GC 触发点（差集前提=本轮全量引用集已落齐，热路径不具备该前提）。
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
// 差集决策的前提是「渲染引用集=本进程在役投影
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
	// 顺带清理超龄崩溃残留的投影临时文件（CreateTemp 半截
	// .tmp 无引用语义，超龄即可删；在役写入的 .tmp 恒新鲜，不受影响）。
	for _, entry := range entries {
		// 名字形态门——只回收本模块 CreateTemp 产出的临时文件，
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
		// 投影备忘与文件同生命周期：memo 键是投影路径，GC 删文件时不清条目会
		// 让「规则删除/改名」后的 scope 永久驻留（进程级缓慢增长）。memo 只是
		// 快路，清除无正确性代价。
		ipListProjectionMemoMu.Lock()
		for _, path := range deleted {
			delete(ipListProjectionMemo, path)
		}
		ipListProjectionMemoMu.Unlock()
		Logf("info", "IP 名单 GC: 清理 %d 个超龄未引用名单文件", len(deleted))
	}
	// 顺带 prune 引用集中早于 maxAge 的条目——文件已删
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
