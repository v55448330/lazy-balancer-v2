package services

// 结构化 CRS 规则索引：解析 /app/waf/crs/rules/*.conf 中每条 SecRule 的
// id + msg，供三处消费——
//   1. GET /security/crs/rule-index（handlers.GetCRSRuleIndex）；
//   2. BuildCorazaDirectives 的 crs_rule_groups 混合展开（6 位 ID → 父文件
//      Include + 补删）与 crs_excluded_rules 作用域展开（组号 → 逐 ID
//      ctl:ruleRemoveById）及陈旧过滤（ruleId 不在本地索引 → 跳过发射）；
//   3. 保存侧（handlers.validateAndNormalizeCRSField）6 位规则 ID / 两位
//      组号的存在性校验（陈旧 → 400）。
// 从节点携带本地 CRS 文件，同一索引在其本地构建即可判陈旧（与主端解耦）。
//
// 缓存：键 = security_crs_version 行值 + 目录路径 + 规则目录的（文件数,
// 最大 mtime, 总 size）——CRS 手动/自动更新与从节点 waf_files 同步会写文件
// 与版本行，增删文件/mtime/size/版本变化即键变重建；目录路径编入键使测试
// 夹具/多目录的同统计量场景不会错命中。已知边界：同大小内容替换且 mtime
// 不变的逐字节改写不改键（键是代际判别器，非内容指纹）。命中率稳态下每次
// 取值 ~50 次 stat + 1 次 DB 查询。

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"lazy-balancer-v2/internal/db"
)

// CRSRuleIndexDir 是规则索引的解析目录（与 handlers.crsRulesDir 同默认值）。
// 导出为测试缝：handlers 侧端点/校验测试与 services 侧发射测试共用同一覆盖点。
var CRSRuleIndexDir = "/app/waf/crs/rules"

// CRSRuleIndexEntry 是索引中的单条规则（CRS 9xxxxx ID 空间）。
type CRSRuleIndexEntry struct {
	ID       string `json:"id"`
	Msg      string `json:"msg"`
	File     string `json:"file"`
	Category string `json:"category"`
}

// CRSRuleIndex 是一次解析产物：版本行值 + 按 id 升序的规则列表。
type CRSRuleIndex struct {
	Version string              `json:"version"`
	Rules   []CRSRuleIndexEntry `json:"rules"`

	// ids 为 Has() 的存在性集合（构造期填充，不序列化）。
	ids map[string]struct{} `json:"-"`
}

// Has 报告 ruleID 是否存在于索引。
func (idx *CRSRuleIndex) Has(ruleID string) bool {
	if idx == nil {
		return false
	}
	_, ok := idx.ids[ruleID]
	return ok
}

// Find 返回 ruleID 的索引条目（id 升序线性扫描）；不存在返回 nil。
// Find 线性扫描返回首个同 id 条目（切片升序即最低 id）。
// 评估过集合化：需把 ids 集合值改为切片下标，收益在每条目 µs 级——裁定保留
// 现实现（调用点为配置构建/预览路径，非请求热路径），注释声明为有意取舍。
func (idx *CRSRuleIndex) Find(ruleID string) *CRSRuleIndexEntry {
	if idx == nil {
		return nil
	}
	for i := range idx.Rules {
		if idx.Rules[i].ID == ruleID {
			return &idx.Rules[i]
		}
	}
	return nil
}

// HasGroup 报告两位组号（如 "42" 对应 942xxx 段）是否在索引中至少存在
// 一条规则。CRS 更替后组消失（陈旧组号）时返回 false。
func (idx *CRSRuleIndex) HasGroup(group string) bool {
	if idx == nil || len(group) != 2 {
		return false
	}
	prefix := "9" + group
	for i := range idx.Rules {
		if strings.HasPrefix(idx.Rules[i].ID, prefix) {
			return true
		}
	}
	return false
}

// RuleIDsByGroup 返回两位组号对应的全部规则 ID（索引已按 id 升序，天然有序）。
func (idx *CRSRuleIndex) RuleIDsByGroup(group string) []string {
	if idx == nil || len(group) != 2 {
		return nil
	}
	prefix := "9" + group
	var ids []string
	for i := range idx.Rules {
		if strings.HasPrefix(idx.Rules[i].ID, prefix) {
			ids = append(ids, idx.Rules[i].ID)
		}
	}
	return ids
}

// RuleIDsByFile 把索引按文件聚合为 文件名 → id 升序列表。crs_rule_groups
// 混合选择时对「仅因 ID 引入的父文件」补删其余未选 ID 用。
func (idx *CRSRuleIndex) RuleIDsByFile() map[string][]string {
	out := make(map[string][]string)
	if idx == nil {
		return out
	}
	for i := range idx.Rules {
		out[idx.Rules[i].File] = append(out[idx.Rules[i].File], idx.Rules[i].ID)
	}
	return out
}

// CategorizeCRSFile 按文件名中的 CRS 组号归类（ListCRSRules 与规则索引共用，
// 从 handlers 迁入以保证两处口径单一来源）。
func CategorizeCRSFile(filename string) string {
	name := strings.ToUpper(filename)
	switch {
	case strings.Contains(name, "920-"):
		return "协议异常"
	case strings.Contains(name, "921-"):
		return "协议攻击"
	case strings.Contains(name, "922-"):
		return "multipart 攻击"
	case strings.Contains(name, "930-"):
		return "路径穿越 (LFI)"
	case strings.Contains(name, "931-"):
		return "远程文件包含 (RFI)"
	case strings.Contains(name, "932-"):
		return "远程代码执行 (RCE)"
	case strings.Contains(name, "933-"):
		return "PHP 攻击"
	case strings.Contains(name, "934-"):
		return "通用攻击"
	case strings.Contains(name, "941-"):
		return "XSS 跨站脚本"
	case strings.Contains(name, "942-"):
		return "SQL 注入"
	case strings.Contains(name, "943-"):
		return "会话固定"
	case strings.Contains(name, "944-"):
		return "Java 攻击"
	case strings.Contains(name, "949-"):
		return "评分拦截"
	case strings.Contains(name, "950-"):
		return "响应信息泄露"
	case strings.Contains(name, "951-"):
		return "响应 SQL 泄露"
	case strings.Contains(name, "952-"):
		return "响应 Java 泄露"
	case strings.Contains(name, "953-"):
		return "响应 PHP 泄露"
	case strings.Contains(name, "954-"):
		return "响应 IIS 泄露"
	case strings.Contains(name, "955-"):
		return "Webshell"
	case strings.Contains(name, "956-"):
		return "响应 Ruby 泄露"
	case strings.Contains(name, "959-"):
		return "响应阻断评估"
	case strings.Contains(name, "980-"):
		return "事件关联"
	case strings.Contains(name, "900-"):
		return "初始化/排除"
	case strings.Contains(name, "901-"):
		return "初始化"
	case strings.Contains(name, "905-"):
		return "通用异常"
	case strings.Contains(name, "911-"):
		return "方法限制"
	case strings.Contains(name, "913-"):
		return "爬虫检测"
	case strings.Contains(name, "915-"):
		return "请求体限制"
	case strings.Contains(name, "999-"):
		return "通用排除（CRS 后）"
	default:
		return "其他"
	}
}

var (
	// crsRuleIDPattern 匹配指令动作串里的 id:9xxxxx（CRS ID 空间）。
	// "SecRuleRemoveById 942100"/"ctl:ruleRemoveTargetById=942550" 无冒号，
	// 不会被误捕。
	crsRuleIDPattern = regexp.MustCompile(`\bid:\s*(9[0-9]{5})\b`)
	// crsDirectiveStartPattern 识别行首指令起点（SecRuleRemoveById /
	// SecRuleUpdateTargetById 等 t: 类指令不在此列——"SecRule" 后无词边界）。
	crsDirectiveStartPattern = regexp.MustCompile(`^(?:SecRule|SecAction|SecMarker|Include|SecComponentSignature)\b`)
)

// extractCRSRuleMsg 取指令块中 msg 动作的引号内容。引号形态三种：单引号
// msg:'...'、双引号 msg:"..."、以及双引号动作串内的转义形态 msg:\"...\"。
// 终止符与开引号同形（转义开 → 转义闭，裸开 → 裸闭）：msg:'can\'t' 中 \' 是
// 内容，而 msg:\"...\" 的闭引号恰是 \". 返回还原转义、去首尾空白的文本。
func extractCRSRuleMsg(chunk string) string {
	loc := strings.Index(chunk, "msg:")
	if loc < 0 {
		return ""
	}
	rest := chunk[loc+len("msg:"):]
	i := 0
	for i < len(rest) && (rest[i] == ' ' || rest[i] == '\t') {
		i++
	}
	escapedOpen := false
	if i < len(rest) && rest[i] == '\\' {
		escapedOpen = true
		i++
	}
	if i >= len(rest) || (rest[i] != '\'' && rest[i] != '"') {
		return ""
	}
	quote := rest[i]
	i++
	var content strings.Builder
	for i < len(rest) {
		ch := rest[i]
		if ch == '\\' && i+1 < len(rest) {
			if rest[i+1] == quote && escapedOpen {
				break
			}
			content.WriteByte(rest[i+1])
			i += 2
			continue
		}
		if ch == quote {
			break
		}
		content.WriteByte(ch)
		i++
	}
	return strings.TrimSpace(content.String())
}

// crsRuleIDSearchSpace 从指令块文本中取出「id: 可出现的区段」：指令的最后一个
// 引号字面量（动作串；SecRule/SecAction 的动作列表恒为末位引号参数），并剥离
// 其内部使用另一种引号嵌套的 msg/tag 内容。找不到引号字面量时退回整段文本
// （兼容非标准但历史上可解析的形态）。
func crsRuleIDSearchSpace(chunk string) string {
	literal, outer := lastCRSQuotedLiteral(chunk)
	if literal == "" {
		return chunk
	}
	return stripCRSNestedQuotes(literal, outer)
}

// lastCRSQuotedLiteral 返回最后一个引号字面量的内容与其引号字符。
// 引号内的反斜杠转义（' / "）不结束字面量。
func lastCRSQuotedLiteral(s string) (string, byte) {
	var last string
	var outer byte
	var quote byte
	start := -1
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case quote == 0:
			if ch == '\'' || ch == '"' {
				quote = ch
				start = i + 1
			}
		case ch == '\\' && i+1 < len(s):
			i++
		case ch == quote:
			last = s[start:i]
			outer = quote
			quote = 0
			start = -1
		}
	}
	if quote != 0 && start >= 0 {
		// 未闭合字面量：取到结尾（宽松解析，保持历史行为）
		return s[start:], quote
	}
	return last, outer
}

// stripCRSNestedQuotes 移除 literal 内部的「另一种引号」字面量内容，
// 保留外层引号对应的顶层文本。
func stripCRSNestedQuotes(literal string, outer byte) string {
	nested := byte('\'')
	if outer == '\'' {
		nested = '"'
	}
	var b strings.Builder
	inNested := false
	for i := 0; i < len(literal); i++ {
		ch := literal[i]
		if inNested {
			if ch == '\\' && i+1 < len(literal) {
				i++
				continue
			}
			if ch == nested {
				inNested = false
			}
			continue
		}
		if ch == nested {
			inNested = true
			continue
		}
		b.WriteByte(ch)
	}
	return b.String()
}

// parseCRSRuleFileContent 把单个 conf 文件解析为 (id, msg) 序列。
// 按指令分块：行首 SecRule/SecAction/... 开块，反斜杠续行直到不续的行收块；
// 注释行（# 开头）整体剔除，防注释里的 id:/msg: 假条目进入索引。msg 捕获
// 到引号内容为止（phase/action 噪声天然不在引号内），并还原 \' / \" 转义。
func parseCRSRuleFileContent(content string) []CRSRuleIndexEntry {
	var out []CRSRuleIndexEntry
	var chunk strings.Builder
	chunkOpen := false
	flush := func() {
		if !chunkOpen {
			return
		}
		text := chunk.String()
		chunk.Reset()
		chunkOpen = false
		// 只在动作串（最后一个引号字面量）里取 id，并剥离其内部
		// msg/tag 单引号内容——整段匹配会把数据操作数 / msg / tag 文本里的
		// "id:9xxxxx" 当规则 ID（幻影 ID 会放行不存在规则的保存）。
		idMatch := crsRuleIDPattern.FindStringSubmatch(crsRuleIDSearchSpace(text))
		if idMatch == nil {
			return
		}
		out = append(out, CRSRuleIndexEntry{ID: idMatch[1], Msg: extractCRSRuleMsg(text)})
	}
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if crsDirectiveStartPattern.MatchString(trimmed) {
			flush()
			chunkOpen = true
		}
		if !chunkOpen {
			continue
		}
		chunk.WriteString(line)
		chunk.WriteString("\n")
		if !strings.HasSuffix(strings.TrimRight(trimmed, " \t\r"), "\\") {
			flush()
		}
	}
	flush()
	return out
}

var (
	crsRuleIndexMu    sync.Mutex
	crsRuleIndexCache *CRSRuleIndex
	crsRuleIndexKey   string
)

// crsRuleIndexVersion 读取 security_crs_version 行值（收敛到
// readCurrentCRSVersion 单一真源——此前这里与更新判定各有一套「空串 vs
// bundled」口径）。索引读取的容错口径保留：库不可用/读失败回落空串（索引
// 仍可用，仅版本展示为空）；行缺失/空值按首装口径回落 bundled，与更新判定
// 同源不漂移。
func crsRuleIndexVersion() string {
	if db.DB == nil {
		return ""
	}
	version, err := readCurrentCRSVersion()
	if err != nil {
		return ""
	}
	return version
}

// crsRuleIndexCacheKey 计算索引缓存键（单返回值；目录不可解析时以 "-" 结尾
// 参与键）：键 = 版本 + 目录路径 + 文件聚合 stat（数量 + 最大 mtime + 总
// size）。目录路径必须在键内——同统计量的不同目录（测试夹具/多目录场景）
// 不得命中同一缓存。注意边界：「同大小内容替换且 mtime 不变」不改键
// （tar 解包保留 mtime 时理论可达），文件内容的逐字节变化不在键的覆盖范围
// 内——键是代际判别器而非内容指纹。
// crsRuleIndexKeyEvals 是测试可观察的指纹键求值计数（生产零消费，仅原子
// 自增）：钉住「生成上下文级索引令牌 → 每轮渲染只求值一次」。
var crsRuleIndexKeyEvals atomic.Int64

func crsRuleIndexCacheKey(version string) string {
	crsRuleIndexKeyEvals.Add(1)
	entries, err := os.ReadDir(CRSRuleIndexDir)
	if err != nil {
		return version + "|" + CRSRuleIndexDir + "|-"
	}
	var maxMtime, totalSize int64
	count := 0
	var modeFold uint32
	for _, entry := range entries {
		// CRS 发行契约=扁平 rules/ 目录（键只聚合顶层 .conf 的 stat）：子目录
		// .conf 不进键，其增删改不会触发索引重建。本键在**每次渲染取值**时
		// 求值，不得在此递归遍历子目录——契约破裂的检测放在重建路径
		// （buildCRSRuleIndex，与同一守卫同源），命中缓存即零额外工作。
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			// 键少算一个文件会让索引缓存停留在旧代（读到已删除/改名的规则
			// 仍判存在）。按文件限流留痕，不静默。
			if msg := fmt.Sprintf("CRS 规则索引缓存键: stat %s 失败（该文件不进键，判存/选组可能陈旧）: %v", entry.Name(), err); auditFailureShouldLog(msg) {
				Logf("warn", "%s", msg)
			}
			continue
		}
		count++
		// 权限位纳入键：chmod 致不可读后 mtime/size/count 不变，旧缓存继续
		// 命中会把「读失败」掩盖成健康态；权限变化必须触发重建。
		modeFold = modeFold*31 + uint32(info.Mode().Perm())
		if mtime := info.ModTime().UnixNano(); mtime > maxMtime {
			maxMtime = mtime
		}
		totalSize += info.Size()
	}
	return fmt.Sprintf("%s|%s|%d|%d|%d|%d", version, CRSRuleIndexDir, count, maxMtime, totalSize, modeFold)
}

// crsSubdirGuardWalks 统计子目录守卫的调用次数（生产零消费，仅原子自增）：
// 钉住「只在重建路径执行」——缓存键求值发生在每次渲染取值上，键里递归遍历
// 子目录会把稳态成本从零变成逐轮全树 Walk。
var crsSubdirGuardWalks atomic.Int64

// warnCRSSubdirRuleFiles 检测子目录内是否存在 .conf 规则文件：CRS 发行契约
// 是扁平 rules/ 目录，索引/缓存键只扫顶层；rule_count 与完整性探针递归全树
// ——子目录规则会让「组存在性 400」与计数口径分叉。返回是否命中（供守卫
// 测试），命中时告警（节流，避免每次索引重建刷屏）。
func warnCRSSubdirRuleFiles(dir string) bool {
	crsSubdirGuardWalks.Add(1)
	found := false
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".conf") {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	if !found {
		return false
	}
	msg := fmt.Sprintf("CRS 规则目录含子目录 .conf（%s）：索引/选组只扫顶层，rule_count 与完整性探针递归全树——规则存在性判定可能与计数分叉（CRS 发行契约=扁平 rules/）", dir)
	if auditFailureShouldLog(msg) {
		Logf("warn", "%s", msg)
	}
	return true
}

// buildCRSRuleIndex 全量解析规则目录：文件名升序遍历（确定性），同 ID
// 保留首见条目（keep first msg），最终按 id 升序输出。version 由调用方传入
// ——键与产物必须同源（两次独立读取会在版本行/目录形态变化时把新代产物挂到
// 旧键上，下一次调用再全量重建一次）。
//
// CRS 发行契约=扁平 rules/ 目录（仅扫顶层）：rule_count 与完整性探针按全树
// 递归口径（子目录 .conf 计入），两者在子目录形态下会分叉——检测到子目录
// .conf 时 WARN（契约被打破，选组存在性判定可能与计数不一致）。
func buildCRSRuleIndex(version string) *CRSRuleIndex {
	index := &CRSRuleIndex{Version: version, Rules: []CRSRuleIndexEntry{}, ids: map[string]struct{}{}}
	entries, err := os.ReadDir(CRSRuleIndexDir)
	if err != nil {
		return index
	}
	for _, entry := range entries {
		if entry.IsDir() {
			warnCRSSubdirRuleFiles(filepath.Join(CRSRuleIndexDir, entry.Name()))
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(CRSRuleIndexDir, entry.Name()))
		if err != nil {
			// 单文件读失败会让整份规则文件的 ID 从索引消失：Has/HasGroup 误判
			// 导致保存 400「规则组不存在」，选组侧把存在 ID 当陈旧跳过（静默
			// 少发射）。必须留痕（按文件限流），不得静默 continue。
			if msg := fmt.Sprintf("CRS 规则索引读取 %s 失败（该文件规则 ID 不进索引，存在性/选组判定可能失真）: %v", entry.Name(), err); auditFailureShouldLog(msg) {
				Logf("warn", "%s", msg)
			}
			continue
		}
		for _, raw := range parseCRSRuleFileContent(string(content)) {
			if _, dup := index.ids[raw.ID]; dup {
				continue
			}
			index.ids[raw.ID] = struct{}{}
			index.Rules = append(index.Rules, CRSRuleIndexEntry{
				ID:       raw.ID,
				Msg:      raw.Msg,
				File:     entry.Name(),
				Category: CategorizeCRSFile(entry.Name()),
			})
		}
	}
	sort.Slice(index.Rules, func(i, j int) bool { return index.Rules[i].ID < index.Rules[j].ID })
	return index
}

// GetCRSRuleIndex 返回规则索引（命中缓存或重建）。永不返回 nil，Rules
// 恒为非 nil 空切片起步。
//
// （verify 结论：确认为有界瞬态窗口，不修锁）：本函数与
// BuildCorazaDirectives 的读侧不持 wafFileMu，而 CRS 树交换
// （swapCRSTreeFromStaging）持 wafFileMu 执行 RemoveAll(rules)→moveTree。
// 两者互不阻塞，交换窗口内并发生成可能读到缺失/部分 rules 树（索引为空 →
// 混选组缺项）。不需要额外锁的理由：①生成+应用与更新自身的 reloader 同持
// CaddyOpLock，更新触发必然在交换完成后以正确代重新生成并最后应用；②窗口内
// 并发生成若选中已被移除的文件，coraza 加载失败→/load 被拒，运行配置保持
// 上一代（不发布半代）；③交换完成后引用键（目录条目数/尺寸/最大 mtime）必然
// 变化，窗口内缓存的空索引不会被后续渲染复用。禁止让渲染持 wafFileMu：渲染/重载
// 在 CaddyOpLock 临界区内，而全局锁序为导入=排空→wafFileMu→CaddyOpLock——
// 持 CaddyOpLock 再取 wafFileMu 即反向嵌套 = AB-BA 死锁。
func GetCRSRuleIndex() *CRSRuleIndex {
	// 版本读取与键/产物同源单次：分开读会在两次读之间版本变化时把新代产物
	// 挂到旧键上（下一次调用键不同→多一次全量重建）。
	version := crsRuleIndexVersion()
	key := crsRuleIndexCacheKey(version)
	crsRuleIndexMu.Lock()
	defer crsRuleIndexMu.Unlock()
	if crsRuleIndexCache != nil && crsRuleIndexKey == key {
		return crsRuleIndexCache
	}
	index := buildCRSRuleIndex(version)
	crsRuleIndexCache, crsRuleIndexKey = index, key
	return index
}

// lazyCRSRuleIndex 返回链级惰性索引取值闭包：单次配置生成内
// BuildCorazaDirectives 的索引消费点（emitScopedCRSExclusions 一次取值；
// emitCRSRuleGroupSelection 的 HasGroup 校验与 id 选组各一次取值）各自直调
// GetCRSRuleIndex 会各付一次缓存键计算（ReadDir + 全量 stat + DB 查询），
// 200 规则全量生成时数百次纯浪费且全程持 CaddyService 写锁；闭包首次调用
// 才取值，同链共享同一实例（零 WAF 选组/无作用域排除时不触发）。
func lazyCRSRuleIndex() func() *CRSRuleIndex {
	return sync.OnceValue(GetCRSRuleIndex)
}
