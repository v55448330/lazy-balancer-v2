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
// 缓存：键 = security_crs_version 行值 + 规则目录的（文件数, 最大 mtime,
// 总 size）——CRS 手动/自动更新与从节点 waf_files 同步只写文件与版本行，
// 任一变化即键变重建；命中率稳态下每次取值 ~50 次 stat + 1 次 DB 查询。

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

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
		idMatch := crsRuleIDPattern.FindStringSubmatch(text)
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

// crsRuleIndexVersion 读取 security_crs_version 行值；库不可用/行缺失时
// 回落空串（索引仍可用，仅版本展示为空）。
func crsRuleIndexVersion() string {
	if db.DB == nil {
		return ""
	}
	var version string
	if err := db.DB.QueryRow("SELECT COALESCE(version,'') FROM security_crs_version WHERE id=1").Scan(&version); err != nil {
		return ""
	}
	return version
}

// crsRuleIndexCacheKey 计算（键, 是否可解析目录）。文件聚合 stat：数量 +
// 最大 mtime + 总 size——任一文件内容/时间戳变化或增删文件都会改变键。
func crsRuleIndexCacheKey(version string) string {
	entries, err := os.ReadDir(CRSRuleIndexDir)
	if err != nil {
		return version + "|-"
	}
	var maxMtime, totalSize int64
	count := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		count++
		if mtime := info.ModTime().UnixNano(); mtime > maxMtime {
			maxMtime = mtime
		}
		totalSize += info.Size()
	}
	return fmt.Sprintf("%s|%d|%d|%d", version, count, maxMtime, totalSize)
}

// buildCRSRuleIndex 全量解析规则目录：文件名升序遍历（确定性），同 ID
// 保留首见条目（keep first msg），最终按 id 升序输出。
func buildCRSRuleIndex() *CRSRuleIndex {
	index := &CRSRuleIndex{Version: crsRuleIndexVersion(), Rules: []CRSRuleIndexEntry{}, ids: map[string]struct{}{}}
	entries, err := os.ReadDir(CRSRuleIndexDir)
	if err != nil {
		return index
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(CRSRuleIndexDir, entry.Name()))
		if err != nil {
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
func GetCRSRuleIndex() *CRSRuleIndex {
	key := crsRuleIndexCacheKey(crsRuleIndexVersion())
	crsRuleIndexMu.Lock()
	defer crsRuleIndexMu.Unlock()
	if crsRuleIndexCache != nil && crsRuleIndexKey == key {
		return crsRuleIndexCache
	}
	index := buildCRSRuleIndex()
	crsRuleIndexCache, crsRuleIndexKey = index, key
	return index
}

// lazyCRSRuleIndex（审计 M4）返回链级惰性索引取值闭包：单次配置生成内
// BuildCorazaDirectives 的三个消费点（crsCoveredInfraGroupCodes /
// emitCRSRuleGroupSelection / emitScopedCRSExclusions）各自直调 GetCRSRuleIndex
// 会各付一次缓存键计算（ReadDir + 全量 stat + DB 查询），200 规则全量生成时
// 数百次纯浪费且全程持 CaddyService 写锁；闭包首次调用才取值，同链共享同一
// 实例（零 WAF 选组/无作用域排除时不触发）。
func lazyCRSRuleIndex() func() *CRSRuleIndex {
	return sync.OnceValue(GetCRSRuleIndex)
}
