package services

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/wafiplist"
)

// ipListChunkSize bounds each IN (...) placeholder batch (SQLite 上限 32766 绑定
// 变量，与 policyCustomRuleChunkSize 同型防线)：超大会让整个查询失败，引用条目
// 静默丢失（IP 控制削弱）。
var ipListChunkSize = 500

// policyIPRefExpansion 是 expandPolicyIPRefs 的输出：inline ∪ 引用条目的合并集
// （去重、inline 优先）。listByID 为 nil/缺失 id/畸形 refs 时退化为 inline-only。
type policyIPRefExpansion struct {
	ACLList   []string
	Whitelist []string
}

// parseIPListRefs 解析 refs JSON（[]int64 形态）：nil/空串/空白 → nil；畸形 → nil
// （跳过引用，仅保留 inline，发射不因此失败——与 resolvePolicyCustomRules 的
// 悬空引用仅留痕口径一致）。条目去重，保持出现顺序。
// parseIPListRefs 与 handlers.parseIPListRefsIDs 为镜像实现
// 裁定保留双份并声明）：本侧投影路径去重保序，handlers 侧校验路径不去重
// ——语义有意分叉，勿单方面合并。
// 本函数为零日志形态（判定/兼容调用）；渲染路径
// 必须走 parseIPListRefsLogged——畸形 refs 静默按空集处理会让 deny ACL 仅引用
// 列表的策略合并集为空、id:2 永不命中（静默 fail-open），此前零告警。
func parseIPListRefs(raw string) []int64 {
	ids, _ := parseIPListRefsChecked(raw)
	return ids
}

// parseIPListRefsChecked 与 parseIPListRefs 同解析语义，另把「非空但畸形」暴露
// 为错误（空/空白=未配置引用，不算畸形）。
func parseIPListRefsChecked(raw string) ([]int64, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var ids []int64
	if err := json.Unmarshal([]byte(raw), &ids); err != nil {
		return nil, err
	}
	seen := make(map[int64]struct{}, len(ids))
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, nil
}

// parseIPListRefsLogged 渲染路径解析入口：非空畸形 refs 留痕后按
// 空集处理——行为与旧实现一致（仅保留 inline，不升级 IPRefMissing：该标记会
// 让整条策略含 WAF/限流一并跳过渲染，缺失面反而放大）。
func parseIPListRefsLogged(policyID int, field, raw string) []int64 {
	ids, err := parseIPListRefsChecked(raw)
	if err != nil {
		logMalformedIPListRefs(policyID, field, err)
	}
	return ids
}

// logMalformedIPListRefs 渲染期引用 IP 名单 JSON 畸形留痕
// 与 logMalformedInlineIPList 同口径。写侧（handlers parseIPListRefsPayload）/
// 导入校验已拒畸形，仅带外改库/集群快照继承/旧备份可达。
func logMalformedIPListRefs(policyID int, field string, err error) {
	msg := fmt.Sprintf("渲染: 策略 #%d 引用 IP 名单 %s 解析失败（该列按空集处理，仅保留 inline 条目）: %v", policyID, field, err)
	if auditFailureShouldLog(msg) {
		Logf("warn", "%s", msg)
	}
}

// ipListRefsNonEmpty 报告 refs JSON 是否解析出至少一个条目（畸形视为空）。
// SecurityPolicyHasIPControl 用它在无需加载数据库的情况下判定「仅引用」策略。
func ipListRefsNonEmpty(raw string) bool {
	return len(parseIPListRefs(raw)) > 0
}

// logMalformedInlineIPList 渲染期内联 IP 名单 JSON 畸形留痕（带限流）。
// 写侧/导入侧已拒非 JSON，仅带外改库/旧库残留可达；旧实现
// 静默按空集处理——deny ACL / 黑名单方向即 fail-open 且零告警。
func logMalformedInlineIPList(policyID int, field string, err error) {
	msg := fmt.Sprintf("渲染: 策略 #%d 内联 IP 名单 %s 解析失败（该列按空集处理）: %v", policyID, field, err)
	if auditFailureShouldLog(msg) {
		Logf("warn", "%s", msg)
	}
}

// logMalformedInlineIPLists 按策略留痕两个内联 IP 列（合并集缓存
// 命中时不再走 expandPolicyIPRefs，需在此补齐该策略自身的畸形留痕）。
func logMalformedInlineIPLists(p *models.SecurityPolicy) {
	if p == nil {
		return
	}
	var list []string
	if err := json.Unmarshal([]byte(p.IPACLList), &list); err != nil {
		logMalformedInlineIPList(p.ID, "ip_acl_list", err)
	}
	list = nil
	if err := json.Unmarshal([]byte(string(p.IPWhitelist)), &list); err != nil {
		logMalformedInlineIPList(p.ID, "ip_whitelist", err)
	}
}

// expandPolicyIPRefs 把策略的 inline IP 条目与引用的 IP 列表条目合并为生效集：
// inline 条目优先，其后按 refs 出现顺序追加各列表条目；跨来源逐值去重；
// listsByID 缺失的 id 与内嵌 null 值跳过。纯函数，不触碰数据库。
func expandPolicyIPRefs(p *models.SecurityPolicy, listsByID map[int64][]string) policyIPRefExpansion {
	var exp policyIPRefExpansion
	if p == nil {
		return exp
	}
	merge := func(field, refsField, inlineRaw string, refsRaw string) []string {
		var merged []string
		seen := make(map[string]struct{})
		addAll := func(entries []string) {
			for _, entry := range entries {
				if entry == "" {
					continue
				}
				if _, dup := seen[entry]; dup {
					continue
				}
				seen[entry] = struct{}{}
				merged = append(merged, entry)
			}
		}
		var inline []string
		if err := json.Unmarshal([]byte(inlineRaw), &inline); err != nil {
			logMalformedInlineIPList(p.ID, field, err)
		}
		addAll(inline)
		// 非法 refs 与非 inline 同口径留痕（同一消息限流，不重复刷屏）。
		for _, id := range parseIPListRefsLogged(p.ID, refsField, refsRaw) {
			addAll(listsByID[id])
		}
		return merged
	}
	// 合并即聚合（修复，用户上报「规则越多保存越慢」根因）
	// 发射端 mergedACLList/mergedWhitelist 按规则×策略逐次调用，若在此处不
	// 聚合，万条级合并集（如 USTC 11415 条）会被每次调用全量重聚合——保存
	// 耗时随绑定规则数线性放大。聚合幂等，此处一次完成后发射端直接返回。
	exp.ACLList = aggregateIPEntries(merge("ip_acl_list", "ip_acl_list_refs", p.IPACLList, p.IPACLListRefs))
	exp.Whitelist = aggregateIPEntries(merge("ip_whitelist", "ip_whitelist_refs", string(p.IPWhitelist), p.IPWhitelistRefs))
	return exp
}

// ipListChunkFailure 一块分批查询的失败（查询或行迭代错误）。调用方按各自
// 严格模式口径处置该块 id：渲染把整块标记为装载失败，摘要同判。
type ipListChunkFailure struct {
	ids   []int64
	cause error
}

// forEachIPListChunk 按 ipListChunkSize 分批执行「SELECT <columns> FROM
// security_ip_lists WHERE id IN (...)」，每块仅在有可见行时调用 scanRows
// （回调内自建 Next/Scan 循环，行级失败由回调自行处置），块级失败收集返回。
// 渲染装载与摘要存在性判定共用同一分批、占位符构造与迭代错误捕获——两者
// 差异只剩列清单与行处理。
func forEachIPListChunk(store caddyConfigStore, ids []int64, columns string, scanRows func(rows *sql.Rows)) []ipListChunkFailure {
	if len(ids) == 0 {
		return nil
	}
	var failures []ipListChunkFailure
	for start := 0; start < len(ids); start += ipListChunkSize {
		end := start + ipListChunkSize
		if end > len(ids) {
			end = len(ids)
		}
		chunk := ids[start:end]
		placeholders := strings.Repeat("?,", len(chunk))
		placeholders = placeholders[:len(placeholders)-1]
		args := make([]interface{}, len(chunk))
		for i, id := range chunk {
			args[i] = id
		}
		rows, err := store.Query("SELECT "+columns+" FROM security_ip_lists WHERE id IN ("+placeholders+")", args...)
		if err != nil {
			failures = append(failures, ipListChunkFailure{ids: chunk, cause: fmt.Errorf("store 查询 security_ip_lists: %w", err)})
			continue
		}
		scanRows(rows)
		// 迭代错误必须显式捕获——rows.Next() 因错误（而非 EOF）返回 false 时
		// 静默走掉会让装载集合缺行而 failedIDs 不置位，引用策略拿到「静默缺内容
		// 的合并集」绕过 IPRefMissing 严格模式（ACL/信任面静默收窄零留痕）。
		if err := rows.Err(); err != nil {
			failures = append(failures, ipListChunkFailure{ids: chunk, cause: fmt.Errorf("store 迭代 security_ip_lists: %w", err)})
		}
		rows.Close()
	}
	return failures
}

// store 感知装载（审计）——store 非-nil（v2 导入事务视图）经其查询，
// nil 回退 db.DB。镜像 resolvePolicyIPListRefs 的回退逻辑。
func loadIPListEntriesVia(store caddyConfigStore, ids []int64) (map[int64][]string, map[int64]bool, error) {
	if store == nil {
		m, err := LoadIPListEntriesByID(ids)
		return m, nil, err
	}
	// RDB 文件化：system=1（威胁库）条目读 .iplist 文件，system=0（自定义）
	// 读 DB entries——查询加 system+source 列路由。
	entries := make(map[int64][]string, len(ids))
	failed := make(map[int64]bool) // RDB 严格模式：文件读取失败的列表 id
	if len(ids) == 0 {
		return entries, failed, nil
	}
	var firstErr error
	failures := forEachIPListChunk(store, ids, "id, COALESCE(entries,'[]'), COALESCE(system,0), COALESCE(name,'')", func(rows *sql.Rows) {
		for rows.Next() {
			var id int64
			var raw string
			var system int
			var name string
			if err := rows.Scan(&id, &raw, &system, &name); err != nil {
				// Scan 失败不再静默——行丢弃须留痕（该列表
				// 若被引用，缺失表现为合并集静默缺条目）。
				Logf("warn", "渲染: security_ip_lists 行扫描失败（该行丢弃）: %v", err)
				// 严格模式必须把该 id 记为失败；仅 continue 会按 inline-only
				// 继续渲染，deny 集合静默收窄。
				failed[id] = true
				if firstErr == nil {
					firstErr = fmt.Errorf("scan security_ip_lists id %d: %w", id, err)
				}
				continue
			}
			if system == 1 && threatSourceByListName(name) != "" {
				// 威胁库（RDB 文件化名单）：读.iplist 文件（源文件）。
				// 以「名字映射到威胁源」路由而非 system=1——自动封禁预置名单
				// 同为 system=1 但条目在 DB entries，走文件分支会恒失败并触发
				// 严格模式跳过引用策略的渲染。
				vals, ferr := readThreatIplistEntries(name)
				if ferr != nil {
					Logf("error", "渲染: 威胁库 %q 文件读取失败: %v（严格模式：引用该列表的策略将被跳过渲染）", name, ferr)
					failed[id] = true
					if firstErr == nil {
						firstErr = ferr
					}
					continue
				}
				entries[id] = vals
			} else {
				// 自定义列表：读 DB entries JSON（解析判定与摘要单源）
				list, perr := parseIPListEntriesStrict(raw)
				if perr != nil {
					// 畸形自定义名单必须进入 failedIDs：引用策略走严格跳过，
					// 不得以缺内容的合并集静默收窄防护；不向全局 firstErr 上抛，
					// 避免未引用该名单的渲染被无关脏行整体阻断。
					Logf("error", "渲染: 自定义 IP 列表(id=%d) entries 解析失败（引用策略将跳过渲染）: %v", id, perr)
					failed[id] = true
					continue
				}
				// 过期条目（expires_at 可解析且 <= now）不再下发——到期即
				// 自动解封的唯一发射面。解析失败的 expires_at 保留条目（fail-open
				// 不误删）；判断以 UTC 墙钟串（autobanTimeLayout 同形态），
				// 时钟走 autobanNow 缝（与自动封禁同源，测试可注入时间轴）。
				// 判据单源化 autobanEntryExpired——/status 计数
				// 与渲染生效面共用同一谓词，永不漂移。
				now := autobanNow()
				vals := make([]string, 0, len(list))
				for _, e := range list {
					v := strings.TrimSpace(e.Value)
					if v == "" {
						continue
					}
					if autobanEntryExpired(e, now) {
						continue
					}
					vals = append(vals, v)
				}
				entries[id] = vals
			}
		}
	})
	// 块级失败按渲染口径整块 fail-closed（全入 failedIDs）+首错上抛。
	for _, f := range failures {
		Logf("error", "渲染: security_ip_lists 分批装载失败（本块 %d 个列表全部按装载失败处理）: %v", len(f.ids), f.cause)
		for _, id := range f.ids {
			failed[id] = true
		}
		if firstErr == nil {
			firstErr = f.cause
		}
	}
	if firstErr != nil {
		return entries, failed, firstErr
	}
	return entries, failed, nil
}

// parseIPListEntriesStrict 解析自定义名单的 entries 列（渲染与摘要共用的
// 「装载失败」判定单源）：只有 JSON 解析错误算失败——null 与 [] 同为合法
// 空集（渲染按空集合继续发射，摘要必须同判，否则同一条名单在列表里显示
// 「缺失」而实际按空集生效）。
func parseIPListEntriesStrict(raw string) ([]models.IPListEntry, error) {
	var list []models.IPListEntry
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		return nil, err
	}
	return list, nil
}

// threatTextScanRunsForTest 统计文本名单条目被解析的总次数（生产零消费，仅
// 原子自增）：钉住「一次读取内只解析一遍」——旧实现在同一份文本上先算可解析
// 率、再剔除坏行（各自全量遍历），同一批条目被解析 2–3 遍。
var threatTextScanRunsForTest atomic.Int64

// threatTextScan 文本代际的单遍扫描结果：一次遍历同时产出「剔除不可解析行后
// 的渲染集」与「可解析条数/总条数」，让可解析率门与坏行剔除共用同一份结果。
type threatTextScan struct {
	kept   []string
	parsed int
	total  int
}

// scanThreatTextEntries 单遍解析文本名单条目（与下载解析同口径：不可解析即
// 丢弃，只收合法行）。文本被截断/损坏（乱码行）时解析率显著低于正常名单，
// 调用方据此决定是否改用 .fast 代际——旧实现在同一份 vals 上分别调用
// 「算比率」与「剔除坏行」两个函数，条目被重复解析 2–3 遍。
func scanThreatTextEntries(vals []string) threatTextScan {
	scan := threatTextScan{kept: make([]string, 0, len(vals)), total: len(vals)}
	for _, v := range vals {
		threatTextScanRunsForTest.Add(1)
		if _, err := wafiplist.ParseIPEntry(v); err != nil {
			continue
		}
		scan.parsed++
		scan.kept = append(scan.kept, v)
	}
	return scan
}

// ratio 可解析率比值（0..1；空文本为 0）——与下载解析的 threatMinParseRatio
// 同一判据。
func (s threatTextScan) ratio() float64 {
	if s.total == 0 {
		return 0
	}
	return float64(s.parsed) / float64(s.total)
}

// discarded 被剔除的不可解析行数。
func (s threatTextScan) discarded() int { return s.total - s.parsed }

// logDiscarded 坏行剔除留痕（剔除=渲染集静默缩水，必须可见）。
func (s threatTextScan) logDiscarded(path string) {
	if dropped := s.discarded(); dropped > 0 {
		Logf("warn", "威胁名单 %s 有 %d/%d 行不可解析，已从渲染集剔除（与下载解析同口径）", path, dropped, s.total)
	}
}

// readThreatIplistPath 按代际读取威胁名单文件：文本与
// .fast 同时存在时以 mtime 较新者为准——从节点只同步 .fast（零编译裁定），
// 降级前遗留的文本可能是旧代；旧「文本优先」会让集群新同步的 .fast 被陈旧
// 文本静默遮蔽（新威胁漏拦/已移除误拦）。同代（mtime 相等）保持文本优先
// （两侧内容等价，文本形态更易读）。
//
// 代际方向的事实依据（**禁止调整写侧 rename 顺序**）：主节点写相位是
// 先 replace `.fast`、后 replace 文本（threatupdate.go 的
// writeThreatIplistCompiled），rename 不改 mtime——稳态下 live `.fast` 的
// mtime 恒不早于文本，故主节点实际读 `.fast`。若把顺序改回「先文本后 fast」
// （与早前注释描述相反），陈旧文本会恒定更新而遮蔽新 fast，正是本判据当初要
// 消灭的缺陷形态。
// 本判据真正覆盖的形态：从节点遗留的旧文本 / 带外 touch 文本 / `.fast` 缺失
// （此时文本代际更可靠）。
// 两个文件都缺失返回文本侧错误（os.ErrNotExist 语义由调用方判定）。
// .fast 较新但损坏/不可读时回退文本（在场时）
// 并告警——旧实现直接失败，引用名单的 ACL/信任策略被渲染层整体跳过
// （安全面静默缺失），且更新器哈希快路径按 stat 判定永不修复。
func readThreatIplistPath(iplistPath string) ([]string, error) {
	textInfo, textErr := os.Stat(iplistPath)
	fastPath := wafiplist.FastPath(iplistPath)
	fastInfo, fastErr := os.Stat(fastPath)
	readText := func() ([]string, error) {
		raw, err := os.ReadFile(iplistPath)
		if err != nil {
			return nil, err
		}
		// 行过滤口径单源 iterIPListTextLines（渲染/UI/编译/下载四处
		// 同口径：空行与 #/; 注释跳过）。
		vals := make([]string, 0, 1024)
		iterIPListTextLines(raw, func(line string) bool {
			vals = append(vals, line)
			return true
		})
		return vals, nil
	}
	readFast := func() ([]string, error) { return expandThreatFastEntries(fastPath) }
	// 文本损坏（低可解析率/空文本）但 .fast 完好的单向自愈缺口——
	// 旧实现无条件信任文本代际，损坏文本被整段渲染，.fast 正确条目反被遮蔽，
	// 拦截面静默缩水且无任何留痕。文本解析率不达标时改用 .fast（下轮威胁库
	// 更新会重写文本，构成反向自愈）。
	// 两者都不可用（文本损坏 + .fast 缺失/不可读）时必须按读取失败上报：
	// 此前「按文本装载」会让引用名单静默变成垃圾/空集——deny 方向失去拦截、
	// allow 方向（否定算子+交集）全拒，且只有一条 warn 可见。按失败上报后
	// 走既有严格模式（引用策略 IPRefMissing 跳过渲染 + 审计）与 UI 侧
	// fail-visible，与「自定义名单畸形条目」同一口径。
	useText := !threatIplistPreferFast(textInfo, textErr, fastInfo, fastErr)
	if useText {
		vals, err := readText()
		if err != nil {
			return nil, err
		}
		// 单遍扫描：可解析率门与坏行剔除共用同一份结果（旧实现同一份 vals
		// 被解析 2–3 遍）。
		scan := scanThreatTextEntries(vals)
		if scan.ratio() >= threatMinParseRatio {
			scan.logDiscarded(iplistPath)
			return scan.kept, nil
		}
		if fastErr == nil {
			fastVals, fastReadErr := readFast()
			if fastReadErr == nil {
				Logf("warn", "威胁名单 %s 文本可解析率 %d/%d 低于 %.0f%%（疑似损坏），改用 .fast",
					iplistPath, scan.parsed, scan.total, threatMinParseRatio*100)
				return fastVals, nil
			}
			Logf("error", "威胁名单 %s 文本可解析率 %d/%d 低于 %.0f%% 且 .fast 不可读（引用策略将跳过渲染）: %v",
				iplistPath, scan.parsed, scan.total, threatMinParseRatio*100, fastReadErr)
			return nil, fmt.Errorf("威胁名单 %s 文本可解析率 %d/%d 低于 %.0f%% 且 .fast 不可读: %w",
				iplistPath, scan.parsed, scan.total, threatMinParseRatio*100, fastReadErr)
		}
		Logf("error", "威胁名单 %s 文本可解析率 %d/%d 低于 %.0f%% 且无 .fast 可回退（引用策略将跳过渲染，等待下次威胁库更新重建）",
			iplistPath, scan.parsed, scan.total, threatMinParseRatio*100)
		return nil, fmt.Errorf("威胁名单 %s 文本可解析率 %d/%d 低于 %.0f%% 且无 .fast 可回退（等待下次威胁库更新重建）",
			iplistPath, scan.parsed, scan.total, threatMinParseRatio*100)
	}
	if fastErr == nil {
		vals, err := readFast()
		if err == nil {
			return vals, nil
		}
		// .fast 较新但损坏：文本在场时回退文本（告警留痕）；无文本才报错。
		// 回退同样受可解析率门约束——文本也损坏时两个代际都不可用，按读取失败
		// 上报（否则垃圾/空文本被当成生效名单）。
		if textErr == nil {
			textVals, textReadErr := readText()
			if textReadErr != nil {
				return nil, textReadErr
			}
			textScan := scanThreatTextEntries(textVals)
			if textScan.ratio() >= threatMinParseRatio {
				Logf("warn", "威胁名单 %s 的 .fast 读取失败（回退 .iplist 文本）: %v", fastPath, err)
				textScan.logDiscarded(iplistPath)
				return textScan.kept, nil
			}
			Logf("error", "威胁名单 %s 的 .fast 读取失败且文本可解析率 %d/%d 低于 %.0f%%（引用策略将跳过渲染）: %v",
				iplistPath, textScan.parsed, textScan.total, threatMinParseRatio*100, err)
			return nil, fmt.Errorf("威胁名单 %s 的 .fast 不可读且文本可解析率 %d/%d 低于 %.0f%%: %w",
				iplistPath, textScan.parsed, textScan.total, threatMinParseRatio*100, err)
		}
		return nil, err
	}
	if textErr != nil {
		return nil, textErr
	}
	// 当前判据下不可达（textErr==nil 且 fastErr!=nil 时 useText 恒 true，已被
	// 上方分支覆盖）。保留 fail-visible 返回而非删除死代码：将来判据改写引入
	// 未覆盖组合时，错误上抛（引用策略按装载失败跳过渲染）而不是静默返回
	// fastErr（可能为 nil 的旧形态）。
	return nil, fmt.Errorf("威胁名单 %s 的代际选择未覆盖组合（textErr=%v fastErr=%v）", iplistPath, textErr, fastErr)
}

// threatIplistPreferFast 报告是否应优先使用 .fast 代际（判据单源：文本缺失
// 或 .fast 比文本更新）。readThreatIplistPath 的 useText 取本函数反值。
func threatIplistPreferFast(textInfo os.FileInfo, textErr error, fastInfo os.FileInfo, fastErr error) bool {
	return fastErr == nil && (textErr != nil || fastInfo.ModTime().After(textInfo.ModTime()))
}

// threatIplistHasEntries 只判定威胁名单是否有生效条目（摘要/列表路径）：
// .fast 可优先时只取头部规模（ReadFastFile 后取 len(V4)+len(V6)>0），不再把
// 整份前缀集展开成 []string（威胁上限 20 万条时省一次 MB 级分配）；.fast
// 缺失/损坏/更旧时回退完整读取（含文本可解析率门），失败判定与渲染同源。
func threatIplistHasEntries(iplistPath string) (bool, error) {
	textInfo, textErr := os.Stat(iplistPath)
	fastPath := wafiplist.FastPath(iplistPath)
	fastInfo, fastErr := os.Stat(fastPath)
	if threatIplistPreferFast(textInfo, textErr, fastInfo, fastErr) {
		if set, err := wafiplist.ReadFastFile(fastPath); err == nil {
			return len(set.V4)+len(set.V6) > 0, nil
		}
		// .fast 损坏：回退完整读取路径（文本回退 + 可解析率门 + 失败上报）。
	}
	vals, err := readThreatIplistPath(iplistPath)
	if err != nil {
		return false, err
	}
	return len(vals) > 0, nil
}

// expandThreatFastEntries 展开 .fast 前缀集（已聚合排序，match-set 等价）。
func expandThreatFastEntries(fastPath string) ([]string, error) {
	set, err := wafiplist.ReadFastFile(fastPath)
	if err != nil {
		return nil, err
	}
	vals := make([]string, 0, len(set.V4)+len(set.V6))
	for _, p := range set.V4 {
		vals = append(vals, p.String())
	}
	for _, p := range set.V6 {
		vals = append(vals, p.String())
	}
	return vals, nil
}

// readThreatIplistEntries 按列表名读威胁名单条目（渲染层消费）。
// 文件路径: /app/waf/threat-{source_name}.iplist
func readThreatIplistEntries(listName string) ([]string, error) {
	source := threatSourceByListName(listName)
	if source == "" {
		return nil, fmt.Errorf("列表 %q 不映射到任何威胁源", listName)
	}
	iplistPath := filepath.Join(wafDir, fmt.Sprintf("threat-%s.iplist", source))
	vals, err := readThreatIplistPath(iplistPath)
	if err != nil {
		// 严格模式由调用方跳过策略：两个文件都不可用时才报错。
		return nil, fmt.Errorf("读取 %s 与其 .fast 均失败: %w", iplistPath, err)
	}
	return vals, nil
}

// threatSourceByListName 列表名 → 威胁源名（反向映射 ThreatListNameBySource）。
func threatSourceByListName(listName string) string {
	for _, sl := range db.ThreatSystemLists() {
		if sl.Name == listName {
			return sl.Source
		}
	}
	return ""
}

// IsThreatSystemListName 报告列表名是否登记为威胁情报系统名单。
func IsThreatSystemListName(listName string) bool {
	return threatSourceByListName(listName) != ""
}

// LoadIPListEntriesByID 以一次查询批量加载 IP 地址列表条目值（仅 value）。
// ids 为空或数据库未初始化时返回空映射；缺失的 id 不出现在结果中。
// loadIPListEntriesVia：唯一装载实现（渲染与严格校验统一走 Via 错误通道），
// 本函数只是 store=db.DB 的薄包装。
func LoadIPListEntriesByID(ids []int64) (map[int64][]string, error) {
	if len(ids) == 0 || db.DB == nil {
		return map[int64][]string{}, nil
	}
	// db 分支错误上抛(对齐 store 分支契约)
	// ——委托 loadIPListEntriesVia(分块+错误通道),不再吞错返回恒 nil error。
	entries, _, err := loadIPListEntriesVia(db.DB, ids)
	return entries, err
}

// danglingIPListRefs 返回既未装载成功也未标记失败的引用 id（列表已删除或导入残留）。
func danglingIPListRefs(p *models.SecurityPolicy, listsByID map[int64][]string, failedIDs map[int64]bool) []int64 {
	if p == nil {
		return nil
	}
	seen := make(map[int64]struct{})
	var dangling []int64
	for _, raw := range []string{p.IPACLListRefs, p.IPWhitelistRefs} {
		for _, id := range parseIPListRefs(raw) {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			if _, loaded := listsByID[id]; !loaded && !failedIDs[id] {
				dangling = append(dangling, id)
			}
		}
	}
	return dangling
}

// ResolvePolicyIPListRefsForSummary 供摘要/列表路径批量解析引用 IP 名单。
// 摘要只需要「引用的名单是否有生效条目」这一判定（SecurityPolicyHasIPControl
// 与发射面同式），不需要合并集内容——列表端点按秒级轮询，全量装载最坏
// 64 refs × 2000 条目/请求（每秒 MB 级 JSON 解析 + 主库读）纯属浪费。
// 因此走 loadIPListRefPresenceVia：只回引用名单的生效条目存在性（自定义名单
// 解析 entries 后按未到期过滤，威胁库文件型名单仍读文件——失败判定与渲染
// 一致）。
// 语义与渲染路径对齐：装载失败（威胁库文件缺失/自定义 entries 畸形）→
// IPRefMissing（摘要不得在策略会被跳过渲染时宣称已启用 IP 控制）；列表已
// 删除 → 仅日志 warn（合并集退化 inline-only，与渲染同向）。
// 读路径只写日志、不写审计——「渲染跳过」审计归渲染路径（读端点带写副作用
// 会污染审计追溯）。
func ResolvePolicyIPListRefsForSummary(policies []*models.SecurityPolicy) {
	if db.DB == nil {
		return
	}
	seen := make(map[int64]struct{})
	var ids []int64
	collect := func(raw string) {
		// 畸形 refs 按空集处理（与渲染路径同解析语义；渲染侧的限流留痕由
		// parseIPListRefsLogged 承担，摘要不重复刷屏）。
		for _, id := range parseIPListRefs(raw) {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	for _, p := range policies {
		if p == nil {
			continue
		}
		collect(p.IPACLListRefs)
		collect(p.IPWhitelistRefs)
	}
	if len(ids) == 0 {
		return
	}
	presence, failed := loadIPListRefPresenceVia(db.DB, ids)
	for _, p := range policies {
		if p == nil {
			continue
		}
		aclIDs := parseIPListRefs(p.IPACLListRefs)
		wlIDs := parseIPListRefs(p.IPWhitelistRefs)
		// 严格模式失败判定：与渲染同序（ACL 优先），首命中即置位并留痕。
		markFailed := func(id int64) {
			p.IPRefMissing = true
			msg := fmt.Sprintf("策略 %q 引用的 IP 列表(id=%d)装载失败", p.Name, id)
			if auditFailureShouldLog(msg) {
				Logf("error", "%s——该策略将被跳过渲染", msg)
			}
		}
		for _, id := range aclIDs {
			if failed[id] {
				markFailed(id)
				break
			}
		}
		if !p.IPRefMissing {
			for _, id := range wlIDs {
				if failed[id] {
					markFailed(id)
					break
				}
			}
		}
		if p.IPRefMissing {
			continue
		}
		for _, id := range wlIDs {
			if presence[id] {
				p.IPWhitelistRefsNonEmpty = true
				break
			}
		}
		for _, id := range append(append([]int64{}, aclIDs...), wlIDs...) {
			if _, exists := presence[id]; exists || failed[id] {
				continue
			}
			msg := fmt.Sprintf("策略 %q 引用的 IP 列表(id=%d)不存在（列表已删除或导入残留），仅保留 inline 条目", p.Name, id)
			if auditFailureShouldLog(msg) {
				Logf("warn", "%s", msg)
			}
		}
	}
}

// loadIPListRefPresenceVia 是摘要路径的轻量装载：只判定「引用名单是否有生效
// 条目」与「装载是否失败」，不构造合并集。
// 失败判定与 loadIPListEntriesVia 同语义：威胁库（system=1 且名字映射到威胁
// 源）读 .iplist/.fast 文件，读取失败即失败；自定义名单 entries 畸形（非 JSON
// 数组）即失败；查询/迭代失败按 chunk 全失败处理。
// 条数口径：与渲染生效面同源——解析 entries 后只数「值非空且未到期」的条目
// （autobanEntryExpired 单一判据）。按原始条数判定会让「引用名单的条目全部
// 到期」时摘要宣称 IP 控制生效，而渲染合并集为空（摘要与发射面不同判定）。
func loadIPListRefPresenceVia(store caddyConfigStore, ids []int64) (map[int64]bool, map[int64]bool) {
	presence := make(map[int64]bool, len(ids))
	failed := make(map[int64]bool)
	failures := forEachIPListChunk(store, ids, "id, COALESCE(system,0), COALESCE(name,''), COALESCE(entries,'[]')", func(rows *sql.Rows) {
		for rows.Next() {
			var id int64
			var system int
			var name, raw string
			if err := rows.Scan(&id, &system, &name, &raw); err != nil {
				Logf("warn", "摘要: security_ip_lists 行扫描失败（该行丢弃）: %v", err)
				failed[id] = true
				continue
			}
			if system == 1 && threatSourceByListName(name) != "" {
				// 只判存在性（不构造整份 []string）：摘要/列表按秒级轮询，
				// 全量展开最坏 3 × 20 万条前缀集纯属浪费。
				has, ferr := threatIplistHasEntries(filepath.Join(wafDir, fmt.Sprintf("threat-%s.iplist", threatSourceByListName(name))))
				if ferr != nil {
					Logf("error", "摘要: 威胁库 %q 文件读取失败: %v（严格模式：引用该列表的策略按装载失败处理）", name, ferr)
					failed[id] = true
					continue
				}
				presence[id] = has
				continue
			}
			list, perr := parseIPListEntriesStrict(raw)
			if perr != nil {
				Logf("error", "摘要: 自定义 IP 列表(id=%d) entries 畸形（引用策略按装载失败处理）: %v", id, perr)
				failed[id] = true
				continue
			}
			// 与渲染同源：值非空且未到期的条目才构成发射面。
			now := autobanNow()
			effective := 0
			for _, e := range list {
				if strings.TrimSpace(e.Value) == "" || autobanEntryExpired(e, now) {
					continue
				}
				effective++
			}
			presence[id] = effective > 0
		}
	})
	for _, f := range failures {
		Logf("error", "摘要: security_ip_lists 分批存在性查询失败（本块 %d 个列表按装载失败处理）: %v", len(f.ids), f.cause)
		for _, id := range f.ids {
			failed[id] = true
		}
	}
	return presence, failed
}

// resolvePolicyIPListRefs 在策略加载路径上完成引用解析：跨整个已加载批次收集
// 引用的列表 id（去重），仅当存在引用时执行恰好一次批量查询，再把每条策略的
// 合并集（inline ∪ 引用条目）附加到 MergedACLList / MergedWhitelist。
// store 与策略预载同源：v2 导入事务内重插的 security_ip_lists
// 行只有 tx 视角可见，走 db.DB 会让引用条目在渲染期静默丢失；store=nil 回退
// db.DB（非批量路径）。批次内无任何引用时零查询（性能预算：每次生成至多
// 一次额外查询，与引用数无关）。
func resolvePolicyIPListRefs(policies []*models.SecurityPolicy, store caddyConfigStore) {
	var refIDs []int64
	seen := make(map[int64]struct{})
	for _, p := range policies {
		if p == nil {
			continue
		}
		// 渲染解析路径（本循环覆盖每条策略两个 refs 列各一次）对
		// 畸形非空 refs 留痕——空/空白不告警（未配置引用）。
		for _, id := range parseIPListRefsLogged(p.ID, "ip_acl_list_refs", p.IPACLListRefs) {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			refIDs = append(refIDs, id)
		}
		for _, id := range parseIPListRefsLogged(p.ID, "ip_whitelist_refs", p.IPWhitelistRefs) {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			refIDs = append(refIDs, id)
		}
	}
	// 无引用形态（绝大多数策略）：不再早退——inline 合并集同样在此一次展开并
	// 附加（幂等：expandPolicyIPRefs 在空 listsByID 下与 mergedWhitelist 的
	// inline-only 回退逐字等价）。此前早退让 MergedACLList/MergedWhitelist
	// 恒为 nil，发射端每次调用 mergedWhitelist 都重跑 json.Unmarshal +
	// aggregateIPEntries——摄取侧按「规则×策略」逐次调用，万条级名单的聚合
	// 成本随事件吞吐线性放大。
	var listsByID map[int64][]string
	var failedIDs map[int64]bool
	// 仅「确实有引用」时才定义：failedIDs 为空映射时循环内的失败分支不可达。
	var markLoadFailure func(p *models.SecurityPolicy, id int64)
	if len(refIDs) > 0 {
		effective := store
		if effective == nil {
			effective = db.DB
		}
		if effective == nil {
			return
		}
		var loadErr error
		listsByID, failedIDs, loadErr = loadIPListEntriesVia(effective, refIDs)
		markLoadFailure = func(p *models.SecurityPolicy, id int64) {
			refErr := fmt.Sprintf("策略 %q 引用的 IP 列表(id=%d)装载失败", p.Name, id)
			if loadErr != nil {
				refErr += fmt.Sprintf(": %v", loadErr)
			}
			if auditFailureShouldLog(refErr) {
				Logf("error", "%s——该策略将被跳过渲染", refErr)
				RecordAuditLog("system", "渲染跳过", "安全策略", refErr+"，已跳过该策略渲染", "")
			}
		}
	}
	// 展开结果按「四条来源列完全相同」在本次调用内
	// 去重。多策略引用同一大名单（常见形态）时，per-policy aggregateIPEntries
	// （20 万条 ≈ 19ms）只做一次；单一策略形态零行为差异。键只含策略来源列
	// （纯函数输入，本次调用内 listsByID 固定），故不存在跨 tick 陈旧风险，
	// 也无内存常驻（随调用生命周期回收）。
	expandMemo := make(map[string]policyIPRefExpansion, len(policies))
	for _, p := range policies {
		if p == nil {
			continue
		}
		for _, id := range danglingIPListRefs(p, listsByID, failedIDs) {
			msg := fmt.Sprintf("策略 %q 引用的 IP 列表(id=%d)不存在（列表已删除或导入残留），仅保留 inline 条目", p.Name, id)
			if auditFailureShouldLog(msg) {
				Logf("warn", "%s", msg)
			}
		}
		// RDB 严格模式：策略引用的任一列表装载失败（威胁库 .iplist 缺失或
		// 自定义 entries 畸形）→ 标记跳过渲染，绝不以空集静默收窄 ACL 保护面。
		// 同一 policy+list+错误文本按 auditFailureShouldLog 限流。
		for _, id := range parseIPListRefs(p.IPACLListRefs) {
			if failedIDs[id] {
				p.IPRefMissing = true
				markLoadFailure(p, id)
				break
			}
		}
		if !p.IPRefMissing {
			for _, id := range parseIPListRefs(p.IPWhitelistRefs) {
				if failedIDs[id] {
					p.IPRefMissing = true
					markLoadFailure(p, id)
					break
				}
			}
		}
		if p.IPRefMissing {
			continue
		}
		key := strings.Join([]string{p.IPACLList, p.IPACLListRefs, string(p.IPWhitelist), p.IPWhitelistRefs}, "\x00")
		exp, cached := expandMemo[key]
		if cached {
			// 命中时不再付聚合成本，但仍按本策略留痕内联畸形（expand 里的
			// 同一消息在限流窗口内会被抑制）。
			logMalformedInlineIPLists(p)
		} else {
			exp = expandPolicyIPRefs(p, listsByID)
			expandMemo[key] = exp
		}
		p.MergedACLList = exp.ACLList
		p.MergedWhitelist = exp.Whitelist
	}
}

// mergedACLList 返回策略生效的 ACL 条目集：加载路径已附加合并集时直接使用，
// 否则（未解析/直接构造的策略）回退 inline-only——保证既有调用与测试不变。
// v2.3.x：返回处统一过 CIDR 聚合（去重/兄弟归并/覆盖剔除，匹配集合不变）——
// 发射面（@ipListFast 文件与残留内联）共享同一规范形态。
func mergedACLList(p *models.SecurityPolicy) []string {
	if p.MergedACLList != nil {
		return p.MergedACLList // 扩展开期已聚合（见 expandPolicyIPRefs），直接返回
	}
	var list []string
	if err := json.Unmarshal([]byte(p.IPACLList), &list); err != nil {
		logMalformedInlineIPList(p.ID, "ip_acl_list", err)
	}
	return aggregateIPEntries(list)
}

// mergedWhitelist 同 mergedACLList，作用于信任名单（ip_whitelist）。
func mergedWhitelist(p *models.SecurityPolicy) []string {
	if p.MergedWhitelist != nil {
		return p.MergedWhitelist // 同上：扩开期已聚合
	}
	var list []string
	if err := json.Unmarshal(p.IPWhitelist, &list); err != nil {
		logMalformedInlineIPList(p.ID, "ip_whitelist", err)
	}
	return aggregateIPEntries(list)
}

// ReadThreatIplistForUI 供 UI 预览调用：按列表名读威胁名单条目。
// 文件不存在返回空集（禁用/未更新源）。与渲染侧 readThreatIplistEntries 共用
// readThreatIplistPath（代际感知：新同步的.fast 不被陈旧文本遮蔽）。
func ReadThreatIplistForUI(listName string) ([]string, error) {
	source := threatSourceByListName(listName)
	if source == "" {
		return nil, nil // 非威胁库列表——调用方处理
	}
	path := filepath.Join(wafDir, "threat-"+source+".iplist")
	vals, err := readThreatIplistPath(path)
	if err != nil {
		if os.IsNotExist(err) {
			// 从节点 waf_files 只同步.fast——两个文件都
			// 缺失才视为「未更新源」空集。
			return nil, nil
		}
		return nil, err
	}
	return vals, nil
}

// ReadThreatIplistBySource 按源名读威胁名单内容（导出用）。
// 与渲染/UI 共用代际感知读取——从节点文本可能是旧代，导出必须与
// 执行面一致（.fast 较新时展开为文本行）。两文件都缺失返回 nil。
func ReadThreatIplistBySource(source string) ([]byte, error) {
	if source == "" {
		return nil, nil
	}
	vals, err := readThreatIplistPath(filepath.Join(wafDir, "threat-"+source+".iplist"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if len(vals) == 0 {
		return nil, nil
	}
	return []byte(strings.Join(vals, "\n") + "\n"), nil
}
