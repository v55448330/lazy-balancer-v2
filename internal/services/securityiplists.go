package services

import (
	"encoding/json"
	"fmt"
	"lazy-balancer-v2/wafiplist"
	"os"
	"path/filepath"
	"strings"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
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
// parseIPListRefs 与 handlers.parseIPListRefsIDs 为镜像实现（第 54 轮 P5-4
// 裁定保留双份并声明）：本侧投影路径去重保序，handlers 侧校验路径不去重
// ——语义有意分叉，勿单方面合并。
func parseIPListRefs(raw string) []int64 {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var ids []int64
	if err := json.Unmarshal([]byte(raw), &ids); err != nil {
		return nil
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
	return out
}

// ipListRefsNonEmpty 报告 refs JSON 是否解析出至少一个条目（畸形视为空）。
// SecurityPolicyHasIPControl 用它在无需加载数据库的情况下判定「仅引用」策略。
func ipListRefsNonEmpty(raw string) bool {
	return len(parseIPListRefs(raw)) > 0
}

// expandPolicyIPRefs 把策略的 inline IP 条目与引用的 IP 列表条目合并为生效集：
// inline 条目优先，其后按 refs 出现顺序追加各列表条目；跨来源逐值去重；
// listsByID 缺失的 id 与内嵌 null 值跳过。纯函数，不触碰数据库。
func expandPolicyIPRefs(p *models.SecurityPolicy, listsByID map[int64][]string) policyIPRefExpansion {
	var exp policyIPRefExpansion
	if p == nil {
		return exp
	}
	merge := func(inlineRaw string, refsRaw string) []string {
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
		json.Unmarshal([]byte(inlineRaw), &inline)
		addAll(inline)
		for _, id := range parseIPListRefs(refsRaw) {
			addAll(listsByID[id])
		}
		return merged
	}
	// 合并即聚合（第 57 轮 P5 修复，用户上报「规则越多保存越慢」根因）：
	// 发射端 mergedACLList/mergedWhitelist 按规则×策略逐次调用，若在此处不
	// 聚合，万条级合并集（如 USTC 11415 条）会被每次调用全量重聚合——保存
	// 耗时随绑定规则数线性放大。聚合幂等，此处一次完成后发射端直接返回。
	exp.ACLList = aggregateIPEntries(merge(p.IPACLList, p.IPACLListRefs))
	exp.Whitelist = aggregateIPEntries(merge(string(p.IPWhitelist), p.IPWhitelistRefs))
	return exp
}

// loadIPListEntries 在给定 store 上以一次（或分块）查询取回 id → 条目值列表
// 映射：只解析 entries 的 value，remark 不参与生成；行缺失（悬空引用）与
// entries 畸形行跳过——与自定义规则悬空引用仅留痕口径一致。
// loadIPListEntries 与 loadIPListEntriesVia 是有意双实现(F64-P5 声明):
// 前者供降级路径(渲染容忍缺失列表),后者供严格校验(refs 必须全部存在)。
// 错误通道语义不同是设计意图,非冗余——合并需逐调用方审计错误处理链。
func loadIPListEntries(store caddyConfigStore, ids []int64) map[int64][]string {
	if len(ids) == 0 || store == nil {
		return nil
	}
	listsByID := make(map[int64][]string, len(ids))
	for start := 0; start < len(ids); start += ipListChunkSize {
		end := start + ipListChunkSize
		if end > len(ids) {
			end = len(ids)
		}
		chunk := ids[start:end]
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")
		args := make([]interface{}, len(chunk))
		for i, id := range chunk {
			args[i] = id
		}
		rows, err := store.Query("SELECT id, COALESCE(entries,'[]') FROM security_ip_lists WHERE id IN ("+placeholders+")", args...)
		if err != nil {
			Logf("warn", "加载 IP 地址列表分块查询失败（id 段 %d-%d）: %v", chunk[0], chunk[len(chunk)-1], err)
			continue
		}
		for rows.Next() {
			var id int64
			var entriesJSON string
			if err := rows.Scan(&id, &entriesJSON); err != nil {
				continue
			}
			var entries []models.IPListEntry
			if err := json.Unmarshal([]byte(entriesJSON), &entries); err != nil {
				continue
			}
			values := make([]string, 0, len(entries))
			for _, entry := range entries {
				if entry.Value != "" {
					values = append(values, entry.Value)
				}
			}
			listsByID[id] = values
		}
		rows.Close()
	}
	return listsByID
}

// LoadIPListEntriesByID 以一次查询批量加载 IP 地址列表条目值（仅 value）。
// ids 为空或数据库未初始化时返回空映射；缺失的 id 不出现在结果中。
// loadIPListEntriesVia：store 感知装载（审计 U1-F3）——store 非-nil（v2 导入
// 事务视图）经其查询，nil 回退 db.DB。镜像 resolvePolicyIPListRefs 的回退逻辑。
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
		rows, err := store.Query("SELECT id, COALESCE(entries,'[]'), COALESCE(system,0), COALESCE(name,'') FROM security_ip_lists WHERE id IN ("+placeholders+")", args...)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("store 查询 security_ip_lists: %w", err)
			}
			for _, id := range chunk {
				failed[id] = true
			}
			continue
		}
		for rows.Next() {
			var id int64
			var raw string
			var system int
			var name string
			if err := rows.Scan(&id, &raw, &system, &name); err != nil {
				continue
			}
			if system == 1 {
				// 威胁库：读 .iplist 文件（RDB 源文件）
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
				// 自定义列表：读 DB entries JSON
				var list []models.IPListEntry
				if err := json.Unmarshal([]byte(raw), &list); err != nil {
					continue
				}
				vals := make([]string, 0, len(list))
				for _, e := range list {
					if v := strings.TrimSpace(e.Value); v != "" {
						vals = append(vals, v)
					}
				}
				entries[id] = vals
			}
		}
		rows.Close()
	}
	if firstErr != nil {
		return entries, failed, firstErr
	}
	return entries, failed, nil
}

// readThreatIplistEntries 按列表名读 .iplist 文件条目（渲染层消费）。
// 文件路径: /app/waf/threat-{source_name}.iplist
func readThreatIplistEntries(listName string) ([]string, error) {
	source := threatSourceByListName(listName)
	if source == "" {
		return nil, fmt.Errorf("列表 %q 不映射到任何威胁源", listName)
	}
	iplistPath := filepath.Join(wafDir, fmt.Sprintf("threat-%s.iplist", source))
	if raw, err := os.ReadFile(iplistPath); err == nil {
		// 主节点/备份导入路径：文本源文件在场，逐行解析
		var vals []string
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			vals = append(vals, line)
		}
		return vals, nil
	}
	// 从节点路径：waf_files 通道只同步 .fast 二进制（零编译裁定）——文本
	// 缺失时展开 .fast 前缀集（已聚合排序，match-set 等价）。两个文件都
	// 缺失才报错（严格模式由调用方跳过策略）。
	fastPath := wafiplist.FastPath(iplistPath)
	set, err := wafiplist.ReadFastFile(fastPath)
	if err != nil {
		return nil, fmt.Errorf("读取 %s 与 %s 均失败: %w", iplistPath, fastPath, err)
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

// threatSourceByListName 列表名 → 威胁源名（反向映射 ThreatListNameBySource）。
func threatSourceByListName(listName string) string {
	for _, sl := range db.ThreatSystemLists {
		if sl.Name == listName {
			return sl.Source
		}
	}
	return ""
}

func LoadIPListEntriesByID(ids []int64) (map[int64][]string, error) {
	if len(ids) == 0 || db.DB == nil {
		return map[int64][]string{}, nil
	}
	// SLB12-P3-6(第 12 轮审计):db 分支错误上抛(对齐 store 分支 V3-S1 契约)
	// ——委托 loadIPListEntriesVia(分块+错误通道),不再吞错返回恒 nil error。
	entries, _, err := loadIPListEntriesVia(db.DB, ids)
	return entries, err
}

// resolvePolicyIPListRefs 在策略加载路径上完成引用解析：跨整个已加载批次收集
// 引用的列表 id（去重），仅当存在引用时执行恰好一次批量查询，再把每条策略的
// 合并集（inline ∪ 引用条目）附加到 MergedACLList / MergedWhitelist。
// store 与策略预载同源（A-I1 同型约束）：v2 导入事务内重插的 security_ip_lists
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
		for _, id := range parseIPListRefs(p.IPACLListRefs) {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			refIDs = append(refIDs, id)
		}
		for _, id := range parseIPListRefs(p.IPWhitelistRefs) {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			refIDs = append(refIDs, id)
		}
	}
	if len(refIDs) == 0 {
		return
	}
	effective := store
	if effective == nil {
		effective = db.DB
	}
	if effective == nil {
		return
	}
	listsByID, failedIDs, err := loadIPListEntriesVia(effective, refIDs)
	if len(listsByID) == 0 && len(failedIDs) == 0 {
		return
	}
	for _, p := range policies {
		if p == nil {
			continue
		}
		// RDB 严格模式：策略引用的任一列表装载失败（威胁库 .iplist 缺失）→
		// 标记跳过渲染，绝不以空集静默收窄 ACL 保护面。
		for _, id := range parseIPListRefs(p.IPACLListRefs) {
			if failedIDs[id] {
				p.IPRefMissing = true
				Logf("error", "策略 %q 引用的威胁库列表(id=%d)装载失败——该策略将被跳过渲染", p.Name, id)
				RecordAuditLog("system", "渲染跳过", "安全策略", fmt.Sprintf("策略 %q 引用的威胁库列表(id=%d)装载失败，已跳过该策略渲染: %v", p.Name, id, err), "")
				break
			}
		}
		if !p.IPRefMissing {
			for _, id := range parseIPListRefs(p.IPWhitelistRefs) {
				if failedIDs[id] {
					p.IPRefMissing = true
					Logf("error", "策略 %q 引用的威胁库列表(id=%d)装载失败——该策略将被跳过渲染", p.Name, id)
					RecordAuditLog("system", "渲染跳过", "安全策略", fmt.Sprintf("策略 %q 引用的威胁库列表(id=%d)装载失败，已跳过该策略渲染: %v", p.Name, id, err), "")
					break
				}
			}
		}
		if p.IPRefMissing {
			continue
		}
		exp := expandPolicyIPRefs(p, listsByID)
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
	json.Unmarshal([]byte(p.IPACLList), &list)
	return aggregateIPEntries(list)
}

// mergedWhitelist 同 mergedACLList，作用于信任名单（ip_whitelist）。
func mergedWhitelist(p *models.SecurityPolicy) []string {
	if p.MergedWhitelist != nil {
		return p.MergedWhitelist // 同上：扩开期已聚合
	}
	var list []string
	json.Unmarshal(p.IPWhitelist, &list)
	return aggregateIPEntries(list)
}

// ReadThreatIplistForUI 供 UI 预览调用：按列表名读 .iplist 文件条目。
// 文件不存在返回空集（禁用/未更新源）。
func ReadThreatIplistForUI(listName string) ([]string, error) {
	source := threatSourceByListName(listName)
	if source == "" {
		return nil, nil // 非威胁库列表——调用方处理
	}
	path := filepath.Join(wafDir, "threat-"+source+".iplist")
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// SEC-U2（第 69 轮）：从节点 waf_files 只同步 .fast（零编译裁定）——
			// .iplist 缺失时展开 .fast 前缀集，与渲染侧 readThreatIplistEntries
			// 同口径；两个文件都缺失才返回空集（未更新源）。
			fastPath := wafiplist.FastPath(path)
			set, ferr := wafiplist.ReadFastFile(fastPath)
			if ferr != nil {
				return nil, nil
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
		return nil, err
	}
	var vals []string
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			vals = append(vals, line)
		}
	}
	return vals, nil
}

// ReadThreatIplistBySource 按源名读 .iplist 原始内容（导出用）。
func ReadThreatIplistBySource(source string) []byte {
	if source == "" {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(wafDir, "threat-"+source+".iplist"))
	if err != nil {
		return nil
	}
	return data
}
