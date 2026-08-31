package services

import (
	"encoding/json"
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
	exp.ACLList = merge(p.IPACLList, p.IPACLListRefs)
	exp.Whitelist = merge(string(p.IPWhitelist), p.IPWhitelistRefs)
	return exp
}

// loadIPListEntries 在给定 store 上以一次（或分块）查询取回 id → 条目值列表
// 映射：只解析 entries 的 value，remark 不参与生成；行缺失（悬空引用）与
// entries 畸形行跳过——与自定义规则悬空引用仅留痕口径一致。
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
func LoadIPListEntriesByID(ids []int64) (map[int64][]string, error) {
	if len(ids) == 0 {
		return map[int64][]string{}, nil
	}
	if db.DB == nil {
		return map[int64][]string{}, nil
	}
	return loadIPListEntries(db.DB, ids), nil
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
	listsByID := loadIPListEntries(effective, refIDs)
	if len(listsByID) == 0 {
		return
	}
	for _, p := range policies {
		if p == nil {
			continue
		}
		exp := expandPolicyIPRefs(p, listsByID)
		p.MergedACLList = exp.ACLList
		p.MergedWhitelist = exp.Whitelist
	}
}

// mergedACLList 返回策略生效的 ACL 条目集：加载路径已附加合并集时直接使用，
// 否则（未解析/直接构造的策略）回退 inline-only——保证既有调用与测试不变。
func mergedACLList(p *models.SecurityPolicy) []string {
	if p.MergedACLList != nil {
		return p.MergedACLList
	}
	var list []string
	json.Unmarshal([]byte(p.IPACLList), &list)
	return list
}

// mergedWhitelist 同 mergedACLList，作用于信任名单（ip_whitelist）。
func mergedWhitelist(p *models.SecurityPolicy) []string {
	if p.MergedWhitelist != nil {
		return p.MergedWhitelist
	}
	var list []string
	json.Unmarshal(p.IPWhitelist, &list)
	return list
}
