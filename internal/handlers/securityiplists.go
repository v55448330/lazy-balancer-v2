package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"lazy-balancer-v2/internal/services"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"

	"github.com/gin-gonic/gin"
)

const (
	ipListMaxNameLength        = 50
	ipListMaxDescriptionLength = 200
	ipListMaxCategoryLength    = 32
	ipListMaxRemarkLength      = 100
	ipListMaxEntries           = 2000
	ipListMaxGlobalCount       = 200
)

// loadSystemListIDs 一次读取全部 system=1 内置名单的 name→id 映射（威胁库与
// 爬虫库列表共用）。缺行不制造默认值：调用方取 map 未命中得到 0（DTO 保留
// list_id=0）；查询/扫描/迭代故障显式返回 error，由端点 500（残缺列表不得
// 以 200 返回）。
func loadSystemListIDs() (map[string]int, error) {
	rows, err := db.DB.Query(`SELECT name, id FROM security_ip_lists WHERE system=1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := map[string]int{}
	for rows.Next() {
		var name string
		var id int
		if err := rows.Scan(&name, &id); err != nil {
			return nil, err
		}
		ids[name] = id
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ids, nil
}

// parseIPListRefsIDs 宽松解析 refs JSON 为 id 列表：畸形/空 → nil（重启用悬空
// 引用门读取存量值用；存量列恒为写入侧校验过的合法形态，畸形仅见于带外改库）。
// 与 services.parseIPListRefs 为镜像实现（去重语义有意分叉，见 services 侧
// 投影路径）：本侧保原始序列，services 侧去重保序，勿单方面合并。
func parseIPListRefsIDs(raw string) []int64 {
	var ids []int64
	if err := json.Unmarshal([]byte(raw), &ids); err != nil {
		return nil
	}
	return ids
}

// ipListQueryer 是 allow 生效集合校验的查询面（*sql.DB 与 *sql.Tx 共用）。
type ipListQueryer interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

// loadIPListEntriesForAllow 读取引用名单的实际条目（allow 生效集合判定单源）。
func loadIPListEntriesForAllow(q ipListQueryer, ids []int64) (map[int64][]string, error) {
	out := make(map[int64][]string, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	// 去重（同一名单重复引用不放大绑定变量）+ 分块，避免超过 SQLite 变量上限。
	unique := make([]int64, 0, len(ids))
	seen := make(map[int64]struct{}, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	for start := 0; start < len(unique); start += 500 {
		end := start + 500
		if end > len(unique) {
			end = len(unique)
		}
		chunk := unique[start:end]
		placeholders := make([]string, len(chunk))
		args := make([]any, len(chunk))
		for i, id := range chunk {
			placeholders[i] = "?"
			args[i] = id
		}
		rows, err := q.Query("SELECT id, COALESCE(entries,'[]') FROM security_ip_lists WHERE id IN ("+strings.Join(placeholders, ",")+")", args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id int64
			var raw string
			if err := rows.Scan(&id, &raw); err != nil {
				rows.Close()
				return nil, err
			}
			raw = normalizeIPListEntriesJSON(raw)
			var entries []models.IPListEntry
			if err := json.Unmarshal([]byte(raw), &entries); err != nil {
				rows.Close()
				return nil, fmt.Errorf("IP 列表 #%d 条目损坏: %w", id, err)
			}
			// 与渲染投影层共用同一条目到期判据：仅已到期条目的名单不得被当非空。
			entries = services.AutobanActiveEntries(entries)
			values := make([]string, 0, len(entries))
			for _, e := range entries {
				if e.Value != "" {
					values = append(values, e.Value)
				}
			}
			out[id] = values
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	return out, nil
}

// allowEffectiveListNonEmpty 判定 allow 模式的生效集合是否非空：内联条目 ∪
// 全部引用名单的**实际条目**并集（不要求每个引用名单非空）。旧写侧
// 门只看引用个数，引用一个空名单即落库「启用 allow + 空生效集」——发射端
// 现对空交集恒发 deny（fail-closed，锁死全部请求），不再静默跳过 ACL；写侧
// 本门是防「保存即全站 403」的 UX 门，不是防绕过门。查询失败返回错误，
// 调用方按 500 处理（不得按空集合或非空猜测）。
func allowEffectiveListNonEmpty(q ipListQueryer, inlineRaw, refsRaw string) (bool, error) {
	var inline []string
	if strings.TrimSpace(inlineRaw) != "" {
		if err := json.Unmarshal([]byte(inlineRaw), &inline); err != nil {
			return false, fmt.Errorf("内联 IP 列表解析失败: %w", err)
		}
	}
	for _, v := range inline {
		if strings.TrimSpace(v) != "" {
			return true, nil
		}
	}
	refs := parseIPListRefsIDs(refsRaw)
	if len(refs) == 0 {
		return false, nil
	}
	entries, err := loadIPListEntriesForAllow(q, refs)
	if err != nil {
		return false, err
	}
	for _, values := range entries {
		if len(values) > 0 {
			return true, nil
		}
	}
	return false, nil
}

// allowEmptyingBlockedByPolicies 判定「把 listID 清空为 replacement」是否会让
// 任一 allow 策略的生效集合变为空。偏严语义：检查全部
// 启用 allow 策略（含 disabled 策略——与 Create/Update 对禁用策略同样设门的
// 口径一致）。查询失败返回错误（调用方 500，fail-closed）。
func allowEmptyingBlockedByPolicies(q ipListQueryer, listID int64, replacement []string) (bool, error) {
	rows, err := q.Query(`SELECT COALESCE(ip_acl_list,'[]'), COALESCE(ip_acl_list_refs,'[]') FROM security_policies WHERE COALESCE(ip_acl_enabled,0)=1 AND COALESCE(ip_acl_mode,'')='allow'`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	type policyAllowShape struct {
		inline string
		refs   []int64
	}
	var shapes []policyAllowShape
	needIDs := make(map[int64]bool)
	for rows.Next() {
		var inline, refsRaw string
		if err := rows.Scan(&inline, &refsRaw); err != nil {
			return false, err
		}
		refs := parseIPListRefsIDs(refsRaw)
		references := false
		for _, r := range refs {
			if r == listID {
				references = true
			} else {
				needIDs[r] = true
			}
		}
		if references {
			shapes = append(shapes, policyAllowShape{inline: inline, refs: refs})
		}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	if len(shapes) == 0 {
		return false, nil
	}
	ids := make([]int64, 0, len(needIDs))
	for id := range needIDs {
		ids = append(ids, id)
	}
	entries, err := loadIPListEntriesForAllow(q, ids)
	if err != nil {
		return false, err
	}
	for _, shape := range shapes {
		var inline []string
		if strings.TrimSpace(shape.inline) != "" {
			if err := json.Unmarshal([]byte(shape.inline), &inline); err != nil {
				return false, fmt.Errorf("策略内联 IP 列表解析失败: %w", err)
			}
		}
		nonEmpty := false
		for _, v := range inline {
			if strings.TrimSpace(v) != "" {
				nonEmpty = true
				break
			}
		}
		if nonEmpty {
			continue
		}
		for _, ref := range shape.refs {
			values := replacement
			if ref != listID {
				values = entries[ref]
			}
			if len(values) > 0 {
				nonEmpty = true
				break
			}
		}
		if !nonEmpty {
			return true, nil
		}
	}
	return false, nil
}

// parseIPListRefsPayload 校验并归一 refs 载荷：空白归一为 "[]"；非空必须是
// 整数数组 JSON（字符串/对象条目拒绝），同时把归一结果写回 *val，返回去重 id。
func parseIPListRefsPayload(field string, val *string) ([]int64, error) {
	if val == nil {
		return nil, nil
	}
	if strings.TrimSpace(*val) == "" {
		*val = "[]"
		return nil, nil
	}
	var ids []int64
	if err := json.Unmarshal([]byte(*val), &ids); err != nil {
		return nil, fmt.Errorf("%s 必须是 IP 列表 id 的整数数组 JSON", field)
	}
	seen := make(map[int64]struct{}, len(ids))
	unique := make([]int64, 0, len(ids))
	for _, id := range ids {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	if len(unique) > 64 {
		// refs 无上限会让渲染端逐条展开 ACL 条目,单策略即可
		// 撑爆配置体积——封顶 64(去重后计数)。
		return nil, fmt.Errorf("%s 引用的 IP 列表数量不能超过 64", field)
	}
	normalized, err := json.Marshal(unique)
	if err != nil {
		return nil, fmt.Errorf("%s 归一化失败: %w", field, err)
	}
	*val = string(normalized)
	return unique, nil
}

// validateIPListRefsExistence 批量校验引用的 IP 列表存在性：两组 id 合并去重后
// 一次 IN 查询判定，缺失的 id → 「引用了不存在的 IP 列表 #N」（acl 组优先报告）。
// 查询在调用方提供的事务/连接上执行（与写入同事务，同 validateSecurityPolicyReferences）。
func validateIPListRefsExistence(q policyQueryRower, aclIDs, wlIDs []int64) (string, error) {
	ordered := append(append([]int64{}, aclIDs...), wlIDs...)
	if len(ordered) == 0 {
		return "", nil
	}
	seen := make(map[int64]struct{}, len(ordered))
	unique := make([]int64, 0, len(ordered))
	for _, id := range ordered {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	// 32766 绑定变量上限分块(fail-closed,整体 500)。
	const chunkLimit = 500
	found := make(map[int64]struct{}, len(unique))
	for start := 0; start < len(unique); start += chunkLimit {
		end := start + chunkLimit
		if end > len(unique) {
			end = len(unique)
		}
		chunk := unique[start:end]
		placeholders := make([]string, len(chunk))
		args := make([]interface{}, len(chunk))
		for i, id := range chunk {
			placeholders[i] = "?"
			args[i] = id
		}
		rows, err := q.Query("SELECT id FROM security_ip_lists WHERE id IN ("+strings.Join(placeholders, ",")+")", args...)
		if err != nil {
			return "", err
		}
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return "", err
			}
			found[id] = struct{}{}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return "", err
		}
	}
	for _, id := range aclIDs {
		if _, ok := found[id]; !ok {
			return fmt.Sprintf("引用了不存在的 IP 列表 #%d", id), nil
		}
	}
	for _, id := range wlIDs {
		if _, ok := found[id]; !ok {
			return fmt.Sprintf("引用了不存在的 IP 列表 #%d", id), nil
		}
	}
	return "", nil
}

// builtinIPListLabel 内置名单的用户可读类别（按名单名分流——
// 自动封禁预置名单不是威胁情报名单，提示语不得误称）。
func builtinIPListLabel(name string) string {
	if name == services.AutobanPresetListName {
		return "内置自动封禁名单"
	}
	return "内置威胁情报名单"
}

func validateBuiltinIPListRefs(builtin map[int64]string, aclIDs, wlIDs, excludedIDs []int64, aclMode string) string {
	if len(builtin) == 0 {
		return ""
	}
	in := func(ids []int64) (int64, bool) {
		for _, id := range ids {
			if _, ok := builtin[id]; ok {
				return id, true
			}
		}
		return 0, false
	}
	if id, hit := in(wlIDs); hit {
		return fmt.Sprintf("「%s」是%s，仅允许用于 IP 访问控制的黑名单模式，不能用于信任名单", builtin[id], builtinIPListLabel(builtin[id]))
	}
	if aclMode != "deny" {
		if id, hit := in(aclIDs); hit {
			return fmt.Sprintf("「%s」是%s，仅允许用于 IP 访问控制的黑名单模式", builtin[id], builtinIPListLabel(builtin[id]))
		}
	}
	if id, hit := in(excludedIDs); hit {
		return fmt.Sprintf("「%s」是%s，仅允许用于 IP 访问控制的黑名单模式，不能用于 CRS 排除", builtin[id], builtinIPListLabel(builtin[id]))
	}
	return ""
}

// validateBuiltinThreatListRefs 内置威胁名单引用门禁（2026-09-24 用户裁定）：
// system=1 名单仅允许 IP ACL 黑名单（deny）引用；信任名单 / ACL 白名单
// （allow、绕过）/ CRS 排除作用域一律拒绝。大 ID 集按 500 分块，避免 SQLite
// 变量上限；判定逻辑与备份导入共用 validateBuiltinIPListRefs。
func validateBuiltinThreatListRefs(q policyQueryRower, aclIDs, wlIDs, excludedIDs []int64, aclMode string) (string, error) {
	all := append(append(append([]int64{}, aclIDs...), wlIDs...), excludedIDs...)
	if len(all) == 0 {
		return "", nil
	}
	seen := make(map[int64]struct{}, len(all))
	unique := make([]int64, 0, len(all))
	for _, id := range all {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	builtin := make(map[int64]string)
	for _, chunk := range chunkIDs(unique, 500) {
		rows, err := q.Query("SELECT id, name FROM security_ip_lists WHERE system=1 AND id IN ("+chunk.placeholders+")", chunk.args...)
		if err != nil {
			return "", err
		}
		for rows.Next() {
			var id int64
			var name string
			if err := rows.Scan(&id, &name); err != nil {
				rows.Close()
				return "", err
			}
			builtin[id] = name
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return "", err
		}
	}
	return validateBuiltinIPListRefs(builtin, aclIDs, wlIDs, excludedIDs, aclMode), nil
}

func validateIPListMetadataShape(name, description, category string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("名称不能为空")
	}
	if len([]rune(name)) > ipListMaxNameLength {
		return fmt.Errorf("名称长度不能超过 %d 个字符", ipListMaxNameLength)
	}
	if len([]rune(description)) > ipListMaxDescriptionLength {
		return fmt.Errorf("描述长度不能超过 %d 个字符", ipListMaxDescriptionLength)
	}
	if len([]rune(category)) > ipListMaxCategoryLength {
		return fmt.Errorf("分类长度不能超过 %d 个字符", ipListMaxCategoryLength)
	}
	return nil
}

func normalizeIPListEntriesJSON(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return "[]"
	}
	return raw
}

// ipListEntriesChanged 判定条目是否**实际变化**（渲染生效集同口径）。
// 原始 JSON 字节等值会把前端序列化差异（键序/空白/数组重排）判为变化，
// 触发一次无收益的投影原子重写与审计噪音；解析失败（带外脏行）时退回
// 字节比较——宁可多判一次变化，也不得漏判真实变化。
func ipListEntriesChanged(oldJSON, newJSON string) bool {
	if oldJSON == newJSON {
		return false
	}
	var oldEntries, newEntries []models.IPListEntry
	if err := json.Unmarshal([]byte(oldJSON), &oldEntries); err != nil {
		return true
	}
	if err := json.Unmarshal([]byte(newJSON), &newEntries); err != nil {
		return true
	}
	if len(oldEntries) != len(newEntries) {
		return true
	}
	// 条目顺序不参与渲染（生效集/投影均按集合消费），故按排序后的四元组
	// 逐项比较：value/remark/created_at/expires_at 任一不同即为真实变化。
	key := func(e models.IPListEntry) string {
		return e.Value + "\x00" + e.Remark + "\x00" + e.CreatedAt + "\x00" + e.ExpiresAt
	}
	oldKeys := make([]string, len(oldEntries))
	for i, entry := range oldEntries {
		oldKeys[i] = key(entry)
	}
	newKeys := make([]string, len(newEntries))
	for i, entry := range newEntries {
		newKeys[i] = key(entry)
	}
	sort.Strings(oldKeys)
	sort.Strings(newKeys)
	for i := range oldKeys {
		if oldKeys[i] != newKeys[i] {
			return true
		}
	}
	return false
}

// validateIPListShape 校验列表载荷并返回**生效**条目：名称非空 ≤50、描述 ≤200、
// 分类 ≤32、生效条目数 ≤2000（修正：2026-10-14 用户裁定上限已 500→2000）、
// value 过 validIPOrCIDR、remark ≤100。
//
// 到期条目在保存时剔除（到期即解封，与渲染生效集/追加上限同判据
// services.AutobanActiveEntries）：自动封禁关闭后到期条目不再被任务清理，
// 旧实现按原始长度计上限，让「生效 2000 + 到期残留 N」的整表保存被 400 挡下
// ——用户只能逐行删除到期行才能保存。剔除后返回的条目即落库形态，原始条数
// 与生效条数不再有两个口径；被剔除的条数由 prunedExpired 返回供响应披露。
func validateIPListShape(name, description, category, entriesJSON string) ([]models.IPListEntry, int, error) {
	if err := validateIPListMetadataShape(name, description, category); err != nil {
		return nil, 0, err
	}
	var raw []models.IPListEntry
	if err := json.Unmarshal([]byte(entriesJSON), &raw); err != nil {
		return nil, 0, fmt.Errorf("entries 必须是 {value, remark} 对象的 JSON 数组")
	}
	entries := services.AutobanActiveEntries(raw)
	prunedExpired := len(raw) - len(entries)
	if len(entries) > ipListMaxEntries {
		return nil, 0, fmt.Errorf("生效条目数量不能超过 %d 条（已到期条目不计入）", ipListMaxEntries)
	}
	for i, entry := range entries {
		if !validIPOrCIDR(entry.Value) {
			return nil, 0, fmt.Errorf("条目 %d 包含无效的 IP/CIDR：%s", i+1, entry.Value)
		}
		if len([]rune(entry.Remark)) > ipListMaxRemarkLength {
			return nil, 0, fmt.Errorf("条目 %d 的备注长度不能超过 %d 个字符", i+1, ipListMaxRemarkLength)
		}
		// 备注控制字符门：导出件以「值 空格 备注」逐行组文本，备注里的换行
		// 会造出多一行伪条目（导出再被当名单导入即误加 IP），制表/回车同样
		// 破坏行结构；前端展示也会断行。此处是备注写入的唯一收口（新建/整表
		// 保存共用），故按单源拒绝。
		if hasIPListRemarkControlChar(entry.Remark) {
			return nil, 0, fmt.Errorf("条目 %d 的备注不能包含换行、制表符或其他控制字符", i+1)
		}
	}
	return entries, prunedExpired, nil
}

// hasIPListRemarkControlChar 报告备注是否含 C0/C1 控制字符或 DEL
// （含 \n \r \t）。备注是单行展示/导出的文本字段，控制字符无正常用途。
func hasIPListRemarkControlChar(remark string) bool {
	for _, r := range remark {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return true
		}
	}
	return false
}

type ipListRefPolicy struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	// Enabled 引用策略的启用态：引用计数同时覆盖禁用策略（展示面），
	// 但只有启用的引用会阻止删除（DeleteIPList 409 门只计 enabled=1）——
	// 前端据此给禁用引用加「已禁用」标注，消除「显示有引用却能删」的落差。
	Enabled bool `json:"enabled"`
}

type ipListRow struct {
	ID          int             `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Category    string          `json:"category"`
	Entries     json.RawMessage `json:"entries,omitempty"`
	EntryCount  int             `json:"entry_count"`
	RefCount    int             `json:"ref_count"`
	// RefCountEnabled 启用策略引用数（与 DeleteIPList 的 409 门同口径，
	// 含受信代理引用）——ref_count 含禁用策略的展示面引用，页面对
	// 「显示有引用但能删」的解释由本字段与 ref_policies[].enabled 承担。
	RefCountEnabled int               `json:"ref_count_enabled"`
	RefPolicies     []ipListRefPolicy `json:"ref_policies"`
	CreatedBy       int               `json:"created_by"`
	CreatedAt       string            `json:"created_at"`
	UpdatedBy       int               `json:"updated_by"`
	UpdatedAt       string            `json:"updated_at"`
	// System=内置只读名单（威胁情报库三源，v2.3.2 名单化）——前端据此只读化。
	System bool `json:"system"`
	// PresetAutoban=预置「自动封禁名单」：system=1 但条目可改/禁删
	// ——前端据此渲染编辑形态与到期列（与威胁名单只读形态区分）。
	PresetAutoban bool `json:"preset_autoban"`
	// TrustedProxyReferenced 名单被 Caddy 全局「受信代理网段」引用
	// 引用视图纳入受信代理面——旧实现展示 0 引用但删除 409。不伪造 policy id。
	TrustedProxyReferenced bool `json:"trusted_proxy_referenced"`
	// TrustedProxyScope 受信代理引用范围的可读说明（空=未引用）。
	TrustedProxyScope string `json:"trusted_proxy_scope,omitempty"`
}

// loadIPListRefPolicies 一次查询全部策略的两列 refs 并在 Go 侧解析引用关系。
// 刻意不用 SQL LIKE（"5" 会命中 "[15]"、"[51]"——15 误报对 5 的假阳性），
// JSON 解析是唯一精确口径。
func loadIPListRefPolicies() (map[int64][]ipListRefPolicy, error) {
	rows, err := db.DB.Query("SELECT id, COALESCE(name,''), COALESCE(enabled,0), COALESCE(ip_acl_list_refs,'[]'), COALESCE(ip_whitelist_refs,'[]'), COALESCE(crs_excluded_rules,'[]') FROM security_policies")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	refs := make(map[int64][]ipListRefPolicy)
	for rows.Next() {
		var policyID, enabled int
		var policyName, aclRefs, wlRefs, crsExcluded string
		if err := rows.Scan(&policyID, &policyName, &enabled, &aclRefs, &wlRefs, &crsExcluded); err != nil {
			return nil, err
		}
		seenList := make(map[int64]struct{})
		// 引用计数补排除条目 listRefs 面（409 守卫已覆盖此面，仅补展示口径，
		// 消除「显示 0 引用可删、点删得 409」的观测缺口）。
		for _, raw := range []string{aclRefs, wlRefs} {
			for _, listID := range parseIPListRefsIDs(raw) {
				if _, dup := seenList[listID]; dup {
					continue
				}
				seenList[listID] = struct{}{}
				refs[listID] = append(refs[listID], ipListRefPolicy{ID: policyID, Name: policyName, Enabled: enabled != 0})
			}
		}
		// 补排除条目 listRefs 面（409 守卫已覆盖，仅补展示口径）。
		for _, listID := range crsExcludedListRefs(crsExcluded) {
			if _, dup := seenList[listID]; dup {
				continue
			}
			seenList[listID] = struct{}{}
			refs[listID] = append(refs[listID], ipListRefPolicy{ID: policyID, Name: policyName, Enabled: enabled != 0})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return refs, nil
}

// loadTrustedProxyRefIDs 读取受信代理网段所引用的 IP 名单 id 集合
// （global_config.trusted_proxy_range_refs）——删除守卫与展示面同源。
func loadTrustedProxyRefIDs() (map[int64]bool, error) {
	var raw string
	if err := db.DB.QueryRow(`SELECT COALESCE(trusted_proxy_range_refs,'[]') FROM global_config WHERE id=1`).Scan(&raw); err != nil {
		return nil, err
	}
	ids := make(map[int64]bool)
	for _, id := range parseIPListRefsIDs(raw) {
		ids[id] = true
	}
	return ids, nil
}

// applyIPListRefView 把引用面（策略引用 + 受信代理引用）写入单行 DTO——
// 列表与详情共用，消除「同一资源两个读端点字段语义分叉」：详情此前恒零值
// （ref_count=0 / ref_policies=null / trusted_proxy_* 零），消费详情的调用方
// 会把被引用的名单看成 0 引用，且前端契约声明 ref_policies 为非可选数组。
func applyIPListRefView(row *ipListRow, refs map[int64][]ipListRefPolicy, trustedProxyRefs map[int64]bool) {
	row.RefPolicies = refs[int64(row.ID)]
	if row.RefPolicies == nil {
		row.RefPolicies = []ipListRefPolicy{}
	}
	row.RefCount = len(row.RefPolicies)
	for _, ref := range row.RefPolicies {
		if ref.Enabled {
			row.RefCountEnabled++
		}
	}
	if trustedProxyRefs[int64(row.ID)] {
		row.TrustedProxyReferenced = true
		row.TrustedProxyScope = "受信代理网段"
		row.RefCount++ // 展示计数合并（ref_policies 不伪造策略项）
		// 受信代理引用同属删除门（409），计入阻止删除的引用数。
		row.RefCountEnabled++
	}
}

func (h *Handlers) ListIPLists(c *gin.Context) {
	// entry_count 走 SQL 侧 json_array_length——不再全量
	// 读+逐行解析 entries 仅为计数（万条名单 ≈460KB/行 的 CPU/内存开销归零）；
	// 畸形 JSON 同样报错 500（json_array_length 解析失败→rows.Err），口径不变。
	// RDB 文件化：system=1 行 entries=''（空串非 NULL，COALESCE 不替换），
	// json_array_length('') 会抛 malformed JSON → 500。空串归 0；威胁库真实
	// 条数在下方由 security_threat_sources.entry_count 覆写。
	// 系统名单置顶（2026-10-14 用户裁定）：内置威胁名单×3+自动封禁名单恒排
	// 在用户自建列表之前；系统组内按更新时间序（威胁库更新任务/封禁写入会
	// 刷新 updated_at），用户组随后；id 兜底保证确定性全序。
	rows, err := db.DB.Query("SELECT id, name, COALESCE(description,''), COALESCE(category,''), CASE WHEN COALESCE(entries,'')='' THEN 0 ELSE json_array_length(COALESCE(entries,'[]')) END, COALESCE(created_by,0), COALESCE(created_at,''), COALESCE(updated_by,0), COALESCE(updated_at,''), COALESCE(system,0) FROM security_ip_lists ORDER BY COALESCE(system,0) DESC, updated_at DESC, id ASC")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	defer rows.Close()
	lists := []ipListRow{}
	for rows.Next() {
		var row ipListRow
		if err := rows.Scan(&row.ID, &row.Name, &row.Description, &row.Category, &row.EntryCount, &row.CreatedBy, &row.CreatedAt, &row.UpdatedBy, &row.UpdatedAt, &row.System); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		}
		lists = append(lists, row)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	refs, err := loadIPListRefPolicies()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	// 受信代理引用面（global_config.trusted_proxy_range_refs）——与
	// DeleteIPList 的 409 守卫同源，消除「展示 0 引用却删不掉」的观测缺口。
	trustedProxyRefs, tpErr := loadTrustedProxyRefIDs()
	if tpErr != nil {
		// 与删除守卫同口径 fail-closed——查询失败时不得把引用面
		// 展示为空（页面「无引用可删」与删除 409/500 自相矛盾）；显式
		// 500 让运维区分「真无引用」与「观测失败」。
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取受信代理引用失败"})
		return
	}
	// RDB 文件化：威胁库条数以 threat_sources 为准（DB entries 恒空）
	threatCounts := map[string]int{}
	trows, terr := db.DB.Query(`SELECT name, COALESCE(entry_count,0) FROM security_threat_sources`)
	if terr != nil {
		// 辅助查询失败记日志（曾静默条数 0——与同域「失败不假绿」纪律冲突）
		services.Logf("warn", "威胁库条数查询失败（系统名单条数将显示为 0）: %v", terr)
	}
	if terr == nil {
		for trows.Next() {
			var src string
			var cnt int
			if err := trows.Scan(&src, &cnt); err != nil {
				services.Logf("warn", "威胁库条数扫描失败（系统名单条数可能不完整）: %v", err)
				continue
			}
			if listName := db.ThreatListNameBySource(src); listName != "" {
				threatCounts[listName] = cnt
			}
		}
		// 迭代失败与查询失败同待遇（降级语义——
		// 记 warn，已收行数保留，系统名单条数可能少计/显示 0）。
		if err := trows.Err(); err != nil {
			services.Logf("warn", "威胁库条数查询迭代失败（系统名单条数可能不完整）: %v", err)
		}
		trows.Close()
	}
	for i := range lists {
		row := &lists[i]
		// v2.3.2 弹框性能重构：列表载荷不再内联 entries（大名单 1.4 万条
		// 会背 ~460KB/行）；弹框经 GET /security/ip-lists/:id 按需拉取。
		// 自动封禁预置名单（system=1 但条目在 DB）不适用威胁库条数
		// 覆写——threatCounts 无该名会得到 0 假空；条数取 json_array_length 真值。
		if row.System && row.Name != services.AutobanPresetListName {
			// 仅威胁库条数由 threat_sources 覆写；其他系统名单（爬虫地址库/
			// 后续新族）保留 DB entries 的真实计数，不得被缺省 0 假空。
			if count, ok := threatCounts[row.Name]; ok {
				row.EntryCount = count
			}
		}
		row.PresetAutoban = row.System && row.Name == services.AutobanPresetListName
		// 引用面装载与详情同源（applyIPListRefView）。
		applyIPListRefView(row, refs, trustedProxyRefs)
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: lists})
}

// GetIPList 单条详情（含 entries）——弹框按需拉取（v2.3.2 弹框性能重构：
// 列表接口不再内联 entries，大名单查看/编辑不再背全表载荷）。
func (h *Handlers) GetIPList(c *gin.Context) {
	id := c.Param("id")
	// 非规范数字 ID 门（与全部写路径/策略详情同口径）：SQLite 数值亲和
	// 会让 "5.0" 命中 id=5，必须 400。例外：导出端点（ExportIPList）保留
	// 容忍形态——文本附件下载无歧义面，且文件名已回库内行 ID。
	if _, ok := parsePositiveNumericID(id); !ok {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的列表 ID"})
		return
	}
	var row ipListRow
	var entriesJSON string
	if err := db.DB.QueryRow("SELECT id, name, COALESCE(description,''), COALESCE(category,''), COALESCE(entries,'[]'), COALESCE(created_by,0), COALESCE(created_at,''), COALESCE(updated_by,0), COALESCE(updated_at,''), COALESCE(system,0) FROM security_ip_lists WHERE id=?", id).
		Scan(&row.ID, &row.Name, &row.Description, &row.Category, &entriesJSON, &row.CreatedBy, &row.CreatedAt, &row.UpdatedBy, &row.UpdatedAt, &row.System); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "IP 地址列表不存在"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	entriesJSON = normalizeIPListEntriesJSON(entriesJSON)
	// 预置自动封禁名单（system=1 但条目在 DB）走自定义分支——威胁文件
	// 读取对该名恒失败（未映射威胁源）会让弹框 500。
	row.PresetAutoban = row.System && row.Name == services.AutobanPresetListName
	if row.System && !row.PresetAutoban && services.IsThreatSystemListName(row.Name) {
		// RDB 文件化: 威胁名单条目从 .iplist 文件读取；爬虫地址库仍由
		// DB entries 提供（不得误走威胁文件路径返回空集）。
		vals, ferr := services.ReadThreatIplistForUI(row.Name)
		if ferr != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", ferr)})
			return
		}
		entries := make([]models.IPListEntry, len(vals))
		for i, v := range vals {
			entries[i] = models.IPListEntry{Value: v}
		}
		encoded, _ := json.Marshal(entries)
		row.Entries = json.RawMessage(encoded)
		row.EntryCount = len(entries)
	} else {
		var entries []models.IPListEntry
		if err := json.Unmarshal([]byte(entriesJSON), &entries); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("IP 列表 %s 的条目解析失败: %v", id, err)})
			return
		}
		row.Entries = json.RawMessage(entriesJSON)
		row.EntryCount = len(entries)
	}
	// 引用面与列表同源装载（ref_count/ref_count_enabled/ref_policies/
	// trusted_proxy_*）——详情此前恒零值且 ref_policies 为 null，与前端契约
	// （非可选数组）及列表端点分叉。失败 fail-closed（同列表：不得把引用面
	// 展示为空，否则「无引用可删」与删除 409 自相矛盾）。
	refs, refErr := loadIPListRefPolicies()
	if refErr != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("读取列表引用失败", refErr)})
		return
	}
	trustedProxyRefs, tpErr := loadTrustedProxyRefIDs()
	if tpErr != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取受信代理引用失败"})
		return
	}
	applyIPListRefView(&row, refs, trustedProxyRefs)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: row})
}

func (h *Handlers) CreateIPList(c *gin.Context) {
	// 导入窗口 fast-fail：security_ip_lists 在导入全量替换清单内，排队到导入
	// 提交后再写会改写刚恢复的名单（放行/拦截集合被静默改回）。
	if rejectWriteDuringImport(c, "执行 IP 名单写操作") {
		return
	}
	var req models.CreateIPListRequest
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	if strings.TrimSpace(req.Entries) == "" {
		req.Entries = "[]"
	}
	entries, prunedExpired, err := validateIPListShape(req.Name, req.Description, req.Category, req.Entries)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	// 落库形态=校验返回的生效条目（到期条目已剔除，见 validateIPListShape）。
	entriesJSON, err := json.Marshal(entries)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	defer tx.Rollback()
	var dup int
	if err := tx.QueryRowContext(caddyWriteCtx(c), "SELECT COUNT(*) FROM security_ip_lists WHERE LOWER(name)=LOWER(?)", req.Name).Scan(&dup); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if dup > 0 {
		// 与内置威胁名单重名给出专属提示（2026-09-24 用户裁定：用户名单
		// 不允许与内置名单重名——选择器分组依赖名字区分归属）
		var sysDupName string
		if err := tx.QueryRowContext(caddyWriteCtx(c), "SELECT name FROM security_ip_lists WHERE LOWER(name)=LOWER(?) AND system=1", req.Name).Scan(&sysDupName); err == nil && sysDupName != "" {
			// 保留名提示按命中的内置名单名分流。
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: fmt.Sprintf("该名称为%s保留，请换一个名称", builtinIPListLabel(sysDupName))})
			return
		}
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "IP 列表名称已存在"})
		return
	}
	// 额度只计**用户创建**的名单：系统内置名单（威胁情报库/爬虫地址库/自动
	// 封禁预置）在提交后由 SeedSystemIPLists 自动补齐，不应占用用户额度。
	// 与备份导入的 validateBackupIPListQuota 同口径（userCount ≤ 200），
	// 否则系统名单行会挤掉用户可建空间（导入 197 条用户名单后新建被误挡）。
	var total int
	if err := tx.QueryRowContext(caddyWriteCtx(c), "SELECT COUNT(*) FROM security_ip_lists WHERE COALESCE(system,0)=0").Scan(&total); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if total >= ipListMaxGlobalCount {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("IP 地址列表（用户创建）数量已达上限（%d 个）", ipListMaxGlobalCount)})
		return
	}
	result, err := tx.ExecContext(caddyWriteCtx(c), `INSERT INTO security_ip_lists (name, description, category, entries, created_by, created_at, updated_by, updated_at) VALUES (?,?,?,?,?,datetime('now'),?,datetime('now'))`,
		req.Name, req.Description, req.Category, string(entriesJSON), int(contextUserID(c)), int(contextUserID(c)))
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	id, _ := result.LastInsertId()
	createData := gin.H{"id": id, "entry_count": len(entries)}
	if prunedExpired > 0 {
		createData["pruned_expired"] = prunedExpired
	}
	h.finishTxApply(c, tx, txApplyFinish{
		Resource: "IP 地址列表", AuditAction: "创建",
		AuditDetail: fmt.Sprintf("名称：%s（#%d，%d 条）", req.Name, id, len(entries)),
		SuccessMsg:  "IP 地址列表创建成功",
		Data:        createData,
	})
}

func (h *Handlers) UpdateIPList(c *gin.Context) {
	if rejectWriteDuringImport(c, "执行 IP 名单写操作") {
		return
	}
	id := c.Param("id")
	listID, idOK := parsePositiveNumericID(id)
	if !idOK {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的列表 ID"})
		return
	}
	var req models.UpdateIPListRequest
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	defer tx.Rollback()
	var name, description, category, entriesJSON string
	var system int
	if err := tx.QueryRowContext(caddyWriteCtx(c), "SELECT name, COALESCE(description,''), COALESCE(category,''), COALESCE(entries,'[]'), COALESCE(system,0) FROM security_ip_lists WHERE id=?", id).Scan(&name, &description, &category, &entriesJSON, &system); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "IP 地址列表不存在"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	// 条目变化判定基准=归一后快照：存量 entries='' 行归一为 '[]' 后纯元数据
	// 更新（改描述/分类）不得被误判为条目变化而触发热路径重渲染（与
	// TestUpdateIPList_metadataOnlySkipsHotPath 的「元数据-only 零发射面」契约一致）。
	oldEntriesJSON := normalizeIPListEntriesJSON(entriesJSON)
	// 内置只读名单（威胁情报库，system=1）：内容只读，由更新任务独占维护。
	// 例外：自动封禁预置名单条目可改（手动追加/删除条目经弹框），但名称/
	// 分类/描述三字段锁定（2026-10-14 用户裁定）——自动封禁任务按名单名定位
	// 预置行，改名即失联；分类/描述是预置行身份的一部分，同样禁改。
	autobanPreset := system != 0 && name == services.AutobanPresetListName
	if system != 0 && !autobanPreset {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "内置名单只读，由威胁情报库更新任务维护"})
		return
	}
	if autobanPreset && req.Name != nil && *req.Name != name {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "自动封禁名单为预置名单，名称不可修改"})
		return
	}
	if autobanPreset && req.Category != nil && *req.Category != category {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "自动封禁名单为预置名单，分类不可修改"})
		return
	}
	if autobanPreset && req.Description != nil && *req.Description != description {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "自动封禁名单为预置名单，描述不可修改"})
		return
	}
	if req.Name != nil {
		name = *req.Name
	}
	if req.Description != nil {
		description = *req.Description
	}
	if req.Category != nil {
		category = *req.Category
	}
	if req.Entries != nil {
		entriesJSON = *req.Entries
	}
	entriesJSON = normalizeIPListEntriesJSON(entriesJSON)
	var entries []models.IPListEntry
	var prunedExpired int
	if req.Entries != nil {
		entries, prunedExpired, err = validateIPListShape(name, description, category, entriesJSON)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
		// 落库形态=生效条目（到期条目已剔除）：原始条数与生效条数不再有两个
		// 口径，后续保存不会再被到期残留顶到上限。
		marshaled, merr := json.Marshal(entries)
		if merr != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", merr)})
			return
		}
		entriesJSON = string(marshaled)
	} else {
		// 元数据-only：存量条目不是本次输入，不重跑条目校验——存量含脏值
		// （导入遗留/带外改库）时改名/改描述不得被「条目 N 包含无效的
		// IP/CIDR」400 挡死（用户动作与错误文案不匹配，且无自助修复入口）。
		// 审计条数取存量行数（与导出/删除口径一致），而非到期剔除后的生效集
		// 条数——此前「（N 条）」可能小于库内真实行数。
		if err := validateIPListMetadataShape(name, description, category); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
		if uerr := json.Unmarshal([]byte(entriesJSON), &entries); uerr != nil {
			// 存量条目无法解析（带外脏行）：元数据维护照常放行，审计条数记 0
			// （entries 置 nil，len=0）；条目文本原样写回，不丢数据。
			entries = nil
		}
	}
	// 条目清空 + 本列表被 allow 模式策略引用 → 该策略
	// 生效名单变空 → 渲染侧对空交集恒发 deny（fail-closed：拒绝所有请求，
	// 而非旧文档所称的「放行全部」），UI 却仍宣称 IP 控制已启用。判据必须与
	// RemoveIPListEntry 同源——
	// 走 allowEmptyingBlockedByPolicies 的「并集是否为空」语义（策略内联或
	// 其他引用名单仍有条目时清空本列表不会锁死全部请求），此前按「是否被
	// 引用」一律 409 的偏严口径给出的文案在并集非空时是假的。
	// entries 已是生效集合（到期条目在 validateIPListShape 剔除），因此
	// 「仅剩已到期条目」的保存同样走本门——否则渲染侧
	// （AutobanActiveEntries）生效集为空 = allow 策略恒拒全部请求。
	if req.Entries != nil && len(entries) == 0 {
		blocked, berr := allowEmptyingBlockedByPolicies(tx, listID, nil)
		if berr != nil {
			// 守卫查询失败 fail-closed——静默放行「清空被 allow 引用的列表」
			// 正是要防的「保存即全站 403」形态。
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("校验 IP 列表引用失败", berr)})
			return
		}
		if blocked {
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409,
				Message: "清空后会使引用它的白名单策略生效集合为空（空名单会拒绝该策略的全部请求）；请先为相关策略补充内联条目或其他引用名单，或解除引用"})
			return
		}
	}
	var dup int
	if err := tx.QueryRowContext(caddyWriteCtx(c), "SELECT COUNT(*) FROM security_ip_lists WHERE LOWER(name)=LOWER(?) AND id<>?", name, id).Scan(&dup); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if dup > 0 {
		// 改名撞内置名单同 Create 口径给专属提示（问题
		// 同一裁定语义在更新路径此前退化为通用提示）。
		var sysDupName string
		if err := tx.QueryRowContext(caddyWriteCtx(c), "SELECT name FROM security_ip_lists WHERE LOWER(name)=LOWER(?) AND system=1", name).Scan(&sysDupName); err == nil && sysDupName != "" {
			// 保留名提示按命中的内置名单名分流。
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: fmt.Sprintf("该名称为%s保留，请换一个名称", builtinIPListLabel(sysDupName))})
			return
		}
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "IP 列表名称已存在"})
		return
	}
	result, err := tx.ExecContext(caddyWriteCtx(c), `UPDATE security_ip_lists SET name=?, description=?, category=?, entries=?, updated_by=?, updated_at=datetime('now') WHERE id=?`,
		name, description, category, entriesJSON, int(contextUserID(c)), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if !rowsAffectedOrRespond(c, result, "IP 地址列表不存在") {
		return
	}
	// 同族收敛：预置名单差集全量保存中被移除的条目即解封
	//（删除语义=解封起点，手动/自动条目同口径）——old−new 差集逐 IP 清零
	// 计数桶（services.AutobanForgetIPs 单一入口，与 remove-ip 端点同族），
	// 否则窗口内旧计数让 autoban 下一轮零新流量重封、解封被 ≤1 tick 撤销。
	// 清桶先于提交无回滚副作用（同 remove-ip 路径注释）。
	if autobanPreset && req.Entries != nil {
		var oldEntries []models.IPListEntry
		if err := json.Unmarshal([]byte(oldEntriesJSON), &oldEntries); err == nil {
			newValues := make(map[string]struct{}, len(entries))
			for _, e := range entries {
				newValues[e.Value] = struct{}{}
			}
			removed := make([]string, 0, len(oldEntries))
			for _, e := range oldEntries {
				if _, kept := newValues[e.Value]; !kept {
					removed = append(removed, e.Value)
				}
			}
			services.AutobanForgetIPs(removed)
		}
	}
	applyData := gin.H(nil)
	if req.Entries != nil {
		applyData = gin.H{"entry_count": len(entries)}
		if prunedExpired > 0 {
			applyData["pruned_expired"] = prunedExpired
		}
	}
	if h.tryIPListHotPathApply(c, tx, listID, ipListEntriesChanged(oldEntriesJSON, entriesJSON), txApplyFinish{
		Resource: "IP 地址列表", AuditAction: "更新",
		AuditDetail: fmt.Sprintf("名称：%s（#%s，%d 条）", name, id, len(entries)),
		SuccessMsg:  "IP 地址列表已更新",
		Data:        applyData,
	}) {
		return
	}
	h.finishTxApply(c, tx, txApplyFinish{
		Resource: "IP 地址列表", AuditAction: "更新",
		AuditDetail: fmt.Sprintf("名称：%s（#%s，%d 条）", name, id, len(entries)),
		SuccessMsg:  "IP 地址列表已更新",
		Data:        applyData,
	})
}

func (h *Handlers) DeleteIPList(c *gin.Context) {
	// 门必须先于取锁：导入全程持 caddyOpMu，排队到提交后按陈旧 id 删除会
	// 删掉刚由导入恢复的名单。
	if rejectWriteDuringImport(c, "执行 IP 名单写操作") {
		return
	}
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	id := c.Param("id")
	// 非规范 ID 门与家族同序（UpdateIPList/AddIPToList/RemoveIPFromList 先
	// 400 再读列）——先用原始路由段做 system/name 读取会被 SQLite 数值亲和
	// 命中（"5.0"→行 5），错误码文案与家族分叉。
	listID, idOK := parsePositiveNumericID(id)
	if !idOK {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的列表 ID"})
		return
	}
	// 引用检查与删除同事务（镜像 DeleteSecurityBlockPage 的口径）
	// 检查通过后、DELETE 之前并发的策略更新不得插入新引用。
	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	defer tx.Rollback()
	// 存在性判定与读列合并为单条查询——ErrNoRows=404，其余=500
	//（此前先 COUNT 再 SELECT 同一行，同事务内多一次往返与两套分支）。
	var system int
	var listName string
	if err := tx.QueryRowContext(caddyWriteCtx(c), "SELECT COALESCE(system,0), COALESCE(name,'') FROM security_ip_lists WHERE id=?", id).Scan(&system, &listName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "IP 地址列表不存在"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if system != 0 {
		// 预置「自动封禁名单」禁删（自动封禁任务按名定位+策略引用目标），
		// 与威胁名单只读门文案区分——放行路径=移除对应条目。
		if listName == services.AutobanPresetListName {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "自动封禁名单为预置名单，不可删除（如需放行请移除对应条目）"})
			return
		}
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "内置名单只读，由威胁情报库更新任务维护"})
		return
	}
	// 仅 enabled=1 策略的引用阻止删除，与
	// DeleteSecurityCustomRule/DeleteSecurityBlockPage 同口径——禁用策略的
	// 悬空引用由重启用门兜底（重启用按有效形态过
	// validateIPListRefsExistence，禁用期间被删的列表不得静默激活）。
	rows, err := tx.QueryContext(caddyWriteCtx(c), "SELECT id, COALESCE(ip_acl_list_refs,'[]'), COALESCE(ip_whitelist_refs,'[]'), COALESCE(crs_excluded_rules,'[]') FROM security_policies WHERE enabled=1")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	referencingPolicyIDs := make(map[int64]struct{})
	for rows.Next() {
		var policyID int64
		var aclRefs, wlRefs, crsExcluded string
		if err := rows.Scan(&policyID, &aclRefs, &wlRefs, &crsExcluded); err != nil {
			rows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		}
		for _, raw := range []string{aclRefs, wlRefs} {
			for _, refID := range parseIPListRefsIDs(raw) {
				if refID == listID {
					referencingPolicyIDs[policyID] = struct{}{}
				}
			}
		}
		// crs_excluded_rules 作用域条目的 listRefs 同为引用（JSON 对象数组，
		// 读侧双格式归一后收集；旧 []string 格式恒无引用）。
		for _, refID := range crsExcludedListRefs(crsExcluded) {
			if refID == listID {
				referencingPolicyIDs[policyID] = struct{}{}
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if len(referencingPolicyIDs) > 0 {
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: fmt.Sprintf("该 IP 列表正被 %d 个启用的安全策略引用，请先解除引用", len(referencingPolicyIDs))})
		return
	}
	// 受信代理引用面守卫（2026-10-12，参照 crs_excluded 引用面守卫）：
	// 被 trusted_proxy_range_refs 引用的名单删除会使受信网段渲染静默缺
	// 条目（保存侧存在性门只拦新写入，不追存量悬空）——同事务内检查，
	// 解除引用（Caddy 全局设置）后方可删除。查询/解析失败一律按被引用处理
	// （宁可拒绝删除，不放行悬空引用）。
	var trustedRefs string
	if err := tx.QueryRowContext(caddyWriteCtx(c), `SELECT COALESCE(trusted_proxy_range_refs,'[]') FROM global_config WHERE id=1`).Scan(&trustedRefs); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "校验受信代理引用失败"})
		return
	}
	for _, refID := range parseIPListRefsIDs(trustedRefs) {
		if refID == listID {
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "该 IP 列表正被受信代理网段引用，请先在 Caddy 全局设置中解除引用"})
			return
		}
	}
	// 快照条目数须在 DELETE 前取（名称已在前置门 listName 取得；同事务无写点）
	// 快照读/解析失败降级为「条目数未知」并留 warn——
	// 此前 `_ =` 双吞错会把 DB 瞬时故障记成「0 条」，删除审计与实际删除量不符。
	var delEntries string
	delEntriesKnown := true
	if err := tx.QueryRowContext(caddyWriteCtx(c), "SELECT COALESCE(entries,'[]') FROM security_ip_lists WHERE id=?", id).Scan(&delEntries); err != nil {
		services.Logf("warn", "security: 删除 IP 列表 #%s 前读取条目快照失败（审计条目数记未知）: %v", id, err)
		delEntriesKnown = false
	}
	var delParsed []models.IPListEntry
	if delEntriesKnown {
		if err := json.Unmarshal([]byte(delEntries), &delParsed); err != nil {
			services.Logf("warn", "security: 删除 IP 列表 #%s 前解析条目快照失败（审计条目数记未知）: %v", id, err)
			delEntriesKnown = false
		}
	}
	result, err := tx.ExecContext(caddyWriteCtx(c), "DELETE FROM security_ip_lists WHERE id=?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if !rowsAffectedOrRespond(c, result, "IP 地址列表不存在") {
		return
	}
	entryCountLabel := "条目数未知"
	if delEntriesKnown {
		entryCountLabel = fmt.Sprintf("%d 条", len(delParsed))
	}
	h.finishTxApply(c, tx, txApplyFinish{
		Resource: "IP 地址列表", AuditAction: "删除",
		AuditDetail: fmt.Sprintf("名称：%s（#%s，%s）", listName, id, entryCountLabel),
		SuccessMsg:  "IP 地址列表已删除",
	})
}

func (h *Handlers) AddIPToList(c *gin.Context) {
	if rejectWriteDuringImport(c, "执行 IP 名单写操作") {
		return
	}
	id := c.Param("id")
	listID, idOK := parsePositiveNumericID(id)
	if !idOK {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的列表 ID"})
		return
	}
	var req models.AddIPToListRequest
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	if !validIPOrCIDR(req.Value) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的 IP/CIDR：" + req.Value})
		return
	}
	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	defer tx.Rollback()
	var entriesJSON, listName string
	var system int
	if err := tx.QueryRowContext(caddyWriteCtx(c), "SELECT COALESCE(name,''), COALESCE(entries,'[]'), COALESCE(system,0) FROM security_ip_lists WHERE id=?", id).Scan(&listName, &entriesJSON, &system); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "IP 地址列表不存在"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if system != 0 {
		// 例外：自动封禁预置名单允许手动追加（手动封禁条目，任务 merge
		// 永不挤出）；威胁情报名单保持只读。
		if listName != services.AutobanPresetListName {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "内置名单只读，由威胁情报库更新任务维护"})
			return
		}
	}
	entriesJSON = normalizeIPListEntriesJSON(entriesJSON)
	var entries []models.IPListEntry
	if err := json.Unmarshal([]byte(entriesJSON), &entries); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "存储的 IP 列表条目已损坏，请用整表覆盖（清空/重新导入）修复"})
		return
	}
	// 预置名单手动追加条目的默认备注：手动封禁（任务 merge 的挤出豁免判据
	// 是 remark=自动封禁，手动条目天然豁免；备注区分来源便于面板展示）。
	newEntryRemark := "事件处置"
	if system != 0 {
		newEntryRemark = services.AutobanManualUnbanRemark
	}
	// 同值判重必须区分「生效中」与「已到期未清理」——
	// 自动封禁关闭时过期条目永不清理，旧实现命中即 added:false，手动封禁成为
	// 静默 no-op（渲染生效集仍为空）。到期条目原位覆盖为手动条目（清空
	// expires_at），生效条目保持幂等返回。
	added := true
	for i, entry := range entries {
		if entry.Value != req.Value {
			continue
		}
		if len(services.AutobanActiveEntries([]models.IPListEntry{entry})) > 0 {
			// 幂等无损路径：事务内只有 SELECT 与内存比较，无写语句——
			// 直接回滚（defer 已覆盖，这里显式表达意图）后返回「确定未变更」。
			// 旧实现在此 Commit，把「不可能发生的提交错误」写成
			// 「提交结果不确定」，误导调用方按已写入处理；Commit 失败还会
			// 把事务以未回收形态留下，占住 SQLite 连接锁。
			_ = tx.Rollback()
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"added": false}})
			return
		}
		entries[i] = models.IPListEntry{Value: req.Value, Remark: newEntryRemark}
		added = false
		break
	}
	if added {
		// 上限按生效条目计（与读取/渲染口径 AutobanActiveEntries 同源）——
		// 自动封禁关闭期间滞留的已到期条目不占名额（清理只在启用收尾/任务
		// merge 时发生，按原始长度计会把生效远未达上限的手动封禁 400 挡下）。
		if len(services.AutobanActiveEntries(entries)) >= ipListMaxEntries {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("生效条目数量不能超过 %d 条", ipListMaxEntries)})
			return
		}
		entries = append(entries, models.IPListEntry{Value: req.Value, Remark: newEntryRemark})
	}
	mergedJSON, err := json.Marshal(entries)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if _, err := tx.ExecContext(caddyWriteCtx(c), `UPDATE security_ip_lists SET entries=?, updated_by=?, updated_at=datetime('now') WHERE id=?`, string(mergedJSON), int(contextUserID(c)), id); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}

	// 覆盖已到期条目的动作在审计中显式区分（不是「新增」）——响应仍为
	// added:true（该 IP 已进入生效集），审计标签与之一致地表述为「新增
	// （覆盖已到期条目）」：同一动作不再出现「新增」与「覆盖」两种口径。
	actionLabel := "新增"
	if !added {
		actionLabel = "新增（覆盖已到期条目）"
	}
	if h.tryIPListHotPathApply(c, tx, listID, true, txApplyFinish{
		Resource: "IP 地址列表", AuditAction: "写入",
		AuditDetail: fmt.Sprintf("名称：%s（#%s）追加 IP %s（%s，现共 %d 条）", listName, id, req.Value, actionLabel, len(entries)),
		SuccessMsg:  "已追加",
		Data:        gin.H{"added": true},
	}) {
		return
	}
	h.finishTxApply(c, tx, txApplyFinish{
		Resource: "IP 地址列表", AuditAction: "写入",
		AuditDetail: fmt.Sprintf("名称：%s（#%s）追加 IP %s（%s，现共 %d 条）", listName, id, req.Value, actionLabel, len(entries)),
		SuccessMsg:  "已追加",
		Data:        gin.H{"added": true},
	})
}

// RemoveIPFromList POST /security/ip-lists/:id/remove-ip 从地址列表移除单条 IP
// （弹框重构配套端点，用户裁定：加入/移除统一走地址列表，内置威胁
// 名单只读）。与追加幂等对称：值不在名单时 200 {removed:false}（重复移除
// 无害）；成功移除 200 {removed:true}。移除/追加经 finishTxApply 同链触发
// 引用策略重载。
func (h *Handlers) RemoveIPFromList(c *gin.Context) {
	if rejectWriteDuringImport(c, "执行 IP 名单写操作") {
		return
	}
	id := c.Param("id")
	listID, idOK := parsePositiveNumericID(id)
	if !idOK {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的列表 ID"})
		return
	}
	var req models.AddIPToListRequest
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	// 名单写路径统一持锁（同文件 Create/Update/Delete/Add 均持，
	// 唯本端点历史新增时漂移漏锁——apply 与持锁写并发交错可丢配置更新）
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	if !validIPOrCIDR(req.Value) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的 IP/CIDR：" + req.Value})
		return
	}
	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	defer tx.Rollback()
	var entriesJSON, listName string
	var system int
	if err := tx.QueryRowContext(caddyWriteCtx(c), "SELECT COALESCE(name,''), COALESCE(entries,'[]'), COALESCE(system,0) FROM security_ip_lists WHERE id=?", id).Scan(&listName, &entriesJSON, &system); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "IP 地址列表不存在"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if system != 0 {
		// 例外：自动封禁预置名单允许条目管理（删除条目即解封——
		// 2026-10-15 用户裁定：无抑制窗口，IP 重新达标会被再次封禁）；
		// 威胁情报名单保持只读。
		if listName != services.AutobanPresetListName {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "内置名单只读，由威胁情报库更新任务维护"})
			return
		}
	}
	entriesJSON = normalizeIPListEntriesJSON(entriesJSON)
	var entries []models.IPListEntry
	if err := json.Unmarshal([]byte(entriesJSON), &entries); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "存储的 IP 列表条目已损坏，请用整表覆盖（清空/重新导入）修复"})
		return
	}
	kept := make([]models.IPListEntry, 0, len(entries))
	removed := false
	for _, entry := range entries {
		// 按 value 移除**所有**精确同值条目（旧实现!removed 门只删
		// 第一条，重复行残留需多次操作；前端已有重复行入口，端点侧收敛）。
		if entry.Value == req.Value {
			removed = true
			continue
		}
		kept = append(kept, entry)
	}
	if !removed {
		// 幂等无损路径：事务内无写语句，回滚即「确定未变更」（同追加侧）。
		_ = tx.Rollback()
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"removed": false}})
		return
	}
	// 删后形态若使任一启用 allow 策略的生效集合为空，
	// 拒绝移除（409）；只有策略 inline 或其他引用名单仍有条目时才允许清空。
	// 判据必须用**过滤到期后**的有效集合——导入/带外
	// 名单可含 expires_at，移除最后一个未到期条目后仅剩过期条目，原始 len>0
	// 会绕过守卫；渲染侧（AutobanActiveEntries）的生效集合已为空。
	keptValues := make([]string, 0, len(kept))
	for _, entry := range services.AutobanActiveEntries(kept) {
		if entry.Value != "" {
			keptValues = append(keptValues, entry.Value)
		}
	}
	if len(keptValues) == 0 {
		blocked, berr := allowEmptyingBlockedByPolicies(tx, listID, keptValues)
		if berr != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("校验 IP 列表引用失败", berr)})
			return
		}
		if blocked {
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "移除后该名单为空，会使引用它的白名单策略生效集合为空（空名单会拒绝所有请求）；请先调整相关安全策略"})
			return
		}
	}
	mergedJSON, err := json.Marshal(kept)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if _, err := tx.ExecContext(caddyWriteCtx(c), `UPDATE security_ip_lists SET entries=?, updated_by=?, updated_at=datetime('now') WHERE id=?`, string(mergedJSON), int(contextUserID(c)), id); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	// （用户裁定「删除即解封」语义闭环）：预置名单移除条目
	// 即解封——同步清零该 IP 计数桶（经 services.AutobanForgetIPs 单一入口，
	// 与差集保存路径同族收敛）。不清桶则窗口内旧计数让 autoban 下一轮在零
	// 新流量下立即重封，解封被 ≤1 tick 撤销。清桶先于提交无回滚副作用：事务
	// 失败回滚时条目仍在名单，merge 的已在名单过滤使空桶无行为影响。
	if listName == services.AutobanPresetListName {
		services.AutobanForgetIPs([]string{req.Value})
	}
	if h.tryIPListHotPathApply(c, tx, listID, true, txApplyFinish{
		Resource: "IP 地址列表", AuditAction: "写入",
		AuditDetail: fmt.Sprintf("名称：%s（#%s）移除 IP %s（现共 %d 条）", listName, id, req.Value, len(kept)),
		SuccessMsg:  "已移除",
		Data:        gin.H{"removed": true},
	}) {
		return
	}
	h.finishTxApply(c, tx, txApplyFinish{
		Resource: "IP 地址列表", AuditAction: "写入",
		AuditDetail: fmt.Sprintf("名称：%s（#%s）移除 IP %s（现共 %d 条）", listName, id, req.Value, len(kept)),
		SuccessMsg:  "已移除",
		Data:        gin.H{"removed": true},
	})
}

// ipListCommitTxForTest 仅测试注入 commit 失败（nil=生产直通）。测试实现应
// 先回滚事务再返回错误，确保恢复逻辑读到已提交视图。
var ipListCommitTxForTest func(*sql.Tx) error

func commitIPListTx(tx *sql.Tx) error {
	if ipListCommitTxForTest != nil {
		return ipListCommitTxForTest(tx)
	}
	if txCommitForTest != nil {
		return txCommitForTest(tx)
	}
	return tx.Commit()
}

// tryIPListHotPathApply 名单-only 变更的投影热路径（2026-10-15 用户裁定）。
// 资格 = 条目实际变化 ∧ 被启用策略引用 ∧ 被受信代理/CRS 排除引用面覆盖
// （引用面判定单源 IPListsReferencedByEnabledPolicy，补全
// trusted_proxy_range_refs 与 crs_excluded_rules scope=ip/list 的 ListRefs；
// tp.txt 经 http.ip_sources.lb_file ≤1s stat 热感知）。
// 资格内以事务视图渲染重写投影文件（原子 tmp+rename）并按三态收敛
// （IPListProjectionOutcome）
//   - Converged：提交+业务审计+热路径说明（零 /load，@ipListFast 匹配器
//     ≤1s stat 热感知；不落「重载」审计——审计真实性）；
//   - NeedForce：本轮渲染物化了证书文件而 JSON 字节一致——强制重载收敛
//     （ApplyConfigFromTxCertAwareForce，击穿 errSameConfig），收尾镜像
//     finishTxApply 三分支，落「重载」审计（确有真实重载）；
//   - Fallback / 渲染被拒 / 运行配置不可读：返回 false 落回 finishTxApply
//     全量链（拒绝同口径 400+回滚）。
//
// 已持 caddyOpMu（=CaddyOpLock，调用方写路径临界区），渲染与 /load 永不交错。
// 返回 true = 请求已终结（调用方立即 return）。
func (h *Handlers) tryIPListHotPathApply(c *gin.Context, tx *sql.Tx, listID int64, entriesChanged bool, f txApplyFinish) bool {
	if !entriesChanged {
		return false // 元数据-only 变更零发射面影响，维持既有全量链（同字节短路）
	}
	if listID <= 0 {
		return false
	}
	if !services.IPListsReferencedByEnabledPolicy([]int{int(listID)}) {
		return false
	}
	hot, err := h.caddyService.RefreshIPListProjectionsFromTxInLock(tx)
	if err != nil {
		return false
	}
	if hot == services.ProjectionFallback {
		// 发射面变化/运行配置不可读 → 回退既有全量链（非强制形态足够：字节
		// 不一致时真实 /load 必然发生，errSameConfig 不可能短路）。
		return false
	}
	if hot == services.ProjectionNeedForce {
		// 本轮渲染经 MaterializeCertPairs 物化了证书文件
		// 而配置 JSON 字节一致——零 /load 收尾会把新证书留在磁盘、旧证书留在
		// Caddy 内存。走强制重载收敛：ApplyConfigFromTxCertAwareForce
		// 以同一事务视图渲染+强制 /load（must-revalidate 击穿
		// errSameConfig），收尾分支镜像 finishTxApply 三分支（拒绝回滚/系统
		// 失败退化提交/成功提交），重载审计照常落「重载」行（审计真实性：
		// 本次确有真实重载）。
		appliedConfig, applyErr := h.caddyService.ApplyConfigFromTxCertAwareForce(tx)
		if applyErr != nil {
			if services.IsConfigRejected(applyErr) {
				// 强制被拒=tx 回滚——refresh 渲染已按
				// 未提交条目重写投影，磁盘回退到已提交态（证书物化内容本即已提交
				// PEM，物化无需撤销；见 RollbackIPListProjectionsToCommittedInLock 披露）。
				h.caddyService.RollbackIPListProjectionsToCommittedInLock()
				recordAudit(c, f.AuditAction+"失败", f.Resource, caddyFailureAuditDetail("Caddy 校验未通过", applyErr))
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy 配置校验未通过，" + f.Resource + "未保存: " + applyErr.Error()})
				return true
			}
			// 传输/系统失败 → 退化语义（与 finishTxApply 同口径）：提交 + 业务审计 + 重载失败审计
			// + caddy_apply_error 标记 + 200 带告警（与 finishTxApply 同口径）。
			if err := commitIPListTx(tx); err != nil {
				recovery := h.recoverCommittedViewAfterCommitFailure(tx)
				// 恢复失败=运行配置可能停留候选且 DB 已回滚——横幅必须落盘
				// （看门狗只比对路由 @id，名单/证书变化不触发漂移->分叉不可见）。
				// 本条 apply 已失败，不得补「重载」审计。
				h.recordPostCommitRestoreFailure(commitSaveFailedSubject, err, recovery.runtime, recovery.db)
				joined := errors.Join(err, recovery.err())
				recordAudit(c, f.AuditAction+"失败", f.Resource, caddyFailureAuditDetail(commitUncertainLabel, joined))
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: commitUncertainLabel + "：" + joined.Error()})
				return true
			}
			// 退化提交（DB 已提交、运行配置未生效）与 finishTxApply 同一横幅
			// 形态：「已保存但未生效」；失败横幅的「旧配置已保留」会被误读为
			// 未保存 → 重复提交。
			h.recordCaddyApplySavedNotLive(applyErr)
			recordAudit(c, f.AuditAction, f.Resource, f.AuditDetail)
			recordAudit(c, "重载失败", "Caddy服务", services.RedactCaddyAdminEndpoint(applyErr.Error()))
			services.Logf("warn", "IP 名单热路径：%s（#%d）投影已重写，证书物化触发的强制重载失败: %v", f.Resource, listID, applyErr)
			status := f.SuccessStatus
			if status == 0 {
				status = http.StatusOK
			}
			c.JSON(status, models.APIResponse{Code: 0, Message: f.SuccessMsg + "；但 Caddy 配置应用失败：" + applyErr.Error(), Data: f.Data})
			return true
		}
		if err := commitIPListTx(tx); err != nil {
			recovery := h.recoverCommittedViewAfterCommitFailure(tx)
			// 强制 /load 已真实成功——「触发重载必须留痕」不因 commit 失败豁免。
			recordAudit(c, "重载", "Caddy服务", services.FormatAuditDetail("IP 名单热路径证书物化，强制重载收敛", services.AuditResultPart("success")))
			h.recordPostCommitRestoreFailure(commitSaveFailedSubject, err, recovery.runtime, recovery.db)
			joined := errors.Join(err, recovery.err())
			recordAudit(c, f.AuditAction+"失败", f.Resource, caddyFailureAuditDetail(commitUncertainLabel, joined))
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: commitUncertainLabel + "：" + joined.Error()})
			return true
		}
		h.caddyService.PersistLastGoodBytesInLock(appliedConfig)
		h.recordCaddyApplyResult(nil)
		recordAudit(c, f.AuditAction, f.Resource, f.AuditDetail)
		recordAudit(c, "重载", "Caddy服务", services.FormatAuditDetail("IP 名单热路径证书物化，强制重载收敛", services.AuditResultPart("success")))
		services.Logf("info", "IP 名单热路径：%s（#%d）投影文件已重写；本轮渲染物化了证书文件，已强制重载收敛", f.Resource, listID)
		status := f.SuccessStatus
		if status == 0 {
			status = http.StatusOK
		}
		c.JSON(status, models.APIResponse{Code: 0, Message: f.SuccessMsg, Data: f.Data})
		return true
	}
	// 热路径收尾：镜像 finishTxApply 成功分支，但零 /load（无重载审计）。
	if err := commitIPListTx(tx); err != nil {
		// 提交失败后 database/sql 已把 Tx 标记为 done、不再调用 driver.Rollback：
		// SQLite 的 deferred 约束/IO 类失败会让底层事务保持活动（写锁滞留，
		// 刚归还的池连接仍可见未提交数据）。统一走 rollbackLeakedTx 补发
		// ROLLBACK，再从已提交 DB 视图重写投影；本分支没有 /load 副作用，
		// 保持零重载恢复语义。不得自造 tx.Rollback 分支——那会吞掉 ErrTxDone
		// 且泄漏事务无人释放。
		rollbackLeakedTx()
		h.caddyService.RollbackIPListProjectionsToCommittedInLock()
		recordAudit(c, f.AuditAction+"失败", f.Resource, services.FormatAuditDetail(commitUncertainLabel, err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: commitUncertainLabel + "：" + err.Error()})
		return true
	}
	h.recordCaddyApplyResult(nil) // 比对证实运行配置=已提交 DB 视图，清除既往失败标记
	recordAudit(c, f.AuditAction, f.Resource, f.AuditDetail)
	services.Logf("info", "IP 名单热路径：%s（#%d）投影文件已重写，零 Caddy 重载（匹配器 ≤1s 热感知生效）", f.Resource, listID)
	status := f.SuccessStatus
	if status == 0 {
		status = http.StatusOK
	}
	c.JSON(status, models.APIResponse{Code: 0, Message: f.SuccessMsg, Data: f.Data})
	return true
}

// ExportIPList GET /security/ip-lists/:id/export：名单导出为 TXT（每行
// 「IP/CIDR 备注」，备注为空仅 IP）。自定义名单读 DB entries；威胁名单
// （entries 空）回退读 .iplist 文件条目（无备注列，仅 IP）。文本附件下载
// ，读路径全员可用（business 组）。
func (h *Handlers) ExportIPList(c *gin.Context) {
	id := c.Param("id")
	// 已声明例外：本端点容忍非规范数字路由段（"5.0" 经 SQLite 亲和命中
	// id=5）——文本附件下载无歧义面，且文件名取库内行 ID 而非路由段。
	// 详情读路径（GetIPList）与全部写路径已统一 parsePositiveNumericID 400 门，
	// 此处刻意不加（ExportIPList 容忍形态回归钉测：
	// TestExportIPList_filenameUsesListRowID）。
	var name, entriesJSON string
	var system int
	// 文件名恒为「名单 ID」形态——此前以 name 非空作
	// 条件却仍用 id 组名，死分支误导（阅读者以为名称参与文件名）。取库内行 ID
	// 而非路由段，避免非规范路由段（"5.0"）导出成 ip-list-0.txt。
	var listID int64
	err := db.DB.QueryRowContext(c.Request.Context(),
		`SELECT id, COALESCE(name,''), COALESCE(entries,'[]'), COALESCE(system,0) FROM security_ip_lists WHERE id=?`, id).
		Scan(&listID, &name, &entriesJSON, &system)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "IP 地址列表不存在"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	var entries []models.IPListEntry
	if system == 1 && services.IsThreatSystemListName(name) {
		// 威胁名单以 .iplist/.fast 代际文件为唯一真相；DB entries 可能
		// 是文件化前遗留内容，不得优先导出。文件缺失按空导出。
		vals, ferr := services.ReadThreatIplistForUI(name)
		if ferr != nil {
			// 只有「文件不存在」按空导出；读取/解析
			// 故障必须显式 500——否则调用方拿到 200 空文件无法区分「名单为空」，
			// 与同域读端点（GetIPList）的失败口径一致。
			services.Logf("error", "导出威胁名单 %q 读取失败: %v", name, ferr)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("读取威胁名单文件失败", ferr)})
			return
		}
		entries = make([]models.IPListEntry, 0, len(vals))
		for _, v := range vals {
			entries = append(entries, models.IPListEntry{Value: v})
		}
	} else {
		// 自定义/自动封禁/爬虫名单：DB entries（空串按空导出，畸形显式 500——
		// 200 空文件无法与「名单为空」区分，与 GetIPList/威胁导出同口径）。
		if strings.TrimSpace(entriesJSON) != "" {
			if err := json.Unmarshal([]byte(entriesJSON), &entries); err != nil {
				services.Logf("error", "导出名单 %q entries 解析失败: %v", name, err)
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "名单条目数据损坏"})
				return
			}
		}
	}
	var b strings.Builder
	for _, e := range entries {
		v := strings.TrimSpace(e.Value)
		if v == "" {
			continue
		}
		b.WriteString(v)
		if remark := strings.TrimSpace(e.Remark); remark != "" {
			b.WriteString(" ")
			b.WriteString(remark)
		}
		b.WriteString("\n")
	}
	filename := "ip-list-" + strconv.FormatInt(listID, 10) + ".txt"
	c.Header("Content-Disposition", `attachment; filename="`+filename+`"`)
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(b.String()))
}
