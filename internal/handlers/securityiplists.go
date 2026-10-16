package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"lazy-balancer-v2/internal/services"
	"net/http"
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

// parseIPListRefsIDs 宽松解析 refs JSON 为 id 列表：畸形/空 → nil（重启用悬空
// 引用门读取存量值用；存量列恒为写入侧校验过的合法形态，畸形仅见于带外改库）。
// parseIPListRefsIDs 与 services.parseIPListRefs 为镜像实现（第 54 轮 P5-4
// 裁定保留双份并声明）：本侧服务载荷校验路径不去重（保原始序列语义），
// services 侧投影路径去重保序——语义有意分叉，勿单方面合并。
func parseIPListRefsIDs(raw string) []int64 {
	var ids []int64
	if err := json.Unmarshal([]byte(raw), &ids); err != nil {
		return nil
	}
	return ids
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
		// SEC40-B1-3:refs 无上限会让渲染端逐条展开 ACL 条目,单策略即可
		// 撑爆配置体积——封顶 64(去重后计数)。
		return nil, fmt.Errorf("%s 引用的 IP 列表数量不能超过 64", field)
	}
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
	// SLB13-P4-O1:32766 绑定变量上限分块(fail-closed,整体 500)。
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

// builtinIPListLabel 内置名单的用户可读类别（AU-6 第 74 轮：按名单名分流——
// 自动封禁预置名单不是威胁情报名单，提示语不得误称）。
func builtinIPListLabel(name string) string {
	if name == services.AutobanPresetListName {
		return "内置自动封禁名单"
	}
	return "内置威胁情报名单"
}

// validateBuiltinThreatListRefs 内置威胁名单引用门禁（2026-09-24 用户裁定）：
// system=1 名单（威胁情报库三源）仅允许 IP ACL 黑名单（deny）引用——
// 信任名单 / ACL 白名单（allow、bypass）/ CRS 排除作用域一律拒绝。
// aclMode 为生效模式（请求值 ?? 存量值，由调用方合并）。与存在性校验同型：
// 单批 IN 查询取 system 标记，命中即返回用户可读提示。
func validateBuiltinThreatListRefs(q policyQueryRower, aclIDs, wlIDs, excludedIDs []int64, aclMode string) (string, error) {
	all := append(append(append([]int64{}, aclIDs...), wlIDs...), excludedIDs...)
	if len(all) == 0 {
		return "", nil
	}
	seen := make(map[int64]struct{}, len(all))
	unique := make([]interface{}, 0, len(all))
	placeholders := make([]string, 0, len(all))
	for _, id := range all {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
		placeholders = append(placeholders, "?")
	}
	builtin := make(map[int64]string)
	rows, err := q.Query("SELECT id, name FROM security_ip_lists WHERE system=1 AND id IN ("+strings.Join(placeholders, ",")+")", unique...)
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
	if len(builtin) == 0 {
		return "", nil
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
		return fmt.Sprintf("「%s」是%s，仅允许用于 IP 访问控制的黑名单模式，不能用于信任名单", builtin[id], builtinIPListLabel(builtin[id])), nil
	}
	if aclMode != "deny" {
		if id, hit := in(aclIDs); hit {
			return fmt.Sprintf("「%s」是%s，仅允许用于 IP 访问控制的黑名单模式", builtin[id], builtinIPListLabel(builtin[id])), nil
		}
	}
	if id, hit := in(excludedIDs); hit {
		return fmt.Sprintf("「%s」是%s，仅允许用于 IP 访问控制的黑名单模式，不能用于 CRS 排除", builtin[id], builtinIPListLabel(builtin[id])), nil
	}
	return "", nil
}

// validateIPListShape 校验列表载荷并返回解析后的条目：名称非空 ≤50、描述 ≤200、
// 分类 ≤32、条目数 ≤2000（AU-7 第 74 轮修正：2026-10-14 用户裁定上限已 500→2000）、
// value 过 validIPOrCIDR、remark ≤100。
func validateIPListShape(name, description, category, entriesJSON string) ([]models.IPListEntry, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("名称不能为空")
	}
	if len([]rune(name)) > ipListMaxNameLength {
		return nil, fmt.Errorf("名称长度不能超过 %d 个字符", ipListMaxNameLength)
	}
	if len([]rune(description)) > ipListMaxDescriptionLength {
		return nil, fmt.Errorf("描述长度不能超过 %d 个字符", ipListMaxDescriptionLength)
	}
	if len([]rune(category)) > ipListMaxCategoryLength {
		return nil, fmt.Errorf("分类长度不能超过 %d 个字符", ipListMaxCategoryLength)
	}
	var entries []models.IPListEntry
	if err := json.Unmarshal([]byte(entriesJSON), &entries); err != nil {
		return nil, fmt.Errorf("entries 必须是 {value, remark} 对象的 JSON 数组")
	}
	if len(entries) > ipListMaxEntries {
		return nil, fmt.Errorf("条目数量不能超过 %d 条", ipListMaxEntries)
	}
	for i, entry := range entries {
		if !validIPOrCIDR(entry.Value) {
			return nil, fmt.Errorf("条目 %d 包含无效的 IP/CIDR：%s", i+1, entry.Value)
		}
		if len([]rune(entry.Remark)) > ipListMaxRemarkLength {
			return nil, fmt.Errorf("条目 %d 的备注长度不能超过 %d 个字符", i+1, ipListMaxRemarkLength)
		}
	}
	return entries, nil
}

type ipListRefPolicy struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type ipListRow struct {
	ID          int               `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Category    string            `json:"category"`
	Entries     json.RawMessage   `json:"entries,omitempty"`
	EntryCount  int               `json:"entry_count"`
	RefCount    int               `json:"ref_count"`
	RefPolicies []ipListRefPolicy `json:"ref_policies"`
	CreatedBy   int               `json:"created_by"`
	CreatedAt   string            `json:"created_at"`
	UpdatedBy   int               `json:"updated_by"`
	UpdatedAt   string            `json:"updated_at"`
	// System=内置只读名单（威胁情报库三源，v2.3.2 名单化）——前端据此只读化。
	System bool `json:"system"`
	// PresetAutoban=预置「自动封禁名单」（F73-A）：system=1 但条目可改/禁删
	// ——前端据此渲染编辑形态与到期列（与威胁名单只读形态区分）。
	PresetAutoban bool `json:"preset_autoban"`
}

// loadIPListRefPolicies 一次查询全部策略的两列 refs 并在 Go 侧解析引用关系。
// 刻意不用 SQL LIKE（"5" 会命中 "[15]"、"[51]"——15 误报对 5 的假阳性），
// JSON 解析是唯一精确口径。
func loadIPListRefPolicies() (map[int64][]ipListRefPolicy, error) {
	rows, err := db.DB.Query("SELECT id, COALESCE(name,''), COALESCE(ip_acl_list_refs,'[]'), COALESCE(ip_whitelist_refs,'[]'), COALESCE(crs_excluded_rules,'[]') FROM security_policies")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	refs := make(map[int64][]ipListRefPolicy)
	for rows.Next() {
		var policyID int
		var policyName, aclRefs, wlRefs, crsExcluded string
		if err := rows.Scan(&policyID, &policyName, &aclRefs, &wlRefs, &crsExcluded); err != nil {
			return nil, err
		}
		seenList := make(map[int64]struct{})
		// 审计 U3-F4：引用计数补排除条目 listRefs 面（409 守卫已覆盖此面，仅补展示口径，
		// 消除「显示 0 引用可删、点删得 409」的观测缺口）。
		for _, raw := range []string{aclRefs, wlRefs} {
			for _, listID := range parseIPListRefsIDs(raw) {
				if _, dup := seenList[listID]; dup {
					continue
				}
				seenList[listID] = struct{}{}
				refs[listID] = append(refs[listID], ipListRefPolicy{ID: policyID, Name: policyName})
			}
		}
		// 审计 U3-F4：补排除条目 listRefs 面（409 守卫已覆盖，仅补展示口径）。
		for _, listID := range crsExcludedListRefs(crsExcluded) {
			if _, dup := seenList[listID]; dup {
				continue
			}
			seenList[listID] = struct{}{}
			refs[listID] = append(refs[listID], ipListRefPolicy{ID: policyID, Name: policyName})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return refs, nil
}

func (h *Handlers) ListIPLists(c *gin.Context) {
	// entry_count 走 SQL 侧 json_array_length（第 53 轮补充轮 P3-1）——不再全量
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
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	defer rows.Close()
	refs, err := loadIPListRefPolicies()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	// RDB 文件化：威胁库条数以 threat_sources 为准（DB entries 恒空）
	threatCounts := map[string]int{}
	trows, terr := db.DB.Query(`SELECT name, COALESCE(entry_count,0) FROM security_threat_sources`)
	if terr != nil {
		// U3-P4-4：辅助查询失败记日志（曾静默条数 0——与同域「失败不假绿」纪律冲突）
		services.Logf("warn", "威胁库条数查询失败（系统名单条数将显示为 0）: %v", terr)
	}
	if terr == nil {
		for trows.Next() {
			var src string
			var cnt int
			if trows.Scan(&src, &cnt) == nil {
				if listName := db.ThreatListNameBySource(src); listName != "" {
					threatCounts[listName] = cnt
				}
			}
		}
		// SEC-A-3（第 70 轮）：迭代失败与查询失败同待遇（U3-P4-4 降级语义——
		// 记 warn，已收行数保留，系统名单条数可能少计/显示 0）。
		if err := trows.Err(); err != nil {
			services.Logf("warn", "威胁库条数查询迭代失败（系统名单条数可能不完整）: %v", err)
		}
		trows.Close()
	}
	lists := []ipListRow{}
	for rows.Next() {
		var row ipListRow
		if err := rows.Scan(&row.ID, &row.Name, &row.Description, &row.Category, &row.EntryCount, &row.CreatedBy, &row.CreatedAt, &row.UpdatedBy, &row.UpdatedAt, &row.System); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
			return
		}
		// v2.3.2 弹框性能重构：列表载荷不再内联 entries（大名单 1.4 万条
		// 会背 ~460KB/行）；弹框经 GET /security/ip-lists/:id 按需拉取。
		// F73-A：自动封禁预置名单（system=1 但条目在 DB）不适用威胁库条数
		// 覆写——threatCounts 无该名会得到 0 假空；条数取 json_array_length 真值。
		if row.System && row.Name != services.AutobanPresetListName {
			// 仅威胁库条数由 threat_sources 覆写；其他系统名单（爬虫地址库/
			// 后续新族）保留 DB entries 的真实计数，不得被缺省 0 假空。
			if count, ok := threatCounts[row.Name]; ok {
				row.EntryCount = count
			}
		}
		row.PresetAutoban = row.System && row.Name == services.AutobanPresetListName
		row.RefPolicies = refs[int64(row.ID)]
		if row.RefPolicies == nil {
			row.RefPolicies = []ipListRefPolicy{}
		}
		row.RefCount = len(row.RefPolicies)
		lists = append(lists, row)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: lists})
}

// GetIPList 单条详情（含 entries）——弹框按需拉取（v2.3.2 弹框性能重构：
// 列表接口不再内联 entries，大名单查看/编辑不再背全表载荷）。
func (h *Handlers) GetIPList(c *gin.Context) {
	id := c.Param("id")
	var row ipListRow
	var entriesJSON string
	if err := db.DB.QueryRow("SELECT id, name, COALESCE(description,''), COALESCE(category,''), COALESCE(entries,'[]'), COALESCE(created_by,0), COALESCE(created_at,''), COALESCE(updated_by,0), COALESCE(updated_at,''), COALESCE(system,0) FROM security_ip_lists WHERE id=?", id).
		Scan(&row.ID, &row.Name, &row.Description, &row.Category, &entriesJSON, &row.CreatedBy, &row.CreatedAt, &row.UpdatedBy, &row.UpdatedAt, &row.System); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "IP 地址列表不存在"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	// F73-A：预置自动封禁名单（system=1 但条目在 DB）走自定义分支——威胁文件
	// 读取对该名恒失败（未映射威胁源）会让弹框 500。
	row.PresetAutoban = row.System && row.Name == services.AutobanPresetListName
	if row.System && !row.PresetAutoban && row.Category != "搜索引擎爬虫" {
		// RDB 文件化: 威胁名单条目从 .iplist 文件读取；爬虫地址库仍由
		// DB entries 提供（不得误走威胁文件路径返回空集）。
		vals, ferr := services.ReadThreatIplistForUI(row.Name)
		if ferr != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: ferr.Error()})
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
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: row})
}

func (h *Handlers) CreateIPList(c *gin.Context) {
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	var req models.CreateIPListRequest
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	if strings.TrimSpace(req.Entries) == "" {
		req.Entries = "[]"
	}
	entries, err := validateIPListShape(req.Name, req.Description, req.Category, req.Entries)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	defer tx.Rollback()
	var dup int
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT COUNT(*) FROM security_ip_lists WHERE LOWER(name)=LOWER(?)", req.Name).Scan(&dup); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if dup > 0 {
		// 与内置威胁名单重名给出专属提示（2026-09-24 用户裁定：用户名单
		// 不允许与内置名单重名——选择器分组依赖名字区分归属）
		var sysDupName string
		if err := tx.QueryRowContext(c.Request.Context(), "SELECT name FROM security_ip_lists WHERE LOWER(name)=LOWER(?) AND system=1", req.Name).Scan(&sysDupName); err == nil && sysDupName != "" {
			// AU-6（第 74 轮）：保留名提示按命中的内置名单名分流。
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: fmt.Sprintf("该名称为%s保留，请换一个名称", builtinIPListLabel(sysDupName))})
			return
		}
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "IP 列表名称已存在"})
		return
	}
	var total int
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT COUNT(*) FROM security_ip_lists").Scan(&total); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if total >= ipListMaxGlobalCount {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("IP 地址列表数量已达上限（%d 个）", ipListMaxGlobalCount)})
		return
	}
	result, err := tx.ExecContext(c.Request.Context(), `INSERT INTO security_ip_lists (name, description, category, entries, created_by, created_at, updated_by, updated_at) VALUES (?,?,?,?,?,datetime('now'),?,datetime('now'))`,
		req.Name, req.Description, req.Category, req.Entries, int(contextUserID(c)), int(contextUserID(c)))
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	id, _ := result.LastInsertId()
	h.finishTxApply(c, tx, txApplyFinish{
		Resource: "IP 地址列表", AuditAction: "创建",
		AuditDetail: fmt.Sprintf("名称：%s（#%d，%d 条）", req.Name, id, len(entries)),
		SuccessMsg:  "IP 地址列表创建成功",
		Data:        gin.H{"id": id},
	})
}

func (h *Handlers) UpdateIPList(c *gin.Context) {
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	id := c.Param("id")
	var req models.UpdateIPListRequest
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	defer tx.Rollback()
	var name, description, category, entriesJSON string
	var system int
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT name, COALESCE(description,''), COALESCE(category,''), COALESCE(entries,'[]'), COALESCE(system,0) FROM security_ip_lists WHERE id=?", id).Scan(&name, &description, &category, &entriesJSON, &system); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "IP 地址列表不存在"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	oldEntriesJSON := entriesJSON // 条目变化判定基准（归一前快照，热路径资格用）
	// 内置只读名单（威胁情报库，system=1）：内容只读，由更新任务独占维护。
	// F73-A 例外：自动封禁预置名单条目可改（手动追加/删除条目经弹框），但名称/
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
	if strings.TrimSpace(entriesJSON) == "" {
		entriesJSON = "[]"
	}
	entries, err := validateIPListShape(name, description, category, entriesJSON)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	// N1(第 2 轮审计):条目清空 + 本列表被 allow 模式策略引用 → 该策略
	// 生效名单变空 → 发射端 fail-open(「其余一律拒绝」实际全放行)且 UI
	// 仍宣称 IP 控制已启用。镜像 DeleteIPList 引用门:条目将被清空且存在
	// allow 引用时 409 拒绝(同事务内检查,持 caddyOpMu)。
	if req.Entries != nil && len(entries) == 0 {
		// SLB12-P2-2(第 12 轮审计):非规范数字 id('5.0'/' 5')经 SQLite 数值
		// 亲和仍命中行,但 ParseInt 失败使守卫静默跳过 → 清空被 allow 引用的
		// 列表 fail-open。与 DeleteIPList 同口径:解析失败直接 400。
		listID, perr := strconv.ParseInt(id, 10, 64)
		if perr != nil || listID <= 0 {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的列表 ID"})
			return
		}
		var allowRefCount int
		if err := tx.QueryRowContext(c.Request.Context(),
			`SELECT COUNT(*) FROM security_policies
WHERE COALESCE(ip_acl_enabled,0)=1 AND COALESCE(ip_acl_mode,'')='allow'
  AND json_valid(COALESCE(ip_acl_list_refs,'[]')) AND EXISTS (SELECT 1 FROM json_each(COALESCE(ip_acl_list_refs,'[]')) je WHERE je.value=?)`,
			listID).Scan(&allowRefCount); err != nil {
			// SLB10-N1(第 10 轮审计):守卫查询失败 fail-closed——此前
			// err==nil&& 使查询错误静默放行「清空被 allow 引用的列表」,
			// 正是 N1 要防的发射端 fail-open 形态;与 12 行后重名门同口径。
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "校验 IP 列表引用失败"})
			return
		} else if allowRefCount > 0 {
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409,
				Message: fmt.Sprintf("该列表正被 %d 个白名单模式策略引用，清空条目会使这些策略放行全部请求，请先解除引用", allowRefCount)})
			return
		}
	}
	var dup int
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT COUNT(*) FROM security_ip_lists WHERE LOWER(name)=LOWER(?) AND id<>?", name, id).Scan(&dup); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if dup > 0 {
		// 改名撞内置名单同 Create 口径给专属提示（第 53 轮补充轮 B1 P5-3：
		// 同一裁定语义在更新路径此前退化为通用提示）。
		var sysDupName string
		if err := tx.QueryRowContext(c.Request.Context(), "SELECT name FROM security_ip_lists WHERE LOWER(name)=LOWER(?) AND system=1", name).Scan(&sysDupName); err == nil && sysDupName != "" {
			// AU-6（第 74 轮）：保留名提示按命中的内置名单名分流。
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: fmt.Sprintf("该名称为%s保留，请换一个名称", builtinIPListLabel(sysDupName))})
			return
		}
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "IP 列表名称已存在"})
		return
	}
	result, err := tx.ExecContext(c.Request.Context(), `UPDATE security_ip_lists SET name=?, description=?, category=?, entries=?, updated_by=?, updated_at=datetime('now') WHERE id=?`,
		name, description, category, entriesJSON, int(contextUserID(c)), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "IP 地址列表不存在"})
		return
	}
	// 第 76 轮 F2/AB-1 同族收敛：预置名单差集全量保存中被移除的条目即解封
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
	if h.tryIPListHotPathApply(c, tx, id, oldEntriesJSON != entriesJSON, txApplyFinish{
		Resource: "IP 地址列表", AuditAction: "更新",
		AuditDetail: fmt.Sprintf("名称：%s（#%s，%d 条）", name, id, len(entries)),
		SuccessMsg:  "IP 地址列表已更新",
	}) {
		return
	}
	h.finishTxApply(c, tx, txApplyFinish{
		Resource: "IP 地址列表", AuditAction: "更新",
		AuditDetail: fmt.Sprintf("名称：%s（#%s，%d 条）", name, id, len(entries)),
		SuccessMsg:  "IP 地址列表已更新",
	})
}

func (h *Handlers) DeleteIPList(c *gin.Context) {
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	id := c.Param("id")
	// 引用检查与删除同事务（镜像 DeleteSecurityBlockPage 的 R37 I1 口径）：
	// 检查通过后、DELETE 之前并发的策略更新不得插入新引用。
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT COUNT(*) FROM security_ip_lists WHERE id=?", id).Scan(&exists); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if exists == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "IP 地址列表不存在"})
		return
	}
	var system int
	var listName string
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT COALESCE(system,0), COALESCE(name,'') FROM security_ip_lists WHERE id=?", id).Scan(&system, &listName); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if system != 0 {
		// F73-A：预置「自动封禁名单」禁删（自动封禁任务按名定位+策略引用目标），
		// 与威胁名单只读门文案区分——放行路径=移除对应条目。
		if listName == services.AutobanPresetListName {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "自动封禁名单为预置名单，不可删除（如需放行请移除对应条目）"})
			return
		}
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "内置名单只读，由威胁情报库更新任务维护"})
		return
	}
	listID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的列表 id"})
		return
	}
	// SEC41-4（第 41 轮审计）：仅 enabled=1 策略的引用阻止删除，与
	// DeleteSecurityCustomRule/DeleteSecurityBlockPage 同口径——禁用策略的
	// 悬空引用由 R63 B-N1 重启用门兜底（重启用按有效形态过
	// validateIPListRefsExistence，禁用期间被删的列表不得静默激活）。
	rows, err := tx.QueryContext(c.Request.Context(), "SELECT id, COALESCE(ip_acl_list_refs,'[]'), COALESCE(ip_whitelist_refs,'[]'), COALESCE(crs_excluded_rules,'[]') FROM security_policies WHERE enabled=1")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	referencingPolicyIDs := make(map[int64]struct{})
	for rows.Next() {
		var policyID int64
		var aclRefs, wlRefs, crsExcluded string
		if err := rows.Scan(&policyID, &aclRefs, &wlRefs, &crsExcluded); err != nil {
			rows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
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
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if len(referencingPolicyIDs) > 0 {
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: fmt.Sprintf("该 IP 列表正被 %d 个启用的安全策略引用，请先解除引用", len(referencingPolicyIDs))})
		return
	}
	// 受信代理引用面守卫（2026-10-12，参照 crs_excluded 引用面守卫）：
	// 被 trusted_proxy_range_refs 引用的名单删除会使受信网段渲染静默缺
	// 条目（保存侧存在性门只拦新写入，不追存量悬空）——同事务内检查，
	// 解除引用（Caddy 全局设置）后方可删除。查询/解析失败 fail-closed：
	// 按被引用处理（宁可拒绝删除，不放行悬空引用）。
	var trustedRefs string
	if err := tx.QueryRowContext(c.Request.Context(), `SELECT COALESCE(trusted_proxy_range_refs,'[]') FROM global_config WHERE id=1`).Scan(&trustedRefs); err != nil {
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
	var delEntries string
	_ = tx.QueryRowContext(c.Request.Context(), "SELECT COALESCE(entries,'[]') FROM security_ip_lists WHERE id=?", id).Scan(&delEntries)
	var delParsed []models.IPListEntry
	_ = json.Unmarshal([]byte(delEntries), &delParsed)
	result, err := tx.ExecContext(c.Request.Context(), "DELETE FROM security_ip_lists WHERE id=?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "IP 地址列表不存在"})
		return
	}
	h.finishTxApply(c, tx, txApplyFinish{
		Resource: "IP 地址列表", AuditAction: "删除",
		AuditDetail: fmt.Sprintf("名称：%s（#%s，%d 条）", listName, id, len(delParsed)),
		SuccessMsg:  "IP 地址列表已删除",
	})
}

func (h *Handlers) AddIPToList(c *gin.Context) {
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	id := c.Param("id")
	var req models.AddIPToListRequest
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	if !validIPOrCIDR(req.Value) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的 IP/CIDR：" + req.Value})
		return
	}
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	defer tx.Rollback()
	var entriesJSON, listName string
	var system int
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT COALESCE(name,''), COALESCE(entries,'[]'), COALESCE(system,0) FROM security_ip_lists WHERE id=?", id).Scan(&listName, &entriesJSON, &system); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "IP 地址列表不存在"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if system != 0 {
		// F73-A 例外：自动封禁预置名单允许手动追加（手动封禁条目，任务 merge
		// 永不挤出）；威胁情报名单保持只读。
		if listName != services.AutobanPresetListName {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "内置名单只读，由威胁情报库更新任务维护"})
			return
		}
	}
	var entries []models.IPListEntry
	if err := json.Unmarshal([]byte(entriesJSON), &entries); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "存储的 IP 列表条目已损坏，请删除后重建"})
		return
	}
	for _, entry := range entries {
		if entry.Value == req.Value {
			if err := tx.Commit(); err != nil {
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交事务失败: " + err.Error()})
				return
			}
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"added": false}})
			return
		}
	}
	// 预置名单手动追加条目的默认备注：手动封禁（任务 merge 的挤出豁免判据
	// 是 remark=自动封禁，手动条目天然豁免；备注区分来源便于面板展示）。
	newEntryRemark := "事件处置"
	if system != 0 {
		newEntryRemark = services.AutobanManualUnbanRemark
	}
	if len(entries) >= ipListMaxEntries {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("条目数量不能超过 %d 条", ipListMaxEntries)})
		return
	}
	entries = append(entries, models.IPListEntry{Value: req.Value, Remark: newEntryRemark})
	mergedJSON, err := json.Marshal(entries)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if _, err := tx.ExecContext(c.Request.Context(), `UPDATE security_ip_lists SET entries=?, updated_by=?, updated_at=datetime('now') WHERE id=?`, string(mergedJSON), int(contextUserID(c)), id); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}

	if h.tryIPListHotPathApply(c, tx, id, true, txApplyFinish{
		Resource: "IP 地址列表", AuditAction: "写入",
		AuditDetail: fmt.Sprintf("名称：%s（#%s）追加 IP %s（新增，现共 %d 条）", listName, id, req.Value, len(entries)),
		SuccessMsg:  "已追加",
		Data:        gin.H{"added": true},
	}) {
		return
	}
	h.finishTxApply(c, tx, txApplyFinish{
		Resource: "IP 地址列表", AuditAction: "写入",
		AuditDetail: fmt.Sprintf("名称：%s（#%s）追加 IP %s（新增，现共 %d 条）", listName, id, req.Value, len(entries)),
		SuccessMsg:  "已追加",
		Data:        gin.H{"added": true},
	})
}

// RemoveIPFromList POST /security/ip-lists/:id/remove-ip：从地址列表移除单条 IP
// （第 57 轮弹框重构配套端点，用户裁定：加入/移除统一走地址列表，内置威胁
// 名单只读）。与追加幂等对称：值不在名单时 200 {removed:false}（重复移除
// 无害）；成功移除 200 {removed:true}。移除/追加经 finishTxApply 同链触发
// 引用策略重载。
func (h *Handlers) RemoveIPFromList(c *gin.Context) {
	// 第 60 轮 P3：家族 3 写路径统一持锁（同文件 Create/Update/Delete/Add 均持，
	// 唯本端点第 57 轮新增时漂移漏锁——apply 与持锁写并发交错可丢配置更新）
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	id := c.Param("id")
	var req models.AddIPToListRequest
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	if !validIPOrCIDR(req.Value) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的 IP/CIDR：" + req.Value})
		return
	}
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	defer tx.Rollback()
	var entriesJSON, listName string
	var system int
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT COALESCE(name,''), COALESCE(entries,'[]'), COALESCE(system,0) FROM security_ip_lists WHERE id=?", id).Scan(&listName, &entriesJSON, &system); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "IP 地址列表不存在"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if system != 0 {
		// F73-A 例外：自动封禁预置名单允许条目管理（删除条目即解封——
		// 2026-10-15 用户裁定：无抑制窗口，IP 重新达标会被再次封禁）；
		// 威胁情报名单保持只读。
		if listName != services.AutobanPresetListName {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "内置名单只读，由威胁情报库更新任务维护"})
			return
		}
	}
	var entries []models.IPListEntry
	if err := json.Unmarshal([]byte(entriesJSON), &entries); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "存储的 IP 列表条目已损坏，请删除后重建"})
		return
	}
	kept := make([]models.IPListEntry, 0, len(entries))
	removed := false
	for _, entry := range entries {
		if !removed && entry.Value == req.Value {
			removed = true
			continue
		}
		kept = append(kept, entry)
	}
	if !removed {
		if err := tx.Commit(); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交事务失败: " + err.Error()})
			return
		}
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"removed": false}})
		return
	}
	mergedJSON, err := json.Marshal(kept)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if _, err := tx.ExecContext(c.Request.Context(), `UPDATE security_ip_lists SET entries=?, updated_by=?, updated_at=datetime('now') WHERE id=?`, string(mergedJSON), int(contextUserID(c)), id); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	// 第 76 轮 F2/AB-1（用户裁定「删除即解封」语义闭环）：预置名单移除条目
	// 即解封——同步清零该 IP 计数桶（经 services.AutobanForgetIPs 单一入口，
	// 与差集保存路径同族收敛）。不清桶则窗口内旧计数让 autoban 下一轮在零
	// 新流量下立即重封，解封被 ≤1 tick 撤销。清桶先于提交无回滚副作用：事务
	// 失败回滚时条目仍在名单，merge 的已在名单过滤使空桶无行为影响。
	if listName == services.AutobanPresetListName {
		services.AutobanForgetIPs([]string{req.Value})
	}
	if h.tryIPListHotPathApply(c, tx, id, true, txApplyFinish{
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

// tryIPListHotPathApply 名单-only 变更的投影热路径（2026-10-15 用户裁定）。
// 资格 = 条目实际变化 ∧ 被启用策略引用 ∧ 被受信代理/CRS 排除引用面覆盖
// （引用面判定单源 IPListsReferencedByEnabledPolicy，第 76 轮 SEC-2 补全
// trusted_proxy_range_refs 与 crs_excluded_rules scope=ip/list 的 ListRefs；
// tp.txt 经 http.ip_sources.lb_file ≤1s stat 热感知）。
// 资格内以事务视图渲染重写投影文件（原子 tmp+rename）并按三态收敛
// （IPListProjectionOutcome，第 76 轮 CERT-1）：
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
func (h *Handlers) tryIPListHotPathApply(c *gin.Context, tx *sql.Tx, id string, entriesChanged bool, f txApplyFinish) bool {
	if !entriesChanged {
		return false // 元数据-only 变更零发射面影响，维持既有全量链（同字节短路）
	}
	listID, perr := strconv.ParseInt(id, 10, 64)
	if perr != nil || listID <= 0 {
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
		// CERT-1（第 76 轮）：本轮渲染经 MaterializeCertPairs 物化了证书文件
		// 而配置 JSON 字节一致——零 /load 收尾会把新证书留在磁盘、旧证书留在
		// Caddy 内存（R72 W1-1 失守）。走强制重载收敛：ApplyConfigFromTxCertAwareForce
		// 以同一事务视图渲染+强制 /load（Cache-Control: must-revalidate 击穿
		// errSameConfig），收尾分支镜像 finishTxApply 三分支（拒绝回滚/系统
		// 失败退化提交/成功提交），重载审计照常落「重载」行（审计真实性：
		// 本次确有真实重载）。
		applyErr := h.caddyService.ApplyConfigFromTxCertAwareForce(tx)
		if applyErr != nil {
			if services.IsConfigRejected(applyErr) {
				// HP77-1/HP77-5（第 77 轮）：强制被拒=tx 回滚——refresh 渲染已按
				// 未提交条目重写投影，磁盘回退到已提交态（证书物化内容本即已提交
				// PEM，物化无需撤销；见 RollbackIPListProjectionsToCommittedInLock 披露）。
				h.caddyService.RollbackIPListProjectionsToCommittedInLock()
				recordAudit(c, f.AuditAction+"失败", f.Resource, services.FormatAuditDetail("Caddy 校验未通过", applyErr.Error(), services.AuditResultPart("failure")))
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy 配置校验未通过，" + f.Resource + "未保存: " + applyErr.Error()})
				return true
			}
			// 传输/系统失败 → 家族 2 退化语义：提交 + 业务审计 + 重载失败审计
			// + caddy_apply_error 标记 + 200 带告警（与 finishTxApply 同口径）。
			if err := tx.Commit(); err != nil {
				recordAudit(c, f.AuditAction+"失败", f.Resource, services.FormatAuditDetail("提交事务失败", err.Error(), services.AuditResultPart("failure")))
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交事务失败: " + err.Error()})
				return true
			}
			h.recordCaddyApplyResult(applyErr)
			recordAudit(c, f.AuditAction, f.Resource, f.AuditDetail)
			recordAudit(c, "重载失败", "Caddy服务", applyErr.Error())
			services.Logf("warn", "IP 名单热路径：%s（#%s）投影已重写，证书物化触发的强制重载失败: %v", f.Resource, id, applyErr)
			status := f.SuccessStatus
			if status == 0 {
				status = http.StatusOK
			}
			c.JSON(status, models.APIResponse{Code: 0, Message: f.SuccessMsg + "；但 Caddy 配置应用失败：" + applyErr.Error(), Data: f.Data})
			return true
		}
		if err := tx.Commit(); err != nil {
			recordAudit(c, f.AuditAction+"失败", f.Resource, services.FormatAuditDetail("提交事务失败", err.Error(), services.AuditResultPart("failure")))
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交事务失败: " + err.Error()})
			return true
		}
		h.recordCaddyApplyResult(nil)
		recordAudit(c, f.AuditAction, f.Resource, f.AuditDetail)
		recordAudit(c, "重载", "Caddy服务", services.FormatAuditDetail("IP 名单热路径证书物化，强制重载收敛", services.AuditResultPart("success")))
		services.Logf("info", "IP 名单热路径：%s（#%s）投影文件已重写；本轮渲染物化了证书文件，已强制重载收敛", f.Resource, id)
		status := f.SuccessStatus
		if status == 0 {
			status = http.StatusOK
		}
		c.JSON(status, models.APIResponse{Code: 0, Message: f.SuccessMsg, Data: f.Data})
		return true
	}
	// 热路径收尾：镜像 finishTxApply 成功分支，但零 /load（无重载审计）。
	if err := tx.Commit(); err != nil {
		// 2026-09-07 审计 L5：SQLite commit 失败极罕见；apply 侧本次为纯投影
		// 重写（无 /load），无运行配置回弹面——投影与 DB 的分叉由下次任意
		// 渲染收敛（同字节跳写保护在役文件）。
		recordAudit(c, f.AuditAction+"失败", f.Resource, services.FormatAuditDetail("提交事务失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交事务失败: " + err.Error()})
		return true
	}
	h.recordCaddyApplyResult(nil) // 比对证实运行配置=已提交 DB 视图，清除既往失败标记
	recordAudit(c, f.AuditAction, f.Resource, f.AuditDetail)
	services.Logf("info", "IP 名单热路径：%s（#%s）投影文件已重写，零 Caddy 重载（匹配器 ≤1s 热感知生效）", f.Resource, id)
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
// （Content-Disposition），读路径全员可用（business 组）。
func (h *Handlers) ExportIPList(c *gin.Context) {
	id := c.Param("id")
	var name, entriesJSON string
	var system int
	err := db.DB.QueryRowContext(c.Request.Context(),
		`SELECT COALESCE(name,''), COALESCE(entries,'[]'), COALESCE(system,0) FROM security_ip_lists WHERE id=?`, id).
		Scan(&name, &entriesJSON, &system)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "IP 地址列表不存在"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	var entries []models.IPListEntry
	if system == 0 || entriesJSON != "" && entriesJSON != "[]" {
		// 自定义名单/自动封禁名单：DB entries（空串/畸形按空导出）。
		_ = json.Unmarshal([]byte(entriesJSON), &entries)
	}
	if len(entries) == 0 && system == 1 {
		// 威胁名单（RDB 文件化，entries 恒空）：导出 .iplist 文件条目；
		// 文件缺失（源禁用/未更新）按空导出，不阻断下载。
		if vals, ferr := services.ReadThreatIplistForUI(name); ferr == nil {
			for _, v := range vals {
				entries = append(entries, models.IPListEntry{Value: v})
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
	filename := "ip-list-export.txt"
	if name != "" {
		filename = "ip-list-" + strconv.Itoa(safeAtoiOrZero(id)) + ".txt"
	}
	c.Header("Content-Disposition", `attachment; filename="`+filename+`"`)
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(b.String()))
}

// safeAtoiOrZero 导出文件名用的宽松 id 解析（路由段恒为数字，畸形归 0）。
func safeAtoiOrZero(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
