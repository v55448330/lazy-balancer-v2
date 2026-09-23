package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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
	ipListMaxEntries           = 500
	ipListMaxGlobalCount       = 200
)

// parseIPListRefsIDs 宽松解析 refs JSON 为 id 列表：畸形/空 → nil（重启用悬空
// 引用门读取存量值用；存量列恒为写入侧校验过的合法形态，畸形仅见于带外改库）。
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
		return fmt.Sprintf("「%s」是内置威胁情报名单，仅允许用于 IP 访问控制的黑名单模式，不能用于信任名单", builtin[id]), nil
	}
	if aclMode != "deny" {
		if id, hit := in(aclIDs); hit {
			return fmt.Sprintf("「%s」是内置威胁情报名单，仅允许用于 IP 访问控制的黑名单模式", builtin[id]), nil
		}
	}
	if id, hit := in(excludedIDs); hit {
		return fmt.Sprintf("「%s」是内置威胁情报名单，仅允许用于 IP 访问控制的黑名单模式，不能用于 CRS 排除", builtin[id]), nil
	}
	return "", nil
}

// validateIPListShape 校验列表载荷并返回解析后的条目：名称非空 ≤50、描述 ≤200、
// 分类 ≤32、条目数 ≤500、value 过 validIPOrCIDR、remark ≤100。
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
	rows, err := db.DB.Query("SELECT id, name, COALESCE(description,''), COALESCE(category,''), COALESCE(entries,'[]'), COALESCE(created_by,0), COALESCE(created_at,''), COALESCE(updated_by,0), COALESCE(updated_at,''), COALESCE(system,0) FROM security_ip_lists ORDER BY id")
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
	lists := []ipListRow{}
	for rows.Next() {
		var row ipListRow
		var entriesJSON string
		if err := rows.Scan(&row.ID, &row.Name, &row.Description, &row.Category, &entriesJSON, &row.CreatedBy, &row.CreatedAt, &row.UpdatedBy, &row.UpdatedAt, &row.System); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
			return
		}
		var entries []models.IPListEntry
		if err := json.Unmarshal([]byte(entriesJSON), &entries); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("IP 列表 %d 的条目解析失败: %v", row.ID, err)})
			return
		}
		// v2.3.2 弹框性能重构：列表载荷不再内联 entries（大名单 1.4 万条
		// 会背 ~460KB/行）；弹框经 GET /security/ip-lists/:id 按需拉取。
		row.EntryCount = len(entries)
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
	var entries []models.IPListEntry
	if err := json.Unmarshal([]byte(entriesJSON), &entries); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("IP 列表 %s 的条目解析失败: %v", id, err)})
		return
	}
	row.Entries = json.RawMessage(entriesJSON)
	row.EntryCount = len(entries)
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
		var sysDup int
		if err := tx.QueryRowContext(c.Request.Context(), "SELECT COUNT(*) FROM security_ip_lists WHERE LOWER(name)=LOWER(?) AND system=1", req.Name).Scan(&sysDup); err == nil && sysDup > 0 {
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "该名称为内置威胁情报名单保留，请换一个名称"})
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
	// 内置只读名单（威胁情报库，system=1）：内容只读，由更新任务独占维护。
	if system != 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "内置名单只读，由威胁情报库更新任务维护"})
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
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT COALESCE(system,0) FROM security_ip_lists WHERE id=?", id).Scan(&system); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if system != 0 {
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
	// 快照名称与条目数须在 DELETE 前取（同事务内删除后行已不可见）
	var delName, delEntries string
	_ = tx.QueryRowContext(c.Request.Context(), "SELECT COALESCE(name,''), COALESCE(entries,'[]') FROM security_ip_lists WHERE id=?", id).Scan(&delName, &delEntries)
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
		AuditDetail: fmt.Sprintf("名称：%s（#%s，%d 条）", delName, id, len(delParsed)),
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
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "内置名单只读，由威胁情报库更新任务维护"})
		return
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
	if len(entries) >= ipListMaxEntries {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("条目数量不能超过 %d 条", ipListMaxEntries)})
		return
	}
	entries = append(entries, models.IPListEntry{Value: req.Value, Remark: "事件处置"})
	mergedJSON, err := json.Marshal(entries)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if _, err := tx.ExecContext(c.Request.Context(), `UPDATE security_ip_lists SET entries=?, updated_by=?, updated_at=datetime('now') WHERE id=?`, string(mergedJSON), int(contextUserID(c)), id); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	h.finishTxApply(c, tx, txApplyFinish{
		Resource: "IP 地址列表", AuditAction: "写入",
		AuditDetail: fmt.Sprintf("名称：%s（#%s）追加 IP %s（新增，现共 %d 条）", listName, id, req.Value, len(entries)),
		SuccessMsg:  "已追加",
		Data:        gin.H{"added": true},
	})
}
