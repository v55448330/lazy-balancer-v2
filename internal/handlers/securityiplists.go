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
	placeholders := make([]string, len(unique))
	args := make([]interface{}, len(unique))
	for i, id := range unique {
		placeholders[i] = "?"
		args[i] = id
	}
	rows, err := q.Query("SELECT id FROM security_ip_lists WHERE id IN ("+strings.Join(placeholders, ",")+")", args...)
	if err != nil {
		return "", err
	}
	found := make(map[int64]struct{}, len(unique))
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
	Entries     json.RawMessage   `json:"entries"`
	EntryCount  int               `json:"entry_count"`
	RefCount    int               `json:"ref_count"`
	RefPolicies []ipListRefPolicy `json:"ref_policies"`
	CreatedBy   int               `json:"created_by"`
	CreatedAt   string            `json:"created_at"`
	UpdatedBy   int               `json:"updated_by"`
	UpdatedAt   string            `json:"updated_at"`
}

// loadIPListRefPolicies 一次查询全部策略的两列 refs 并在 Go 侧解析引用关系。
// 刻意不用 SQL LIKE（"5" 会命中 "[15]"、"[51]"——15 误报对 5 的假阳性），
// JSON 解析是唯一精确口径。
func loadIPListRefPolicies() (map[int64][]ipListRefPolicy, error) {
	rows, err := db.DB.Query("SELECT id, COALESCE(name,''), COALESCE(ip_acl_list_refs,'[]'), COALESCE(ip_whitelist_refs,'[]') FROM security_policies")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	refs := make(map[int64][]ipListRefPolicy)
	for rows.Next() {
		var policyID int
		var policyName, aclRefs, wlRefs string
		if err := rows.Scan(&policyID, &policyName, &aclRefs, &wlRefs); err != nil {
			return nil, err
		}
		seenList := make(map[int64]struct{})
		for _, raw := range []string{aclRefs, wlRefs} {
			for _, listID := range parseIPListRefsIDs(raw) {
				if _, dup := seenList[listID]; dup {
					continue
				}
				seenList[listID] = struct{}{}
				refs[listID] = append(refs[listID], ipListRefPolicy{ID: policyID, Name: policyName})
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return refs, nil
}

func (h *Handlers) ListIPLists(c *gin.Context) {
	rows, err := db.DB.Query("SELECT id, name, COALESCE(description,''), COALESCE(category,''), COALESCE(entries,'[]'), COALESCE(created_by,0), COALESCE(created_at,''), COALESCE(updated_by,0), COALESCE(updated_at,'') FROM security_ip_lists ORDER BY id")
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
		if err := rows.Scan(&row.ID, &row.Name, &row.Description, &row.Category, &entriesJSON, &row.CreatedBy, &row.CreatedAt, &row.UpdatedBy, &row.UpdatedAt); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
			return
		}
		var entries []models.IPListEntry
		if err := json.Unmarshal([]byte(entriesJSON), &entries); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("IP 列表 %d 的条目解析失败: %v", row.ID, err)})
			return
		}
		row.Entries = json.RawMessage(entriesJSON)
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

func (h *Handlers) CreateIPList(c *gin.Context) {
	var req models.CreateIPListRequest
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
		req.Name, req.Description, req.Category, req.Entries, getContextUserIDInt(c), getContextUserIDInt(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	id, _ := result.LastInsertId()
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交事务失败: " + err.Error()})
		return
	}
	recordAudit(c, "创建", "IP 地址列表", fmt.Sprintf("名称：%s（#%d，%d 条）", req.Name, id, len(entries)))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "IP 地址列表创建成功" + h.caddyApplyNote(c), Data: gin.H{"id": id}})
}

func (h *Handlers) UpdateIPList(c *gin.Context) {
	id := c.Param("id")
	var req models.UpdateIPListRequest
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
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT name, COALESCE(description,''), COALESCE(category,''), COALESCE(entries,'[]') FROM security_ip_lists WHERE id=?", id).Scan(&name, &description, &category, &entriesJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "IP 地址列表不存在"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
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
	entries, err := validateIPListShape(name, description, category, entriesJSON)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
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
		name, description, category, entriesJSON, getContextUserIDInt(c), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "IP 地址列表不存在"})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交事务失败: " + err.Error()})
		return
	}
	recordAudit(c, "更新", "IP 地址列表", fmt.Sprintf("名称：%s（#%s，%d 条）", name, id, len(entries)))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "IP 地址列表已更新" + h.caddyApplyNote(c)})
}

func (h *Handlers) DeleteIPList(c *gin.Context) {
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
	listID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的列表 id"})
		return
	}
	rows, err := tx.QueryContext(c.Request.Context(), "SELECT COALESCE(ip_acl_list_refs,'[]'), COALESCE(ip_whitelist_refs,'[]') FROM security_policies")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	referenced := 0
	for rows.Next() {
		var aclRefs, wlRefs string
		if err := rows.Scan(&aclRefs, &wlRefs); err != nil {
			rows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
			return
		}
		for _, raw := range []string{aclRefs, wlRefs} {
			for _, refID := range parseIPListRefsIDs(raw) {
				if refID == listID {
					referenced++
				}
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if referenced > 0 {
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: fmt.Sprintf("该 IP 列表正被 %d 个安全策略引用，请先解除引用", referenced)})
		return
	}
	result, err := tx.ExecContext(c.Request.Context(), "DELETE FROM security_ip_lists WHERE id=?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "IP 地址列表不存在"})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交事务失败: " + err.Error()})
		return
	}
	recordAudit(c, "删除", "IP 地址列表", fmt.Sprintf("列表 #%s", id))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "IP 地址列表已删除" + h.caddyApplyNote(c)})
}

func (h *Handlers) AddIPToList(c *gin.Context) {
	id := c.Param("id")
	var req models.AddIPToListRequest
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
	var entriesJSON string
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT COALESCE(entries,'[]') FROM security_ip_lists WHERE id=?", id).Scan(&entriesJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "IP 地址列表不存在"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
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
	if _, err := tx.ExecContext(c.Request.Context(), `UPDATE security_ip_lists SET entries=?, updated_by=?, updated_at=datetime('now') WHERE id=?`, string(mergedJSON), getContextUserIDInt(c), id); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交事务失败: " + err.Error()})
		return
	}
	recordAudit(c, "写入", "IP 地址列表", fmt.Sprintf("列表 #%s 追加 %s", id, req.Value))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已追加" + h.caddyApplyNote(c), Data: gin.H{"added": true}})
}
