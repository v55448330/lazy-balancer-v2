package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 受信代理网段引用 IP 地址列表（trusted_proxy_range_refs，2026-10-12）：
// 保存侧四道关卡——引用存在、总 CIDR ≤2000（内联+展开）、引用名单条目
// 格式合法、round-trip 回读；删除守卫——被引用名单 400 拒绝删除。

func newTrustedProxyRefsRouter(t *testing.T) *gin.Engine {
	t.Helper()
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)
	router.GET("/config", handler.GetConfig)
	router.POST("/config/preview", handler.PreviewConfigUpdate)
	router.DELETE("/security/ip-lists/:id", handler.DeleteIPList)
	router.POST("/security/ip-lists", handler.CreateIPList)
	return router
}

func putConfig(t *testing.T, router *gin.Engine, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

// seedTrustedRefList 直插一条自定义名单（绕过条目数/形状门，供超限与
// 非法条目形状测试使用），返回 id。
func seedTrustedRefList(t *testing.T, name, entriesJSON string) int64 {
	t.Helper()
	res, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, entries) VALUES (?, ?)`, name, entriesJSON)
	if err != nil {
		t.Fatalf("seed ip list %s: %v", name, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestUpdateConfig_trustedProxyRefs_roundtrip(t *testing.T) {
	router := newTrustedProxyRefsRouter(t)
	listID := seedTrustedRefList(t, "cdn-ref-list", `[{"value":"198.51.100.0/24","remark":""}]`)

	body := fmt.Sprintf(`{"source":"caddy","trusted_proxy_enabled":true,"trusted_proxy_ranges":"[\"203.0.113.0/24\"]","trusted_proxy_range_refs":"[%d]"}`, listID)
	if rec := putConfig(t, router, body); rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/config", nil)
	getResp := httptest.NewRecorder()
	router.ServeHTTP(getResp, getReq)
	if getResp.Code != http.StatusOK {
		t.Fatalf("get status=%d", getResp.Code)
	}
	var payload struct {
		Data struct {
			TrustedProxyRangeRefs string `json:"trusted_proxy_range_refs"`
		} `json:"data"`
	}
	if err := json.Unmarshal(getResp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Data.TrustedProxyRangeRefs != fmt.Sprintf("[%d]", listID) {
		t.Fatalf("trusted_proxy_range_refs=%q, want [%d]", payload.Data.TrustedProxyRangeRefs, listID)
	}
}

func TestUpdateConfig_trustedProxyRefs_rejectsMissingList(t *testing.T) {
	router := newTrustedProxyRefsRouter(t)
	body := `{"source":"caddy","trusted_proxy_ranges":"[]","trusted_proxy_range_refs":"[424242]"}`
	if rec := putConfig(t, router, body); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "不存在") {
		t.Fatalf("missing ref must 400 with 不存在, got %d %s", rec.Code, rec.Body.String())
	}
	// 预览端点同校验（未过校验的载荷不得给出变更清单）
	preview := httptest.NewRequest(http.MethodPost, "/config/preview", strings.NewReader(body))
	preview.Header.Set("Content-Type", "application/json")
	previewResp := httptest.NewRecorder()
	router.ServeHTTP(previewResp, preview)
	if previewResp.Code != http.StatusBadRequest {
		t.Fatalf("preview status=%d body=%s, want 400", previewResp.Code, previewResp.Body.String())
	}
}

func TestUpdateConfig_trustedProxyRefs_rejectsOverTotalCap(t *testing.T) {
	router := newTrustedProxyRefsRouter(t)
	// 2001 条有效条目（直插绕过 2000 条形状门——总上限门独立于写侧形状门）
	entries := make([]string, 0, 2001)
	for i := range 2001 {
		entries = append(entries, fmt.Sprintf(`{"value":"10.1.%d.%d/24","remark":""}`, i/250, i%250))
	}
	listID := seedTrustedRefList(t, "huge-ref-list", "["+strings.Join(entries, ",")+"]")

	body := fmt.Sprintf(`{"source":"caddy","trusted_proxy_ranges":"[]","trusted_proxy_range_refs":"[%d]"}`, listID)
	if rec := putConfig(t, router, body); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "2000") {
		t.Fatalf("over-cap refs must 400 with 2000 上限, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestUpdateConfig_trustedProxyRefs_rejectsInvalidListEntry(t *testing.T) {
	router := newTrustedProxyRefsRouter(t)
	listID := seedTrustedRefList(t, "bad-entry-list", `[{"value":"not-an-ip","remark":""}]`)

	body := fmt.Sprintf(`{"source":"caddy","trusted_proxy_ranges":"[]","trusted_proxy_range_refs":"[%d]"}`, listID)
	if rec := putConfig(t, router, body); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "无效") {
		t.Fatalf("invalid entry must 400 with 无效, got %d %s", rec.Code, rec.Body.String())
	}
}

// 总量门此前只挂在 refs 载荷分支——inline-only 更新
// 时库中既有引用展开不参与合计，「内联 ≤64 + 存量 refs 展开 1999」可破
// 2000 上限（非对称）。钉：inline 载荷 + 库中存量 refs 超总量组合 → 400；
// 未超总量 → 200（回归形状）。
func TestUpdateConfig_trustedProxyInlineOnlyUpdate_countsStoredRefsInTotalCap(t *testing.T) {
	router := newTrustedProxyRefsRouter(t)
	// Given: 库中存量 refs 指向 1999 条名单（直插绕过写侧形状门）
	entries := make([]string, 0, 1999)
	for i := range 1999 {
		entries = append(entries, fmt.Sprintf(`{"value":"10.%d.%d.0/24","remark":""}`, i/250, i%250))
	}
	listID := seedTrustedRefList(t, "stored-ref-list", "["+strings.Join(entries, ",")+"]")
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_range_refs=? WHERE id=1`, fmt.Sprintf("[%d]", listID)); err != nil {
		t.Fatal(err)
	}

	// When: 仅携带 inline ranges（refs 未随载荷），内联 2 条 + 存量展开 1999 > 2000
	body := `{"source":"caddy","trusted_proxy_ranges":"[\"203.0.113.0/24\",\"198.51.100.0/24\"]"}`
	if rec := putConfig(t, router, body); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "2000") {
		t.Fatalf("inline+stored-refs over cap must 400 with 2000 上限, got %d %s", rec.Code, rec.Body.String())
	}

	// And: 存量 refs 清空后同一 inline 载荷照常 200（回归形状）
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_range_refs='[]' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if rec := putConfig(t, router, body); rec.Code != http.StatusOK {
		t.Fatalf("inline-only under cap must 200, got %d %s", rec.Code, rec.Body.String())
	}
}

// 名单删除被 trusted_proxy_range_refs 引用 → 拒绝删除（参照策略引用守卫）；
// 解除引用后删除恢复 200。
func TestDeleteIPList_blockedByTrustedProxyRefs(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newTrustedProxyRefsRouter(t)
	listID := seedTrustedRefList(t, "trusted-refd", `[{"value":"198.51.100.0/24","remark":""}]`)
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_range_refs=? WHERE id=1`, fmt.Sprintf("[%d]", listID)); err != nil {
		t.Fatal(err)
	}

	if rec := deleteRequest(t, router, fmt.Sprintf("/security/ip-lists/%d", listID)); rec.Code != http.StatusConflict {
		t.Fatalf("referenced list delete must 409, got %d %s", rec.Code, rec.Body.String())
	}

	// 解除引用 → 删除放行
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_range_refs='[]' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if rec := deleteRequest(t, router, fmt.Sprintf("/security/ip-lists/%d", listID)); rec.Code != http.StatusOK {
		t.Fatalf("unreferenced list delete must 200, got %d %s", rec.Code, rec.Body.String())
	}
}

// 全局配置区 round-trip（2026-10-12）：dumpTable 按列全集导出、Config 区
// PATCH 语义导入——trusted_proxy_range_refs 随备份往返不丢。
func TestConfigBackup_trustedProxyRangeRefsRoundTrip(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO users (id, username, password_hash, role, display_name, is_enabled) VALUES (2, 'backup-admin', 'hash', 'admin', 'Backup Admin', 1) ON CONFLICT(id) DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	// id 3 是内置威胁名单（db 种子）——内置名单引用自本轮起 400
	// 拒绝（威胁名单条目在 .iplist 文件，DB entries 恒空会让格式/总量门失效），
	// 本往返用例改用不冲突的自定义 id。
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_range_refs='[903,907]' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	// 导入门后的语义：备份携带 security_ip_lists 表时（carried=true）名单表
	// 随备份全量替换，refs 存在性**只**按备份行集合解析——库内命中不放行
	//（防导入后悬空）；仅当备份未携带该表（carried=false）才回落库内解析。
	// 故此处两行必须真随备份导出（带外直写悬空 refs 已被悬空 refs 门 400
	// 拒绝，钉测见 TestRevalidateImportTrustedProxyRefsAgainstCarriedLists）。
	for _, id := range []int64{903, 907} {
		if _, err := db.DB.Exec(`INSERT OR IGNORE INTO security_ip_lists (id, name, entries) VALUES (?, ?, '[]')`, id, fmt.Sprintf("roundtrip-%d", id)); err != nil {
			t.Fatal(err)
		}
	}
	router := gin.New()
	router.GET("/config/export", h.ExportConfigBackup)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/config/export", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", response.Code, response.Body.String())
	}
	var backup configBackup
	if err := json.Unmarshal(unpackExportBody(t, response.Body.Bytes()), &backup); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	if got, _ := backup.Config["trusted_proxy_range_refs"].(string); got != "[903,907]" {
		t.Fatalf("export config region trusted_proxy_range_refs=%v, want [903,907]", backup.Config["trusted_proxy_range_refs"])
	}

	// 清空后导入同一备份（校验和原样携带）→ 值还原
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_range_refs='[]' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	backupJSON, err := json.Marshal(backup)
	if err != nil {
		t.Fatal(err)
	}
	importRouter := gin.New()
	importRouter.POST("/config/import", h.ImportConfigBackup)
	importReq := httptest.NewRequest(http.MethodPost, "/config/import", bytes.NewReader(backupJSON))
	importReq.Header.Set("Content-Type", "application/json")
	importResp := httptest.NewRecorder()
	importRouter.ServeHTTP(importResp, importReq)
	if importResp.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", importResp.Code, importResp.Body.String())
	}
	var got string
	if err := db.DB.QueryRow(`SELECT COALESCE(trusted_proxy_range_refs,'[]') FROM global_config WHERE id=1`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "[903,907]" {
		t.Fatalf("imported trusted_proxy_range_refs=%q, want [903,907]", got)
	}
}

// 引用展开计数曾按原始 len(entries) 累加，而逐条校验
// 与渲染层都跳过空 value 条目——名单含空条目（带外改库/旧数据）时，实际
// 展开 ≤2000 的合法载荷会被总量门 400 拒绝。钉：两侧（refs 载荷分支与
// inline-only 存量分支）都只计通过校验的非空条目。
func TestUpdateConfig_trustedProxyRefs_countsOnlyNonEmptyEntries(t *testing.T) {
	router := newTrustedProxyRefsRouter(t)
	entries := make([]string, 0, 2001)
	for i := range 2000 {
		entries = append(entries, fmt.Sprintf(`{"value":"10.1.%d.%d/24","remark":""}`, i/250, i%250))
	}
	entries = append(entries, `{"value":"","remark":"历史空条目"}`)
	listID := seedTrustedRefList(t, "empties-ref-list", "["+strings.Join(entries, ",")+"]")

	// 形状 1：refs 载荷分支——实际展开 2000 条（1 条空值跳过）→ 200。
	body := fmt.Sprintf(`{"source":"caddy","trusted_proxy_ranges":"[]","trusted_proxy_range_refs":"[%d]"}`, listID)
	if rec := putConfig(t, router, body); rec.Code != http.StatusOK {
		t.Fatalf("refs 载荷：实际展开 2000 条（1 条空值跳过）必须 200, got %d %s", rec.Code, rec.Body.String())
	}

	// 形状 2：inline-only 分支——存量 refs 展开同样只计非空条目 → 200。
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_range_refs=? WHERE id=1`, fmt.Sprintf("[%d]", listID)); err != nil {
		t.Fatal(err)
	}
	inlineOnly := `{"source":"caddy","trusted_proxy_ranges":"[]"}`
	if rec := putConfig(t, router, inlineOnly); rec.Code != http.StatusOK {
		t.Fatalf("inline-only：存量展开 2000 条（1 条空值跳过）必须 200, got %d %s", rec.Code, rec.Body.String())
	}

	// 回归形状：多出 1 条真实条目即越过上限 → 仍 400。
	over := append([]string{`{"value":"192.0.2.0/24","remark":""}`}, entries...)
	overID := seedTrustedRefList(t, "over-ref-list", "["+strings.Join(over, ",")+"]")
	overBody := fmt.Sprintf(`{"source":"caddy","trusted_proxy_ranges":"[]","trusted_proxy_range_refs":"[%d]"}`, overID)
	if rec := putConfig(t, router, overBody); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "2000") {
		t.Fatalf("over-cap 必须 400 且点名 2000 上限, got %d %s", rec.Code, rec.Body.String())
	}
}

// 锁内受信代理复核第二分支（名单随备份替换 + refs 保持 live）：live refs
// 指向备份行中 system=1 内置名单必须拒绝（与写侧「受信代理不能引用内置
// 地址列表」契约一致——初检只校验内置行名称白名单，允许 id 撞号）。
func TestRevalidateImportTrustedProxyRefs_listsCarriedRejectsBuiltinRef(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if _, err := db.DB.Exec(`INSERT OR IGNORE INTO global_config (id) VALUES (1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_range_refs='[901]' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	backup := &configBackup{
		Tables: map[string][]map[string]any{
			"security_ip_lists": {
				{"id": 901, "name": "办公网", "system": 1},
			},
		},
	}
	tx, err := db.DB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	// refs 指向备份行中的 system=1 行 → 拒绝
	if err := revalidateImportTrustedProxyRefs(t.Context(), tx, backup); err == nil || !strings.Contains(err.Error(), "内置") {
		t.Fatalf("refs 指内置名单必须拒绝: %v", err)
	}
	// 同 id 非内置行 → 放行
	backup.Tables["security_ip_lists"][0]["system"] = 0
	if err := revalidateImportTrustedProxyRefs(t.Context(), tx, backup); err != nil {
		t.Fatalf("非内置名单 refs 必须放行: %v", err)
	}
}

// 锁内复核的「名单表携带」判据取备份实际携带的表（backup.Tables），不是
// sections 分类选中集合：迟到表 era 的 backups（sections 缺省=全选但表未随包）
// 中 live refs 非空时，按分类判定会把 live refs 与空备份 id 集比对而误拒。
func TestRevalidateImportTrustedProxyRefs_absentListsTableDoesNotRejectLiveRefs(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if _, err := db.DB.Exec(`INSERT OR IGNORE INTO global_config (id) VALUES (1)`); err != nil {
		t.Fatal(err)
	}
	listID := seedIPListRow(t, "live-only", `[{"value":"198.51.100.0/24","remark":""}]`)
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_range_refs=? WHERE id=1`, fmt.Sprintf("[%d]", listID)); err != nil {
		t.Fatal(err)
	}
	tx, err := db.DB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	// Given：备份未携带名单表（迟到表 era），也未携带 refs 键。
	backup := &configBackup{Tables: map[string][]map[string]any{
		"lb_rules": {{"caddy_id": "lb_1", "domain": "a.example", "listen_port": 80}},
	}}
	// Then：两侧均不改变该配对 → 不得因 live refs 非空而拒绝。
	if err := revalidateImportTrustedProxyRefs(t.Context(), tx, backup); err != nil {
		t.Fatalf("名单表未随包携带时不得复核 live refs: %v", err)
	}
}
