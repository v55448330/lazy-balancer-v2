package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// IP 列表弹框性能重构（v2.3.2）：列表接口不再内联 entries（大名单载荷瘦身），
// 新增单条详情端点供弹框按需拉取。
func TestListIPLists_omitsEntries_keepsCount(t *testing.T) {
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, category, entries) VALUES ('big-list', '恶意 IP', '[{"value":"10.0.0.1","remark":"a"},{"value":"10.0.0.2","remark":""}]')`); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.GET("/security/ip-lists", h.ListIPLists)

	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/security/ip-lists", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d", resp.Code)
	}
	var payload struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	var found map[string]any
	for _, row := range payload.Data {
		if row["name"] == "big-list" {
			found = row
		}
	}
	if found == nil {
		t.Fatal("big-list 行缺失")
	}
	if _, has := found["entries"]; has {
		t.Fatalf("列表载荷不得内联 entries: %v", found)
	}
	if found["entry_count"] != float64(2) {
		t.Fatalf("entry_count=%v, want 2", found["entry_count"])
	}
}

func TestGetIPList_returnsEntries(t *testing.T) {
	newBackupTestHandlers(t)
	res, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, category, entries) VALUES ('detail-list', '数据中心', '[{"value":"192.0.2.1","remark":"r1"}]')`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.GET("/security/ip-lists/:id", h.GetIPList)

	// When
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/security/ip-lists/"+strconv.Itoa(int(id)), nil))

	// Then
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "192.0.2.1") || !strings.Contains(resp.Body.String(), "r1") {
		t.Fatalf("详情须含条目: %s", resp.Body.String()[:300])
	}
	// 不存在 → 404
	resp2 := httptest.NewRecorder()
	router.ServeHTTP(resp2, httptest.NewRequest(http.MethodGet, "/security/ip-lists/99999", nil))
	if resp2.Code != http.StatusNotFound {
		t.Fatalf("缺失 id status=%d, want 404", resp2.Code)
	}
}

// 名单详情读路径同属非规范数字 ID 家族门（与 GetSecurityPolicy 同口径）：
// SQLite 数值亲和会让 '5.0' 命中 id=5 并返回详情，与全部写路径
// （parsePositiveNumericID → 400）口径分叉。导出端点是已声明的例外
// （容忍形态，文件名回库内行 ID），不在本门内。
func TestGetIPList_rejectsNoncanonicalID(t *testing.T) {
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (id, name, entries) VALUES (5, 'nc-list', '[]')`); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.GET("/security/ip-lists/:id", h.GetIPList)

	// 规范 ID 仍正常返回
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/security/ip-lists/5", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("canonical id status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}

	for _, bad := range []string{"5.0", "0x5", "%205", "5e0"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/security/ip-lists/"+bad, nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("id=%q status=%d body=%s, want 400（读路径须与写路径同门）", bad, rec.Code, rec.Body.String())
		}
	}
}

// 用户名单不得与内置威胁名单重名（2026-09-24 用户裁定）——内置重名走专属
// 409 提示；同库既有通用重名校验含内置行，本测试钉住专属文案分支。
func TestCreateIPList_rejectsBuiltinName(t *testing.T) {
	newBackupTestHandlers(t) // 迁移已种子三源内置名单（新专业化名）
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.POST("/security/ip-lists", h.CreateIPList)

	body := `{"name":"中科大恶意 IP 名单（USTC）","category":"恶意 IP","entries":"[]"}`
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/security/ip-lists", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "内置威胁情报名单保留") {
		t.Fatalf("应提示内置保留名: %s", resp.Body.String())
	}
}

// 内置威胁名单引用门禁（2026-09-24 用户裁定）：system=1 名单仅允许 IP ACL
// 黑名单（deny）引用；信任名单 / ACL 白名单（allow/绕过）/ CRS 排除一律 400。
func TestCreatePolicy_rejectsBuiltinListOutsideACLDeny(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/security/policies", h.CreateSecurityPolicy)
	var sysID int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE system=1 ORDER BY id LIMIT 1`).Scan(&sysID); err != nil {
		t.Fatalf("内置名单种子缺失: %v", err)
	}
	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/security/policies", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		return resp
	}
	refs := fmt.Sprintf(`[%d]`, sysID)

	// 信任名单引用内置名单 → 400
	if resp := post(`{"name":"t1","policy_type":"stage0","ip_whitelist_refs":"` + refs + `"}`); resp.Code != http.StatusBadRequest {
		t.Fatalf("信任名单引用内置名单应 400, got %d: %s", resp.Code, resp.Body.String())
	}
	// ACL 白名单模式引用内置名单 → 400
	if resp := post(`{"name":"t2","policy_type":"stage1","ip_acl_enabled":true,"ip_acl_mode":"allow","ip_acl_list_refs":"` + refs + `"}`); resp.Code != http.StatusBadRequest {
		t.Fatalf("ACL allow 引用内置名单应 400, got %d: %s", resp.Code, resp.Body.String())
	}
	// ACL 绕过 引用内置名单 → 400
	if resp := post(`{"name":"t2b","policy_type":"stage1","ip_acl_enabled":true,"ip_acl_mode":"绕过","ip_acl_list_refs":"` + refs + `"}`); resp.Code != http.StatusBadRequest {
		t.Fatalf("ACL 绕过 引用内置名单应 400, got %d: %s", resp.Code, resp.Body.String())
	}
	// ACL 黑名单模式引用内置名单 → 放行（唯一合法用途）
	if resp := post(`{"name":"t3","policy_type":"stage1","ip_acl_enabled":true,"ip_acl_mode":"deny","ip_acl_list_refs":"` + refs + `"}`); resp.Code != http.StatusOK {
		t.Fatalf("ACL deny 引用内置名单应放行, got %d: %s", resp.Code, resp.Body.String())
	}
	// 用户名单不受限（信任名单引用自建名单 → 放行）
	if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, category, entries) VALUES ('自建名单', '数据中心', '[]')`); err != nil {
		t.Fatal(err)
	}
	var userID int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name='自建名单'`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if resp := post(fmt.Sprintf(`{"name":"t4","policy_type":"stage0","ip_whitelist_refs":"[%d]"}`, userID)); resp.Code != http.StatusOK {
		t.Fatalf("信任名单引用自建名单应放行, got %d: %s", resp.Code, resp.Body.String())
	}
}

// RDB 文件化（v2.3.4）：system=1 威胁库详情条目从 .iplist 文件读取
// （DB entries 已恒空）；system=0 仍读 DB entries（回归形状）。
func TestGetIPList_systemListReadsIplistFile(t *testing.T) {
	newBackupTestHandlers(t)
	wafDir := t.TempDir()
	restoreWaf := services.OverrideThreatWafDirForTest(wafDir)
	defer restoreWaf()
	if err := os.WriteFile(filepath.Join(wafDir, "threat-ustc.iplist"), []byte("192.0.2.0/24\n198.51.100.7\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// 内置威胁名单行（迁移已种子；DB entries 恒空）
	var id int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE system=1 AND name=?`, db.ThreatListNameBySource("ustc")).Scan(&id); err != nil {
		t.Fatalf("种子威胁名单缺失: %v", err)
	}
	// category 可被历史/带外数据改写，且 DB entries 可能是陈旧值；详情路由
	// 必须按名单名→威胁源，而不是 category 或 DB 残留条目。
	if _, err := db.DB.Exec(`UPDATE security_ip_lists SET category='搜索引擎爬虫', entries='[{"value":"9.9.9.9"}]' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.GET("/security/ip-lists/:id", h.GetIPList)

	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/security/ip-lists/"+strconv.Itoa(int(id)), nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	body := resp.Body.String()
	if !strings.Contains(body, "192.0.2.0/24") || !strings.Contains(body, "198.51.100.7") {
		t.Fatalf("详情须含 .iplist 文件条目: %s", body[:min(300, len(body))])
	}
	if !strings.Contains(body, `"entry_count":2`) {
		t.Fatalf("entry_count 必须=2: %s", body[:min(300, len(body))])
	}

	// 文件缺失（禁用/未更新）→ 空集不报错
	os.Remove(filepath.Join(wafDir, "threat-ustc.iplist"))
	resp2 := httptest.NewRecorder()
	router.ServeHTTP(resp2, httptest.NewRequest(http.MethodGet, "/security/ip-lists/"+strconv.Itoa(int(id)), nil))
	if resp2.Code != http.StatusOK {
		t.Fatalf("文件缺失应返回空集 200, got %d", resp2.Code)
	}
	if !strings.Contains(resp2.Body.String(), `"entry_count":0`) {
		t.Fatalf("文件缺失 entry_count=0: %s", resp2.Body.String()[:min(300, len(resp2.Body.String()))])
	}
}

func TestExportIPList_threatUsesFileTruth(t *testing.T) {
	newBackupTestHandlers(t)
	wafDir := t.TempDir()
	restoreWaf := services.OverrideThreatWafDirForTest(wafDir)
	defer restoreWaf()
	if err := os.WriteFile(filepath.Join(wafDir, "threat-ustc.iplist"), []byte("192.0.2.0/24\n198.51.100.7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE system=1 AND name=?`, db.ThreatListNameBySource("ustc")).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_ip_lists SET entries='[{"value":"9.9.9.9","remark":"stale"}]' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{}
	router := gin.New()
	router.GET("/security/ip-lists/:id/export", h.ExportIPList)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/security/ip-lists/"+strconv.FormatInt(id, 10)+"/export", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	if got, want := resp.Body.String(), "192.0.2.0/24\n198.51.100.7\n"; got != want {
		t.Fatalf("threat export=%q, want file truth %q (stale DB entries must be ignored)", got, want)
	}
	// 文件名恒为「名单 ID」形态（此前 name 非空只作条件，
	// 实际仍用 id，死分支误导）。
	if got, want := resp.Header().Get("Content-Disposition"), `attachment; filename="ip-list-`+strconv.FormatInt(id, 10)+`.txt"`; got != want {
		t.Fatalf("Content-Disposition=%q, want %q", got, want)
	}
}

func TestExportIPList_corruptEntriesReturns500(t *testing.T) {
	newBackupTestHandlers(t)
	res, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, entries, system) VALUES ('corrupt', '{bad', 0)`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	h := &Handlers{}
	router := gin.New()
	router.GET("/security/ip-lists/:id/export", h.ExportIPList)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/security/ip-lists/"+strconv.FormatInt(id, 10)+"/export", nil))
	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（畸形 entries 不得 200 空文件）", resp.Code, resp.Body.String())
	}
}

// RDB 文件化回归（v2.3.4）：system=1 行 entries=”（空串非 NULL）时
// ListIPLists 不得因 json_array_length(”) 报 500；威胁库条数改由
// security_threat_sources.entry_count 供给。
func TestListIPLists_emptyEntriesOnSystemRows(t *testing.T) {
	newBackupTestHandlers(t) // 迁移已种子三源内置名单与 threat_sources 行
	// RDB 形态：system 行 entries 置空串（非 NULL——COALESCE 不会替换）
	if _, err := db.DB.Exec(`UPDATE security_ip_lists SET entries='' WHERE system=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET entry_count=14189 WHERE name='ustc'`); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.GET("/security/ip-lists", h.ListIPLists)

	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/security/ip-lists", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("entries='' 的 system 行不得 500: status=%d body=%s", resp.Code, resp.Body.String()[:min(200, len(resp.Body.String()))])
	}
	var payload struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	// 名单名同源单源：种子改名/换语种时本用例必须失靶报错，不得整体空转仍绿。
	wantName := db.ThreatListNameBySource("ustc")
	if wantName == "" {
		t.Fatal("威胁名单名称单源未返回 ustc 名单（种子数据形态变化）")
	}
	matched := false
	for _, row := range payload.Data {
		system, _ := row["system"].(bool)
		name, _ := row["name"].(string)
		if system && name == wantName {
			matched = true
			if row["entry_count"] != float64(14189) {
				t.Fatalf("威胁库 entry_count 须取自 threat_sources: got %v want 14189", row["entry_count"])
			}
		}
	}
	if !matched {
		t.Fatalf("系统名单 %q 未出现在列表载荷中——用例失靶（entry_count 断言未执行）", wantName)
	}
}

func TestListIPLists_threatCountScanFailureWarns(t *testing.T) {
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET entry_count='not-a-number' WHERE name='ustc'`); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	oldOutput := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(oldOutput) })
	h := &Handlers{}
	router := gin.New()
	router.GET("/security/ip-lists", h.ListIPLists)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/security/ip-lists", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("auxiliary count scan failure should retain degraded 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(logs.String(), "威胁库条数扫描失败") {
		t.Fatalf("scan failure must be visible, logs=%q", logs.String())
	}
}

// ---- 系统名单置顶（2026-10-14 用户裁定） ----

// Given 系统名单×4（威胁三源+自动封禁）与用户自建列表并存，且用户列表的
// 更新时间最新（若按更新时间全局排序会排最前）。
// When GET /security/ip-lists。
// Then 系统名单恒排在用户列表之前（系统组内按更新时间序——最新更新的系统
// 名单组内第一），用户组随后。
func TestListIPLists_systemListsPinnedFirst(t *testing.T) {
	newBackupTestHandlers(t)
	for _, name := range []string{"用户甲", "用户乙"} {
		if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, category, entries, system, created_at, updated_at)
			VALUES (?, '', '[]', 0, datetime('now'), datetime('now'))`, name); err != nil {
			t.Fatal(err)
		}
	}
	// 一个威胁名单的更新时间顶到组内最新（组内排序判据）；刻意选 id 最大的
	// 系统名单——旧的 ORDER BY id 序下首行是 id 最小的威胁名单，本判据才会红。
	if _, err := db.DB.Exec(`UPDATE security_ip_lists SET updated_at=datetime('now','+1 hour') WHERE system=1 AND name=?`, threatSystemListNameForOrderTest(t)); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.GET("/security/ip-lists", h.ListIPLists)

	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/security/ip-lists", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Data []struct {
			Name   string `json:"name"`
			System bool   `json:"system"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	rows := payload.Data
	// 系统名单数量取自种子行（威胁三源 + 自动封禁名单），不硬编码。
	var wantSystem int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE system=1`).Scan(&wantSystem); err != nil {
		t.Fatal(err)
	}
	if len(rows) < wantSystem+2 {
		t.Fatalf("行数=%d, want ≥%d（%d 系统+2 用户）", len(rows), wantSystem+2, wantSystem)
	}
	// 系统行必须是**连续前缀**（置顶形态）——不绑定具体系统名单数量。
	sysCount := 0
	seenUser := false
	for i, row := range rows {
		if row.System {
			if seenUser {
				t.Fatalf("系统名单必须连续置顶：第 %d 行 %q 出现在用户列表之后", i, row.Name)
			}
			sysCount++
			continue
		}
		seenUser = true
	}
	if sysCount != wantSystem {
		t.Fatalf("系统名单=%d, want %d（种子表）", sysCount, wantSystem)
	}
	if rows[0].Name != threatSystemListNameForOrderTest(t) {
		t.Fatalf("系统组内应按更新时间序（最新在前），首行=%q", rows[0].Name)
	}
}

// threatSystemListNameForOrderTest 取 id 最大的威胁名单名（置顶排序测试的组内
// 判据名单——选 id 最大者使旧 id 序下它不在首行，判据可红）。
func threatSystemListNameForOrderTest(t *testing.T) string {
	t.Helper()
	var name string
	if err := db.DB.QueryRow(`SELECT name FROM security_ip_lists WHERE system=1 AND name<>? ORDER BY id DESC LIMIT 1`, services.AutobanPresetListName).Scan(&name); err != nil {
		t.Fatalf("threat list missing: %v", err)
	}
	return name
}

// 导出文件名恒取**库内行 ID**。此前以 name 非空作条件
// 却仍用路由段经 safeAtoiOrZero 折算——名称从不参与文件名（死分支），且非规范
// 路由段 "<id>.0"（SQLite INTEGER 亲和命中该行）会导出成 ip-list-0.txt。
func TestExportIPList_filenameUsesListRowID(t *testing.T) {
	newBackupTestHandlers(t)
	res, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, entries) VALUES ('导出命名', '[{"value":"198.51.100.1","remark":""}]')`)
	if err != nil {
		t.Fatal(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	h := &Handlers{}
	router := gin.New()
	router.GET("/security/ip-lists/:id/export", h.ExportIPList)
	// 非规范路由段仍命中该行（亲和），文件名必须回到真实行 ID
	path := "/security/ip-lists/" + strconv.FormatInt(id, 10) + ".0/export"
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, path, nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", resp.Code, resp.Body.String())
	}
	want := `attachment; filename="ip-list-` + strconv.FormatInt(id, 10) + `.txt"`
	if got := resp.Header().Get("Content-Disposition"); got != want {
		t.Fatalf("Content-Disposition=%q, want %q（文件名须取库内行 ID，名称不参与）", got, want)
	}
}
