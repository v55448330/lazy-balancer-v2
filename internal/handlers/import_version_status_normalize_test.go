package handlers

// 导入门对四张版本/源表的 update_status 归一：词表外值（含空串/非字符串形态）
// 一律归一为 idle 并进响应 warnings；合法词表值与缺席键不动。运行态词表列
// 前端直读、渲染层零兜底，带外直写或旧备份的词表外值必须先于落库收敛。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func TestImportNormalizesVersionUpdateStatuses(t *testing.T) {
	// Given 四张表各带一种词表外形（含合法对照行与缺席键行）。
	tables := map[string][]map[string]any{
		"security_crs_version": {
			{"id": 1, "version": "v1", "update_status": "queued"},
			{"id": 2, "version": "v2", "update_status": "success"},
			{"id": 3, "version": "v3"},
		},
		"security_ip2region_version": {
			{"id": 1, "version": "v1", "update_status": ""},
		},
		"security_threat_sources": {
			{"id": 1, "name": "ustc", "update_status": 42},
		},
		"security_crawler_sources": {
			{"id": 1, "name": "googlebot", "update_status": "unknown-stat"},
		},
	}

	// When
	warnings := normalizeImportedVersionUpdateStatuses(tables)

	// Then 四行词表外值全部归一为 idle，一条汇总警告点名条数。
	for _, table := range []string{"security_crs_version", "security_ip2region_version", "security_threat_sources", "security_crawler_sources"} {
		if got := tables[table][0]["update_status"]; got != string(services.CRSStatusIdle) {
			t.Fatalf("%s.update_status=%v, want idle", table, got)
		}
	}
	if len(warnings) != 1 || !strings.Contains(zhWarning(warnings[0]), "4 条版本/源记录") || !strings.Contains(zhWarning(warnings[0]), "已归一为 idle") {
		t.Fatalf("warnings=%v, want 单条「4 条…已归一为 idle」", warnings)
	}

	// Then 合法词表值保持原样；键缺席的行不得被补写。
	if got := tables["security_crs_version"][1]["update_status"]; got != "success" {
		t.Fatalf("合法 update_status 被改动: %v", got)
	}
	if _, exists := tables["security_crs_version"][2]["update_status"]; exists {
		t.Fatal("键缺席的行不得被补写 update_status")
	}

	// 回归形状：全部合法时不产生警告。
	if warnings := normalizeImportedVersionUpdateStatuses(map[string][]map[string]any{
		"security_crs_version": {{"id": 1, "update_status": "failed"}},
	}); len(warnings) != 0 {
		t.Fatalf("合法值不应产生警告: %v", warnings)
	}
}

func TestImportConfigBackup_normalizesCarriedVersionUpdateStatus(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'current-admin','hash','admin',1)`); err != nil {
		t.Fatalf("seed current admin: %v", err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)

	// Given 安全分类备份携带三张表，update_status 均为词表外值。
	body := buildBackup(t, backupFixtureOptions{
		Sections: []string{"security"},
		Tables: map[string][]map[string]any{
			"security_crs_version":       {{"id": 1, "version": "crs-v1", "update_status": "queued"}},
			"security_ip2region_version": {{"id": 1, "version": "xdb-v1", "update_status": ""}},
			"security_crawler_sources":   {{"id": 1, "name": "googlebot", "update_status": "unknown-stat"}},
			"security_policies":          {},
			"security_policy_bindings":   {},
			"security_custom_rules":      {},
			"security_block_pages":       {},
			"security_ip_lists":          {},
		},
		EmptyConfigIfNil: true,
	})

	// When
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	// Then 导入成功且响应 warnings 携带归一提示（条数=随包落库/参与准备的三表行）。
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "update_status 不在词表内，已归一为 idle") {
		t.Fatalf("body=%s, want update_status 归一警告", recorder.Body.String())
	}

	// Then 落库终态：爬虫源行的词表外值被归一。
	var crawlerStatus string
	if err := db.DB.QueryRow(`SELECT update_status FROM security_crawler_sources WHERE name='googlebot'`).Scan(&crawlerStatus); err != nil {
		t.Fatalf("read crawler source status: %v", err)
	}
	if crawlerStatus != string(services.CRSStatusIdle) {
		t.Fatalf("crawler update_status=%q, want idle", crawlerStatus)
	}
	// 纯 JSON 不携带规则库文件：版本表与记录同批落地契约要求它们保持本地值
	// （元数据不得先于文件替换）。
	var carriedCRS int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_crs_version WHERE version='crs-v1' OR update_status='queued'`).Scan(&carriedCRS); err != nil {
		t.Fatalf("read crs version rows: %v", err)
	}
	if carriedCRS != 0 {
		t.Fatalf("纯 JSON 导入写入了 %d 条 CRS 版本记录（记录与文件分叉）", carriedCRS)
	}
}

// 活动态是「类」而非逐词白名单：随备份带进的活动词（版本表四活动词 +
// 源表唯一活动词 running）一律归一为 failed + 归属文案——导入节点不执行该
// 任务，原样落库会让规则库页/更新弹框长期显示「更新中」而任务监控显示空闲；
// 同时 running 必须留在共享词表内（源表写侧合法值），不得被误判为词表外值。
func TestImportNormalizesCarriedActiveUpdateStatuses(t *testing.T) {
	// Given 四张表各带一种活动态词（含带/不带 message 列的形态）。
	tables := map[string][]map[string]any{
		"security_crs_version":       {{"id": 1, "version": "v1", "update_status": "downloading", "message": "正在下载"}},
		"security_ip2region_version": {{"id": 1, "version": "v1", "update_status": "installing"}},
		"security_threat_sources":    {{"id": 1, "name": "ustc", "update_status": "running", "message": "下载中"}},
		"security_crawler_sources":   {{"id": 1, "name": "googlebot", "update_status": "reloading"}},
	}

	// When
	warnings := normalizeImportedVersionUpdateStatuses(tables)

	// Then 四行活动态全部归一为 failed，且只产出一条「活动态」汇总警告
	//（不得再附加失实的「不在词表内」告警）。
	for _, table := range []string{"security_crs_version", "security_ip2region_version", "security_threat_sources", "security_crawler_sources"} {
		if got := tables[table][0]["update_status"]; got != string(services.CRSStatusFailed) {
			t.Fatalf("%s.update_status=%v, want failed（活动态只属执行进程）", table, got)
		}
	}
	if len(warnings) != 1 || !strings.Contains(zhWarning(warnings[0]), "4 条版本/源记录") || !strings.Contains(zhWarning(warnings[0]), "「更新中」活动态") {
		t.Fatalf("warnings=%v, want 单条「4 条…「更新中」活动态」", warnings)
	}
	if strings.Contains(zhWarning(warnings[0]), "不在词表内") {
		t.Fatalf("warnings=%v 不得把合法活动词报成词表外值", warnings)
	}
	// Then 带 message 列的行写入归属文案（不得保留活动态原文案）；键缺席的行
	// 不得被补写。
	if got := tables["security_crs_version"][0]["message"]; got == "正在下载" || got == "" {
		t.Fatalf("crs message=%v, want 归一后的归属文案（不得保留活动态原文案）", got)
	}
	if _, exists := tables["security_ip2region_version"][0]["message"]; exists {
		t.Fatal("message 键缺席的行不得被补写")
	}

	// Then 词表单源：源表活动词 running 属于合法词表值（不被归一为 idle），
	// 终态词同样原样保留且不产生告警。
	if got := services.NormalizeVersionUpdateStatus("running"); got != "running" {
		t.Fatalf(`NormalizeVersionUpdateStatus("running")=%q, want running（源表合法活动词）`, got)
	}
	if warnings := normalizeImportedVersionUpdateStatuses(map[string][]map[string]any{
		"security_threat_sources": {{"id": 1, "name": "ustc", "update_status": "success"}},
	}); len(warnings) != 0 {
		t.Fatalf("终态值不应产生警告: %v", warnings)
	}
}

// 端到端：备份携带活动的源表状态导入后落库为 failed，且响应 warnings 点名
// 「进行中」归一（与 status/读侧投影同一结论，不再出现「更新中」残留）。
func TestImportConfigBackup_normalizesCarriedActiveSourceStatus(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'current-admin','hash','admin',1)`); err != nil {
		t.Fatalf("seed current admin: %v", err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)

	body := buildBackup(t, backupFixtureOptions{
		Sections: []string{"security"},
		Tables: map[string][]map[string]any{
			"security_crawler_sources": {{"id": 1, "name": "googlebot", "update_status": "running"}},
			"security_policies":        {},
			"security_policy_bindings": {},
			"security_custom_rules":    {},
			"security_block_pages":     {},
			"security_ip_lists":        {},
		},
		EmptyConfigIfNil: true,
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "「更新中」活动态") {
		t.Fatalf("body=%s, want 活动态归一警告", recorder.Body.String())
	}
	var crawlerStatus string
	if err := db.DB.QueryRow(`SELECT update_status FROM security_crawler_sources WHERE name='googlebot'`).Scan(&crawlerStatus); err != nil {
		t.Fatalf("read crawler source status: %v", err)
	}
	if crawlerStatus != string(services.CRSStatusFailed) {
		t.Fatalf("crawler update_status=%q, want failed（活动态不得随备份落库）", crawlerStatus)
	}
}
