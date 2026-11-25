package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/i18n"
)

// 导入/还原的预览与结果 warnings、冲突明细、安全事件行的保留提示走词条。
//
// 2026-11-25 项目所有者裁定（web/docs/I18N.md 第 0 节）：后端只下发稳定键 + 参数，
// 文案只归前端。因此本文件的判据从「英文请求返回英文」改为两条更强的断言：
//   1. 响应与 Accept-Language 无关——同一请求带 zh-CN 与 en 的响应体逐字相同；
//   2. 响应用的是中文母本（词条目录），操作审计明细同样恒为中文母本。
// 英文界面由前端按 message_key 取自己的词条渲染（web/tests/apiMessagesParity.spec.ts
// 钉住键集合双向对等）。

var importCJKPattern = regexp.MustCompile(`\p{Han}`)

// zhWarnings / zhWarning 把告警事实按中文母本渲染——既有用例直测产出函数时
// 断言的中文字面量不变，只是取词方式从字符串改为事实渲染。
func zhWarnings(warnings importWarnings) []string { return warnings.render() }

func zhWarning(warning importWarning) string { return warning.render() }

// catalogZH 返回字面量作为词条键时的中文母本；不是键或未登记时返回空串。
func catalogZH(literal string) string {
	if !i18n.IsMessageKey(literal) {
		return ""
	}
	zh := i18n.T(literal)
	if zh == literal {
		return ""
	}
	return zh
}

type importLanguageEnvelope struct {
	// status 是 HTTP 状态码（响应体 code 成功时恒为 0，两者不可混用）。
	status  int
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Valid             bool                   `json:"valid"`
		Error             string                 `json:"error"`
		Warnings          []string               `json:"warnings"`
		DisabledConflicts []disabledRuleConflict `json:"disabled_conflicts"`
	} `json:"data"`
}

// postImportRaw 以指定 Accept-Language 调用端点，返回原始响应体（用于跨语言逐字比对）。
func postImportRaw(t *testing.T, router *gin.Engine, method, path, body, lang string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Language", lang)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// volatileTempSuffix 归一化响应里的一次性临时文件名（os.CreateTemp 生成的随机后缀）：
// 同一请求两次执行会得到不同的临时名，那不是语言差异，也不是可重复的响应内容。
var volatileTempSuffix = regexp.MustCompile(`-[0-9]+\.tmp`)

func normalizeVolatile(body string) string {
	return volatileTempSuffix.ReplaceAllString(body, "-N.tmp")
}

// assertLanguageIndependent 对同一请求分别带 zh-CN 与 en 各打一次（run 负责为每次调用
// 准备**独立**的 handler/router：导入类端点会写库，共享实例会让第二次请求看到已变更的状态，
// 那不是语言差异），要求状态码与响应体逐字相同：后端不再按请求语言渲染。
func assertLanguageIndependent(t *testing.T, run func(lang string) (int, string)) (int, string) {
	t.Helper()
	zhStatus, zhBody := run("zh-CN")
	enStatus, enBody := run("en")
	if zhStatus != enStatus {
		t.Fatalf("状态码随 Accept-Language 变化: zh=%d en=%d", zhStatus, enStatus)
	}
	if normalizeVolatile(zhBody) != normalizeVolatile(enBody) {
		t.Fatalf("响应体随 Accept-Language 变化（后端不得按语言渲染）:\n zh: %s\n en: %s", zhBody, enBody)
	}
	return zhStatus, zhBody
}

// assertLanguageIndependentEnvelope 同 assertLanguageIndependent，并把响应解析成导入类信封。
func assertLanguageIndependentEnvelope(t *testing.T, run func(lang string) (int, string)) importLanguageEnvelope {
	t.Helper()
	status, body := assertLanguageIndependent(t, run)
	envelope := importLanguageEnvelope{status: status}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		t.Fatalf("解析响应失败: %v (body=%s)", err, body)
	}
	return envelope
}

func conflictReasonTexts(conflicts []disabledRuleConflict) []string {
	var texts []string
	for _, conflict := range conflicts {
		texts = append(texts, conflict.Reason)
		for _, opponent := range conflict.ConflictsWith {
			texts = append(texts, opponent.Reason)
		}
	}
	return texts
}

func assertWarningsContainAll(t *testing.T, warnings []string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !warningsContain(warnings, want) {
			t.Errorf("warnings 缺少 %q: %v", want, warnings)
		}
	}
}

// warningRichBackupJSON 一份能触发尽量多告警面的纯 JSON 备份：跨版本、空域名
// 规则及其策略绑定、空内容拦截页、版本/源状态归一（活动态与词表外值）、冲突
// 规则、全局配置钳制与自动封禁钳制。
func warningRichBackupJSON(t *testing.T) string {
	t.Helper()
	backup := buildBackupStruct(t, backupFixtureOptions{
		FillAll: true,
		Tables: map[string][]map[string]any{
			"lb_rules": {
				{"caddy_id": "lb_dup_a", "name": "dup-a", "protocol": "http", "domain": "dup.example.test", "listen_port": 18081, "enabled": true},
				{"caddy_id": "lb_dup_b", "name": "dup-b", "protocol": "http", "domain": "dup.example.test", "listen_port": 18081, "enabled": true},
				{"caddy_id": "lb_empty", "name": "", "protocol": "http", "domain": "", "listen_port": 18082, "enabled": true},
			},
			"security_policy_bindings": {{"id": 1, "policy_id": 1, "rule_caddy_id": "lb_empty"}},
			"security_block_pages":     {{"id": 7, "name": "", "content": "   "}},
			"security_threat_sources":  {{"id": 1, "name": "ustc", "update_status": "running"}},
			"security_crawler_sources": {{"id": 1, "name": "googlebot", "update_status": "unknown-status"}},
			"security_crs_version":     {{"id": 1, "version": "v1", "update_status": "downloading"}},
		},
		Config: map[string]any{
			"jwt_expire_minutes":       99999,
			"autoban_threshold":        0,
			"request_body_max_size_mb": "abc",
		},
	})
	backup.Meta.AppVersion = "v0.0.1"
	return marshalJSONForTest(t, backup)
}

// warningRichBackupSharedZHFragments 纯 JSON 备份在预览与导入响应里都必然出现
// 的中文母本（证明各产生点被夹具真实触发，而非因零文案空过守卫）。
func warningRichBackupSharedZHFragments() []string {
	return []string{
		"纯 JSON 备份不携带威胁名单文件，已保留本地威胁源配置与名单",
		"规则 lb_empty 的域名为空，已跳过导入",
		"1 条安全策略绑定随空域名规则一并跳过",
		"拦截页面 #7 的内容为空，已跳过导入",
		"条版本/源记录携带「更新中」活动态，导入节点不执行该任务，已归一为 failed",
		"条版本/源记录的 update_status 不在词表内，已归一为 idle",
		"备份导出产品版本为 v0.0.1，当前运行版本为 v9.9.9——跨版本还原可能存在兼容性差异，请确认后继续",
		"备份不含规则库数据文件——规则库版本记录已跳过（仅 lbbak 完整备份可导入该类）",
	}
}

// warningRichBackupPreviewOnlyZHFragments 只在预览响应出现的中文母本：操作者
// 缺席的预览口径与两类钳制说明（导入侧的钳制说明只进操作审计）。
func warningRichBackupPreviewOnlyZHFragments() []string {
	return []string{
		"备份不包含当前操作账户——若导入时勾选“系统数据”，导入后请使用备份内的管理员账户登录",
		"jwt_expire_minutes 越界，已重置为 20",
		"autoban_threshold 越界（0），已钳位为 1",
		"request_body_max_size_mb 非法形态（abc），已归一为 128",
	}
}

func TestValidateConfigImport_warningsAreLanguageIndependentChineseMother(t *testing.T) {
	body := warningRichBackupJSON(t)
	response := assertLanguageIndependentEnvelope(t, func(lang string) (int, string) {
		h := newAutoBackupTestHandlers(t)
		h.cfg.Version = "v9.9.9"
		router := languageRouter("current-admin")
		router.POST("/config/import/validate", h.ValidateConfigImport)
		return postImportRaw(t, router, http.MethodPost, "/config/import/validate", body, lang)
	})
	if response.status != http.StatusOK || !response.Data.Valid {
		t.Fatalf("预览未通过: status=%d valid=%v error=%q", response.status, response.Data.Valid, response.Data.Error)
	}
	reasons := conflictReasonTexts(response.Data.DisabledConflicts)
	if len(response.Data.DisabledConflicts) != 2 || len(reasons) == 0 {
		t.Fatalf("冲突明细未触发: %+v", response.Data.DisabledConflicts)
	}
	assertWarningsContainAll(t, response.Data.Warnings, append(warningRichBackupSharedZHFragments(), warningRichBackupPreviewOnlyZHFragments()...)...)
	assertWarningsContainAll(t, reasons, "HTTP 域名 dup.example.test 重复")
	// 顺序与逐字形态钉住：软跳过三条在前，其后是拦截页跳过与版本状态归一。
	wantHead := []string{
		"纯 JSON 备份不携带威胁名单文件，已保留本地威胁源配置与名单",
		"规则 lb_empty 的域名为空，已跳过导入",
		"1 条安全策略绑定随空域名规则一并跳过",
		"拦截页面 #7 的内容为空，已跳过导入",
	}
	if len(response.Data.Warnings) < len(wantHead) {
		t.Fatalf("warnings=%v", response.Data.Warnings)
	}
	for index, want := range wantHead {
		if got := response.Data.Warnings[index]; got != want {
			t.Errorf("warnings[%d]=%q, want 中文母本逐字不变 %q", index, got, want)
		}
	}
}

// 史前（结构版本 1）备份不含完整性校验和：预览必须披露内容未经摘要校验。
func TestValidateConfigImport_legacyNoChecksumWarningLanguageIndependent(t *testing.T) {
	backup := buildBackupStruct(t, backupFixtureOptions{FillAll: true, EmptyConfigIfNil: true})
	backup.Meta.Version = 1
	backup.Meta.Checksum = ""
	body := marshalJSONForTest(t, backup)
	response := assertLanguageIndependentEnvelope(t, func(lang string) (int, string) {
		h := newAutoBackupTestHandlers(t)
		router := languageRouter("")
		router.POST("/config/import/validate", h.ValidateConfigImport)
		return postImportRaw(t, router, http.MethodPost, "/config/import/validate", body, lang)
	})
	if response.status != http.StatusOK || !response.Data.Valid {
		t.Fatalf("预览未通过: status=%d valid=%v error=%q", response.status, response.Data.Valid, response.Data.Error)
	}
	assertWarningsContainAll(t, response.Data.Warnings, "备份不含完整性校验和（史前版本导出），已按结构性校验导入——文件内容未经摘要校验，建议尽快用当前版本重新导出备份")
}

func TestImportConfigBackup_warningsAreLanguageIndependentChineseMother(t *testing.T) {
	body := warningRichBackupJSON(t)
	response := assertLanguageIndependentEnvelope(t, func(lang string) (int, string) {
		h := newAutoBackupTestHandlers(t)
		h.cfg.DataDir = t.TempDir()
		h.cfg.Version = "v9.9.9"
		router := languageRouter("current-admin")
		router.POST("/config/import", h.ImportConfigBackup)
		return postImportRaw(t, router, http.MethodPost, "/config/import", body, lang)
	})
	if response.status != http.StatusOK {
		t.Fatalf("导入未成功: status=%d message=%q", response.status, response.Message)
	}
	reasons := conflictReasonTexts(response.Data.DisabledConflicts)
	if len(reasons) == 0 {
		t.Fatalf("冲突明细未触发: %+v", response.Data.DisabledConflicts)
	}
	assertWarningsContainAll(t, response.Data.Warnings, append(warningRichBackupSharedZHFragments(),
		"备份不含当前操作账户——系统数据已替换，请使用备份内的管理员账户登录")...)
	if warningsContain(response.Data.Warnings, "jwt_expire_minutes") {
		t.Errorf("导入响应不得出现钳制说明（该说明只进操作审计）: %v", response.Data.Warnings)
	}
	// 操作审计明细恒为中文母本（与界面语言无关，因为后端已无语言概念）。
	for _, want := range []string{
		"跳过警告：纯 JSON 备份不携带威胁名单文件，已保留本地威胁源配置与名单；规则 lb_empty 的域名为空，已跳过导入；1 条安全策略绑定随空域名规则一并跳过",
		"jwt_expire_minutes 越界，已重置为 20",
		"autoban_threshold 越界（0），已钳位为 1",
		"冲突置为禁用：dup-a（冲突对象：dup-b：HTTP 域名 dup.example.test 重复）",
	} {
		var auditCount int
		if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE resource='配置备份' AND detail LIKE ?`, "%"+want+"%").Scan(&auditCount); err != nil {
			t.Fatalf("读取审计: %v", err)
		}
		if auditCount == 0 {
			t.Errorf("操作审计未保留中文母本: %q", want)
		}
	}
}

// v1WarningRichBackupJSON 一份能触发转换警告、软跳过与归一说明的 v1（nginx）
// 备份：负载策略无法映射、空域名规则、健康检查间隔过短、禁用且空证书、
// HTTP 规则上游协议归一、同域名同端口冲突。
func v1WarningRichBackupJSON() string {
	proxy := func(pk int, name string, listen int, serverName string, extra string) string {
		return fmt.Sprintf(`{"pk":%d,"fields":{"proxy_name":%q,"protocol":true,"listen":%d,"server_name":%q,"status":true,"fail_timeout":1,"upstream_list":[%d]%s}}`,
			pk, name, listen, serverName, pk, extra)
	}
	upstream := func(pk int) string {
		return fmt.Sprintf(`{"pk":%d,"fields":{"status":true,"address":"127.0.0.1","port":%d,"weight":100}}`, pk, 19000+pk)
	}
	return fmt.Sprintf(`{
		"proxy_config":{"config":[
			%s,
			%s,
			%s,
			%s
		]},
		"upstream_config":{"config":[
			%s,
			%s,
			%s,
			%s
		]}
	}`,
		proxy(1, "v1-mystery", 18561, "v1-mystery.example.test", `,"balancer_type":"mystery","ssl":true,"backend_protocol":"tcp","status":false`),
		proxy(2, "v1-empty", 18562, "", ""),
		proxy(3, "v1-dup-a", 18563, "v1-dup.example.test", ""),
		proxy(4, "v1-dup-b", 18563, "v1-dup.example.test", ""),
		upstream(1), upstream(2), upstream(3), upstream(4),
	)
}

func TestValidateConfigImport_v1WarningsAreLanguageIndependentChineseMother(t *testing.T) {
	body := v1WarningRichBackupJSON()
	response := assertLanguageIndependentEnvelope(t, func(lang string) (int, string) {
		h := newBackupTestHandlers(t)
		router := languageRouter("")
		router.POST("/config/import/validate", h.ValidateConfigImport)
		return postImportRaw(t, router, http.MethodPost, "/config/import/validate", body, lang)
	})
	if response.status != http.StatusOK || !response.Data.Valid {
		t.Fatalf("v1 预览未通过: status=%d valid=%v error=%q warnings=%v", response.status, response.Data.Valid, response.Data.Error, response.Data.Warnings)
	}
	reasons := conflictReasonTexts(response.Data.DisabledConflicts)
	if len(reasons) == 0 {
		t.Fatalf("v1 冲突明细未触发: %+v", response.Data.DisabledConflicts)
	}
	assertWarningsContainAll(t, response.Data.Warnings,
		"仅导入负载规则（用户、全局配置不导入；旧规则的证书任务、证书材料与日志将随规则替换一并清理）",
		`规则 v1-mystery 的负载策略 "mystery" 无法映射，已使用 weighted_round_robin`,
		"规则 v1-empty 的域名为空，已跳过导入",
		"规则 #1（v1-mystery）上游 #1：HTTP 规则上游协议 tcp 已按 http 导入",
		"规则 #1（v1-mystery）：v1 健康检查间隔过短，已提为 ",
		"规则 #1（v1-mystery）：规则为禁用状态且证书/私钥为空，已按关闭 TLS 导入（证书可后续补齐再启用）")
	assertWarningsContainAll(t, reasons, "HTTP 域名 v1-dup.example.test 重复")
}

// 备份历史还原与文件导入共用导入核心，动作词为「还原」。
func TestRestoreAutoBackup_warningsAreLanguageIndependentChineseMother(t *testing.T) {
	response := assertLanguageIndependentEnvelope(t, func(lang string) (int, string) {
		h := newAutoBackupTestHandlers(t)
		h.cfg.DataDir = t.TempDir()
		payload, _, _, _, err := h.buildLbbakExport(context.Background(), []string{"users"})
		if err != nil {
			t.Fatalf("构建 lbbak: %v", err)
		}
		name := "lbbak-restore-language.lbbak"
		if err := os.WriteFile(filepath.Join(h.cfg.BackupDir, name), payload, 0o644); err != nil {
			t.Fatal(err)
		}
		row, err := db.DB.Exec(`INSERT INTO auto_backups (filename, status, trigger_type) VALUES (?, 'success', 'manual')`, name)
		if err != nil {
			t.Fatalf("登记备份行: %v", err)
		}
		id, _ := row.LastInsertId()
		router := languageRouter("admin")
		router.POST("/auto-backup/:id/restore", h.RestoreAutoBackup)
		return postImportRaw(t, router, http.MethodPost, fmt.Sprintf("/auto-backup/%d/restore", id), "", lang)
	})
	if response.status != http.StatusOK {
		t.Fatalf("还原未成功: status=%d message=%q", response.status, response.Message)
	}
	assertWarningsContainAll(t, response.Data.Warnings, "系统数据已还原：全部登录会话已吊销，请重新登录")
}

// lbbak 包内 manifest 未登记的威胁库条目：预览告警。
func TestValidateConfigImport_lbbakUnregisteredThreatWarningsLanguageIndependent(t *testing.T) {
	backupJSON := buildBackup(t, backupFixtureOptions{FillAll: true, EmptyConfigIfNil: true})
	body := string(buildLbbakWithExtraThreatEntry(t, backupJSON, []byte("1.2.3.4\n")))
	response := assertLanguageIndependentEnvelope(t, func(lang string) (int, string) {
		h := newBackupTestHandlers(t)
		router := languageRouter("")
		router.POST("/config/import/validate", h.ValidateConfigImport)
		return postImportRaw(t, router, http.MethodPost, "/config/import/validate", body, lang)
	})
	if response.status != http.StatusOK || !response.Data.Valid {
		t.Fatalf("lbbak 预览未通过: status=%d valid=%v error=%q", response.status, response.Data.Valid, response.Data.Error)
	}
	assertWarningsContainAll(t, response.Data.Warnings,
		"lbbak 含威胁库名单文件（完整性已校验）——导入「安全防护」将落盘名单文件；本包不含 CRS/IP2Region 数据文件",
		"lbbak 含 manifest 未登记的威胁库条目（threat/ustc.iplist）——内容未经完整性校验，已按原样落盘；建议核实来源后重新导出备份")
}

func TestGetLogStats_securityEventsRetentionNoteLanguageIndependent(t *testing.T) {
	status, body := assertLanguageIndependent(t, func(lang string) (int, string) {
		h := newBackupTestHandlers(t)
		router := languageRouter("")
		router.GET("/logs/stats", h.GetLogStats)
		return postImportRaw(t, router, http.MethodGet, "/logs/stats?key=security_events", "", lang)
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var resp struct {
		Data struct {
			Logs []struct {
				Key           string `json:"key"`
				RetentionNote string `json:"retention_note"`
				LimitRows     *int64 `json:"limit_rows"`
			} `json:"logs"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Data.Logs) != 1 || resp.Data.Logs[0].Key != "security_events" {
		t.Fatalf("logs=%+v, want exactly security_events row", resp.Data.Logs)
	}
	row := resp.Data.Logs[0]
	if !strings.HasPrefix(row.RetentionNote, fmt.Sprintf("每日清理 · 保留 %d 天 / 上限 %d 行", db.DefaultSecurityEventsRetentionDays, db.DefaultSecurityEventsRowCap)) {
		t.Errorf("retention_note=%q, want 中文母本", row.RetentionNote)
	}
	if row.LimitRows == nil || *row.LimitRows != int64(db.DefaultSecurityEventsRowCap) {
		t.Errorf("limit_rows=%v, want %d", row.LimitRows, db.DefaultSecurityEventsRowCap)
	}
}

// 词条守卫：导入/还原告警面与安全事件行提示用到的每个键都已登记，且中文母本
// 模板里的 fmt 动词数不超过实参数——模板经 fmt.Sprintf 渲染，多传会输出
// %!(EXTRA …)、少传会输出 %!s(MISSING)。
// 英文译文的动词对齐归前端守卫（后端不再登记译文）。
func TestImportWarningCatalog_keysRegisteredAndVerbsAligned(t *testing.T) {
	files := []string{
		"config_backup.go", "config_import_chain.go", "config_import_v1.go",
		"config_backup_lbbak.go", "config_import_coordinator.go", "helpers.go", "logstats.go",
		"../services/autoban.go", "../services/securityevents_retention.go",
	}
	fset := token.NewFileSet()
	checked := 0
	for _, path := range files {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			key, err := strconv.Unquote(literal.Value)
			if err != nil || !i18n.IsMessageKey(key) {
				return true
			}
			zh := i18n.T(key)
			// 形态像键但未登记的，是 manifest.json / caddy.log 这类文件名字面量——语义键与
			// 文件名同为「小写.小写」形态，只看形态分不出来。是否登记由全仓守卫
			// TestMessageKeyUses_areRegistered 负责；这里只管已登记词条的中文母本形态。
			if zh == key {
				return true
			}
			checked++
			// 中文母本可以是纯符号模板（"%s"、"IP：%s"）：不含汉字的形态由
			// internal/i18n 的 noHanChineseMother 基线钉住，这里不再重复判。
			return true
		})
	}
	if checked < 100 {
		t.Fatalf("仅核对了 %d 个词条引用——扫描面漂移", checked)
	}
}

// 传参点槽数对账：importWarn、lbbakWafApplyResult.warn 与 services 侧 say 的
// 实参数必须等于所引词条中文母本的动词数——模板经 fmt.Sprintf 渲染，多传会输出
// %!(EXTRA …)、少传会输出 %!s(MISSING)。
func TestImportWarningCallSites_argsMatchTemplateSlots(t *testing.T) {
	files := []string{
		"config_backup.go", "config_import_chain.go", "config_import_v1.go",
		"config_backup_lbbak.go", "config_import_coordinator.go", "helpers.go",
		"../services/autoban.go",
	}
	fset := token.NewFileSet()
	checked := 0
	for _, path := range files {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || call.Ellipsis != token.NoPos {
				return true
			}
			var keyArg ast.Expr
			args := 0
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				if (fun.Name == "importWarn" || fun.Name == "say") && len(call.Args) >= 1 {
					keyArg, args = call.Args[0], len(call.Args)-1
				}
			case *ast.SelectorExpr:
				if fun.Sel.Name == "warn" && len(call.Args) >= 3 {
					keyArg, args = call.Args[2], len(call.Args)-3
				}
			}
			if keyArg == nil {
				return true
			}
			for _, key := range warningKeysOf(keyArg) {
				template := i18n.T(key)
				if template == key {
					continue // 未登记的键由词条守卫报告
				}
				checked++
				if slots := len(fmtVerbs(template)); slots != args {
					t.Errorf("%s: 传 %d 参，词条 %s（zh=%q）有 %d 个槽", fset.Position(call.Pos()), args, key, template, slots)
				}
			}
			return true
		})
	}
	if checked < 100 {
		t.Fatalf("仅核对了 %d 个传参点——扫描面漂移", checked)
	}
}

// warningKeysOf 取传参点的词条键：字面量，或 importActionKey(action, 导入键,
// 还原键) 的两个键；解析不出键时返回 nil。
func warningKeysOf(expr ast.Expr) []string {
	switch node := expr.(type) {
	case *ast.BasicLit:
		key, err := strconv.Unquote(node.Value)
		if err != nil {
			return nil
		}
		return []string{key}
	case *ast.CallExpr:
		if ident, ok := node.Fun.(*ast.Ident); ok && ident.Name == "importActionKey" && len(node.Args) == 3 {
			var keys []string
			for _, arg := range node.Args[1:] {
				keys = append(keys, warningKeysOf(arg)...)
			}
			return keys
		}
	}
	return nil
}

// fmtVerbs 列出模板里的 fmt 动词（%% 是转义的百分号字面量，不计）。
func fmtVerbs(template string) []string {
	var verbs []string
	for index := 0; index < len(template); index++ {
		if template[index] != '%' {
			continue
		}
		if index+1 < len(template) && template[index+1] == '%' {
			index++
			continue
		}
		end := index + 1
		for end < len(template) && !isASCIILetter(template[end]) {
			end++
		}
		if end < len(template) {
			verbs = append(verbs, template[index:end+1])
			index = end
		}
	}
	return verbs
}

func isASCIILetter(char byte) bool {
	return (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z')
}
