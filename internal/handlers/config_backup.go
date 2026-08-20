package handlers

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

var configBackupTables = []string{"lb_rules", "upstreams", "path_rules", "users", "api_keys", "ca_providers", "certificate_configs", "cert_jobs", "security_policies", "security_policy_bindings", "security_custom_rules", "security_block_pages", "security_crs_version", "security_ip2region_version"}
var configBackupV1Tables = []string{"lb_rules", "upstreams", "users", "api_keys", "ca_providers", "certificate_configs", "cert_jobs"}

var configBackupCertJobStatuses = map[string]struct{}{
	"queued": {}, "pending": {}, "processing": {}, "creating_account": {}, "creating_order": {}, "order_created": {},
	"cleanup_dns": {}, "cleanup_warning": {}, "presenting_dns": {}, "waiting_propagation": {}, "dns_propagated": {},
	"accepting_challenge": {}, "validating": {}, "validated": {}, "finalizing": {}, "finalized": {}, "downloading": {},
	"downloaded": {}, "issued": {}, "failed": {}, "waiting_ca": {}, "disabled": {}, "waiting_order_ready": {}, "order_ready": {},
	"waiting_order_valid": {}, "order_valid": {},
}

var configBackupProtectedConfigKeys = map[string]bool{
	"id": true, "is_master": true, "master_url": true, "cluster_token": true,
	"registration_id": true, "registration_secret": true, "applied_version": true,
	"sync_fingerprint": true, "last_sync": true, "last_sync_error": true, "cluster_version": true,
}

var requeueNonTerminalCertJobs = services.RequeueNonTerminalCertJobs

type importQueueRecovery struct {
	manager *services.CAQueueManager
	done    bool
}

func (recovery *importQueueRecovery) finish() error {
	if recovery.manager == nil || recovery.done {
		return nil
	}
	recovery.done = true
	recovery.manager.Resume()
	return requeueNonTerminalCertJobs()
}

func finishImportFailure(tx *sql.Tx, recovery *importQueueRecovery, importErr error) error {
	if tx != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			importErr = errors.Join(importErr, rollbackErr)
		}
	}
	return errors.Join(importErr, recovery.finish())
}

type configBackup struct {
	Meta   configBackupMeta            `json:"meta"`
	Config map[string]any              `json:"config"`
	Tables map[string][]map[string]any `json:"tables"`
}

type configBackupMeta struct {
	App        string `json:"app"`
	Version    int    `json:"version"`
	ExportedAt string `json:"exported_at"`
	Checksum   string `json:"checksum,omitempty"`
}

type tableQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func dumpTable(ctx context.Context, database tableQuerier, table string) ([]map[string]any, error) {
	return queryRowsAsMaps(ctx, database, rowQuery{label: "表 " + table, query: "SELECT * FROM " + table})
}

func tableColumns(ctx context.Context, database *sql.DB, table string) (map[string]bool, error) {
	rows, err := database.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, columnType string
		var notNull int
		var defaultValue any
		var pk int
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &pk); err != nil {
			return nil, err
		}
		columns[name] = true
	}
	return columns, rows.Err()
}

func restoreTable(ctx context.Context, tx *sql.Tx, database *sql.DB, table string, rows []map[string]any) error {
	valid, err := tableColumns(ctx, database, table)
	if err != nil {
		return fmt.Errorf("读取表结构 %s: %w", table, err)
	}
	for _, row := range rows {
		columns := make([]string, 0, len(row))
		placeholders := make([]string, 0, len(row))
		values := make([]any, 0, len(row))
		for column, value := range row {
			if !valid[column] {
				continue
			}
			columns = append(columns, `"`+column+`"`)
			placeholders = append(placeholders, "?")
			values = append(values, value)
		}
		if len(columns) == 0 {
			continue
		}
		query := "INSERT INTO " + table + " (" + joinStrings(columns, ",") + ") VALUES (" + joinStrings(placeholders, ",") + ")"
		if _, err := tx.ExecContext(ctx, query, values...); err != nil {
			return fmt.Errorf("写入表 %s: %w", table, err)
		}
	}
	return nil
}

func joinStrings(parts []string, sep string) string {
	out := ""
	for i, part := range parts {
		if i > 0 {
			out += sep
		}
		out += part
	}
	return out
}

type importRuntimeSnapshot struct {
	caddyConfig map[string]interface{}
	certFiles   services.CertFilesSnapshot
}

type importCertificate struct {
	ruleID  string
	certPEM string
	keyPEM  string
}

func currentRuleIDs(ctx context.Context) ([]string, error) {
	rows, err := db.DB.QueryContext(ctx, "SELECT caddy_id FROM lb_rules")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ruleIDs := make([]string, 0)
	for rows.Next() {
		var ruleID string
		if err := rows.Scan(&ruleID); err != nil {
			return nil, err
		}
		ruleIDs = append(ruleIDs, ruleID)
	}
	return ruleIDs, rows.Err()
}

func (h *Handlers) snapshotImportRuntime(ruleIDs []string) (importRuntimeSnapshot, error) {
	caddyConfig, err := h.caddyService.GetConfig()
	if err != nil {
		return importRuntimeSnapshot{}, fmt.Errorf("读取当前 Caddy 配置: %w", err)
	}
	certFiles, err := services.SnapshotCertFiles(ruleIDs)
	if err != nil {
		return importRuntimeSnapshot{}, err
	}
	return importRuntimeSnapshot{caddyConfig: caddyConfig, certFiles: certFiles}, nil
}

func (h *Handlers) restoreImportRuntime(snapshot importRuntimeSnapshot) error {
	certErr := services.RestoreCertFiles(snapshot.certFiles)
	caddyErr := h.caddyService.ApplyConfig(snapshot.caddyConfig)
	return errors.Join(caddyErr, certErr)
}

func materializeImportCertificates(certificates []importCertificate) error {
	for _, certificate := range certificates {
		if err := validateTLSCertificate(certificate.certPEM, certificate.keyPEM); err != nil {
			return fmt.Errorf("验证规则 %s 的证书: %w", certificate.ruleID, err)
		}
		if err := services.WriteCertFiles(certificate.ruleID, certificate.certPEM, certificate.keyPEM); err != nil {
			return fmt.Errorf("写入规则 %s 的证书文件: %w", certificate.ruleID, err)
		}
	}
	return nil
}

// normalizeBackupBooleanNulls 把 pre-R24/pre-R36 库导出的 NULL 布尔行归一为当前表结构
// 要求的非空值（lb_rules/upstreams.enabled NULL→0、users.is_enabled NULL→1），与
// R36/R24 迁移口径一致（用户缺省启用，规则/上游缺省禁用）。
// 必须在 checksum 校验之后执行（checksum 覆盖原始内容，先归一会让自带校验和的备份
// 全部误报篡改），并在管理员校验之前执行（backupBooleanEnabled(nil)=false 会把
// 全 null 管理员备份先行 400 拦截，归一不可达——R39-C-1）。
func normalizeBackupBooleanNulls(tables map[string][]map[string]any) {
	for _, table := range []string{"lb_rules", "upstreams"} {
		for _, row := range tables[table] {
			if enabled, exists := row["enabled"]; exists && enabled == nil {
				row["enabled"] = 0
			}
		}
	}
	for _, row := range tables["users"] {
		if enabled, exists := row["is_enabled"]; exists && enabled == nil {
			row["is_enabled"] = 1
		}
	}
}

// validateBackupRuleReferences 写入前校验跨表引用均存在于备份自带的数据：
// upstreams/path_rules 的 rule_id ∈ lb_rules（悬挂引用靠 FK 在删表后以 500 回滚兜底，
// 与 cert_jobs 的显式清理语义不一致；提前转为 400 校验错误，保证校验不过零写入），
// 以及 security_policy_bindings 的 rule_caddy_id ∈ lb_rules、policy_id ∈ security_policies
// （该表无外键，无 FK 兜底，见 R49 C-#2）。
func validateBackupRuleReferences(tables map[string][]map[string]any) error {
	ruleIDs := make(map[string]struct{}, len(tables["lb_rules"]))
	for _, row := range tables["lb_rules"] {
		if id, ok := row["caddy_id"].(string); ok {
			ruleIDs[id] = struct{}{}
		}
	}
	for _, table := range []string{"upstreams", "path_rules"} {
		for i, row := range tables[table] {
			ruleID, _ := row["rule_id"].(string)
			if _, exists := ruleIDs[ruleID]; !exists {
				return fmt.Errorf("备份校验失败：%s 第 %d 行引用了不存在的规则 %q", table, i+1, ruleID)
			}
		}
	}
	// R49 C-#2：security_policy_bindings 无外键约束，悬挂引用可原样落库——绑定指向
	// 不存在的策略时，loadSecurityPolicyContext 查不到策略即按无策略渲染，该规则
	// WAF/限流/GeoIP 全部静默失效（与 R47 B-5 同类的静默 weakening）。保存侧绑定
	// 要求策略与规则均存在，导入校验须同严。
	policyIDs := make(map[int]struct{}, len(tables["security_policies"]))
	for _, row := range tables["security_policies"] {
		if id, ok := backupInteger(row["id"]); ok {
			policyIDs[id] = struct{}{}
		}
	}
	for i, row := range tables["security_policy_bindings"] {
		ruleID, _ := row["rule_caddy_id"].(string)
		if _, exists := ruleIDs[ruleID]; !exists {
			return fmt.Errorf("备份校验失败：security_policy_bindings 第 %d 行引用了不存在的规则 %q", i+1, ruleID)
		}
		policyID, ok := backupInteger(row["policy_id"])
		if !ok {
			return fmt.Errorf("备份校验失败：security_policy_bindings 第 %d 行 policy_id 必须为整数", i+1)
		}
		if _, exists := policyIDs[policyID]; !exists {
			return fmt.Errorf("备份校验失败：security_policy_bindings 第 %d 行引用了不存在的安全策略 %d", i+1, policyID)
		}
	}
	return nil
}

// validateV2Backup 校验 v2 备份结构与完整性。返回 usedLegacyChecksum=true 表示
// 走了旧格式（仅 tables）校验和回退——调用方应记审计警告（R43 F-D）。
func validateV2Backup(backup configBackup) (bool, error) {
	if backup.Meta.App != "lazy-balancer-v2" || backup.Tables == nil {
		return false, errors.New("不是有效的 Lazy Balancer 备份文件")
	}
	if backup.Meta.Version != 1 && backup.Meta.Version != 2 {
		return false, fmt.Errorf("不支持的备份版本: %d", backup.Meta.Version)
	}
	if backup.Config == nil {
		return false, errors.New("备份缺少全局配置")
	}
	// R45 F-3: v2 备份必带导出时间戳与校验和（v2.1.1 起导出即两者齐备）。剥掉
	// exported_at 或 checksum 的 v2 文件一律按不兼容拒绝——旧格式校验和回退仅限
	// Version==1 的史前导出，防止 Config 区（dns_credentials/acme_email/管理面板
	// TLS 材料）借字段剥离绕过完整性校验。
	if backup.Meta.Version == 2 && backup.Meta.ExportedAt == "" {
		return false, errors.New("备份由 v2.1.1 或更早版本导出，校验和格式不兼容，请使用 v2.1.2 及以上版本重新导出后再导入")
	}
	if backup.Meta.Version == 2 && backup.Meta.Checksum == "" {
		return false, errors.New("备份缺少完整性校验和，请使用 v2.1.2 及以上版本重新导出后再导入")
	}
	if backup.Meta.Checksum != "" {
		checksumPayload, err := json.Marshal(struct {
			Tables map[string][]map[string]any `json:"tables"`
			Config map[string]any              `json:"config"`
		}{backup.Tables, backup.Config})
		if err != nil {
			return false, fmt.Errorf("计算备份校验和失败: %w", err)
		}
		sum := sha256.Sum256(checksumPayload)
		if hex.EncodeToString(sum[:]) != backup.Meta.Checksum {
			// R43 F-D: 旧格式（仅 tables）校验和回退仅限明确的旧格式标记
			// （Version==1 且无 exported_at 的史前导出，R45 F-3 收紧）；新格式文件
			// （带 exported_at）校验和不匹配直接拒绝——否则仅篡改 Config 区
			// （dns_credentials/acme_email/管理面板 TLS 材料）而保留 tables 的文件
			// 可借回退通过完整性校验。
			tablesJSON, _ := json.Marshal(backup.Tables)
			oldSum := sha256.Sum256(tablesJSON)
			tablesOnlyMatch := hex.EncodeToString(oldSum[:]) == backup.Meta.Checksum
			if backup.Meta.ExportedAt == "" && backup.Meta.Version == 1 {
				if tablesOnlyMatch {
					return true, nil
				}
			} else if tablesOnlyMatch {
				// R44 C1: v2.1.1（及更早）导出即「tables-only 校验和 + exported_at
				// 非空」形态——tables 区完整性成立，是合法旧版文件而非篡改证据；
				// 但 Config 区不受旧校验和保护，仍须拒绝导入，仅改报兼容性提示。
				return false, errors.New("备份由 v2.1.1 或更早版本导出，校验和格式不兼容，请使用 v2.1.2 及以上版本重新导出后再导入")
			}
			return false, errors.New("备份校验和不匹配，文件可能已被篡改或损坏")
		}
	}
	// R39 C-1: 归一须在 checksum 校验之后（避免自带校验和的备份被误判篡改）、
	// 管理员校验之前（backupBooleanEnabled(nil)=false 会先行 400 拦截全 null 管理员备份）。
	normalizeBackupBooleanNulls(backup.Tables)
	requiredTables := configBackupTables
	if backup.Meta.Version == 1 {
		requiredTables = configBackupV1Tables
	}
	for _, required := range requiredTables {
		if _, exists := backup.Tables[required]; !exists {
			return false, errors.New("备份缺少必需的数据表: " + required)
		}
	}
	for _, table := range configBackupTables {
		if _, exists := backup.Tables[table]; !exists {
			backup.Tables[table] = []map[string]any{}
		}
	}
	for _, job := range backup.Tables["cert_jobs"] {
		status, ok := job["status"].(string)
		if !ok {
			return false, errors.New("证书任务状态不能为空")
		}
		if _, allowed := configBackupCertJobStatuses[status]; !allowed {
			return false, fmt.Errorf("无效的证书任务状态: %s", status)
		}
	}
	const invalidCredentialsMsg = "备份包含无效的凭证格式（ca_providers.credentials / certificate_configs.dns_credentials 需为 JSON 对象）"
	for _, provider := range backup.Tables["ca_providers"] {
		if err := validateCredentialsJSONObject(backupString(provider["credentials"])); err != nil {
			return false, errors.New(invalidCredentialsMsg)
		}
	}
	for _, certCfg := range backup.Tables["certificate_configs"] {
		if err := validateCredentialsJSONObject(backupString(certCfg["dns_credentials"])); err != nil {
			return false, errors.New(invalidCredentialsMsg)
		}
	}
	for _, user := range backup.Tables["users"] {
		if role, _ := user["role"].(string); role == "admin" && backupBooleanEnabled(user["is_enabled"]) {
			return false, nil
		}
	}
	return false, errors.New("备份必须至少包含一个已启用的管理员账号")
}

// validateV2BackupRules 逐行校验备份 lb_rules 的端口与特性（校验侧保守口径）。
// 必须在 skipEmptyDomainHTTPRules 之后执行（R38 C-3）：空域名行无论端口/特性
// 是否非法都一律软跳过，不被逐行校验先行整包 400。
func validateV2BackupRules(rows, pathRows []map[string]any) error {
	for index, rule := range rows {
		protocol, _ := rule["protocol"].(string)
		listenPort, validPort := backupInteger(rule["listen_port"])
		if !validPort {
			return fmt.Errorf("规则 #%d：监听端口必须为整数", index+1)
		}
		if err := validateRuleListenPort(protocol, listenPort); err != nil {
			return fmt.Errorf("规则 #%d：%w", index+1, err)
		}
		// Round 29 G-1: 补传 ListenPort/EnableTLS/TLSHTTPRedirect 等字段，启用
		// validateRuleFeatures 的 80 端口 + TLS 跳转自环检查（此前仅端口/策略校验，
		// 备份中自环规则校验放行并导入成功，生成自环 Location）；行内有
		// custom_routes_enabled/path_rules 信息时一并传入，保持与保存路径同口径。
		// Round 30 F-1: 禁用规则不参与渲染（caddy.go WHERE enabled=1），其
		// 80+TLS+跳转组合无运行时影响；若仍按启用态校验会整包拒绝，导出→导入
		// 往返断裂（与 v1 路径自环规则软跳过口径一致），故禁用行将
		// EnableTLS/TLSHTTPRedirect 置 false，其余字段校验保留。
		enabled := backupRuleEnabled(rule)
		// R43 F-C / R46 C-B-1: 启用的手动 TLS 规则必须携带证书与私钥（镜像保存/启用侧
		// rule_features.go validateStoredRuleConfig 口径），拒绝时点名规则。
		// 导入此前是唯一能绕过该校验的门：无证书规则不在 availableCerts 内 → 无
		// TLS policy → TLS 端口明文服务，且 autohttps.disable_certificates 阻止
		// Caddy 自动签发自愈。
		if enabled && protocol == "http" && backupBooleanEnabled(rule["enable_tls"]) &&
			backupString(rule["tls_source"]) == "manual" &&
			(strings.TrimSpace(backupString(rule["tls_cert"])) == "" || strings.TrimSpace(backupString(rule["tls_key"])) == "") {
			return fmt.Errorf("规则 #%d（%s）：手动证书模式下必须提供 TLS 证书和私钥", index+1, backupString(rule["name"]))
		}
		input := ruleFeatureInput{
			Protocol:                   protocol,
			Strategy:                   backupString(rule["strategy"]),
			ListenPort:                 listenPort,
			EnableTLS:                  backupBooleanEnabled(rule["enable_tls"]) && enabled,
			TLSHTTPRedirect:            backupBooleanEnabled(rule["tls_http_redirect"]) && enabled,
			CustomRoutesEnabled:        backupBooleanEnabled(rule["custom_routes_enabled"]),
			ProxyDialTimeout:           backupInt(rule["proxy_dial_timeout"]),
			ProxyResponseHeaderTimeout: backupInt(rule["proxy_response_header_timeout"]),
			ProxyReadTimeout:           backupInt(rule["proxy_read_timeout"]),
			ProxyWriteTimeout:          backupInt(rule["proxy_write_timeout"]),
			ProxyStreamTimeout:         backupInt(rule["proxy_stream_timeout"]),
			ProxyFlushInterval:         backupInt(rule["proxy_flush_interval"]),
			ProxyStreamCloseDelay:      backupInt(rule["proxy_stream_close_delay"]),
			EnableCompress:             backupBooleanEnabled(rule["enable_compress"]),
			CompressTypes:              backupString(rule["compress_types"]),
		}
		if pathRules, found := backupPathRulesForRule(pathRows, backupString(rule["caddy_id"])); found {
			// Round 30 F-6: 保存路径先 normalizePathRules（TrimSpace）再校验
			// （createRuleFeatures/updateRuleFeatures），备份路径此前直传导致手造备份
			// 含前导空格路径时 validateRuleFeatures 的 HasPrefix("/") 误拒绝。
			input.PathRules = normalizePathRules(pathRules)
		}
		if err := validateRuleFeatures(input); err != nil {
			return fmt.Errorf("规则 #%d：%w", index+1, err)
		}
	}
	return nil
}

// validateV2BackupSecurityPolicies 按保存侧同口径（validateAndNormalizeCRSField，
// security.go）校验备份 security_policies 的 crs_rule_groups/crs_excluded_rules，
// 拒绝时点名策略；合法行同步写回归一值（空串→"[]"），保持列形状一致。
// R48-3：原始值存在且非字符串（数字/布尔/数组，null/缺省除外）直接拒绝——
// 保存侧 JSON 绑定对同值 400，导入侧不得经 backupString 静默归一放行。
// R47 B-5：旧版备份可能携带 "941" 式组号或含空白的条目——导入原样落库后
// REQUEST-9<code>-*.conf glob 零匹配，blocking 模式静默无任何 CRS 规则生效。
func validateV2BackupSecurityPolicies(rows []map[string]any) error {
	for index, policy := range rows {
		name := backupString(policy["name"])
		for _, field := range []string{"crs_rule_groups", "crs_excluded_rules"} {
			raw, exists := policy[field]
			if exists && raw != nil {
				if _, ok := raw.(string); !ok {
					return fmt.Errorf("安全策略 #%d（%s）：%s 需为字符串（JSON 数组文本），实际类型 %T", index+1, name, field, raw)
				}
			}
			value := backupString(raw)
			if err := validateAndNormalizeCRSField(field, &value); err != nil {
				return fmt.Errorf("安全策略 #%d（%s）：%w", index+1, name, err)
			}
			policy[field] = value
		}
	}
	return nil
}

func backupBooleanEnabled(value any) bool {
	switch value := value.(type) {
	case bool:
		return value
	case float64:
		return value == 1
	case int:
		return value == 1
	case int64:
		return value == 1
	default:
		return false
	}
}

// backupRuleEnabled 读取备份行 enabled 字段：校验侧保守口径——缺省视为启用以覆盖
// 自环/遮蔽检查（不放松校验）；存储口径 NULL 视同禁用（R36 迁移 + IIF）。
func backupRuleEnabled(row map[string]any) bool {
	if raw, exists := row["enabled"]; exists {
		return backupBooleanEnabled(raw)
	}
	return true
}

func backupString(value any) string {
	if s, ok := value.(string); ok {
		return s
	}
	return ""
}

// backupPathRulesForRule 从备份 path_rules 表收集指定规则的自定义路径规则，
// 供 validateV2Backup 按保存路径同口径校验；无该规则行时返回 found=false。
func backupPathRulesForRule(rows []map[string]any, ruleID string) ([]models.PathRule, bool) {
	if ruleID == "" {
		return nil, false
	}
	found := false
	pathRules := make([]models.PathRule, 0)
	for _, row := range rows {
		ownerID, _ := row["rule_id"].(string)
		if ownerID != ruleID {
			continue
		}
		found = true
		pathRule := models.PathRule{
			SortOrder: backupInt(row["sort_order"]),
			MatchType: backupString(row["match_type"]),
			Path:      backupString(row["path"]),
		}
		if raw, ok := row["upstreams_json"].(string); ok && raw != "" {
			_ = json.Unmarshal([]byte(raw), &pathRule.Upstreams)
		}
		pathRules = append(pathRules, pathRule)
	}
	return pathRules, found
}

// validateCredentialsJSONObject allows empty strings but requires non-empty values to be JSON objects.
func validateCredentialsJSONObject(raw string) error {
	if raw == "" {
		return nil
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		return err
	}
	return nil
}

func backupInt(value any) int {
	if v, ok := backupInteger(value); ok {
		return v
	}
	return 0
}

func backupInteger(value any) (int, bool) {
	switch value := value.(type) {
	case float64:
		if value == math.Trunc(value) && value >= math.MinInt && value <= math.MaxInt {
			return int(value), true
		}
	case int:
		return value, true
	case int64:
		if value >= math.MinInt && value <= math.MaxInt {
			return int(value), true
		}
	}
	return 0, false
}

// skipEmptyDomainHTTPRules 移除域名为空的 HTTP 规则及其关联行（上游/路径规则/证书任务），
// 返回跳过警告；TCP 规则无需域名，不受影响。
func skipEmptyDomainHTTPRules(tables map[string][]map[string]any) []string {
	rows, exists := tables["lb_rules"]
	if !exists {
		return nil
	}
	skippedIDs := map[string]bool{}
	warnings := []string{}
	kept := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		protocol, _ := row["protocol"].(string)
		domain, _ := row["domain"].(string)
		// Round 35 I-10: 空 protocol（非法但 v1 备份可能存在）也按 HTTP 处理，避免绕过空域名跳过逻辑。
		if (protocol != "http" && protocol != "") || strings.TrimSpace(domain) != "" {
			kept = append(kept, row)
			continue
		}
		caddyID, _ := row["caddy_id"].(string)
		name, _ := row["name"].(string)
		if name == "" {
			name = caddyID
		}
		skippedIDs[caddyID] = true
		warnings = append(warnings, fmt.Sprintf("规则 %s 的域名为空，已跳过导入", name))
	}
	if len(skippedIDs) == 0 {
		return nil
	}
	tables["lb_rules"] = kept
	for _, table := range []string{"upstreams", "path_rules", "cert_jobs"} {
		related, exists := tables[table]
		if !exists {
			continue
		}
		filtered := make([]map[string]any, 0, len(related))
		for _, row := range related {
			ruleID, _ := row["rule_id"].(string)
			if skippedIDs[ruleID] {
				continue
			}
			filtered = append(filtered, row)
		}
		tables[table] = filtered
	}
	return warnings
}

func disableV2RuleConflicts(rows []map[string]any) []disabledRuleConflict {
	candidates := make([]ruleConflictCandidate, len(rows))
	for index, row := range rows {
		candidates[index] = newRuleConflictCandidate(
			backupString(row["name"]), backupString(row["caddy_id"]), backupString(row["protocol"]), backupString(row["domain"]),
			backupInt(row["listen_port"]),
			// Round 32 F-1: 与校验侧 backupRuleEnabled（config_backup.go:284）同口径——
			// 手造备份缺 enabled 列时按表结构 COALESCE(enabled,1) 视为启用；此前用
			// backupBooleanEnabled 缺键按禁用，C1 门控下校验按启用、矩阵按禁用跳过，
			// 两条同端口同域名规则双双启用导入、运行时相互遮蔽。
			backupRuleEnabled(row), backupBooleanEnabled(row["enable_tls"]), backupBooleanEnabled(row["tls_http_redirect"]),
		)
	}
	conflicts := validateRuleConflictMatrix(candidates)
	for _, conflict := range conflicts {
		rows[conflict.index]["enabled"] = 0
	}
	return conflicts
}

func clampBackupJWTExpireMinutes(value any) (any, bool) {
	switch minutes := value.(type) {
	case float64:
		if minutes >= 1 && minutes <= 1440 && minutes == math.Trunc(minutes) {
			return value, false
		}
	case int:
		if minutes >= 1 && minutes <= 1440 {
			return value, false
		}
	case int64:
		if minutes >= 1 && minutes <= 1440 {
			return value, false
		}
	}
	return 20, true
}

func (h *Handlers) ExportConfigBackup(c *gin.Context) {
	if isMaster, err := h.clusterService.IsMaster(c.Request.Context()); err != nil || !isMaster {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "仅主节点支持导出配置"})
		return
	}
	ctx := c.Request.Context()
	backup := configBackup{
		Meta:   configBackupMeta{App: "lazy-balancer-v2", Version: 2, ExportedAt: time.Now().UTC().Format(time.RFC3339)},
		Tables: map[string][]map[string]any{},
	}
	tx, err := db.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "导出失败: " + err.Error()})
		return
	}
	configRows, err := dumpTable(ctx, tx, "global_config")
	if err != nil {
		err = errors.Join(err, tx.Rollback())
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "导出失败: " + err.Error()})
		return
	}
	if len(configRows) > 0 {
		backup.Config = configRows[0]
		for key := range configBackupProtectedConfigKeys {
			delete(backup.Config, key)
		}
	}
	for _, table := range configBackupTables {
		rows, err := dumpTable(ctx, tx, table)
		if err != nil {
			err = errors.Join(err, tx.Rollback())
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "导出失败: " + err.Error()})
			return
		}
		backup.Tables[table] = rows
	}
	checksumPayload, err := json.Marshal(struct {
		Tables map[string][]map[string]any `json:"tables"`
		Config map[string]any              `json:"config"`
	}{backup.Tables, backup.Config})
	if err != nil {
		err = errors.Join(err, tx.Rollback())
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "导出失败: " + err.Error()})
		return
	}
	sum := sha256.Sum256(checksumPayload)
	backup.Meta.Checksum = hex.EncodeToString(sum[:])
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "导出失败: " + err.Error()})
		return
	}
	recordAudit(c, "导出", "配置备份", services.FormatAuditDetail(importCountsDetail(backup.Tables), "导出为完整备份（含凭证与证书材料），请妥善保管", services.AuditResultPart("success")))
	c.Header("Cache-Control", "no-store, private")
	c.Header("Pragma", "no-cache")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Content-Disposition", "attachment; filename=lazy-balancer-backup-"+time.Now().Format("20060102-150405")+".json")
	c.JSON(http.StatusOK, backup)
}

func (h *Handlers) ImportConfigBackup(c *gin.Context) {
	if isMaster, err := h.clusterService.IsMaster(c.Request.Context()); err != nil || !isMaster {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "仅主节点支持导入配置"})
		return
	}
	if !limitConfigImportBody(c) {
		return
	}
	var backup configBackup
	if err := c.ShouldBindJSON(&backup); err != nil {
		if isRequestBodyTooLarge(err) {
			c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "备份文件不能超过 16MB"})
			return
		}
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "备份文件格式不正确"})
		return
	}
	usedLegacyChecksum, err := validateV2Backup(backup)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if usedLegacyChecksum {
		// R43 F-D: 旧格式校验和仅覆盖数据表、不含全局配置区，完整性保障较弱，
		// 显式记审计警告以便追溯（预览端点只读不落审计，避免 UI 选择文件即刷屏）。
		recordAudit(c, "导入警告", "配置备份", "使用旧格式校验和（仅覆盖数据表，不含全局配置）验证备份完整性，建议升级后重新导出备份")
	}
	// R38 C-3: 空域名行软跳过须先于逐行校验（validateV2BackupRules）——否则
	// 空域名+非法端口行会先行整包 400，与「空域名规则一律软跳过」语义不符；
	// 校验和/结构校验已在 validateV2Backup 内完成，不受跳过影响。
	skipWarnings := skipEmptyDomainHTTPRules(backup.Tables)
	if err := validateBackupRuleReferences(backup.Tables); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if err := validateV2BackupRules(backup.Tables["lb_rules"], backup.Tables["path_rules"]); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if err := validateV2BackupSecurityPolicies(backup.Tables["security_policies"]); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	disabledConflicts := disableV2RuleConflicts(backup.Tables["lb_rules"])
	jwtExpireClamped := false
	if value, exists := backup.Config["jwt_expire_minutes"]; exists {
		backup.Config["jwt_expire_minutes"], jwtExpireClamped = clampBackupJWTExpireMinutes(value)
	}
	ctx := c.Request.Context()
	importUsername := c.GetString("username")
	session, err := h.beginConfigImport(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	defer session.close()
	tx := session.tx
	deleteOrder := []string{"security_policy_bindings", "security_crs_version", "security_ip2region_version", "security_custom_rules", "security_block_pages", "security_policies", "api_keys", "path_rules", "upstreams", "cert_jobs", "lb_rules", "users", "ca_providers", "certificate_configs"}
	for _, table := range deleteOrder {
		if _, exists := backup.Tables[table]; !exists {
			continue
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			err = session.abort(err)
			recordAudit(c, "导入失败", "配置备份", err.Error())
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "清空表 " + table + " 失败，已回滚: " + err.Error()})
			return
		}
	}
	insertOrder := []string{"users", "lb_rules", "ca_providers", "certificate_configs", "api_keys", "upstreams", "path_rules", "cert_jobs", "security_policies", "security_crs_version", "security_ip2region_version", "security_block_pages", "security_custom_rules", "security_policy_bindings"}
	for _, table := range insertOrder {
		rows, exists := backup.Tables[table]
		if !exists {
			continue
		}
		// 归一兜底：validateV2Backup 内的 normalizeBackupBooleanNulls 已被
		// legacy（仅 tables）校验和早退路径跳过，此处幂等重复执行覆盖该场景
		//（R37 F37-2 / R38 C-1 / R39 C-1）。
		if table == "lb_rules" || table == "upstreams" || table == "users" {
			normalizeBackupBooleanNulls(map[string][]map[string]any{table: rows})
		}
		if err := restoreTable(ctx, tx, db.DB, table, rows); err != nil {
			err = session.abort(err)
			recordAudit(c, "导入失败", "配置备份", err.Error())
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "导入失败，已回滚: " + err.Error()})
			return
		}
	}
	// R41 B1: pre-R40 备份可能携带 ≥2 个 is_default=1 的拦截页。restoreTable
	// 原值插入后这些行全部成为不可编辑/删除的死行，且 branding 重渲染会覆盖
	// 全部默认页内容。提交前降级多余默认页，仅保留 MIN(id) 一行。
	// R42 B42-2: pre-R40 备份中保留行（MIN id）常是未定制过的种子行，而用户真实
	// 定制内容在被降级行上。保留行内容为种子库存（空或默认渲染）且存在内容不同的
	// 被降级行时，把内容非空且非库存、id 最大的被降级行 content 提升到保留行；
	// 失败仅记警告（内容层面问题，branding 重渲染会覆盖，不影响拦截功能）。
	// R43 B43-1: 提升先于降级执行——降级后「被降级行」与从未是默认页的自定义行
	// 无法区分；CTE 在降级前圈定待降级行集合，提升源限定该集合且以 EXISTS 门控
	// （未发生降级即跳过提升），单默认页+自定义页的备份不再静默改写默认页内容。
	stockBlockPage := renderDefaultBlockPage(loadBrandingConfig(h.cfg.DataDir))
	if _, err := tx.ExecContext(ctx, `WITH demoted AS (SELECT id, content FROM security_block_pages WHERE is_default=1 AND id != (SELECT MIN(id) FROM security_block_pages WHERE is_default=1)) UPDATE security_block_pages SET content=(SELECT content FROM demoted WHERE content NOT IN ('', ?) ORDER BY id DESC LIMIT 1) WHERE id=(SELECT MIN(id) FROM security_block_pages WHERE is_default=1) AND content IN ('', ?) AND EXISTS (SELECT 1 FROM demoted WHERE content NOT IN ('', ?))`, stockBlockPage, stockBlockPage, stockBlockPage); err != nil {
		recordAudit(c, "导入警告", "配置备份", "默认拦截页面内容提升失败: "+err.Error())
	}
	if _, err := tx.ExecContext(ctx, `UPDATE security_block_pages SET is_default=0 WHERE is_default=1 AND id != (SELECT MIN(id) FROM security_block_pages WHERE is_default=1)`); err != nil {
		err = session.abort(err)
		recordAudit(c, "导入失败", "配置备份", "降级多余的默认拦截页失败: "+err.Error())
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "降级多余的默认拦截页失败，已回滚: " + err.Error()})
		return
	}
	// R41 B3: 默认页重播种移入导入事务，与导入同生共死；失败仅记警告不阻断
	// 导入（拦截响应短暂退化，由后续 SeedDefaultBlockPage/branding 触发自愈）。
	reseedBlockPageNeeded := false
	var hasDefaultBlockPage int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM security_block_pages WHERE is_default=1").Scan(&hasDefaultBlockPage); err != nil {
		recordAudit(c, "导入警告", "配置备份", "默认拦截页面计数失败: "+err.Error())
	} else if hasDefaultBlockPage == 0 {
		result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO security_block_pages (id, name, description, content, is_default, created_at, updated_at) VALUES (1, '默认拦截页面', '系统默认 403 拦截页面', '', TRUE, datetime('now'), datetime('now'))`)
		if err != nil {
			recordAudit(c, "导入警告", "配置备份", "默认拦截页面重播种失败: "+err.Error())
		} else if affected, _ := result.RowsAffected(); affected == 0 {
			// R42 B42-1: 备份携带 id=1 的非默认行时 OR IGNORE 因 PK 冲突静默
			// no-op，导入后仍旧零默认页且无任何 error——B3 的告警机制不会
			// 触发，此处显式补记警告以便追溯。
			recordAudit(c, "导入警告", "配置备份", "默认拦截页面重播种未生效（id=1 已存在）")
		} else {
			reseedBlockPageNeeded = true
		}
	}
	if _, err := tx.ExecContext(ctx, "UPDATE users SET password_version=COALESCE(password_version,0)+1"); err != nil {
		err = session.abort(err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "吊销现有登录会话失败，已回滚: " + err.Error()})
		return
	}
	var enabledAdmins int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE role='admin' AND is_enabled=1").Scan(&enabledAdmins); err != nil {
		err = session.abort(err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "确认管理员账号失败，已回滚: " + err.Error()})
		return
	}
	if enabledAdmins == 0 {
		err = session.abort(errors.New("导入后必须至少保留一个已启用的管理员账号"))
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	var importUserID sql.NullInt64
	if importUsername != "" {
		err := tx.QueryRowContext(ctx, "SELECT id FROM users WHERE username=?", importUsername).Scan(&importUserID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			err = session.abort(err)
			recordAudit(c, "导入失败", "配置备份", "重映射规则操作者失败: "+err.Error())
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "重映射规则操作者失败，已回滚: " + err.Error()})
			return
		}
	}
	if _, err := tx.ExecContext(ctx, "UPDATE lb_rules SET updated_by=?", importUserID); err != nil {
		err = session.abort(err)
		recordAudit(c, "导入失败", "配置备份", "更新规则操作者失败: "+err.Error())
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新规则操作者失败，已回滚: " + err.Error()})
		return
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM cert_jobs WHERE rule_id NOT IN (SELECT caddy_id FROM lb_rules)"); err != nil {
		err = session.abort(err)
		recordAudit(c, "导入失败", "配置备份", "清理孤儿证书任务失败: "+err.Error())
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "清理孤儿证书任务失败，已回滚: " + err.Error()})
		return
	}
	if backup.Config != nil {
		valid, err := tableColumns(ctx, db.DB, "global_config")
		if err != nil {
			err = session.abort(err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取配置结构失败: " + err.Error()})
			return
		}
		sets := []string{}
		values := []any{}
		for column, value := range backup.Config {
			if configBackupProtectedConfigKeys[column] || !valid[column] {
				continue
			}
			sets = append(sets, `"`+column+`"=?`)
			values = append(values, value)
		}
		if len(sets) > 0 {
			if _, err := tx.ExecContext(ctx, "UPDATE global_config SET "+joinStrings(sets, ",")+" WHERE id=1", values...); err != nil {
				err = session.abort(err)
				recordAudit(c, "导入失败", "配置备份", err.Error())
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "导入全局配置失败，已回滚: " + err.Error()})
				return
			}
		}
	}
	affectedRuleIDs := append([]string(nil), session.existingRuleIDs...)
	pendingCertificates := make([]importCertificate, 0)
	for _, row := range backup.Tables["lb_rules"] {
		if caddyID, ok := row["caddy_id"].(string); ok && caddyID != "" {
			affectedRuleIDs = append(affectedRuleIDs, caddyID)
			certPEM, _ := row["tls_cert"].(string)
			keyPEM, _ := row["tls_key"].(string)
			if certPEM != "" && keyPEM != "" {
				pendingCertificates = append(pendingCertificates, importCertificate{ruleID: caddyID, certPEM: certPEM, keyPEM: keyPEM})
			}
		}
	}
	counts := importCountsDetail(backup.Tables)
	if err := session.commit(affectedRuleIDs, pendingCertificates); err != nil {
		status := http.StatusInternalServerError
		message := "配置导入失败: " + err.Error()
		if importFailurePhase(err) == importPhaseCaddy {
			status = http.StatusBadRequest
			message = "备份生成的配置未通过 Caddy 验证，未执行导入: " + err.Error()
		}
		if importFailurePhase(err) == importPhaseQueue {
			message = "配置已导入但证书任务恢复失败: " + err.Error()
		}
		auditAction := "导入失败"
		if importFailurePhase(err) == importPhaseQueue {
			auditAction = "部分失败"
		}
		auditDetail := err.Error()
		if importFailurePhase(err) == importPhaseQueue && len(disabledConflicts) > 0 {
			auditDetail = services.FormatAuditDetail(auditDetail, "冲突置为禁用："+formatDisabledRuleConflicts(disabledConflicts))
		}
		recordAudit(c, auditAction, "配置备份", auditDetail)
		c.JSON(status, models.APIResponse{Code: status, Message: message, Data: gin.H{"summary": counts, "disabled_conflicts": disabledConflicts, "warnings": skipWarnings}})
		return
	}

	if reseedBlockPageNeeded {
		// 提交成功后才渲染 branding 内容：INSERT 只放空 content 占位，真实内容
		// 由 SeedDefaultBlockPage 依据 branding.json 写入；失败不影响导入结果。
		// R42 B42-1: 返回值不再丢弃——渲染出错，或未生效且表内仍无默认页时记警告。
		seeded, seedErr := SeedDefaultBlockPage(h.cfg.DataDir)
		if seedErr != nil {
			recordAudit(c, "导入警告", "配置备份", "默认拦截页面内容渲染失败: "+seedErr.Error())
		} else if !seeded {
			var defaultCount int
			if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_block_pages WHERE is_default=1").Scan(&defaultCount); err == nil && defaultCount == 0 {
				recordAudit(c, "导入警告", "配置备份", "默认拦截页面重播种后仍无默认页")
			}
		}
		note := h.caddyApplyNoteLocked()
		if note != "" {
			recordAudit(c, "导入警告", "配置备份", "默认拦截页面重新播种后"+note)
		}
	}

	auditParts := []string{"来源：v2 备份（覆盖导入）", counts}
	if jwtExpireClamped {
		auditParts = append(auditParts, "jwt_expire_minutes 越界，已重置为 20")
	}
	if len(skipWarnings) > 0 {
		auditParts = append(auditParts, "空域名规则跳过："+strings.Join(skipWarnings, "；"))
	}
	if len(disabledConflicts) > 0 {
		auditParts = append(auditParts, "冲突置为禁用："+formatDisabledRuleConflicts(disabledConflicts))
	}
	auditParts = append(auditParts, services.AuditResultPart("success"))
	recordAudit(c, "导入", "配置备份", services.FormatAuditDetail(auditParts...))
	recordAudit(c, "重载", "Caddy服务", "导入配置后自动重载")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: fmt.Sprintf("配置导入成功：%s", strings.ReplaceAll(counts, "；", "、")), Data: gin.H{"summary": counts, "disabled_conflicts": disabledConflicts, "warnings": skipWarnings}})
}

func importCountsDetail(tables map[string][]map[string]any) string {
	parts := []string{}
	labels := []struct {
		table string
		label string
	}{
		{"lb_rules", "规则 %d 条"},
		{"upstreams", "上游 %d 个"},
		{"users", "用户 %d 个"},
		{"api_keys", "密钥 %d 个"},
		{"ca_providers", "CA %d 个"},
		{"certificate_configs", "DNS %d 个"},
		{"cert_jobs", "任务 %d 个"},
		{"security_crs_version", "CRS 版本 %d 条"},
		{"security_ip2region_version", "IP2Region 版本 %d 条"},
	}
	for _, item := range labels {
		if rows, ok := tables[item.table]; ok {
			parts = append(parts, fmt.Sprintf(item.label, len(rows)))
		}
	}
	return joinStrings(parts, "；")
}
