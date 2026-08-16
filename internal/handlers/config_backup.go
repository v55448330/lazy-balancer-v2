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

func validateV2Backup(backup configBackup) error {
	if backup.Meta.App != "lazy-balancer-v2" || backup.Tables == nil {
		return errors.New("不是有效的 Lazy Balancer 备份文件")
	}
	if backup.Meta.Version != 1 && backup.Meta.Version != 2 {
		return fmt.Errorf("不支持的备份版本: %d", backup.Meta.Version)
	}
	if backup.Config == nil {
		return errors.New("备份缺少全局配置")
	}
	if backup.Meta.Checksum != "" {
		checksumPayload, err := json.Marshal(struct {
			Tables map[string][]map[string]any `json:"tables"`
			Config map[string]any              `json:"config"`
		}{backup.Tables, backup.Config})
		if err != nil {
			return fmt.Errorf("计算备份校验和失败: %w", err)
		}
		sum := sha256.Sum256(checksumPayload)
		if hex.EncodeToString(sum[:]) != backup.Meta.Checksum {
			tablesJSON, _ := json.Marshal(backup.Tables)
			oldSum := sha256.Sum256(tablesJSON)
			if hex.EncodeToString(oldSum[:]) == backup.Meta.Checksum {
				return nil
			}
			return errors.New("备份校验和不匹配，文件可能已被篡改或损坏")
		}
	}
	requiredTables := configBackupTables
	if backup.Meta.Version == 1 {
		requiredTables = configBackupV1Tables
	}
	for _, required := range requiredTables {
		if _, exists := backup.Tables[required]; !exists {
			return errors.New("备份缺少必需的数据表: " + required)
		}
	}
	for _, table := range configBackupTables {
		if _, exists := backup.Tables[table]; !exists {
			backup.Tables[table] = []map[string]any{}
		}
	}
	for index, rule := range backup.Tables["lb_rules"] {
		protocol, _ := rule["protocol"].(string)
		listenPort, validPort := backupInteger(rule["listen_port"])
		if !validPort {
			return fmt.Errorf("规则 #%d：监听端口必须为整数", index+1)
		}
		if err := validateRuleListenPort(protocol, listenPort); err != nil {
			return fmt.Errorf("规则 #%d：%w", index+1, err)
		}
		if err := validateRuleFeatures(ruleFeatureInput{
			Protocol:                   protocol,
			Strategy:                   backupString(rule["strategy"]),
			ProxyDialTimeout:           backupInt(rule["proxy_dial_timeout"]),
			ProxyResponseHeaderTimeout: backupInt(rule["proxy_response_header_timeout"]),
			ProxyReadTimeout:           backupInt(rule["proxy_read_timeout"]),
			ProxyWriteTimeout:          backupInt(rule["proxy_write_timeout"]),
			ProxyStreamTimeout:         backupInt(rule["proxy_stream_timeout"]),
			ProxyFlushInterval:         backupInt(rule["proxy_flush_interval"]),
			ProxyStreamCloseDelay:      backupInt(rule["proxy_stream_close_delay"]),
			EnableCompress:             backupBooleanEnabled(rule["enable_compress"]),
			CompressTypes:              backupString(rule["compress_types"]),
		}); err != nil {
			return fmt.Errorf("规则 #%d：%w", index+1, err)
		}
	}
	for _, job := range backup.Tables["cert_jobs"] {
		status, ok := job["status"].(string)
		if !ok {
			return errors.New("证书任务状态不能为空")
		}
		if _, allowed := configBackupCertJobStatuses[status]; !allowed {
			return fmt.Errorf("无效的证书任务状态: %s", status)
		}
	}
	for _, user := range backup.Tables["users"] {
		if role, _ := user["role"].(string); role == "admin" && backupBooleanEnabled(user["is_enabled"]) {
			return nil
		}
	}
	return errors.New("备份必须至少包含一个已启用的管理员账号")
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

func backupString(value any) string {
	if s, ok := value.(string); ok {
		return s
	}
	return ""
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
		candidates[index].name, _ = row["name"].(string)
		candidates[index].caddyID, _ = row["caddy_id"].(string)
		candidates[index].protocol, _ = row["protocol"].(string)
		candidates[index].domain, _ = row["domain"].(string)
		candidates[index].listenPort, _ = backupInteger(row["listen_port"])
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
	if err := validateV2Backup(backup); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	skipWarnings := skipEmptyDomainHTTPRules(backup.Tables)
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
		if err := restoreTable(ctx, tx, db.DB, table, rows); err != nil {
			err = session.abort(err)
			recordAudit(c, "导入失败", "配置备份", err.Error())
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "导入失败，已回滚: " + err.Error()})
			return
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
			auditAction = "导入部分失败"
		}
		auditDetail := err.Error()
		if importFailurePhase(err) == importPhaseQueue && len(disabledConflicts) > 0 {
			auditDetail = services.FormatAuditDetail(auditDetail, "冲突置为禁用："+formatDisabledRuleConflicts(disabledConflicts))
		}
		recordAudit(c, auditAction, "配置备份", auditDetail)
		c.JSON(status, models.APIResponse{Code: status, Message: message, Data: gin.H{"summary": counts, "disabled_conflicts": disabledConflicts, "warnings": skipWarnings}})
		return
	}

	var hasDefaultBlockPage int
	db.DB.QueryRow("SELECT COUNT(*) FROM security_block_pages WHERE is_default=1").Scan(&hasDefaultBlockPage)
	if hasDefaultBlockPage == 0 {
		db.DB.Exec(`INSERT OR IGNORE INTO security_block_pages (id, name, description, content, is_default, created_at, updated_at) VALUES (1, '默认拦截页面', '系统默认 403 拦截页面', '', TRUE, datetime('now'), datetime('now'))`)
		SeedDefaultBlockPage(h.cfg.DataDir)
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
	recordAudit(c, "重载", "Caddy配置", "导入配置后自动重载")
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
