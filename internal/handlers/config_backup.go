package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

var configBackupTables = []string{"lb_rules", "upstreams", "path_rules", "users", "api_keys", "ca_providers", "certificate_configs", "cert_jobs"}

var configBackupProtectedConfigKeys = map[string]bool{
	"id": true, "is_master": true, "master_url": true, "cluster_token": true,
	"registration_id": true, "registration_secret": true, "applied_version": true,
	"sync_fingerprint": true, "last_sync": true, "last_sync_error": true, "cluster_version": true,
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
}

func dumpTable(ctx context.Context, database *sql.DB, table string) ([]map[string]any, error) {
	rows, err := database.QueryContext(ctx, "SELECT * FROM "+table)
	if err != nil {
		return nil, fmt.Errorf("读取表 %s: %w", table, err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	result := make([]map[string]any, 0)
	for rows.Next() {
		values := make([]any, len(columns))
		targets := make([]any, len(columns))
		for i := range values {
			targets[i] = &values[i]
		}
		if err := rows.Scan(targets...); err != nil {
			return nil, fmt.Errorf("扫描表 %s: %w", table, err)
		}
		row := map[string]any{}
		for i, column := range columns {
			if bytes, ok := values[i].([]byte); ok {
				row[column] = string(bytes)
			} else {
				row[column] = values[i]
			}
		}
		result = append(result, row)
	}
	return result, rows.Err()
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
	if backup.Meta.Version != 1 {
		return fmt.Errorf("不支持的备份版本: %d", backup.Meta.Version)
	}
	for _, required := range []string{"lb_rules", "users"} {
		if _, exists := backup.Tables[required]; !exists {
			return errors.New("备份缺少必需的数据表: " + required)
		}
	}
	return nil
}

func (h *Handlers) ExportConfigBackup(c *gin.Context) {
	if isMaster, err := h.clusterService.IsMaster(c.Request.Context()); err != nil || !isMaster {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "仅主节点支持导出配置"})
		return
	}
	ctx := c.Request.Context()
	backup := configBackup{
		Meta:   configBackupMeta{App: "lazy-balancer-v2", Version: 1, ExportedAt: time.Now().UTC().Format(time.RFC3339)},
		Tables: map[string][]map[string]any{},
	}
	configRows, err := dumpTable(ctx, db.DB, "global_config")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "导出失败: " + err.Error()})
		return
	}
	if len(configRows) > 0 {
		backup.Config = configRows[0]
	}
	for _, table := range configBackupTables {
		rows, err := dumpTable(ctx, db.DB, table)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "导出失败: " + err.Error()})
			return
		}
		backup.Tables[table] = rows
	}
	recordAudit(c, "导出", "配置备份", services.FormatAuditDetail(importCountsDetail(backup.Tables), services.AuditResultPart("success")))
	c.Header("Content-Disposition", "attachment; filename=lazy-balancer-backup-"+time.Now().Format("20060102-150405")+".json")
	c.JSON(http.StatusOK, backup)
}

func (h *Handlers) ImportConfigBackup(c *gin.Context) {
	if isMaster, err := h.clusterService.IsMaster(c.Request.Context()); err != nil || !isMaster {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "仅主节点支持导入配置"})
		return
	}
	var backup configBackup
	if err := c.ShouldBindJSON(&backup); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "备份文件格式不正确"})
		return
	}
	if err := validateV2Backup(backup); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	ctx := c.Request.Context()
	existingRuleIDs, err := currentRuleIDs(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取现有规则失败"})
		return
	}
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开始导入事务失败"})
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	deleteOrder := []string{"api_keys", "path_rules", "upstreams", "cert_jobs", "lb_rules", "users", "ca_providers", "certificate_configs"}
	for _, table := range deleteOrder {
		if _, exists := backup.Tables[table]; !exists {
			continue
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			recordAudit(c, "导入失败", "配置备份", err.Error())
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "清空表 " + table + " 失败，已回滚: " + err.Error()})
			return
		}
	}
	insertOrder := []string{"users", "lb_rules", "ca_providers", "certificate_configs", "api_keys", "upstreams", "path_rules", "cert_jobs"}
	for _, table := range insertOrder {
		rows, exists := backup.Tables[table]
		if !exists {
			continue
		}
		if err := restoreTable(ctx, tx, db.DB, table, rows); err != nil {
			recordAudit(c, "导入失败", "配置备份", err.Error())
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "导入失败，已回滚: " + err.Error()})
			return
		}
	}
	importUserID := 0
	if uid, exists := c.Get("user_id"); exists {
		if f, ok := uid.(float64); ok {
			importUserID = int(f)
		}
	}
	if _, err := tx.ExecContext(ctx, "UPDATE lb_rules SET updated_by=? WHERE id IN (SELECT id FROM lb_rules)", importUserID); err != nil {
		recordAudit(c, "导入失败", "配置备份", "更新规则操作者失败: "+err.Error())
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新规则操作者失败，已回滚: " + err.Error()})
		return
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM cert_jobs WHERE rule_id NOT IN (SELECT caddy_id FROM lb_rules)"); err != nil {
		recordAudit(c, "导入失败", "配置备份", "清理孤儿证书任务失败: "+err.Error())
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "清理孤儿证书任务失败，已回滚: " + err.Error()})
		return
	}
	if backup.Config != nil {
		valid, err := tableColumns(ctx, db.DB, "global_config")
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取配置结构失败"})
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
				recordAudit(c, "导入失败", "配置备份", err.Error())
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "导入全局配置失败，已回滚: " + err.Error()})
				return
			}
		}
	}
	affectedRuleIDs := append([]string(nil), existingRuleIDs...)
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
	h.caddyOpMu.Lock()
	runtimeSnapshot, err := h.snapshotImportRuntime(affectedRuleIDs)
	if err != nil {
		h.caddyOpMu.Unlock()
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份当前运行配置失败: " + err.Error()})
		return
	}
	restoreRuntime := func() {
		if restoreErr := h.restoreImportRuntime(runtimeSnapshot); restoreErr != nil {
			log.Printf("导入失败后恢复运行配置失败: %v", restoreErr)
		}
	}
	if err := materializeImportCertificates(pendingCertificates); err != nil {
		restoreRuntime()
		h.caddyOpMu.Unlock()
		recordAudit(c, "导入失败", "配置备份", err.Error())
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "准备证书文件失败，已回滚: " + err.Error()})
		return
	}
	if err := h.caddyService.ApplyConfigFromTx(h.cfg, tx); err != nil {
		restoreRuntime()
		h.caddyOpMu.Unlock()
		recordAudit(c, "导入失败", "配置备份", "Caddy 配置验证未通过，数据库未变更: "+err.Error())
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "备份生成的配置未通过 Caddy 验证，未执行导入: " + err.Error()})
		return
	}
	if err := services.BumpClusterVersion(ctx, tx); err != nil {
		restoreRuntime()
		h.caddyOpMu.Unlock()
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新配置版本失败"})
		return
	}
	if err := tx.Commit(); err != nil {
		restoreRuntime()
		h.caddyOpMu.Unlock()
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交导入失败"})
		return
	}
	committed = true
	h.caddyOpMu.Unlock()
	counts := importCountsDetail(backup.Tables)
	recordAudit(c, "导入", "配置备份", services.FormatAuditDetail("来源：v2 备份（覆盖导入）", counts, services.AuditResultPart("success")))
	recordAudit(c, "重载", "Caddy配置", "导入配置后自动重载")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "配置导入成功", Data: gin.H{"summary": counts}})
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
	}
	for _, item := range labels {
		if rows, ok := tables[item.table]; ok {
			parts = append(parts, fmt.Sprintf(item.label, len(rows)))
		}
	}
	return joinStrings(parts, "；")
}
