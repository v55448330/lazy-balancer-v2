package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/services/dnsproviders"
)

// maskedDNSCredentialsSentinel（R72 二十六次 D4）：非 admin 响应中 DNS 凭证值的
// 掩码占位。更新路径识别到全掩码形态按「未提交」处理（保持原值）——前端
// FreeCertificates 的编辑表单会原样回传 GET 到的值。
const maskedDNSCredentialsSentinel = "***"

// maskDNSCredentialsJSON 把凭证 JSON 串的每个值替换为掩码（保留键形态，
// 前端表单按 provider 字段渲染）。解析失败时整体掩码（防御性）。
func maskDNSCredentialsJSON(raw string) string {
	if raw == "" {
		return ""
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return maskedDNSCredentialsSentinel
	}
	masked := make(map[string]string, len(m))
	for k, v := range m {
		if v == "" {
			masked[k] = ""
			continue
		}
		masked[k] = maskedDNSCredentialsSentinel
	}
	out, err := json.Marshal(masked)
	if err != nil {
		return maskedDNSCredentialsSentinel
	}
	return string(out)
}

// isMaskedDNSCredentials 判断提交的凭证是否为全掩码回传（GET 掩码 → 未改动
// → 保持原值）。空串值不算掩码（允许部分字段清空的语义保留给显式提交）。
func isMaskedDNSCredentials(m map[string]string) bool {
	if len(m) == 0 {
		return false
	}
	for _, v := range m {
		if v != "" && v != maskedDNSCredentialsSentinel {
			return false
		}
	}
	// 至少一个非空值（全空串 = 显式清空语义，交给原逻辑）。
	for _, v := range m {
		if v == maskedDNSCredentialsSentinel {
			return true
		}
	}
	return false
}

func (h *Handlers) ListCertificateConfigs(c *gin.Context) {
	rows, err := db.DB.Query("SELECT id, name, dns_provider, COALESCE(dns_credentials,''), enabled, created_at, updated_at FROM certificate_configs ORDER BY id")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to query configs"})
		return
	}
	defer rows.Close()

	isAdmin := false
	if role, ok := c.Get("role"); ok && role == "admin" {
		isAdmin = true
	}
	var configs []models.CertificateConfig
	for rows.Next() {
		var cfg models.CertificateConfig
		if err := rows.Scan(&cfg.ID, &cfg.Name, &cfg.DNSProvider, &cfg.DNSCredentials, &cfg.Enabled, &cfg.CreatedAt, &cfg.UpdatedAt); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取证书配置失败: " + err.Error()})
			return
		}
		// R72 二十六次 D4：凭证最小可见性——非 admin 只见掩码形态。
		if !isAdmin {
			cfg.DNSCredentials = maskDNSCredentialsJSON(cfg.DNSCredentials)
		}
		configs = append(configs, cfg)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取证书配置失败: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: configs})
}

func (h *Handlers) CreateCertificateConfig(c *gin.Context) {

	var req models.CreateCertificateConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	if req.DNSProvider == "" {
		req.DNSProvider = "dnspod"
	}

	provider, ok := dnsproviders.Get(req.DNSProvider)
	if !ok {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Unknown DNS provider"})
		return
	}

	if _, err := provider.BuildCredentialsJSON(req.DNSCredentials); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	credsJSON, _ := json.Marshal(req.DNSCredentials)
	result, err := db.DB.Exec(`
		INSERT INTO certificate_configs (name, dns_provider, dns_credentials, enabled)
		VALUES (?, ?, ?, ?)
	`, req.Name, req.DNSProvider, string(credsJSON), req.Enabled)

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to create config"})
		return
	}

	id, _ := result.LastInsertId()
	recordAudit(c, "创建", "DNS配置", services.FormatAuditDetail(fmt.Sprintf("配置 %d", id), req.Name, req.DNSProvider, fmt.Sprintf("启用：%t", req.Enabled)))
	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Message: "Config created", Data: gin.H{"id": id}})
}

func (h *Handlers) UpdateCertificateConfig(c *gin.Context) {

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid id parameter"})
		return
	}

	var req models.UpdateCertificateConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	var oldName, oldProvider, oldCredentials string
	var oldEnabled bool
	if err := db.DB.QueryRow("SELECT name, dns_provider, COALESCE(dns_credentials,''), COALESCE(enabled,1) FROM certificate_configs WHERE id=?", id).Scan(&oldName, &oldProvider, &oldCredentials, &oldEnabled); dbQueryNotFound(c, err, "Config not found", "UpdateCertificateConfig query config") {
		return
	}
	effectiveProvider := oldProvider
	if req.DNSProvider != "" {
		effectiveProvider = req.DNSProvider
	}
	effectiveCredentials := req.DNSCredentials
	if effectiveCredentials == nil {
		effectiveCredentials = map[string]string{}
		if err := json.Unmarshal([]byte(oldCredentials), &effectiveCredentials); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid stored DNS credentials"})
			return
		}
	}
	provider, ok := dnsproviders.Get(effectiveProvider)
	if !ok {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Unknown DNS provider"})
		return
	}
	if _, err := provider.BuildCredentialsJSON(effectiveCredentials); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	changed := []string{}
	query := "UPDATE certificate_configs SET "
	var args []interface{}

	if req.Name != "" && req.Name != oldName {
		query += "name = ?, "
		args = append(args, req.Name)
		changed = append(changed, "名称")
	}
	if req.DNSProvider != "" && req.DNSProvider != oldProvider {
		query += "dns_provider = ?, "
		args = append(args, req.DNSProvider)
		changed = append(changed, "DNS提供商")
	}
	if req.DNSCredentials != nil {
		// R72 二十六次 D4：全掩码回传（非 admin GET 后未改动即保存）按未提交
		// 处理——否则掩码串会覆盖真实凭证。
		if isMaskedDNSCredentials(req.DNSCredentials) {
			req.DNSCredentials = nil
		} else {
			credsJSON, _ := json.Marshal(req.DNSCredentials)
			if string(credsJSON) != oldCredentials {
				query += "dns_credentials = ?, "
				args = append(args, string(credsJSON))
				changed = append(changed, "凭证")
			}
		}
	}
	if req.Enabled != nil && *req.Enabled != oldEnabled {
		query += "enabled = ?, "
		args = append(args, *req.Enabled)
		changed = append(changed, "启用状态")
	}

	if len(changed) == 0 {
		recordAudit(c, "更新", "DNS配置", services.FormatAuditDetail(fmt.Sprintf("配置 %d", id), "无修改"))
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Config unchanged"})
		return
	}

	query += "updated_at = datetime('now') WHERE id = ?"
	args = append(args, id)

	if _, err := db.DB.Exec(query, args...); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to update config"})
		return
	}
	recordAudit(c, "更新", "DNS配置", services.FormatAuditDetail(fmt.Sprintf("配置 %d", id), fmt.Sprintf("变更：%s", strings.Join(changed, "、"))))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Config updated"})
}

func (h *Handlers) DeleteCertificateConfig(c *gin.Context) {

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid id parameter"})
		return
	}
	var name, provider string
	if err := db.DB.QueryRow("SELECT name, dns_provider FROM certificate_configs WHERE id = ?", id).Scan(&name, &provider); dbQueryNotFound(c, err, "Config not found", "DeleteCertificateConfig query config") {
		return
	}
	// C-04（2026-09-05 证书域审计裁定）：删除前检查规则引用（全部规则，不限
	// enabled）——被引用的配置删除后，关联规则下一次续签/首签会以
	//「未选择可用的 DNS 提供商」静默失败，必须 409 显式列出引用方。
	refs, refErr := db.DB.Query(`SELECT caddy_id, COALESCE(domain,'') FROM lb_rules WHERE acme_config_id=? ORDER BY caddy_id`, id)
	if refErr != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to check rule references"})
		return
	}
	type ruleRef struct{ caddyID, domain string }
	var references []ruleRef
	for refs.Next() {
		var ref ruleRef
		if err := refs.Scan(&ref.caddyID, &ref.domain); err != nil {
			refs.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to check rule references"})
			return
		}
		references = append(references, ref)
	}
	if err := refs.Err(); err != nil {
		refs.Close()
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to check rule references"})
		return
	}
	if err := refs.Close(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to check rule references"})
		return
	}
	if len(references) > 0 {
		const maxListedReferences = 5
		listed := make([]string, 0, len(references))
		for _, ref := range references {
			if len(listed) == maxListedReferences {
				break
			}
			if ref.domain != "" {
				listed = append(listed, fmt.Sprintf("%s (%s)", ref.domain, ref.caddyID))
			} else {
				listed = append(listed, ref.caddyID)
			}
		}
		message := fmt.Sprintf("该 DNS 配置正被 %d 条负载规则引用，删除后这些规则将无法自动签发/续签证书，请先修改规则的 DNS 配置后再删除：%s", len(references), strings.Join(listed, "、"))
		if len(references) > maxListedReferences {
			message += fmt.Sprintf(" 等 %d 条规则", len(references))
		}
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: message})
		return
	}
	if _, err := db.DB.Exec("DELETE FROM certificate_configs WHERE id = ?", id); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to delete config"})
		return
	}
	recordAudit(c, "删除", "DNS配置", services.FormatAuditDetail(fmt.Sprintf("配置 %d", id), name, provider))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Config deleted"})
}

func (h *Handlers) ListDNSProviders(c *gin.Context) {
	providers := dnsproviders.List()
	var result []gin.H
	for _, p := range providers {
		fields := p.CredentialFields()
		var fieldList []gin.H
		for _, f := range fields {
			fieldList = append(fieldList, gin.H{
				"name":        f.Name,
				"label":       f.Label,
				"type":        f.Type,
				"required":    f.Required,
				"placeholder": f.Placeholder,
				"options":     p.CredentialFieldOptions(f.Name),
			})
		}
		result = append(result, gin.H{
			"code":              p.Code(),
			"name":              p.Name(),
			"credential_fields": fieldList,
		})
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: result})
}

func (h *Handlers) TestCertificateConfig(c *gin.Context) {
	var provider, credentials string
	var creds map[string]string

	var req struct {
		Domain         string            `json:"domain"`
		DNSProvider    string            `json:"dns_provider"`
		DNSCredentials map[string]string `json:"dns_credentials"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	idParam := c.Param("id")
	id, idErr := strconv.Atoi(idParam)
	if idParam != "" && (idErr != nil || id <= 0) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid id parameter"})
		return
	}
	var configName string
	if idParam != "" {
		err := db.DB.QueryRow("SELECT name, dns_provider, COALESCE(dns_credentials,'') FROM certificate_configs WHERE id=?", id).Scan(&configName, &provider, &credentials)
		if errors.Is(err, sql.ErrNoRows) {
			recordAudit(c, "测试失败", "DNS配置", services.FormatAuditDetail(fmt.Sprintf("配置 %d", id), services.AuditResultPart("not_found")))
		}
		if dbQueryNotFound(c, err, "Config not found", "TestCertificateConfig query config") {
			return
		}
		// R68 B-F5：存储凭证「非空但解析失败」与「凭证填错」是不同故障——
		// unmarshal 错误此前被吞，creds=nil 走到 Validate 报「缺少凭证」，被误
		// 归因为 credentials_invalid（400），运营方会反复重改凭证。损坏归 500 +
		// 独立审计类别；空凭证（未填写/NULL）仍走 Validate 的缺凭证 400 原语义。
		if credentials != "" {
			if uerr := json.Unmarshal([]byte(credentials), &creds); uerr != nil {
				recordAudit(c, "测试失败", "DNS配置", services.FormatAuditDetail(fmt.Sprintf("配置 %d", id), configName, provider, services.AuditResultPart("storage_corrupted")))
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "存储的 DNS 凭证已损坏，请重新保存配置"})
				return
			}
		}
	} else {
		provider = req.DNSProvider
		creds = req.DNSCredentials
	}
	// C-16（2026-09-05 证书域审计裁定）：无 id 的保存前凭证测试（前端 saveConfig
	// 先调本端点验证）此前审计 detail 落「配置 0」——改为语义化来源标注；
	// 有 id 路径保留「配置 N」。
	auditTarget := fmt.Sprintf("配置 %d", id)
	if idParam == "" {
		auditTarget = services.AuditSourcePart("保存前测试")
	}
	if req.Domain == "" {
		recordAudit(c, "测试失败", "DNS配置", services.FormatAuditDetail(auditTarget, configName, provider, services.AuditResultPart("missing_domain")))
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请输入用于测试的域名"})
		return
	}

	p, ok := dnsproviders.Get(provider)
	if !ok {
		recordAudit(c, "测试失败", "DNS配置", services.FormatAuditDetail(auditTarget, configName, provider, services.AuditResultPart("unknown_provider")))
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Unknown provider"})
		return
	}
	if err := p.Validate(creds, req.Domain); err != nil {
		recordAudit(c, "测试失败", "DNS配置", services.FormatAuditDetail(auditTarget, configName, provider, req.Domain, services.AuditResultPart("credentials_invalid")))
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	recordAudit(c, "测试成功", "DNS配置", services.FormatAuditDetail(auditTarget, configName, provider, req.Domain, services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "凭证有效"})
}

func (h *Handlers) ListCertificates(c *gin.Context) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, h.cfg.CaddyAdminURL+"/pki/ca/local", nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "构造证书请求失败"})
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "获取证书列表失败: " + err.Error()})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("Caddy 返回异常状态: %d", resp.StatusCode)})
		return
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "解析证书列表失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: data})
}

func (h *Handlers) IssueCertificate(c *gin.Context) {
	var req struct {
		CaddyID string `json:"caddy_id"`
		Domain  string `json:"domain"`
		// C-19（2026-09-06 裁定）：批量全量重签须显式 {"all":true} 确认（含已签发任务、消耗 CA 配额）；caddy_id 与 all 同传以 caddy_id 为准
		All bool `json:"all"`
	}
	bindErr := c.ShouldBindJSON(&req)
	scope := "范围：全部 ACME 规则"
	if req.CaddyID != "" {
		scope = fmt.Sprintf("规则：%s", req.CaddyID)
	}
	auditFailure := func(result string, detail ...string) {
		parts := append([]string{scope}, detail...)
		parts = append(parts, services.AuditResultPart(result))
		recordAudit(c, "触发签发", "证书", services.FormatAuditDetail(parts...))
	}
	if bindErr != nil && !(errors.Is(bindErr, io.EOF) && c.Request.ContentLength == 0) {
		auditFailure("invalid_request")
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}
	if req.CaddyID == "" && req.Domain != "" {
		auditFailure("invalid_request")
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}
	qm := services.GetCAQueueManager()
	if qm == nil {
		auditFailure("failed", "CA 队列未初始化")
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "CA 队列未初始化"})
		return
	}
	queued := 0
	if req.CaddyID != "" {
		var enabled, enableTLS bool
		var protocol, tlsSource, ruleDomain string
		err := db.DB.QueryRow(`SELECT COALESCE(enabled,0), COALESCE(enable_tls,0), COALESCE(protocol,''), COALESCE(tls_source,''), COALESCE(domain,'') FROM lb_rules WHERE caddy_id = ?`, req.CaddyID).
			Scan(&enabled, &enableTLS, &protocol, &tlsSource, &ruleDomain)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				auditFailure("failed", "规则不存在")
			} else {
				auditFailure("failed", "查询规则失败")
			}
		}
		if dbQueryNotFound(c, err, "规则不存在", "IssueCertificate query rule") {
			return
		}
		if !enabled || protocol != "http" || !enableTLS || tlsSource != "acme_dns" {
			auditFailure("failed", "规则状态不支持 ACME 签发")
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "规则不是启用状态的 ACME HTTPS 规则"})
			return
		}
		canonicalRuleDomain, canonicalErr := services.CanonicalACMEDomains(ruleDomain)
		if canonicalErr != nil {
			auditFailure("failed", "规则域名无效")
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "规则域名不符合 ACME 签发要求"})
			return
		}
		if req.Domain != "" {
			canonicalRequestDomain, canonicalErr := services.CanonicalACMEDomains(req.Domain)
			if canonicalErr != nil || canonicalRequestDomain != canonicalRuleDomain {
				auditFailure("failed", "域名集合与规则不一致")
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "域名集合与规则不一致"})
				return
			}
		}
		var jobStatus string
		var jobUpdatedAt sql.NullTime
		err = db.DB.QueryRow("SELECT status, updated_at FROM cert_jobs WHERE rule_id=? AND domain=?", req.CaddyID, canonicalRuleDomain).Scan(&jobStatus, &jobUpdatedAt)
		if err == nil {
			if blocked, message := certJobRetryBlocked(jobStatus, jobUpdatedAt, time.Now()); blocked {
				auditFailure("blocked", "证书任务正在执行")
				c.JSON(http.StatusTooManyRequests, models.APIResponse{Code: 429, Message: message})
				return
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			auditFailure("failed", "读取证书任务失败: "+err.Error())
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取证书任务失败"})
			return
		}
		_, changed, err := services.CreateOrRequeueCertJobWithChange(req.CaddyID, canonicalRuleDomain, 0, qm)
		if err != nil {
			auditFailure("failed", "创建签发任务失败: "+err.Error())
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "创建签发任务失败: " + err.Error()})
			return
		}
		if changed {
			queued++
		}
	} else {
		if !req.All {
			auditFailure("invalid_request", "请求格式错误")
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "批量签发需要显式确认：请求体须包含 {\"all\": true}（定向签发请提供 caddy_id）"})
			return
		}
		rows, err := db.DB.Query("SELECT caddy_id, COALESCE(domain,'') FROM lb_rules WHERE enabled=1 AND enable_tls=1 AND tls_source='acme_dns' AND protocol='http' AND COALESCE(domain,'') != ''")
		if err != nil {
			auditFailure("failed", "查询 ACME 规则失败: "+err.Error())
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "查询 ACME 规则失败"})
			return
		}
		var failed []string
		type certTarget struct {
			ruleID string
			domain string
		}
		var targets []certTarget
		for rows.Next() {
			var ruleID, domain string
			if err := rows.Scan(&ruleID, &domain); err != nil {
				err = errors.Join(err, rows.Close())
				auditFailure("failed", "读取 ACME 规则失败: "+err.Error())
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取 ACME 规则失败: " + err.Error()})
				return
			}
			targets = append(targets, certTarget{ruleID: ruleID, domain: domain})
		}
		if err := rows.Err(); err != nil {
			err = errors.Join(err, rows.Close())
			auditFailure("failed", "遍历 ACME 规则失败: "+err.Error())
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "遍历 ACME 规则失败: " + err.Error()})
			return
		}
		if err := rows.Close(); err != nil {
			auditFailure("failed", "关闭 ACME 规则结果失败: "+err.Error())
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "关闭 ACME 规则结果失败: " + err.Error()})
			return
		}
		for _, target := range targets {
			_, changed, err := services.CreateOrRequeueCertJobWithChange(target.ruleID, target.domain, 0, qm)
			if err != nil {
				failed = append(failed, fmt.Sprintf("%s(%v)", target.domain, err))
				continue
			}
			if changed {
				queued++
			}
		}
		if queued == 0 && len(failed) > 0 {
			auditFailure("failed")
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "全部签发任务创建失败: " + strings.Join(failed, "; ")})
			return
		}
		if len(failed) > 0 {
			recordAudit(c, "触发签发", "证书", services.FormatAuditDetail(scope, fmt.Sprintf("入队 %d 个任务，失败 %d 个", queued, len(failed)), services.AuditResultPart("partial")))
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: fmt.Sprintf("已创建 %d 个签发任务，%d 个失败: %s", queued, len(failed), strings.Join(failed, "; ")), Data: gin.H{"queued": queued, "failed": len(failed)}})
			return
		}
	}
	recordAudit(c, "触发签发", "证书", services.FormatAuditDetail(scope, fmt.Sprintf("入队 %d 个任务", queued), services.AuditResultPart("requested")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: fmt.Sprintf("已创建 %d 个签发任务", queued) + h.caddyApplyNote(c), Data: gin.H{"queued": queued}})
}

func (h *Handlers) ParseCertificate(c *gin.Context) {
	// R72 二十八次审计 F3：证书解析入参 PEM 上限 2MB（对齐 admin-tls inspect 的
	// maxAdminTLSJSONBytes 量级）——此前无上限，任何持凭证者（含只读 API key，
	// 本端点在 readOnlyWriteRoutes）可投递任意大 body 造成内存压力。
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 2<<20)
	var req struct {
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	info, err := parseTLSCertificate(req.CertPEM, req.KeyPEM)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: info})
}
