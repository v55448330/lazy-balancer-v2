package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

type v1Backup struct {
	UserList       *v1Section `json:"user_list"`
	MainConfig     *v1Section `json:"main_config"`
	ProxyConfig    *v1Section `json:"proxy_config"`
	UpstreamConfig *v1Section `json:"upstream_config"`
}

type v1Section struct {
	Config json.RawMessage `json:"config"`
}

type v1Upstream struct {
	PK     int `json:"pk"`
	Fields struct {
		Status  bool   `json:"status"`
		Address string `json:"address"`
		Port    int    `json:"port"`
		Weight  int    `json:"weight"`
	} `json:"fields"`
}

type v1Proxy struct {
	PK     int `json:"pk"`
	Fields struct {
		ProxyName           string `json:"proxy_name"`
		Protocol            bool   `json:"protocol"`
		Listen              int    `json:"listen"`
		ServerName          string `json:"server_name"`
		BalancerType        string `json:"balancer_type"`
		HTTPCheck           bool   `json:"http_check"`
		Gzip                bool   `json:"gzip"`
		Description         string `json:"description"`
		SSL                 bool   `json:"ssl"`
		SSLRedirectHTTPS    bool   `json:"ssl_redirect_https"`
		SSLCert             string `json:"ssl_cert"`
		SSLKey              string `json:"ssl_key"`
		BackendProtocol     string `json:"backend_protocol"`
		BackendDomainToggle bool   `json:"backend_domain_toggle"`
		BackendDomain       string `json:"backend_domain"`
		Status              bool   `json:"status"`
		MaxFails            int    `json:"max_fails"`
		FailTimeout         int    `json:"fail_timeout"`
		UpstreamList        []int  `json:"upstream_list"`
	} `json:"fields"`
}

type convertedRule struct {
	Name        string
	Domain      string
	ListenPort  int
	Protocol    string
	EnableTLS   bool
	TLSCert     string
	TLSKey      string
	Redirect    bool
	Compress    bool
	HealthFails int
	HealthInt   int
	ActiveHC    bool
	Enabled     bool
	HostHeader  string
	Description string
	Upstreams   []convertedUpstream
}

type convertedUpstream struct {
	Host     string
	Port     int
	Weight   int
	Enabled  bool
	Protocol string
}

func (b *v1Backup) parse() ([]v1Proxy, map[int]v1Upstream, error) {
	if b.ProxyConfig == nil || b.UpstreamConfig == nil {
		return nil, nil, fmt.Errorf("不是有效的 V1 备份文件（缺少 proxy_config/upstream_config）")
	}
	proxiesRaw, err := unwrapJSONString(b.ProxyConfig.Config)
	if err != nil {
		return nil, nil, fmt.Errorf("解析 proxy_config 失败: %w", err)
	}
	var proxies []v1Proxy
	if err := json.Unmarshal(proxiesRaw, &proxies); err != nil {
		return nil, nil, fmt.Errorf("解析 proxy_config 失败: %w", err)
	}
	upstreamsRaw, err := unwrapJSONString(b.UpstreamConfig.Config)
	if err != nil {
		return nil, nil, fmt.Errorf("解析 upstream_config 失败: %w", err)
	}
	var upstreams []v1Upstream
	if err := json.Unmarshal(upstreamsRaw, &upstreams); err != nil {
		return nil, nil, fmt.Errorf("解析 upstream_config 失败: %w", err)
	}
	byPK := make(map[int]v1Upstream, len(upstreams))
	for _, u := range upstreams {
		if _, dup := byPK[u.PK]; dup {
			return nil, nil, fmt.Errorf("upstream_config 中存在重复的主键: %d", u.PK)
		}
		byPK[u.PK] = u
	}
	return proxies, byPK, nil
}

func unwrapJSONString(raw json.RawMessage) (json.RawMessage, error) {
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err == nil {
		return json.RawMessage(encoded), nil
	}
	return raw, nil
}

func convertV1Rules(proxies []v1Proxy, upstreams map[int]v1Upstream) []convertedRule {
	rules := make([]convertedRule, 0, len(proxies))
	for _, p := range proxies {
		f := p.Fields
		rule := convertedRule{
			Name:        f.ProxyName,
			Domain:      f.ServerName,
			ListenPort:  f.Listen,
			Protocol:    "http",
			EnableTLS:   f.SSL,
			Redirect:    f.SSLRedirectHTTPS,
			Compress:    f.Gzip,
			HealthFails: f.MaxFails,
			HealthInt:   f.FailTimeout,
			ActiveHC:    f.HTTPCheck,
			Enabled:     f.Status,
			Description: f.Description,
		}
		if !f.Protocol {
			rule.Protocol = "tcp"
		}
		if rule.HealthFails <= 0 {
			rule.HealthFails = 3
		}
		if rule.HealthInt <= 0 {
			rule.HealthInt = 10
		}
		if f.SSL {
			rule.TLSCert = f.SSLCert
			rule.TLSKey = f.SSLKey
		}
		if f.BackendDomainToggle && f.BackendDomain != "" {
			rule.HostHeader = f.BackendDomain
		}
		for _, pk := range f.UpstreamList {
			u, ok := upstreams[pk]
			if !ok {
				continue
			}
			protocol := f.BackendProtocol
			if protocol == "" {
				protocol = "http"
			}
			weight := u.Fields.Weight
			if weight <= 0 {
				weight = 100
			}
			rule.Upstreams = append(rule.Upstreams, convertedUpstream{
				Host: u.Fields.Address, Port: u.Fields.Port, Weight: weight, Enabled: u.Fields.Status, Protocol: protocol,
			})
		}
		rules = append(rules, rule)
	}
	return rules
}

type importValidateResponse struct {
	Valid    bool           `json:"valid"`
	Type     string         `json:"type"`
	Error    string         `json:"error,omitempty"`
	Summary  map[string]int `json:"summary,omitempty"`
	Warnings []string       `json:"warnings,omitempty"`
}

const maxConfigImportBytes int64 = 16 << 20

func limitConfigImportBody(c *gin.Context) bool {
	if c.Request.ContentLength > maxConfigImportBytes {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "备份文件不能超过 16MB"})
		return false
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxConfigImportBytes)
	return true
}

func isRequestBodyTooLarge(err error) bool {
	var maxBytesErr *http.MaxBytesError
	return errors.As(err, &maxBytesErr)
}

func (h *Handlers) ValidateConfigImport(c *gin.Context) {
	if isMaster, err := h.clusterService.IsMaster(c.Request.Context()); err != nil || !isMaster {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "仅主节点支持导入配置"})
		return
	}
	if !limitConfigImportBody(c) {
		return
	}
	body, err := c.GetRawData()
	if isRequestBodyTooLarge(err) {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "备份文件不能超过 16MB"})
		return
	}
	if err != nil || len(body) == 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "备份文件内容为空"})
		return
	}
	body = bytes.TrimPrefix(body, []byte("\xef\xbb\xbf"))
	var v2Probe struct {
		Meta struct {
			App string `json:"app"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(body, &v2Probe); err == nil && v2Probe.Meta.App == "lazy-balancer-v2" {
		var backup configBackup
		if err := json.Unmarshal(body, &backup); err != nil {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: importValidateResponse{Valid: false, Type: "v2", Error: "备份文件格式不正确: " + err.Error()}})
			return
		}
		if err := validateV2Backup(backup); err != nil {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: importValidateResponse{Valid: false, Type: "v2", Error: err.Error()}})
			return
		}
		summary := map[string]int{}
		for table, rows := range backup.Tables {
			summary[table] = len(rows)
		}
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: importValidateResponse{Valid: true, Type: "v2", Summary: summary}})
		return
	}
	var v1 v1Backup
	if err := json.Unmarshal(body, &v1); err == nil && v1.ProxyConfig != nil && v1.UpstreamConfig != nil {
		proxies, upstreams, err := v1.parse()
		if err != nil {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: importValidateResponse{Valid: false, Type: "v1", Error: err.Error()}})
			return
		}
		rules := convertV1Rules(proxies, upstreams)
		tlsCount := 0
		upstreamCount := 0
		for _, r := range rules {
			if r.EnableTLS {
				tlsCount++
			}
			upstreamCount += len(r.Upstreams)
		}
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: importValidateResponse{
			Valid: true,
			Type:  "v1",
			Summary: map[string]int{
				"rules":     len(rules),
				"tls_rules": tlsCount,
				"upstreams": upstreamCount,
			},
			Warnings: []string{
				"仅导入负载均衡规则（用户、全局配置、证书任务不导入）",
				"v1 不支持 ACME，HTTPS 规则的证书与私钥将以手动方式随规则导入",
				"nginx 特有配置（custom_config、日志路径等）已忽略",
			},
		}})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: importValidateResponse{Valid: false, Error: "无法识别的备份文件格式（既不是 V2 备份，也不是 V1 备份）"}})
}

func (h *Handlers) ImportV1Config(c *gin.Context) {
	if isMaster, err := h.clusterService.IsMaster(c.Request.Context()); err != nil || !isMaster {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "仅主节点支持导入配置"})
		return
	}
	if !limitConfigImportBody(c) {
		return
	}
	body, err := c.GetRawData()
	if isRequestBodyTooLarge(err) {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "备份文件不能超过 16MB"})
		return
	}
	if err != nil || len(body) == 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "备份文件内容为空"})
		return
	}
	body = bytes.TrimPrefix(body, []byte("\xef\xbb\xbf"))
	var v1 v1Backup
	if err := json.Unmarshal(body, &v1); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "备份文件不是有效的 JSON"})
		return
	}
	proxies, upstreams, err := v1.parse()
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	rules := convertV1Rules(proxies, upstreams)
	if len(rules) == 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "备份中没有可导入的规则"})
		return
	}
	ctx := c.Request.Context()
	existingRuleIDs, err := currentRuleIDs(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取现有规则失败"})
		return
	}
	// 与 UpdateRule 同一锁序：先 caddyOpMu 后 DB 事务，避免与规则写路径循环等待
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	if queueManager := services.GetCAQueueManager(); queueManager != nil {
		queueManager.PauseAndDrain()
		defer func() {
			queueManager.Resume()
			if err := services.RequeueNonTerminalCertJobs(); err != nil {
				log.Printf("ImportV1Config certificate job recovery failed: %v", err)
			}
		}()
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
	if _, err := tx.ExecContext(ctx, "DELETE FROM upstreams"); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "清理旧上游失败，已回滚: " + err.Error()})
		return
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM lb_rules"); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "清理旧规则失败，已回滚: " + err.Error()})
		return
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM cert_jobs WHERE rule_id NOT IN (SELECT caddy_id FROM lb_rules)"); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "清理孤儿证书任务失败，已回滚: " + err.Error()})
		return
	}
	userID := int(contextUserID(c))
	imported := 0
	tlsCount := 0
	upstreamCount := 0
	affectedRuleIDs := append([]string(nil), existingRuleIDs...)
	var pendingCerts []importCertificate
	for _, r := range rules {
		caddyID, err := services.GenerateCaddyID()
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "生成规则编号失败"})
			return
		}
		affectedRuleIDs = append(affectedRuleIDs, caddyID)
		_, err = tx.ExecContext(ctx, `INSERT INTO lb_rules (name, description, protocol, domain, listen_port, strategy, dynamic_dns, enable_dns_server, dns_server,
			health_check_path, health_check_interval, health_check_timeout,
			health_check_unhealthy_threshold, health_check_healthy_threshold,
			enable_active_health_check, tcp_health_check_port, tcp_try_duration, tcp_try_interval,
			request_body_max_size_mb, upstream_keepalive_timeout, server_tokens_hidden,
			host_header, enable_tls, tls_source, acme_config_id, ca_provider_id, tls_cert, tls_key, tls_http_redirect,
			enable_compress, compress_types, enabled, created_by, updated_by, updated_at, caddy_id, log_enabled)
		VALUES (?, ?, ?, ?, ?, ?, 0, 0, '', '', ?, 5, ?, 2, ?, 0, 0, 250, 0, 0, 0, ?, ?, ?, 0, 0, ?, ?, ?, ?, 'gzip', ?, ?, ?, datetime('now'), ?, 0)`,
			r.Name, r.Description, r.Protocol, r.Domain, r.ListenPort, "weighted_round_robin",
			r.HealthInt, r.HealthFails, r.ActiveHC,
			r.HostHeader, r.EnableTLS, tlsSource(r), r.TLSCert, r.TLSKey, r.Redirect,
			r.Compress, r.Enabled, userID, userID, caddyID)
		if err != nil {
			recordAudit(c, "导入失败", "配置备份", fmt.Sprintf("规则 %s: %v", r.Name, err))
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "导入规则失败，已回滚: " + err.Error()})
			return
		}
		for _, u := range r.Upstreams {
			if _, err := tx.ExecContext(ctx, `INSERT INTO upstreams (rule_id, host, port, weight, domain, dynamic_dns, enabled, protocol, host_header, dns_server, max_connections)
				VALUES (?, ?, ?, ?, '', 0, ?, ?, '', '', 0)`, caddyID, u.Host, u.Port, u.Weight, u.Enabled, u.Protocol); err != nil {
				recordAudit(c, "导入失败", "配置备份", fmt.Sprintf("规则 %s 上游: %v", r.Name, err))
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "导入上游失败，已回滚: " + err.Error()})
				return
			}
			upstreamCount++
		}
		if r.EnableTLS && r.TLSCert != "" && r.TLSKey != "" {
			pendingCerts = append(pendingCerts, importCertificate{ruleID: caddyID, certPEM: r.TLSCert, keyPEM: r.TLSKey})
		}
		if r.EnableTLS {
			tlsCount++
		}
		imported++
	}
	runtimeSnapshot, err := h.snapshotImportRuntime(affectedRuleIDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份当前运行配置失败: " + err.Error()})
		return
	}
	restoreRuntime := func(importErr error) error {
		if restoreErr := h.restoreImportRuntime(runtimeSnapshot); restoreErr != nil {
			return errors.Join(importErr, fmt.Errorf("恢复运行配置失败: %w", restoreErr))
		}
		return importErr
	}
	if err := materializeImportCertificates(pendingCerts); err != nil {
		err = restoreRuntime(err)
		recordAudit(c, "导入失败", "配置备份", err.Error())
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "准备证书文件失败: " + err.Error()})
		return
	}
	if err := h.caddyService.ApplyConfigFromTx(h.cfg, tx); err != nil {
		err = restoreRuntime(err)
		recordAudit(c, "导入失败", "配置备份", "Caddy 配置验证未通过，数据库未变更: "+err.Error())
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "备份生成的配置未通过 Caddy 验证，未执行导入: " + err.Error()})
		return
	}
	if err := services.BumpClusterVersion(ctx, tx); err != nil {
		err = restoreRuntime(err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新配置版本失败: " + err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		err = restoreRuntime(err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交导入失败: " + err.Error()})
		return
	}
	committed = true
	recordAudit(c, "导入", "配置备份", services.FormatAuditDetail("来源：v1 备份（覆盖导入规则）", fmt.Sprintf("规则 %d 条", imported), fmt.Sprintf("TLS 规则 %d 条", tlsCount), fmt.Sprintf("上游 %d 个", upstreamCount), services.AuditResultPart("success")))
	recordAudit(c, "重载", "Caddy配置", "导入配置后自动重载")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: fmt.Sprintf("已导入 %d 条规则", imported), Data: gin.H{"imported": imported}})
}

func tlsSource(r convertedRule) string {
	if r.EnableTLS {
		return "manual"
	}
	return ""
}
