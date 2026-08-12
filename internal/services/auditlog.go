package services

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
)

var (
	auditCleanupOnce   sync.Once
	auditCleanupMu     sync.Mutex
	auditCleanupCancel context.CancelFunc
	auditCleanupDone   chan struct{}
)

var configFieldSections = map[string]string{
	"acme_email":             "ACME全局设置",
	"cert_expiry_days":       "ACME全局设置",
	"cert_renewal_days":      "ACME全局设置",
	"cert_renewal_attempts":  "ACME全局设置",
	"default_ca_provider_id": "ACME全局设置",
	"dns_provider":           "ACME全局设置",
	"dns_credentials":        "ACME全局设置",

	"caddy_log_level":               "Caddy全局配置",
	"caddy_log_size_mb":             "Caddy全局配置",
	"request_body_max_size_mb":      "Caddy全局配置",
	"http_read_timeout":             "Caddy全局配置",
	"http_write_timeout":            "Caddy全局配置",
	"http_idle_timeout":             "Caddy全局配置",
	"upstream_keepalive_timeout":    "Caddy全局配置",
	"proxy_dial_timeout":            "Caddy全局配置",
	"proxy_response_header_timeout": "Caddy全局配置",
	"proxy_read_timeout":            "Caddy全局配置",
	"proxy_write_timeout":           "Caddy全局配置",
	"proxy_stream_timeout":          "Caddy全局配置",
	"proxy_flush_interval":          "Caddy全局配置",
	"proxy_stream_close_delay":      "Caddy全局配置",
	"server_tokens_hidden":          "Caddy全局配置",
	"access_log_json":               "Caddy全局配置",
	"access_log_format":             "Caddy全局配置",

	"log_level":                      "基础设置",
	"cert_job_log_size_mb":           "基础设置",
	"runtime_log_size_mb":            "基础设置",
	"audit_retention_months":         "基础设置",
	"security_events_retention_days": "基础设置",
	"security_events_retention_max":  "基础设置",
	"jwt_expire_minutes":             "基础设置",
	"timezone":                       "基础设置",
}

func GetConfigSection(field string) string {
	if section, ok := configFieldSections[field]; ok {
		return section
	}
	return "全局配置"
}

func GetConfigSourceSection(source string) string {
	switch source {
	case "basic":
		return "基础设置"
	case "cluster":
		return "集群管理"
	case "acme":
		return "ACME全局设置"
	case "caddy":
		return "Caddy全局配置"
	default:
		return "全局配置"
	}
}

func RecordAuditLog(username, action, resource, detail, ipAddress string) {
	if db.AuditDB == nil {
		log.Printf("audit log write skipped: audit database is not initialized")
		return
	}
	if _, err := db.AuditDB.Exec("INSERT INTO audit_log (username, action, resource, detail, ip_address) VALUES (?, ?, ?, ?, ?)",
		username, action, resource, detail, ipAddress); err != nil {
		Logf("error", "audit log write failed: %v", err)
	}
}

func AppendAPIKeyAuditDetail(detail string, keyID int, keyName string) string {
	apiKeyPart := fmt.Sprintf("API密钥 %d（%s）", keyID, keyName)
	if detail == "" {
		return fmt.Sprintf("认证方式：API密钥；%s", apiKeyPart)
	}
	return fmt.Sprintf("%s；认证方式：API密钥；%s", detail, apiKeyPart)
}

func CleanupAuditLogs() {
	var retentionMonths int
	if err := db.DB.QueryRow("SELECT COALESCE(audit_retention_months, 3) FROM global_config WHERE id=1").Scan(&retentionMonths); err != nil {
		return
	}
	if retentionMonths < 1 {
		retentionMonths = 1
	}
	cutoff := time.Now().UTC().AddDate(0, -retentionMonths, 0).Format("2006-01-02 15:04:05")
	if db.AuditDB == nil {
		log.Printf("audit log cleanup skipped: audit database is not initialized")
		return
	}
	if _, err := db.AuditDB.Exec("DELETE FROM audit_log WHERE created_at < ?", cutoff); err != nil {
		log.Printf("audit log cleanup failed: %v", err)
	}
}

func StartAuditCleanup() {
	auditCleanupOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		auditCleanupMu.Lock()
		auditCleanupCancel = cancel
		auditCleanupDone = done
		auditCleanupMu.Unlock()
		go func() {
			defer close(done)
			ticker := time.NewTicker(24 * time.Hour)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					CleanupAuditLogs()
				case <-ctx.Done():
					return
				}
			}
		}()
		CleanupAuditLogs()
	})
}

func StopAuditCleanup() {
	auditCleanupMu.Lock()
	cancel := auditCleanupCancel
	done := auditCleanupDone
	auditCleanupMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

func FormatAuditAction(method, path string) (action, resource, detail string) {
	p := path
	detail = p

	switch {
	case p == "/api/v1/auth/login":
		return "登录", "用户认证", p
	case p == "/api/v1/auth/logout":
		return "登出", "用户认证", p
	case strings.Contains(p, "/rules/") && strings.Contains(p, "/enable"):
		return "启用", "负载均衡规则", p
	case strings.Contains(p, "/rules/") && strings.Contains(p, "/disable"):
		return "禁用", "负载均衡规则", p
	case strings.Contains(p, "/rules/") && strings.Contains(p, "/duplicate"):
		return "复制", "负载均衡规则", p
	case strings.HasPrefix(p, "/api/v1/rules") && method == "POST":
		return "创建", "负载均衡规则", p
	case strings.HasPrefix(p, "/api/v1/rules/") && method == "PUT":
		return "更新", "负载均衡规则", p
	case strings.HasPrefix(p, "/api/v1/rules/") && method == "DELETE":
		return "删除", "负载均衡规则", p

	case strings.Contains(p, "/users/") && strings.Contains(p, "/reset-password"):
		return "重置密码", "用户", p
	case strings.Contains(p, "/users/") && strings.Contains(p, "/status"):
		return "修改状态", "用户", p
	case strings.Contains(p, "/users/me"):
		return "更新资料", "用户", p
	case strings.HasPrefix(p, "/api/v1/users") && method == "POST":
		return "创建", "用户", p
	case strings.HasPrefix(p, "/api/v1/users/") && method == "PUT":
		return "更新", "用户", p
	case strings.HasPrefix(p, "/api/v1/users/") && method == "DELETE":
		return "删除", "用户", p

	case strings.Contains(p, "/keys") && method == "POST":
		return "创建", "API密钥", p
	case strings.Contains(p, "/api-keys/") && strings.Contains(p, "/status"):
		return "修改状态", "API密钥", p
	case strings.Contains(p, "/users/me/api-keys/") && method == "PATCH":
		return "修改状态", "API密钥", p
	case strings.Contains(p, "/keys") && method == "DELETE":
		return "删除", "API密钥", p

	case p == "/api/v1/config":
		return "", "", ""
	case strings.Contains(p, "/config/reload"):
		return "重载", "Caddy配置", p

	case strings.Contains(p, "/certificate-configs") && method == "POST":
		return "创建", "DNS提供商配置", p
	case strings.Contains(p, "/certificate-configs") && method == "PUT":
		return "更新", "DNS提供商配置", p
	case strings.Contains(p, "/certificate-configs") && method == "DELETE":
		return "删除", "DNS提供商配置", p

	case strings.Contains(p, "/ca-providers") && strings.Contains(p, "/test"):
		return "", "", ""
	case strings.Contains(p, "/ca-providers") && method == "PUT":
		return "", "", ""

	case strings.Contains(p, "/certificates/jobs") && strings.Contains(p, "/retry"):
		return "重试", "证书签发任务", p
	case strings.Contains(p, "/certificates/jobs") && method == "DELETE":
		return "删除", "证书签发任务", p
	case strings.Contains(p, "/certificates/issue"):
		return "触发签发", "证书", p

	case strings.Contains(p, "/nodes/register"):
		return "注册", "集群节点", p
	case strings.Contains(p, "/nodes/") && strings.Contains(p, "/approve"):
		return "审批", "集群节点", p
	case strings.Contains(p, "/nodes/") && strings.Contains(p, "/reject"):
		return "拒绝", "集群节点", p
	case strings.Contains(p, "/nodes/") && method == "DELETE":
		return "删除", "集群节点", p
	case strings.Contains(p, "/nodes/") && method == "PUT":
		return "更新", "集群节点", p

	case strings.Contains(p, "/caddy/start"):
		return "启动", "Caddy服务", p
	case strings.Contains(p, "/caddy/stop"):
		return "停止", "Caddy服务", p
	case strings.Contains(p, "/caddy/restart"):
		return "重启", "Caddy服务", p
	case strings.Contains(p, "/caddy/config") && method == "PUT":
		return "更新", "Caddy配置", p

	case strings.Contains(p, "/sync/pull"):
		return "同步", "配置同步", p
	}

	return "", "", ""
}
