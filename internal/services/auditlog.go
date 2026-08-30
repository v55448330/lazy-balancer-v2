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
	"acme_email":             "ACME配置",
	"cert_expiry_days":       "ACME配置",
	"cert_renewal_days":      "ACME配置",
	"cert_renewal_attempts":  "ACME配置",
	"default_ca_provider_id": "ACME配置",
	"dns_provider":           "ACME配置",
	"dns_credentials":        "ACME配置",

	"caddy_log_level":               "Caddy配置",
	"caddy_log_size_mb":             "Caddy配置",
	"request_body_max_size_mb":      "Caddy配置",
	"http_read_timeout":             "Caddy配置",
	"http_write_timeout":            "Caddy配置",
	"http_idle_timeout":             "Caddy配置",
	"upstream_keepalive_timeout":    "Caddy配置",
	"proxy_dial_timeout":            "Caddy配置",
	"proxy_response_header_timeout": "Caddy配置",
	"proxy_read_timeout":            "Caddy配置",
	"proxy_write_timeout":           "Caddy配置",
	"proxy_stream_timeout":          "Caddy配置",
	"proxy_flush_interval":          "Caddy配置",
	"proxy_stream_close_delay":      "Caddy配置",
	"server_tokens_hidden":          "Caddy配置",
	"access_log_json":               "Caddy配置",
	"access_log_format":             "Caddy配置",

	"log_level":              "基础设置",
	"cert_job_log_size_mb":   "基础设置",
	"audit_log_size_mb":      "基础设置",
	"runtime_log_size_mb":    "基础设置",
	"audit_retention_months": "基础设置",
	"jwt_expire_minutes":     "基础设置",
	"timezone":               "基础设置",
	"github_proxy_url":       "基础设置",
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
		return "ACME配置"
	case "caddy":
		return "Caddy配置"
	default:
		return "全局配置"
	}
}

// 操作日志词汇标准（系统标准，新老事件均须遵循）：操作标签 ≤4 词、事件对象
// ≤5 词。词制计数：中文字符各算 1 词，连续英文/数字串（API、Caddy、
// IP2Region 等缩写）整体算 1 词，空白不计。硬卡控在
// audit_vocabulary_test.go（新增超标字面量测试直接红），此处入口仅告警
// 不阻断，保持 best-effort 写入语义。
const (
	auditActionMaxWords   = 4
	auditResourceMaxWords = 5
)

func auditVocabWords(s string) int {
	words := 0
	inASCII := false
	for _, r := range s {
		switch {
		case r == ' ' || r == '\t':
			inASCII = false
		case r < 128 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'):
			if !inASCII {
				words++
				inASCII = true
			}
		default:
			words++
			inASCII = false
		}
	}
	return words
}

func RecordAuditLog(username, action, resource, detail, ipAddress string) {
	if db.AuditDB == nil {
		log.Printf("audit log write skipped: audit database is not initialized")
		return
	}
	if aw, rw := auditVocabWords(action), auditVocabWords(resource); aw > auditActionMaxWords || rw > auditResourceMaxWords {
		log.Printf("audit vocabulary over limit (action<=%d, resource<=%d): action=%q(%d) resource=%q(%d)", auditActionMaxWords, auditResourceMaxWords, action, aw, resource, rw)
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
		Logf("warn", "audit log cleanup failed: %v", err)
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

// FormatAuditAction 中间件侧通用审计的动作映射。R66 D-N3：仅保留 5 条 Generic
// 路由（auditpolicy.go 分类）中由中间件记录的 3 条 caddy/start|stop|restart——
// 其余全部 Explicit 路由的 handler 自行显式记录且被 HasExplicitAuditEvent 前置
// 短路，本函数对它们的映射运行时不可达（死代码，含映射不存在路由 /nodes/register
// 的历史遗留）；死映射的最大风险是「Explicit 清单漂移漏掉某路由时中间件恢复
// 映射记录 → 与 handler 显式记录叠加成双条」（R65 D-N1 缺陷形态），故全部删除。
// 新增路由的审计分工：handler 显式记录 → 入 auditRoutePolicies 为 Explicit；
// 由中间件记录 → 入 Generic 并在本函数补映射 + TestAuditGenericRoutesExactlyOnce
// 登记表同步。契约绊线见 TestAuditExplicitRoutesMappingEmpty / TestAuditPolicyListsEqual。
func FormatAuditAction(method, path string) (action, resource, detail string) {
	p := path
	detail = p

	switch {
	// R65 D-N1/R68 D-N1：/api/v1/config 为 Explicit（handler 记录，HasExplicitAuditEvent
	// 前置短路）；/config/reload 为 Generic 且由 handler（ReloadCaddy）显式记录，
	// 中间件经本函数的空映射跳过（不记录）——两者均无需映射 case，走兜底空返回。
	// 注意勿为 reload 补映射：Generic + handler 记录 + 非空映射 = 单次动作双条
	//（R65 D-N1 缺陷形态，TestAuditGenericRoutesExactlyOnce 钉住）。

	case strings.Contains(p, "/caddy/start"):
		return "启动", "Caddy服务", p
	case strings.Contains(p, "/caddy/stop"):
		return "停止", "Caddy服务", p
	case strings.Contains(p, "/caddy/restart"):
		return "重启", "Caddy服务", p
	}

	return "", "", ""
}
