package services

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func SelectRuleCertificate(candidates []CertificateCandidate, ruleDomains string, now time.Time) (string, bool) {
	selection, selected := SelectCertificate(candidates, ruleDomains, now)
	if selected {
		return selection.Candidate.CertPEM, true
	}
	return "", false
}

// CertDaysRemaining 证书剩余天数单源（第 76 轮 CERT 域冗余收敛：原
// certjobs/certinfo/certificates/admintls/helpers 五份同表达式——R66 的
// -int(Ceil(-x)) 与 R67 真截断逐值恒等，表达式已统一，本函数固化单一出口）。
// 口径=向零截断（CERT42-3/R67 D-2：未过期 23h→0、过期 1 天 3 小时→-1）；
// 过期判定勿以返回值 ≤0 兼判（-1h 过期返回 0），另用 !now.Before(notAfter)。
func CertDaysRemaining(notAfter, now time.Time) int {
	return int(notAfter.Sub(now).Hours() / 24)
}

// CertificateExpiryStatus 证书到期状态单源（U06-F03，第 78 轮）：天粒度判定，
// 过期优先于临期（-1h 过期时 CertDaysRemaining=0，不得回落 expiring）。
// 消费点：certinfo 列表（FormatRuleCertInfo）、任务列表（handlers.ListCertJobs）、
// 手动巡检（checkManualCertExpiration）——三处必须同结论，禁止各自比较完整时长
// 或另写 switch（原 certjobs 用 `<= days*24h` 纳秒口径，与截断天数在阈值边界分叉）。
func CertificateExpiryStatus(notAfter, now time.Time, thresholdDays int) string {
	if !now.Before(notAfter) {
		return "expired"
	}
	if CertDaysRemaining(notAfter, now) <= thresholdDays {
		return "expiring"
	}
	return "valid"
}

// GetCertExpiryThreshold returns the configured cert expiry warning threshold in days.
// 库值唯一真相（批 3）：cert_expiry_days 类型①值型列直读（COALESCE 兜底
// 删除）——NULL/<=0 由启动回填（db.go defaultUpdates）收敛；此处的降级分支
// 仅覆盖带外直写/读故障，两分支均 error 级显性留痕后按 CERT42-5 读故障族
// 口径取治理默认 db.DefaultCertExpiryDays（R2，第 77 轮：降级取值/日志文本
// 全部单源到常量，禁字面量回流——见 handlers/config_get_test.go 消费点族扫描）。
// 对任务/展示类消费方 fail-visible=日志留痕，不静默。
func GetCertExpiryThreshold() int {
	// SVC-F2（第 73 轮）：同包多数配置读取 helper 有 db.DB==nil 守卫——
	// 未初始化库回退默认值，不得 nil deref（当前不可达，防御性一致）。
	if db.DB == nil {
		return db.DefaultCertExpiryDays
	}
	var days int
	err := db.DB.QueryRow("SELECT cert_expiry_days FROM global_config WHERE id = 1").Scan(&days)
	if err != nil {
		Logf("error", "GetCertExpiryThreshold: failed to read global_config, using default %d: %v", db.DefaultCertExpiryDays, err)
		return db.DefaultCertExpiryDays
	}
	if days <= 0 {
		Logf("error", "GetCertExpiryThreshold: cert_expiry_days 库值无效（%d <=0）——类型①值型列应恒为正（写侧 1-365 校验+启动回填报证），疑似带外直写；本轮降级默认 %d 留痕", days, db.DefaultCertExpiryDays)
		return db.DefaultCertExpiryDays
	}
	return days
}

// GetCertRenewalDays returns the configured certificate renewal window in days.
// U7-P5-2（第 62 轮审计）：cert_renewal_days 读取收敛到本 helper（原四处内联：
// certificates.go 启动恢复/续签巡检/首发失败重试 + certissuer.go 快速路径）。
// CERT42-5（第 42 轮审计）：读取失败降级默认值必须告警——静默落 30 天默认会让
// 配置读取退化无任何可观测痕迹。L04-02（第 78 轮）：库值 0/负值（带外直写/导入
// 遗留；API 与导入下界已钳到 1）同属「读侧带外防线」，降级 30 天时必须 error
// 级留痕库值，禁止静默改写。
func GetCertRenewalDays() int {
	// SVC-F2（第 73 轮）：未初始化库回退默认 30 天（同 GetCertExpiryThreshold）。
	if db.DB == nil {
		return 30
	}
	var days int
	err := db.DB.QueryRow("SELECT COALESCE(cert_renewal_days, 30) FROM global_config WHERE id = 1").Scan(&days)
	if err != nil {
		Logf("error", "GetCertRenewalDays: failed to read global_config, using default 30: %v", err)
		return 30
	}
	if days <= 0 {
		Logf("error", "GetCertRenewalDays: cert_renewal_days 库值无效（%d <=0）——写侧下界 1 已钳制，疑似带外直写/旧导入；本轮降级默认 30 留痕", days)
		return 30
	}
	return days
}

// GetCertRenewalAttempts returns the configured max renewal attempts.
func GetCertRenewalAttempts() int {
	// SVC-F2（第 73 轮）：未初始化库回退默认 5 次（同 GetCertExpiryThreshold）。
	if db.DB == nil {
		return 5
	}
	var attempts int
	err := db.DB.QueryRow("SELECT COALESCE(cert_renewal_attempts, 5) FROM global_config WHERE id = 1").Scan(&attempts)
	if err != nil {
		Logf("error", "GetCertRenewalAttempts: failed to read global_config, using default 5: %v", err)
		return 5
	}
	if attempts <= 0 {
		return 5
	}
	return attempts
}

// FormatRuleCertInfo 从 PEM 证书内容生成展示用 RuleCertInfo——批量
// (handlers.GetRulesCertInfo)与单规则(ParseCertInfo)两路径同用（R73 LBH-F7
// 收敛：原 handlers.parseBatchRuleCertInfo 与本文件 ParseCertInfo 两份实现历史
// 三度分叉）。参数显式化：expiryDays=expiring 阈值天数、now=判定基准（批量取
// 统一快照，避免逐规则 time.Now 漂移）；caddyID 非空时回填。source=acme_dns 且
// PEM 为空时给出 ACME 专属「尚未签发」文案（其余来源「证书不存在」）。
func FormatRuleCertInfo(certPEM, source, ruleDomains, caddyID string, expiryDays int, now time.Time) *models.RuleCertInfo {
	info := &models.RuleCertInfo{
		CaddyID: caddyID,
		Source:  source,
		Domains: ruleDomains,
		Status:  "unknown",
	}

	if strings.TrimSpace(certPEM) == "" {
		if source == "acme_dns" {
			info.Error = "ACME 证书尚未签发或不存在"
		} else {
			info.Error = "证书不存在"
		}
		return info
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		info.Error = "证书格式无效"
		return info
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		info.Error = fmt.Sprintf("证书解析失败: %v", err)
		return info
	}

	// Domains：证书 DNSNames 优先，CommonName 兜底，去重后均无则保留 ruleDomains
	domainSet := make(map[string]struct{}, len(cert.DNSNames)+1)
	parsedDomains := make([]string, 0, len(cert.DNSNames)+1)
	for _, name := range append(cert.DNSNames, cert.Subject.CommonName) {
		if name == "" {
			continue
		}
		if _, exists := domainSet[name]; exists {
			continue
		}
		domainSet[name] = struct{}{}
		parsedDomains = append(parsedDomains, name)
	}
	if len(parsedDomains) > 0 {
		info.Domains = strings.Join(parsedDomains, ", ")
	}

	// Issuer：Organization 优先，CommonName 兜底
	issuer := cert.Issuer.CommonName
	if len(cert.Issuer.Organization) > 0 && cert.Issuer.Organization[0] != "" {
		issuer = cert.Issuer.Organization[0]
		if cert.Issuer.CommonName != "" {
			issuer = fmt.Sprintf("%s (%s)", issuer, cert.Issuer.CommonName)
		}
	}
	info.Issuer = issuer
	if info.Issuer == "" {
		info.Issuer = "-"
	}

	const timeFmt = "2006-01-02 15:04:05"
	info.NotBefore = cert.NotBefore.Format(timeFmt)
	info.NotAfter = cert.NotAfter.Format(timeFmt)
	info.DaysRemaining = CertDaysRemaining(cert.NotAfter, now)
	info.Status = CertificateExpiryStatus(cert.NotAfter, now, expiryDays)

	return info
}

// ParseCertInfo parses a PEM certificate and returns structured display info.
// 阈值取配置值(cert_expiry_days)、基准取当前时刻——批量路径改用
// FormatRuleCertInfo 显式传参（同一实现）。
func ParseCertInfo(certPEM, source, ruleDomains string) *models.RuleCertInfo {
	return FormatRuleCertInfo(certPEM, source, ruleDomains, "", GetCertExpiryThreshold(), time.Now())
}

// GetRuleCertInfo returns parsed certificate info for a single rule.
func GetRuleCertInfo(caddyID string) *models.RuleCertInfo {
	var enableTLS bool
	var tlsSource, ruleDomain, tlsCert string
	err := db.DB.QueryRow(`
		SELECT COALESCE(enable_tls, 0), COALESCE(tls_source, 'manual'), COALESCE(domain, ''), COALESCE(tls_cert, '')
		FROM lb_rules WHERE caddy_id = ?`, caddyID).Scan(&enableTLS, &tlsSource, &ruleDomain, &tlsCert)
	if err != nil {
		Logf("error", "GetRuleCertInfo: failed to read rule %s: %v", caddyID, err)
		return nil
	}

	if !enableTLS {
		return nil
	}

	switch tlsSource {
	case "manual":
		info := ParseCertInfo(tlsCert, "manual", ruleDomain)
		info.CaddyID = caddyID
		return info
	case "acme_dns":
		return getACMECertInfo(caddyID, ruleDomain)
	default:
		// Fallback to manual cert if source is unrecognized but tls_cert exists
		info := ParseCertInfo(tlsCert, tlsSource, ruleDomain)
		info.CaddyID = caddyID
		return info
	}
}

// getACMECertInfo returns parsed certificate info for an ACME-issued rule.
// It reads the issued certificate from cert_jobs.cert_pem.
func getACMECertInfo(caddyID, ruleDomain string) *models.RuleCertInfo {
	rows, err := db.DB.Query(`
		SELECT id, status, COALESCE(cert_pem, ''), COALESCE(key_pem, ''),
		       COALESCE(julianday(COALESCE(updated_at, created_at)), 0), COALESCE(domain, '')
		FROM cert_jobs
		WHERE rule_id = ? AND COALESCE(cert_pem, '') != '' AND COALESCE(key_pem, '') != ''
		ORDER BY updated_at DESC, id DESC`, caddyID)
	if err != nil {
		Logf("error", "GetRuleCertInfo: failed to read ACME certificates for %s: %v", caddyID, err)
		return missingACMECertInfo(caddyID, ruleDomain)
	}
	defer rows.Close()
	candidates := make([]CertificateCandidate, 0)
	for rows.Next() {
		var candidate CertificateCandidate
		if err := rows.Scan(&candidate.ID, &candidate.Status, &candidate.CertPEM, &candidate.KeyPEM, &candidate.UpdatedAt, &candidate.Domain); err != nil {
			Logf("error", "GetRuleCertInfo: failed to scan ACME certificate for %s: %v", caddyID, err)
			return missingACMECertInfo(caddyID, ruleDomain)
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		Logf("error", "GetRuleCertInfo: failed to iterate ACME certificates for %s: %v", caddyID, err)
		return missingACMECertInfo(caddyID, ruleDomain)
	}
	if certPEM, selected := SelectRuleCertificate(candidates, ruleDomain, time.Now()); selected {
		info := ParseCertInfo(certPEM, "acme_dns", ruleDomain)
		info.CaddyID = caddyID
		return info
	}
	// CERT40-1:选中失败区分「已过期」与「尚未签发」。
	if info := ExpiredACMECertInfoFallback(candidates, caddyID, ruleDomain); info != nil {
		return info
	}
	return missingACMECertInfo(caddyID, ruleDomain)
}

// ExpiredACMECertInfoFallback(CERT40-1/CERT42-1 共享):候选集 PEM 非空但
// SelectRuleCertificate 无一可选中时,逐个解析——首个非 disabled 且 PEM 非空
// 的已过期候选按 expired 呈现(Error=「ACME 证书已过期」),不再误报「尚未
// 签发或不存在」;无已过期候选(解析失败/未过期)返回 nil,调用方维持原口径。
// 单规则(GetRuleCertInfo)与批量(handlers GetRulesCertInfo)两路径同用。
func ExpiredACMECertInfoFallback(candidates []CertificateCandidate, caddyID, ruleDomain string) *models.RuleCertInfo {
	for _, candidate := range candidates {
		if strings.TrimSpace(candidate.CertPEM) == "" || candidate.Status == "disabled" {
			continue
		}
		info := ParseCertInfo(candidate.CertPEM, "acme_dns", ruleDomain)
		info.CaddyID = caddyID
		if info.Status == "expired" {
			info.Error = "ACME 证书已过期"
			return info
		}
	}
	return nil
}

func missingACMECertInfo(caddyID, ruleDomain string) *models.RuleCertInfo {
	return &models.RuleCertInfo{
		CaddyID: caddyID,
		Source:  "acme_dns",
		Domains: ruleDomain,
		Status:  "unknown",
		Error:   "ACME 证书尚未签发或不存在",
	}
}
