package services

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// CertificateIssuerDisplay 返回证书签发者的统一显示文案：「Org (CN)」，
// Organization/CommonName 单侧存在时退回该侧，均缺失返回空串（调用方决定
// 占位符，如证书卡用 "-"）。此前三处各自实现——任务列表只取 Organization、
// 规则证书卡取 "Org (CN)"、手动证书校验取 CN 优先——同一证书在 UI 不同位置
// 显示不同文案。
func CertificateIssuerDisplay(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	org := ""
	if len(cert.Issuer.Organization) > 0 {
		org = cert.Issuer.Organization[0]
	}
	cn := cert.Issuer.CommonName
	switch {
	case org != "" && cn != "":
		return fmt.Sprintf("%s (%s)", org, cn)
	case org != "":
		return org
	default:
		return cn
	}
}

func SelectRuleCertificate(candidates []CertificateCandidate, ruleDomains string, now time.Time) (string, bool) {
	selection, selected := selectCertificate(candidates, ruleDomains, now)
	if selected {
		return selection.Candidate.CertPEM, true
	}
	return "", false
}

// CertDaysRemaining 证书剩余天数单源（CERT 域冗余收敛：原
// certjobs/certinfo/certificates/admintls/helpers 五份同表达式——
// int(Ceil(-x)) 与真截断逐值恒等，表达式已统一，本函数固化单一出口）。
// 口径=向零截断（未过期 23h→0、过期 1 天 3 小时→-1）；
// 过期判定勿以返回值 ≤0 兼判（-1h 过期返回 0），另用 !now.Before(notAfter)。
func CertDaysRemaining(notAfter, now time.Time) int {
	return int(notAfter.Sub(now).Hours() / 24)
}

// CertificateExpiryStatus 证书到期状态单源：天粒度判定，
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
// 仅覆盖带外直写/读故障，两分支均 error 级显性留痕后按读故障族
// 口径取治理默认 db.DefaultCertExpiryDays（降级取值/日志文本
// 全部单源到常量，禁字面量回流——见 handlers/config_get_test.go 消费点族扫描）。
// 对任务/展示类消费方 fail-visible=日志留痕，不静默。
func GetCertExpiryThreshold() int {
	// 同包多数配置读取 helper 有 db.DB==nil 守卫——
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
	if days > 365 {
		Logf("error", "GetCertExpiryThreshold: cert_expiry_days 库值超上界（%d >365）——写侧/导入 1-365 之外，疑似带外直写/旧快照；本轮降级默认 %d 留痕", days, db.DefaultCertExpiryDays)
		return db.DefaultCertExpiryDays
	}
	return days
}

// CertRenewalLifetimeDays 是 ACME 证书的规划寿命（Let's Encrypt/ZeroSSL 均签发
// 90 天证书），用作续签窗口安全上限的基准。
const CertRenewalLifetimeDays = 90

// CertRenewalDaysMax 是安全续签窗口上限（整数天）：按 90 天规划寿命，窗口必须
// 比寿命至少小一整天，否则证书刚签发就落在窗口内，相邻两次自动续签的自然间隔
// L−W 退化到日级（约 5-7 天即触发 CA 重复证书限流、任务落 failed 后自动续签链
// 终止，再约一个寿命后证书到期、HTTPS 规则 fail-closed）。写侧校验
// （handlers.UpdateConfig）、导入钳制与读侧生效窗口共用本单源；存量越界值不
// 静默改写库（读侧按上限生效并显性告警）。CA 实际寿命不可预知，扫描侧另有
// certRenewalWindowForLifetime 按真实寿命收敛（见 certificates.go）。
const CertRenewalDaysMax = CertRenewalLifetimeDays - 2

// GetCertRenewalDays returns the configured certificate renewal window in days.
// cert_renewal_days 读取收敛到本 helper（原四处内联
// certificates.go 启动恢复/续签巡检/首发失败重试 + certissuer.go 快速路径）。
// 读取失败降级默认值必须告警——静默落 30 天默认会让
// 配置读取退化无任何可观测痕迹。库值 0/负值（带外直写/导入
// 遗留；API 与导入下界已钳到 1）同属「读侧带外防线」，降级 30 天时必须 error
// 级留痕库值，禁止静默改写。
func GetCertRenewalDays() int {
	// 未初始化库回退默认 30 天（同 GetCertExpiryThreshold）。
	// 读侧直读库值零兜底——启动回填保证 NULL/<=0 已收敛，
	// 此后的无效值只可能来自运行期带外直写，显性留痕降级。
	if db.DB == nil {
		return db.DefaultCertRenewalDays
	}
	var days int
	err := db.DB.QueryRow("SELECT cert_renewal_days FROM global_config WHERE id = 1").Scan(&days)
	if err != nil {
		Logf("error", "GetCertRenewalDays: failed to read global_config, using default %d: %v", db.DefaultCertRenewalDays, err)
		return db.DefaultCertRenewalDays
	}
	if days == 0 {
		// 0 的 UI/写侧语义=默认 30（不是异常）；与导入钳制同口径。
		return db.DefaultCertRenewalDays
	}
	if days < 0 {
		Logf("error", "GetCertRenewalDays: cert_renewal_days 库值无效（%d <0）——疑似带外直写/旧导入；本轮降级默认 %d 留痕", days, db.DefaultCertRenewalDays)
		return db.DefaultCertRenewalDays
	}
	// 读侧上界与写侧（handlers.UpdateConfig 0-CertRenewalDaysMax）/导入钳制
	// 对齐——带外直写 365 会让 90 天证书整年处于续签窗口，每 6h 触发一次签发
	// 风暴耗尽 CA 配额。与 <=0 同形态：error 级留痕后降级治理默认。
	if days > 90 {
		Logf("error", "GetCertRenewalDays: cert_renewal_days 库值超上界（%d >90）——写侧校验/导入钳制之外，疑似带外直写/旧备份恢复（续签风暴风险）；本轮降级默认 %d 留痕", days, db.DefaultCertRenewalDays)
		return db.DefaultCertRenewalDays
	}
	// 存量/旧备份遗留的 89/90 仍在旧契约内，但已超过安全上限（窗口接近寿命时
	// 相邻两次续签间隔退化到日级）。不得静默改写库值：库保持原样，本轮按安全
	// 上限生效并显性告警，让运维从续签节奏与日志两侧看到真实原因。
	if days > CertRenewalDaysMax {
		Logf("error", "GetCertRenewalDays: cert_renewal_days=%d 超过安全上限 %d（证书寿命按 %d 天规划，窗口接近寿命会让相邻两次续签间隔退化到日级/亚日级并触发 CA 重复证书限流）——疑似旧版本/备份导入遗留；库值保留、本轮按 %d 生效，请调小续签时间", days, CertRenewalDaysMax, CertRenewalLifetimeDays, CertRenewalDaysMax)
		return CertRenewalDaysMax
	}
	return days
}

// getCertRenewalAttempts returns the configured max renewal attempts.
// 与 GetCertRenewalDays 同口径——直读库值、无效值 error 级
// 留痕（此前 <=0 静默返回 5，排障无法区分「配置为 0」与「读失败」）。
func getCertRenewalAttempts() int {
	// 未初始化库回退默认 5 次（同 GetCertExpiryThreshold）。
	if db.DB == nil {
		return db.DefaultCertRenewalAttempts
	}
	var attempts int
	err := db.DB.QueryRow("SELECT cert_renewal_attempts FROM global_config WHERE id = 1").Scan(&attempts)
	if err != nil {
		Logf("error", "getCertRenewalAttempts: failed to read global_config, using default %d: %v", db.DefaultCertRenewalAttempts, err)
		return db.DefaultCertRenewalAttempts
	}
	if attempts <= 0 {
		Logf("error", "getCertRenewalAttempts: cert_renewal_attempts 库值无效（%d <=0）——启动回填只处理 <=0，写侧/导入 1-10 之外的最后防线，疑似带外直写/旧导入；本轮降级默认 %d 留痕", attempts, db.DefaultCertRenewalAttempts)
		return db.DefaultCertRenewalAttempts
	}
	// 读侧上界与写侧（1-10）/导入钳制（1-10）对齐——带外直写
	// 100 会让失败任务自动重试 100 次（CA 配额与 Caddy 重载压力）。
	if attempts > 10 {
		Logf("error", "getCertRenewalAttempts: cert_renewal_attempts 库值超上界（%d >10）——写侧/导入 1-10 之外，疑似带外直写/旧备份恢复；本轮降级默认 %d 留痕", attempts, db.DefaultCertRenewalAttempts)
		return db.DefaultCertRenewalAttempts
	}
	return attempts
}

// FormatRuleCertInfo 从 PEM 证书内容生成展示用 RuleCertInfo——批量
// (handlers.GetRulesCertInfo)与单规则(parseCertInfo)两路径同用
// 收敛：原 handlers.parseBatchRuleCertInfo 与本文件 parseCertInfo 两份实现历史
// 三度分叉）。参数显式化：expiryDays=expiring 阈值天数、now=判定基准（批量取
// 统一快照，避免逐规则 time.Now 漂移）；caddyID 非空时回填。source=acme_dns 且
// PEM 为空时给出 ACME 专属「尚未签发」文案（其余来源「证书不存在」）。
func FormatRuleCertInfo(certPEM, source, ruleDomains, caddyID string, expiryDays int, now time.Time) *models.RuleCertInfo {
	return formatRuleCertInfo(certPEM, nil, source, ruleDomains, caddyID, expiryDays, now)
}

// formatRuleCertInfo 与 FormatRuleCertInfo 同源：cert 非空时复用已解析证书
// （候选装载阶段预解析的 Leaf），不再 pem.Decode + x509.ParseCertificate
// （过期回退逐个候选择优后再解析一次的重复成本）。
func formatRuleCertInfo(certPEM string, cert *x509.Certificate, source, ruleDomains, caddyID string, expiryDays int, now time.Time) *models.RuleCertInfo {
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

	if cert == nil {
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			info.Error = "证书格式无效"
			return info
		}

		parsed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			info.Error = fmt.Sprintf("证书解析失败: %v", err)
			return info
		}
		cert = parsed
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

	// Issuer：单源显示口径（任务列表/规则证书卡/手动证书校验三处共用）
	info.Issuer = CertificateIssuerDisplay(cert)
	if info.Issuer == "" {
		info.Issuer = "-"
	}

	// 时间字段契约：UTC 墙钟（"2006-01-02 15:04:05"，无时区标识）。消费方
	// MUST 按 UTC 解释后转配置时区（web/src/utils/date.ts 的 formatDate）；
	// 原样展示会在非 UTC 时区差一个偏移。
	const timeFmt = "2006-01-02 15:04:05"
	info.NotBefore = cert.NotBefore.Format(timeFmt)
	info.NotAfter = cert.NotAfter.Format(timeFmt)
	info.DaysRemaining = CertDaysRemaining(cert.NotAfter, now)
	info.Status = CertificateExpiryStatus(cert.NotAfter, now, expiryDays)
	// 未来生效（NotBefore > now）：状态枚举保持 valid（前端无 not_yet_valid
	// 分支），用 Error 字段显性说明——此前手动证书卡片显示 valid + 很大的剩余
	// 天数，而客户端在 NotBefore 前会拒绝该证书（与 /certificates/parse 的
	// warning 口径相反）。ACME 路径由 ExpiredACMECertInfoFallback 单列处理。
	if now.Before(cert.NotBefore) {
		info.Error = fmt.Sprintf("证书尚未生效（生效时间 %s）", cert.NotBefore.In(CurrentLocation()).Format("2006-01-02 15:04:05"))
	}

	return info
}

// parseCertInfo parses a PEM certificate and returns structured display info.
// 阈值取配置值(cert_expiry_days)、基准取当前时刻——批量路径改用
// FormatRuleCertInfo 显式传参（同一实现）。
func parseCertInfo(certPEM, source, ruleDomains string) *models.RuleCertInfo {
	return FormatRuleCertInfo(certPEM, source, ruleDomains, "", GetCertExpiryThreshold(), time.Now())
}

// GetRuleCertInfo returns parsed certificate info for a single rule.
// 返回 error 仅表示读取失败（DB 故障必须 fail-visible，不得折叠成
// 「无证书信息」假成功）；「规则不存在」「规则禁用」与「未启用 TLS」仍以 (nil, nil) 表达
// ——handler 保持 200 + data:null 的既有契约。批量端点 GetRulesCertInfo 走
// 另一入口（整批失败已 500），不受本签名影响。
func GetRuleCertInfo(caddyID string) (*models.RuleCertInfo, error) {
	var enabled, enableTLS bool
	var tlsSource, ruleDomain, tlsCert string
	err := db.DB.QueryRow(`
		SELECT COALESCE(enabled, 0), COALESCE(enable_tls, 0), COALESCE(tls_source, 'manual'), COALESCE(domain, ''), COALESCE(tls_cert, '')
		FROM lb_rules WHERE caddy_id = ?`, caddyID).Scan(&enabled, &enableTLS, &tlsSource, &ruleDomain, &tlsCert)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		Logf("error", "GetRuleCertInfo: failed to read rule %s: %v", caddyID, err)
		return nil, fmt.Errorf("读取规则 %s 证书配置: %w", caddyID, err)
	}

	if !enabled || !enableTLS {
		return nil, nil
	}

	switch tlsSource {
	case "manual":
		info := parseCertInfo(tlsCert, "manual", ruleDomain)
		info.CaddyID = caddyID
		return info, nil
	case "acme_dns":
		return getACMECertInfo(caddyID, ruleDomain)
	default:
		// Fallback to manual cert if source is unrecognized but tls_cert exists
		info := parseCertInfo(tlsCert, tlsSource, ruleDomain)
		info.CaddyID = caddyID
		return info, nil
	}
}

// getACMECertInfo returns parsed certificate info for an ACME-issued rule.
// It reads the issued certificate from cert_jobs.cert_pem.
// 与规则行读取同契约——cert_jobs 的查询/Scan/迭代失败必须上抛
// （handler 500），不得折叠成 missingACMECertInfo「尚未签发或不存在」假成功：
// DB 故障与「确实还没有证书」对操作者必须可区分。仅「无候选行」返回 missing。
func getACMECertInfo(caddyID, ruleDomain string) (*models.RuleCertInfo, error) {
	// 阈值/基准取一次，供候选选择与过期回退共用——此前
	// ExpiredACMECertInfoFallback 对每个候选调用 parseCertInfo，每候选一次
	// global_config 读 + 重复 X509 解析。
	now := time.Now()
	expiryDays := GetCertExpiryThreshold()
	rows, err := db.DB.Query(`
		SELECT id, status, COALESCE(cert_pem, ''), COALESCE(key_pem, ''),
		       COALESCE(julianday(COALESCE(updated_at, created_at)), 0), COALESCE(domain, '')
		FROM cert_jobs
		WHERE rule_id = ? AND `+CertJobMaterialPredicateSQL("")+`
		ORDER BY updated_at DESC, id DESC`, caddyID)
	if err != nil {
		Logf("error", "GetRuleCertInfo: failed to read ACME certificates for %s: %v", caddyID, err)
		return nil, fmt.Errorf("读取规则 %s 的 ACME 证书: %w", caddyID, err)
	}
	defer rows.Close()
	candidates := make([]CertificateCandidate, 0)
	for rows.Next() {
		var candidate CertificateCandidate
		if err := rows.Scan(&candidate.ID, &candidate.Status, &candidate.CertPEM, &candidate.KeyPEM, &candidate.UpdatedAt, &candidate.Domain); err != nil {
			Logf("error", "GetRuleCertInfo: failed to scan ACME certificate for %s: %v", caddyID, err)
			return nil, fmt.Errorf("解析规则 %s 的 ACME 证书行: %w", caddyID, err)
		}
		// 候选查询已由 CertJobMaterialPredicateSQL 排除 disabled 行，
		// 此处无需再判状态——预解析一次供选择与过期回退共用。
		candidate.Leaf = ParseCertificateLeaf(candidate.CertPEM, candidate.KeyPEM)
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		Logf("error", "GetRuleCertInfo: failed to iterate ACME certificates for %s: %v", caddyID, err)
		return nil, fmt.Errorf("遍历规则 %s 的 ACME 证书: %w", caddyID, err)
	}
	if certPEM, selected := SelectRuleCertificate(candidates, ruleDomain, now); selected {
		info := FormatRuleCertInfo(certPEM, "acme_dns", ruleDomain, caddyID, expiryDays, now)
		return info, nil
	}
	// 选中失败区分「已过期」与「尚未签发」。
	if info := ExpiredACMECertInfoFallback(candidates, caddyID, ruleDomain, expiryDays, now); info != nil {
		return info, nil
	}
	return missingACMECertInfo(caddyID, ruleDomain), nil
}

// ExpiredACMECertInfoFallback:候选集 PEM 非空但
// SelectRuleCertificate 无一可选中时,逐个解析——首个非 disabled 且 PEM 非空
// 的已过期候选按 expired 呈现(Error=「ACME 证书已过期」)、尚未生效
// （NotBefore 在未来，certissuer 的未来时钟证书已写盘+已 reload 形态）候选按
// unknown + 「证书尚未生效」呈现,两者都不再误报「尚未签发或不存在」;
// 无已过期/未生效候选(解析失败)返回 nil,调用方维持原口径。
// 单规则(GetRuleCertInfo)与批量(handlers GetRulesCertInfo)两路径同用。
// expiryDays/now 由调用方一次性提供（批量端点已有阈值与 now），
// 避免每个候选一次 global_config 查询；解析结果直接复用 FormatRuleCertInfo。
func ExpiredACMECertInfoFallback(candidates []CertificateCandidate, caddyID, ruleDomain string, expiryDays int, now time.Time) *models.RuleCertInfo {
	for _, candidate := range candidates {
		if strings.TrimSpace(candidate.CertPEM) == "" || candidate.Status == "disabled" {
			continue
		}
		// 域名适用性：先按「任务行域名 == 规则域名」判定（对账/物化同源）；
		// 不匹配时再按证书 SAN 覆盖判定（与选择路径 VerifyHostname 同口径）——
		// 规则域名曾由「根域+www」收窄/放宽后，旧任务行的 domain 是当时集合的
		// 快照，精确比较会把仍覆盖当前域名的证书卡从「已过期」误报成「尚未签发」。
		leaf := candidate.Leaf
		if leaf == nil {
			leaf = parseCertificateLeafFromPEM(candidate.CertPEM)
		}
		if !certJobRuleApplicable(true, ruleDomain, candidate.Domain) && !leafCoversRuleDomains(leaf, ruleDomain) {
			continue
		}
		info := formatRuleCertInfo(candidate.CertPEM, candidate.Leaf, "acme_dns", ruleDomain, caddyID, expiryDays, now)
		if info.Status == "expired" {
			info.Error = "ACME 证书已过期"
			return info
		}
		// 已签发但未生效：selectCertificate 因 now<NotBefore 跳过该候选，
		// 回退若仍报「尚未签发或不存在」会诱导运维重复触发签发（白烧 CA
		// 配额），且与磁盘/Caddy 实际部署状态矛盾。
		if leaf != nil && now.Before(leaf.NotBefore) {
			info.Status = "unknown"
			info.Error = fmt.Sprintf("ACME 证书尚未生效（NotBefore %s）", leaf.NotBefore.Format("2006-01-02 15:04:05"))
			return info
		}
	}
	return nil
}

// parseCertificateLeafFromPEM 只解析证书首块（不要求私钥配对）——历史行的
// 私钥可能已损坏/缺失，但「证书覆盖哪些域名」只依赖证书本体。
func parseCertificateLeafFromPEM(certPEM string) *x509.Certificate {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return leaf
}

// leafCoversRuleDomains 与 selectCertificate 的覆盖判定同源（逐域名
// VerifyHostname）；它只看 SAN/CN 是否覆盖，不看到期时间。
func leafCoversRuleDomains(leaf *x509.Certificate, ruleDomain string) bool {
	if leaf == nil {
		return false
	}
	canonical, err := CanonicalACMEDomains(ruleDomain)
	if err != nil {
		return false
	}
	for _, domain := range strings.Split(canonical, ",") {
		if leaf.VerifyHostname(domain) != nil {
			return false
		}
	}
	return true
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
