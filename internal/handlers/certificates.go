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

// maskedDNSCredentialsSentinel：非 admin 响应中 DNS 凭证值的
// 掩码占位。更新路径识别到全掩码形态按「未提交」处理（保持原值）——前端
// FreeCertificates 的编辑表单会原样回传 GET 到的值。
const maskedDNSCredentialsSentinel = "***"

// certificateConfigNameMaxRunes 与 CA 提供商名称校验同口径（services
// ErrCAProviderNameTooLong=100 rune）。binding:"required" 不拦纯空白，SQLite
// 也不强制 VARCHAR(100)——校验必须在这里做。
const certificateConfigNameMaxRunes = 100

// maxParseCertificateBytes 是证书解析端点（POST /certificates/parse）的请求体
// 上限：入参是 PEM 文本（证书链+私钥），与普通 JSON 配置写端点的「请求体大小」
// 配置项无关——2MB 足以容纳最长链，且对齐 admin-tls inspect 的量级。
const maxParseCertificateBytes = 2 << 20

// maxBatchIssueTargets 是批量签发（{"all":true}）单次目标数上限：该分支在
// 全局 caddyOpMu 内逐目标做查询+upsert/入队（原子性所需），规则数百条时
// 规则写、配置写与 Caddy 启停全部排队且 failed 切片无界。超上限显式 400
// 提示分批执行，而不是静默截断或让全局锁无限期占用。
const maxBatchIssueTargets = 500

// normalizeCertificateConfigName 统一 trim + 非空 + 长度校验，写入 trimmed 值。
func normalizeCertificateConfigName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", errors.New("DNS 配置名称不能为空")
	}
	if len([]rune(name)) > certificateConfigNameMaxRunes {
		return "", fmt.Errorf("DNS 配置名称不能超过 %d 个字符", certificateConfigNameMaxRunes)
	}
	return name, nil
}

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

// isMaskedDNSCredentials 判断提交的凭证是否为「GET 掩码原样回传」（未改动）。
// 只有**全部值均为掩码哨兵**（且至少一个键）才算未改动。
// 旧口径把空串视为「可以共存」，`{"app_id":"","app_token":"***"}` 被整体吞成未修改
// ——用户显式清空 app_id 的意图静默丢失。含空串/真实值的回传一律走
// mergeMaskedDNSCredentials（空串保留为空 = 显式清空，哨兵逐字段取库值）。
func isMaskedDNSCredentials(m map[string]string) bool {
	if len(m) == 0 {
		return false
	}
	for _, v := range m {
		if v != maskedDNSCredentialsSentinel {
			return false
		}
	}
	return true
}

// mergeMaskedDNSCredentials:部分掩码回传逐字段合并——值为掩码
// 占位的字段取库中原值,非占位取提交值;库中亦无该字段时占位无处可取,
// 返回错误(防掩码串覆盖真实凭证)。
//
// preserveUnsubmitted 控制「提交中缺失的键」语义（与 provider 是否变更绑定）：
//   - true（同一 provider）：缺失键继承库值——稀疏 PATCH 不得静默抹掉未提交的
//     凭证字段。整体缺省 dns_credentials（nil）早已是「保持」语义，字段缺省却
//     「删除」会让同一端点两种缺省含义相反。
//   - false（provider 变更）：不继承旧 provider 的字段——旧键（如 auth_mode）
//     混入新 provider 载荷会被凭据归一误判为旧模式，导致保存失败或语义漂移。
func mergeMaskedDNSCredentials(submitted, stored map[string]string, preserveUnsubmitted bool) (map[string]string, error) {
	merged := make(map[string]string, len(submitted)+len(stored))
	if preserveUnsubmitted {
		for k, v := range stored {
			merged[k] = v
		}
	}
	for k, v := range submitted {
		if v == maskedDNSCredentialsSentinel {
			storedVal, ok := stored[k]
			if !ok || storedVal == "" {
				return nil, fmt.Errorf("凭证字段不能为掩码占位符")
			}
			merged[k] = storedVal
		} else {
			merged[k] = v
		}
	}
	return merged, nil
}

// hasMaskedDNSCredentialValue 报告提交值中是否含掩码占位（区别于
// isMaskedDNSCredentials 的「全部为占位」）。库内凭证损坏时，只有「一个占位都
// 没有」的完整新凭据才能整列覆写；含占位必须回库值取值，500 才是诚实的。
func hasMaskedDNSCredentialValue(m map[string]string) bool {
	for _, v := range m {
		if v == maskedDNSCredentialsSentinel {
			return true
		}
	}
	return false
}

// dnsCredentialFamilyMode 归一凭证 map 的认证族：auth_mode（UI 形态）优先，
// 兼容 canonical 形态的 mode；tencent_cloud 与 tencent 同族。无法判定返回空串。
func dnsCredentialFamilyMode(m map[string]string) string {
	mode := strings.ToLower(strings.TrimSpace(m["auth_mode"]))
	if mode == "" {
		mode = strings.ToLower(strings.TrimSpace(m["mode"]))
	}
	switch mode {
	case "dnspod":
		return "dnspod"
	case "tencent", "tencent_cloud":
		return "tencent"
	}
	return ""
}

// pruneSupersededDNSCredentialFamily 在维护请求把认证族从 stored 切到 creds 时
// 删除旧族字段，返回被删除的键名（未切换返回 nil）。
//
// 合并语义（mergeMaskedDNSCredentials 的 preserveUnsubmitted）目标是「稀疏
// PATCH 不抹掉未提交字段」，但认证族切换不是稀疏 PATCH：旧族密钥已无消费方
// （Canonical 按 auth_mode 只取新族），遗留只会随集群快照/备份扩散，并在切回
// 旧族时被再次启用。前端切换 auth_mode 已按 visible_when 删掉隐藏字段，后端
// 若再从库值继承回来，等于把用户刚清掉的密钥写回去。
func pruneSupersededDNSCredentialFamily(creds, stored map[string]string) []string {
	storedMode, submittedMode := dnsCredentialFamilyMode(stored), dnsCredentialFamilyMode(creds)
	if storedMode == "" || submittedMode == "" || storedMode == submittedMode {
		return nil
	}
	var stale []string
	switch submittedMode {
	case "dnspod":
		stale = []string{"secret_id", "secret_key"}
	case "tencent":
		stale = []string{"app_id", "app_token", "api_token"}
	}
	// 冗余的 legacy mode 与认证族同义：提交带 auth_mode 时由后者表达，删除
	// 避免「auth_mode=新族、mode=旧族」的并存形态误导后续推断。
	if strings.TrimSpace(creds["auth_mode"]) != "" {
		stale = append(stale, "mode")
	}
	removed := make([]string, 0, len(stale))
	for _, key := range stale {
		if _, ok := creds[key]; !ok {
			continue
		}
		delete(creds, key)
		removed = append(removed, key)
	}
	return removed
}

// respondStoredDNSCredentialsCorrupted 处理「库内 dns_credentials 不是合法
// JSON」的存储损坏形态（带外改库/旧版本遗留；导入通道已校验 JSON 对象，正常
// 写入不会产生）：与保存前测试端点（TestCertificateConfig）的
// storage_corrupted 口径同源——500 + 固定中文文案，解析错误只进运行日志。
// 不得折成 400（「Invalid stored DNS credentials」/「凭证字段不能为掩码占位符」
// 等请求类文案），否则运维会把存储损坏误判成自己的表单填写问题并反复重填。
// 文案必须指向唯一可执行动作：提交完整新凭据即整列覆写（损坏行由此自愈），
// 原「请重新保存配置」在省略/掩码载荷上仍会 500，用户照做只会反复失败。
func respondStoredDNSCredentialsCorrupted(c *gin.Context, configID int, cause error) {
	recordAudit(c, "更新失败", "DNS配置", services.FormatAuditDetail(fmt.Sprintf("配置 %d", configID), services.AuditResultPart("storage_corrupted")))
	writeInternalError(c, http.StatusInternalServerError, "存储的 DNS 凭证已损坏，请重新填写完整凭证后保存", cause)
}

func (h *Handlers) ListCertificateConfigs(c *gin.Context) {
	rows, err := db.DB.Query("SELECT id, name, dns_provider, COALESCE(dns_credentials,''), COALESCE(enabled,1), created_at, updated_at FROM certificate_configs ORDER BY id")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to query configs"})
		return
	}
	defer rows.Close()

	isAdmin := false
	if role, ok := c.Get("role"); ok && role == "admin" {
		isAdmin = true
	}
	// 凭证最小可见性——非 admin 只见掩码形态。
	// admin 属主的只读 API Key 同样只见掩码——apiKeyAuth 注入的
	// api_key_read_only 标志(机器身份,密钥泄露面大于会话)独立于属主角色
	// 生效;admin JWT 会话路径不受影响。
	maskCredentials := !isAdmin || c.GetBool("api_key_read_only")
	var configs []models.CertificateConfig
	for rows.Next() {
		var cfg models.CertificateConfig
		if err := rows.Scan(&cfg.ID, &cfg.Name, &cfg.DNSProvider, &cfg.DNSCredentials, &cfg.Enabled, &cfg.CreatedAt, &cfg.UpdatedAt); err != nil {
			writeInternalError(c, http.StatusInternalServerError, "读取证书配置失败", err)
			return
		}
		if maskCredentials {
			cfg.DNSCredentials = maskDNSCredentialsJSON(cfg.DNSCredentials)
		}
		configs = append(configs, cfg)
	}
	if err := rows.Err(); err != nil {
		writeInternalError(c, http.StatusInternalServerError, "读取证书配置失败", err)
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: configs})
}

func (h *Handlers) CreateCertificateConfig(c *gin.Context) {
	// 导入窗口内写入会被全量替换静默覆盖。
	if rejectWriteDuringImport(c, "保存证书配置（配置导入进行中）") {
		return
	}

	var req models.CreateCertificateConfigRequest
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	// 名称与 CA 提供商同族校验：trim 后非空且 ≤100 rune，写 trimmed 值入库。
	name, nameErr := normalizeCertificateConfigName(req.Name)
	if nameErr != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: nameErr.Error()})
		return
	}

	// 删除「空则默认 dnspod」死代码——binding:"required"
	// 保证 dns_provider 非空，兜底不可达；缺字段请求由 400 契约拒绝。
	provider, ok := dnsproviders.Get(req.DNSProvider)
	if !ok {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Unknown DNS provider"})
		return
	}

	// Create 无库值可取,含掩码占位直接拒绝。
	for _, v := range req.DNSCredentials {
		if v == maskedDNSCredentialsSentinel {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "凭证字段不能为掩码占位符"})
			return
		}
	}

	if _, err := provider.BuildCredentialsJSON(req.DNSCredentials); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	credsJSON, _ := json.Marshal(req.DNSCredentials)
	result, err := db.DB.Exec(`
		INSERT INTO certificate_configs (name, dns_provider, dns_credentials, enabled)
		VALUES (?, ?, ?, ?)
	`, name, req.DNSProvider, string(credsJSON), req.Enabled)

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to create config"})
		return
	}

	// LastInsertId 失败时审计会落「配置 0」——失败留痕后按 0 继续（行已落库，
	// 不能因审计 id 丢失而回滚）。
	id, idErr := result.LastInsertId()
	if idErr != nil {
		services.Logf("error", "CreateCertificateConfig: 读取新配置 ID 失败（审计将记为 0）: %v", idErr)
	}
	recordAudit(c, "创建", "DNS配置", services.FormatAuditDetail(fmt.Sprintf("配置 %d", id), name, req.DNSProvider, fmt.Sprintf("启用：%t", req.Enabled)))
	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Message: "Config created", Data: gin.H{"id": id}})
}

const certificateConfigMaxListedReferences = 5

type certificateConfigRuleRef struct {
	caddyID string
	domain  string
}

func formatCertificateConfigReferences(references []certificateConfigRuleRef, referenceKind, verb string) string {
	listed := make([]string, 0, min(len(references), certificateConfigMaxListedReferences))
	for _, ref := range references {
		if len(listed) == certificateConfigMaxListedReferences {
			break
		}
		if ref.domain != "" {
			listed = append(listed, fmt.Sprintf("%s (%s)", ref.domain, ref.caddyID))
		} else {
			listed = append(listed, ref.caddyID)
		}
	}
	message := fmt.Sprintf("该 DNS 配置正被 %d 条%s引用，%s后这些规则将无法自动签发/续签证书，请先修改规则的 DNS 配置后再%s：%s",
		len(references), referenceKind, verb, verb, strings.Join(listed, "、"))
	if len(references) > certificateConfigMaxListedReferences {
		message += fmt.Sprintf(" 等 %d 条规则", len(references))
	}
	return message
}

func (h *Handlers) UpdateCertificateConfig(c *gin.Context) {
	// 导入窗口内写入会被全量替换静默覆盖（本表在导入全量替代表清单内）。
	// 门必须早于 caddyOpMu：导入事务全程持有该锁，排队等待后再按陈旧 id 落库
	// 等价于「导入完成后被旧请求改写导入结果」。
	if rejectWriteDuringImport(c, "保存证书配置（配置导入进行中）") {
		return
	}

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid id parameter"})
		return
	}

	var req models.UpdateCertificateConfigRequest
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	// 与规则写/删除配置共用临界区：引用检查与 enabled 写入必须相对规则绑定原子。
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	// 旧行读取与动态 UPDATE 收敛到同一事务
	//（_txlock=immediate → BEGIN IMMEDIATE 先取写锁）——审计 changed 清单的
	//比对基线即写入前那一刻的真实行，消除「事务外预读 → 写入」窗口内并发
	//提交导致的清单失真（镜像 事务内旧行模式）。
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to update config"})
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	var oldName, oldProvider, oldCredentials string
	var oldEnabled bool
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT name, dns_provider, COALESCE(dns_credentials,''), COALESCE(enabled,1) FROM certificate_configs WHERE id=?", id).Scan(&oldName, &oldProvider, &oldCredentials, &oldEnabled); dbQueryNotFound(c, err, "Config not found", "UpdateCertificateConfig query config") {
		return
	}
	effectiveProvider := oldProvider
	if req.DNSProvider != "" {
		effectiveProvider = req.DNSProvider
	}
	effectiveCredentials := req.DNSCredentials
	// 认证族切换时被清除的旧族字段（见 pruneSupersededDNSCredentialFamily），
	// 供审计 detail 披露「这次保存删掉了哪些存量凭据」。
	var prunedStaleCredentialFields []string
	switch {
	case effectiveCredentials == nil || len(effectiveCredentials) == 0:
		// 省略或空对象（表单未编辑任何凭证字段）等价于「未提交」：以库值参与
		// 校验，且不回写凭证列——空对象不得按「清空全部凭证」落库。
		req.DNSCredentials = nil
		effectiveCredentials = map[string]string{}
		if oldCredentials != "" {
			if err := json.Unmarshal([]byte(oldCredentials), &effectiveCredentials); err != nil {
				respondStoredDNSCredentialsCorrupted(c, id, err)
				return
			}
		}
	case isMaskedDNSCredentials(effectiveCredentials):
		// 全掩码回传(GET 掩码→未改动即保存)按未提交处理——校验
		// 路径以库中旧值为准(掩码串进 BuildCredentialsJSON 会 400「请选择
		// 认证方式」);落库侧下方 isMasked 分支保留作防御(req.DNSCredentials
		// 置 nil 不更新凭证列)。
		effectiveCredentials = map[string]string{}
		if oldCredentials != "" {
			if err := json.Unmarshal([]byte(oldCredentials), &effectiveCredentials); err != nil {
				respondStoredDNSCredentialsCorrupted(c, id, err)
				return
			}
		}
	default:
		// 部分掩码回传先逐字段合并——下方早期校验与最终落库都以
		// 合并结果为准(掩码字段取库值),掩码串不得进入校验/落库。
		stored := map[string]string{}
		var storedCorruptErr error
		if oldCredentials != "" {
			if uerr := json.Unmarshal([]byte(oldCredentials), &stored); uerr != nil {
				storedCorruptErr = uerr
			}
		}
		if storedCorruptErr != nil {
			// 完整新凭据（无掩码占位）是整列覆写，合并语义用不上库值——存储
			// 损坏不构成阻断，否则损坏行永久不可编辑（名称/启用态/凭据都改
			// 不了）。含掩码的载荷仍需库值逐字段取值，只能维持 500。
			if hasMaskedDNSCredentialValue(effectiveCredentials) {
				respondStoredDNSCredentialsCorrupted(c, id, storedCorruptErr)
				return
			}
			stored = map[string]string{}
		}
		merged, merr := mergeMaskedDNSCredentials(effectiveCredentials, stored, effectiveProvider == oldProvider)
		if merr != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: merr.Error()})
			return
		}
		prunedStaleCredentialFields = pruneSupersededDNSCredentialFamily(merged, stored)
		req.DNSCredentials = merged
		effectiveCredentials = merged
	}
	// 表单形态的空对象（用户未编辑任何凭证字段）与省略等价：归一为「未提交」，
	// 否则遗留空凭据配置的改名/禁用会被旧空值阻断（前端表单恒提交凭证对象）。
	// 只含认证方式而无凭证值的载荷长度非零，仍必须过下方 provider 校验。
	if req.DNSCredentials != nil && len(effectiveCredentials) == 0 {
		req.DNSCredentials = nil
	}
	provider, ok := dnsproviders.Get(effectiveProvider)
	if !ok {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Unknown DNS provider"})
		return
	}
	// 遗留 NULL/空串表示「尚未配置凭据」，不是损坏 JSON：改名、禁用及保持
	// 原启用态时不借旧空值阻断；但从禁用转为启用、变更 provider 或显式提交
	// 凭据仍必须过 provider 校验。非空损坏 JSON 与其他无效存量行维持 400。
	legacyEmptyUnchanged := oldCredentials == "" && req.DNSCredentials == nil && effectiveProvider == oldProvider
	enablingLegacyEmpty := legacyEmptyUnchanged && req.Enabled != nil && *req.Enabled && !oldEnabled
	// 生效凭证与库值语义相等（显式提交但未改动凭证）时不重新校验：历史行
	// （导入/旧版本）可能存有当前 provider 不再接受的形态（如部分空串），非
	// admin 编辑表单原样回传（省略键/掩码/空串）不得 400——这是「保持库值」而
	// 非新写入。显式改动、启用与 provider 变更仍走完整校验；未提交凭证的
	// 改名/其它字段更新沿用下方 legacyEmpty/既有校验口径。
	effectiveCredentialsJSON, _ := json.Marshal(effectiveCredentials)
	credentialsUnchangedFromStored := req.DNSCredentials != nil && oldCredentials != "" && effectiveProvider == oldProvider &&
		services.CredentialsSemanticallyEqual(string(effectiveCredentialsJSON), oldCredentials)
	if (!legacyEmptyUnchanged || enablingLegacyEmpty) && !credentialsUnchangedFromStored {
		if _, err := provider.BuildCredentialsJSON(effectiveCredentials); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}

	// 禁用会使启用中的 ACME 规则在下一次签发/续期才失败；与删除路径一样
	// 提前 409 点名引用方。禁用规则的历史绑定不阻止停用，重新启用规则时
	// 仍由 validateRuleACMEReferences 拒绝绑定已禁用配置。守卫只点名
	// enable_tls=1 的规则：TLS 关闭的规则不消费 ACME 证书
	//（签发/续期/渲染证书门均以 enable_tls=1 为前提），点名它属误报。
	if req.Enabled != nil && !*req.Enabled && oldEnabled {
		refs, err := tx.QueryContext(c.Request.Context(), `SELECT caddy_id, COALESCE(domain,'') FROM lb_rules WHERE acme_config_id=? AND enabled=1 AND tls_source='acme_dns' AND IIF(enable_tls IN ('1',1),1,0)=1 ORDER BY caddy_id`, id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to check rule references"})
			return
		}
		var references []certificateConfigRuleRef
		for refs.Next() {
			var ref certificateConfigRuleRef
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
			message := formatCertificateConfigReferences(references, "启用中的 ACME 规则", "禁用")
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: message})
			return
		}
	}

	changed := []string{}
	query := "UPDATE certificate_configs SET "
	var args []interface{}

	if req.Name != "" {
		normalizedName, nameErr := normalizeCertificateConfigName(req.Name)
		if nameErr != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: nameErr.Error()})
			return
		}
		req.Name = normalizedName
	}
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
		// 全掩码回传（非 admin GET 后未改动即保存）按未提交
		// 处理——否则掩码串会覆盖真实凭证。部分掩码已在上方合并进
		// req.DNSCredentials。
		if isMaskedDNSCredentials(req.DNSCredentials) {
			req.DNSCredentials = nil
		} else {
			credsJSON, _ := json.Marshal(req.DNSCredentials)
			// 语义比较（键序/空白无关），与 CA 提供商写路径共用同一判定：
			// 带外写入的非规范 JSON 或前端重排键序不得被记成「凭证变更」。
			if !services.CredentialsSemanticallyEqual(string(credsJSON), oldCredentials) {
				query += "dns_credentials = ?, "
				args = append(args, string(credsJSON))
				changed = append(changed, "凭证")
			}
		}
	}
	if len(prunedStaleCredentialFields) > 0 {
		// 切换认证方式会真删旧族凭据（不是「保留」）：必须在审计里点名删除
		// 了哪些字段，否则事后只能看到一条「凭证」变更。
		changed = append(changed, fmt.Sprintf("清除旧认证方式凭据（%s）", strings.Join(prunedStaleCredentialFields, "、")))
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

	if _, err := tx.ExecContext(c.Request.Context(), query, args...); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to update config"})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to update config"})
		return
	}
	committed = true
	recordAudit(c, "更新", "DNS配置", services.FormatAuditDetail(fmt.Sprintf("配置 %d", id), fmt.Sprintf("变更：%s", strings.Join(changed, "、"))))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Config updated"})
}

// deleteCertificateConfigPreDeleteHook 测试钩子：在引用查询完成、
// DELETE 执行前运行——用于断言「查询→DELETE」窗口仍持有 caddyOpMu，且并发
// UpdateRule 无法在该窗口提交绑定。生产恒 nil。
var deleteCertificateConfigPreDeleteHook func()

// createOrRequeueCertJob 是 IssueCertificate 的入队接缝（测试注入队列族错误，
// 与 issueCertificateBatchSnapshotHook 同型）。生产实现直连服务层，签发端点
// 不得另写一套入队语义。
var createOrRequeueCertJob = services.CreateOrRequeueCertJobWithChange

// issueCertificateBatchSnapshotHook 是测试钩子：批量签发目标快照完成、取
// caddyOpMu 之前运行（生产恒 nil）。测试用它确定性地模拟「快照已取、规则在
// 取锁前被删除」，替代依赖墙钟 sleep 的时序假设。
var issueCertificateBatchSnapshotHook func()

func (h *Handlers) DeleteCertificateConfig(c *gin.Context) {
	// 与 UpdateCertificateConfig 同门：导入窗口内删除会作用到导入后的同 id
	// 行（或阻塞至 busy_timeout 后 500），必须 409 fast-fail。
	if rejectWriteDuringImport(c, "删除证书配置（配置导入进行中）") {
		return
	}

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid id parameter"})
		return
	}
	// 引用查询与 DELETE 必须同一临界区——lb_rules.
	// acme_config_id 上没有外键约束（certificate_configs 的引用无 FK 兜底，SQLite
	// DDL 亦未声明），并发的 UpdateRule（持 caddyOpMu、锁内 validateRuleACMEReferences
	// 查询本表）会在「查到零引用 → DELETE」窗口提交绑定，留下悬空引用（续签/首签
	// 静默失败）。与规则写路径共用 caddyOpMu 串行化；查询在锁内即读，DELETE 在锁内落库。
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	var name, provider string
	if err := db.DB.QueryRow("SELECT name, dns_provider FROM certificate_configs WHERE id = ?", id).Scan(&name, &provider); dbQueryNotFound(c, err, "Config not found", "DeleteCertificateConfig query config") {
		return
	}
	// （2026-09-05 证书域审计裁定）：删除前检查规则引用（全部规则，不限
	// enabled）——被引用的配置删除后，关联规则下一次续签/首签会以
	//「未选择可用的 DNS 提供商」静默失败，必须 409 显式列出引用方。
	refs, refErr := db.DB.Query(`SELECT caddy_id, COALESCE(domain,'') FROM lb_rules WHERE acme_config_id=? ORDER BY caddy_id`, id)
	if refErr != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to check rule references"})
		return
	}
	var references []certificateConfigRuleRef
	for refs.Next() {
		var ref certificateConfigRuleRef
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
		message := formatCertificateConfigReferences(references, "负载规则", "删除")
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: message})
		return
	}
	if deleteCertificateConfigPreDeleteHook != nil {
		deleteCertificateConfigPreDeleteHook()
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
			field := gin.H{
				"name":        f.Name,
				"label":       f.Label,
				"type":        f.Type,
				"required":    f.Required,
				"placeholder": f.Placeholder,
				"options":     p.CredentialFieldOptions(f.Name),
			}
			// 可见性/选项文案元数据（前端表单渲染单源，替代 provider 硬编码）
			if len(f.VisibleWhen) > 0 {
				field["visible_when"] = f.VisibleWhen
			}
			if len(f.OptionLabels) > 0 {
				field["option_labels"] = f.OptionLabels
			}
			fieldList = append(fieldList, field)
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
	if !guardConfiguredJSONBody(c) {
		return
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
		// 存储凭证「非空但解析失败」与「凭证填错」是不同故障——
		// unmarshal 错误此前被吞，creds=nil 走到 Validate 报「缺少凭证」，被误
		// 归因为 credentials_invalid（400），运营方会反复重改凭证。损坏归 500 +
		// 独立审计类别；空凭证（未填写/NULL）仍走 Validate 的缺凭证 400 原语义。
		if credentials != "" {
			if uerr := json.Unmarshal([]byte(credentials), &creds); uerr != nil {
				recordAudit(c, "测试失败", "DNS配置", services.FormatAuditDetail(fmt.Sprintf("配置 %d", id), configName, provider, services.AuditResultPart("storage_corrupted")))
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "存储的 DNS 凭证已损坏，请重新填写完整凭证后保存"})
				return
			}
		}
	} else {
		provider = req.DNSProvider
		creds = req.DNSCredentials
	}
	// （2026-09-05 证书域审计裁定）：无 id 的保存前凭证测试（前端 saveConfig
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
	if err := p.Validate(c.Request.Context(), creds, req.Domain); err != nil {
		recordAudit(c, "测试失败", "DNS配置", services.FormatAuditDetail(auditTarget, configName, provider, req.Domain, services.AuditResultPart("credentials_invalid")))
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	recordAudit(c, "测试成功", "DNS配置", services.FormatAuditDetail(auditTarget, configName, provider, req.Domain, services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "凭证有效"})
}

// ListCertificates 返回证书任务聚合清单（2026-09-10:原实现请求
// Caddy /pki/ca/local 返回内部 local CA 信息——与业务证书无关(autoHTTPS 已
// disable_certificates,证书由 cert_jobs 落盘经 load_files 加载),前端零消费、
// MCP 描述误导。改为从 cert_jobs 聚合每规则、每域名最新任务；同域不同规则
// 不得互相折叠，disabled/历史行也不能遮蔽其他规则的已签发证书。
// 每 (rule_id, domain) 唯一由 idx_cert_jobs_rule_domain_unique 保证——原
// MAX(id) 子查询在该唯一索引下恒等于本行（同一键不可能有更小的 id），
// 属恒等冗余，直读行即可。
func (h *Handlers) ListCertificates(c *gin.Context) {
	// 可选 rule_id 过滤（附加参数，默认行为不变）：全表扫描 + 临时排序在大规模
	// 部署下是每请求一次 O(N)，而 UI/MCP 的常见消费面是「按规则查证书」。
	// 分页与 /certificates/jobs 同口径（parsePaginationParam，缺省即全量上限）：
	// 此前无 LIMIT，规则数×域名数增长后单请求全表扫描+全量序列化。默认
	// page_size=maxCertJobPage（1000）对常规部署等价于原「全量」，响应新增
	// total 报告匹配总数，超出时调用方可翻页。
	pageValue, ok := parsePaginationParam(c, "page", 1, maxCertJobPage)
	if !ok {
		return
	}
	pageSize, ok := parsePaginationParam(c, "page_size", maxCertJobPage, maxCertJobPage)
	if !ok {
		return
	}
	page := int64(pageValue)
	offset := (page - 1) * int64(pageSize)
	whereClause := ""
	var args []any
	if ruleID := strings.TrimSpace(c.Query("rule_id")); ruleID != "" {
		whereClause = ` WHERE j.rule_id = ?`
		args = append(args, ruleID)
	}
	// total 与分页语句同过滤条件：非快照隔离（两条语句），但同一响应内
	// 「total 大于本页条数」始终表示存在更多行。
	var total int64
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM cert_jobs j"+whereClause, args...).Scan(&total); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "查询证书任务失败"})
		return
	}
	// cert_pem 只取首证书块（与 /certificates/jobs 同一单源投影）：expires_at
	// 为 NULL 的历史行（导入/旧备份/集群快照遗留的 downloaded/cleanup_*）需要由
	// PEM 派生到期时间，否则同一任务在两个证书清单端点给出分叉结论。
	query := `
		SELECT j.id, j.rule_id, j.domain, j.status, COALESCE(j.message,''), COALESCE(j.expires_at,''), COALESCE(j.updated_at,''),
			` + certJobFirstCertBlockSQL + ` AS cert_pem
		FROM cert_jobs j` + whereClause
	// ORDER BY 与唯一索引 (rule_id, domain) 的最左前缀对齐，避免临时排序 B-tree。
	query += ` ORDER BY j.rule_id, j.domain LIMIT ? OFFSET ?`
	queryArgs := append(append([]any{}, args...), pageSize, offset)
	rows, err := db.DB.Query(query, queryArgs...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "查询证书任务失败"})
		return
	}
	defer rows.Close()
	certs := make([]gin.H, 0)
	for rows.Next() {
		var id int
		var ruleID, domain, status, message, expiresAt, updatedAt, certPEM string
		if err := rows.Scan(&id, &ruleID, &domain, &status, &message, &expiresAt, &updatedAt, &certPEM); err != nil {
			// 单行 Scan 失败 warn 留痕+跳过（对齐
			// 口径）——静默丢行会让该域名在证书清单中无故缺席；
			// 迭代级失败仍由下方 rows.Err() 500 兜底。
			services.Logf("warn", "证书任务列表：跳过扫描失败行（该域名聚合行本轮缺失）: %v", err)
			continue
		}
		// not_after 与 /certificates/jobs 同语义（优先库值 expires_at，缺失时由
		// PEM 派生）；expires_at 字段本身保持原契约（可能为空）。
		notAfter := certificateListNotAfter(expiresAt, certPEM)
		certs = append(certs, gin.H{"id": id, "rule_id": ruleID, "domain": domain, "status": status, "message": message,
			"expires_at": expiresAt, "not_after": notAfter, "updated_at": updatedAt})
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "遍历证书任务失败"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"certificates": certs, "total": total, "page": page, "page_size": pageSize}})
}

// certificateListNotAfter 给出聚合清单的到期语义：优先库值 expires_at，缺失/不可
// 解析时由 PEM 首证书块派生（与 certJobListItem.scanFrom 单源口径）；两者都拿不到
// 时保持 null，不猜测。
func certificateListNotAfter(expiresAt, certPEM string) models.JSONNullTime {
	if raw := strings.TrimSpace(expiresAt); raw != "" {
		for _, layout := range []string{"2006-01-02 15:04:05", time.RFC3339} {
			if parsed, err := time.ParseInLocation(layout, raw, time.UTC); err == nil {
				return models.JSONNullTime{NullTime: sql.NullTime{Time: parsed.UTC(), Valid: true}}
			}
		}
	}
	if derived, ok := services.CertNotAfterFromPEM(certPEM); ok {
		return models.JSONNullTime{NullTime: sql.NullTime{Time: derived.UTC(), Valid: true}}
	}
	return models.JSONNullTime{}
}

// formulaSkippedNote 生成批量签发跳过归因片段：仅列出非零项，
// 全零返回空串。计数全部来自 changed=false/冷却门出口，响应与审计共用。
// retired（已退役任务，disabled 行）必须与冷却分开：它是永久条件，不是限流。
func formulaSkippedNote(cooldown, inFlight, blocked, unsupported, retired int) string {
	parts := make([]string, 0, 5)
	if cooldown > 0 {
		parts = append(parts, fmt.Sprintf("冷却跳过 %d 个", cooldown))
	}
	if inFlight > 0 {
		parts = append(parts, fmt.Sprintf("在途跳过 %d 个", inFlight))
	}
	if blocked > 0 {
		parts = append(parts, fmt.Sprintf("规则屏障跳过 %d 个", blocked))
	}
	if retired > 0 {
		parts = append(parts, fmt.Sprintf("已退役任务 %d 个", retired))
	}
	if unsupported > 0 {
		parts = append(parts, fmt.Sprintf("状态不支持重排 %d 个", unsupported))
	}
	return strings.Join(parts, "，")
}

func (h *Handlers) IssueCertificate(c *gin.Context) {
	// 导入窗口 fast-fail：导入全程持有 caddyOpMu（可达分钟级，含 30s 在途
	// 任务排空等待），签发请求排队到导入后再按导入前快照/导入后库校验会产生
	// 语义错乱。与 DNS 配置/CA 提供商/任务重试删除共用同一门。
	if rejectWriteDuringImport(c, "触发证书签发（配置导入进行中）") {
		return
	}
	var req struct {
		CaddyID string `json:"caddy_id"`
		Domain  string `json:"domain"`
		// （2026-09-06 裁定）：批量全量重签须显式 {"all":true} 确认（含已签发任务、消耗 CA 配额）；caddy_id 与 all 同传以 caddy_id 为准
		All bool `json:"all"`
	}
	if !guardConfiguredJSONBody(c) {
		return
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
	// 队列暂停必须 409 点名原因——EnqueueIfActive 的
	// !active 出口返回 changed=false（jobID=0 时上游再折成 "CA queue is paused"
	// 错误），原实现走「200 已创建 0 个任务」的假成功或 500。规则屏障与在途
	// 两条 changed=false 出口在下方定向/批量分支分别归因。
	if !qm.IsActive() {
		auditFailure("skipped", "证书签发队列已暂停")
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "证书签发队列已暂停，无法创建签发任务"})
		return
	}
	// 手动签发的 规则当前态读取→冷却门→upsert/入队
	// 全程与规则写/删除/改域共用 caddyOpMu 临界区——此前无锁读取后与
	// UpdateRule 改域迁移（任务行已改到新域）交错，本次仍按旧域 INSERT
	// 新行并入队，对旧域实际发起 CA 签发（部署期域不匹配拒绝，job 滞留
	// downloaded 至 6h sweep）；与 DeleteRule 交错可留孤儿任务行。
	// 请求体已在锁外绑定（bind-before-lock 序）；EnqueueIfActive 只取队列
	// 叶锁（m.mu/q.mu），execute 在锁外 goroutine 运行，无反向锁序。
	//
	// 批量目标快照刻意留在锁外：{"all":true} 的查询/遍历是 O(规则数)，
	// 持全局锁做只会让所有规则写与 Caddy 应用随批量规模线性排队。快照只决定
	// 候选集合，逐目标的当前态复核与 upsert 仍在锁内——已删除/禁用/改域的
	// 规则由 upsert 落库闸按冲突拒绝（ErrCertRuleStateConflict → failed）。
	type certTarget struct {
		ruleID string
		domain string
	}
	var batchTargets []certTarget
	if req.CaddyID == "" && req.All {
		rows, err := db.DB.Query("SELECT caddy_id, COALESCE(domain,'') FROM lb_rules WHERE enabled=1 AND enable_tls=1 AND tls_source='acme_dns' AND protocol='http' AND COALESCE(domain,'') != ''")
		if err != nil {
			// 审计详情/响应体都只放固定归因，底层驱动文本只进运行日志
			// （writeInternalError 记录 cause）——business 组任意登录用户可读。
			auditFailure("failed", "查询 ACME 规则失败")
			writeInternalError(c, http.StatusInternalServerError, "查询 ACME 规则失败", err)
			return
		}
		for rows.Next() {
			var ruleID, domain string
			if err := rows.Scan(&ruleID, &domain); err != nil {
				err = errors.Join(err, rows.Close())
				auditFailure("failed", "读取 ACME 规则失败")
				writeInternalError(c, http.StatusInternalServerError, "读取 ACME 规则失败", err)
				return
			}
			batchTargets = append(batchTargets, certTarget{ruleID: ruleID, domain: domain})
		}
		if err := rows.Err(); err != nil {
			err = errors.Join(err, rows.Close())
			auditFailure("failed", "遍历 ACME 规则失败")
			writeInternalError(c, http.StatusInternalServerError, "遍历 ACME 规则失败", err)
			return
		}
		if err := rows.Close(); err != nil {
			auditFailure("failed", "关闭 ACME 规则结果失败")
			writeInternalError(c, http.StatusInternalServerError, "关闭 ACME 规则结果失败", err)
			return
		}
		if issueCertificateBatchSnapshotHook != nil {
			issueCertificateBatchSnapshotHook()
		}
		// 规模上限必须在取全局锁之前拒绝：批量分支的逐目标查询+upsert 在
		// caddyOpMu 临界区内执行（保持「当前态复核→upsert 同临界区」不变量），
		// 无上限时一次请求可让全部规则写/Caddy 应用线性排队。
		if len(batchTargets) > maxBatchIssueTargets {
			auditFailure("failed", fmt.Sprintf("批量目标数 %d 超过单次上限 %d", len(batchTargets), maxBatchIssueTargets))
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("单次批量签发最多 %d 个规则（本次匹配 %d 个），请分批执行", maxBatchIssueTargets, len(batchTargets))})
			return
		}
	}
	h.caddyOpMu.Lock()
	// 部署重试登记（scheduleDeploymentRetry）可能对在途部署回调做有界等待，
	// 而回调自身要取 caddyOpMu 完成规则写/Caddy 应用——登记必须在锁外执行，
	// 否则互等到 busy 超时（30-60s），拖住全部规则写与 Caddy 启停。
	// 「只差部署」快速路径（定向/批量）会显式解锁并清标记后登记；defer 兜底
	// 其余出口。
	caddyOpHeld := true
	defer func() {
		if caddyOpHeld {
			h.caddyOpMu.Unlock()
		}
	}()
	queued := 0
	// 批量路径套用与定向签发同款冷却门，冷却中
	// 任务跳过并单列计数（仅批量分支产生非零值）。
	skippedCooldown := 0
	// waiting_ca 冷却中的目标单列（批量分支）；语义同冷却跳过，计入文案合计
	// 但响应里可分辨「CA 退避」与「失败/在途冷却」。
	skippedWaitingCA := 0
	// 其余 changed=false 出口的归因计数（仅批量分支产生非零值）。
	skippedInFlight := 0
	skippedBlocked := 0
	skippedUnsupported := 0
	// disabled 任务行（历史残留/脏快照）是永久不可重试条件，必须与冷却分开
	// 计数——把 409 永久条件折进「冷却跳过」会误导用户等待限流恢复。
	skippedRetired := 0
	// force=true 显式越过 CA 冷却（与任务重试同一契约），仅在实际越过时留痕。
	forceCAOverride := false
	forceIssue := c.Query("force") == "true"
	if req.CaddyID != "" {
		// 规则删除/迁移屏障期按冲突语义 409 点名（EnqueueIfActive 内部
		// 同判据兜底，此处给出可读原因）。
		if qm.IsRuleBlocked(req.CaddyID) {
			auditFailure("skipped", "规则证书操作被屏障阻塞（规则正在删除或迁移）")
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "规则证书操作被屏障阻塞（规则正在删除或迁移），请稍后重试"})
			return
		}
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
		var jobID int
		var jobStatus string
		var jobUpdatedAt, jobCreatedAt, jobCAAvailableAfter sql.NullTime
		var jobMaterialUsable bool
		err = db.DB.QueryRow(`SELECT id, status, updated_at, created_at, ca_available_after,
			CASE WHEN `+services.CertJobMaterialPredicateSQL("")+` THEN 1 ELSE 0 END
			FROM cert_jobs WHERE rule_id=? AND domain=?`, req.CaddyID, canonicalRuleDomain).
			Scan(&jobID, &jobStatus, &jobUpdatedAt, &jobCreatedAt, &jobCAAvailableAfter, &jobMaterialUsable)
		if err == nil {
			// 冷却门禁与文案共用同一 now（边界 <1s 时不得出现「门禁拦截、文案 0s」）。
			now := time.Now()
			if blocked, statusCode, message := certJobRetryBlocked(jobStatus, jobUpdatedAt, jobCreatedAt, now); blocked {
				auditFailure("blocked", message)
				c.JSON(statusCode, models.APIResponse{Code: statusCode, Message: message})
				return
			}
			// waiting_ca 的 CA 退避窗口与任务重试共用同一契约：未到期且未
			// force 时 429 并给出剩余时长，否则手动「重新签发」会把退避窗口
			// 静默清零、立即再次撞上 CA 限流并继续消耗配额。
			if certJobCAcooldownActive(jobStatus, jobCAAvailableAfter, now) {
				if !forceIssue {
					message := certJobCAcooldownMessage(jobCAAvailableAfter.Time, now)
					auditFailure("blocked", message)
					c.JSON(http.StatusTooManyRequests, models.APIResponse{Code: http.StatusTooManyRequests, Message: message})
					return
				}
				forceCAOverride = true
			}
			// 部署生命周期 + 材料在库：只差部署，与证书任务重试入口同源
			// （rescheduleDownloadedCertJobDeployment）。整轮重签会丢弃已签发
			// 证书并消耗 CA 配额，且与 certjobs 的重试语义分叉。
			// 锁内只推进部署窗口（DB 决策），登记立即部署 timer 在解锁后进行
			// ——见 h.caddyOpMu 上方的锁序说明。
			if jobMaterialUsable && services.JobLifecycle(jobStatus) == services.JobLifecycleDownloaded {
				rescheduled, markErr := markDownloadedCertJobDeploymentPending(jobID, req.CaddyID, canonicalRuleDomain)
				if markErr != nil {
					statusCode, message := deploymentRetryFailureResponse(markErr)
					if statusCode >= http.StatusInternalServerError {
						services.Logf("error", "IssueCertificate deployment retry failed for job %d: %v", jobID, markErr)
					}
					auditFailure("failed", message)
					c.JSON(statusCode, models.APIResponse{Code: statusCode, Message: message})
					return
				}
				if rescheduled {
					// 窗口已推进：解锁后登记并构造响应。登记失败仍按同一映射
					// 如实报 409/500（启动恢复/周期补扫会接手窗口）。
					h.caddyOpMu.Unlock()
					caddyOpHeld = false
					if deployErr := registerDownloadedCertJobDeploymentRetry(jobID, req.CaddyID); deployErr != nil {
						statusCode, message := deploymentRetryFailureResponse(deployErr)
						if statusCode >= http.StatusInternalServerError {
							services.Logf("error", "IssueCertificate deployment retry failed for job %d: %v", jobID, deployErr)
						}
						auditFailure("failed", message)
						c.JSON(statusCode, models.APIResponse{Code: statusCode, Message: message})
						return
					}
					recordAudit(c, "触发签发", "证书", services.FormatAuditDetail(scope, "已触发重新部署（不重新签发）", services.AuditResultPart("deployment_retry")))
					c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已触发重新部署（不重新签发）", Data: gin.H{"queued": 0, "redeployed": true}})
					return
				}
				// rescheduled=false：规则/材料在窗口内刚变化，回落整轮重签。
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			auditFailure("failed", "读取证书任务失败")
			writeInternalError(c, http.StatusInternalServerError, "读取证书任务失败", err)
			return
		}
		jobID, changed, err := createOrRequeueCertJob(req.CaddyID, canonicalRuleDomain, 0, qm)
		if err != nil {
			if errors.Is(err, services.ErrCertRuleStateConflict) {
				// upsert 落库闸的规则当前态复核拒绝（防御纵深——
				// 持锁临界区内正常不可达）——409 冲突语义，不得折成 500。
				auditFailure("conflict", "规则状态已变更（规则已删除、禁用或域名已修改）")
				c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "规则状态已变更（规则已删除、禁用或域名已修改），请刷新后重试"})
				return
			}
			// 入队族错误（队列暂停/规则屏障）是可行动 409，与规则写/任务重试
			// 共用 certEnqueueErrorResponse 单源映射；其余才是 500，且响应只回
			// 固定前缀（底层错误只进运行日志）。
			statusCode, message := certEnqueueErrorResponse("创建签发任务失败", err)
			if statusCode == http.StatusConflict {
				auditFailure("skipped", message)
			} else {
				auditFailure("failed", message)
			}
			c.JSON(statusCode, models.APIResponse{Code: statusCode, Message: message})
			return
		}
		if !changed {
			// changed=false 必须区分三条出口，不得统一回 200 queued=0。
			switch {
			case !qm.IsActive():
				auditFailure("skipped", "证书签发队列已暂停")
				c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "证书签发队列已暂停，无法创建签发任务"})
			case qm.IsRuleBlocked(req.CaddyID):
				auditFailure("skipped", "规则证书操作被屏障阻塞（规则正在删除或迁移）")
				c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "规则证书操作被屏障阻塞（规则正在删除或迁移），请稍后重试"})
			case qm.IsJobActive(jobID):
				// 在途：保留 200，但明确 queued=0 与归因（未新建任务）。
				recordAudit(c, "触发签发", "证书", services.FormatAuditDetail(scope, "任务正在执行中，未重复入队", services.AuditResultPart("skipped")))
				c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "签发任务正在执行中，未重复入队", Data: gin.H{"queued": 0, "skipped_cooldown": 0, "in_flight": true}})
			default:
				// 任务处于不可重排状态（非在途、非冷却）——如实 409，不伪装成功。
				auditFailure("skipped", "任务状态不支持重新入队")
				c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "签发任务状态不支持重新入队，请刷新任务状态后重试"})
			}
			return
		}
		queued++
	} else {
		if !req.All {
			auditFailure("invalid_request", "请求格式错误")
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "批量签发需要显式确认：请求体须包含 {\"all\": true}（定向签发请提供 caddy_id）"})
			return
		}
		var failed []string
		// 规则当前态冲突（ErrCertRuleStateConflict）单列：全部失败且均为冲突时
		// 与定向签发同口径 409（可行动：刷新后重试），不折成 500 服务器故障。
		conflictFailed := 0
		// 入队族冲突（队列暂停/规则屏障，certEnqueueErrorResponse 判 409）的
		// 目标数与首条归因文案：这批目标没有创建任务但不是服务端故障，全部失败
		// 时必须与定向签发同口径 409，不得折成 500 让调用方按「稍后自动重试」
		// 以外的语义处理。
		enqueueConflict := 0
		enqueueConflictMessage := ""
		// 只重排部署（材料在库、未重新签发）的目标数——与 queued（新建签发任务）
		// 分列，响应文案不得把「重新部署」谎报为「已创建签发任务」。
		redeployed := 0
		// 锁内已推进部署窗口、待锁外登记立即部署的目标——登记可能等待在途
		// 部署回调（回调要取 caddyOpMu），不得在临界区内执行。
		var pendingDeployments []certJobDeploymentRetryTarget
		// 批量循环中队列被并发暂停（不可再入队）的显式信号。
		pausedMidBatch := false
		targets := batchTargets
		for _, target := range targets {
			if !qm.IsActive() {
				// 循环中队列被并发暂停——不再当失败项累积，统一 409。
				pausedMidBatch = true
				break
			}
			if qm.IsRuleBlocked(target.ruleID) {
				skippedBlocked++
				continue
			}
			canonicalDomain, canonicalErr := services.CanonicalACMEDomains(target.domain)
			if canonicalErr != nil {
				failed = append(failed, fmt.Sprintf("%s(%v)", target.domain, canonicalErr))
				continue
			}
			// 逐目标套用与定向签发同款冷却门
			// （certJobRetryBlocked）——失败 5 分钟内/执行中的任务跳过，不再
			// 被批量重签静默重排队、反复消耗 CA 配额；跳过数单列响应计数。
			var jobID int
			var jobStatus string
			var jobUpdatedAt, jobCreatedAt, jobCAAvailableAfter sql.NullTime
			var jobMaterialUsable bool
			// CA 退避窗口是否被 force 越过：置位后仍需入队成功才算真实发生。
			cooldownOverriddenThisTarget := false
			jobErr := db.DB.QueryRow(`SELECT id, status, updated_at, created_at, ca_available_after,
				CASE WHEN `+services.CertJobMaterialPredicateSQL("")+` THEN 1 ELSE 0 END
				FROM cert_jobs WHERE rule_id=? AND domain=?`, target.ruleID, canonicalDomain).
				Scan(&jobID, &jobStatus, &jobUpdatedAt, &jobCreatedAt, &jobCAAvailableAfter, &jobMaterialUsable)
			switch {
			case jobErr == nil:
				if blocked, statusCode, _ := certJobRetryBlocked(jobStatus, jobUpdatedAt, jobCreatedAt, time.Now()); blocked {
					if statusCode == http.StatusConflict {
						// 永久条件（disabled 行）：不是冷却，单列归因。
						skippedRetired++
					} else {
						skippedCooldown++
					}
					continue
				}
				// CA 退避窗口未到期：与定向签发/任务重试同一门（force 才越过）。
				// 是否真实越过要等入队结果：changed=false（在途/屏障/状态冲突）时
				// ca_available_after 从未被清空，不得记「手动越过 CA 冷却」。
				if certJobCAcooldownActive(jobStatus, jobCAAvailableAfter, time.Now()) {
					if !forceIssue {
						skippedWaitingCA++
						continue
					}
					cooldownOverriddenThisTarget = true
				}
				// 部署生命周期 + 材料在库：与定向签发/任务重试同源，只重排部署，
				// 不整轮重签（丢弃已签发证书 + 消耗 CA 配额）。
				// 锁内只推进部署窗口，登记延到锁外（pendingDeployments）——
				// 锁序与定向路径同源。
				if jobMaterialUsable && services.JobLifecycle(jobStatus) == services.JobLifecycleDownloaded {
					rescheduled, markErr := markDownloadedCertJobDeploymentPending(jobID, target.ruleID, canonicalDomain)
					if markErr != nil {
						statusCode, message := deploymentRetryFailureResponse(markErr)
						if statusCode >= http.StatusInternalServerError {
							services.Logf("error", "Batch issue deployment retry failed for job %d: %v", jobID, markErr)
						}
						failed = append(failed, fmt.Sprintf("%s(%s)", target.domain, message))
						continue
					}
					if rescheduled {
						pendingDeployments = append(pendingDeployments, certJobDeploymentRetryTarget{jobID: jobID, ruleID: target.ruleID, domain: target.domain})
						continue
					}
					// rescheduled=false：规则/材料在窗口内刚变化，回落整轮重签。
				}
			case !errors.Is(jobErr, sql.ErrNoRows):
				// 响应体只回固定分类文案：jobErr 含表名/SQL/驱动内部态，只进
				// 运行日志（与全失败 500 出口的脱敏口径一致）。
				services.Logf("error", "Batch issue job lookup failed for %s: %v", target.ruleID, jobErr)
				failed = append(failed, fmt.Sprintf("%s(%s)", target.domain, "查询签发任务失败"))
				continue
			}
			jobID, changed, err := createOrRequeueCertJob(target.ruleID, canonicalDomain, 0, qm)
			if err != nil {
				if errors.Is(err, services.ErrCertRuleStateConflict) {
					conflictFailed++
				}
				// 入队族 409（规则状态冲突/队列暂停/规则屏障）单列计数：全部目标
				// 都是这类可行动冲突时统一按 409 回报（见下方「全部目标未入队」
				// 分支）；仍保留在 failed 清单里，部分成功出口的「N 个失败」
				// 计数与既有契约不变。失败明细恒用映射后的分类文案——err 原文
				// （SQL/队列内部态）只进运行日志，与全失败 5xx 脱敏口径一致；
				// certEnqueueErrorResponse 对非冲突错误即返回固定前缀。
				statusCode, message := certEnqueueErrorResponse("创建签发任务失败", err)
				if statusCode == http.StatusConflict {
					enqueueConflict++
					if enqueueConflictMessage == "" {
						enqueueConflictMessage = message
					}
				}
				failed = append(failed, fmt.Sprintf("%s(%s)", target.domain, message))
				continue
			}
			if !changed {
				// changed=false 逐目标归因，不得静默计入「成功」。
				switch {
				case qm.IsJobActive(jobID):
					skippedInFlight++
				case qm.IsRuleBlocked(target.ruleID):
					skippedBlocked++
				case !qm.IsActive():
					pausedMidBatch = true
				default:
					skippedUnsupported++
				}
				continue
			}
			// 入队成功才真实清空了 CA 退避窗口（upsert 的写侧口径），此刻的
			// force 才是「越过冷却」事实；失败/跳过目标由上面的计数器归因。
			if cooldownOverriddenThisTarget {
				forceCAOverride = true
			}
			queued++
		}
		// 锁外逐个登记立即部署（与定向路径同源）：每个登记都可能等待该任务的
		// 在途部署回调，而回调需要 caddyOpMu 才能完成——先释放全局锁。
		// 登记失败按同一映射计入失败项（窗口已推进，周期补扫会接手）。
		h.caddyOpMu.Unlock()
		caddyOpHeld = false
		for _, pending := range pendingDeployments {
			if deployErr := registerDownloadedCertJobDeploymentRetry(pending.jobID, pending.ruleID); deployErr != nil {
				statusCode, message := deploymentRetryFailureResponse(deployErr)
				if statusCode >= http.StatusInternalServerError {
					services.Logf("error", "Batch issue deployment retry failed for job %d: %v", pending.jobID, deployErr)
				}
				failed = append(failed, fmt.Sprintf("%s(%s)", pending.domain, message))
				continue
			}
			redeployed++
		}
		skippedTotal := skippedCooldown + skippedWaitingCA + skippedBlocked + skippedInFlight + skippedUnsupported + skippedRetired
		// forceNote 只在真实越过 CA 冷却时为非空；批量各出口（暂停/全部失败/
		// 全部跳过/部分成功）都必须携带——被清空 ca_available_after 的行已真实
		// 发生，留痕不能只存在于全成功出口。
		batchForceNote := ""
		if forceCAOverride {
			batchForceNote = "，手动越过 CA 冷却"
		}
		withForceNote := func(text string) string {
			if batchForceNote == "" {
				return text
			}
			if text == "" {
				return strings.TrimPrefix(batchForceNote, "，")
			}
			return text + batchForceNote
		}
		if pausedMidBatch && queued == 0 && redeployed == 0 {
			auditFailure("skipped", withForceNote(formulaSkippedNote(skippedCooldown+skippedWaitingCA, skippedInFlight, skippedBlocked, skippedUnsupported, skippedRetired)), "证书签发队列已暂停")
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "证书签发队列已暂停，无法创建签发任务"})
			return
		}
		if pausedMidBatch && (queued > 0 || redeployed > 0) {
			// 已入队/重排后队列被并发暂停：按部分成功返回，不能 409 谎报全失败
			// 剩余目标留给下次触发。
			skipNote := formulaSkippedNote(skippedCooldown+skippedWaitingCA, skippedInFlight, skippedBlocked, skippedUnsupported, skippedRetired)
			message := fmt.Sprintf("已创建 %d 个签发任务，已触发重新部署 %d 个；证书签发队列被暂停，剩余目标未处理", queued, redeployed)
			if skipNote != "" {
				message += "（" + skipNote + "）"
			}
			message += batchForceNote
			recordAudit(c, "触发签发", "证书", services.FormatAuditDetail(scope, message, services.AuditResultPart("partial")))
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: message, Data: gin.H{
				"queued":             queued,
				"redeployed":         redeployed,
				"failed":             len(failed),
				"skipped_cooldown":   skippedCooldown,
				"skipped_waiting_ca": skippedWaitingCA,
				"skipped_in_flight":  skippedInFlight,
				"skipped_blocked":    skippedBlocked,
				"skipped_other":      skippedUnsupported,
				"skipped_retired":    skippedRetired,
				"paused_mid_batch":   true,
			}})
			return
		}
		if queued == 0 && len(failed) > 0 && redeployed == 0 {
			// 全部失败且都是可行动冲突（规则状态已变更/队列暂停/规则屏障）：
			// 与定向签发同口径 409——批量快照取于锁外，期间规则被删除/禁用/
			// 改域或队列被并发暂停都不是服务端故障，刷新/恢复后重试即可。
			// 入队族判定与定向签发共用 certEnqueueErrorResponse 单源。
			if enqueueConflict == len(failed) {
				if conflictFailed == enqueueConflict {
					auditFailure("conflict", "规则状态已变更（规则已删除、禁用或域名已修改）")
					c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "规则状态已变更（规则已删除、禁用或域名已修改），请刷新后重试"})
					return
				}
				auditFailure("skipped", enqueueConflictMessage)
				c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: enqueueConflictMessage})
				return
			}
			skipNote := formulaSkippedNote(skippedCooldown+skippedWaitingCA, skippedInFlight, skippedBlocked, skippedUnsupported, skippedRetired)
			detail := ""
			if batchForceNote != "" {
				detail = strings.TrimPrefix(batchForceNote, "，")
			}
			if skipNote != "" {
				if detail != "" {
					detail += "；"
				}
				detail += skipNote
			}
			auditFailure("failed", detail)
			// 响应体只回固定文案：failed 明细含 SQL 片段/队列内部态，只进运行
			// 日志（business 组任意登录用户可读，5xx 不得直出底层错误）。
			services.Logf("error", "IssueCertificate batch: 全部签发任务创建失败: %s", strings.Join(failed, "; "))
			message := "全部签发任务创建失败"
			if skipNote != "" {
				// 混合形态（部分目标失败 + 部分目标被冷却/退役跳过）必须同时
				// 交代跳过归因，否则用户会把「冷却/退役跳过」误判为系统故障。
				message += "；" + skipNote
			}
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: message, Data: gin.H{
				"queued":             0,
				"redeployed":         0,
				"failed":             len(failed),
				"skipped_cooldown":   skippedCooldown,
				"skipped_waiting_ca": skippedWaitingCA,
				"skipped_in_flight":  skippedInFlight,
				"skipped_blocked":    skippedBlocked,
				"skipped_other":      skippedUnsupported,
				"skipped_retired":    skippedRetired,
				"enqueue_conflict":   enqueueConflict,
			}})
			return
		}
		if queued == 0 && redeployed > 0 {
			// 全部目标都只差部署：如实回报「重新部署」而不是「创建签发任务」。
			skipNote := withForceNote(formulaSkippedNote(skippedCooldown+skippedWaitingCA, skippedInFlight, skippedBlocked, skippedUnsupported, skippedRetired))
			message := fmt.Sprintf("已触发重新部署 %d 个（不重新签发）", redeployed)
			if len(failed) > 0 {
				message += fmt.Sprintf("；%d 个失败: %s", len(failed), strings.Join(failed, "; "))
			}
			if skipNote != "" {
				message += "；" + skipNote
			}
			recordAudit(c, "触发签发", "证书", services.FormatAuditDetail(scope, message, services.AuditResultPart("deployment_retry")))
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: message, Data: gin.H{
				"queued":             0,
				"redeployed":         redeployed,
				"failed":             len(failed),
				"skipped_cooldown":   skippedCooldown,
				"skipped_waiting_ca": skippedWaitingCA,
				"skipped_in_flight":  skippedInFlight,
				"skipped_blocked":    skippedBlocked,
				"skipped_other":      skippedUnsupported,
				"skipped_retired":    skippedRetired,
			}})
			return
		}
		if queued == 0 && redeployed == 0 {
			// 批量全部跳过（冷却/在途/屏障/状态不支持）→ 409，不得 200 假成功。
			// 零目标（尚无启用中的 ACME 规则）时 skipNote 为空，
			// 不能返回以冒号结尾的空原因——单列文案。
			skipNote := formulaSkippedNote(skippedCooldown+skippedWaitingCA, skippedInFlight, skippedBlocked, skippedUnsupported, skippedRetired)
			if skipNote == "" {
				skipNote = "当前没有处于启用状态的 ACME 签发规则"
			}
			skipNote = withForceNote(skipNote)
			auditFailure("skipped", skipNote)
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "未创建任何签发任务：" + skipNote, Data: gin.H{
				"queued":             0,
				"failed":             len(failed),
				"skipped_cooldown":   skippedCooldown,
				"skipped_waiting_ca": skippedWaitingCA,
				"skipped_in_flight":  skippedInFlight,
				"skipped_blocked":    skippedBlocked,
				"skipped_other":      skippedUnsupported,
				"skipped_retired":    skippedRetired,
			}})
			return
		}
		if len(failed) > 0 || skippedTotal > 0 || redeployed > 0 {
			skipNote := formulaSkippedNote(skippedCooldown+skippedWaitingCA, skippedInFlight, skippedBlocked, skippedUnsupported, skippedRetired)
			format := "入队 %d 个任务"
			message := fmt.Sprintf("已创建 %d 个签发任务", queued)
			if redeployed > 0 {
				format += "，重新部署 %d 个"
				message += fmt.Sprintf("，已触发重新部署 %d 个（不重新签发）", redeployed)
			}
			if len(failed) > 0 {
				format += "，失败 %d 个"
				message += fmt.Sprintf("，%d 个失败: %s", len(failed), strings.Join(failed, "; "))
			}
			if skipNote != "" {
				format += "，" + skipNote
				message += "，" + skipNote
			}
			format += batchForceNote
			message += batchForceNote
			args := []any{queued}
			if redeployed > 0 {
				args = append(args, redeployed)
			}
			if len(failed) > 0 {
				args = append(args, len(failed))
			}
			recordAudit(c, "触发签发", "证书", services.FormatAuditDetail(scope, fmt.Sprintf(format, args...), services.AuditResultPart("partial")))
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: message, Data: gin.H{
				"queued":             queued,
				"redeployed":         redeployed,
				"failed":             len(failed),
				"skipped_cooldown":   skippedCooldown,
				"skipped_waiting_ca": skippedWaitingCA,
				"skipped_in_flight":  skippedInFlight,
				"skipped_blocked":    skippedBlocked,
				"skipped_other":      skippedUnsupported,
				"skipped_retired":    skippedRetired,
			}})
			return
		}

	}
	forceNote := ""
	if forceCAOverride {
		forceNote = "，手动越过 CA 冷却"
	}
	recordAudit(c, "触发签发", "证书", services.FormatAuditDetail(scope, fmt.Sprintf("入队 %d 个任务%s", queued, forceNote), services.AuditResultPart("requested")))
	// 入队后渲染输入零变化——签发完成由 worker 链路自行应用，去掉强制重载
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: fmt.Sprintf("已创建 %d 个签发任务", queued), Data: gin.H{"queued": queued, "skipped_cooldown": skippedCooldown}})
}

func (h *Handlers) ParseCertificate(c *gin.Context) {
	// 证书解析入参 PEM 上限独立于「请求体大小」配置项（见
	// maxParseCertificateBytes 注释）：任何持凭证者（含只读 API key，
	// 本端点在 readOnlyWriteRoutes）可投递 body，必须有硬上限。
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxParseCertificateBytes)
	var req struct {
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		// 体积超限是与「PEM 格式非法」不同的可重试语义——与 ca-providers 等
		// 同域写端点同口径映射 413。
		if isRequestBodyTooLarge(err) {
			c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "请求体过大"})
			return
		}
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	info, err := parseTLSCertificate(req.CertPEM, req.KeyPEM)
	if err != nil {
		// 解析错误含 tls/x509 英文内部文本（仅只读白名单端点也须固定中文文案）：
		// 细节只进运行日志，响应固定为可行动的用户语义。
		services.Logf("warn", "ParseCertificate: 证书解析失败: %v", err)
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "证书或私钥格式无效，或二者不匹配"})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: info})
}
