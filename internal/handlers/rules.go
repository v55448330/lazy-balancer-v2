package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

var (
	createOrRequeueCertJob = services.CreateOrRequeueCertJob
	cancelRuleJobs         = func(ctx context.Context, manager *services.CAQueueManager, ruleID string) error {
		return manager.CancelJobsForRule(ctx, ruleID)
	}
	cancelRuleJobsTimeout = 2 * time.Minute
)

// enableCertJobResumePreUpdateHook 是测试专用钩子：在 EnableRule 的
// EnableCertJobResume 分支 UPDATE 之前触发，用于模拟 SELECT 与 UPDATE 之间
// 任务行被并发删除（R54 S-3 RowsAffected 校验的回归测试）。
var enableCertJobResumePreUpdateHook func(jobID int)

func (h *Handlers) ListRules(c *gin.Context) {
	rows, err := db.DB.Query(`SELECT ` + lbRuleListColumns + ` FROM lb_rules ORDER BY id`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}
	rules, err := scanLbRules(rows)
	// Round 35 I-22: rows.Close 错误也要记录，与 services 层 errors.Join 风格一致。
	if closeErr := rows.Close(); closeErr != nil {
		log.Printf("ListRules rows close error: %v", closeErr)
	}
	if err != nil {
		log.Printf("ListRules scan error: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则失败"})
		return
	}
	if err := hydrateRuleRelations(c.Request.Context(), rules); err != nil {
		log.Printf("ListRules relations error: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则关联数据失败"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: rules})
}

func (h *Handlers) GetRule(c *gin.Context) {
	caddyID := c.Param("caddy_id")
	rows, err := db.DB.Query(`SELECT `+lbRuleColumns+` FROM lb_rules WHERE caddy_id = ?`, caddyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则失败"})
		return
	}
	rules, err := scanLbRules(rows)
	// Round 35 I-22: 同 ListRules。
	if closeErr := rows.Close(); closeErr != nil {
		log.Printf("GetRule rows close error for caddy_id=%s: %v", caddyID, closeErr)
	}
	if err != nil {
		log.Printf("GetRule scan error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则失败"})
		return
	}
	if len(rules) == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
		return
	}
	if err := hydrateRuleRelations(c.Request.Context(), rules); err != nil {
		log.Printf("GetRule relations error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则关联数据失败"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: rules[0]})
}

func (h *Handlers) GetRuleCaddyConfig(c *gin.Context) {
	caddyID := c.Param("caddy_id")

	var r struct {
		CaddyID    string
		ListenPort int
		Enabled    bool
		Domain     string
		Protocol   string
	}

	services.Logf("debug", "GetRuleCaddyConfig: querying rule caddy_id=%s", caddyID)

	err := db.DB.QueryRow(`
		SELECT COALESCE(caddy_id,''), listen_port, IIF(enabled IN ('1',1),1,0), COALESCE(domain,''), COALESCE(protocol,'http')
		FROM lb_rules WHERE caddy_id = ?
	`, caddyID).Scan(&r.CaddyID, &r.ListenPort, &r.Enabled, &r.Domain, &r.Protocol)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
		return
	}

	if err != nil {
		log.Printf("GetRuleCaddyConfig: query/scan error for rule caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "获取规则失败: " + err.Error()})
		return
	}

	var upstreamCount int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM upstreams WHERE rule_id = ? AND IIF(enabled IN ('1',1),1,0) = 1`, caddyID).Scan(&upstreamCount); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "获取上游服务器失败"})
		return
	}

	services.Logf("debug", "GetRuleCaddyConfig: caddyID=%s, port=%d, upstreams=%d, enabled=%v",
		r.CaddyID, r.ListenPort, upstreamCount, r.Enabled)

	responseData := map[string]interface{}{
		"caddy_id": r.CaddyID,
		"enabled":  r.Enabled,
	}

	if r.CaddyID == "" || !r.Enabled {
		responseData["config"] = nil
		responseData["config_not_exists"] = true
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: responseData})
		return
	}

	// Get the actual route object from Caddy via @id
	caddyActualConfig, err := h.caddyService.GetConfigByID(r.CaddyID)
	if err != nil {
		log.Printf("GetRuleCaddyConfig: failed to get config from Caddy for caddy_id=%s: %v", r.CaddyID, err)
		responseData["config"] = nil
		responseData["config_not_exists"] = true
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: responseData})
		return
	}

	// Build the surrounding server/TLS context so the dialog shows certificates
	// and policies. Round 33 N-4: 定向构建仅含本规则端口 server 的上下文，
	// 不再为单条规则触发整库查询+证书快照读取的全量重渲染。
	fullConfig := services.GenerateRuleServerContext(r.CaddyID, r.ListenPort, r.Protocol, r.Domain)
	ruleContext := buildRuleCaddyContext(fullConfig, r.CaddyID, r.ListenPort, r.Domain)

	responseData["config"] = map[string]interface{}{
		"route":                   caddyActualConfig,
		"server_context":          ruleContext["server"],
		"tls_certificates":        ruleContext["tls_certificates"],
		"tls_connection_policies": ruleContext["tls_connection_policies"],
		"automation_policies":     ruleContext["automation_policies"],
	}
	responseData["config_not_exists"] = false
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: responseData})
}

// buildRuleCaddyContext extracts the server and TLS context relevant to a rule from the full Caddy config.
func buildRuleCaddyContext(fullConfig map[string]interface{}, caddyID string, listenPort int, domain string) map[string]interface{} {
	result := map[string]interface{}{
		"server":                  nil,
		"tls_certificates":        []interface{}{},
		"tls_connection_policies": []interface{}{},
		"automation_policies":     []interface{}{},
	}

	apps, _ := fullConfig["apps"].(map[string]interface{})
	if apps == nil {
		return result
	}

	// Search HTTP servers first
	if httpApp, ok := apps["http"].(map[string]interface{}); ok {
		if servers, ok := httpApp["servers"].(map[string]interface{}); ok {
			for serverName, serverVal := range servers {
				server, _ := serverVal.(map[string]interface{})
				if server == nil {
					continue
				}
				routes, _ := server["routes"].([]interface{})
				for _, routeVal := range routes {
					route, _ := routeVal.(map[string]interface{})
					if route == nil {
						continue
					}
					if route["@id"] == caddyID {
						scopedPolicies := scopedTLSConnectionPolicies(server["tls_connection_policies"], caddyID, domain)
						result["server"] = map[string]interface{}{
							"server_name":             serverName,
							"listen":                  server["listen"],
							"tls_connection_policies": scopedPolicies,
						}
						result["tls_connection_policies"] = scopedPolicies
						break
					}
				}
			}
		}
	}

	// If not found in HTTP app, search the layer4 app for TCP rules
	if result["server"] == nil {
		if layer4App, ok := apps["layer4"].(map[string]interface{}); ok {
			if servers, ok := layer4App["servers"].(map[string]interface{}); ok {
				for serverName, serverVal := range servers {
					server, _ := serverVal.(map[string]interface{})
					if server == nil {
						continue
					}
					routes, _ := server["routes"].([]interface{})
					for _, routeVal := range routes {
						route, _ := routeVal.(map[string]interface{})
						if route == nil {
							continue
						}
						if route["@id"] == caddyID {
							result["server"] = map[string]interface{}{
								"server_name": serverName,
								"listen":      server["listen"],
							}
							break
						}
					}
				}
			}
		}
	}

	tlsApp, _ := apps["tls"].(map[string]interface{})
	if tlsApp == nil {
		return result
	}

	if certs, ok := tlsApp["certificates"].(map[string]interface{}); ok {
		var certList []interface{}
		switch v := certs["load_files"].(type) {
		case []interface{}:
			certList = v
		case []map[string]interface{}:
			for _, c := range v {
				certList = append(certList, c)
			}
		}
		if certList == nil {
			switch v := certs["load_pem"].(type) {
			case []interface{}:
				certList = v
			case []map[string]interface{}:
				for _, c := range v {
					certList = append(certList, c)
				}
			}
		}
		for _, certVal := range certList {
			cert, _ := certVal.(map[string]interface{})
			if cert == nil {
				continue
			}
			matched := false
			switch tags := cert["tags"].(type) {
			case []interface{}:
				for _, tag := range tags {
					if tag == caddyID {
						matched = true
						break
					}
				}
			case []string:
				for _, tag := range tags {
					if tag == caddyID {
						matched = true
						break
					}
				}
			}
			if matched {
				result["tls_certificates"] = append(result["tls_certificates"].([]interface{}), cert)
			}
		}
	}

	if automation, ok := tlsApp["automation"].(map[string]interface{}); ok {
		if policies, ok := automation["policies"].([]interface{}); ok {
			wanted := make(map[string]struct{})
			for _, ruleDomain := range normalizedRuleDomains(domain) {
				wanted[ruleDomain] = struct{}{}
			}
			if len(wanted) > 0 {
				scoped := make([]interface{}, 0, len(policies))
				for _, policyVal := range policies {
					policy, _ := policyVal.(map[string]interface{})
					if policy == nil {
						continue
					}
					matched := false
					switch subjects := policy["subjects"].(type) {
					case []interface{}:
						for _, subject := range subjects {
							name, ok := subject.(string)
							if !ok {
								continue
							}
							if _, hit := wanted[name]; hit {
								matched = true
								break
							}
						}
					case []string:
						for _, subject := range subjects {
							if _, hit := wanted[subject]; hit {
								matched = true
								break
							}
						}
					}
					if matched {
						scoped = append(scoped, policyVal)
					}
				}
				result["automation_policies"] = scoped
			}
		}
	}

	return result
}

// scopedTLSConnectionPolicies 只保留属于当前规则的连接策略：
// certificate_selection.any_tag 携带本规则 caddyID，或 match.sni 与规则规范域名相交。
func scopedTLSConnectionPolicies(raw interface{}, caddyID string, domain string) []interface{} {
	policies, ok := raw.([]interface{})
	if !ok {
		return []interface{}{}
	}
	wanted := make(map[string]struct{})
	for _, ruleDomain := range normalizedRuleDomains(domain) {
		wanted[ruleDomain] = struct{}{}
	}
	scoped := make([]interface{}, 0, len(policies))
	for _, policyVal := range policies {
		policy, _ := policyVal.(map[string]interface{})
		if policy == nil {
			continue
		}
		matched := false
		if selection, ok := policy["certificate_selection"].(map[string]interface{}); ok {
			switch tags := selection["any_tag"].(type) {
			case []interface{}:
				for _, tag := range tags {
					if tag == caddyID {
						matched = true
						break
					}
				}
			case []string:
				for _, tag := range tags {
					if tag == caddyID {
						matched = true
						break
					}
				}
			}
		}
		if !matched && len(wanted) > 0 {
			if match, ok := policy["match"].(map[string]interface{}); ok {
				switch sni := match["sni"].(type) {
				case []interface{}:
					for _, name := range sni {
						sniDomain, ok := name.(string)
						if !ok {
							continue
						}
						if _, hit := wanted[sniDomain]; hit {
							matched = true
							break
						}
					}
				case []string:
					for _, sniDomain := range sni {
						if _, hit := wanted[sniDomain]; hit {
							matched = true
							break
						}
					}
				}
			}
		}
		if matched {
			scoped = append(scoped, policyVal)
		}
	}
	return scoped
}

// normalizedRuleDomains 将逗号分隔域名转为规范化集合（小写+punycode）。
// Round 31 C-2: CanonicalDomains 失败（手造脏数据）时回退小写拆分保留，
// 与渲染侧 normalizedDomainSet（caddy.go）同口径——此前失败返回 nil 会把
// 域名整体丢弃，导致遮蔽检查静默通过（两侧不对称且是漏洞方向）。
func normalizedRuleDomains(value string) []string {
	canonical, err := db.CanonicalDomains(value)
	if err == nil {
		return strings.Split(canonical, ",")
	}
	var result []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, strings.ToLower(part))
		}
	}
	return result
}

// canonicalACMEDomainForJobLookup 返回 cert_jobs.domain 使用的排序规范形式，
// 使任务查询不受 lb_rules.domain 用户输入顺序影响；非合法 ACME 域名集时回退原值。
func canonicalACMEDomainForJobLookup(domain string) string {
	canonical, err := services.CanonicalACMEDomains(domain)
	if err != nil {
		return domain
	}
	return canonical
}

// reversedACMEDomainForm 返回双域名集合的逆序形式；cert_jobs.domain 按排序规范
// 形式存储，而导入备份可携带用户输入顺序的非规范行——与 certjobs.go 规则侧
// joined+reversed 双形式匹配同型。
func reversedACMEDomainForm(domain string) string {
	if parts := strings.Split(domain, ","); len(parts) == 2 {
		return parts[1] + "," + parts[0]
	}
	return domain
}

// retireCertJobsForDomain 将规则下旧域证书任务退役为 disabled 终态（保留 PEM 作
// 历史）。导入备份可携带非规范 domain 行（大小写/空白/顺序变体），按去空白小写
// 归一（lower+replace）与 canonical/reversed 双形式匹配，避免变体行逃逸退役
// （R50 S-2）；零行命中为无害无操作。
func retireCertJobsForDomain(database *sql.DB, ruleID, canonicalDomain, reversedDomain string) error {
	_, err := database.Exec(
		`UPDATE cert_jobs SET status='disabled', message='域名迁移事务开启失败，旧域任务退役', updated_at=datetime('now') WHERE rule_id=? AND lower(replace(domain,' ','')) IN (?,?)`,
		ruleID, canonicalDomain, reversedDomain)
	return err
}

func validateRuleListenPort(protocol string, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("端口必须在 1-65535 之间")
	}
	if port == 8000 || port == 2019 {
		return fmt.Errorf("端口 %d 为管理端口，不可使用", port)
	}
	if protocol == "tcp" && (port == 80 || port == 443) {
		return fmt.Errorf("端口 %d 为 HTTP/HTTPS 保留端口", port)
	}
	return nil
}

func enabledRuleDomainConflict(domain string, listenPort int, excludeCaddyID string) (bool, error) {
	return queryRuleDomainConflict(domain, listenPort, excludeCaddyID, " AND enabled = 1")
}

// queryRedirectShadowConflict 检查 80 端口跳转遮蔽：启用中的 TLS+HTTP 跳转规则会在
// 80 端口服务器头部生成 terminal 跳转路由（caddy.go redirectRoutes），同域名直接
// 监听 80 的规则会被遮蔽为死规则。两个方向同判：保存 80 端口规则时查跳转规则占用；
// 保存/启用 TLS+跳转规则时查 80 端口规则占用。返回冲突规则描述与冲突域名。
func queryRedirectShadowConflict(domain string, listenPort int, enableTLS, tlsHTTPRedirect bool, excludeCaddyID string) (string, string, error) {
	candidates := normalizedRuleDomains(domain)
	if len(candidates) == 0 {
		return "", "", nil
	}
	wanted := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		wanted[candidate] = struct{}{}
	}
	var rows *sql.Rows
	var err error
	switch {
	case listenPort == 80:
		// Round 29 G-4: 排除对方 80 端口自环跳转规则（listen_port=80 + TLS + 跳转本身
		// 生成自环 Location、属非法存量，不应作为占用方拦截新建 80 规则）。
		rows, err = db.DB.Query("SELECT caddy_id, name, COALESCE(domain,'') FROM lb_rules WHERE protocol='http' AND enabled=1 AND enable_tls=1 AND tls_http_redirect=1 AND listen_port != 80 AND caddy_id != ?", excludeCaddyID)
	case enableTLS && tlsHTTPRedirect:
		rows, err = db.DB.Query("SELECT caddy_id, name, COALESCE(domain,'') FROM lb_rules WHERE protocol='http' AND enabled=1 AND listen_port=80 AND caddy_id != ?", excludeCaddyID)
	default:
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	defer rows.Close()
	for rows.Next() {
		var otherID, otherName, otherDomain string
		if err := rows.Scan(&otherID, &otherName, &otherDomain); err != nil {
			return "", "", err
		}
		for _, existing := range normalizedRuleDomains(otherDomain) {
			if _, hit := wanted[existing]; hit {
				return otherName + "（" + otherID + "）", existing, nil
			}
		}
	}
	return "", "", rows.Err()
}

func ruleDomainConflict(domain string, listenPort int, excludeCaddyID string) (bool, error) {
	// 仅统计启用中的规则：禁用规则不占用域名，创建/更新时不应被其阻塞；启用时
	// 仍由 enabledRuleDomainConflict 二次把关，避免两条禁用规则同时启用产生冲突。
	return enabledRuleDomainConflict(domain, listenPort, excludeCaddyID)
}

func queryRuleDomainConflict(domain string, listenPort int, excludeCaddyID, extraWhere string) (bool, error) {
	candidates := normalizedRuleDomains(domain)
	if len(candidates) == 0 {
		return false, nil
	}
	wanted := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		wanted[candidate] = struct{}{}
	}
	rows, err := db.DB.Query("SELECT COALESCE(domain,'') FROM lb_rules WHERE protocol='http' AND listen_port = ? AND caddy_id != ?"+extraWhere, listenPort, excludeCaddyID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var existing string
		if err := rows.Scan(&existing); err != nil {
			return false, err
		}
		for _, existingDomain := range normalizedRuleDomains(existing) {
			if _, conflict := wanted[existingDomain]; conflict {
				return true, nil
			}
		}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	return false, nil
}

// 数据库即唯一事实源契约（CreateRule/UpdateRule 保存路径）：
//  1. 全部校验（含 validateCaddyConfigBeforeSave 的 Caddy 整配置预校验）先于任何写库完成，
//     校验不过不落库；
//  2. 写库失败以「写入数据库失败（…）: <原因>」明确回报给保存方；
//  3. Caddy 配置只能从事务内渲染（ApplyConfigFromTx），应用失败即回滚事务并返回 400 +
//     具体原因，数据库与运行配置不会因保存路径产生不一致。
func (h *Handlers) CreateRule(c *gin.Context) {

	// Round 36 BLOCKING-1: 限制请求体大小防止 OOM（与 config_backup.go limitConfigImportBody 一致策略）。
	const maxCreateRuleBodyBytes int64 = 1 << 20 // 1MB
	if c.Request.ContentLength > maxCreateRuleBodyBytes {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "请求体过大"})
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxCreateRuleBodyBytes)
	// Round 35 B2: io.ReadAll(c.Request.Body) 在 ShouldBindJSON 之后调用永远读到空。
	// 改为先读原始 body 再放回，确保错误日志能记录到导致解析失败的实际请求内容。
	rawBody, _ := io.ReadAll(c.Request.Body)
	c.Request.Body = io.NopCloser(bytes.NewReader(rawBody))
	var req models.CreateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Round 36 BLOCKING-3: 截断 body 日志避免敏感信息（TLS 私钥/密码）泄漏。
		bodyPreview := string(rawBody)
		if len(bodyPreview) > 512 {
			bodyPreview = bodyPreview[:512] + "...(truncated)"
		}
		log.Printf("CreateRule bind error: %v, body_length: %d, body_preview: %s", err, len(rawBody), bodyPreview)
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("Invalid request: %v", err)})
		return
	}

	// 与 UpdateRule/DeleteRule 同一锁序：先 caddyOpMu 后 DB，冲突检查与写入串行化
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	log.Printf("CreateRule bind success: name=%s, protocol=%s, port=%d, upstreams=%d", req.Name, req.Protocol, req.ListenPort, len(req.Upstreams))

	if req.Name == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "名称不能为空"})
		return
	}
	if req.Protocol == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "协议不能为空"})
		return
	}
	// When TLS is enabled for HTTP, default the listen port to 443 unless the user explicitly set another port.
	if req.Protocol == "http" && req.EnableTLS && req.ListenPort == 0 {
		req.ListenPort = 443
	}

	if req.ListenPort <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "监听端口必须大于 0"})
		return
	}

	if len(req.Upstreams) == 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "至少需要一个上游服务器"})
		return
	}

	if req.Protocol == "http" && strings.TrimSpace(req.Domain) == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "HTTP/HTTPS 规则的域名不能为空"})
		return
	}
	if req.Protocol == "http" && req.Domain != "" {
		canonicalDomain, err := db.CanonicalDomains(req.Domain)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "域名格式无效"})
			return
		}
		req.Domain = canonicalDomain
	}
	if req.EnableTLS && req.TLSSource == "acme_dns" && req.Domain != "" {
		if err := services.ValidateACMEDomains(req.Domain); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}

	if req.DnsFamily == "" {
		req.DnsFamily = "ipv4"
	}

	if err := validateRuleListenPort(req.Protocol, req.ListenPort); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if err := h.validatePortFromDB(req.Protocol, req.ListenPort, ""); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	// Domain uniqueness: HTTP/HTTPS rules cannot share the same domain.
	if req.Protocol == "http" && req.Domain != "" {
		existing, err := ruleDomainConflict(req.Domain, req.ListenPort, "")
		if err != nil {
			log.Printf("CreateRule domain conflict query failed for domain=%s: %v", req.Domain, err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "检查域名冲突失败"})
			return
		}
		if existing {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "域名已被其他 HTTP/HTTPS 规则使用"})
			return
		}
		shadowRule, shadowDomain, err := queryRedirectShadowConflict(req.Domain, req.ListenPort, req.EnableTLS, req.TLSHTTPRedirect, "")
		if err != nil {
			log.Printf("CreateRule redirect shadow query failed for domain=%s: %v", req.Domain, err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "检查域名冲突失败"})
			return
		}
		if shadowRule != "" {
			if req.ListenPort == 80 {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("域名 %s 已被规则 %s 的 HTTPS 跳转占用（跳转在 80 端口优先生效，保存后本规则将不可达）", shadowDomain, shadowRule)})
			} else {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("域名 %s 已有规则 %s 直接监听 80 端口，开启 HTTP 转 HTTPS 跳转会使其不可达，请先调整该规则", shadowDomain, shadowRule)})
			}
			return
		}
	}
	if req.Strategy == "" {
		req.Strategy = "weighted_round_robin"
	}
	if req.HealthCheckInterval == 0 {
		req.HealthCheckInterval = 10
	}
	if req.HealthCheckTimeout == 0 {
		req.HealthCheckTimeout = 2
	}
	if req.EnableTLS && req.TLSSource != "manual" && req.TLSSource != "acme_dns" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "启用 TLS 时必须选择证书来源（manual 或 acme_dns）"})
		return
	}
	// Validate TLS certificate if provided (manual source only)
	if req.EnableTLS && req.TLSSource == "manual" {
		if strings.TrimSpace(req.TLSCert) == "" || strings.TrimSpace(req.TLSKey) == "" {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "手动证书模式下必须提供 TLS 证书和私钥"})
			return
		}
		if err := validateTLSCertificate(req.TLSCert, req.TLSKey); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "TLS 证书校验失败: " + err.Error()})
			return
		}
	}

	if req.CompressTypes == "" {
		req.CompressTypes = "gzip"
	}

	if req.RequestBodyMaxSizeMB < 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求体大小限制不能为负数"})
		return
	}
	if req.UpstreamKeepaliveTimeout < 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "上游 keepalive 超时不能为负数"})
		return
	}
	if req.ServerTokensHidden < 0 || req.ServerTokensHidden > 2 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "server_tokens_hidden 必须为 0、1 或 2"})
		return
	}
	features := createRuleFeatures(req)
	if err := validateRuleFeatures(features); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	// Determine server name based on port, protocol and TLS status
	var serverName string
	var listenPort int
	if req.Protocol == "http" {
		if req.EnableTLS && req.ListenPort == 443 {
			serverName = "http_443"
		} else if req.ListenPort == 80 {
			serverName = "http_80"
		} else if req.EnableTLS {
			serverName = fmt.Sprintf("http_%d", req.ListenPort)
		} else {
			serverName = fmt.Sprintf("http_%d", req.ListenPort)
		}
		listenPort = req.ListenPort
	} else {
		serverName = fmt.Sprintf("tcp_%d", req.ListenPort)
		listenPort = req.ListenPort
	}

	userIDInt := contextUserID(c)

	// Generate caddy_id for @id-based management
	caddyID, err := services.GenerateCaddyID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "生成规则 ID 失败"})
		return
	}

	var global struct {
		requestBodyMaxSizeMB, upstreamKeepaliveTimeout                                                        int
		proxyDialTimeout, proxyResponseHeaderTimeout, proxyReadTimeout, proxyWriteTimeout, proxyStreamTimeout int
		proxyFlushInterval, proxyStreamCloseDelay                                                             int
		serverTokensHidden                                                                                    bool
	}
	if err := db.DB.QueryRow(`
		SELECT COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0),
			COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0), COALESCE(proxy_flush_interval,0), COALESCE(proxy_stream_close_delay,0),
			COALESCE(server_tokens_hidden,FALSE)
		FROM global_config WHERE id = 1
	`).Scan(&global.requestBodyMaxSizeMB, &global.upstreamKeepaliveTimeout,
		&global.proxyDialTimeout, &global.proxyResponseHeaderTimeout, &global.proxyReadTimeout, &global.proxyWriteTimeout, &global.proxyStreamTimeout, &global.proxyFlushInterval, &global.proxyStreamCloseDelay,
		&global.serverTokensHidden); err != nil {
		log.Printf("CreateRule failed to load global config: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取全局配置失败"})
		return
	}

	// Build route config for Caddy validation (using request data before DB write)
	ruleConfig := services.SingleRuleConfig{
		Protocol:                         req.Protocol,
		Domain:                           req.Domain,
		ListenPort:                       listenPort,
		Strategy:                         req.Strategy,
		DynamicDNS:                       req.DynamicDNS,
		EnableDnsServer:                  req.EnableDnsServer,
		DnsServer:                        req.DnsServer,
		DnsFamily:                        req.DnsFamily,
		HealthCheckPath:                  req.HealthCheckPath,
		HealthCheckInterval:              req.HealthCheckInterval,
		HealthCheckTimeout:               req.HealthCheckTimeout,
		HealthCheckUnhealthyThreshold:    req.HealthCheckUnhealthyThreshold,
		EnableActiveHealthCheck:          req.EnableActiveHealthCheck,
		TCPHealthCheckPort:               req.TCPHealthCheckPort,
		TCPProxyProtocol:                 req.TCPProxyProtocol,
		TCPTryDuration:                   req.TCPTryDuration,
		TCPTryInterval:                   req.TCPTryInterval,
		RequestBodyMaxSizeMB:             req.RequestBodyMaxSizeMB,
		UpstreamKeepaliveTimeout:         req.UpstreamKeepaliveTimeout,
		ServerTokensHidden:               req.ServerTokensHidden,
		GlobalRequestBodyMaxSizeMB:       global.requestBodyMaxSizeMB,
		GlobalUpstreamKeepaliveTimeout:   global.upstreamKeepaliveTimeout,
		GlobalServerTokensHidden:         global.serverTokensHidden,
		CustomRoutesEnabled:              features.CustomRoutesEnabled,
		PathRules:                        toPathRuleConfigs(features.PathRules),
		ProxyDialTimeout:                 features.ProxyDialTimeout,
		ProxyResponseHeaderTimeout:       features.ProxyResponseHeaderTimeout,
		ProxyReadTimeout:                 features.ProxyReadTimeout,
		ProxyWriteTimeout:                features.ProxyWriteTimeout,
		ProxyStreamTimeout:               features.ProxyStreamTimeout,
		ProxyFlushInterval:               features.ProxyFlushInterval,
		ProxyStreamCloseDelay:            features.ProxyStreamCloseDelay,
		GlobalProxyDialTimeout:           global.proxyDialTimeout,
		GlobalProxyResponseHeaderTimeout: global.proxyResponseHeaderTimeout,
		GlobalProxyReadTimeout:           global.proxyReadTimeout,
		GlobalProxyWriteTimeout:          global.proxyWriteTimeout,
		GlobalProxyStreamTimeout:         global.proxyStreamTimeout,
		GlobalProxyFlushInterval:         global.proxyFlushInterval,
		GlobalProxyStreamCloseDelay:      global.proxyStreamCloseDelay,
		EnableTLS:                        req.EnableTLS,
		TLSSource:                        req.TLSSource,
		ACMEConfigID:                     req.ACMEConfigID,
		TLSHTTPRedirect:                  req.TLSHTTPRedirect,
		EnableCompress:                   req.EnableCompress,
		CompressTypes:                    req.CompressTypes,
		HostHeader:                       req.HostHeader,
		CaddyID:                          caddyID,
	}
	for _, u := range req.Upstreams {
		protocol := u.Protocol
		if protocol == "" {
			if req.Protocol == "tcp" {
				protocol = "tcp"
			} else {
				protocol = "http"
			}
		}
		weight := u.Weight
		if weight == 0 {
			weight = 1
		}
		ruleConfig.Upstreams = append(ruleConfig.Upstreams, services.UpstreamConfig{
			Host: u.Host, Port: u.Port, Weight: weight, Protocol: protocol, Enabled: u.Enabled,
			MaxConnections: u.MaxConnections,
		})
	}

	// Validate Caddy config BEFORE writing to database
	if err := h.validateCaddyConfigBeforeSave(req, features, "new_"+generateRandomString(8), serverName); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if req.Protocol == "http" && req.EnableTLS && req.TLSSource == "acme_dns" {
		resolvedCAProviderID, resolveErr := services.ResolveCAProviderID(req.CAProviderID)
		if resolveErr != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "解析 CA 提供商失败: " + resolveErr.Error()})
			return
		}
		req.CAProviderID = resolvedCAProviderID
	} else {
		req.CAProviderID = 0
	}

	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败: " + err.Error()})
		return
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				log.Printf("CreateRule transaction rollback failed for caddy_id=%s: %v", caddyID, rollbackErr)
			}
		}
	}()

	_, err = tx.Exec(`
		INSERT INTO lb_rules (name, description, protocol, domain, listen_port, strategy, dynamic_dns, enable_dns_server, dns_server, dns_family,
			health_check_path, health_check_interval, health_check_timeout,
			health_check_unhealthy_threshold, health_check_healthy_threshold,
			enable_active_health_check, tcp_health_check_port, tcp_proxy_protocol, tcp_try_duration, tcp_try_interval,
		request_body_max_size_mb, upstream_keepalive_timeout, server_tokens_hidden,
		custom_routes_enabled,
		proxy_dial_timeout, proxy_response_header_timeout, proxy_read_timeout, proxy_write_timeout, proxy_stream_timeout, proxy_flush_interval, proxy_stream_close_delay,
		host_header, enable_tls, tls_source, acme_config_id, ca_provider_id, tls_cert, tls_key, tls_http_redirect,
		enable_compress, compress_types, enabled, created_by, updated_at, caddy_id, log_enabled)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, req.Name, req.Description, req.Protocol, req.Domain, req.ListenPort, req.Strategy, req.DynamicDNS, req.EnableDnsServer, req.DnsServer, req.DnsFamily,
		req.HealthCheckPath, req.HealthCheckInterval, req.HealthCheckTimeout,
		req.HealthCheckUnhealthyThreshold, req.HealthCheckHealthyThreshold,
		req.EnableActiveHealthCheck, req.TCPHealthCheckPort, req.TCPProxyProtocol, req.TCPTryDuration, req.TCPTryInterval,
		req.RequestBodyMaxSizeMB, req.UpstreamKeepaliveTimeout, req.ServerTokensHidden,
		features.CustomRoutesEnabled,
		features.ProxyDialTimeout, features.ProxyResponseHeaderTimeout, features.ProxyReadTimeout, features.ProxyWriteTimeout, features.ProxyStreamTimeout, features.ProxyFlushInterval, features.ProxyStreamCloseDelay,
		req.HostHeader, req.EnableTLS, req.TLSSource, req.ACMEConfigID, req.CAProviderID, req.TLSCert, req.TLSKey,
		req.TLSHTTPRedirect, req.EnableCompress, req.CompressTypes, 1, userIDInt, time.Now().UTC().Format("2006-01-02 15:04:05"), caddyID, req.LogEnabled)

	if err != nil {
		tx.Rollback()
		log.Printf("CreateRule database error: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "写入数据库失败（创建规则）: " + err.Error()})
		return
	}

	for _, u := range req.Upstreams {
		if u.Weight == 0 {
			u.Weight = 1
		}
		if u.Protocol == "" {
			if req.Protocol == "tcp" {
				u.Protocol = "tcp"
			} else {
				u.Protocol = "http"
			}
		}
		// Round 37 I-11: HTTP 规则上游 protocol=tls 静默当 http 处理（与 TCP 行为不对称），显式拒绝。
		if req.Protocol == "http" && u.Protocol == "tls" {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "HTTP 规则的上游协议不支持 tls，请使用 http 或 https"})
			return
		}
		_, err = tx.Exec(`INSERT INTO upstreams (rule_id, host, port, weight, dynamic_dns, enabled, protocol, max_connections)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			caddyID, u.Host, u.Port, u.Weight, u.DynamicDNS, u.Enabled, u.Protocol, u.MaxConnections)
		if err != nil {
			tx.Rollback()
			log.Printf("CreateRule upstream insert error: %v", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "写入数据库失败（创建上游服务器）: " + err.Error()})
			return
		}
	}
	if err := replacePathRulesTx(c.Request.Context(), tx, caddyID, features.PathRules); err != nil {
		tx.Rollback()
		log.Printf("CreateRule path_rules replace error: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "写入数据库失败（创建自定义路径规则）: " + err.Error()})
		return
	}

	runtimeSnapshot, err := h.snapshotImportRuntime([]string{caddyID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份当前运行配置失败"})
		return
	}
	if err := h.caddyService.ApplyConfigFromTx(tx); err != nil {
		restoreErr := h.restoreImportRuntime(runtimeSnapshot)
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy 配置应用失败，规则未创建: " + errors.Join(err, restoreErr).Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		restoreErr := h.restoreImportRuntime(runtimeSnapshot)
		log.Printf("CreateRule transaction commit error: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交规则失败: " + errors.Join(err, restoreErr).Error()})
		return
	}
	committed = true

	removeCreatedRule := func() error {
		cleanupCtx, cancelCleanup := compensationContext(c.Request.Context())
		defer cancelCleanup()
		cleanupTx, beginErr := db.DB.BeginTx(cleanupCtx, nil)
		if beginErr != nil {
			return fmt.Errorf("开启创建补偿事务: %w", beginErr)
		}
		cleanupCommitted := false
		defer func() {
			if !cleanupCommitted {
				if rollbackErr := cleanupTx.Rollback(); rollbackErr != nil && rollbackErr != sql.ErrTxDone {
					log.Printf("CreateRule compensation rollback failed for caddy_id=%s: %v", caddyID, rollbackErr)
				}
			}
		}()
		for _, statement := range []string{
			"DELETE FROM cert_jobs WHERE rule_id = ?",
			"DELETE FROM security_policy_bindings WHERE rule_caddy_id = ?",
			"DELETE FROM upstreams WHERE rule_id = ?",
			"DELETE FROM lb_rules WHERE caddy_id = ?",
		} {
			if _, cleanupErr := cleanupTx.ExecContext(cleanupCtx, statement, caddyID); cleanupErr != nil {
				return fmt.Errorf("补偿删除已创建规则: %w", cleanupErr)
			}
		}
		if commitErr := cleanupTx.Commit(); commitErr != nil {
			return fmt.Errorf("提交创建补偿事务: %w", commitErr)
		}
		cleanupCommitted = true
		services.RemoveCertFiles(caddyID)
		return nil
	}
	restoreCreatedRule := func() error {
		return errors.Join(h.restoreImportRuntime(runtimeSnapshot), removeCreatedRule())
	}
	if req.EnableTLS && req.TLSSource == "acme_dns" && req.Protocol == "http" && req.Domain != "" {
		qm := services.GetCAQueueManager()
		if qm == nil {
			if restoreErr := restoreCreatedRule(); restoreErr != nil {
				services.Logf("error", "CRITICAL: CreateRule ACME compensation failed for caddy_id=%s: %v", caddyID, restoreErr)
			}
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "CA 队列未初始化"})
			return
		}
		if _, err := services.CreateOrRequeueCertJob(caddyID, req.Domain, req.CAProviderID, qm); err != nil {
			if restoreErr := restoreCreatedRule(); restoreErr != nil {
				services.Logf("error", "CRITICAL: CreateRule ACME compensation failed for caddy_id=%s: %v", caddyID, restoreErr)
			}
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "创建证书任务失败: " + err.Error()})
			return
		}
	}

	log.Printf("Rule created with caddy_id=%s", caddyID)
	recordAudit(c, "创建", "负载规则", services.FormatAuditDetail(services.AuditRulePart(caddyID), req.Name, fmt.Sprintf("协议：%s", req.Protocol), fmt.Sprintf("端口：%d", req.ListenPort), req.Domain))
	recordAudit(c, "重载", "Caddy服务", services.FormatAuditDetail(services.AuditSourcePart("rule_create"), services.AuditRulePart(caddyID), services.AuditResultPart("success")))
	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Message: "规则已创建", Data: gin.H{"caddy_id": caddyID}})
}

func (h *Handlers) UpdateRule(c *gin.Context) {

	caddyID := c.Param("caddy_id")

	var req models.UpdateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("UpdateRule bind error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的请求: " + err.Error()})
		return
	}
	requestedProtocol := req.Protocol

	// caddyOpMu 必须覆盖 读取→合并→验证→快照→提交→应用→恢复 全程：锁外读取合并时，
	// 并发的成功请求会用旧快照合并值覆盖彼此已提交的字段（丢失更新）。
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	services.Logf("debug", "UpdateRule request for caddy_id=%s: enable_tls=%v, tls_source=%s, ca_provider_id=%v, cert_len=%d, key_len=%d",
		caddyID, derefBool(req.EnableTLS), req.TLSSource, func() interface{} {
			if req.CAProviderID == nil {
				return "<nil>"
			}
			return *req.CAProviderID
		}(), len(req.TLSCert), len(req.TLSKey))

	// When TLS is enabled on HTTP, default the port to 443 if the user didn't explicitly set one.
	// For updates the port is fixed, so we only apply the default when an explicit port was not supplied.
	if req.Protocol == "http" && req.EnableTLS != nil && *req.EnableTLS && req.ListenPort == 0 {
		req.ListenPort = 443
	}

	// Fill in missing fields from database so validation and the update use complete data.
	var existingRule models.LbRule
	err := db.DB.QueryRow(`
		SELECT COALESCE(protocol,''), COALESCE(domain,''), listen_port, COALESCE(strategy,'weighted_round_robin'),
			COALESCE(tls_cert,''), COALESCE(tls_key,''), COALESCE(tls_source,'manual'), COALESCE(acme_config_id,0),
			COALESCE(ca_provider_id,0),
			COALESCE(enable_tls,0), COALESCE(tls_http_redirect,0),
			COALESCE(dynamic_dns,0), COALESCE(enable_dns_server,0), COALESCE(dns_server,''), COALESCE(dns_family,'ipv4'),
			COALESCE(health_check_path,''), COALESCE(health_check_interval,10), COALESCE(health_check_timeout,5),
			COALESCE(health_check_unhealthy_threshold,3), COALESCE(health_check_healthy_threshold,2),
			COALESCE(enable_active_health_check,0), COALESCE(tcp_health_check_port,0), COALESCE(tcp_proxy_protocol,0), COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,250),
		COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,0),
		COALESCE(custom_routes_enabled,0),
		COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0), COALESCE(proxy_flush_interval,0), COALESCE(proxy_stream_close_delay,0),
		COALESCE(host_header,''), COALESCE(enable_compress,1), COALESCE(compress_types,'gzip'),
		IIF(enabled IN ('1',1),1,0), COALESCE(log_enabled,0), name, description
	FROM lb_rules WHERE caddy_id = ?`, caddyID).Scan(
		&existingRule.Protocol, &existingRule.Domain, &existingRule.ListenPort, &existingRule.Strategy,
		&existingRule.TLSCert, &existingRule.TLSKey, &existingRule.TLSSource, &existingRule.ACMEConfigID,
		&existingRule.CAProviderID,
		&existingRule.EnableTLS, &existingRule.TLSHTTPRedirect,
		&existingRule.DynamicDNS, &existingRule.EnableDnsServer, &existingRule.DnsServer, &existingRule.DnsFamily,
		&existingRule.HealthCheckPath, &existingRule.HealthCheckInterval, &existingRule.HealthCheckTimeout,
		&existingRule.HealthCheckUnhealthyThreshold, &existingRule.HealthCheckHealthyThreshold,
		&existingRule.EnableActiveHealthCheck, &existingRule.TCPHealthCheckPort, &existingRule.TCPProxyProtocol, &existingRule.TCPTryDuration, &existingRule.TCPTryInterval,
		&existingRule.RequestBodyMaxSizeMB, &existingRule.UpstreamKeepaliveTimeout, &existingRule.ServerTokensHidden,
		&existingRule.CustomRoutesEnabled,
		&existingRule.ProxyDialTimeout, &existingRule.ProxyResponseHeaderTimeout, &existingRule.ProxyReadTimeout, &existingRule.ProxyWriteTimeout, &existingRule.ProxyStreamTimeout, &existingRule.ProxyFlushInterval, &existingRule.ProxyStreamCloseDelay,
		&existingRule.HostHeader, &existingRule.EnableCompress, &existingRule.CompressTypes,
		&existingRule.Enabled, &existingRule.LogEnabled, &existingRule.Name, &existingRule.Description)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
		return
	}
	existingRule.PathRules, err = loadPathRules(c.Request.Context(), db.DB, caddyID)
	if err != nil {
		log.Printf("UpdateRule failed to load path_rules for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取自定义路径规则失败"})
		return
	}

	// Capture old upstreams for potential DB rollback.
	// Round 34 F-1: 存量 upstreams.enabled 无 NOT NULL，NULL 行裸 scan 进 bool 会 500；
	// IIF 与生成侧（services/caddy.go）同口径：NULL 视同禁用，回写/回滚保持同一有效状态。
	var oldUpstreams []models.Upstream
	oldUpstreamRows, err := db.DB.Query("SELECT host, port, COALESCE(weight,1), COALESCE(dynamic_dns,0), IIF(enabled IN ('1',1),1,0), COALESCE(protocol,'http'), COALESCE(max_connections,0) FROM upstreams WHERE rule_id = ?", caddyID)
	if err != nil {
		log.Printf("UpdateRule failed to read existing upstreams for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取现有上游服务器失败"})
		return
	}
	for oldUpstreamRows.Next() {
		var u models.Upstream
		if err := oldUpstreamRows.Scan(&u.Host, &u.Port, &u.Weight, &u.DynamicDNS, &u.Enabled, &u.Protocol, &u.MaxConnections); err != nil {
			if closeErr := oldUpstreamRows.Close(); closeErr != nil {
				log.Printf("UpdateRule failed to close existing upstream cursor for caddy_id=%s: %v", caddyID, closeErr)
			}
			log.Printf("UpdateRule failed to scan existing upstream for caddy_id=%s: %v", caddyID, err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取现有上游服务器失败"})
			return
		}
		oldUpstreams = append(oldUpstreams, u)
	}
	if err := oldUpstreamRows.Err(); err != nil {
		if closeErr := oldUpstreamRows.Close(); closeErr != nil {
			log.Printf("UpdateRule failed to close existing upstream cursor for caddy_id=%s: %v", caddyID, closeErr)
		}
		log.Printf("UpdateRule existing upstream cursor failed for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取现有上游服务器失败"})
		return
	}
	if err := oldUpstreamRows.Close(); err != nil {
		log.Printf("UpdateRule failed to close existing upstream cursor for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取现有上游服务器失败"})
		return
	}

	// Use existing values for fields not provided in request
	if req.Protocol == "" {
		req.Protocol = existingRule.Protocol
	}
	if req.Domain == "" {
		req.Domain = existingRule.Domain
	}
	if req.ListenPort == 0 {
		req.ListenPort = existingRule.ListenPort
	}
	if req.Strategy == "" {
		req.Strategy = existingRule.Strategy
	}
	if req.TLSSource == "" {
		req.TLSSource = existingRule.TLSSource
	}
	if req.ACMEConfigID == 0 {
		req.ACMEConfigID = existingRule.ACMEConfigID
	}
	// R52 F-1（写侧）：nil=保留现值先合并，validateCaddyConfigBeforeSave
	// 才能对合并后的生效值做存在性校验（与上方 acme_config_id 同口径）。
	if req.CAProviderID == nil {
		req.CAProviderID = &existingRule.CAProviderID
	}
	if req.HealthCheckPath == "" {
		req.HealthCheckPath = existingRule.HealthCheckPath
	}
	if req.HealthCheckInterval == 0 {
		req.HealthCheckInterval = existingRule.HealthCheckInterval
	}
	if req.HealthCheckTimeout == 0 {
		req.HealthCheckTimeout = existingRule.HealthCheckTimeout
	}
	if req.HealthCheckUnhealthyThreshold == 0 {
		req.HealthCheckUnhealthyThreshold = existingRule.HealthCheckUnhealthyThreshold
	}
	if req.HealthCheckHealthyThreshold == 0 {
		req.HealthCheckHealthyThreshold = existingRule.HealthCheckHealthyThreshold
	}
	if req.TCPHealthCheckPort == 0 {
		req.TCPHealthCheckPort = existingRule.TCPHealthCheckPort
	}
	if req.TCPTryDuration == 0 {
		req.TCPTryDuration = existingRule.TCPTryDuration
	}
	if req.TCPTryInterval == 0 {
		req.TCPTryInterval = existingRule.TCPTryInterval
	}
	if req.RequestBodyMaxSizeMB == nil {
		req.RequestBodyMaxSizeMB = &existingRule.RequestBodyMaxSizeMB
	}
	if req.UpstreamKeepaliveTimeout == nil {
		req.UpstreamKeepaliveTimeout = &existingRule.UpstreamKeepaliveTimeout
	}
	if req.ServerTokensHidden == nil {
		req.ServerTokensHidden = &existingRule.ServerTokensHidden
	}
	if req.DynamicDNS == nil {
		req.DynamicDNS = &existingRule.DynamicDNS
	}
	if req.EnableDnsServer == nil {
		req.EnableDnsServer = &existingRule.EnableDnsServer
	}
	if req.EnableActiveHealthCheck == nil {
		req.EnableActiveHealthCheck = &existingRule.EnableActiveHealthCheck
	}
	if req.TCPProxyProtocol == nil {
		req.TCPProxyProtocol = &existingRule.TCPProxyProtocol
	}
	if req.EnableTLS == nil {
		req.EnableTLS = &existingRule.EnableTLS
	}
	if req.TLSHTTPRedirect == nil {
		req.TLSHTTPRedirect = &existingRule.TLSHTTPRedirect
	}
	if req.EnableCompress == nil {
		req.EnableCompress = &existingRule.EnableCompress
	}
	if req.Enabled == nil {
		req.Enabled = &existingRule.Enabled
	}
	if req.LogEnabled == nil {
		req.LogEnabled = &existingRule.LogEnabled
	}
	if req.CompressTypes == "" {
		req.CompressTypes = existingRule.CompressTypes
	}
	if req.DnsServer == "" {
		req.DnsServer = existingRule.DnsServer
	}
	if req.DnsFamily == "" {
		req.DnsFamily = existingRule.DnsFamily
	}
	if req.HostHeader == "" {
		req.HostHeader = existingRule.HostHeader
	}
	if req.Name == "" {
		req.Name = existingRule.Name
	}
	if req.Description == "" {
		req.Description = existingRule.Description
	}

	protocolChanged := requestedProtocol != "" && requestedProtocol != existingRule.Protocol

	if protocolChanged {
		zero, disabled := 0, false
		switch req.Protocol {
		case "tcp":
			if req.Strategy == "cookie" {
				req.Strategy = "weighted_round_robin"
			}
			req.Domain = ""
			req.EnableTLS = &disabled
			req.TLSSource = "manual"
			req.ACMEConfigID = 0
			req.CAProviderID = &zero
			req.TLSCert = ""
			req.TLSKey = ""
			req.TLSHTTPRedirect = &disabled
			req.HealthCheckPath = ""
			req.RequestBodyMaxSizeMB = &zero
			req.UpstreamKeepaliveTimeout = &zero
			req.ServerTokensHidden = &zero
			req.CustomRoutesEnabled = &disabled
			emptyPathRules := []models.PathRule{}
			req.PathRules = &emptyPathRules
			req.ProxyDialTimeout = &zero
			req.ProxyResponseHeaderTimeout = &zero
			req.ProxyReadTimeout = &zero
			req.ProxyWriteTimeout = &zero
			req.ProxyStreamTimeout = &zero
			req.ProxyFlushInterval = &zero
			req.ProxyStreamCloseDelay = &zero
			req.HostHeader = ""
			req.EnableCompress = &disabled
			req.CompressTypes = ""
		case "http":
			req.TCPHealthCheckPort = 0
			req.TCPProxyProtocol = &disabled
			req.TCPTryDuration = 0
			req.TCPTryInterval = 0
		}
	}

	if req.Protocol == "http" && strings.TrimSpace(req.Domain) == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "HTTP/HTTPS 规则的域名不能为空"})
		return
	}
	if req.Protocol == "http" && req.Domain != "" {
		canonicalDomain, err := db.CanonicalDomains(req.Domain)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "域名格式无效"})
			return
		}
		req.Domain = canonicalDomain
		if req.EnableTLS != nil && *req.EnableTLS && req.TLSSource == "acme_dns" {
			if err := services.ValidateACMEDomains(req.Domain); err != nil {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
				return
			}
		}
		// Round 30 F-5 / R38 C-2: existingRule.Domain 可能为导入态非规范化值
		//（"Example.COM"），与规范化后的 req.Domain 比较会误判变更，比较前先做同样规范化。
		existingDomain := existingRule.Domain
		if existingDomain != "" {
			if canonical, err := db.CanonicalDomains(existingDomain); err == nil {
				existingDomain = canonical
			}
		}
		// R38 C-2: 域名冲突检查同样加变更门控——仅当域名/监听端口/启用态相对存量
		// 变化时才执行（ruleDomainConflict 只统计 enabled=1 的规则）。导入遗留的
		// 「一启用一禁用同域名」组合中，禁用方仅改名等无关更新不再被 400 卡死；
		// 启用态变化仍走检查（启用时二次把关，与 enabledRuleDomainConflict 口径一致）。
		// R40 F-1: 启用态门控收敛为仅启用方向（*req.Enabled && !existingRule.Enabled）——
		// 禁用方向不渲染、无冲突可言，存量冲突组合（同域名同端口双启用）的禁用操作
		// 不应被 400 误拦（DisableRule 端点本就不查，口径对齐）。
		if req.Domain != existingDomain || req.ListenPort != existingRule.ListenPort || (*req.Enabled && !existingRule.Enabled) {
			existing, err := ruleDomainConflict(req.Domain, req.ListenPort, caddyID)
			if err != nil {
				log.Printf("UpdateRule domain conflict query failed for caddy_id=%s domain=%s: %v", caddyID, req.Domain, err)
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "检查域名冲突失败"})
				return
			}
			if existing {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "域名已被其他 HTTP/HTTPS 规则使用"})
				return
			}
		}
		// Round 29 G-5: 仅当域名/监听端口/EnableTLS/TLSHTTPRedirect/Enabled 任一相对存量变化时
		// 执行遮蔽检查（fallback 已把 req 字段填成现值，直接与 existingRule 比较）——
		// 存量冲突组合（导入态 80 规则 + 跳转规则并存）下仅改名称/健康检查不应被 400 阻塞。
		// R39 C-2: Enabled 变化也触发——与 EnableRule 端点同口径，禁用规则经 UpdateRule
		// 启用时同样拦截会遮蔽 80 直听规则的跳转组合（shadowRelevantChanged 不含 enabled
		// 时仅提交 {"enabled":true} 会绕过遮蔽检查）。
		// R40 F-1: 启用态门控收敛为仅启用方向——禁用方不渲染，遮蔽检查无意义；
		// 存量冲突组合（80 直听启用 + 443 TLS+跳转启用同域名）的禁用操作不应被 400 误拦。
		// R41 C-2: 门控再加启用状态前置——仅当「新状态启用 或 原状态启用」时才可能产生
		// 运行时影响。禁用中规则（双方均 disabled）不会被渲染，此时改 TLS/跳转/端口/域名
		// 仍被 400 拦截会阻塞「先改好禁用方配置再启用」的正常流程（启用方向仍会二次把关）。
		// R42 F5: 注意放宽的仅是下方遮蔽检查；上方同域名+同端口冲突门控对禁用规则
		// 仍然 400——该组合永远无法启用（EnableRule 端点同样拦截），编辑期拦截只是
		// 提前报错，属有意保守，勿误读为「禁用规则可随意改域名」。
		shadowRelevantChanged := req.Domain != existingDomain ||
			req.ListenPort != existingRule.ListenPort ||
			*req.EnableTLS != existingRule.EnableTLS ||
			*req.TLSHTTPRedirect != existingRule.TLSHTTPRedirect ||
			(*req.Enabled && !existingRule.Enabled)
		if shadowRelevantChanged && (*req.Enabled || existingRule.Enabled) {
			shadowRule, shadowDomain, err := queryRedirectShadowConflict(req.Domain, req.ListenPort, *req.EnableTLS, *req.TLSHTTPRedirect, caddyID)
			if err != nil {
				log.Printf("UpdateRule redirect shadow query failed for caddy_id=%s domain=%s: %v", caddyID, req.Domain, err)
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "检查域名冲突失败"})
				return
			}
			if shadowRule != "" {
				if req.ListenPort == 80 {
					c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("域名 %s 已被规则 %s 的 HTTPS 跳转占用（跳转在 80 端口优先生效，保存后本规则将不可达）", shadowDomain, shadowRule)})
				} else {
					c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("域名 %s 已有规则 %s 直接监听 80 端口，开启 HTTP 转 HTTPS 跳转会使其不可达，请先调整该规则", shadowDomain, shadowRule)})
				}
				return
			}
		}
	}

	// Load existing upstreams if not provided in request
	if len(req.Upstreams) == 0 {
		req.Upstreams = oldUpstreams
	}
	if protocolChanged {
		for index := range req.Upstreams {
			switch req.Protocol {
			case "tcp":
				switch req.Upstreams[index].Protocol {
				case "", "http":
					req.Upstreams[index].Protocol = "tcp"
				case "https":
					req.Upstreams[index].Protocol = "tls"
				}
			case "http":
				switch req.Upstreams[index].Protocol {
				case "", "tcp":
					req.Upstreams[index].Protocol = "http"
				case "tls":
					req.Upstreams[index].Protocol = "https"
				}
			}
		}
	}

	if req.RequestBodyMaxSizeMB != nil && *req.RequestBodyMaxSizeMB < 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求体大小限制不能为负数"})
		return
	}
	if req.UpstreamKeepaliveTimeout != nil && *req.UpstreamKeepaliveTimeout < 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "上游 keepalive 超时不能为负数"})
		return
	}
	if req.ServerTokensHidden != nil && (*req.ServerTokensHidden < 0 || *req.ServerTokensHidden > 2) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "server_tokens_hidden 必须为 0、1 或 2"})
		return
	}
	features := updateRuleFeatures(req, existingRule)
	features.Protocol = req.Protocol
	if err := validateRuleFeatures(features); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	validationServerName := fmt.Sprintf("%s_%d", req.Protocol, req.ListenPort)

	// Validate TLS certificate if provided (manual source only)
	if *req.EnableTLS && req.TLSSource != "manual" && req.TLSSource != "acme_dns" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "启用 TLS 时必须选择证书来源（manual 或 acme_dns）"})
		return
	}
	if (*req.EnableTLS || req.TLSCert != "" || req.TLSKey != "") && req.TLSSource == "manual" {
		tlsCert := req.TLSCert
		tlsKey := req.TLSKey
		// If cert/key not provided in request, get from DB
		if tlsCert == "" {
			tlsCert = existingRule.TLSCert
		}
		if tlsKey == "" {
			tlsKey = existingRule.TLSKey
		}
		if *req.EnableTLS && (strings.TrimSpace(tlsCert) == "" || strings.TrimSpace(tlsKey) == "") {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "手动证书模式下必须提供 TLS 证书和私钥"})
			return
		}
		if tlsCert != "" && tlsKey != "" {
			if err := validateTLSCertificate(tlsCert, tlsKey); err != nil {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "TLS 证书校验失败: " + err.Error()})
				return
			}
		}
	}

	// Validate Caddy config BEFORE writing to database
	if err := h.validateCaddyConfigBeforeSave(req, features, fmt.Sprintf("update_%s_%s", caddyID, generateRandomString(8)), validationServerName); err != nil {
		log.Printf("UpdateRule validation failed for caddy_id=%s, server_name=%s: %v", caddyID, validationServerName, err)
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	// Build dynamic update for lb_rules table
	query := "UPDATE lb_rules SET "
	var args []interface{}

	query += "name = ?, "
	args = append(args, req.Name)
	query += "description = ?, "
	args = append(args, req.Description)
	query += "protocol = ?, "
	args = append(args, req.Protocol)
	query += "domain = ?, "
	args = append(args, req.Domain)
	query += "listen_port = ?, "
	args = append(args, req.ListenPort)
	if err := validateRuleListenPort(req.Protocol, req.ListenPort); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if err := h.validatePortFromDB(req.Protocol, req.ListenPort, caddyID); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	query += "strategy = ?, "
	args = append(args, req.Strategy)
	query += "dynamic_dns = ?, "
	args = append(args, *req.DynamicDNS)
	query += "enable_dns_server = ?, "
	args = append(args, *req.EnableDnsServer)
	query += "dns_server = ?, "
	args = append(args, req.DnsServer)
	query += "dns_family = ?, "
	args = append(args, req.DnsFamily)
	query += "health_check_path = ?, "
	args = append(args, req.HealthCheckPath)
	query += "health_check_interval = ?, "
	args = append(args, req.HealthCheckInterval)
	query += "health_check_timeout = ?, "
	args = append(args, req.HealthCheckTimeout)
	query += "health_check_unhealthy_threshold = ?, "
	args = append(args, req.HealthCheckUnhealthyThreshold)
	query += "health_check_healthy_threshold = ?, "
	args = append(args, req.HealthCheckHealthyThreshold)
	query += "enable_active_health_check = ?, "
	args = append(args, *req.EnableActiveHealthCheck)
	query += "tcp_health_check_port = ?, "
	args = append(args, req.TCPHealthCheckPort)
	query += "tcp_proxy_protocol = ?, "
	args = append(args, *req.TCPProxyProtocol)
	query += "tcp_try_duration = ?, "
	args = append(args, req.TCPTryDuration)
	query += "tcp_try_interval = ?, "
	args = append(args, req.TCPTryInterval)
	query += "request_body_max_size_mb = ?, "
	args = append(args, *req.RequestBodyMaxSizeMB)
	query += "upstream_keepalive_timeout = ?, "
	args = append(args, *req.UpstreamKeepaliveTimeout)
	query += "server_tokens_hidden = ?, "
	args = append(args, *req.ServerTokensHidden)
	query += "custom_routes_enabled = ?, "
	args = append(args, features.CustomRoutesEnabled)
	query += "proxy_dial_timeout = ?, "
	args = append(args, features.ProxyDialTimeout)
	query += "proxy_response_header_timeout = ?, "
	args = append(args, features.ProxyResponseHeaderTimeout)
	query += "proxy_read_timeout = ?, "
	args = append(args, features.ProxyReadTimeout)
	query += "proxy_write_timeout = ?, "
	args = append(args, features.ProxyWriteTimeout)
	query += "proxy_stream_timeout = ?, "
	args = append(args, features.ProxyStreamTimeout)
	query += "proxy_flush_interval = ?, "
	args = append(args, features.ProxyFlushInterval)
	query += "proxy_stream_close_delay = ?, "
	args = append(args, features.ProxyStreamCloseDelay)
	query += "host_header = ?, "
	args = append(args, req.HostHeader)
	query += "enable_tls = ?, "
	args = append(args, *req.EnableTLS)
	query += "tls_source = ?, "
	args = append(args, req.TLSSource)
	query += "acme_config_id = ?, "
	args = append(args, req.ACMEConfigID)
	if req.CAProviderID != nil {
		query += "ca_provider_id = ?, "
		args = append(args, *req.CAProviderID)
	}
	if req.TLSCert != "" || protocolChanged {
		query += "tls_cert = ?, "
		args = append(args, req.TLSCert)
	}
	if req.TLSKey != "" || protocolChanged {
		query += "tls_key = ?, "
		args = append(args, req.TLSKey)
	}
	query += "tls_http_redirect = ?, "
	args = append(args, *req.TLSHTTPRedirect)
	query += "enable_compress = ?, "
	args = append(args, *req.EnableCompress)
	query += "compress_types = ?, "
	args = append(args, req.CompressTypes)
	query += "enabled = ?, "
	args = append(args, *req.Enabled)
	query += "log_enabled = ?, "
	args = append(args, *req.LogEnabled)

	// Build full rule config for route generation
	domain := req.Domain
	listenPort := req.ListenPort
	strategy := req.Strategy
	if strategy == "" {
		strategy = "weighted_round_robin"
	}

	var global struct {
		requestBodyMaxSizeMB, upstreamKeepaliveTimeout                                                                                                   int
		proxyDialTimeout, proxyResponseHeaderTimeout, proxyReadTimeout, proxyWriteTimeout, proxyStreamTimeout, proxyFlushInterval, proxyStreamCloseDelay int
		serverTokensHidden                                                                                                                               bool
	}
	if err := db.DB.QueryRow(`
		SELECT COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0),
			COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0), COALESCE(proxy_flush_interval,0), COALESCE(proxy_stream_close_delay,0),
			COALESCE(server_tokens_hidden,FALSE)
		FROM global_config WHERE id = 1
	`).Scan(
		&global.requestBodyMaxSizeMB, &global.upstreamKeepaliveTimeout,
		&global.proxyDialTimeout, &global.proxyResponseHeaderTimeout, &global.proxyReadTimeout, &global.proxyWriteTimeout, &global.proxyStreamTimeout, &global.proxyFlushInterval, &global.proxyStreamCloseDelay,
		&global.serverTokensHidden); err != nil {
		log.Printf("UpdateRule failed to load global config for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取全局配置失败"})
		return
	}

	ruleConfig := services.SingleRuleConfig{
		Protocol:                         req.Protocol,
		Domain:                           domain,
		ListenPort:                       listenPort,
		Strategy:                         strategy,
		DynamicDNS:                       *req.DynamicDNS,
		EnableDnsServer:                  *req.EnableDnsServer,
		DnsServer:                        req.DnsServer,
		DnsFamily:                        req.DnsFamily,
		HealthCheckPath:                  req.HealthCheckPath,
		HealthCheckInterval:              req.HealthCheckInterval,
		HealthCheckTimeout:               req.HealthCheckTimeout,
		HealthCheckUnhealthyThreshold:    req.HealthCheckUnhealthyThreshold,
		EnableActiveHealthCheck:          *req.EnableActiveHealthCheck,
		TCPHealthCheckPort:               req.TCPHealthCheckPort,
		TCPProxyProtocol:                 *req.TCPProxyProtocol,
		TCPTryDuration:                   req.TCPTryDuration,
		TCPTryInterval:                   req.TCPTryInterval,
		RequestBodyMaxSizeMB:             *req.RequestBodyMaxSizeMB,
		UpstreamKeepaliveTimeout:         *req.UpstreamKeepaliveTimeout,
		ServerTokensHidden:               *req.ServerTokensHidden,
		GlobalRequestBodyMaxSizeMB:       global.requestBodyMaxSizeMB,
		GlobalUpstreamKeepaliveTimeout:   global.upstreamKeepaliveTimeout,
		GlobalServerTokensHidden:         global.serverTokensHidden,
		CustomRoutesEnabled:              features.CustomRoutesEnabled,
		PathRules:                        toPathRuleConfigs(features.PathRules),
		ProxyDialTimeout:                 features.ProxyDialTimeout,
		ProxyResponseHeaderTimeout:       features.ProxyResponseHeaderTimeout,
		ProxyReadTimeout:                 features.ProxyReadTimeout,
		ProxyWriteTimeout:                features.ProxyWriteTimeout,
		ProxyStreamTimeout:               features.ProxyStreamTimeout,
		ProxyFlushInterval:               features.ProxyFlushInterval,
		ProxyStreamCloseDelay:            features.ProxyStreamCloseDelay,
		GlobalProxyDialTimeout:           global.proxyDialTimeout,
		GlobalProxyResponseHeaderTimeout: global.proxyResponseHeaderTimeout,
		GlobalProxyReadTimeout:           global.proxyReadTimeout,
		GlobalProxyWriteTimeout:          global.proxyWriteTimeout,
		GlobalProxyStreamTimeout:         global.proxyStreamTimeout,
		GlobalProxyFlushInterval:         global.proxyFlushInterval,
		GlobalProxyStreamCloseDelay:      global.proxyStreamCloseDelay,
		EnableTLS:                        *req.EnableTLS,
		TLSSource:                        req.TLSSource,
		ACMEConfigID:                     req.ACMEConfigID,
		TLSHTTPRedirect:                  *req.TLSHTTPRedirect,
		EnableCompress:                   *req.EnableCompress,
		CompressTypes:                    req.CompressTypes,
		HostHeader:                       req.HostHeader,
		CaddyID:                          caddyID,
	}

	for _, u := range req.Upstreams {
		protocol := u.Protocol
		if protocol == "" {
			if req.Protocol == "tcp" {
				protocol = "tcp"
			} else {
				protocol = "http"
			}
		}
		weight := u.Weight
		if weight == 0 {
			weight = 1
		}
		ruleConfig.Upstreams = append(ruleConfig.Upstreams, services.UpstreamConfig{
			Host: u.Host, Port: u.Port, Weight: weight, Protocol: protocol, Enabled: u.Enabled,
			MaxConnections: u.MaxConnections,
		})
	}

	runtimeSnapshot, err := h.snapshotImportRuntime([]string{caddyID})
	if err != nil {
		log.Printf("UpdateRule runtime snapshot failed for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份当前运行配置失败"})
		return
	}

	// Caddy 应用失败时需要用这些快照把已提交的 DB 更新恢复回去
	oldRuleRow, oldRuleRowErr := dumpRowByKey(c.Request.Context(), "lb_rules", "caddy_id", caddyID)
	if oldRuleRowErr != nil {
		log.Printf("UpdateRule failed to snapshot lb_rules row for caddy_id=%s: %v", caddyID, oldRuleRowErr)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份规则数据失败"})
		return
	}
	oldUpstreamRowsMap, oldUpstreamRowsErr := dumpRowsByKey(c.Request.Context(), "upstreams", "rule_id", caddyID)
	if oldUpstreamRowsErr != nil {
		log.Printf("UpdateRule failed to snapshot upstreams for caddy_id=%s: %v", caddyID, oldUpstreamRowsErr)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份上游数据失败"})
		return
	}
	restoreRuleDBSnapshot := func() error {
		restoreCtx, cancelRestore := compensationContext(c.Request.Context())
		defer cancelRestore()
		if err := restoreRuleSnapshot(restoreCtx, caddyID, oldRuleRow, oldUpstreamRowsMap, existingRule.PathRules); err != nil {
			services.Logf("error", "CRITICAL: UpdateRule DB restore failed for caddy_id=%s: %v", caddyID, err)
			return err
		}
		return nil
	}

	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败: " + err.Error()})
		return
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				log.Printf("UpdateRule transaction rollback failed for caddy_id=%s: %v", caddyID, rollbackErr)
			}
		}
	}()

	userIDInt := contextUserID(c)
	query += "updated_at = datetime('now'), updated_by = ? WHERE caddy_id = ? AND NOT EXISTS (SELECT 1 FROM cert_jobs WHERE rule_id = ? AND status NOT IN ('issued','failed','disabled'))"
	args = append(args, userIDInt, caddyID, caddyID)

	res, err := tx.Exec(query, args...)
	if err != nil {
		tx.Rollback()
		log.Printf("UpdateRule database error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "写入数据库失败（更新规则）: " + err.Error()})
		return
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		tx.Rollback()
		log.Printf("UpdateRule RowsAffected error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "写入数据库失败（确认规则更新结果）: " + err.Error()})
		return
	}
	services.Logf("debug", "UpdateRule executed for caddy_id=%s: rows_affected=%d ca_provider_id_included=%v", caddyID, rowsAffected, req.CAProviderID != nil)
	if rowsAffected == 0 {
		tx.Rollback()
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "证书申请中，请等待完成或失败后再修改规则"})
		return
	}
	if protocolChanged && req.Protocol == "tcp" {
		if _, err := tx.Exec("DELETE FROM cert_jobs WHERE rule_id = ?", caddyID); err != nil {
			log.Printf("UpdateRule certificate cleanup error for caddy_id=%s: %v", caddyID, err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "清理旧证书任务失败"})
			return
		}
	}

	if _, err := tx.Exec("DELETE FROM upstreams WHERE rule_id = ?", caddyID); err != nil {
		tx.Rollback()
		log.Printf("UpdateRule upstream delete error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "写入数据库失败（更新上游服务器）: " + err.Error()})
		return
	}
	for _, u := range req.Upstreams {
		if u.Weight == 0 {
			u.Weight = 1
		}
		if u.Protocol == "" {
			if req.Protocol == "tcp" {
				u.Protocol = "tcp"
			} else {
				u.Protocol = "http"
			}
		}
		if req.Protocol == "http" && u.Protocol == "tls" {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "HTTP 规则的上游协议不支持 tls，请使用 http 或 https"})
			return
		}
		if _, err := tx.Exec(`INSERT INTO upstreams (rule_id, host, port, weight, dynamic_dns, enabled, protocol, max_connections)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			caddyID, u.Host, u.Port, u.Weight, u.DynamicDNS, u.Enabled, u.Protocol, u.MaxConnections); err != nil {
			tx.Rollback()
			log.Printf("UpdateRule upstream insert error for caddy_id=%s: %v", caddyID, err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "写入数据库失败（更新上游服务器）: " + err.Error()})
			return
		}
	}
	if err := replacePathRulesTx(c.Request.Context(), tx, caddyID, features.PathRules); err != nil {
		tx.Rollback()
		log.Printf("UpdateRule path_rules replace error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "写入数据库失败（更新自定义路径规则）: " + err.Error()})
		return
	}
	if protocolChanged && req.Protocol == "tcp" {
		if err := services.RemoveCertFiles(caddyID); err != nil {
			restoreErr := services.RestoreCertFiles(runtimeSnapshot.certFiles)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "清理旧证书文件失败: " + errors.Join(err, restoreErr).Error()})
			return
		}
	}

	if err := h.caddyService.ApplyConfigFromTx(tx); err != nil {
		restoreErr := h.restoreImportRuntime(runtimeSnapshot)
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy 配置更新失败，数据库未写入: " + errors.Join(err, restoreErr).Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		restoreErr := h.restoreImportRuntime(runtimeSnapshot)
		log.Printf("UpdateRule transaction commit failed for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交规则更新失败: " + errors.Join(err, restoreErr).Error()})
		return
	}
	committed = true

	if *req.Enabled && *req.EnableTLS && req.TLSSource == "acme_dns" && req.Protocol == "http" && domain != "" {
		caProviderID := existingRule.CAProviderID
		if req.CAProviderID != nil {
			caProviderID = *req.CAProviderID
		}
		resolvedCAProviderID, resolveErr := services.ResolveCAProviderID(caProviderID)
		resolvedExistingCAProviderID, resolveExistingErr := services.ResolveCAProviderID(existingRule.CAProviderID)
		if resolveErr != nil || resolveExistingErr != nil {
			restoreErr := errors.Join(h.restoreImportRuntime(runtimeSnapshot), restoreRuleDBSnapshot())
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "解析 CA 提供商失败: " + errors.Join(resolveErr, resolveExistingErr, restoreErr).Error()})
			return
		}
		caProviderID = resolvedCAProviderID
		domainChanged := canonicalACMEDomainForJobLookup(domain) != canonicalACMEDomainForJobLookup(existingRule.Domain)
		// R48-1 不变量：补偿快照必须先于任何它可能需要撤销的变更。
		// 下面的域名迁移会就地抹除已签发任务的 PEM；快照若在其后执行，
		// restoreACMEState 恢复出的任务将永久丢失 PEM（TLS 静默中断且
		// 无自动恢复路径）。快照失败时迁移尚未执行，只需回滚规则与运行时。
		certJobsSnapshot, err := services.SnapshotCertJobsForRule(caddyID)
		if err != nil {
			restoreErr := errors.Join(h.restoreImportRuntime(runtimeSnapshot), restoreRuleDBSnapshot())
			if restoreErr != nil {
				services.Logf("error", "CRITICAL: UpdateRule cert job snapshot failed and restore failed for caddy_id=%s: snapshot=%v restore=%v", caddyID, err, restoreErr)
			}
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份证书任务失败: " + errors.Join(err, restoreErr).Error()})
			return
		}
		// When domain changes, update the existing cert job's domain instead of
		// creating a new job and disabling the old one. This preserves the job ID
		// and maintains the "one rule = one cert job" invariant.
		if domainChanged {
			newCanonical := canonicalACMEDomainForJobLookup(domain)
			// R50 S-5：迁移前取消在途旧域签发。否则 worker 可能在迁移把行改写为新域
			// 之后仍完成签发，confirmCertificateDeployment 见到 job.domain==rule.domain
			// （同为新域）便放行，把旧域证书部署到新域（瞬时 TLS 名称不匹配，重签后
			// 自愈）。CancelJob 等待在途执行退出（30s 上限）；被取消的 worker 走
			// handleExecutionCancellation 的静默分支（q.ctx 未取消、非执行超时），
			// 不写任务状态，requeueCanceledJob 不会复活迁移后置为 'failed' 的行。
			var inFlightJobID int
			if scanErr := db.DB.QueryRow(`SELECT id FROM cert_jobs WHERE rule_id=? ORDER BY id DESC LIMIT 1`, caddyID).Scan(&inFlightJobID); scanErr == nil && inFlightJobID > 0 {
				cancelCertJob(inFlightJobID)
			}
			certTx, txErr := db.DB.Begin()
			if txErr != nil {
				// R48-2：迁移事务开启失败不能静默吞掉——任务仍持旧域，后续会为
				// 新域另建任务，破坏「一规则一任务」。规则主更新已提交且用户请求
				// 本身有效，此时回滚规则是错误语义；记录错误并继续：新任务按
				// 既有 needJob 路径创建。
				// R49 C-#1：旧域残留任务不会被孤儿清扫收敛（sweepOrphanedCertJobs
				// 跳过终态，'issued'+PEM 行将永驻），须在此显式退役旧域任务。
				// 退役与迁移成功路径同为终态（disabled/failed 均使 sweep 不再触碰），
				// 但语义不同：成功路径把行改写为新域、抹除 PEM、置 'failed' 等待重签；
				// 此处域名未实际迁移，故保留 PEM 作历史、置 'disabled'——旧证留在
				// 旧域行上无副作用（部署/续期均按新域匹配，不读此行）。
				services.Logf("error", "UpdateRule: cert job domain migration begin failed for caddy_id=%s: %v", caddyID, txErr)
				oldCanonical := canonicalACMEDomainForJobLookup(existingRule.Domain)
				if retireErr := retireCertJobsForDomain(db.DB, caddyID, oldCanonical, reversedACMEDomainForm(oldCanonical)); retireErr != nil {
					services.Logf("error", "CRITICAL: UpdateRule: failed to retire old-domain cert job after migration begin failure for caddy_id=%s: %v", caddyID, retireErr)
					// R50-N3：退役失败即旧域任务保持原状（'issued'+PEM 行永驻，与
					// pre-R49 行为等效，fail-safe 但静默），补审计让运维可见。
					recordAudit(c, "写入失败", "证书任务", services.FormatAuditDetail(
						services.AuditRulePart(caddyID),
						fmt.Sprintf("域名迁移事务开启失败后旧域任务退役失败：%v。旧域任务保持原状，请人工检查", retireErr),
					))
				}
			} else {
				var existingJobID int
				queryErr := certTx.QueryRow(
					`SELECT id FROM cert_jobs WHERE rule_id=? ORDER BY id DESC LIMIT 1`,
					caddyID).Scan(&existingJobID)
				if queryErr == nil && existingJobID > 0 {
					if _, err := certTx.Exec(
						`UPDATE cert_jobs SET domain=?, status='failed', message='域名已更新，等待重新签发', cert_pem='', key_pem='', expires_at=NULL, renewal_attempts=0, ca_available_after=NULL, last_error_code=NULL, updated_at=datetime('now') WHERE id=?`,
						newCanonical, existingJobID); err != nil {
						services.Logf("error", "UpdateRule: failed to update cert job %d domain for caddy_id=%s: %v", existingJobID, caddyID, err)
					} else {
						log.Printf("UpdateRule: migrated cert job %d domain to %s for caddy_id=%s", existingJobID, newCanonical, caddyID)
					}
					if _, err := certTx.Exec(
						`DELETE FROM cert_jobs WHERE rule_id=? AND id!=?`,
						caddyID, existingJobID); err != nil {
						services.Logf("error", "UpdateRule: failed to clean up extra cert jobs for caddy_id=%s: %v", caddyID, err)
					}
				}
				if err := certTx.Commit(); err != nil {
					services.Logf("error", "UpdateRule: cert job domain migration commit failed for caddy_id=%s: %v", caddyID, err)
				}
			}
		}
		caProviderChanged := resolvedCAProviderID != resolvedExistingCAProviderID
		wasReEnabled := !existingRule.Enabled && *req.Enabled
		tlsSourceChangedToACME := existingRule.TLSSource != "acme_dns"
		var enqueuedJobID int
		var queueManager *services.CAQueueManager
		restoreACMEState := func() error {
			if enqueuedJobID > 0 && queueManager != nil {
				cancelCertJob(enqueuedJobID)
			}
			return errors.Join(h.restoreImportRuntime(runtimeSnapshot), restoreRuleDBSnapshot(), services.RestoreCertJobsForRule(certJobsSnapshot))
		}
		var jobID, jobProviderID int
		var jobStatus string
		var jobExpiresAt sql.NullTime
		jobErr := db.DB.QueryRow("SELECT id,status,expires_at,COALESCE(ca_provider_id,0) FROM cert_jobs WHERE rule_id=? AND domain=? ORDER BY id DESC LIMIT 1", caddyID, canonicalACMEDomainForJobLookup(domain)).Scan(&jobID, &jobStatus, &jobExpiresAt, &jobProviderID)
		if jobErr != nil && !errors.Is(jobErr, sql.ErrNoRows) {
			restoreErr := restoreACMEState()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取证书任务失败: " + errors.Join(jobErr, restoreErr).Error()})
			return
		}
		if jobErr == nil {
			resolvedJobProviderID, resolveJobErr := services.ResolveCAProviderID(jobProviderID)
			if resolveJobErr != nil {
				restoreErr := restoreACMEState()
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "解析证书任务 CA 提供商失败: " + errors.Join(resolveJobErr, restoreErr).Error()})
				return
			}
			caProviderChanged = caProviderChanged || resolvedJobProviderID != caProviderID
		}
		resumedValidJob := false
		if wasReEnabled && jobErr == nil {
			var renewalDays int
			if err := db.DB.QueryRow("SELECT COALESCE(cert_renewal_days,30) FROM global_config WHERE id=1").Scan(&renewalDays); err != nil {
				restoreErr := restoreACMEState()
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取证书续签配置失败: " + errors.Join(err, restoreErr).Error()})
				return
			}
			var expiryPtr *time.Time
			if jobExpiresAt.Valid {
				expiry := jobExpiresAt.Time
				expiryPtr = &expiry
			}
			if !domainChanged && !caProviderChanged && ResolveEnableCertJobAction(true, jobStatus, expiryPtr, time.Now(), renewalDays) == EnableCertJobResume {
				if _, err := db.DB.Exec("UPDATE cert_jobs SET status='issued',message='证书有效，已恢复使用',renewal_attempts=0,ca_available_after=NULL,last_error_code=NULL,updated_at=datetime('now') WHERE id=?", jobID); err != nil {
					restoreErr := restoreACMEState()
					c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "恢复证书任务失败: " + errors.Join(err, restoreErr).Error()})
					return
				}
				resumedValidJob = true
			}
		}
		needJob := domainChanged || caProviderChanged || !services.IsACMECertIssued(caddyID, domain) ||
			((wasReEnabled || tlsSourceChangedToACME) && !services.HasCertJob(caddyID, domain))
		needJob = needJob && !resumedValidJob
		if needJob {
			queueManager = services.GetCAQueueManager()
			if queueManager == nil {
				restoreErr := restoreACMEState()
				if restoreErr != nil {
					services.Logf("error", "CRITICAL: UpdateRule ACME enqueue failed and restore failed for caddy_id=%s: restore=%v", caddyID, restoreErr)
					c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("CA 队列未初始化且恢复失败: %v", restoreErr)})
					return
				}
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "CA 队列未初始化"})
				return
			}
			log.Printf("UpdateRule enqueueing cert job for caddy_id=%s domain=%s ca_provider_id=%d", caddyID, domain, caProviderID)
			jobID, err := createOrRequeueCertJob(caddyID, domain, caProviderID, queueManager)
			enqueuedJobID = jobID
			if err != nil {
				restoreErr := restoreACMEState()
				if restoreErr != nil {
					services.Logf("error", "CRITICAL: UpdateRule ACME enqueue failed and restore failed for caddy_id=%s: enqueue=%v restore=%v", caddyID, err, restoreErr)
					c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("创建证书任务失败且恢复失败: %v; %v", err, restoreErr)})
					return
				}
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "创建证书任务失败: " + err.Error()})
				return
			}
		}
	}

	log.Printf("Rule %s updated", caddyID)
	tlsPart := ""
	if req.Protocol == "http" {
		tlsPart = fmt.Sprintf("TLS：%s", boolText(*req.EnableTLS))
	}
	auditParts := []string{services.AuditRulePart(caddyID), req.Name, fmt.Sprintf("协议：%s", req.Protocol), domain, tlsPart}
	recordAudit(c, "更新", "负载规则", services.FormatAuditDetail(auditParts...))
	recordAudit(c, "重载", "Caddy服务", services.FormatAuditDetail(services.AuditSourcePart("rule_update"), services.AuditRulePart(caddyID), services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已更新"})
}

func (h *Handlers) DeleteRule(c *gin.Context) {

	caddyID := c.Param("caddy_id")

	// 与 UpdateRule 同一锁序：先 caddyOpMu 后 DB 事务，避免 AB-BA 循环等待
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	var protocol string
	var listenPort int
	var domain string
	err := db.DB.QueryRow("SELECT COALESCE(caddy_id,''), COALESCE(protocol,''), listen_port, COALESCE(domain,'') FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&caddyID, &protocol, &listenPort, &domain)
	if dbQueryNotFound(c, err, "规则不存在", "DeleteRule query rule") {
		return
	}
	certJobsSnapshot, err := services.SnapshotCertJobsForRule(caddyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份证书任务失败: " + err.Error()})
		return
	}
	queueManager := services.GetCAQueueManager()
	jobsCanceled := false
	deleteCompleted := false
	compensationStarted := false
	var blockToken services.RuleBlockToken
	if queueManager != nil {
		// No DB transaction is held while waiting, so worker rollback/reload paths can exit.
		blockToken = queueManager.BlockJobsForRule(caddyID)
		// R51 发现1：租约释放收口到登记于 drain 之前的唯一 defer——drain 前/中
		// panic（gin Recovery 只恢复 HTTP 栈、不清理 blockedRules）也能走到这里。
		// 补偿一旦启动成功即接管租约（完成时自行释放），abort 路径不得提前释放，
		// 否则补偿的 enqueueCompensation 见租约缺失而永久退避（R50 注释描述的
		// panic 窗口由此真正闭合）。UnblockJobsForRule 幂等：token 未注册均为无操作。
		defer func() {
			if compensationStarted || deleteCompleted {
				return
			}
			if !jobsCanceled {
				queueManager.UnblockJobsForRule(caddyID, blockToken)
				return
			}
			if err := queueManager.StartRuleDeletionCompensation(services.RuleDeletionCompensation{
				RuleID: caddyID, Token: blockToken, Snapshot: certJobsSnapshot,
			}); err != nil {
				services.Logf("error", "CRITICAL: DeleteRule failed to start certificate rollback compensation for caddy_id=%s: %v", caddyID, err)
				// R49 A-N1：同上——补偿未能接管租约时立即释放，不留孤儿屏障。
				queueManager.UnblockJobsForRule(caddyID, blockToken)
				return
			}
			compensationStarted = true
		}()
		drainRuleJobs := cancelRuleJobs
		cancelCtx, cancel := context.WithTimeout(c.Request.Context(), cancelRuleJobsTimeout)
		cancelErr := drainRuleJobs(cancelCtx, queueManager, caddyID)
		cancel()
		if cancelErr != nil {
			if err := queueManager.StartRuleDeletionCompensation(services.RuleDeletionCompensation{
				RuleID: caddyID, Token: blockToken, Snapshot: certJobsSnapshot,
				Drain: func(ctx context.Context) error { return drainRuleJobs(ctx, queueManager, caddyID) },
			}); err != nil {
				services.Logf("error", "CRITICAL: DeleteRule failed to start certificate compensation for caddy_id=%s: %v", caddyID, err)
				// R49 A-N1：补偿启动失败即无人持有该 token（典型为降级竞态：Stop 清空
				// blockedRules 后 block 才创建），必须当场释放租约，否则节点重新提升后
				// 该规则证书任务被屏障永久拦截、静默停发直到下一次 Stop。对运行中的
				// manager 同样幂等安全。
				queueManager.UnblockJobsForRule(caddyID, blockToken)
			} else {
				compensationStarted = true
			}
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "取消证书任务超时，规则与证书保持不变: " + cancelErr.Error()})
			return
		}
		jobsCanceled = true
	}

	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && rollbackErr != sql.ErrTxDone {
				log.Printf("DeleteRule transaction rollback failed for caddy_id=%s: %v", caddyID, rollbackErr)
			}
		}
	}()

	if _, err := tx.Exec("DELETE FROM cert_jobs WHERE rule_id = ?", caddyID); err != nil {
		log.Printf("DeleteRule cert_jobs delete error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除证书任务失败"})
		return
	}
	// 删除规则时一并清理安全策略绑定，避免遗留孤儿绑定导致该规则 caddy_id
	// 被新规则复用时错误继承旧策略（M1）。
	if _, err := tx.Exec("DELETE FROM security_policy_bindings WHERE rule_caddy_id = ?", caddyID); err != nil {
		log.Printf("DeleteRule security_policy_bindings delete error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除安全策略绑定失败"})
		return
	}
	if _, err := tx.Exec("DELETE FROM upstreams WHERE rule_id = ?", caddyID); err != nil {
		log.Printf("DeleteRule upstreams delete error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除上游服务器失败"})
		return
	}
	if _, err := tx.Exec("DELETE FROM lb_rules WHERE caddy_id = ?", caddyID); err != nil {
		log.Printf("DeleteRule lb_rules delete error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除规则失败"})
		return
	}

	runtimeSnapshot, err := h.snapshotImportRuntime([]string{caddyID})
	if err != nil {
		log.Printf("DeleteRule runtime snapshot failed for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份当前运行配置失败"})
		return
	}
	if err := h.caddyService.ApplyConfigFromTx(tx); err != nil {
		restoreErr := h.restoreImportRuntime(runtimeSnapshot)
		if restoreErr != nil {
			services.Logf("error", "CRITICAL: DeleteRule Caddy apply and runtime restore failed for caddy_id=%s: apply=%v restore=%v", caddyID, err, restoreErr)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("Caddy 配置应用与恢复均失败: %v; %v", err, restoreErr)})
			return
		}
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy 配置应用失败，规则未删除: " + err.Error()})
		return
	}
	if err := h.removeRuleCertFiles(caddyID); err != nil {
		certPath, keyPath := services.CertFilePaths(caddyID)
		restoreErr := h.restoreImportRuntime(runtimeSnapshot)
		// Round 36 BLOCKING-2: 证书文件可能被部分删除（cert 已删 / key 残留 或反之），
		// 即便 Caddy 配置和 DB 事务都恢复了，下次 reload 可能因找不到证书导致 TLS 静默失败。
		// 用户决策：保留现有顺序（先删文件再 commit），但加 CRITICAL 告警 + audit + 安全事件，
		// 让运维收到通知后人工恢复证书文件（从备份或其他节点同步）。
		services.Logf("error", "CRITICAL: DeleteRule 证书文件清理失败，可能存在 DB-文件状态不一致。caddy_id=%s cert_path=%s key_path=%s cleanup_error=%v restore_error=%v。请人工检查证书文件并在必要时从备份恢复",
			caddyID, certPath, keyPath, err, restoreErr)
		recordAudit(c, "清理失败", "证书文件", services.FormatAuditDetail(
			services.AuditRulePart(caddyID),
			fmt.Sprintf("残留路径：%s, %s。错误：%v。请人工检查证书文件，必要时从备份恢复", certPath, keyPath, err),
		))
		if restoreErr != nil {
			services.Logf("error", "CRITICAL: DeleteRule certificate cleanup and runtime restore failed for caddy_id=%s: cleanup=%v restore=%v", caddyID, err, restoreErr)
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "清理规则证书文件失败，删除已回滚。规则已恢复但证书文件可能不一致，请检查日志并人工恢复证书: " + errors.Join(err, restoreErr).Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		restoreErr := h.restoreImportRuntime(runtimeSnapshot)
		log.Printf("DeleteRule transaction commit failed for caddy_id=%s: %v", caddyID, err)
		if restoreErr != nil {
			services.Logf("error", "CRITICAL: DeleteRule commit and runtime restore failed for caddy_id=%s: commit=%v restore=%v", caddyID, err, restoreErr)
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交规则删除失败"})
		return
	}
	committed = true
	deleteCompleted = true
	if queueManager != nil {
		queueManager.UnblockJobsForRule(caddyID, blockToken)
	}

	if db.MetricsDB != nil {
		if _, err := db.MetricsDB.Exec("DELETE FROM metrics_history WHERE rule_id = ?", caddyID); err != nil {
			log.Printf("DeleteRule metrics_history delete error for caddy_id=%s: %v", caddyID, err)
		}
	}

	services.RemoveRuleLogFiles(caddyID)
	if err := services.RemoveCertJobLogFiles(caddyID); err != nil {
		log.Printf("DeleteRule cert-job log cleanup failed for caddy_id=%s: %v", caddyID, err)
		recordAudit(c, "清理失败", "证书日志", services.FormatAuditDetail(services.AuditRulePart(caddyID), fmt.Sprintf("路径：%s", services.CertJobLogPath(caddyID)), err.Error()))
	}

	recordAudit(c, "删除", "负载规则", services.FormatAuditDetail(services.AuditRulePart(caddyID), fmt.Sprintf("协议：%s", protocol), fmt.Sprintf("端口：%d", listenPort), domain))
	recordAudit(c, "重载", "Caddy服务", services.FormatAuditDetail(services.AuditSourcePart("rule_delete"), services.AuditRulePart(caddyID), services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已删除"})
}

func (h *Handlers) DuplicateRule(c *gin.Context) {
	caddyID := c.Param("caddy_id")
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	rows, err := db.DB.Query(`SELECT `+lbRuleColumns+` FROM lb_rules WHERE caddy_id = ?`, caddyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则失败"})
		return
	}
	rules, err := scanLbRules(rows)
	// Round 35 I-22: 同 ListRules。
	if closeErr := rows.Close(); closeErr != nil {
		log.Printf("DuplicateRule rows close error for caddy_id=%s: %v", caddyID, closeErr)
	}
	if err != nil {
		log.Printf("DuplicateRule scan error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则失败"})
		return
	}
	if len(rules) == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
		return
	}
	rule := rules[0]
	if rule.Protocol == "http" && rule.Domain != "" {
		rule.Domain, err = db.CanonicalDomains(rule.Domain)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "域名格式无效"})
			return
		}
	}

	userIDInt := contextUserID(c)

	newCaddyID, err := services.GenerateCaddyID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "生成规则 ID 失败"})
		return
	}

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启复制事务失败"})
		return
	}
	committed := false
	defer func() {
		if !committed {
			// Round 35 B5: 与 CreateRule/UpdateRule/DeleteRule 模式一致，回滚错误需记录。
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				log.Printf("DuplicateRule transaction rollback failed: %v", rollbackErr)
			}
		}
	}()

	// Round 38 B3: DuplicateRule 必须经过与 CreateRule 一致的校验。
	enabledUpstreamCount := 0
	for _, u := range rule.Upstreams {
		if u.Enabled {
			enabledUpstreamCount++
		}
	}
	if err := validateRuleFeatures(ruleFeatureInput{
		Protocol: rule.Protocol, Strategy: rule.Strategy, DynamicDNS: rule.DynamicDNS,
		EnabledUpstreamCount: enabledUpstreamCount,
		HealthCheckInterval:  rule.HealthCheckInterval, HealthCheckTimeout: rule.HealthCheckTimeout,
		EnableCompress: rule.EnableCompress, CompressTypes: rule.CompressTypes,
		CustomRoutesEnabled: rule.CustomRoutesEnabled, PathRules: rule.PathRules,
		ProxyDialTimeout: rule.ProxyDialTimeout, ProxyResponseHeaderTimeout: rule.ProxyResponseHeaderTimeout,
		ProxyReadTimeout: rule.ProxyReadTimeout, ProxyWriteTimeout: rule.ProxyWriteTimeout,
		ProxyStreamTimeout: rule.ProxyStreamTimeout, ProxyFlushInterval: rule.ProxyFlushInterval,
		ProxyStreamCloseDelay: rule.ProxyStreamCloseDelay,
	}); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "源规则配置不合法：" + err.Error()})
		return
	}

	// R53 发现5：副本原样继承 acme_config_id/ca_provider_id——源规则携带悬挂/
	// 已禁用引用时必须先 400 点名源规则，否则副本可经 EnableRule 投入运行
	// （R53 发现1 修复前）或持续携带坏引用（修复后 EnableRule 才会拦）。
	if err := validateRuleACMEReferences(acmeReferenceInput{
		EnableTLS: rule.EnableTLS, TLSSource: rule.TLSSource,
		ACMEConfigID: rule.ACMEConfigID, CAProviderID: rule.CAProviderID,
	}); err != nil {
		var validationErr *configValidationError
		if errors.As(err, &validationErr) {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("源规则 %s（%s）：%s", rule.Name, caddyID, validationErr.Error())})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "校验源规则 ACME 引用失败: " + err.Error()})
		return
	}

	if _, err := tx.Exec(`
		INSERT INTO lb_rules (name, description, protocol, domain, listen_port, strategy, dynamic_dns, enable_dns_server, dns_server, dns_family,
			health_check_path, health_check_interval, health_check_timeout,
			health_check_unhealthy_threshold, health_check_healthy_threshold,
			enable_active_health_check, tcp_health_check_port, tcp_proxy_protocol, tcp_try_duration, tcp_try_interval,
			request_body_max_size_mb, upstream_keepalive_timeout, server_tokens_hidden,
			enable_tls, tls_source, acme_config_id, ca_provider_id, tls_cert, tls_key,
	tls_http_redirect, enable_compress, compress_types, enabled, created_by, updated_by, created_at, updated_at, host_header, log_enabled, caddy_id,
		custom_routes_enabled,
		proxy_dial_timeout, proxy_response_header_timeout, proxy_read_timeout, proxy_write_timeout, proxy_stream_timeout, proxy_flush_interval, proxy_stream_close_delay)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, rule.Name+"（副本）", rule.Description, rule.Protocol, rule.Domain, rule.ListenPort, rule.Strategy,
		rule.DynamicDNS, rule.EnableDnsServer, rule.DnsServer, rule.DnsFamily, rule.HealthCheckPath, rule.HealthCheckInterval, rule.HealthCheckTimeout,
		rule.HealthCheckUnhealthyThreshold, rule.HealthCheckHealthyThreshold,
		rule.EnableActiveHealthCheck, rule.TCPHealthCheckPort, rule.TCPProxyProtocol, rule.TCPTryDuration, rule.TCPTryInterval,
		rule.RequestBodyMaxSizeMB, rule.UpstreamKeepaliveTimeout, rule.ServerTokensHidden,
		rule.EnableTLS, rule.TLSSource, rule.ACMEConfigID, rule.CAProviderID, rule.TLSCert, rule.TLSKey,
		rule.TLSHTTPRedirect, rule.EnableCompress, rule.CompressTypes, 0, userIDInt, userIDInt,
		now, now, rule.HostHeader, rule.LogEnabled, newCaddyID,
		rule.CustomRoutesEnabled,
		rule.ProxyDialTimeout, rule.ProxyResponseHeaderTimeout, rule.ProxyReadTimeout, rule.ProxyWriteTimeout, rule.ProxyStreamTimeout, rule.ProxyFlushInterval, rule.ProxyStreamCloseDelay,
	); err != nil {
		log.Printf("Failed to duplicate rule %s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "复制规则失败，已回滚: " + err.Error()})
		return
	}

	// Round 34 F-1: 同 UpdateRule——NULL enabled 行须 IIF 归一化（NULL 视同禁用），
	// 复制出的新行显式落 0，避免裸 scan 500 与复制后意外启用。
	upstreamRows, err := tx.Query(`
		SELECT host, port, weight, dynamic_dns, IIF(enabled IN ('1',1),1,0), COALESCE(protocol,'http'), COALESCE(max_connections,0)
		FROM upstreams WHERE rule_id = ?
	`, caddyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取上游失败，已回滚: " + err.Error()})
		return
	}
	for upstreamRows.Next() {
		var u struct {
			Host           string
			Port           int
			Weight         int
			DynamicDNS     bool
			Enabled        bool
			Protocol       string
			MaxConnections int
		}
		if err := upstreamRows.Scan(&u.Host, &u.Port, &u.Weight, &u.DynamicDNS, &u.Enabled, &u.Protocol, &u.MaxConnections); err != nil {
			upstreamRows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "扫描上游失败，已回滚: " + err.Error()})
			return
		}
		if _, err := tx.Exec(`
			INSERT INTO upstreams (rule_id, host, port, weight, dynamic_dns, enabled, protocol, max_connections)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`, newCaddyID, u.Host, u.Port, u.Weight, u.DynamicDNS, u.Enabled, u.Protocol, u.MaxConnections); err != nil {
			upstreamRows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "复制上游失败，已回滚: " + err.Error()})
			return
		}
	}
	if err := upstreamRows.Err(); err != nil {
		if closeErr := upstreamRows.Close(); closeErr != nil {
			log.Printf("DuplicateRule failed to close upstream cursor for caddy_id=%s: %v", caddyID, closeErr)
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "遍历上游失败，已回滚: " + err.Error()})
		return
	}
	if err := upstreamRows.Close(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "关闭上游游标失败，已回滚: " + err.Error()})
		return
	}

	if rule.CustomRoutesEnabled {
		if _, err := tx.Exec(`
			INSERT INTO path_rules (rule_id, sort_order, match_type, path, upstreams_json, created_at, updated_at)
			SELECT ?, sort_order, match_type, path, upstreams_json, datetime('now'), datetime('now') FROM path_rules WHERE rule_id = ?
		`, newCaddyID, caddyID); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "复制路径规则失败，已回滚: " + err.Error()})
			return
		}
	}

	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交复制事务失败: " + err.Error()})
		return
	}
	committed = true

	recordAudit(c, "复制", "负载规则", services.FormatAuditDetail(fmt.Sprintf("源规则：%s", caddyID), fmt.Sprintf("新规则：%s", newCaddyID), rule.Name))
	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Message: "副本已创建（已禁用）：域名与源规则相同，启用前请修改域名或端口", Data: gin.H{"caddy_id": newCaddyID}})
}

func (h *Handlers) EnableRule(c *gin.Context) {
	caddyID := c.Param("caddy_id")

	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	var originalEnabled, enableTLS, tlsHTTPRedirect bool
	var ruleProtocol, ruleDomain, tlsSource string
	var rulePort, caProviderID int
	err := db.DB.QueryRow(`SELECT IIF(enabled IN ('1',1),1,0), COALESCE(protocol,''), COALESCE(domain,''), listen_port,
		COALESCE(tls_source,''), COALESCE(enable_tls,0), COALESCE(tls_http_redirect,0), COALESCE(ca_provider_id,0)
		FROM lb_rules WHERE caddy_id = ?`, caddyID).Scan(&originalEnabled, &ruleProtocol, &ruleDomain, &rulePort, &tlsSource, &enableTLS, &tlsHTTPRedirect, &caProviderID)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则失败"})
		return
	}
	if ruleProtocol == "http" && ruleDomain != "" {
		ruleDomain, err = db.CanonicalDomains(ruleDomain)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "域名格式无效"})
			return
		}
	}
	if originalEnabled {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已启用"})
		return
	}
	if err := validateStoredRuleConfig(c.Request.Context(), caddyID); err != nil {
		var validationErr *configValidationError
		if errors.As(err, &validationErr) {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: validationErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "预校验规则配置失败: " + err.Error()})
		return
	}
	if err := validateRuleListenPort(ruleProtocol, rulePort); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "端口冲突，无法启用: " + err.Error()})
		return
	}
	if err := h.validatePortFromDB(ruleProtocol, rulePort, caddyID); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "端口冲突，无法启用: " + err.Error()})
		return
	}
	if ruleProtocol == "http" && ruleDomain != "" {
		conflict, err := enabledRuleDomainConflict(ruleDomain, rulePort, caddyID)
		if err != nil {
			log.Printf("EnableRule domain conflict query failed for caddy_id=%s domain=%s: %v", caddyID, ruleDomain, err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "检查域名冲突失败"})
			return
		}
		if conflict {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("域名 %s 已被其他启用中的规则使用，无法启用", ruleDomain)})
			return
		}
		shadowRule, shadowDomain, err := queryRedirectShadowConflict(ruleDomain, rulePort, enableTLS, tlsHTTPRedirect, caddyID)
		if err != nil {
			log.Printf("EnableRule redirect shadow query failed for caddy_id=%s domain=%s: %v", caddyID, ruleDomain, err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "检查域名冲突失败"})
			return
		}
		if shadowRule != "" {
			if rulePort == 80 {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("域名 %s 已被规则 %s 的 HTTPS 跳转占用（跳转在 80 端口优先生效，启用后本规则将不可达），无法启用", shadowDomain, shadowRule)})
			} else {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("域名 %s 已有规则 %s 直接监听 80 端口，启用 HTTP 转 HTTPS 跳转会使其不可达，请先调整该规则", shadowDomain, shadowRule)})
			}
			return
		}
	}
	isACME := enableTLS && tlsSource == "acme_dns" && ruleDomain != ""
	var certJobsSnapshot services.CertJobsSnapshot
	if isACME {
		certJobsSnapshot, err = services.SnapshotCertJobsForRule(caddyID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份证书任务失败: " + err.Error()})
			return
		}
	}
	runtimeSnapshot, err := h.snapshotImportRuntime([]string{caddyID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份当前运行配置失败: " + err.Error()})
		return
	}
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				log.Printf("EnableRule transaction rollback failed for caddy_id=%s: %v", caddyID, rollbackErr)
			}
		}
	}()
	userIDInt := contextUserID(c)
	if _, err := tx.Exec("UPDATE lb_rules SET enabled = 1, domain = ?, updated_at = datetime('now'), updated_by = ? WHERE caddy_id = ?", ruleDomain, userIDInt, caddyID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "启用规则失败"})
		return
	}
	if err := h.caddyService.ApplyConfigFromTx(tx); err != nil {
		restoreErr := h.restoreImportRuntime(runtimeSnapshot)
		var validationErr *configValidationError
		if errors.As(err, &validationErr) {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy 配置验证失败: " + errors.Join(validationErr, restoreErr).Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("应用 Caddy 配置失败: %v", errors.Join(err, restoreErr))})
		return
	}
	if err := tx.Commit(); err != nil {
		restoreErr := h.restoreImportRuntime(runtimeSnapshot)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交规则启用失败: " + errors.Join(err, restoreErr).Error()})
		return
	}
	committed = true

	var enqueuedJobID int
	var queueManager *services.CAQueueManager
	restoreEnabledState := func() error {
		if enqueuedJobID > 0 && queueManager != nil {
			cancelCertJob(enqueuedJobID)
		}
		var caddyErr, dbErr, jobsErr error
		if isACME {
			caddyErr = h.restoreImportRuntime(runtimeSnapshot)
		}
		if _, dbErr = db.DB.Exec("UPDATE lb_rules SET enabled = ?, updated_at = datetime('now') WHERE caddy_id = ?", originalEnabled, caddyID); dbErr != nil {
			dbErr = fmt.Errorf("恢复规则启用状态: %w", dbErr)
		}
		if isACME {
			jobsErr = services.RestoreCertJobsForRule(certJobsSnapshot)
		}
		return errors.Join(caddyErr, dbErr, jobsErr)
	}
	failEnable := func(message string) {
		if restoreErr := restoreEnabledState(); restoreErr != nil {
			services.Logf("error", "CRITICAL: EnableRule compensation failed for caddy_id=%s: %v", caddyID, restoreErr)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: message + "；规则与 Caddy 恢复失败: " + restoreErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: message})
	}

	domain := ruleDomain
	log.Printf("EnableRule TLS state for caddy_id=%s: enableTLS=%v tlsSource=%s domain=%s caProviderID=%d", caddyID, enableTLS, tlsSource, domain, caProviderID)
	if isACME {
		resolvedCAProviderID, resolveErr := services.ResolveCAProviderID(caProviderID)
		if resolveErr != nil {
			failEnable("解析 CA 提供商失败: " + resolveErr.Error())
			return
		}
		caProviderID = resolvedCAProviderID
		queueManager = services.GetCAQueueManager()

		var jobStatus, jobMsg string
		var jobExpiresAt sql.NullTime
		var jobID, jobProviderID int
		hasJob := false
		err := db.DB.QueryRow("SELECT id, status, COALESCE(message,''), expires_at, COALESCE(ca_provider_id,0) FROM cert_jobs WHERE rule_id=? AND domain=? ORDER BY id DESC LIMIT 1", caddyID, canonicalACMEDomainForJobLookup(domain)).Scan(&jobID, &jobStatus, &jobMsg, &jobExpiresAt, &jobProviderID)
		if err == nil {
			hasJob = true
		} else if err != sql.ErrNoRows {
			failEnable("读取证书任务失败")
			return
		}
		var renewalDays int
		if err := db.DB.QueryRow("SELECT COALESCE(cert_renewal_days,30) FROM global_config WHERE id=1").Scan(&renewalDays); err != nil {
			failEnable("读取证书续签配置失败")
			return
		}
		var expiryPtr *time.Time
		if jobExpiresAt.Valid {
			expiry := jobExpiresAt.Time
			expiryPtr = &expiry
		}
		action := ResolveEnableCertJobAction(hasJob, jobStatus, expiryPtr, time.Now(), renewalDays)
		if hasJob {
			resolvedJobProviderID, resolveJobErr := services.ResolveCAProviderID(jobProviderID)
			if resolveJobErr != nil {
				failEnable("解析证书任务 CA 提供商失败: " + resolveJobErr.Error())
				return
			}
			if resolvedJobProviderID != caProviderID {
				action = EnableCertJobRetry
			}
		}

		switch action {
		case EnableCertJobCreate:
			if queueManager == nil {
				failEnable("CA 队列未初始化，无法创建证书任务")
				return
			}
			enqueuedJobID, err = services.CreateOrRequeueCertJob(caddyID, domain, caProviderID, queueManager)
			if err != nil {
				failEnable("创建证书任务失败: " + err.Error())
				return
			}
			recordAudit(c, "创建", "证书任务", fmt.Sprintf("启用规则 %s，创建证书任务 (%s)", caddyID, domain))
		case EnableCertJobKeep:
			recordAudit(c, "启用", "证书任务", fmt.Sprintf("启用规则 %s，证书有效（过期前%d天续签），保持现有证书", caddyID, renewalDays))
		case EnableCertJobResume:
			if enableCertJobResumePreUpdateHook != nil {
				enableCertJobResumePreUpdateHook(jobID)
			}
			// R54 S-3：UPDATE 无状态 CAS，任何未来在上方 SELECT 与此处之间
			// 删除行的路径都会 0 行命中，「启用成功但任务行不存在、续签链断」
			// 被审计文案掩盖——核对 RowsAffected==1，否则按失败补偿。
			resumeResult, err := db.DB.Exec("UPDATE cert_jobs SET status='issued', message='证书有效，已恢复使用', renewal_attempts=0, ca_available_after=NULL, last_error_code=NULL, updated_at=datetime('now') WHERE id=?", jobID)
			if err != nil {
				failEnable("恢复证书任务失败: " + err.Error())
				return
			}
			resumed, err := resumeResult.RowsAffected()
			if err != nil || resumed != 1 {
				failEnable("恢复证书任务失败：任务行不存在或已被并发变更")
				return
			}
			recordAudit(c, "启用", "证书任务", fmt.Sprintf("启用规则 %s，证书仍有效，恢复使用现有证书", caddyID))
		case EnableCertJobRenew:
			if queueManager == nil {
				failEnable("CA 队列未初始化，无法续签证书")
				return
			}
			enqueuedJobID, err = services.CreateOrRequeueCertJob(caddyID, domain, caProviderID, queueManager)
			if err != nil {
				failEnable("续签排队失败: " + err.Error())
				return
			}
			recordAudit(c, "续签", "证书任务", fmt.Sprintf("启用规则 %s，证书即将过期，重新排队续签", caddyID))
		case EnableCertJobRetry:
			if queueManager == nil {
				failEnable("CA 队列未初始化，无法重试证书任务")
				return
			}
			enqueuedJobID, err = services.CreateOrRequeueCertJob(caddyID, domain, caProviderID, queueManager)
			if err != nil {
				failEnable("重试排队失败: " + err.Error())
				return
			}
			recordAudit(c, "重试", "证书任务", fmt.Sprintf("启用规则 %s，任务之前已暂停/失败，重新排队", caddyID))
		default:
			recordAudit(c, "启用", "证书任务", fmt.Sprintf("启用规则 %s，签发任务已在进行中 (状态: %s)", caddyID, jobStatus))
		}
	}

	recordAudit(c, "启用", "负载规则", services.FormatAuditDetail(services.AuditRulePart(caddyID), "状态：已启用"))
	recordAudit(c, "重载", "Caddy服务", services.FormatAuditDetail(services.AuditSourcePart("rule_enable"), services.AuditRulePart(caddyID), services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已启用"})
}

func (h *Handlers) DisableRule(c *gin.Context) {
	caddyID := c.Param("caddy_id")

	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	var originalEnabled, enableTLS bool
	var domain, tlsSource string
	err := db.DB.QueryRow("SELECT IIF(enabled IN ('1',1),1,0), COALESCE(domain,''), COALESCE(tls_source,''), COALESCE(enable_tls,0) FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&originalEnabled, &domain, &tlsSource, &enableTLS)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则失败"})
		return
	}
	if !originalEnabled {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已禁用"})
		return
	}

	runtimeSnapshot, err := h.snapshotImportRuntime([]string{caddyID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份当前运行配置失败: " + err.Error()})
		return
	}
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				log.Printf("DisableRule transaction rollback failed for caddy_id=%s: %v", caddyID, rollbackErr)
			}
		}
	}()
	userIDInt := contextUserID(c)
	if _, err := tx.Exec("UPDATE lb_rules SET enabled = 0, updated_at = datetime('now'), updated_by = ? WHERE caddy_id = ?", userIDInt, caddyID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "禁用规则失败"})
		return
	}
	var disabledJobs int64
	if enableTLS && tlsSource == "acme_dns" && domain != "" {
		result, err := tx.Exec("UPDATE cert_jobs SET status='disabled', message='规则已禁用，任务已暂停', updated_at=datetime('now') WHERE rule_id=? AND status NOT IN ('failed','disabled')", caddyID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新证书任务状态失败: " + err.Error()})
			return
		}
		disabledJobs, err = result.RowsAffected()
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "确认证书任务状态失败: " + err.Error()})
			return
		}
	}
	if err := h.caddyService.ApplyConfigFromTx(tx); err != nil {
		restoreErr := h.restoreImportRuntime(runtimeSnapshot)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("Failed to apply Caddy config: %v", errors.Join(err, restoreErr))})
		return
	}
	if err := tx.Commit(); err != nil {
		restoreErr := h.restoreImportRuntime(runtimeSnapshot)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交规则禁用失败: " + errors.Join(err, restoreErr).Error()})
		return
	}
	committed = true
	if disabledJobs > 0 {
		services.WriteCertJobLogByRule(caddyID, "WARN", "cancelled", "规则已禁用，证书任务已暂停")
		recordAudit(c, "禁用", "证书任务", fmt.Sprintf("规则 %s 已禁用，%d 个证书任务状态设为已禁用", caddyID, disabledJobs))
	}

	// 取消仍在排队或执行中的签发协程，避免已禁用规则继续占用 CA 配额
	if qm := services.GetCAQueueManager(); qm != nil {
		cancelCtx, cancel := context.WithTimeout(c.Request.Context(), cancelRuleJobsTimeout)
		if err := cancelRuleJobs(cancelCtx, qm, caddyID); err != nil {
			log.Printf("DisableRule certificate cancellation timed out for caddy_id=%s: %v", caddyID, err)
		}
		cancel()
	}

	recordAudit(c, "禁用", "负载规则", services.FormatAuditDetail(services.AuditRulePart(caddyID), "状态：已禁用"))
	recordAudit(c, "重载", "Caddy服务", services.FormatAuditDetail(services.AuditSourcePart("rule_disable"), services.AuditRulePart(caddyID), services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已禁用"})
}

func (h *Handlers) GetRuleLogStream(c *gin.Context) {
	caddyID := c.Param("caddy_id")
	offset, _ := strconv.ParseInt(c.Query("offset"), 10, 64)
	lines, next := services.ReadRuleLogFrom(caddyID, offset)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"offset": next, "lines": lines}})
}

func (h *Handlers) GetRuleLogs(c *gin.Context) {
	caddyID := c.Param("caddy_id")
	content, offset := services.ReadRuleLogTail(caddyID, 1000)
	// offset must point just past the returned tail so a following stream
	// request continues without re-reading the same lines.
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"content": content, "offset": offset + int64(len(content))}})
}
