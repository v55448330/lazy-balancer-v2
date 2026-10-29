package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

var (
	createOrRequeueCertJobVerified = services.CreateOrRequeueCertJobVerified
	cancelRuleJobs                 = func(ctx context.Context, manager *services.CAQueueManager, ruleID string) error {
		return manager.CancelJobsForRule(ctx, ruleID)
	}
	cancelRuleJobsTimeout = 2 * time.Minute
)

// enableCertJobResumePreUpdateHook 是测试专用钩子：在 EnableRule 的
// EnableCertJobResume 分支 UPDATE 之前触发，用于模拟 SELECT 与 UPDATE 之间
// 任务行被并发删除（RowsAffected 校验的回归测试）。
var enableCertJobResumePreUpdateHook func(jobID int)

func (h *Handlers) ListRules(c *gin.Context) {
	// lb_rules.id 为可空遗留列（生产形态恒 NULL，cluster_apply 才显式
	// 带值），ORDER BY id 语义退化；rowid 显式化——行为与现状等价（NULL 排序
	// 实践上即 rowid 序）。
	rows, err := db.DB.Query(`SELECT ` + lbRuleListColumns + ` FROM lb_rules ORDER BY rowid`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}
	rules, err := scanLbRules(rows)
	// rows.Close 错误也要记录，与 services 层 errors.Join 风格一致。
	if closeErr := rows.Close(); closeErr != nil {
		services.Logf("error", "ListRules rows close error: %v", closeErr)
	}
	if err != nil {
		services.Logf("error", "ListRules scan error: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则失败"})
		return
	}
	if err := hydrateRuleRelations(c.Request.Context(), rules); err != nil {
		services.Logf("error", "ListRules relations error: %v", err)
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
	// 同 ListRules。
	if closeErr := rows.Close(); closeErr != nil {
		services.Logf("error", "GetRule rows close error for caddy_id=%s: %v", caddyID, closeErr)
	}
	if err != nil {
		services.Logf("error", "GetRule scan error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则失败"})
		return
	}
	if len(rules) == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
		return
	}
	if err := hydrateRuleRelations(c.Request.Context(), rules); err != nil {
		services.Logf("error", "GetRule relations error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则关联数据失败"})
		return
	}
	rule := rules[0]
	// 手动证书私钥与导出备份同敏感级——仅管理员 JWT
	// 与管理员读写 Key 可回读；只读 Key/非管理员掩码为空串并置 TLSKeySet，
	// 供编辑表单区分「未配置」与「已隐藏」（UpdateRule 空值=保留原私钥）。
	if rule.TLSKey != "" && !canReadSensitiveSecrets(c) {
		rule.TLSKey = ""
		rule.TLSKeySet = true
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: rule})
}

// canReadSensitiveSecrets 报告当前请求身份是否可回读敏感原文：规则手动证书
// 私钥（GetRule/GetRuleCaddyConfig）、全局配置内联原文（GetConfig 的
// caddy_config）与运行时原始配置（GetCaddyConfig）同敏感级——仅管理员 JWT
// 与管理员读写 API Key 可见；只读 Key/非管理员恒掩码或拒绝。四处消费同一判据，
// 避免敏感面判定分叉。
func canReadSensitiveSecrets(c *gin.Context) bool {
	if c.GetString("role") != "admin" {
		return false
	}
	return !(c.GetString("auth_type") == "api_key" && c.GetBool("api_key_read_only"))
}

// maskRuleCaddyPrivateKeys 递归掩码证书条目中的私钥字段：证书条目
// （load_files 的私钥文件路径 / load_pem 的 PEM 正文）携带 certificate 与
// key，非管理员/只读 Key 看到的 key 置空并标记 key_redacted——配置查看框
// 只需证书与策略，无需私钥；与 GetRule 的 TLSKeySet 掩码口径一致。
func maskRuleCaddyPrivateKeys(value interface{}) {
	switch typed := value.(type) {
	case map[string]interface{}:
		if _, hasCertificate := typed["certificate"]; hasCertificate {
			if key, ok := typed["key"].(string); ok && key != "" {
				typed["key"] = ""
				typed["key_redacted"] = true
			}
		}
		for _, child := range typed {
			maskRuleCaddyPrivateKeys(child)
		}
	case []interface{}:
		for _, child := range typed {
			maskRuleCaddyPrivateKeys(child)
		}
	}
}

func (h *Handlers) GetRuleCaddyConfig(c *gin.Context) {
	caddyID := c.Param("caddy_id")

	var r struct {
		CaddyID    string
		ListenPort int
		Enabled    bool
	}

	services.Logf("debug", "GetRuleCaddyConfig: querying rule caddy_id=%s", caddyID)

	err := db.DB.QueryRow(`
		SELECT COALESCE(caddy_id,''), listen_port, IIF(enabled IN ('1',1),1,0)
		FROM lb_rules WHERE caddy_id = ?
	`, caddyID).Scan(&r.CaddyID, &r.ListenPort, &r.Enabled)

	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
		return
	}

	if err != nil {
		services.Logf("error", "GetRuleCaddyConfig: query/scan error for rule caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "规则 Caddy 配置查询失败"})
		return
	}

	// 同族：该 enabled 上游 COUNT 仅用于 debug 日志，
	// 每次请求额外执行一次查询——删除（排障价值不抵每请求成本）。
	services.Logf("debug", "GetRuleCaddyConfig: caddyID=%s, port=%d, enabled=%v",
		r.CaddyID, r.ListenPort, r.Enabled)

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

	// 一次读取运行配置，按 @id 归属收集本规则的全部路由——主路由
	// （@id == caddyID，与原 GetConfigByID 同源）与兄弟路由（caddyID_ 前缀：
	// 自定义路由渲染的 caddyID_path_N、GeoIP pass 的 caddyID_geoip、
	// HTTP→HTTPS 跳转的 caddyID_redirect）。启用自定义路由的规则此前只返回
	// 主路由对象，配置查看对话框拿到的 JSON 缺路径路由。
	runtimeConfig, err := h.caddyService.GetConfig()
	if err != nil {
		// admin 不可达/超时 ≠「规则未应用」——此前两者都归一为
		// config_not_exists，排障被误导。返回 502，让 UI 的失败分支如实展示
		// 「获取配置失败」（后者只表示该规则无运行路由）。
		services.Logf("error", "GetRuleCaddyConfig: failed to get config from Caddy for caddy_id=%s: %v", r.CaddyID, err)
		writeInternalError(c, http.StatusBadGateway, "读取 Caddy 运行配置失败", nil)
		return
	}
	mainRoute, allRuleRoutes := ruleCaddyRoutes(runtimeConfig, r.CaddyID)
	if mainRoute == nil {
		services.Logf("info", "GetRuleCaddyConfig: route %s not found in running config", r.CaddyID)
		responseData["config"] = nil
		responseData["config_not_exists"] = true
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: responseData})
		return
	}

	// server/TLS 上下文与 route/routes 同源（同一份运行配置）——server_context
	// 曾按库现值渲染，在「库态≠运行态」（apply 失败/外部 caddy api 改动/集群
	// 未收敛）时对话框会把运行中的路由与库渲染的 server/TLS 上下文拼在一起
	// 互相矛盾，排障者据此误判证书/策略是否生效。buildRuleCaddyContext 与
	// ruleCaddyRoutes 同源（含 TLS 策略的 SNI 过滤），零额外 IO。
	ruleContext := buildRuleCaddyContext(runtimeConfig, r.CaddyID)

	responseData["config"] = map[string]interface{}{
		"route":                   mainRoute,
		"routes":                  allRuleRoutes,
		"server_context":          ruleContext["server"],
		"tls_certificates":        ruleContext["tls_certificates"],
		"tls_connection_policies": ruleContext["tls_connection_policies"],
	}
	responseData["config_not_exists"] = false
	// 规则私钥字段与 GetRule 同敏感级：非管理员/只读 Key 不下发私钥（PEM
	// 正文或私钥文件路径），只保留证书与策略上下文。
	if !canReadSensitiveSecrets(c) {
		maskRuleCaddyPrivateKeys(responseData)
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: responseData})
}

// sortedStringKeys 按字典序返回任意 map[string]V 的键——留痕/展示/遍历
// 顺序依赖时使用，map 迭代序会让同一输入产出行序漂移。
func sortedStringKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// buildRuleCaddyContext extracts the server and TLS context relevant to a rule from the full Caddy config.
func buildRuleCaddyContext(fullConfig map[string]interface{}, caddyID string) map[string]interface{} {
	result := map[string]interface{}{
		"server":                  nil,
		"tls_certificates":        []interface{}{},
		"tls_connection_policies": []interface{}{},
	}

	apps, _ := fullConfig["apps"].(map[string]interface{})
	if apps == nil {
		return result
	}

	// 同一 @id 若出现在多个 server（外部写入/历史漂移，
	// 本仓另有漂移检测守卫但仍属可能形态），旧实现只在 routes 循环内 break，
	// 外层继续遍历并用后遍历者覆盖 result["server"]——map 序遍历不确定，
	// 配置查看框的 server_context 随机漂移，误导排障。改为按 server 名排序
	// 遍历 + 命中即跳出外层循环：同一份配置恒得同一结果（确定性=排序首个）。
	if httpApp, ok := apps["http"].(map[string]interface{}); ok {
		if servers, ok := httpApp["servers"].(map[string]interface{}); ok {
			for _, serverName := range sortedStringKeys(servers) {
				server, _ := servers[serverName].(map[string]interface{})
				if server == nil {
					continue
				}
				routes, _ := server["routes"].([]interface{})
				matched := false
				for _, routeVal := range routes {
					route, _ := routeVal.(map[string]interface{})
					if route == nil {
						continue
					}
					if route["@id"] == caddyID {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
				scopedPolicies := scopedTLSConnectionPolicies(server["tls_connection_policies"], caddyID, server)
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

	// If not found in HTTP app, search the layer4 app for TCP rules
	if result["server"] == nil {
		if layer4App, ok := apps["layer4"].(map[string]interface{}); ok {
			if servers, ok := layer4App["servers"].(map[string]interface{}); ok {
				for _, serverName := range sortedStringKeys(servers) {
					server, _ := servers[serverName].(map[string]interface{})
					if server == nil {
						continue
					}
					routes, _ := server["routes"].([]interface{})
					matched := false
					for _, routeVal := range routes {
						route, _ := routeVal.(map[string]interface{})
						if route == nil {
							continue
						}
						if route["@id"] == caddyID {
							matched = true
							break
						}
					}
					if !matched {
						continue
					}
					result["server"] = map[string]interface{}{
						"server_name": serverName,
						"listen":      server["listen"],
					}
					break
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

	// 此处曾有 tls.automation.policies 的域名作用域扫描——生产
	// 渲染（全量生成）从不产出 tls.automation
	// （注释明确「no Caddy ACME automation」，证书由应用层任务管理），该字段
	// 恒为 []，测试为自造输入假绿。删除死代码，配置查看框不再展示不存在的
	// automation policies。
	return result
}

// ruleCaddyRoutes 从运行配置收集归属该规则的全部路由：遍历 http 与
// layer4 两个 app 的全部 server，按 services.RouteIDBelongsToRule 识别
// 主路由（@id == caddyID）与兄弟路由（caddyID_path_N / caddyID_geoip /
// caddyID_redirect）。同一 server 内保持运行顺序；跨 server（如 80 端口
// 跳转路由）按 app 与 server 名排序遍历——map 序会让同一份运行配置的返回
// 顺序在两次请求间抖动（配置查看对话框 routes 数组无序漂移）。
func ruleCaddyRoutes(full map[string]interface{}, caddyID string) (main map[string]interface{}, all []interface{}) {
	apps, _ := full["apps"].(map[string]interface{})
	if apps == nil {
		return nil, nil
	}
	collect := func(routesRaw interface{}) {
		routes, _ := routesRaw.([]interface{})
		for _, routeVal := range routes {
			route, _ := routeVal.(map[string]interface{})
			if route == nil {
				continue
			}
			routeID, _ := route["@id"].(string)
			if routeID == "" || !services.RouteIDBelongsToRule(routeID, caddyID) {
				continue
			}
			if routeID == caddyID {
				main = route
			}
			all = append(all, route)
		}
	}
	for _, appName := range []string{"http", "layer4"} {
		app, _ := apps[appName].(map[string]interface{})
		if app == nil {
			continue
		}
		servers, _ := app["servers"].(map[string]interface{})
		for _, serverName := range sortedStringKeys(servers) {
			server, _ := servers[serverName].(map[string]interface{})
			if server == nil {
				continue
			}
			collect(server["routes"])
		}
	}
	return main, all
}

// scopedTLSConnectionPolicies 只保留属于当前规则的连接策略：
// certificate_selection.any_tag 携带本规则 caddyID，或 match.sni 与所属
// server（运行配置）routes[].match[].host 的域名集合相交。域名来源用运行
// 配置而非库值——库态≠运行态时（apply 失败/外部 caddy api 改动/集群未收敛）
// 按库值过滤会漏掉服务端真实存在的策略，配置查看框显示空列表，重演
// 「证书/策略未下发」的误判。server 由 buildRuleCaddyContext 传入。
func scopedTLSConnectionPolicies(raw interface{}, caddyID string, server map[string]interface{}) []interface{} {
	policies, ok := raw.([]interface{})
	if !ok {
		return []interface{}{}
	}
	wanted := serverRouteHosts(server)
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
						if _, hit := wanted[strings.ToLower(sniDomain)]; hit {
							matched = true
							break
						}
					}
				case []string:
					for _, sniDomain := range sni {
						if _, hit := wanted[strings.ToLower(sniDomain)]; hit {
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

// serverRouteHosts 收集该 server 全部路由声明的 host 集合（小写去重）。
// TLS 策略的 SNI 过滤与服务端路由同源于运行配置。
func serverRouteHosts(server map[string]interface{}) map[string]struct{} {
	hosts := map[string]struct{}{}
	routes, _ := server["routes"].([]interface{})
	for _, routeVal := range routes {
		route, _ := routeVal.(map[string]interface{})
		if route == nil {
			continue
		}
		matches, _ := route["match"].([]interface{})
		for _, matchVal := range matches {
			match, _ := matchVal.(map[string]interface{})
			if match == nil {
				continue
			}
			switch rawHosts := match["host"].(type) {
			case []interface{}:
				for _, rawHost := range rawHosts {
					if host, ok := rawHost.(string); ok && host != "" {
						hosts[strings.ToLower(host)] = struct{}{}
					}
				}
			case []string:
				for _, host := range rawHosts {
					if host != "" {
						hosts[strings.ToLower(host)] = struct{}{}
					}
				}
			}
		}
	}
	return hosts
}

// normalizedRuleDomains 将逗号分隔域名转为规范化集合（小写+punycode）。
// CanonicalDomains 失败（手造脏数据）时回退小写拆分保留，
// 与渲染侧 normalizedDomainSet（caddy.go）同口径——此前失败返回 nil 会把
// 域名整体丢弃，导致遮蔽检查静默通过（两侧不对称且是问题方向）。
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
// 单源收敛至 services.ReversedCertJobDomain（与
// certjobs.reversedCertJobDomain 同实现，两侧委托）。
func reversedACMEDomainForm(domain string) string {
	return services.ReversedCertJobDomain(domain)
}

// retireCertJobsForDomain 将规则下旧域证书任务退役为 disabled 终态（保留 PEM 作
// 导入备份可携带非规范 domain 行（大小写/空白/顺序变体），按去空白小写
// 归一（lower+replace）与 canonical/reversed 双形式匹配，避免变体行逃逸退役
// 零行命中为无害无操作。
// stage 参数化失败阶段(事务开启/迁移 UPDATE/commit),退役 message
// 随实际失败阶段落库,运维可从任务行直接看出哪一步失败。
func retireCertJobsForDomain(database *sql.DB, ruleID, canonicalDomain, reversedDomain, stage string) error {
	_, err := database.Exec(
		`UPDATE cert_jobs SET status='disabled', message=?, updated_at=datetime('now') WHERE rule_id=? AND lower(replace(domain,' ','')) IN (?,?)`,
		stage+"，旧域任务退役", ruleID, canonicalDomain, reversedDomain)
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

// validateRuleListenPortForSave 在包级 validateRuleListenPort（范围/默认管理口
// 8000/2019/TCP 80/443 保留）之上，叠加本进程实际管理端口校验：管理
// 面板 HTTP/HTTPS 监听口（cfg.Port——admin TLS 与面板同一监听口，见
// cmd/server/main.go）与 Caddy admin API 端口（cfg.CaddyAdminURL 解析）。此前
// 仅硬编码 8000/2019，部署自定义端口（config 文件 port / caddy_admin_url）时
// 规则可抢占面板端口导致管理面失联。导入链（config_backup/config_import_v1）
// 经 validateV2BackupRules/validateConvertedV1Rules 的可选 portGate 传入本函数，
// 与保存链同口径。
func (h *Handlers) validateRuleListenPortForSave(protocol string, port int) error {
	if err := validateRuleListenPort(protocol, port); err != nil {
		return err
	}
	// 管理端口族：面板端口、caddy_admin_url 引导端口、渲染产物 admin 稳态
	// 端口（services.CaddyAdminListenPort=2019，/load 后 admin 恒迁至此）——
	// 三者在不同窗口期都可能被占用，一律禁止规则监听。
	if port == h.adminPanelListenPort() || port == h.caddyAdminListenPort() || port == services.CaddyAdminListenPort {
		return fmt.Errorf("端口 %d 为管理端口，不可使用", port)
	}
	return nil
}

func (h *Handlers) adminPanelListenPort() int {
	if h.cfg != nil && h.cfg.Port >= 1 && h.cfg.Port <= 65535 {
		return h.cfg.Port
	}
	return 8000
}

// caddyAdminListenPort 返回 caddy_admin_url 配置解析出的端口（引导期占用）——
// 首次成功 /load 之前 Caddy admin 在该端口监听。稳态端口恒为
// services.CaddyAdminListenPort（渲染产物 admin listen 单源，/load 后 admin
// 迁到该端口）——两端口都可能是管理端口，调用方必须同时保留（见
// validateRuleListenPortForSave），单看任一口径都会漏拦一个窗口期。
func (h *Handlers) caddyAdminListenPort() int {
	if h.cfg != nil && h.cfg.CaddyAdminURL != "" {
		if parsed, err := url.Parse(h.cfg.CaddyAdminURL); err == nil {
			if port, err := strconv.Atoi(parsed.Port()); err == nil && port >= 1 && port <= 65535 {
				return port
			}
		}
	}
	return services.CaddyAdminListenPort
}

// enabledRuleDomainConflict 同域名同端口冲突检查（删除
// 原 ruleDomainConflict 空包装，Create/Update/Enable 三处直用本函数）。
// 仅统计启用中且至少一个上游启用的规则：禁用规则与全部上游被禁用的规则都不
// 产生 host 路由、不占用域名，创建/更新时不应被其阻塞；启用时由 EnableRule
// 侧同一函数二次把关，避免两条禁用规则同时启用产生冲突。
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
		// 排除对方 80 端口自环跳转规则（listen_port=80 + TLS + 跳转本身
		// 生成自环 Location、属非法存量，不应作为占用方拦截新建 80 规则）。
		// 镜像 2026-09 复审裁定 2(跳转分支同款 EXISTS)
		// 全部上游被禁用的规则不产生 host 路由与跳转(caddy.go ),
		// 不作为占用方;此前裁定只落了单侧,该形态下 80 规则被纯误拦 400。
		rows, err = db.DB.Query(`SELECT caddy_id, name, COALESCE(domain,'') FROM lb_rules WHERE protocol='http' AND enabled=1 AND enable_tls=1 AND tls_http_redirect=1 AND listen_port != 80 AND caddy_id != ? AND EXISTS (SELECT 1 FROM upstreams u WHERE u.rule_id=lb_rules.caddy_id AND `+services.UpstreamEnabledSQLPredicate+`)`, excludeCaddyID)
	case enableTLS && tlsHTTPRedirect:
		// 2026-09 复审裁定 2：与渲染面同口径——全部上游被禁用的 80 规则不产生
		// host 路由、不会遮蔽跳转，不再作为占用方（报错与真实渲染行为一致）。
		rows, err = db.DB.Query(`SELECT r.caddy_id, r.name, COALESCE(r.domain,'') FROM lb_rules r
			WHERE r.protocol='http' AND r.enabled=1 AND r.listen_port=80 AND r.caddy_id != ?
			AND EXISTS (SELECT 1 FROM upstreams u WHERE u.rule_id=r.caddy_id AND `+services.UpstreamEnabledSQLPredicate+`)`, excludeCaddyID)
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

func queryRuleDomainConflict(domain string, listenPort int, excludeCaddyID, extraWhere string) (bool, error) {
	candidates := normalizedRuleDomains(domain)
	if len(candidates) == 0 {
		return false, nil
	}
	wanted := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		wanted[candidate] = struct{}{}
	}
	// 与渲染层/跳转遮蔽门同口径：全部上游被禁用的规则不产生 host 路由
	//（渲染主循环直接跳过该规则），不作为域名占用方——否则「A 上游全禁用 +
	// B 同域名同端口」形态下 B 被误拦，而运行时实际只有 B 生效。
	// 启用方向由 EnableRule 复用本函数二次把关；两侧都有启用上游时照旧硬拦。
	query := "SELECT COALESCE(domain,'') FROM lb_rules WHERE protocol='http' AND listen_port = ? AND caddy_id != ?" + extraWhere +
		" AND EXISTS (SELECT 1 FROM upstreams u WHERE u.rule_id = lb_rules.caddy_id AND " + services.UpstreamEnabledSQLPredicate + ")"
	rows, err := db.DB.Query(query, listenPort, excludeCaddyID)
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

// pinLastGoodAfterCompensation 把 LKG 钉回「已提交库视图」（零 /load）。
// 规则族提交后补偿链用 restoreImportRuntime 恢复「请求前运行配置」，而该
// 函数经 ApplyConfig(persistLastGood=true) 会在恢复 /load 成功后把这份快照
// 写进 LKG——LKG 的全族不变量是「最后一次已提交且已下发的配置」，请求前
// 运行配置可能本就是漂移形态（逃生口写入 / 外来 caddy api 改动），一旦被
// 固化，重启兜底（DB 渲染被拒时）会回放从未提交的形态。设置族与逃生口
// （UpdateConfig / PutCaddyConfig）已是同口径；规则族补偿链在此单点收口，
// 调用方勿再各写一次。
//
// 调用约束：必须在本请求的 DB 回退完成之后调用——钉回渲染的是「已提交
// 视图」，DB 尚未回退时会把本请求的改动当成已提交内容写回 LKG。
//
// 留痕单点：本函数只返回点名 LKG 的错误，不再自行 Logf/写审计——附带失败的
// 唯一写点是调用方汇入 sideErr 后的 recordCompensationSideEffects（配置族）
// 或 recordPostCommitRestoreFailure。自身再写一次会让同一次失败产生两行
// 「补偿失败」审计与两条 error 日志，运维按行数会读成两起问题。
func (h *Handlers) pinLastGoodAfterCompensation() error {
	var err error
	if pinLastGoodForTest != nil {
		err = pinLastGoodForTest()
	} else {
		err = h.caddyService.PersistCommittedViewAsLastGoodInLock()
	}
	if err != nil {
		return fmt.Errorf("last-known-good 钉回失败（重启兜底可能回放漂移形态）：%w", err)
	}
	return nil
}

// pinLastGoodForTest 仅测试注入 LKG 钉回失败（nil = 生产直通）。留痕单点契约
// （同一次失败恰好一行「补偿失败」审计，设置族/逃生口/导入不得零审计）只有
// 可注入才可能钉住——正常路径下钉回失败需要已提交视图渲染失败（库损坏），
// 无法在单测里稳定构造。
var pinLastGoodForTest func() error

// respondRuleApplyError 规则×5 apply 错误统一映射（裁定 2026-09-07）
// 配置拒绝（CLI/admin 4xx/生成失败）→ 400「Caddy 配置应用失败，规则未<动词>: …」；
// ErrUnvalidatedApply/传输失败 → 500 同文案。恢复失败并入消息（不改状态码分类）。
// 五个调用方的 applyErr 分支均伴随 tx 回滚——applyFromTxNote
// 的 CLI 预检/事务内应用两轮渲染已按未提交内容重写投影文件（规则×绑定策略的
// u-*/p<id> 投影），磁盘同步回退到已提交态（零 /load；单一收敛点= 同族
// 收敛，禁止单点补丁）。
//
// runtimeErr = 运行配置是否已恢复（唯一驱动横幅两态标签）；sideErr = 附带失败
// （未提交事务回滚 / LKG 钉回），独立留痕，不进标签。
func (h *Handlers) respondRuleApplyError(c *gin.Context, applyErr, runtimeErr, sideErr error, verb string) {
	h.caddyService.RollbackIPListProjectionsToCommittedInLock()
	allErr := errors.Join(applyErr, runtimeErr, sideErr)
	// 横幅事实源收口（与配置域 UpdateConfig/PutCaddyConfig/finishTxApply
	// 同口径）：只有库态与运行态可能分叉的失败才写横幅——配置拒绝（CLI
	// 校验/admin 4xx）时候选未 /load、事务已回滚，运行配置仍是提交前形态，
	// 写横幅会让用户追一个不存在的不一致（finishTxApply 的拒绝分支即不写）。
	// 恢复失败（runtimeErr≠nil）时运行配置状态未知，无条件落横幅；恢复成功
	// 时横幅为「旧配置已保留」，恢复失败（双失败）改口「状态未知」，不得在
	// 同一行里既称已保留又称恢复失败。
	h.recordCompensationSideEffects("Caddy 配置应用失败，规则未"+verb, sideErr)
	if !services.IsConfigRejected(applyErr) || runtimeErr != nil {
		h.recordCaddyApplyFailure(allErr, runtimeErr)
	}
	// 规则五端点均为 Explicit 审计策略（中间件对 Explicit 整体
	// 跳过）——此前 apply 失败只写 HTTP 响应，操作审计完全缺席。与配置域
	// finishTxApply（拒绝/未校验分支）及安全域同口径：失败必须留痕。
	// 审计词条用字面量（词汇表门禁禁止动态 action；动词集合固定为五值）。
	failureDetail := caddyFailureAuditDetail("Caddy 配置应用失败", allErr)
	switch verb {
	case "创建":
		recordAudit(c, "创建失败", "负载规则", failureDetail)
	case "更新":
		recordAudit(c, "更新失败", "负载规则", failureDetail)
	case "删除":
		recordAudit(c, "删除失败", "负载规则", failureDetail)
	case "启用":
		recordAudit(c, "启用失败", "负载规则", failureDetail)
	case "禁用":
		recordAudit(c, "禁用失败", "负载规则", failureDetail)
	}
	if services.IsConfigRejected(applyErr) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy 配置应用失败，规则未" + verb + ": " + allErr.Error()})
		return
	}
	writeInternalError(c, http.StatusInternalServerError, "Caddy 配置应用失败，规则未"+verb, nil)
}

// respondRuleSnapshotError 规则×5 运行配置快照失败的统一收尾：500 + 操作
// 审计（这些路由均为 Explicit 审计策略，中间件不补失败留痕）+ 错误详情。
// 快照失败发生在事务开启前，DB 零变更；失败审计仍必须留痕（与配置域
// 「Caddy 不可达」同口径）。verb 取固定五值字面量（词汇表门禁禁动态 action）。
func (h *Handlers) respondRuleSnapshotError(c *gin.Context, verb string, err error) {
	detail := caddyFailureAuditDetail("备份当前运行配置失败", err)
	switch verb {
	case "创建":
		recordAudit(c, "创建失败", "负载规则", detail)
	case "更新":
		recordAudit(c, "更新失败", "负载规则", detail)
	case "删除":
		recordAudit(c, "删除失败", "负载规则", detail)
	case "启用":
		recordAudit(c, "启用失败", "负载规则", detail)
	case "禁用":
		recordAudit(c, "禁用失败", "负载规则", detail)
	}
	writeInternalError(c, http.StatusInternalServerError, "备份当前运行配置失败", err)
}

// ruleConflictDetail 阻断型 409 的审计明细（规则归因 + 原因 + 失败结果）。
// 动作词由调用点以字面量传入并直接进 recordAudit——审计动作必须能静态扫描
// （词汇门禁），因此不在本函数内拼接动作。被在途证书签发 / 放锁窗口内的并发
// 删除或修改挡住的操作必须留痕：运维要能从审计回答「谁在何时尝试、被什么
// 挡住」，此前 409 族只有版本冲突与并发中止两处有账。
func ruleConflictDetail(caddyID, reason string) string {
	return services.FormatAuditDetail(services.AuditRulePart(caddyID), reason, services.AuditResultPart("failure"))
}

// recordRuleWriteFailure 是规则写端点「数据库层失败」的统一留痕：这些路由
// 均为 Explicit 审计策略（中间件不补失败留痕），Caddy 层失败（apply/快照/
// 提交后）已有账，DB 层失败此前只回 500 无任何操作审计——运维无法回答
// 「谁在何时尝试写库失败」。phase 描述失败相位（开启事务/写入规则/写入上游/
// 清理安全策略绑定…），err 可为 nil（下推为固定文案的分支）。
// verb 取固定五值字面量（词汇表门禁禁止动态 action）。
func recordRuleWriteFailure(c *gin.Context, verb, phase string, err error) {
	detail := phase
	if err != nil {
		detail = phase + "：" + err.Error()
	}
	parts := []string{detail, services.AuditResultPart("failure")}
	if caddyID := c.Param("caddy_id"); caddyID != "" {
		parts = append([]string{services.AuditRulePart(caddyID)}, parts...)
	}
	failureDetail := services.FormatAuditDetail(parts...)
	switch verb {
	case "创建":
		recordAudit(c, "创建失败", "负载规则", failureDetail)
	case "更新":
		recordAudit(c, "更新失败", "负载规则", failureDetail)
	case "删除":
		recordAudit(c, "删除失败", "负载规则", failureDetail)
	case "启用":
		recordAudit(c, "启用失败", "负载规则", failureDetail)
	case "禁用":
		recordAudit(c, "禁用失败", "负载规则", failureDetail)
	}
}

// respondCAProviderResolveFailure 是「生效 CA 提供商不可解析」的统一分类：
// 「跟随默认」解析不到任何启用提供商是用户可修复的配置状态（管理端可添加/
// 启用提供商，或为规则显式选择）——400 + 可操作指引；DB 驱动/IO 故障才是
// 500 并留痕。创建/更新/启用三条写路径共用同一分类，避免状态码与文案漂移。
//
// 调用点必须是写前门：在事务提交与 Caddy 应用之前判定，否则一个可写前判定
// 的前置条件会被拖到提交后以 500 整体回滚（一次真实 apply 白做）。
func respondCAProviderResolveFailure(c *gin.Context, verb string, resolveErr error) {
	if errors.Is(resolveErr, sql.ErrNoRows) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "没有可用的 CA 提供商，请先在 CA 提供商页面添加并启用"})
		return
	}
	recordRuleWriteFailure(c, verb, "解析 CA 提供商失败", resolveErr)
	writeInternalError(c, http.StatusInternalServerError, "解析 CA 提供商失败", resolveErr)
}

// rollbackRuleWriteTx 规则写端点早退路径的事务回滚：回滚失败必须留一行日志
// （SQLite busy/IO 时写锁可能滞留，缺这行排障就少了关键证据）；ErrTxDone
// 表示事务已结束（提交失败路径或 defer 兜底已回滚），不构成失败。调用点仍在
// return 前显式回滚——SQLite 写锁释放时点不变。
func rollbackRuleWriteTx(tx *sql.Tx, endpoint, caddyID string) {
	if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
		services.Logf("error", "%s transaction rollback failed for caddy_id=%s: %v", endpoint, caddyID, rbErr)
	}
}

// normalizeInactiveHealthCheckFields 主动健康检查未启用时，其专属字段
// （health_check_path / health_check_host / tcp_health_check_port）渲染零消费
// （caddy.go 的 health_checks.active 块仅在 enable_active_health_check=1 时发射）——
// 保存侧归一清零，防止死配置随导出/备份/集群快照放大（API/MCP 可写入 UI
// 隐藏的字段，无服务端披露则用户以为生效）。返回被清字段名（审计明细披露，
// 空=无变化）。指针形参是唯一判据：nil=该入口不处置此字段——Create（值字段
// 恒非 nil，按生效态清零）、Update（只有本次显式提交的字段传指针，缺席字段
// 传 nil 以守住部分更新契约）、Duplicate（副本按生效态清零）三入口共用。
func normalizeInactiveHealthCheckFields(enabled bool, path *string, host *string, port *int) []string {
	if enabled {
		return nil
	}
	var cleared []string
	if path != nil && *path != "" {
		*path = ""
		cleared = append(cleared, "health_check_path")
	}
	if host != nil && *host != "" {
		*host = ""
		cleared = append(cleared, "health_check_host")
	}
	if port != nil && *port != 0 {
		*port = 0
		cleared = append(cleared, "tcp_health_check_port")
	}
	return cleared
}

// inactiveHealthCheckAuditHint 把归一清零结果转成审计明细披露片段。
func inactiveHealthCheckAuditHint(cleared []string) string {
	if len(cleared) == 0 {
		return ""
	}
	return "已清空未启用主动健康检查的死配置：" + strings.Join(cleared, ", ")
}

// tcpDeadFields 是 TCP 写入侧「HTTP 专属字段」的指针视图：CreateRule（值
// 字段）/ UpdateRule（指针字段）/ DuplicateRule（存量行）共用同一张归一
// 清单。nil 目标 = 该入口有意不处置该字段（Create 的 NTLMCompatible/
// HealthCheckHost——显式携带由保存门 400 拒绝，不做静默弃置；Update 的
// NTLMCompatible 由调用点按「是否显式提供」分别 400/自愈）。
type tcpDeadFields struct {
	EnableTLS                *bool
	TLSSource                *string
	TLSCert                  *string
	TLSKey                   *string
	ACMEConfigID             *int
	CAProviderID             *int
	Domain                   *string
	TLSHTTPRedirect          *bool
	HostHeader               *string
	HealthCheckPath          *string
	HealthCheckHost          *string
	EnableCompress           *bool
	CompressTypes            *string
	RequestBodyMaxSizeMB     *int
	UpstreamKeepaliveTimeout *int
	ServerTokensHidden       *int
	NTLMCompatible           *int
	UpstreamForceHTTP1       *int
	BlockPageStage1ID        *int
	BlockPageStage1Status    *int
	BlockPageStage3ID        *int
	BlockPageStage3Status    *int
	// 访问日志渲染仅对 HTTP 生成 logger_names（caddy.go 按
	// r.Protocol=="http" 门控），TCP 行的 log_enabled 是死配置——UI 已对
	// TCP 隐藏开关，API/导入仍可写入，随导出/快照放大。
	LogEnabled *bool
	// TCP 自愈族（2026-10-22）：代理超时族与自定义上层/路径同属 HTTP
	// 语义（buildTCPServer/buildTCPProxyRoute 零消费，validateRuleFeatures
	// TCP 分支显式拒绝）——存量行携带这些死值会让任何无关编辑/复制命中
	// 保存门恒 400 死端（指针合并 nil=沿用存量）。save/update/duplicate
	// 三入口归一为 0，与导入/启动迁移 SQL 同族。
	ProxyDialTimeout           *int
	ProxyResponseHeaderTimeout *int
	ProxyReadTimeout           *int
	ProxyWriteTimeout          *int
	ProxyStreamTimeout         *int
	ProxyFlushInterval         *int
	ProxyStreamCloseDelay      *int
	CustomRoutesEnabled        *bool
	DynamicDNS                 *bool
	// Strategy：TCP 策略白名单外唯一 HTTP-only 值是 cookie
	//（validateStrategyForProtocol）——归一为 DDL 默认策略而非清空。
	Strategy *string
	// DnsFamily：仅 HTTP 消费（dynamic_dns 的上游族过滤），TCP 无
	// resolver 消费点——归一到建库默认 ipv4（而非空串）：同一 TCP 终态不得
	// 出现 '' / ipv4 两形态，导出/快照 canonical 才有稳定值。
	DnsFamily *string
}

// tcpDeadFieldReset 是 TCP 规则归一的单一事实源
// TCP 渲染不消费下列 HTTP 专属字段（buildTCPServer/buildTCPProxyRoute
// 实证），携带即弃置——与协议切换归零同格，防止死配置随快照/导出/复制
// 放大。三入口各自用适配器把字段接进本清单，新增字段只改这一处。
func tcpDeadFieldReset(protocol string, fields tcpDeadFields) {
	if protocol != "tcp" {
		return
	}
	deadFalse, deadZero, deadEmpty := false, 0, ""
	for _, target := range []*bool{fields.EnableTLS, fields.TLSHTTPRedirect, fields.EnableCompress, fields.LogEnabled, fields.CustomRoutesEnabled, fields.DynamicDNS} {
		if target != nil {
			*target = deadFalse
		}
	}
	if fields.TLSSource != nil {
		*fields.TLSSource = "manual"
	}
	// cookie 是 TCP 策略白名单外的唯一 HTTP-only 值；空串则来自手造/旧版本
	// 备份（v2 导入只替换 nil，不补显式 ""）。两者都归一为 DDL 默认策略
	// （weighted_round_robin，与导入/启动迁移 SQL 的 CASE 同终态），不清空。
	if fields.Strategy != nil && (*fields.Strategy == "cookie" || *fields.Strategy == "") {
		*fields.Strategy = "weighted_round_robin"
	}
	// dns_family 与 strategy 同格：TCP 无消费点，归一到建库默认 ipv4 而非空串
	// （空串会让同一终态裂成两种形态，导出/快照 canonical 不稳定）。
	if fields.DnsFamily != nil {
		*fields.DnsFamily = "ipv4"
	}
	for _, target := range []*string{fields.TLSCert, fields.TLSKey, fields.Domain, fields.HostHeader, fields.HealthCheckPath, fields.HealthCheckHost, fields.CompressTypes} {
		if target != nil {
			*target = deadEmpty
		}
	}
	for _, target := range []*int{
		fields.ACMEConfigID, fields.CAProviderID, fields.RequestBodyMaxSizeMB,
		fields.UpstreamKeepaliveTimeout, fields.ServerTokensHidden,
		fields.NTLMCompatible, fields.UpstreamForceHTTP1,
		fields.BlockPageStage1ID, fields.BlockPageStage1Status,
		fields.BlockPageStage3ID, fields.BlockPageStage3Status,
		fields.ProxyDialTimeout, fields.ProxyResponseHeaderTimeout,
		fields.ProxyReadTimeout, fields.ProxyWriteTimeout,
		fields.ProxyStreamTimeout, fields.ProxyFlushInterval,
		fields.ProxyStreamCloseDelay,
	} {
		if target != nil {
			*target = deadZero
		}
	}
}

// createRuleTCPDeadFields 接 CreateRule 的值字段；NTLMCompatible 留空——
// TCP 创建携带 NTLM 必须经 validateRuleFeatures 显式 400（2026-10-12 定稿）。
// HealthCheckHost 亦留空：HTTP-only 字段由保存门
// validateRulePayloadBeforeSave 显式 400（既有行为，与 NTLM 同格的「显式
// 携带即拒」），仅存量/复制/传输路径沉默归一。
// TCP 自愈族：代理超时族/自定义路由/动态上游/策略(cookie) 同样留空——
// Create 的代理超时负值先在调用点归一 0，其余显式死配置继续由
// validateRuleFeatures TCP 分支 400 点名；同协议编辑/复制路径才需全量自愈。
func createRuleTCPDeadFields(req *models.CreateRuleRequest) tcpDeadFields {
	return tcpDeadFields{
		EnableTLS:                &req.EnableTLS,
		TLSSource:                &req.TLSSource,
		TLSCert:                  &req.TLSCert,
		TLSKey:                   &req.TLSKey,
		ACMEConfigID:             &req.ACMEConfigID,
		CAProviderID:             &req.CAProviderID,
		Domain:                   &req.Domain,
		TLSHTTPRedirect:          &req.TLSHTTPRedirect,
		HostHeader:               &req.HostHeader,
		HealthCheckPath:          &req.HealthCheckPath,
		EnableCompress:           &req.EnableCompress,
		CompressTypes:            &req.CompressTypes,
		RequestBodyMaxSizeMB:     &req.RequestBodyMaxSizeMB,
		UpstreamKeepaliveTimeout: &req.UpstreamKeepaliveTimeout,
		ServerTokensHidden:       &req.ServerTokensHidden,
		UpstreamForceHTTP1:       &req.UpstreamForceHTTP1,
		BlockPageStage1ID:        &req.BlockPageStage1ID,
		BlockPageStage1Status:    &req.BlockPageStage1Status,
		BlockPageStage3ID:        &req.BlockPageStage3ID,
		BlockPageStage3Status:    &req.BlockPageStage3Status,
		LogEnabled:               &req.LogEnabled,
		DnsFamily:                &req.DnsFamily,
	}
}

// updateRuleTCPDeadFields 接 UpdateRule 合并后的指针字段（调用点已保证非 nil）。
func updateRuleTCPDeadFields(req *models.UpdateRuleRequest) tcpDeadFields {
	return tcpDeadFields{
		EnableTLS:                req.EnableTLS,
		TLSSource:                &req.TLSSource,
		TLSCert:                  &req.TLSCert,
		TLSKey:                   &req.TLSKey,
		ACMEConfigID:             &req.ACMEConfigID,
		CAProviderID:             req.CAProviderID,
		Domain:                   &req.Domain,
		TLSHTTPRedirect:          req.TLSHTTPRedirect,
		HostHeader:               req.HostHeader,
		HealthCheckPath:          req.HealthCheckPath,
		HealthCheckHost:          req.HealthCheckHost,
		EnableCompress:           req.EnableCompress,
		CompressTypes:            &req.CompressTypes,
		RequestBodyMaxSizeMB:     req.RequestBodyMaxSizeMB,
		UpstreamKeepaliveTimeout: req.UpstreamKeepaliveTimeout,
		ServerTokensHidden:       req.ServerTokensHidden,
		// NTLMCompatible 有意留空：TCP 显式携带由保存门 400 点名，未携带的
		// 存量死值由 UpdateRule 调用点按「是否显式提供」自愈归零——通用归一
		// 无法区分二者，会把显式 1 静默改写成 0。
		UpstreamForceHTTP1:    req.UpstreamForceHTTP1,
		BlockPageStage1ID:     req.BlockPageStage1ID,
		BlockPageStage1Status: req.BlockPageStage1Status,
		BlockPageStage3ID:     req.BlockPageStage3ID,
		BlockPageStage3Status: req.BlockPageStage3Status,
		LogEnabled:            req.LogEnabled,
		// TCP 自愈族：同协议编辑自愈族（调用点已保证非 nil）——
		// 存量死值不再让无关编辑恒 400 死端。
		ProxyDialTimeout:           req.ProxyDialTimeout,
		ProxyResponseHeaderTimeout: req.ProxyResponseHeaderTimeout,
		ProxyReadTimeout:           req.ProxyReadTimeout,
		ProxyWriteTimeout:          req.ProxyWriteTimeout,
		ProxyStreamTimeout:         req.ProxyStreamTimeout,
		ProxyFlushInterval:         req.ProxyFlushInterval,
		ProxyStreamCloseDelay:      req.ProxyStreamCloseDelay,
		CustomRoutesEnabled:        req.CustomRoutesEnabled,
		DynamicDNS:                 req.DynamicDNS,
		Strategy:                   &req.Strategy,
		DnsFamily:                  &req.DnsFamily,
	}
}

// storedRuleTCPDeadFields 接 DuplicateRule 的存量源行。
func storedRuleTCPDeadFields(rule *models.LbRule) tcpDeadFields {
	return tcpDeadFields{
		EnableTLS:                &rule.EnableTLS,
		TLSSource:                &rule.TLSSource,
		TLSCert:                  &rule.TLSCert,
		TLSKey:                   &rule.TLSKey,
		ACMEConfigID:             &rule.ACMEConfigID,
		CAProviderID:             &rule.CAProviderID,
		Domain:                   &rule.Domain,
		TLSHTTPRedirect:          &rule.TLSHTTPRedirect,
		HostHeader:               &rule.HostHeader,
		HealthCheckPath:          &rule.HealthCheckPath,
		HealthCheckHost:          &rule.HealthCheckHost,
		EnableCompress:           &rule.EnableCompress,
		CompressTypes:            &rule.CompressTypes,
		RequestBodyMaxSizeMB:     &rule.RequestBodyMaxSizeMB,
		UpstreamKeepaliveTimeout: &rule.UpstreamKeepaliveTimeout,
		ServerTokensHidden:       &rule.ServerTokensHidden,
		NTLMCompatible:           &rule.NTLMCompatible,
		UpstreamForceHTTP1:       &rule.UpstreamForceHTTP1,
		BlockPageStage1ID:        &rule.BlockPageStage1ID,
		BlockPageStage1Status:    &rule.BlockPageStage1Status,
		BlockPageStage3ID:        &rule.BlockPageStage3ID,
		BlockPageStage3Status:    &rule.BlockPageStage3Status,
		LogEnabled:               &rule.LogEnabled,
		// TCP 自愈族：TCP 源行携带的 HTTP 专属代理/路由/策略死值不得
		// 原样放大到副本（复制路径此前让 tcp+cookie、tcp+proxy 超时、
		// tcp+自定义路径的存量行复制即 400 死端）。
		ProxyDialTimeout:           &rule.ProxyDialTimeout,
		ProxyResponseHeaderTimeout: &rule.ProxyResponseHeaderTimeout,
		ProxyReadTimeout:           &rule.ProxyReadTimeout,
		ProxyWriteTimeout:          &rule.ProxyWriteTimeout,
		ProxyStreamTimeout:         &rule.ProxyStreamTimeout,
		ProxyFlushInterval:         &rule.ProxyFlushInterval,
		ProxyStreamCloseDelay:      &rule.ProxyStreamCloseDelay,
		CustomRoutesEnabled:        &rule.CustomRoutesEnabled,
		DynamicDNS:                 &rule.DynamicDNS,
		Strategy:                   &rule.Strategy,
		DnsFamily:                  &rule.DnsFamily,
	}
}

// request_body_max_size_mb 与 Coraza 可编译的 SecRequestBodyLimit 上限一致。
const maxRequestBodySizeMB = 1024

// validateRuleRequestBodyMaxSizeMB 是 request_body_max_size_mb 的单一值域门
// （0-1024；0=不限制/跟随全局），Create/Update/Duplicate 三入口共用。
func validateRuleRequestBodyMaxSizeMB(value int) error {
	if value < 0 || value > maxRequestBodySizeMB {
		return fmt.Errorf("请求体大小限制必须在 0-%d MB 之间", maxRequestBodySizeMB)
	}
	return nil
}

// 规则文本列长度上限（规则文本长度上限，Ruling：取 DDL 声明值）：lb_rules.name
// VARCHAR(100)、description VARCHAR(300)（db.go 建表/重建 DDL 两处同值）。
// SQLite 不强制 VARCHAR 长度，无本门时超长文本可经 API 落库并随导出/快照/
// 备份放大。按 rune 计数（与前端 maxlength 的字符语义一致）。
const (
	maxRuleNameRunes        = 100
	maxRuleDescriptionRunes = 300
)

// validateRuleTextLengths 是 name/description 长度门的单一事实源
// （Create/Update/Duplicate 三入口共用）。
func validateRuleTextLengths(name, description string) error {
	if n := utf8.RuneCountInString(name); n > maxRuleNameRunes {
		return fmt.Errorf("规则名称过长（最多 %d 个字符，当前 %d 个）", maxRuleNameRunes, n)
	}
	if n := utf8.RuneCountInString(description); n > maxRuleDescriptionRunes {
		return fmt.Errorf("规则描述过长（最多 %d 个字符，当前 %d 个）", maxRuleDescriptionRunes, n)
	}
	return nil
}

// ruleDuplicateName 生成副本名「源名（副本）」并保证累积后缀不突破长度
// 上限（规则文本长度上限）：反复复制时源名本身已含「（副本）」后缀——截断基名而不是
// 后缀，否则后缀会被截掉导致副本名无法辨识。
func ruleDuplicateName(sourceName string) string {
	const suffix = "（副本）"
	base := []rune(sourceName)
	if limit := maxRuleNameRunes - utf8.RuneCountInString(suffix); len(base) > limit {
		base = base[:limit]
	}
	return string(base) + suffix
}

// duplicateRulePayloadRequest 把存量源行投影为共享保存输入，供
// validateRulePayloadBeforeSave 复用字段层校验（上游 host/端口/权重/查重/
// 健康检查/ACME 引用）。复制语义放宽 Create 表单门：零上游、零启用上游的
// 存量行合法（副本默认禁用，可事后补配），以一条探针启用上游满足「至少
// 一个上游 + 至少一个启用上游」两门后，其余字段仍逐项校验。
func duplicateRulePayloadRequest(rule models.LbRule) models.CreateRuleRequest {
	req := models.CreateRuleRequest{
		Name:                          rule.Name,
		Description:                   rule.Description,
		Protocol:                      rule.Protocol,
		Domain:                        rule.Domain,
		ListenPort:                    rule.ListenPort,
		Strategy:                      rule.Strategy,
		DynamicDNS:                    rule.DynamicDNS,
		EnableDnsServer:               rule.EnableDnsServer,
		DnsServer:                     rule.DnsServer,
		DnsFamily:                     rule.DnsFamily,
		HealthCheckPath:               rule.HealthCheckPath,
		HealthCheckInterval:           rule.HealthCheckInterval,
		HealthCheckTimeout:            rule.HealthCheckTimeout,
		HealthCheckUnhealthyThreshold: rule.HealthCheckUnhealthyThreshold,
		HealthCheckHealthyThreshold:   rule.HealthCheckHealthyThreshold,
		EnableActiveHealthCheck:       rule.EnableActiveHealthCheck,
		TCPHealthCheckPort:            rule.TCPHealthCheckPort,
		TCPProxyProtocol:              rule.TCPProxyProtocol,
		TCPTryDuration:                rule.TCPTryDuration,
		TCPTryInterval:                rule.TCPTryInterval,
		RequestBodyMaxSizeMB:          rule.RequestBodyMaxSizeMB,
		UpstreamKeepaliveTimeout:      rule.UpstreamKeepaliveTimeout,
		ServerTokensHidden:            rule.ServerTokensHidden,
		NTLMCompatible:                rule.NTLMCompatible,
		UpstreamForceHTTP1:            rule.UpstreamForceHTTP1,
		CustomRoutesEnabled:           rule.CustomRoutesEnabled,
		ProxyDialTimeout:              rule.ProxyDialTimeout,
		ProxyResponseHeaderTimeout:    rule.ProxyResponseHeaderTimeout,
		ProxyReadTimeout:              rule.ProxyReadTimeout,
		ProxyWriteTimeout:             rule.ProxyWriteTimeout,
		ProxyStreamTimeout:            rule.ProxyStreamTimeout,
		ProxyFlushInterval:            rule.ProxyFlushInterval,
		ProxyStreamCloseDelay:         rule.ProxyStreamCloseDelay,
		PathRules:                     rule.PathRules,
		HostHeader:                    rule.HostHeader,
		HealthCheckHost:               rule.HealthCheckHost,
		EnableTLS:                     rule.EnableTLS,
		TLSSource:                     rule.TLSSource,
		ACMEConfigID:                  rule.ACMEConfigID,
		CAProviderID:                  rule.CAProviderID,
		TLSCert:                       rule.TLSCert,
		TLSKey:                        rule.TLSKey,
		TLSHTTPRedirect:               rule.TLSHTTPRedirect,
		EnableCompress:                rule.EnableCompress,
		CompressTypes:                 rule.CompressTypes,
		LogEnabled:                    rule.LogEnabled,
		// 阶段页引用是「存量保留值」：与 UpdateRule 的 nil=保留现值口径
		// 一致（页面存在性由页删除侧引用检查与渲染侧「已失效」回落承担），
		// 复制路径不把存量行重新送进存在性门（否则存量坏引用使复制恒 400，
		// 而副本本就默认禁用、页面修复后可再启用）。
	}
	req.Upstreams = append(req.Upstreams, rule.Upstreams...)
	hasEnabled := false
	for _, upstream := range req.Upstreams {
		if upstream.Enabled {
			hasEnabled = true
			break
		}
	}
	if !hasEnabled {
		req.Upstreams = append(req.Upstreams, models.Upstream{
			Host: "duplicate-probe.invalid", Port: 1, Weight: 1, Enabled: true, Protocol: rule.Protocol,
		})
	}
	return req
}

// validateDuplicateRulePayload 是复制路径的字段层校验：源行的
// 上游 host/端口/权重/查重/健康检查与请求体大小等坏形态必须 400 点名源
// 规则，不得原样放大到副本。
func (h *Handlers) validateDuplicateRulePayload(rule models.LbRule) error {
	return h.validateRulePayloadBeforeSave(duplicateRulePayloadRequest(rule))
}

// 数据库即唯一事实源契约（CreateRule/UpdateRule 保存路径，2026-09-06 裁定 ④'）：
//  1. 三层校验：后端字段校验（validateRuleFeatures/validateRulePayloadBeforeSave）先于
//     任何写库；Caddy 层由 applyFromTxNote 内的 CLI 校验（真 validate-only）+ 事务内
//     ApplyConfigFromTx（最终门控）承担，校验与应用的输入同为事务视图最终渲染——
//     校验不过不落库；
//  2. 写库失败以「写入数据库失败（…）: <原因>」明确回报给保存方；
//  3. Caddy 配置只能从事务内渲染（ApplyConfigFromTx），应用失败即回滚事务并返回 400 +
//     具体原因，数据库与运行配置不会因保存路径产生不一致。
func (h *Handlers) CreateRule(c *gin.Context) {

	// 导入窗口 fast-fail：规则写要等 caddyOpMu（导入全程持有，可达分钟级），
	// 排队到导入后再按导入后的库校验/落库会让客户端看到「提交的是哪一版」
	// 漂移（无数据丢失但语义错乱）。门必须先于请求体读取与取锁。
	if rejectWriteDuringImport(c, "执行规则写操作") {
		return
	}
	// 限制请求体大小防止 OOM（与 config_backup.go limitConfigImportBody 一致策略）。
	const maxCreateRuleBodyBytes int64 = 1 << 20 // 1MB
	if c.Request.ContentLength > maxCreateRuleBodyBytes {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "请求体过大"})
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxCreateRuleBodyBytes)
	// io.ReadAll(c.Request.Body) 在 ShouldBindJSON 之后调用永远读到空。
	// 改为先读原始 body 再放回，确保错误日志能记录到导致解析失败的实际请求内容。
	rawBody, readErr := io.ReadAll(c.Request.Body)
	c.Request.Body = io.NopCloser(bytes.NewReader(rawBody))
	// MaxBytesReader 截断(chunked/未知 ContentLength 时快路径
	// 不触发)映射 413,与 PutCaddyConfig/导入路径同口径——预读会吞掉
	// MaxBytesError 让 bind 落在「unexpected EOF」的 400 上,须在预读处判。
	if isRequestBodyTooLarge(readErr) {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "请求体过大"})
		return
	}
	var req models.CreateRuleRequest
	// ShouldBindBodyWith（缓存请求体）供 weight 省略探针二次解码。
	if err := c.ShouldBindBodyWith(&req, binding.JSON); err != nil {
		if isRequestBodyTooLarge(err) {
			c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "请求体过大"})
			return
		}
		// 畸形 JSON 的请求体可能含
		// tls_key/tls_cert/password，运行日志对所有登录用户可读——原实现
		// 只截 512B 仍把密钥前缀写入日志。改为只记录结构性元信息，正文
		// 一律不落日志。
		services.Logf("error", "CreateRule bind error: %v, body_length: %d, content_type: %s（请求体正文不记录，避免证书/密钥泄漏）",
			err, len(rawBody), c.GetHeader("Content-Type"))
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("Invalid request: %v", err)})
		return
	}

	// 省略 weight 的上游行落默认 1（显式 0 由写侧校验 400）。
	applyOmittedUpstreamWeightDefaults(c, req.Upstreams)

	// 与 UpdateRule/DeleteRule 同一锁序：先 caddyOpMu 后 DB，冲突检查与写入串行化
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	services.Logf("info", "CreateRule bind success: name=%s, protocol=%s, port=%d, upstreams=%d", req.Name, req.Protocol, req.ListenPort, len(req.Upstreams))

	if req.Name == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "名称不能为空"})
		return
	}
	// 规则文本长度上限：name/description 长度门（DDL 声明值，SQLite 不强制）。
	if err := validateRuleTextLengths(req.Name, req.Description); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
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

	// CreateRule 补归一——
	// TCP 规则不终结入站 TLS，保留 enable_tls=1 落库成死形态行（tcp+acme 组合
	// 还会产生永不消费证书的僵尸续签任务）。与 UpdateRule 归一分支同语义。
	// 归一前移至全部 TLS 相关校验（来源白名单/手动证书
	// 材料/ACME 域名形状）之前——归一后 EnableTLS=false，校验自然跳过；此前
	// TCP+enable_tls:true+空/bogus tls_source 创建恒 400 而同形态更新放行 200。
	// +：HTTP 专属死配置字段（含
	// tls_http_redirect/domain/upstream_force_http1）经同一 tcpDeadFieldReset
	// 清单弃置——TCP 渲染零消费（buildTCPServer/buildTCPProxyRoute grep 实证），
	// 携带即归一 0，不随快照/导出/复制放大。NTLM 兼容是清单的唯一例外：
	// TCP 创建携带 ntlm_compatible=1 由保存门（validateRuleFeatures）显式 400
	// 拒绝，不做静默弃置（2026-10-12 定稿），故 create 适配器不提供该字段。
	if req.Protocol == "tcp" {
		for _, value := range []*int{
			&req.ProxyDialTimeout, &req.ProxyResponseHeaderTimeout,
			&req.ProxyReadTimeout, &req.ProxyWriteTimeout,
			&req.ProxyStreamTimeout, &req.ProxyFlushInterval, &req.ProxyStreamCloseDelay,
		} {
			if *value < 0 {
				*value = 0
			}
		}
		tcpDeadFieldReset(req.Protocol, createRuleTCPDeadFields(&req))
	} else if req.Protocol == "http" {
		// HTTP 渲染不消费 TCP-only 字段，创建时显式弃置。
		req.TCPProxyProtocol = false
		req.TCPHealthCheckPort = 0
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

	// TCP 渲染零消费 DnsFamily；协议切换路径会清空该列。仅 HTTP 新规则补
	// 默认，避免同一 TCP 终态出现 ipv4/'' 两种形态。
	if req.Protocol == "http" && req.DnsFamily == "" {
		req.DnsFamily = "ipv4"
	}

	// 创建即禁用（enabled 显式 false）跳过冲突门——禁用规则不渲染、
	// 零冲突（UI 复制向导按预览「禁用」态创建副本，旧码被下方域名/端口门恒
	// 400）；启用方向由 EnableRule 既有二次门把守（与 DuplicateRule 无门、
	// UpdateRule 启用方向检查同构）。enabled=true/缺省的创建行为完全不变。
	creatingDisabled := req.Enabled != nil && !*req.Enabled

	if err := h.validateRuleListenPortForSave(req.Protocol, req.ListenPort); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if !creatingDisabled {
		if err := h.validatePortFromDB(req.Protocol, req.ListenPort, ""); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}

	// Domain uniqueness: HTTP/HTTPS rules cannot share the same domain.
	if req.Protocol == "http" && req.Domain != "" && !creatingDisabled {
		existing, err := enabledRuleDomainConflict(req.Domain, req.ListenPort, "")
		if err != nil {
			services.Logf("error", "CreateRule domain conflict query failed for domain=%s: %v", req.Domain, err)
			recordRuleWriteFailure(c, "创建", "检查域名冲突失败", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "检查域名冲突失败"})
			return
		}
		if existing {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "域名已被其他 HTTP/HTTPS 规则使用"})
			return
		}
		shadowRule, shadowDomain, err := queryRedirectShadowConflict(req.Domain, req.ListenPort, req.EnableTLS, req.TLSHTTPRedirect, "")
		if err != nil {
			services.Logf("error", "CreateRule redirect shadow query failed for domain=%s: %v", req.Domain, err)
			recordRuleWriteFailure(c, "创建", "检查域名跳转冲突失败", err)
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
	// 库值唯一真相（批 1+2）：健康检查 interval/timeout 为类型①值型列——
	// 0→10/2 的写侧静默归一废除（0 由 validateRulePayloadBeforeSave 的 <1
	// 边界 400；前端表单初值=默认，清空提交被拦）。
	// 非 acme_dns 来源不消费 acme_config_id（签发/渲染均按 tls_source
	// 分流）——清理跨模式死引用，避免随导出/快照放大不可达配置。条件按
	// 「非 acme_dns」而非「== manual」：空来源（API 创建 TLS 关闭且未选来源、
	// 旧版本行）同样不消费 ACME 引用。
	if req.TLSSource != "acme_dns" {
		req.ACMEConfigID = 0
	}
	// 生效来源非 manual 时一律弃置证书材料——API/MCP/导入
	// 给 acme 行携带 tls_cert/tls_key 时私钥正文会随导出/备份/快照放大（渲染
	// 按 tls_source 分流零消费）。与 UpdateRule 的对称清理同口径。
	if req.TLSSource != "manual" {
		req.TLSCert, req.TLSKey = "", ""
	}
	// Validate TLS certificate if provided (manual source only)
	var certWarnings []string
	if req.EnableTLS && req.TLSSource == "manual" {
		if strings.TrimSpace(req.TLSCert) == "" || strings.TrimSpace(req.TLSKey) == "" {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "手动证书模式下必须提供 TLS 证书和私钥"})
			return
		}
		if err := validateTLSCertificate(req.TLSCert, req.TLSKey); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "TLS 证书校验失败: " + err.Error()})
			return
		}
		// 链完整性/域名覆盖质量警告(不阻断)——配对合法性仍由上方
		// validateTLSCertificate 硬校验;警告随成功审计留痕(与导入侧同格)。
		certWarnings = tlsCertificateWarnings(req.TLSCert, req.TLSKey, req.Domain)
		for _, warning := range certWarnings {
			services.Logf("warn", "CreateRule manual TLS certificate warning (rule %s, domain %s): %s", req.Name, req.Domain, warning)
		}
	}

	// gzip 默认仅 http 注入——TCP 归一（创建头部）已清零
	// CompressTypes，此处不重建死配置（压缩是 HTTP 渲染语义）。
	if req.Protocol != "tcp" && req.CompressTypes == "" {
		req.CompressTypes = "gzip"
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
	// 后端字段层校验（三层校验第 2 层；Caddy 层由 applyFromTxNote 的 CLI 预检
	// + 事务内应用承担，裁定 2026-09-06 ④'）。本门同时
	// 承担 tls_source 白名单与请求体上限——Create/Update 入口的同款本地检查
	// 已删除（单源，杜绝两处文案/边界漂移）。
	if err := h.validateRulePayloadBeforeSave(req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	// 同端口 TLS/明文混布拦截(创建方向)。创建即禁用
	// 同样跳过——禁用规则不进入监听器渲染，启用方向由 EnableRule 同函数把守。
	if req.Protocol == "http" && !creatingDisabled {
		if err := checkPortTLSMix("", req.ListenPort, req.EnableTLS); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}

	userIDInt := contextUserID(c)

	// Generate caddy_id for @id-based management
	caddyID, err := services.GenerateCaddyID()
	if err != nil {
		recordRuleWriteFailure(c, "创建", "生成规则 ID 失败", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "生成规则 ID 失败"})
		return
	}

	// 运行配置快照：仅用于事务内应用失败的恢复（裁定 ④'：保存路径无预校验
	// 探针，快照摄取时点不再受副作用约束；Caddy 级校验由 applyFromTxNote 内
	// 的 CLI 层承担）。
	runtimeSnapshot, snapErr := h.snapshotImportRuntime([]string{caddyID})
	if snapErr != nil {
		h.respondRuleSnapshotError(c, "创建", snapErr)
		return
	}
	if req.Protocol == "http" && req.EnableTLS && req.TLSSource == "acme_dns" {
		resolvedCAProviderID, resolveErr := services.ResolveCAProviderID(req.CAProviderID)
		if resolveErr != nil {
			// 单源分类：「跟随默认」解析不到任何启用提供商是可执行的配置状态
			// （400 + 可操作指引），DB 故障（驱动/IO）才走 500 + 失败审计。
			respondCAProviderResolveFailure(c, "创建", resolveErr)
			return
		}
		req.CAProviderID = resolvedCAProviderID
	} else {
		req.CAProviderID = 0
	}

	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		recordRuleWriteFailure(c, "创建", "开启数据库事务失败", err)
		writeInternalError(c, http.StatusInternalServerError, "开启数据库事务失败", err)
		return
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				services.Logf("error", "CreateRule transaction rollback failed for caddy_id=%s: %v", caddyID, rollbackErr)
			}
		}
	}()

	// enabled 指针化落库——缺省=创建即启用（行为），显式 false=禁用
	//（UI 复制向导按预览「禁用」态创建副本）。
	enabledVal := 1
	if req.Enabled != nil && !*req.Enabled {
		enabledVal = 0
	}

	// 主动健康检查未启用时其专属字段渲染零消费——保存侧归一清零（死配置
	// 不随导出/备份/快照放大），清零结果进成功审计披露。
	clearedDeadHealthCheck := normalizeInactiveHealthCheckFields(req.EnableActiveHealthCheck,
		&req.HealthCheckPath, &req.HealthCheckHost, &req.TCPHealthCheckPort)

	// INSERT 列清单与值投影走唯一事实源（services.LbRuleInsertSQL/
	// LbRuleInsertArgs）——新建排除 id/created_at/updated_by（主键自增分配、
	// created_at 走 schema 默认、updated_by 留 NULL 待首次更新），列形态与
	// 复制/集群镜像/快照导出同源自此结构性保证。
	rule := models.LbRule{
		CaddyID: caddyID, Name: req.Name, Description: req.Description, Protocol: req.Protocol,
		Domain: req.Domain, ListenPort: req.ListenPort, Strategy: req.Strategy,
		DynamicDNS: req.DynamicDNS, EnableDnsServer: req.EnableDnsServer, DnsServer: req.DnsServer, DnsFamily: req.DnsFamily,
		HealthCheckPath: req.HealthCheckPath, HealthCheckInterval: req.HealthCheckInterval, HealthCheckTimeout: req.HealthCheckTimeout,
		HealthCheckUnhealthyThreshold: req.HealthCheckUnhealthyThreshold, HealthCheckHealthyThreshold: req.HealthCheckHealthyThreshold,
		EnableActiveHealthCheck: req.EnableActiveHealthCheck, TCPHealthCheckPort: req.TCPHealthCheckPort,
		TCPProxyProtocol: req.TCPProxyProtocol, TCPTryDuration: req.TCPTryDuration, TCPTryInterval: req.TCPTryInterval,
		RequestBodyMaxSizeMB: req.RequestBodyMaxSizeMB, UpstreamKeepaliveTimeout: req.UpstreamKeepaliveTimeout,
		ServerTokensHidden: req.ServerTokensHidden, NTLMCompatible: req.NTLMCompatible, UpstreamForceHTTP1: req.UpstreamForceHTTP1,
		CustomRoutesEnabled: features.CustomRoutesEnabled,
		ProxyDialTimeout:    features.ProxyDialTimeout, ProxyResponseHeaderTimeout: features.ProxyResponseHeaderTimeout,
		ProxyReadTimeout: features.ProxyReadTimeout, ProxyWriteTimeout: features.ProxyWriteTimeout,
		ProxyStreamTimeout: features.ProxyStreamTimeout, ProxyFlushInterval: features.ProxyFlushInterval,
		ProxyStreamCloseDelay: features.ProxyStreamCloseDelay,
		HostHeader:            req.HostHeader, HealthCheckHost: req.HealthCheckHost,
		EnableTLS: req.EnableTLS, TLSSource: req.TLSSource, ACMEConfigID: req.ACMEConfigID, CAProviderID: req.CAProviderID,
		TLSCert: req.TLSCert, TLSKey: req.TLSKey, TLSHTTPRedirect: req.TLSHTTPRedirect,
		EnableCompress: req.EnableCompress, CompressTypes: req.CompressTypes,
		Enabled: enabledVal == 1, LogEnabled: req.LogEnabled, CreatedBy: int(userIDInt),
		UpdatedAt:         models.JSONNullTime{NullTime: sql.NullTime{Time: time.Now().UTC(), Valid: true}},
		BlockPageStage1ID: req.BlockPageStage1ID, BlockPageStage1Status: req.BlockPageStage1Status,
		BlockPageStage3ID: req.BlockPageStage3ID, BlockPageStage3Status: req.BlockPageStage3Status,
	}
	insertColumns := services.LbRuleInsertColumns("id", "created_at", "updated_by")
	_, err = tx.Exec(services.LbRuleInsertSQL(insertColumns), services.LbRuleInsertArgs(&rule, insertColumns)...)

	if err != nil {
		rollbackRuleWriteTx(tx, "CreateRule", caddyID)
		services.Logf("error", "CreateRule database error: %v", err)
		recordRuleWriteFailure(c, "创建", "写入数据库失败（创建规则）", err)
		writeInternalError(c, http.StatusInternalServerError, "写入数据库失败（创建规则）", nil)
		return
	}

	for _, u := range req.Upstreams {
		// weight<1 已由 validateRulePayloadBeforeSave 响亮拒绝
		//（0→1 静默归一废除），此处不再兜底归一。
		if u.Protocol == "" {
			if req.Protocol == "tcp" {
				u.Protocol = "tcp"
			} else {
				u.Protocol = "http"
			}
		}
		// 非协议族的上游 protocol（如 HTTP 规则携带 tls，此前
		// 静默当 http 处理，与 TCP 行为不对称）已在 validateRulePayloadBeforeSave
		// 显式 400 拒绝——此处 INSERT 只写归一后的合法值。
		_, err = tx.Exec(`INSERT INTO upstreams (rule_id, host, port, weight, dynamic_dns, enabled, protocol, max_connections, origin_domain)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			caddyID, u.Host, u.Port, u.Weight, false /* dynamic_dns 废弃列：写侧恒 0，渲染只读规则级 */, u.Enabled, u.Protocol, u.MaxConnections, u.OriginDomain)
		if err != nil {
			rollbackRuleWriteTx(tx, "CreateRule", caddyID)
			services.Logf("error", "CreateRule upstream insert error: %v", err)
			recordRuleWriteFailure(c, "创建", "写入数据库失败（创建上游服务器）", err)
			writeInternalError(c, http.StatusInternalServerError, "写入数据库失败（创建上游服务器）", nil)
			return
		}
	}
	if err := replacePathRulesTx(caddyWriteCtx(c), tx, caddyID, features.PathRules); err != nil {
		rollbackRuleWriteTx(tx, "CreateRule", caddyID)
		services.Logf("error", "CreateRule path_rules replace error: %v", err)
		recordRuleWriteFailure(c, "创建", "写入数据库失败（创建自定义路径规则）", err)
		writeInternalError(c, http.StatusInternalServerError, "写入数据库失败（创建自定义路径规则）", nil)
		return
	}

	reloadNote, applyErr := h.applyFromTxNote(c, tx, txReloadDetail("rule_create", caddyID), true)
	if applyErr != nil {
		// 恢复收口（四步，与配置域同口径横幅事实源）：①显式回滚事务
		// （释放 SQLite 写锁——已提交视图重渲染读 db.DB 不被阻塞；defer
		// 回滚对 ErrTxDone 幂等）；②运行配置+证书文件按请求前快照回退
		// （同字节短路安全——候选未生效时零 /load；新规则证书文件快照为
		// 空对即删除孤儿）；③LKG 钉回已提交视图（零 /load——补偿链的
		// restoreImportRuntime→ApplyConfig 会在恢复 /load 成功时把「请求前
		// 运行配置」写进 LKG，而该快照可能是漂移形态，重启兜底不得回放）；
		// ④横幅持久化（respondRuleApplyError 内）。
		var sideErr error
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			sideErr = fmt.Errorf("回滚未提交事务失败: %w", rbErr)
		}
		runtimeErr := h.restoreImportRuntime(runtimeSnapshot)
		sideErr = errors.Join(sideErr, h.pinLastGoodAfterCompensation())
		h.respondRuleApplyError(c, applyErr, runtimeErr, sideErr, "创建")
		return
	}
	if err := commitTx(tx); err != nil {
		//  +：commit 失败与 finishTxApply/UpdateConfig
		// 同收口——统一恢复回滚事务、按已提交视图重渲染并 /load，双失败时
		// 仍把已提交字节写回 LKG（restoreImportRuntime 只用运行时快照，恢复
		// /load 失败会让 LKG 滞留未提交内容）。
		recovery := h.recoverCommittedViewAfterCommitFailure(tx)
		// 新规则证书文件可能已在事务内渲染时物化。Commit 返回错误无法区分
		// 「未提交」与「已提交但确认丢失」（commitUncertainLabel）——清理按
		// 已提交视图的存在性判定（见 helper 注释）。证书清理失败属附带失败：
		// 运行配置是否已恢复与它无关。
		certCleanupErr := cleanupUncommittedRuleCertsAfterCommitFailure(caddyID)
		services.Logf("error", "CreateRule transaction commit error: %v", err)
		// 提交后失败的两条留痕：真实 /load 已发生（重载审计）+ 恢复失败时
		// 库态/运行态分叉的横幅（刷新后唯一可见信号）。
		reloadNote.auditReload()
		h.recordPostCommitRestoreFailure(commitSaveFailedSubject, err, recovery.runtime, errors.Join(recovery.db, certCleanupErr))
		// 提交后失败审计：Explicit 审计策略下提交后失败必须留痕（与
		// respondRuleApplyError / EnableRule failEnableWithStatus 同口径）。
		recordAudit(c, "创建失败", "负载规则", services.FormatAuditDetail(
			services.AuditRulePart(caddyID), commitUncertainLabel+"："+errors.Join(err, recovery.err(), certCleanupErr).Error(), services.AuditResultPart("failure")))
		writeInternalError(c, http.StatusInternalServerError, commitUncertainLabel, nil)
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
				// 附带：ErrTxDone 判定统一 errors.Is（与
				// 本文件其余五处回滚守卫同格，裸 != 不穿透包装）。
				if rollbackErr := cleanupTx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
					services.Logf("error", "CreateRule compensation rollback failed for caddy_id=%s: %v", caddyID, rollbackErr)
				}
			}
		}()
		for _, statement := range []string{
			"DELETE FROM cert_jobs WHERE rule_id = ?",
			"DELETE FROM security_policy_bindings WHERE rule_caddy_id = ?",
			"DELETE FROM upstreams WHERE rule_id = ?",
			"DELETE FROM path_rules WHERE rule_id = ?",
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
	restoreCreatedRule := func() (runtimeErr, sideErr error) {
		// 顺序不可换：DB 回退（removeCreatedRule）完成后才能钉回——已提交
		// 视图不得含本请求新建的规则。运行配置恢复与附带失败（DB 回退、
		// LKG 钉回）分通道返回：只有前者决定横幅两态标签。
		runtimeErr = h.restoreImportRuntime(runtimeSnapshot)
		sideErr = errors.Join(removeCreatedRule(), h.pinLastGoodAfterCompensation())
		return runtimeErr, sideErr
	}
	if enabledVal == 1 && req.EnableTLS && req.TLSSource == "acme_dns" && req.Protocol == "http" && req.Domain != "" {
		qm := services.GetCAQueueManager()
		if qm == nil {
			runtimeErr, sideErr := restoreCreatedRule()
			if restoreErr := errors.Join(runtimeErr, sideErr); restoreErr != nil {
				services.Logf("error", "补偿失败: CreateRule ACME 补偿未完成 for caddy_id=%s: %v", caddyID, restoreErr)
			}
			// 提交后失败的两条留痕：真实 /load 已发生（重载审计）+ 补偿
			// 恢复失败时库态/运行态分叉的横幅。
			reloadNote.auditReload()
			h.recordPostCommitRestoreFailure(certJobEnqueueFailedSubject, errors.New("证书任务入队失败：CA 队列未初始化"), runtimeErr, sideErr)
			// 提交后失败审计：提交后失败（含补偿）必须落操作审计。
			detail := "证书任务入队失败：CA 队列未初始化，已回滚创建"
			if restoreErr := errors.Join(runtimeErr, sideErr); restoreErr != nil {
				detail = "证书任务入队失败（CA 队列未初始化），补偿恢复失败: " + restoreErr.Error()
			}
			recordAudit(c, "创建失败", "负载规则", services.FormatAuditDetail(
				services.AuditRulePart(caddyID), detail, services.AuditResultPart("failure")))
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "CA 队列未初始化"})
			return
		}
		if _, err := services.CreateOrRequeueCertJob(caddyID, req.Domain, req.CAProviderID, qm); err != nil {
			runtimeErr, sideErr := restoreCreatedRule()
			if restoreErr := errors.Join(runtimeErr, sideErr); restoreErr != nil {
				services.Logf("error", "补偿失败: CreateRule ACME 补偿未完成 for caddy_id=%s: %v", caddyID, restoreErr)
			}
			reloadNote.auditReload()
			h.recordPostCommitRestoreFailure(certJobEnqueueFailedSubject, err, runtimeErr, sideErr)
			// 提交后失败审计：入队失败 + 补偿结果一并留痕（补偿失败时点名）。
			detail := "证书任务入队失败，已回滚创建: " + err.Error()
			if restoreErr := errors.Join(runtimeErr, sideErr); restoreErr != nil {
				detail = "证书任务入队失败，补偿恢复失败: " + errors.Join(err, restoreErr).Error()
			}
			recordAudit(c, "创建失败", "负载规则", services.FormatAuditDetail(
				services.AuditRulePart(caddyID), detail, services.AuditResultPart("failure")))
			// 证书签发任务未运行（队列 paused/inactive）与手工签发
			// 同口径 409，不再折成 500 误报内部故障。
			status, message := certEnqueueErrorResponse("创建证书任务失败", err)
			c.JSON(status, models.APIResponse{Code: status, Message: message})
			return
		}
	}

	services.Logf("info", "Rule created with caddy_id=%s", caddyID)
	createAuditParts := []string{services.AuditRulePart(caddyID), req.Name, fmt.Sprintf("协议：%s", req.Protocol), fmt.Sprintf("端口：%d", req.ListenPort), req.Domain}
	if hint := inactiveHealthCheckAuditHint(clearedDeadHealthCheck); hint != "" {
		createAuditParts = append(createAuditParts, hint)
	}
	if len(certWarnings) > 0 {
		// 证书链/域名警告随成功审计留痕(不阻断)。
		createAuditParts = append(createAuditParts, "证书警告："+strings.Join(certWarnings, "；"))
	}
	recordAudit(c, "创建", "负载规则", services.FormatAuditDetail(createAuditParts...))
	reloadNote.finalize()
	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Message: "规则已创建", Data: gin.H{"caddy_id": caddyID}})
}

// certEnqueueErrorResponse 证书任务入队失败的状态/文案单源
// 证书签发任务未运行（队列 paused/inactive）→ 409 点名可操作原因，与手工
// 签发端点同口径；规则当前态守卫拒绝（服务层
// ErrCertRuleStateConflict——并发禁用/改域/删除，services/certificates.go
// 明确要求 handler 409、不得折成 500）同样映射 409；规则屏障期
// （ErrCertRuleBusy——删除/禁用/更新的取消窗口内并发入队）是瞬时冲突，
// 同样 409 可重试；其余内部失败维持 500。
func certEnqueueErrorResponse(prefix string, err error) (int, string) {
	if errors.Is(err, services.ErrCertificateQueueInactive) {
		return http.StatusConflict, prefix + "：证书签发任务已停止，请先在任务监控中恢复后再试（" + err.Error() + "）"
	}
	if errors.Is(err, services.ErrCertRuleStateConflict) {
		return http.StatusConflict, prefix + "：规则状态已变更，请刷新后重试（" + err.Error() + "）"
	}
	if errors.Is(err, services.ErrCertRuleBusy) {
		return http.StatusConflict, prefix + "：" + err.Error()
	}
	// 其余内部失败维持 500：文案只回固定前缀，底层错误（SQL/队列内部态）
	// 只进运行日志——与 business 组 5xx 政策同源。
	services.Logf("error", "%s: %v", prefix, err)
	return http.StatusInternalServerError, prefix
}

// retireOldDomainCertJobOrAudit：UpdateRule 域名迁移
// 三失败分支（事务开启/UPDATE/commit 失败）的「退役旧域任务 + 退役失败补
// 审计」块逐字三份——收敛为单一 helper，三处只差退役原因/日志相位/审计
// 前缀文案，行为零变化。退役失败即旧域任务保持原状（'issued'+PEM
// 行永驻，与 pre-v2 行为等效，fail-safe 但静默），补审计让运维可见。
func retireOldDomainCertJobOrAudit(c *gin.Context, caddyID string, existingRule models.LbRule, reason, logPhase, auditPrefix string) {
	oldCanonical := canonicalACMEDomainForJobLookup(existingRule.Domain)
	if retireErr := retireCertJobsForDomain(db.DB, caddyID, oldCanonical, reversedACMEDomainForm(oldCanonical), reason); retireErr != nil {
		services.Logf("error", "清理失败: UpdateRule: failed to retire old-domain cert job after %s for caddy_id=%s: %v", logPhase, caddyID, retireErr)
		recordAudit(c, "写入失败", "证书任务", services.FormatAuditDetail(
			services.AuditRulePart(caddyID),
			fmt.Sprintf("%s：%v。旧域任务保持原状，请人工检查", auditPrefix, retireErr),
		))
	}
}

// ruleVersionLayouts 是规则版本值可接受的时间布局：RFC3339（前端把列表行的
// updated_at 原样回传，JSONNullTime 序列化为 RFC3339）与库内
// datetime('now') 的平面 UTC 形态（API/MCP 客户端可直接抄库值）。
var ruleVersionLayouts = []string{"2006-01-02 15:04:05", time.RFC3339}

// parseRuleVersionValue 解析版本值并按秒截断（库列精度=秒）。
func parseRuleVersionValue(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	for _, layout := range ruleVersionLayouts {
		if parsed, err := time.ParseInLocation(layout, raw, time.UTC); err == nil {
			return parsed.UTC().Truncate(time.Second), true
		}
	}
	return time.Time{}, false
}

// parseRuleVersionExpectation 解析可选的 expected_updated_at：空串=未提供
// （不校验，API/MCP 向后兼容）；非空但不可解析=400（客户端错误必须响亮，
// 静默忽略会让调用方误以为拿到了并发保护）。
func parseRuleVersionExpectation(raw string) (time.Time, bool, error) {
	if strings.TrimSpace(raw) == "" {
		return time.Time{}, false, nil
	}
	parsed, ok := parseRuleVersionValue(raw)
	if !ok {
		return time.Time{}, false, fmt.Errorf("expected_updated_at 格式无效：需为 RFC3339 或 'YYYY-MM-DD HH:MM:SS'")
	}
	return parsed, true, nil
}

// ruleVersionConflicts 报告库内版本与客户端期望版本是否冲突。库内 NULL/
// 形态异常一律视为冲突（fail-closed）：无法证明「未被他人修改」时宁可让
// 客户端刷新后重试，也不静默覆盖。
// 比较口径为秒（写侧 datetime('now') 只到秒）：同一秒内的并发提交版本值
// 相同，本门无法识别——这是明示的保护下限，不是「严格无丢失更新」。
func ruleVersionConflicts(current string, expected time.Time) bool {
	currentVersion, ok := parseRuleVersionValue(current)
	if !ok {
		return true
	}
	return !currentVersion.Equal(expected.UTC().Truncate(time.Second))
}

func (h *Handlers) UpdateRule(c *gin.Context) {

	if rejectWriteDuringImport(c, "执行规则写操作") {
		return
	}
	caddyID := c.Param("caddy_id")

	// 与 CreateRule同口径的请求体上限——UpdateRule
	// 同样携带 tls_cert/tls_key 与 upstreams 数组，缺此门时认证客户端可用超大 body
	// OOM 单进程服务（gin + Caddy 编排 + 证书队列同进程）。
	const maxUpdateRuleBodyBytes int64 = 1 << 20 // 1MB
	if c.Request.ContentLength > maxUpdateRuleBodyBytes {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "请求体过大"})
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxUpdateRuleBodyBytes)
	var req models.UpdateRuleRequest
	// ShouldBindBodyWith（缓存请求体）供 weight 省略探针二次解码。
	if err := c.ShouldBindBodyWith(&req, binding.JSON); err != nil {
		// MaxBytesReader 超限(chunked/未知长度)映射 413,
		// 与 CreateRule/PutCaddyConfig/导入路径口径一致。
		if isRequestBodyTooLarge(err) {
			c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "请求体过大"})
			return
		}
		services.Logf("error", "UpdateRule bind error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的请求: " + err.Error()})
		return
	}
	// 省略 weight 的上游行落默认 1（显式 0 由写侧校验 400）；
	// upstreams 整体省略时 len=0 探针 no-op，合并区保留存量。
	applyOmittedUpstreamWeightDefaults(c, req.Upstreams)
	requestedProtocol := req.Protocol
	// 乐观并发前置条件（可选）：解析在取锁之前完成，非法形态直接 400（不做
	// 任何读取/写入）；实际比对在事务内进行——事务以 immediate 模式持写锁，
	// 「读库版本 → 写库」不被并发写者穿插，锁内比较才是可证明的。
	expectedUpdatedAt, hasExpectedUpdatedAt, versionErr := parseRuleVersionExpectation(req.ExpectedUpdatedAt)
	if versionErr != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: versionErr.Error()})
		return
	}

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

	// 443 默认只属于「新建」。此处若在读到存量之前就
	// 把省略的 listen_port 填成 443，下方 `req.ListenPort == 0` 的存量合并在
	// 结构上永不生效——API/MCP 的部分更新（update_rule 明确允许省略字段）
	// 会把 8443/8080 的规则静默迁到 443，且旧端口的占用/混布校验被整体跳过。
	// 默认改到合并之后：存量端口优先，仅在合并后仍为 0（理论上不可达）时兜底。

	// Fill in missing fields from database so validation and the update use complete data.
	var existingRule models.LbRule
	err := db.DB.QueryRow(`
		SELECT COALESCE(protocol,''), COALESCE(domain,''), listen_port, COALESCE(strategy,'weighted_round_robin'),
			COALESCE(tls_cert,''), COALESCE(tls_key,''), COALESCE(tls_source,'manual'), COALESCE(acme_config_id,0),
			COALESCE(ca_provider_id,0),
			COALESCE(enable_tls,0), COALESCE(tls_http_redirect,0),
			COALESCE(dynamic_dns,0), COALESCE(enable_dns_server,0), COALESCE(dns_server,''), COALESCE(dns_family,'ipv4'),
			COALESCE(health_check_path,''), COALESCE(health_check_interval,10), COALESCE(health_check_timeout,2),
			COALESCE(health_check_unhealthy_threshold,3), COALESCE(health_check_healthy_threshold,2),
			COALESCE(enable_active_health_check,0), COALESCE(tcp_health_check_port,0), COALESCE(tcp_proxy_protocol,0), COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,250),
	COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,0), COALESCE(ntlm_compatible,0), COALESCE(upstream_force_http1,0),
		COALESCE(custom_routes_enabled,0),
		COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0), COALESCE(proxy_flush_interval,0), COALESCE(proxy_stream_close_delay,0),
		COALESCE(host_header,''), COALESCE(health_check_host,''), COALESCE(enable_compress,0), COALESCE(compress_types,'gzip'),
		IIF(enabled IN ('1',1),1,0), COALESCE(log_enabled,0), name, COALESCE(description,'')
	FROM lb_rules WHERE caddy_id = ?`, caddyID).Scan(
		&existingRule.Protocol, &existingRule.Domain, &existingRule.ListenPort, &existingRule.Strategy,
		&existingRule.TLSCert, &existingRule.TLSKey, &existingRule.TLSSource, &existingRule.ACMEConfigID,
		&existingRule.CAProviderID,
		&existingRule.EnableTLS, &existingRule.TLSHTTPRedirect,
		&existingRule.DynamicDNS, &existingRule.EnableDnsServer, &existingRule.DnsServer, &existingRule.DnsFamily,
		&existingRule.HealthCheckPath, &existingRule.HealthCheckInterval, &existingRule.HealthCheckTimeout,
		&existingRule.HealthCheckUnhealthyThreshold, &existingRule.HealthCheckHealthyThreshold,
		&existingRule.EnableActiveHealthCheck, &existingRule.TCPHealthCheckPort, &existingRule.TCPProxyProtocol, &existingRule.TCPTryDuration, &existingRule.TCPTryInterval,
		&existingRule.RequestBodyMaxSizeMB, &existingRule.UpstreamKeepaliveTimeout, &existingRule.ServerTokensHidden, &existingRule.NTLMCompatible, &existingRule.UpstreamForceHTTP1,
		&existingRule.CustomRoutesEnabled,
		&existingRule.ProxyDialTimeout, &existingRule.ProxyResponseHeaderTimeout, &existingRule.ProxyReadTimeout, &existingRule.ProxyWriteTimeout, &existingRule.ProxyStreamTimeout, &existingRule.ProxyFlushInterval, &existingRule.ProxyStreamCloseDelay,
		&existingRule.HostHeader, &existingRule.HealthCheckHost, &existingRule.EnableCompress, &existingRule.CompressTypes,
		&existingRule.Enabled, &existingRule.LogEnabled, &existingRule.Name, &existingRule.Description)
	if err != nil {
		// 分判 ErrNoRows 与真实 DB 故障(同 EnableRule 口径)——
		// 此前任意 DB 错误误报 404「规则不存在」误导排障。
		if dbQueryNotFound(c, err, "规则不存在", "读取规则") {
			return
		}
		recordRuleWriteFailure(c, "更新", "读取规则失败", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则失败"})
		return
	}
	existingRule.PathRules, err = db.LoadPathRules(c.Request.Context(), db.DB, caddyID)
	if err != nil {
		services.Logf("error", "UpdateRule failed to load path_rules for caddy_id=%s: %v", caddyID, err)
		recordRuleWriteFailure(c, "更新", "读取自定义路径规则失败", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取自定义路径规则失败"})
		return
	}

	// Capture old upstreams for potential DB rollback.
	// 存量 upstreams.enabled 无 NOT NULL，NULL 行裸 scan 进 bool 会 500；
	// 启用判定引用 services 单源常量（NULL 视同禁用），回写/回滚保持同一有效状态。
	var oldUpstreams []models.Upstream
	oldUpstreamRows, err := db.DB.Query("SELECT host, port, COALESCE(weight,1), COALESCE(dynamic_dns,0), "+services.UpstreamEnabledSQLValue+", COALESCE(protocol,'http'), COALESCE(max_connections,0), COALESCE(origin_domain,'') FROM upstreams u WHERE rule_id = ?", caddyID)
	if err != nil {
		services.Logf("error", "UpdateRule failed to read existing upstreams for caddy_id=%s: %v", caddyID, err)
		recordRuleWriteFailure(c, "更新", "读取现有上游服务器失败", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取现有上游服务器失败"})
		return
	}
	for oldUpstreamRows.Next() {
		var u models.Upstream
		if err := oldUpstreamRows.Scan(&u.Host, &u.Port, &u.Weight, &u.DynamicDNS, &u.Enabled, &u.Protocol, &u.MaxConnections, &u.OriginDomain); err != nil {
			if closeErr := oldUpstreamRows.Close(); closeErr != nil {
				services.Logf("error", "UpdateRule failed to close existing upstream cursor for caddy_id=%s: %v", caddyID, closeErr)
			}
			services.Logf("error", "UpdateRule failed to scan existing upstream for caddy_id=%s: %v", caddyID, err)
			recordRuleWriteFailure(c, "更新", "读取现有上游服务器失败", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取现有上游服务器失败"})
			return
		}
		oldUpstreams = append(oldUpstreams, u)
	}
	if err := oldUpstreamRows.Err(); err != nil {
		if closeErr := oldUpstreamRows.Close(); closeErr != nil {
			services.Logf("error", "UpdateRule failed to close existing upstream cursor for caddy_id=%s: %v", caddyID, closeErr)
		}
		services.Logf("error", "UpdateRule existing upstream cursor failed for caddy_id=%s: %v", caddyID, err)
		recordRuleWriteFailure(c, "更新", "读取现有上游服务器失败", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取现有上游服务器失败"})
		return
	}
	if err := oldUpstreamRows.Close(); err != nil {
		services.Logf("error", "UpdateRule failed to close existing upstream cursor for caddy_id=%s: %v", caddyID, err)
		recordRuleWriteFailure(c, "更新", "读取现有上游服务器失败", err)
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
	// F10：删除「合并后仍为 0 再填 443」的兜底——existingRule.listen_port 为
	// NOT NULL，合并后为 0 不可达（死代码）；合并后仍为 0 走下方
	// 「监听端口必须大于 0」显性拒绝，不再静默改端口。
	// 策略是否本次显式提交（合并前记录）：TCP 行的显式 cookie 必须由
	// validateStrategyForProtocol 显式 400（与 CreateRule 契约一致），只有
	// 未提交/存量死值才自愈为 weighted_round_robin。
	strategySubmitted := req.Strategy != ""
	// TCP 死字段是否在请求中显式提供必须在任何归一/合并前记录：
	// 显式值交保存门 400，未提交或存量死值才允许自愈清零。
	dynamicDNSSubmitted := req.DynamicDNS != nil
	customRoutesEnabledSubmitted := req.CustomRoutesEnabled != nil
	proxyDialTimeoutSubmitted := req.ProxyDialTimeout != nil
	proxyResponseHeaderTimeoutSubmitted := req.ProxyResponseHeaderTimeout != nil
	proxyReadTimeoutSubmitted := req.ProxyReadTimeout != nil
	proxyWriteTimeoutSubmitted := req.ProxyWriteTimeout != nil
	proxyStreamTimeoutSubmitted := req.ProxyStreamTimeout != nil
	proxyFlushIntervalSubmitted := req.ProxyFlushInterval != nil
	proxyStreamCloseDelaySubmitted := req.ProxyStreamCloseDelay != nil
	if req.Strategy == "" {
		req.Strategy = existingRule.Strategy
	}
	if req.TLSSource == "" {
		req.TLSSource = existingRule.TLSSource
	}
	if req.ACMEConfigID == 0 {
		req.ACMEConfigID = existingRule.ACMEConfigID
	}
	// 非 acme_dns 来源同格清理残留 ACME 配置引用（存量导入/旧版本
	// 行可携带 acme_config_id 而 tls_source 为 manual 或空串；渲染/签发零消费）。
	// 必须在 validateRulePayloadBeforeSave 之前——否则残留引用指向已删除配置时，
	// 编辑会被不存在的 ACME 引用门 400 卡死，清理永远不可达。
	if req.TLSSource != "acme_dns" {
		req.ACMEConfigID = 0
	}
	// （写侧）：nil=保留现值先合并，validateRulePayloadBeforeSave
	// 才能对合并后的生效值做存在性校验（与上方 acme_config_id 同口径）。
	if req.CAProviderID == nil {
		req.CAProviderID = &existingRule.CAProviderID
	}
	// 主动健康检查族（开关 + 三个派生字段）的「本次是否显式提交」必须在合并
	// 存量前记录：nil 合并后指向存量值（与 existingRule 共享底层），合并后无法
	// 再区分「未提交（沿用存量）」与「提交但生效态为 false（清零）」。
	healthCheckSwitchSubmitted := req.EnableActiveHealthCheck != nil
	healthCheckPathSubmitted := req.HealthCheckPath != nil
	healthCheckHostSubmitted := req.HealthCheckHost != nil
	tcpHealthCheckPortSubmitted := req.TCPHealthCheckPort != nil
	if req.HealthCheckPath == nil {
		req.HealthCheckPath = &existingRule.HealthCheckPath
	}
	// 非 nil=沿用存量（0=未提供的 API 编码，非显式零值）先合并——合并后的
	// 生效值经 validateRulePayloadBeforeSave 的 <1 边界校验（库值唯一真相批 1+2：
	// 类型①值型列落库恒有效，渲染零兜底）。指针阈值列 nil=沿用存量、显式 0
	// 直达 <1 门 400。
	if req.HealthCheckInterval == 0 {
		req.HealthCheckInterval = existingRule.HealthCheckInterval
	}
	if req.HealthCheckTimeout == 0 {
		req.HealthCheckTimeout = existingRule.HealthCheckTimeout
	}
	if req.HealthCheckUnhealthyThreshold == nil {
		req.HealthCheckUnhealthyThreshold = &existingRule.HealthCheckUnhealthyThreshold
	}
	if req.HealthCheckHealthyThreshold == nil {
		req.HealthCheckHealthyThreshold = &existingRule.HealthCheckHealthyThreshold
	}
	// nil=沿用存量，显式 0=真实零值（0=不重试/默认间隔/
	// 跟随上游端口均有消费语义，此前非指针合并使显式清零永不可达）。
	// 合并前先记录请求是否显式提供——显式越界必须 400
	// （交 validateRuleFeatures 上界门，错误点名字段），只有存量/导入/直改
	// DB 的越界值允许随编辑自愈。
	tcpTryDurationProvided := req.TCPTryDuration != nil
	tcpTryIntervalProvided := req.TCPTryInterval != nil
	if req.TCPHealthCheckPort == nil {
		req.TCPHealthCheckPort = &existingRule.TCPHealthCheckPort
	}
	if req.TCPTryDuration == nil {
		req.TCPTryDuration = &existingRule.TCPTryDuration
	}
	if req.TCPTryInterval == nil {
		req.TCPTryInterval = &existingRule.TCPTryInterval
	}
	// 重试窗口上界自愈——仅存量/导入/直改 DB 行携带
	// >60000 的越界值随任意编辑归零（0=默认窗口），避免命中新增上界门 400
	// 死端（与负值自愈同格；http 侧 td=-1 是 NTLM 接管态合法哨兵，
	// 不在本门，TCP 侧负值由下方 TCP 块按归零）。
	if !tcpTryDurationProvided && *req.TCPTryDuration > 60000 {
		upperZero := 0
		req.TCPTryDuration = &upperZero
	}
	if !tcpTryIntervalProvided && *req.TCPTryInterval > 60000 {
		upperZero := 0
		req.TCPTryInterval = &upperZero
		// interval 是 duration>0 时的渲染必填值（caddy.go 两处
		// 渲染门：td>0 && ti<=0 直接生成失败）——interval 越界归零后
		// duration 不得残留正值，否则保存成功但配置生成必败（自相矛盾）。
		if *req.TCPTryDuration > 0 {
			req.TCPTryDuration = &upperZero
		}
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
	// NTLM 兼容列在 TCP 行是死字段：显式携带必须 400（保存门点名），
	// 存量/导入/直改 DB 的死值则随任意同协议编辑自愈归零——合并前记录是否
	// 显式提供，避免把存量死值当成用户显式输入拒掉（400 死端）。
	ntlmCompatibleProvided := req.NTLMCompatible != nil
	if req.NTLMCompatible == nil {
		req.NTLMCompatible = &existingRule.NTLMCompatible
	}
	if req.UpstreamForceHTTP1 == nil {
		req.UpstreamForceHTTP1 = &existingRule.UpstreamForceHTTP1
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
	if req.DnsServer == nil {
		req.DnsServer = &existingRule.DnsServer
	}
	if req.DnsFamily == "" {
		req.DnsFamily = existingRule.DnsFamily
	}
	if req.HostHeader == nil {
		req.HostHeader = &existingRule.HostHeader
	}
	if req.HealthCheckHost == nil {
		req.HealthCheckHost = &existingRule.HealthCheckHost
	}
	// 清零判据：合并后的生效态为关闭时
	//   ① 请求显式提交开关 ⇒ 视为对「主动健康检查族」的整体动作，连存量派生
	//      字段一起清零（与 Create 的保存终态一致，存量死配置不再残留）；
	//   ② 只提交派生字段 ⇒ 只清被提交项（API/MCP 只交 health_check_path 时与
	//      Create 同口径清零，本轮修复的入口形态）；
	//   ③ 三者全缺席的无关编辑 ⇒ 不清零（部分更新契约不得把缺席字段当
	//      「显式清空」）。
	clearPath, clearHost, clearPort := req.HealthCheckPath, req.HealthCheckHost, req.TCPHealthCheckPort
	if !healthCheckSwitchSubmitted && !healthCheckPathSubmitted {
		clearPath = nil
	}
	if !healthCheckSwitchSubmitted && !healthCheckHostSubmitted {
		clearHost = nil
	}
	// TCP 显式提交 health_check_host：不得在「未启用健康检查」归一里静默
	// 清零，否则保存门只看到空串而放行（Create 在归一前校验 → 400，Update
	// 必须同结论）。显式值原样交给 validateRulePayloadBeforeSave 点名拒绝。
	if req.Protocol != "http" && healthCheckHostSubmitted {
		clearHost = nil
	}
	if !healthCheckSwitchSubmitted && !tcpHealthCheckPortSubmitted {
		clearPort = nil
	}
	clearedDeadHealthCheck := normalizeInactiveHealthCheckFields(*req.EnableActiveHealthCheck,
		clearPath, clearHost, clearPort)
	if req.Name == "" {
		req.Name = existingRule.Name
	}
	if req.Description == nil {
		req.Description = &existingRule.Description
	}
	// 规则文本长度上限：合并后的 name/description 长度门（DDL 声明值）。
	if err := validateRuleTextLengths(req.Name, *req.Description); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	protocolChanged := requestedProtocol != "" && requestedProtocol != existingRule.Protocol

	if protocolChanged {
		zero, disabled, empty := 0, false, ""
		switch req.Protocol {
		case "tcp":
			// 未显式提交时把存量的 HTTP cookie 策略自愈为 TCP 默认策略
			// （协议切换不是用户对策略的显式输入）；显式提交 cookie 则保留，
			// 交 validateStrategyForProtocol 400（与 CreateRule 同契约）。
			if !strategySubmitted && req.Strategy == "cookie" {
				req.Strategy = "weighted_round_robin"
			}
			// HTTP 专属死配置字段统一由下方最终协议 tcp 块的
			// tcpDeadFieldReset 清单处置。协议切换只清零未提交/存量值；
			// 显式值必须原样留给 validateRuleFeatures 400，不得在此吞掉。
			if !customRoutesEnabledSubmitted {
				req.CustomRoutesEnabled = &disabled
			}
			emptyPathRules := []models.PathRule{}
			req.PathRules = &emptyPathRules
			if !proxyDialTimeoutSubmitted {
				req.ProxyDialTimeout = &zero
			}
			if !proxyResponseHeaderTimeoutSubmitted {
				req.ProxyResponseHeaderTimeout = &zero
			}
			if !proxyReadTimeoutSubmitted {
				req.ProxyReadTimeout = &zero
			}
			if !proxyWriteTimeoutSubmitted {
				req.ProxyWriteTimeout = &zero
			}
			if !proxyStreamTimeoutSubmitted {
				req.ProxyStreamTimeout = &zero
			}
			if !proxyFlushIntervalSubmitted {
				req.ProxyFlushInterval = &zero
			}
			if !proxyStreamCloseDelaySubmitted {
				req.ProxyStreamCloseDelay = &zero
			}
			// DNS 动态上游是 HTTP 语义；未提交/存量值切换即清零，
			// 显式 dynamic_dns 则交保存门拒绝。
			if !dynamicDNSSubmitted {
				req.DynamicDNS = &disabled
			}
			req.EnableDnsServer = &disabled
			req.DnsServer = &empty
			req.DnsFamily = ""
			// 显式提交的健康检查域名不在切换路径静默清零——交保存门 400
			// （与 CreateRule 同契约）；未提交的存量 HTTP 值仍按死配置自愈。
			if !healthCheckHostSubmitted {
				req.HealthCheckHost = &empty
			}
		case "http":
			// TCP 三字段已指针化，切回 http 时以显式零指针清理。
			req.TCPHealthCheckPort = &zero
			req.TCPProxyProtocol = &disabled
			req.TCPTryDuration = &zero
			req.TCPTryInterval = &zero
			// 回切 http 恢复 dns_family 默认(与 CreateRule
			// :758-760 同口径)——切 TCP 已清零(:1337),存量 '' 直接落库会让
			// DB 终态与创建态分叉(读路径 COALESCE 兜底,快照/导出携带脏空值)。
			if req.DnsFamily == "" {
				req.DnsFamily = "ipv4"
			}
		}
	}
	// 最终协议为 tcp 时一律归一 TLS 字段（与上方切换到 TCP 的分支同
	// 语义）——存量 v1 导入可能携带 enable_tls=1 + 空 manual 证书的死形态（渲染
	// 忽略，但下方非协议门控的手动证书检查会让该规则任何编辑恒 400，UI 又对 TCP
	// 隐藏 TLS 开关而无自救路径）；协议未变的 tcp 编辑在此顺带自愈。
	// HTTP 专属死配置字段族（host_header/health_check_path/
	// enable_compress/compress_types/request_body_max_size_mb/
	// upstream_keepalive_timeout/server_tokens_hidden/ntlm_compatible/
	// upstream_force_http1/tls_http_redirect/domain/TLS 族/阶段页）统一经
	// tcpDeadFieldReset 清单弃置——与 CreateRule/DuplicateRule 共用同一清单。
	if req.Protocol == "tcp" {
		tcpZero := 0
		// 阶段页四列在 UpdateRule 是「仅非 nil 才写库」的指针语义——TCP 归一
		// 必须显式提供零值指针，否则协议切换/同协议编辑不会把存量非零值落库
		// 归零（tcpDeadFieldReset 对 nil 目标跳过）。
		if req.BlockPageStage1ID == nil {
			req.BlockPageStage1ID = &tcpZero
		}
		if req.BlockPageStage1Status == nil {
			req.BlockPageStage1Status = &tcpZero
		}
		if req.BlockPageStage3ID == nil {
			req.BlockPageStage3ID = &tcpZero
		}
		if req.BlockPageStage3Status == nil {
			req.BlockPageStage3Status = &tcpZero
		}
		// log_enabled 仅 HTTP 渲染消费（logger_names 按协议门控）——
		// 指针合并会把存量 1 带进 TCP 终态，显式补 false 指针使同协议编辑也自愈。
		if req.LogEnabled == nil {
			tcpLogOff := false
			req.LogEnabled = &tcpLogOff
		}
		// TCP 自愈族：代理超时族/自定义路径同协议编辑自愈——这些字段
		// 在 UpdateRule 是「仅非 nil 才写库」的指针语义，nil 合并会沿用存量
		// 死值并喂进 validateRuleFeatures TCP 分支，使任何无关编辑恒 400
		// 死端（存量 v1 导入/直改 DB 行携带）。显式补零指针：与协议切换块
		// 同口径（TCP 终态不携带这些 HTTP 专属配置）；path_rules 由指针填充
		// 为空集后经 replacePathRulesTx 删除存量行。
		for _, target := range []**int{
			&req.ProxyDialTimeout, &req.ProxyResponseHeaderTimeout,
			&req.ProxyReadTimeout, &req.ProxyWriteTimeout,
			&req.ProxyStreamTimeout, &req.ProxyFlushInterval,
			&req.ProxyStreamCloseDelay,
		} {
			if *target == nil {
				*target = &tcpZero
			}
		}
		if req.CustomRoutesEnabled == nil {
			tcpRoutesOff := false
			req.CustomRoutesEnabled = &tcpRoutesOff
		}
		if req.PathRules == nil {
			emptyPathRules := []models.PathRule{}
			req.PathRules = &emptyPathRules
		}
		// NTLM 兼容列（仅 HTTP 语义）：显式携带由保存门 400 点名；未携带
		// 时把存量死值归零，否则任何无关编辑都会把存量 1 送进保存门恒 400。
		if !ntlmCompatibleProvided {
			req.NTLMCompatible = &tcpZero
		}
		deadFields := updateRuleTCPDeadFields(&req)
		// 显式提交的 HTTP-only 值不静默弃置：Strategy、health_check_host、
		// 动态上游、自定义路径与代理超时族均交保存门 400（与 CreateRule
		// 契约一致）。只有未提交/存量死值走自愈归零。
		if strategySubmitted {
			deadFields.Strategy = nil
		}
		if healthCheckHostSubmitted {
			deadFields.HealthCheckHost = nil
		}
		if dynamicDNSSubmitted {
			deadFields.DynamicDNS = nil
		}
		if customRoutesEnabledSubmitted {
			deadFields.CustomRoutesEnabled = nil
		}
		if proxyDialTimeoutSubmitted {
			deadFields.ProxyDialTimeout = nil
		}
		if proxyResponseHeaderTimeoutSubmitted {
			deadFields.ProxyResponseHeaderTimeout = nil
		}
		if proxyReadTimeoutSubmitted {
			deadFields.ProxyReadTimeout = nil
		}
		if proxyWriteTimeoutSubmitted {
			deadFields.ProxyWriteTimeout = nil
		}
		if proxyStreamTimeoutSubmitted {
			deadFields.ProxyStreamTimeout = nil
		}
		if proxyFlushIntervalSubmitted {
			deadFields.ProxyFlushInterval = nil
		}
		if proxyStreamCloseDelaySubmitted {
			deadFields.ProxyStreamCloseDelay = nil
		}
		tcpDeadFieldReset(req.Protocol, deadFields)
		// 重试窗口是 http/tcp 共用字段（方案 C），http 侧
		// -1=NTLM 接管态合法；指针合并（nil=沿用存量）会把存量 -1 带进 TCP
		// 值域门（rule_features.go TCP 分支拒负值）——切换与同协议编辑双路径
		// 均命中 400 死端，错误指向用户从未提交的字段。负值一律自愈归零
		// （TCP 语义：0 与 -1 均为零窗口=不重试；5s 默认窗口仅属 HTTP）；
		// 非负值尊重指针合并契约（nil=沿用存量/
		// 显式值=尊重输入，rules_lb_fixes_test 钉测）——不可无条件归零。
		if req.TCPTryDuration != nil && *req.TCPTryDuration < 0 {
			req.TCPTryDuration = &tcpZero
		}
		if req.TCPTryInterval != nil && *req.TCPTryInterval < 0 {
			req.TCPTryInterval = &tcpZero
		}
	} else if req.Protocol == "http" {
		// HTTP 渲染不消费 TCP-only 字段；同协议编辑也显式清零，
		// 防止历史 TCP→HTTP 残留随快照/导出放大。
		zero, disabled := 0, false
		req.TCPHealthCheckPort = &zero
		req.TCPProxyProtocol = &disabled
		// HTTP 侧重试窗口下界自愈（与上方上界自愈同格）：存量/导入/直改库
		// 行携带 tcp_try_duration < -1 或 tcp_try_interval < 0 时，值域门会让
		// 任意无关编辑 400 死端，而界面无该字段可自救。-1 是 NTLM 接管态
		// 合法哨兵（保留），越界值归零（0=默认窗口）；interval 非法时 duration
		// 不得残留正值——td>0+ti=0 是渲染必填门的自相矛盾形态。显式提交的
		// 越界值仍交值域门 400（只自愈存量，不改请求契约）。
		if !tcpTryDurationProvided && req.TCPTryDuration != nil && *req.TCPTryDuration < -1 {
			req.TCPTryDuration = &zero
		}
		if !tcpTryIntervalProvided && req.TCPTryInterval != nil && *req.TCPTryInterval < 0 {
			req.TCPTryInterval = &zero
			if *req.TCPTryDuration > 0 {
				req.TCPTryDuration = &zero
			}
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
		// existingRule.Domain 可能为导入态非规范化值
		//（"Example.COM"），与规范化后的 req.Domain 比较会误判变更，比较前先做同样规范化。
		existingDomain := existingRule.Domain
		if existingDomain != "" {
			if canonical, err := db.CanonicalDomains(existingDomain); err == nil {
				existingDomain = canonical
			}
		}
		// 域名冲突检查同样加变更门控——仅当域名/监听端口/启用态相对存量
		// 变化时才执行（enabledRuleDomainConflict 只统计 enabled=1 的规则）。导入遗留的
		// 「一启用一禁用同域名」组合中，禁用方仅改名等无关更新不再被 400 卡死；
		// 启用态变化仍走检查（启用时二次把关，与 enabledRuleDomainConflict 口径一致）。
		// 启用态门控收敛为仅启用方向（*req.Enabled &&!existingRule.Enabled）——
		// 禁用方向不渲染、无冲突可言，存量冲突组合（同域名同端口双启用）的禁用操作
		// 不应被 400 误拦（DisableRule 端点本就不查，口径对齐）。
		if req.Domain != existingDomain || req.ListenPort != existingRule.ListenPort || (*req.Enabled && !existingRule.Enabled) {
			existing, err := enabledRuleDomainConflict(req.Domain, req.ListenPort, caddyID)
			if err != nil {
				services.Logf("error", "UpdateRule domain conflict query failed for caddy_id=%s domain=%s: %v", caddyID, req.Domain, err)
				recordRuleWriteFailure(c, "更新", "检查域名冲突失败", err)
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "检查域名冲突失败"})
				return
			}
			if existing {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "域名已被其他 HTTP/HTTPS 规则使用"})
				return
			}
		}
		// 仅当域名/监听端口/EnableTLS/TLSHTTPRedirect/Enabled 任一相对存量变化时
		// 执行遮蔽检查（fallback 已把 req 字段填成现值，直接与 existingRule 比较）——
		// 存量冲突组合（导入态 80 规则 + 跳转规则并存）下仅改名称/健康检查不应被 400 阻塞。
		// Enabled 变化也触发——与 EnableRule 端点同口径，禁用规则经 UpdateRule
		// 启用时同样拦截会遮蔽 80 直听规则的跳转组合（shadowRelevantChanged 不含 enabled
		// 时仅提交 {"enabled":true} 会绕过遮蔽检查）。
		// 启用态门控收敛为仅启用方向——禁用方不渲染，遮蔽检查无意义；
		// 存量冲突组合（80 直听启用 + 443 TLS+跳转启用同域名）的禁用操作不应被 400 误拦。
		// 门控再加启用状态前置——仅当「新状态启用 或 原状态启用」时才可能产生
		// 运行时影响。禁用中规则（双方均 disabled）不会被渲染，此时改 TLS/跳转/端口/域名
		// 仍被 400 拦截会阻塞「先改好禁用方配置再启用」的正常流程（启用方向仍会二次把关）。
		// 注意放宽的仅是下方遮蔽检查；上方同域名+同端口冲突门控对禁用规则
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
				services.Logf("error", "UpdateRule redirect shadow query failed for caddy_id=%s domain=%s: %v", caddyID, req.Domain, err)
				recordRuleWriteFailure(c, "更新", "检查域名跳转冲突失败", err)
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
	// nil 判定区分「省略」与「显式空数组」——len==0 会把显式
	// [] 归并进保留存量。显式 []=非合法形态:下游 validateRulePayloadBeforeSave
	// 「至少需要一个上游服务器」(handlers.go)400 拒绝、存量不变( 注释纠正
	// 此处曾误称「显式 []=清空,零上游为合法形态」——实际清空路径被 400 拒绝,
	// 裁定)。updateRuleFeatures 按调用契约直接消费合并后的 req.Upstreams
	// （删死分支后不再按 nil 判空）。
	if req.Upstreams == nil {
		req.Upstreams = oldUpstreams
	}
	// 同协议 TCP 编辑也必须弃置上游回源域名（HTTP-only
	// 语义）——此前只在 protocolChanged 分支清理，存量残留会在下方
	// validateRulePayloadBeforeSave 命中「回源域名仅 HTTP」400，UI 对 TCP
	// 隐藏该字段，用户无自救路径。协议切换分支的同类清理保留（幂等）。
	if req.Protocol == "tcp" {
		for index := range req.Upstreams {
			req.Upstreams[index].OriginDomain = ""
		}
	}
	if protocolChanged {
		for index := range req.Upstreams {
			switch req.Protocol {
			case "tcp":
				// 回源域名是 HTTP-only 语义——切换即弃置
				//（与 host_header/health_check_host 归零同格），否则隐藏残留字段
				// 被「回源域名仅 HTTP 规则支持」门恒拒，卡死保存。
				req.Upstreams[index].OriginDomain = ""
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
	// 后端字段层校验（三层校验第 2 层，同 CreateRule，裁定 2026-09-06 ④'）。
	if err := h.validateRulePayloadBeforeSave(req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	// 生效 CA 提供商必须在写前可解析：「跟随默认」解析不到任何启用提供商是
	// 用户可修复的配置状态（400 + 指引），不是服务端故障。此前该判定发生在
	// 事务提交 + /load 之后——一个可在写前判定的前置条件把已提交的更新整体
	// 回滚成 500（一次真实 apply 白做）。前移后，提交后的解析分支只剩并发
	// 变更/DB 故障面。
	if *req.EnableTLS && req.TLSSource == "acme_dns" && req.Protocol == "http" && req.Domain != "" {
		if _, resolveErr := services.ResolveCAProviderID(*req.CAProviderID); resolveErr != nil {
			respondCAProviderResolveFailure(c, "更新", resolveErr)
			return
		}
		// 存量 CA 是提交后迁移比较的输入（判定是否需要重新签发）；它不可解析
		// 同样属于写前可判定的配置状态（导入还原留下 ca=0 + 零启用提供商）。
		if _, resolveExistingErr := services.ResolveCAProviderID(existingRule.CAProviderID); resolveExistingErr != nil {
			respondCAProviderResolveFailure(c, "更新", resolveExistingErr)
			return
		}
	}
	// 同端口 TLS/明文混布拦截(更新方向)。EnableTLS 的「nil=保留现值」合并
	// 已在更新入口完成（req.EnableTLS == nil 时替换为 &existingRule.EnableTLS），
	// 此处恒非 nil——直接解引用；运行期兜底分支不可达（死代码），保留只会
	// 让读侧误以为此处仍接受 nil 语义。
	if req.Protocol == "http" {
		if err := checkPortTLSMix(caddyID, req.ListenPort, *req.EnableTLS); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}

	// Validate TLS certificate if provided (manual source only)
	var certWarnings []string
	if (*req.EnableTLS || req.TLSCert != "" || req.TLSKey != "") && req.TLSSource == "manual" {
		tlsCert := req.TLSCert
		tlsKey := req.TLSKey
		// （用户裁定）:从 acme_dns 切换到 manual 时必须提供新的证书
		// 和私钥——不允许静默沿用 ACME 签发的旧证书（用户以为换了新证书，
		// 实际在用旧证书）；仅同为 manual 且未修改证书时允许 DB 回退。
		if existingRule.TLSSource == "acme_dns" {
			if strings.TrimSpace(req.TLSCert) == "" || strings.TrimSpace(req.TLSKey) == "" {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "从自动签发切换到手动模式必须上传或填写新的证书和私钥，不能沿用自动签发的旧证书"})
				return
			}
		} else {
			// If cert/key not provided in request, get from DB (same-mode fallback)
			if tlsCert == "" {
				tlsCert = existingRule.TLSCert
			}
			if tlsKey == "" {
				tlsKey = existingRule.TLSKey
			}
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
			// 链完整性/域名覆盖质量警告(不阻断)——与 CreateRule/导入侧同格,
			// 按生效证书材料与合并后域名评估,警告随成功审计留痕。
			certWarnings = tlsCertificateWarnings(tlsCert, tlsKey, req.Domain)
			for _, warning := range certWarnings {
				services.Logf("warn", "UpdateRule manual TLS certificate warning for caddy_id=%s (domain %s): %s", caddyID, req.Domain, warning)
			}
		}
	}

	// 端口类 400 前移至快照/validate 之前（与 CreateRule 的
	// validateRuleListenPortForSave/validatePortFromDB 前置顺序对齐）
	// ——TCP 候选 server 名含端口，validate 经 /load 真实加载会把同端口启用中规则 B
	// 的 server 替换为候选（跨规则流量顶替），此前端口冲突在 validate 之后才拒绝且
	// 无运行配置恢复。前移后该场景在副作用发生前拦截。
	if err := h.validateRuleListenPortForSave(req.Protocol, req.ListenPort); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if err := h.validatePortFromDB(req.Protocol, req.ListenPort, caddyID); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	// PUT enabled=false 与 /disable 同语义，同样在副作用
	// 之前做「执行中签发」快路径 409——此前 UpdateRule 直接进入有界取消等待
	// （最长数分钟）并返回 200，/disable 同场景秒回 409，任务史与行为分叉。
	// 仅拦「执行中」（HasRunningJobForRule）；queued/pending 维持既有语义。
	// 单源判据：updatingToDisabled 同时供事务内 disableCertJobsForRuleTx 使用。
	updatingToDisabled := existingRule.Enabled && !derefBool(req.Enabled) &&
		derefBool(req.EnableTLS) && req.TLSSource == "acme_dns"
	if updatingToDisabled {
		if qm := services.GetCAQueueManager(); qm != nil && qm.HasRunningJobForRule(caddyID) {
			// 与 /disable、DELETE 同口径：被在途签发挡住的禁用尝试必须留痕
			//（同场景走 /disable 有账、走编辑入口无账，审计会出现动作盲区）。
			recordAudit(c, "更新失败", "负载规则", ruleConflictDetail(caddyID, "该规则有正在进行的证书签发任务（约需几分钟），请任务完成后再禁用或稍后重试"))
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "该规则有正在进行的证书签发任务（约需几分钟），请任务完成后再禁用或稍后重试"})
			return
		}
	}

	// 运行配置快照：仅用于事务内应用失败的恢复（同 CreateRule，裁定 ④'）。
	runtimeSnapshot, snapErr := h.snapshotImportRuntime([]string{caddyID})
	if snapErr != nil {
		services.Logf("error", "UpdateRule runtime snapshot failed for caddy_id=%s: %v", caddyID, snapErr)
		h.respondRuleSnapshotError(c, "更新", snapErr)
		return
	}

	// 离开 ACME 时（禁用 TLS / 切手动 / 切空来源 / 切 TCP）的在途/排队任务
	// 收敛分两步（镜像 DisableRule 正确序）：事务内先把非终态 cert_jobs 翻转为
	// 终态（见下方 orphanACME 分支——否则主 UPDATE 的 NOT EXISTS 守卫恒 409、
	// queued/waiting_ca 行被 30s 补扫复活重签），事务提交后再取消队列在途签发
	// （见 committed 之后的 cancelRuleJobs——提交前取消会在回滚/重试窗口留下
	// 「队列已摘、行仍非终态」的复活态）。
	// acme_config_id 的清零在同格合并后的「非 acme_dns」门统一完成（覆盖 manual
	// 与空来源，见上方合并块），此处不再重复。
	// 生效证书来源非 manual 时不保留任何证书材料——
	// manual→acme_dns 此前保留 tls_cert/tls_key（渲染按 tls_source 分流零消费，
	// 但私钥正文长期留在 lb_rules 并随导出/备份/集群快照放大）。与
	// 「acme→manual 必须重新上传」对称清理。
	clearingTLSMaterial := req.TLSSource != "manual"
	if clearingTLSMaterial {
		req.TLSCert, req.TLSKey = "", ""
	}
	// 生效来源非 acme_dns 时 ca_provider_id 归零（与
	// CreateRule 非 ACME 分支同口径）。此前仅 acme→manual 切换 / tcp 归零，
	// manual→manual 编辑把存量残留值原样写回；而 ResolveCAProviderID 对非 0
	// 直接返回（不校验存在性），残留死引用会随导出放大并在签发期才暴露。
	if req.TLSSource != "acme_dns" {
		zeroCA := 0
		req.CAProviderID = &zeroCA
	}

	// Build dynamic update for lb_rules table
	query := "UPDATE lb_rules SET "
	var args []interface{}

	query += "name = ?, "
	args = append(args, req.Name)
	query += "description = ?, "
	args = append(args, derefStr(req.Description))
	query += "protocol = ?, "
	args = append(args, req.Protocol)
	query += "domain = ?, "
	args = append(args, req.Domain)
	query += "listen_port = ?, "
	args = append(args, req.ListenPort)
	query += "strategy = ?, "
	args = append(args, req.Strategy)
	query += "dynamic_dns = ?, "
	args = append(args, *req.DynamicDNS)
	query += "enable_dns_server = ?, "
	args = append(args, *req.EnableDnsServer)
	query += "dns_server = ?, "
	args = append(args, derefStr(req.DnsServer))
	query += "dns_family = ?, "
	args = append(args, req.DnsFamily)
	query += "health_check_path = ?, "
	args = append(args, derefStr(req.HealthCheckPath))
	query += "health_check_interval = ?, "
	args = append(args, req.HealthCheckInterval)
	query += "health_check_timeout = ?, "
	args = append(args, req.HealthCheckTimeout)
	query += "health_check_unhealthy_threshold = ?, "
	args = append(args, *req.HealthCheckUnhealthyThreshold)
	query += "health_check_healthy_threshold = ?, "
	args = append(args, *req.HealthCheckHealthyThreshold)
	query += "enable_active_health_check = ?, "
	args = append(args, *req.EnableActiveHealthCheck)
	query += "tcp_health_check_port = ?, "
	args = append(args, *req.TCPHealthCheckPort)
	query += "tcp_proxy_protocol = ?, "
	args = append(args, *req.TCPProxyProtocol)
	query += "tcp_try_duration = ?, "
	args = append(args, *req.TCPTryDuration)
	query += "tcp_try_interval = ?, "
	args = append(args, *req.TCPTryInterval)
	query += "request_body_max_size_mb = ?, "
	args = append(args, *req.RequestBodyMaxSizeMB)
	query += "upstream_keepalive_timeout = ?, "
	args = append(args, *req.UpstreamKeepaliveTimeout)
	query += "server_tokens_hidden = ?, "
	args = append(args, *req.ServerTokensHidden)
	query += "ntlm_compatible = ?, "
	args = append(args, *req.NTLMCompatible)
	query += "upstream_force_http1 = ?, "
	args = append(args, *req.UpstreamForceHTTP1)
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
	args = append(args, derefStr(req.HostHeader))
	query += "health_check_host = ?, "
	args = append(args, derefStr(req.HealthCheckHost))
	query += "enable_tls = ?, "
	args = append(args, *req.EnableTLS)
	query += "tls_source = ?, "
	args = append(args, req.TLSSource)
	query += "acme_config_id = ?, "
	args = append(args, req.ACMEConfigID)
	// ca_provider_id 恒随更新写入——前方合并区已保证
	// req.CAProviderID 非 nil（nil=沿用存量），原 if 条件恒真。
	query += "ca_provider_id = ?, "
	args = append(args, *req.CAProviderID)
	if req.BlockPageStage1ID != nil {
		query += "block_page_stage1_id = ?, "
		args = append(args, *req.BlockPageStage1ID)
	}
	if req.BlockPageStage1Status != nil {
		query += "block_page_stage1_status = ?, "
		args = append(args, *req.BlockPageStage1Status)
	}
	if req.BlockPageStage3ID != nil {
		query += "block_page_stage3_id = ?, "
		args = append(args, *req.BlockPageStage3ID)
	}
	if req.BlockPageStage3Status != nil {
		query += "block_page_stage3_status = ?, "
		args = append(args, *req.BlockPageStage3Status)
	}
	// 空值=保留存量的语义只适用于 HTTP（手动证书留空=沿用）；
	// TCP 行经上方 tcpDeadFieldReset 已把 TLSCert/TLSKey 置空，但同协议编辑
	// 时两条件此前皆假 → DELETE 列不写，死证书/私钥材料永久滞留并随导出/
	// 快照放大。TCP 恒写（值为归一后的空串）。
	if req.TLSCert != "" || protocolChanged || req.Protocol == "tcp" || clearingTLSMaterial {
		query += "tls_cert = ?, "
		args = append(args, req.TLSCert)
	}
	if req.TLSKey != "" || protocolChanged || req.Protocol == "tcp" || clearingTLSMaterial {
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

	// 原此处的 SingleRuleConfig 死构造（建成后无任何消费）已删。
	// domain 保留：下方 ACME 任务域名迁移/查找以其为键。
	domain := req.Domain

	// Caddy 应用失败时需要用这些快照把已提交的 DB 更新恢复回去
	oldRuleRow, oldRuleRowErr := dumpRowByKey(c.Request.Context(), "lb_rules", "caddy_id", caddyID)
	if oldRuleRowErr != nil {
		services.Logf("error", "UpdateRule failed to snapshot lb_rules row for caddy_id=%s: %v", caddyID, oldRuleRowErr)
		recordRuleWriteFailure(c, "更新", "备份规则数据失败", oldRuleRowErr)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份规则数据失败"})
		return
	}
	oldUpstreamRowsMap, oldUpstreamRowsErr := dumpRowsByKey(c.Request.Context(), "upstreams", "rule_id", caddyID)
	if oldUpstreamRowsErr != nil {
		services.Logf("error", "UpdateRule failed to snapshot upstreams for caddy_id=%s: %v", caddyID, oldUpstreamRowsErr)
		recordRuleWriteFailure(c, "更新", "备份上游数据失败", oldUpstreamRowsErr)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份上游数据失败"})
		return
	}
	restoreRuleDBSnapshot := func() error {
		restoreCtx, cancelRestore := compensationContext(c.Request.Context())
		defer cancelRestore()
		if err := restoreRuleSnapshot(restoreCtx, caddyID, oldRuleRow, oldUpstreamRowsMap, existingRule.PathRules); err != nil {
			services.Logf("error", "恢复失败: UpdateRule DB restore failed for caddy_id=%s: %v", caddyID, err)
			return err
		}
		return nil
	}

	// 证书任务补偿快照——必须在事务提交前、且在任何 cert_jobs 变更之前取。
	//
	// 只有两种形态需要它：①事务内禁用（updatingToDisabled）把非终态任务行翻成
	// disabled；②提交后的 ACME 段（域迁移/入队/重载失败）靠 restoreACMEState
	// 回退任务行。若快照在提交之后才取（历史实现），禁用方向的目标态已是
	// disabled——应用失败时 restoreRuleDBSnapshot 把规则回滚为启用，任务行却
	// 停留 disabled，下一次任意渲染因「启用但无可用证书」把整条规则摘除
	// （fail-closed），而 /enable 入口又被 disabled 任务 409 挡住，自愈只剩 6h
	// 补建或手工 disable→enable。
	// 退出 ACME（整行删除）不取快照：删除就是请求的终态，提交后没有任何补偿
	// 分支会回滚任务行，多取一份只会在读失败时把本可成功的更新变成 500。
	// 快照失败仍在零副作用阶段，直接失败即可。
	entersACMEPostCommit := derefBool(req.EnableTLS) && req.TLSSource == "acme_dns" &&
		req.Protocol == "http" && domain != ""
	var certJobsSnapshot services.CertJobsSnapshot
	if updatingToDisabled || entersACMEPostCommit {
		snapshot, snapErr := services.SnapshotCertJobsForRule(caddyID)
		if snapErr != nil {
			services.Logf("error", "UpdateRule failed to snapshot cert jobs for caddy_id=%s: %v", caddyID, snapErr)
			recordRuleWriteFailure(c, "更新", "备份证书任务失败", snapErr)
			writeInternalError(c, http.StatusInternalServerError, "备份证书任务失败", snapErr)
			return
		}
		certJobsSnapshot = snapshot
	}

	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		recordRuleWriteFailure(c, "更新", "开启数据库事务失败", err)
		writeInternalError(c, http.StatusInternalServerError, "开启数据库事务失败", err)
		return
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				services.Logf("error", "UpdateRule transaction rollback failed for caddy_id=%s: %v", caddyID, rollbackErr)
			}
		}
	}()

	// 乐观并发检查必须在事务内（immediate 已持写锁）且先于任何写入/证书任务
	// 副作用：此前的合并基线来自事务外的存量读取，浏览器打开表单到本次提交
	// 之间的他人提交会成为「丢失更新」——向导回写的是打开时的陈旧字段全集，
	// 合并分支只保护省略字段。比对失败=409 且库/运行配置零改动。
	if hasExpectedUpdatedAt {
		var currentVersion string
		if err := tx.QueryRow(`SELECT COALESCE(updated_at,'') FROM lb_rules WHERE caddy_id = ?`, caddyID).Scan(&currentVersion); err != nil {
			services.Logf("error", "UpdateRule failed to read rule version for caddy_id=%s: %v", caddyID, err)
			recordRuleWriteFailure(c, "更新", "读取规则版本失败", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则版本失败"})
			return
		}
		if ruleVersionConflicts(currentVersion, expectedUpdatedAt) {
			recordAudit(c, "更新失败", "负载规则", services.FormatAuditDetail(
				services.AuditRulePart(caddyID), "并发修改：规则已被他人修改，请刷新后重试", services.AuditResultPart("failure")))
			c.JSON(http.StatusConflict, models.APIResponse{Code: http.StatusConflict, Message: "规则已被他人修改，请刷新后重试"})
			return
		}
	}

	// 孤儿自愈（用户裁定，取代 的转换事件判定）：规则保存后
	// 终态不使用 ACME 自动签发（证书源手动 / 禁用 TLS）即删除其全部 cert_jobs
	//（含 failed/issued 历史残留）——v2.3.5 时代 acme→manual 翻转语义遗留的
	// 失败行，用户重存规则（manual→manual，无转换事件）也一并收敛，幂等。
	// 30s 补扫不再有非终态行可复活；事务回滚（应用失败）时删除一并撤销。
	// req.TLSSource/req.EnableTLS 在合并区已按 existingRule 兜底（缺省提交
	// =维持原状），直接判终态即可。删除在 tx 内（应用失败随事务回滚），提交
	// 后仍取消队列在途签发（下方 cancelRuleJobs——行已删仍需防 worker 僵尸执行）。
	orphanACME := !derefBool(req.EnableTLS) || req.TLSSource != "acme_dns"
	var switchedCertJobs int64
	delReason := ""
	if orphanACME {
		// （收窄裁定 2026-10-19，不反转）：409 在途守卫
		// 前置到删除之前——此前先 DELETE 致下方 UPDATE 的 NOT EXISTS 守卫在
		// 本路径恒失效，CA 往返在途的规则可被改成 manual/关 TLS（队列取消是
		// 提交后 best-effort）。阻塞集由 certJobStatusSemanticTable 单源派生
		// （executingACMEJobStatuses）：queued/pending 与 downloaded 维持
		// 「删除+提交后取消+200」语义（未起动行 / 已签发仅部署退避，均无 worker
		// 在跑），其余在途状态 409。
		executingStatuses := executingACMEJobStatuses()
		if len(executingStatuses) > 0 {
			countArgs := make([]any, 0, len(executingStatuses)+1)
			countArgs = append(countArgs, caddyID)
			placeholders := ""
			for i, status := range executingStatuses {
				if i > 0 {
					placeholders += ","
				}
				placeholders += "?"
				countArgs = append(countArgs, status)
			}
			var executingJobs int
			if scanErr := tx.QueryRow("SELECT COUNT(*) FROM cert_jobs WHERE rule_id=? AND status IN ("+placeholders+")", countArgs...).Scan(&executingJobs); scanErr != nil {
				services.Logf("error", "UpdateRule executing cert job check error for caddy_id=%s: %v", caddyID, scanErr)
				recordRuleWriteFailure(c, "更新", "检查证书任务状态失败", scanErr)
				writeInternalError(c, http.StatusInternalServerError, "检查证书任务状态失败", nil)
				return
			}
			if executingJobs > 0 {
				rollbackRuleWriteTx(tx, "UpdateRule", caddyID)
				recordAudit(c, "更新失败", "负载规则", ruleConflictDetail(caddyID, "证书申请中，请等待完成或失败后再修改规则"))
				c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "证书申请中，请等待完成或失败后再修改规则"})
				return
			}
		}
		delReason = "规则已不使用 ACME 自动签发，证书任务已删除"
		delResult, delErr := tx.Exec("DELETE FROM cert_jobs WHERE rule_id=?", caddyID)
		if delErr != nil {
			services.Logf("error", "UpdateRule cert job delete error for caddy_id=%s: %v", caddyID, delErr)
			recordRuleWriteFailure(c, "更新", "删除证书任务失败", delErr)
			writeInternalError(c, http.StatusInternalServerError, "删除证书任务失败", nil)
			return
		}
		switchedCertJobs, delErr = delResult.RowsAffected()
		if delErr != nil {
			services.Logf("error", "UpdateRule cert job delete RowsAffected error for caddy_id=%s: %v", caddyID, delErr)
			recordRuleWriteFailure(c, "更新", "确认证书任务删除结果失败", delErr)
			writeInternalError(c, http.StatusInternalServerError, "确认证书任务删除结果失败", nil)
			return
		}
	}

	// PUT enabled=false 与 /disable 同语义：ACME 任务置 disabled 并取消在途，
	// 否则任务视图仍显示 issued。谓词经
	// disableCertJobsForRuleTx 单源（failed 终态行保留失败史实）。
	// 单源判据：上方 updatingToDisabled 已含 !orphanACME 的全部条件（启用中 +
	// 请求禁用 + 终态仍为 acme_dns + TLS 开启），此处复用避免两处谓词漂移。
	disabledByUpdate := updatingToDisabled
	var disabledJobs int64
	if disabledByUpdate {
		var derr error
		disabledJobs, derr = disableCertJobsForRuleTx(tx, caddyID)
		if derr != nil {
			recordRuleWriteFailure(c, "更新", "暂停证书任务失败", derr)
			writeInternalError(c, http.StatusInternalServerError, "暂停证书任务失败", derr)
			return
		}
	}

	userIDInt := contextUserID(c)
	// 守卫谓词的状态集与 ruleEditBlockingCertJobStatuses 单源（此前写死
	// NOT IN ('issued','failed','disabled')，把无 worker 的 waiting_ca/
	// downloaded 一起拦下，与同族端点口径分裂）。
	blockingStatuses := ruleEditBlockingCertJobStatuses()
	if len(blockingStatuses) > 0 {
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(blockingStatuses)), ",")
		query += "updated_at = datetime('now'), updated_by = ? WHERE caddy_id = ? AND NOT EXISTS (SELECT 1 FROM cert_jobs WHERE rule_id = ? AND status IN (" + placeholders + "))"
		args = append(args, userIDInt, caddyID, caddyID)
		for _, status := range blockingStatuses {
			args = append(args, status)
		}
	} else {
		query += "updated_at = datetime('now'), updated_by = ? WHERE caddy_id = ?"
		args = append(args, userIDInt, caddyID)
	}

	res, err := tx.Exec(query, args...)
	if err != nil {
		rollbackRuleWriteTx(tx, "UpdateRule", caddyID)
		services.Logf("error", "UpdateRule database error for caddy_id=%s: %v", caddyID, err)
		recordRuleWriteFailure(c, "更新", "写入数据库失败（更新规则）", err)
		writeInternalError(c, http.StatusInternalServerError, "写入数据库失败（更新规则）", nil)
		return
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		rollbackRuleWriteTx(tx, "UpdateRule", caddyID)
		services.Logf("error", "UpdateRule RowsAffected error for caddy_id=%s: %v", caddyID, err)
		recordRuleWriteFailure(c, "更新", "写入数据库失败（确认规则更新结果）", err)
		writeInternalError(c, http.StatusInternalServerError, "写入数据库失败（确认规则更新结果）", nil)
		return
	}
	services.Logf("debug", "UpdateRule executed for caddy_id=%s: rows_affected=%d", caddyID, rowsAffected)
	if rowsAffected == 0 {
		rollbackRuleWriteTx(tx, "UpdateRule", caddyID)
		// 409 早退（非终态证书任务在途）。裁定 ④' 后保存路径无预校验
		// 探针，此处早退零运行时扰动，无需恢复。
		recordAudit(c, "更新失败", "负载规则", ruleConflictDetail(caddyID, "证书申请中，请等待完成或失败后再修改规则"))
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "证书申请中，请等待完成或失败后再修改规则"})
		return
	}
	// TCP 终态一律解除安全策略绑定（不只协议切换）——TCP 渲染链
	// （buildTCPProxyRoute）不加载策略，残留绑定会在策略页 rule_count/绑定视图
	// 中显示为生效而运行态零防护；绑定写接口又拒绝 TCP，用户无法在面板内自救。
	// 存量/带外改库写入的 TCP 绑定同样在此收口（启用端点同族清理）。
	// 同协议 HTTP 编辑保留绑定（对照行为由 general_regression_02_test.go 的
	// TestProtocolSwitchToTCPDropsSecurityBindings 钉住）。
	var droppedBindings int64
	if req.Protocol == "tcp" {
		result, err := tx.Exec("DELETE FROM security_policy_bindings WHERE rule_caddy_id = ?", caddyID)
		if err != nil {
			rollbackRuleWriteTx(tx, "UpdateRule", caddyID)
			services.Logf("error", "UpdateRule security_policy_bindings cleanup error for caddy_id=%s: %v", caddyID, err)
			recordRuleWriteFailure(c, "更新", "写入数据库失败（清理安全策略绑定）", err)
			writeInternalError(c, http.StatusInternalServerError, "写入数据库失败（清理安全策略绑定）", nil)
			return
		}
		// 影响行数读失败时绑定已删除——不能当 0 跳过审计（审计与事实不符）。
		affected, raErr := result.RowsAffected()
		if raErr != nil {
			rollbackRuleWriteTx(tx, "UpdateRule", caddyID)
			services.Logf("error", "UpdateRule security_policy_bindings RowsAffected error for caddy_id=%s: %v", caddyID, raErr)
			recordRuleWriteFailure(c, "更新", "确认安全策略绑定清理结果失败", raErr)
			writeInternalError(c, http.StatusInternalServerError, "写入数据库失败（清理安全策略绑定）", nil)
			return
		}
		droppedBindings = affected
	}

	// 归一（weight/protocol/tls 校验）前置后走增量收敛——同内容编辑
	// 不再 DELETE+INSERT 重建全部上游行（id 保留、不触发上游表行级同步触发器）。
	for i := range req.Upstreams {
		u := &req.Upstreams[i]
		// weight<1 已由 validateRulePayloadBeforeSave 响亮拒绝
		//（0→1 静默归一废除），此处不再兜底归一。
		if u.Protocol == "" {
			if req.Protocol == "tcp" {
				u.Protocol = "tcp"
			} else {
				u.Protocol = "http"
			}
		}
	}
	if err := replaceUpstreamsTx(caddyWriteCtx(c), tx, caddyID, req.Upstreams); err != nil {
		rollbackRuleWriteTx(tx, "UpdateRule", caddyID)
		services.Logf("error", "UpdateRule upstreams replace error for caddy_id=%s: %v", caddyID, err)
		recordRuleWriteFailure(c, "更新", "写入数据库失败（更新上游服务器）", err)
		writeInternalError(c, http.StatusInternalServerError, "写入数据库失败（更新上游服务器）", nil)
		return
	}
	if err := replacePathRulesTx(caddyWriteCtx(c), tx, caddyID, features.PathRules); err != nil {
		rollbackRuleWriteTx(tx, "UpdateRule", caddyID)
		services.Logf("error", "UpdateRule path_rules replace error for caddy_id=%s: %v", caddyID, err)
		recordRuleWriteFailure(c, "更新", "写入数据库失败（更新自定义路径规则）", err)
		writeInternalError(c, http.StatusInternalServerError, "写入数据库失败（更新自定义路径规则）", nil)
		return
	}
	// 离开 ACME（禁用 TLS / 切换手动 / 切到 TCP）后，旧 ACME 私钥不再被
	// 规则引用，与任务行同事务语义清理；manual 替换会由下方渲染重新物化
	// 新证书，应用失败则由 runtimeSnapshot 恢复旧文件。
	if (protocolChanged && req.Protocol == "tcp") || (existingRule.TLSSource == "acme_dns" && orphanACME) {
		if err := services.RemoveCertFiles(caddyID); err != nil {
			restoreErr := services.RestoreCertFiles(runtimeSnapshot.certFiles)
			recordRuleWriteFailure(c, "更新", "清理旧证书文件失败", errors.Join(err, restoreErr))
			writeInternalError(c, http.StatusInternalServerError, "清理旧证书文件失败", errors.Join(err, restoreErr))
			return
		}
	}

	reloadNote, applyErr := h.applyFromTxNote(c, tx, txReloadDetail("rule_update", caddyID), true)
	if applyErr != nil {
		// 恢复收口（与创建分支同构）：显式回滚事务 → 快照回退运行配置/
		// 证书文件（同字节短路安全）→ LKG 钉回已提交视图（零 /load）→
		// 横幅持久化（respondRuleApplyError 内）。
		var sideErr error
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			sideErr = fmt.Errorf("回滚未提交事务失败: %w", rbErr)
		}
		runtimeErr := h.restoreImportRuntime(runtimeSnapshot)
		sideErr = errors.Join(sideErr, h.pinLastGoodAfterCompensation())
		h.respondRuleApplyError(c, applyErr, runtimeErr, sideErr, "更新")
		return
	}
	if err := commitTx(tx); err != nil {
		//  +：commit 失败统一走已提交视图恢复
		//（回滚事务 + 重渲染 /load + 回退 LKG/投影/证书物化）。
		recovery := h.recoverCommittedViewAfterCommitFailure(tx)
		services.Logf("error", "UpdateRule transaction commit failed for caddy_id=%s: %v", caddyID, err)
		// 真实 /load 已发生（重载审计）+ 恢复失败时的分叉横幅。
		reloadNote.auditReload()
		h.recordPostCommitRestoreFailure(commitSaveFailedSubject, err, recovery.runtime, recovery.db)
		// 提交后失败审计：提交后失败留痕（Explicit 审计策略，中间件不兜底）。
		recordAudit(c, "更新失败", "负载规则", services.FormatAuditDetail(
			services.AuditRulePart(caddyID), commitUncertainLabel+"："+errors.Join(err, recovery.err()).Error(), services.AuditResultPart("failure")))
		writeInternalError(c, http.StatusInternalServerError, commitUncertainLabel, nil)
		return
	}
	committed = true

	// 并发修改复核：并发修改基线——本请求提交后的规则形态（lb_rules 行 +
	// upstreams + path_rules）。下方放锁窗口内他人 UpdateRule 可完整提交；
	// 基线用于窗口后判定「补偿是否仍只回退本请求」，指纹读取失败时降级为
	// 不判定（仍走既有 delete 复核与恢复链）。
	postCommitFingerprint, fingerprintErr := ruleMutationFingerprint(c.Request.Context(), caddyID)
	if fingerprintErr != nil {
		services.Logf("error", "UpdateRule: 记录规则并发基线失败 for caddy_id=%s: %v", caddyID, fingerprintErr)
	}

	if droppedBindings > 0 {
		recordAudit(c, "更新", "安全策略", fmt.Sprintf("规则 %s 为 TCP，已解除 %d 条安全策略绑定（TCP 不参与策略渲染）", caddyID, droppedBindings))
	}

	// /规则脱离 ACME（改手动/禁用 TLS）第二步——提交成功后留痕
	// 并取消队列在途签发（DisableRule 同序：先收敛任务行后取消）。有界等待；
	// 失败仅告警继续——规则切换本身已提交，任务行已删除，队列残留由取消的
	// best-effort 收敛。
	if orphanACME || disabledByUpdate {
		if switchedCertJobs > 0 {
			services.WriteCertJobLogByRule(caddyID, "WARN", "cancelled", delReason)
			recordAudit(c, "更新", "证书任务", fmt.Sprintf("规则 %s %s（%d 个）", caddyID, delReason, switchedCertJobs))
		}
		if disabledByUpdate && disabledJobs > 0 {
			services.WriteCertJobLogByRule(caddyID, "WARN", "cancelled", "规则已禁用，证书任务已暂停")
			recordAudit(c, "更新", "证书任务", fmt.Sprintf("规则 %s 已禁用，暂停证书任务（%d 个）", caddyID, disabledJobs))
		}
		if qm := services.GetCAQueueManager(); qm != nil {
			// 有界取消等待不得占住全局 Caddy 操作锁；队列屏障阻止
			// 等待期间的新任务入队，panic 时 defer 先恢复锁再走补偿链。
			func() {
				blockToken := qm.BlockJobsForRule(caddyID)
				defer qm.UnblockJobsForRule(caddyID, blockToken)
				h.caddyOpMu.Unlock()
				defer h.caddyOpMu.Lock()
				if updateRuleLockWindowHook != nil {
					updateRuleLockWindowHook(caddyID, 1)
				}
				cancelCtx, cancel := context.WithTimeout(c.Request.Context(), cancelRuleJobsTimeout)
				defer cancel()
				if err := cancelRuleJobs(cancelCtx, qm, caddyID); err != nil {
					services.Logf("warn", "UpdateRule cert job cancel for %s failed: %v (continuing)", caddyID, err)
				}
			}()
			// 放锁窗口内可能已并发删除本规则；继续后续迁移/补偿会把它复活。
			// 中止只跳过补偿与成功收尾——本次 /load 已真实发生，仍须落重载审计。
			if abortIfRuleDeleted(c, caddyID) {
				reloadNote.auditReload()
				return
			}
			// 并发修改复核：窗口内他人提交的更新不得被本请求的失败补偿回退。
			if fingerprintErr == nil && abortIfRuleConcurrentlyModified(c, caddyID, postCommitFingerprint) {
				reloadNote.auditReload()
				return
			}
		}
	}

	// updateWarnings 是「本次保存直接造成的可用性变化」的披露面（改域弃用旧
	// 证书等）：必须进成功响应 data.warnings（前端弹框展示）与操作审计双通道。
	// 与 certWarnings（材料质量提示，只随审计留痕）分开口径——把用户可感知的
	// 服务可用性变化只写审计等于没告知。
	var updateWarnings []string

	// 门控放宽到「ACME+http+domain 变化」——迁移
	// 逻辑与启用态无关;此前 *req.Enabled 门控使禁用态改域绕过迁移,旧域
	// disabled 任务行永驻,再启用时按新域查不到任务另建新行,破坏「一规则
	// 一任务」不变量(块内 needJob 判定仍按启用语义执行)。
	if *req.EnableTLS && req.TLSSource == "acme_dns" && req.Protocol == "http" && domain != "" {
		// 同族：合并区已保证 req.CAProviderID 非 nil，
		// 原 if 判空恒真，直接解引用。
		// 写前门已判定两侧 CA 皆可解析（无可用提供商=400，未提交任何状态），
		// 此处的解析失败只剩并发禁用/删除与 DB 故障面——保留补偿链与 500。
		caProviderID := *req.CAProviderID
		resolvedCAProviderID, resolveErr := services.ResolveCAProviderID(caProviderID)
		resolvedExistingCAProviderID, resolveExistingErr := services.ResolveCAProviderID(existingRule.CAProviderID)
		if resolveErr != nil || resolveExistingErr != nil {
			runtimeErr := h.restoreImportRuntime(runtimeSnapshot)
			// 任务行同样按请求前快照回退：事务内的禁用已把非终态行翻成
			// disabled，只回滚规则行会留下「启用但任务暂停」的分叉态。
			// 顺序=先规则行（恢复为启用/ACME 后 RestoreCertJobsForRule 的
			// 「规则仍属快照时代」判据才成立）后任务行，再钉回 LKG。
			sideErr := errors.Join(restoreRuleDBSnapshot(), services.RestoreCertJobsForRule(certJobsSnapshot), h.pinLastGoodAfterCompensation())
			reloadNote.auditReload()
			h.recordPostCommitRestoreFailure(caddyApplyFailureSubject("解析 CA 提供商失败"), errors.Join(resolveErr, resolveExistingErr), runtimeErr, sideErr)
			// 审计项：提交后失败的更早补偿分支同样必须留痕（此前只有应用日志）。
			restoreErr := errors.Join(runtimeErr, sideErr)
			detail := "解析 CA 提供商失败，已回滚更新: " + errors.Join(resolveErr, resolveExistingErr).Error()
			if restoreErr != nil {
				detail = "解析 CA 提供商失败且恢复失败: " + errors.Join(resolveErr, resolveExistingErr, restoreErr).Error()
			}
			recordAudit(c, "更新失败", "负载规则", services.FormatAuditDetail(
				services.AuditRulePart(caddyID), detail, services.AuditResultPart("failure")))
			writeInternalError(c, http.StatusInternalServerError, "解析 CA 提供商失败", errors.Join(resolveErr, resolveExistingErr, restoreErr))
			return
		}
		caProviderID = resolvedCAProviderID
		domainChanged := canonicalACMEDomainForJobLookup(domain) != canonicalACMEDomainForJobLookup(existingRule.Domain)
		// 补偿快照已在事务提交前取得（见 beginCaddyWriteTx 之前的快照块）：
		// 提交后的域迁移会就地抹除已签发任务的 PEM，而回滚目标态必须是
		// 「请求前」——提交后再取会把事务内的禁用/迁移结果当目标态。
		// When domain changes, update the existing cert job's domain instead of
		// creating a new job and disabling the old one. This preserves the job ID
		// and maintains the "one rule = one cert job" invariant.
		if domainChanged {
			newCanonical := canonicalACMEDomainForJobLookup(domain)
			// 迁移会就地抹除已签发材料（cert_pem/key_pem/expires_at 置空、状态
			// 置 failed 等待重签），旧材料此后**不可恢复**（补偿快照只在本请求
			// 内有效）。只有「旧行确实握着可用材料」时才存在「旧证书被弃用」这
			// 一事实，据此决定成功响应是否披露。只读采集：读失败按无材料处理，
			// 不影响迁移（否则一次披露用的查询会否掉整个更新）。
			var deprecatedCertMaterial bool
			if materialErr := db.DB.QueryRow(
				`SELECT EXISTS(SELECT 1 FROM cert_jobs WHERE rule_id=? AND `+services.CertJobMaterialPredicateSQL("")+`)`,
				caddyID).Scan(&deprecatedCertMaterial); materialErr != nil {
				services.Logf("warn", "UpdateRule: 域名迁移前读取旧证书材料失败 for caddy_id=%s: %v（按无旧证书披露）", caddyID, materialErr)
				deprecatedCertMaterial = false
			}
			if deprecatedCertMaterial {
				updateWarnings = append(updateWarnings,
					"旧证书已弃用（域名已变更，证书材料已清除），新证书签发完成前该规则 HTTPS 不可用")
			}
			// 迁移前取消在途旧域签发。否则 worker 可能在迁移把行改写为新域
			// 之后仍完成签发，confirmCertificateDeployment 见到 job.domain==rule.domain
			// （同为新域）便放行，把旧域证书部署到新域（瞬时 TLS 名称不匹配，重签后
			// 自愈）。CancelJob 等待在途执行退出（30s 上限）；被取消的 worker 走
			// handleExecutionCancellation 的静默分支（q.ctx 未取消、非执行超时），
			// 不写任务状态，requeueCanceledJob 不会复活迁移后置为 'failed' 的行。
			var inFlightJobID int
			if scanErr := db.DB.QueryRow(`SELECT id FROM cert_jobs WHERE rule_id=? ORDER BY id DESC LIMIT 1`, caddyID).Scan(&inFlightJobID); scanErr == nil && inFlightJobID > 0 {
				// 取消等待在途签发退出；worker 部署尾段需要同一 CaddyOpLock。
				// 持锁等待会形成 30–60s 等待环并阻塞全部配置写。闭包 defer
				// 保证 cancel panic 时先恢复锁，入口 defer 才不会二次 Unlock。
				func() {
					h.caddyOpMu.Unlock()
					defer h.caddyOpMu.Lock()
					cancelCertJob(inFlightJobID)
				}()
				if updateRuleLockWindowHook != nil {
					updateRuleLockWindowHook(caddyID, 2)
				}
				// 取消等待期间并发 DeleteRule 可完整提交；此时继续
				// createOrRequeueCertJobVerified 会命中「规则已删除」并走
				// restoreACMEState → 按快照复活规则。改为在窗口后直接复核。
				// 中止只跳过后续迁移/补偿，本次 /load 已真实发生 → 补重载审计。
				if abortIfRuleDeleted(c, caddyID) {
					reloadNote.auditReload()
					return
				}
				// 并发修改复核：同一窗口内的并发更新同样中止（后续恢复按请求前
				// 快照回滚会覆盖他人已提交内容）。
				if fingerprintErr == nil && abortIfRuleConcurrentlyModified(c, caddyID, postCommitFingerprint) {
					reloadNote.auditReload()
					return
				}
			}
			certTx, txErr := db.DB.Begin()
			if txErr != nil {
				// 迁移事务开启失败不能静默吞掉——任务仍持旧域，后续会为
				// 新域另建任务，破坏「一规则一任务」。规则主更新已提交且用户请求
				// 本身有效，此时回滚规则是错误语义；记录错误并继续：新任务按
				// 既有 needJob 路径创建。
				// 旧域残留任务不会被孤儿清扫收敛（sweepOrphanedCertJobs
				// 跳过终态，'issued'+PEM 行将永驻），须在此显式退役旧域任务。
				// 退役与迁移成功路径同为终态（disabled/failed 均使 sweep 不再触碰），
				// 但语义不同：成功路径把行改写为新域、抹除 PEM、置 'failed' 等待重签；
				// 此处域名未实际迁移，故保留 PEM 作历史、置 'disabled'——旧证留在
				// 旧域行上无副作用（部署/续期均按新域匹配，不读此行）。
				services.Logf("error", "UpdateRule: cert job domain migration begin failed for caddy_id=%s: %v", caddyID, txErr)
				retireOldDomainCertJobOrAudit(c, caddyID, existingRule, "域名迁移事务开启失败", "migration begin failure", "域名迁移事务开启失败后旧域任务退役失败")
			} else {
				var existingJobID int
				queryErr := certTx.QueryRow(
					`SELECT id FROM cert_jobs WHERE rule_id=? ORDER BY id DESC LIMIT 1`,
					caddyID).Scan(&existingJobID)
				migrationRolledBack := false
				// 真实查询错误（busy/IO，非 ErrNoRows）不得当作
				// 「无任务」继续空提交——迁移未生效，旧域 issued+PEM 行永驻（sweep
				// 跳过终态），needJob 又为新域另建行，破坏「一规则一任务」且无留痕。
				// 与下方 UPDATE 失败/commit 失败分支同语义：回滚 + 退役旧域任务。
				if queryErr != nil && !errors.Is(queryErr, sql.ErrNoRows) {
					if rbErr := certTx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
						services.Logf("error", "UpdateRule: cert job domain migration lookup rollback failed for caddy_id=%s: %v", caddyID, rbErr)
					}
					services.Logf("error", "UpdateRule: failed to read cert job during domain migration for caddy_id=%s: %v", caddyID, queryErr)
					retireOldDomainCertJobOrAudit(c, caddyID, existingRule, "域名迁移查询任务失败", "migration lookup failure", "域名迁移查询失败后旧域任务退役失败")
					migrationRolledBack = true
				}
				if queryErr == nil && existingJobID > 0 {
					if _, err := certTx.Exec(
						`UPDATE cert_jobs SET domain=?, status='failed', message='域名已更新，等待重新签发', cert_pem='', key_pem='', expires_at=NULL, renewal_attempts=0, ca_available_after=NULL, last_error_code=NULL, updated_at=datetime('now') WHERE id=?`,
						newCanonical, existingJobID); err != nil {
						// 迁移 UPDATE 失败与事务开启失败
						// 同后果——旧域任务未迁移，稍后 needJob 路径会为新域另建任务，
						// 旧域 'issued'+PEM 行永驻且「一规则一任务」被破坏。回滚本事务
						// （其内无其他有效写），并与开启失败分支同语义退役旧域任务。
						if rbErr := certTx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
							services.Logf("error", "UpdateRule: cert job domain migration rollback failed for caddy_id=%s: %v", caddyID, rbErr)
						}
						services.Logf("error", "UpdateRule: failed to update cert job %d domain for caddy_id=%s: %v", existingJobID, caddyID, err)
						retireOldDomainCertJobOrAudit(c, caddyID, existingRule, "域名迁移 UPDATE 失败", "migration update failure", "域名迁移更新失败后旧域任务退役失败")
						migrationRolledBack = true
					} else {
						services.Logf("info", "UpdateRule: migrated cert job %d domain to %s for caddy_id=%s", existingJobID, newCanonical, caddyID)
					}
					if !migrationRolledBack {
						if _, err := certTx.Exec(
							`DELETE FROM cert_jobs WHERE rule_id=? AND id!=?`,
							caddyID, existingJobID); err != nil {
							services.Logf("error", "UpdateRule: failed to clean up extra cert jobs for caddy_id=%s: %v", caddyID, err)
						}
					}
				}
				if !migrationRolledBack {
					if err := certTx.Commit(); err != nil {
						// commit 失败与开启/更新失败同后果——迁移未生效，
						// 旧域任务持原域永驻（sweep 跳过终态），稍后 needJob 为新域
						// 另建任务破坏「一规则一任务」。与分支同语义退役。
						services.Logf("error", "UpdateRule: cert job domain migration commit failed for caddy_id=%s: %v", caddyID, err)
						retireOldDomainCertJobOrAudit(c, caddyID, existingRule, "域名迁移 commit 失败", "migration commit failure", "域名迁移提交失败后旧域任务退役失败")
					}
				}
			}
		}
		caProviderChanged := resolvedCAProviderID != resolvedExistingCAProviderID
		wasReEnabled := !existingRule.Enabled && *req.Enabled
		tlsSourceChangedToACME := existingRule.TLSSource != "acme_dns"
		var enqueuedJobID int
		var queueManager *services.CAQueueManager
		restoreACMEState := func() (runtimeErr, sideErr error) {
			if enqueuedJobID > 0 && queueManager != nil {
				cancelCertJob(enqueuedJobID)
			}
			// 运行配置恢复与附带失败（DB 回退 + 任务行回退 + LKG 钉回）分通道：
			// 只有前者决定横幅两态标签；钉回必须在 DB 回退之后。
			runtimeErr = h.restoreImportRuntime(runtimeSnapshot)
			sideErr = errors.Join(restoreRuleDBSnapshot(), services.RestoreCertJobsForRule(certJobsSnapshot), h.pinLastGoodAfterCompensation())
			return runtimeErr, sideErr
		}
		// 提交后失败统一出口：补偿 -> 审计 -> 响应。更新端点为 Explicit 审计策略，
		// 中间件不兜底——提交后的每个失败分支都必须留痕（与 EnableRule 的
		// failEnableWithStatus 对称），否则「曾提交并已回滚」在操作审计里缺席。
		// 真实 /load 已发生 → 重载审计；补偿恢复失败 → 分叉横幅。
		failUpdateWithStatus := func(message string, status int, cause error) {
			if cause != nil {
				services.Logf("error", "UpdateRule post-commit failure for caddy_id=%s: %s: %v", caddyID, message, cause)
			}
			runtimeErr, sideErr := restoreACMEState()
			restoreErr := errors.Join(runtimeErr, sideErr)
			reloadNote.auditReload()
			h.recordPostCommitRestoreFailure(caddyApplyFailureSubject(message), errors.New(message), runtimeErr, sideErr)
			detail := message
			if cause != nil {
				detail = message + "：" + cause.Error()
			}
			if restoreErr != nil {
				services.Logf("error", "补偿失败: UpdateRule compensation failed for caddy_id=%s: %v", caddyID, restoreErr)
				detail = detail + "；补偿恢复失败: " + restoreErr.Error()
			}
			recordAudit(c, "更新失败", "负载规则", services.FormatAuditDetail(
				services.AuditRulePart(caddyID), detail, services.AuditResultPart("failure")))
			if restoreErr != nil {
				writeInternalError(c, http.StatusInternalServerError, message+"；规则与 Caddy 恢复失败", nil)
				return
			}
			c.JSON(status, models.APIResponse{Code: status, Message: message})
		}
		var jobID, jobProviderID int
		var jobStatus string
		var jobExpiresAt sql.NullTime
		jobErr := db.DB.QueryRow("SELECT id,status,expires_at,COALESCE(ca_provider_id,0) FROM cert_jobs WHERE rule_id=? AND domain=? ORDER BY id DESC LIMIT 1", caddyID, canonicalACMEDomainForJobLookup(domain)).Scan(&jobID, &jobStatus, &jobExpiresAt, &jobProviderID)
		if jobErr != nil && !errors.Is(jobErr, sql.ErrNoRows) {
			failUpdateWithStatus("读取证书任务失败", http.StatusInternalServerError, jobErr)
			return
		}
		if jobErr == nil {
			resolvedJobProviderID, resolveJobErr := services.ResolveCAProviderID(jobProviderID)
			if resolveJobErr != nil {
				failUpdateWithStatus("解析证书任务 CA 提供商失败", http.StatusInternalServerError, resolveJobErr)
				return
			}
			caProviderChanged = caProviderChanged || resolvedJobProviderID != caProviderID
		}
		resumedValidJob := false
		if wasReEnabled && jobErr == nil {
			// 续期天数读取单源（services.GetCertRenewalDays）——
			// 原内联 COALESCE(cert_renewal_days,30) 与读侧零兜底口径分裂。
			renewalDays := services.GetCertRenewalDays()
			var expiryPtr *time.Time
			if jobExpiresAt.Valid {
				expiry := jobExpiresAt.Time
				expiryPtr = &expiry
			}
			if !domainChanged && !caProviderChanged && ResolveEnableCertJobAction(true, jobStatus, expiryPtr, time.Now(), renewalDays) == EnableCertJobResume {
				// 行被并发删除时 UPDATE 命中 0 行
				// 不报错——必须校验 RowsAffected，否则幻影 resume 抑制 needJob，
				// 续签链静默断裂且被 200 掩盖（与 EnableRule 出口同口径）。
				resumeResult, err := db.DB.Exec("UPDATE cert_jobs SET status='issued',message='证书有效，已恢复使用',renewal_attempts=0,ca_available_after=NULL,last_error_code=NULL,updated_at=datetime('now') WHERE id=?", jobID)
				if err == nil {
					resumed, raErr := resumeResult.RowsAffected()
					if raErr != nil || resumed != 1 {
						err = fmt.Errorf("任务行不存在或已被并发变更（rows=%d, err=%v）", resumed, raErr)
					}
				}
				if err != nil {
					failUpdateWithStatus("恢复证书任务失败", http.StatusInternalServerError, err)
					return
				}
				// （第二出口）：Resume 后已应用配置同样缺 TLS——补一次重渲染
				// 重应用；失败走既有 restoreACMEState 补偿。改走
				// 强制变体（证书文件已在事务外落盘，JSON 相同会被短路）并接线
				// recordCaddyApplyResult（失败必须进 caddy_apply_error，UI 可见）；
				// 本函数已持有 caddyOpMu，不可改用 applyCaddyConfigE（重入死锁）。
				reapplyErr := h.caddyService.GenerateAndApplyConfigForceInLock() // 已持锁——InLock 变体防重入死锁
				h.recordCaddyApplyResult(reapplyErr)
				if reapplyErr != nil {
					failUpdateWithStatus("恢复证书任务后重载 Caddy 配置失败", http.StatusInternalServerError, reapplyErr)
					return
				}
				// 第二轮已持久化恢复后的 TLS 配置，首轮 note 不得再回写无 TLS 载荷。
				reloadNote.markLastGoodSuperseded()
				resumedValidJob = true
				// 与 /enable 的恢复留痕同通道、同 stage；后缀点名入口，
				// 让用户区分「更新规则时重新启用」与显式启用操作。
				services.WriteCertJobLogByRule(caddyID, "INFO", "resumed", "规则已启用，证书任务已恢复（更新规则时重新启用）")
			}
		}
		needJob := domainChanged || caProviderChanged || !services.IsACMECertIssued(caddyID, domain) ||
			((wasReEnabled || tlsSourceChangedToACME) && !services.HasCertJob(caddyID, domain))
		needJob = needJob && !resumedValidJob
		// 外层门放宽后,块内恢复「禁用不签发」语义——
		// 禁用态改域仅做任务迁移,不排队新签发。
		needJob = needJob && *req.Enabled
		if needJob {
			queueManager = services.GetCAQueueManager()
			if queueManager == nil {
				runtimeErr, sideErr := restoreACMEState()
				restoreErr := errors.Join(runtimeErr, sideErr)
				reloadNote.auditReload()
				h.recordPostCommitRestoreFailure(certJobEnqueueFailedSubject, errors.New("证书任务入队失败：CA 队列未初始化"), runtimeErr, sideErr)
				// 提交后失败审计：提交后失败留痕（补偿结果一并点名）。
				detail := "证书任务入队失败：CA 队列未初始化"
				if restoreErr != nil {
					detail = "证书任务入队失败且恢复失败: " + restoreErr.Error()
				}
				recordAudit(c, "更新失败", "负载规则", services.FormatAuditDetail(
					services.AuditRulePart(caddyID), detail, services.AuditResultPart("failure")))
				if restoreErr != nil {
					services.Logf("error", "补偿失败: UpdateRule ACME enqueue failed and restore failed for caddy_id=%s: restore=%v", caddyID, restoreErr)
					writeInternalError(c, http.StatusInternalServerError, "CA 队列未初始化且恢复失败", nil)
					return
				}
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "CA 队列未初始化"})
				return
			}
			services.Logf("info", "UpdateRule enqueueing cert job for caddy_id=%s domain=%s ca_provider_id=%d", caddyID, domain, caProviderID)
			jobID, changed, err := createOrRequeueCertJobVerified(caddyID, domain, caProviderID, queueManager)
			if changed {
				enqueuedJobID = jobID
			}
			if err != nil {
				runtimeErr, sideErr := restoreACMEState()
				restoreErr := errors.Join(runtimeErr, sideErr)
				reloadNote.auditReload()
				h.recordPostCommitRestoreFailure(certJobEnqueueFailedSubject, err, runtimeErr, sideErr)
				// 提交后失败审计：入队失败 + 补偿结果留痕。
				detail := "创建证书任务失败，已回滚更新: " + err.Error()
				if restoreErr != nil {
					detail = "创建证书任务失败且恢复失败: " + errors.Join(err, restoreErr).Error()
				}
				recordAudit(c, "更新失败", "负载规则", services.FormatAuditDetail(
					services.AuditRulePart(caddyID), detail, services.AuditResultPart("failure")))
				if restoreErr != nil {
					services.Logf("error", "补偿失败: UpdateRule ACME enqueue failed and restore failed for caddy_id=%s: enqueue=%v restore=%v", caddyID, err, restoreErr)
					writeInternalError(c, http.StatusInternalServerError, "创建证书任务失败且恢复失败", nil)
					return
				}
				status, message := certEnqueueErrorResponse("创建证书任务失败", err)
				c.JSON(status, models.APIResponse{Code: status, Message: message})
				return
			}
		}
		// 改域后补一次强制重渲染（与 Resume 链同构）：事务内 apply 用的是迁移
		// **之前**的任务行（selectCertificate 要求证书覆盖规则全部域名），提交后
		// 迁移已把旧材料抹除并改写为新域——运行配置必须重新与已提交视图对齐，
		// 不能等新证书部署回调顺带重载（签发持续失败时规则会长期停在「旧配置
		// + 新域」）。强制变体：证书文件已随迁移在事务外变化，JSON 相同会被短路；
		// 失败走既有 restoreACMEState 补偿。本函数已持有 caddyOpMu，不可改用
		// applyCaddyConfigE（重入死锁）。
		if domainChanged && *req.Enabled {
			reapplyErr := h.caddyService.GenerateAndApplyConfigForceInLock() // 已持锁——InLock 变体防重入死锁
			h.recordCaddyApplyResult(reapplyErr)
			if reapplyErr != nil {
				failUpdateWithStatus("域名迁移后重载 Caddy 配置失败", http.StatusInternalServerError, reapplyErr)
				return
			}
			// 第二轮已持久化新域视图，首轮 note 不得再回写旧视图载荷。
			reloadNote.markLastGoodSuperseded()
		}
	}

	services.Logf("info", "Rule %s updated", caddyID)
	tlsPart := ""
	if req.Protocol == "http" {
		tlsPart = fmt.Sprintf("TLS：%s", boolText(*req.EnableTLS))
	}
	auditParts := []string{services.AuditRulePart(caddyID), req.Name, fmt.Sprintf("协议：%s", req.Protocol), domain, tlsPart}
	if hint := inactiveHealthCheckAuditHint(clearedDeadHealthCheck); hint != "" {
		auditParts = append(auditParts, hint)
	}
	if len(certWarnings) > 0 {
		// 证书链/域名警告随成功审计留痕(不阻断)。
		auditParts = append(auditParts, "证书警告："+strings.Join(certWarnings, "；"))
	}
	if len(updateWarnings) > 0 {
		// 可用性变化披露双通道之一（另一通道=响应 data.warnings）：事后只能从
		// 审计判断「这条规则的 HTTPS 为何中断」时，这是唯一线索。
		auditParts = append(auditParts, "可用性变更："+strings.Join(updateWarnings, "；"))
	}
	recordAudit(c, "更新", "负载规则", services.FormatAuditDetail(auditParts...))
	reloadNote.finalize()
	if len(updateWarnings) > 0 {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已更新", Data: gin.H{"warnings": updateWarnings}})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已更新"})
}

func (h *Handlers) DeleteRule(c *gin.Context) {

	if rejectWriteDuringImport(c, "执行规则写操作") {
		return
	}
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

	// UX 快路径预检（用户裁决）：有 worker 正在执行签发时删除会进入有界取消
	// 等待（最长 2 分钟），秒回 409 让用户稍后重试优于请求悬挂。仅拦「执行中」
	// ——queued 取消瞬时、waiting_ca 冷却可达数小时均不拦；检查与操作间的
	// TOCTOU 窗口落入既有超时中止+快照回滚保护，正确性不变。
	if qm := services.GetCAQueueManager(); qm != nil && qm.HasRunningJobForRule(caddyID) {
		recordAudit(c, "删除失败", "负载规则", ruleConflictDetail(caddyID, "该规则有正在进行的证书签发任务（约需几分钟），请任务完成后再删除或稍后重试"))
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "该规则有正在进行的证书签发任务（约需几分钟），请任务完成后再删除或稍后重试"})
		return
	}
	certJobsSnapshot, err := services.SnapshotCertJobsForRule(caddyID)
	if err != nil {
		recordRuleWriteFailure(c, "删除", "备份证书任务失败", err)
		writeInternalError(c, http.StatusInternalServerError, "备份证书任务失败", err)
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
		// 租约释放收口到登记于 drain 之前的唯一 defer——drain 前/中
		// panic（gin Recovery 只恢复 HTTP 栈、不清理 blockedRules）也能走到这里。
		// 补偿一旦启动成功即接管租约（完成时自行释放），abort 路径不得提前释放，
		// 否则补偿的 enqueueCompensation 见租约缺失而永久退避（注释描述的
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
				services.Logf("error", "补偿失败: DeleteRule failed to start certificate rollback compensation for caddy_id=%s: %v", caddyID, err)
				// 同上——补偿未能接管租约时立即释放，不留孤儿屏障。
				queueManager.UnblockJobsForRule(caddyID, blockToken)
				return
			}
			compensationStarted = true
		}()
		h.caddyOpMu.Unlock()
		cancelErr := func() error {
			defer h.caddyOpMu.Lock()
			cancelCtx, cancel := context.WithTimeout(c.Request.Context(), cancelRuleJobsTimeout)
			defer cancel()
			return cancelRuleJobs(cancelCtx, queueManager, caddyID)
		}()
		if cancelErr != nil {
			if err := queueManager.StartRuleDeletionCompensation(services.RuleDeletionCompensation{
				RuleID: caddyID, Token: blockToken, Snapshot: certJobsSnapshot,
				Drain: func(ctx context.Context) error { return cancelRuleJobs(ctx, queueManager, caddyID) },
			}); err != nil {
				services.Logf("error", "补偿失败: DeleteRule failed to start certificate compensation for caddy_id=%s: %v", caddyID, err)
				// 补偿启动失败即无人持有该 token（典型为降级竞态：Stop 清空
				// blockedRules 后 block 才创建），必须当场释放租约，否则节点重新提升后
				// 该规则证书任务被屏障永久拦截、静默停发直到下一次 Stop。对运行中的
				// manager 同样幂等安全。
				queueManager.UnblockJobsForRule(caddyID, blockToken)
			} else {
				compensationStarted = true
			}
			// 提交后失败审计：提交前失败同样必须留痕（Explicit 审计策略）——
			// 规则与证书未变，原因点名取消超时。
			recordAudit(c, "删除失败", "负载规则", services.FormatAuditDetail(
				services.AuditRulePart(caddyID), "取消证书任务超时，规则与证书保持不变: "+cancelErr.Error(), services.AuditResultPart("failure")))
			writeInternalError(c, http.StatusInternalServerError, "取消证书任务超时，规则与证书保持不变", cancelErr)
			return
		}
		jobsCanceled = true
	}

	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		recordRuleWriteFailure(c, "删除", "开启数据库事务失败", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) { // 附带：统一 errors.Is
				services.Logf("error", "DeleteRule transaction rollback failed for caddy_id=%s: %v", caddyID, rollbackErr)
			}
		}
	}()

	if _, err := tx.Exec("DELETE FROM cert_jobs WHERE rule_id = ?", caddyID); err != nil {
		services.Logf("error", "DeleteRule cert_jobs delete error for caddy_id=%s: %v", caddyID, err)
		recordRuleWriteFailure(c, "删除", "删除证书任务失败", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除证书任务失败"})
		return
	}
	// 删除规则时一并清理安全策略绑定，避免遗留孤儿绑定导致该规则 caddy_id
	// 被新规则复用时错误继承旧策略。
	if _, err := tx.Exec("DELETE FROM security_policy_bindings WHERE rule_caddy_id = ?", caddyID); err != nil {
		services.Logf("error", "DeleteRule security_policy_bindings delete error for caddy_id=%s: %v", caddyID, err)
		recordRuleWriteFailure(c, "删除", "删除安全策略绑定失败", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除安全策略绑定失败"})
		return
	}
	if _, err := tx.Exec("DELETE FROM upstreams WHERE rule_id = ?", caddyID); err != nil {
		services.Logf("error", "DeleteRule upstreams delete error for caddy_id=%s: %v", caddyID, err)
		recordRuleWriteFailure(c, "删除", "删除上游服务器失败", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除上游服务器失败"})
		return
	}
	// 审计 FK 刻意 OFF（sqlite_pragmas.go），CASCADE 是死条款——path_rules
	// 必须显式删除，否则孤儿行随备份导出后导入侧引用校验 400（备份自毒）。
	if _, err := tx.Exec("DELETE FROM path_rules WHERE rule_id = ?", caddyID); err != nil {
		services.Logf("error", "DeleteRule path_rules delete error for caddy_id=%s: %v", caddyID, err)
		recordRuleWriteFailure(c, "删除", "删除自定义路径失败", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除自定义路径失败"})
		return
	}
	if _, err := tx.Exec("DELETE FROM lb_rules WHERE caddy_id = ?", caddyID); err != nil {
		services.Logf("error", "DeleteRule lb_rules delete error for caddy_id=%s: %v", caddyID, err)
		recordRuleWriteFailure(c, "删除", "删除规则失败", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除规则失败"})
		return
	}

	runtimeSnapshot, err := h.snapshotImportRuntime([]string{caddyID})
	if err != nil {
		services.Logf("error", "DeleteRule runtime snapshot failed for caddy_id=%s: %v", caddyID, err)
		h.respondRuleSnapshotError(c, "删除", err)
		return
	}
	reloadNote, applyErr := h.applyFromTxNote(c, tx, txReloadDetail("rule_delete", caddyID), true)
	if applyErr != nil {
		// 恢复收口（与创建分支同构）：显式回滚事务 → 快照回退 → LKG 钉回
		// 已提交视图（零 /load）→ 横幅持久化。
		var sideErr error
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			sideErr = fmt.Errorf("回滚未提交事务失败: %w", rbErr)
		}
		runtimeErr := h.restoreImportRuntime(runtimeSnapshot)
		sideErr = errors.Join(sideErr, h.pinLastGoodAfterCompensation())
		if restoreErr := errors.Join(runtimeErr, sideErr); restoreErr != nil {
			services.Logf("error", "恢复失败: DeleteRule Caddy apply and runtime restore failed for caddy_id=%s: apply=%v restore=%v", caddyID, applyErr, restoreErr)
		}
		h.respondRuleApplyError(c, applyErr, runtimeErr, sideErr, "删除")
		return
	}
	if err := h.removeRuleCertFiles(caddyID); err != nil {
		certPath, keyPath := services.CertFilePaths(caddyID)
		// 显式回滚（defer 兜底对 ErrTxDone 幂等）：DB 未回退时恢复运行配置/
		// 钉回 LKG 都会把「本请求已删的规则」当成已提交内容——已提交视图
		// 必须由 DB 先回到删除前形态。回滚同时释放 SQLite 写锁（渲染读
		// db.DB 不被阻塞）。
		var sideErr error
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			sideErr = fmt.Errorf("回滚未提交事务失败: %w", rbErr)
		}
		runtimeErr := h.restoreImportRuntime(runtimeSnapshot)
		sideErr = errors.Join(sideErr, h.pinLastGoodAfterCompensation())
		restoreErr := errors.Join(runtimeErr, sideErr)
		reloadNote.auditReload()
		h.recordPostCommitRestoreFailure(certFileCleanupFailedSubject, err, runtimeErr, sideErr)
		// 证书文件可能被部分删除（cert 已删 / key 残留 或反之），
		// 即便 Caddy 配置和 DB 事务都恢复了，下次 reload 可能因找不到证书导致 TLS 静默失败。
		// 用户决策：保留现有顺序（先删文件再 commit），但加 error 级日志 + audit + 操作审计（当前实现无安全事件写入），
		// 让运维收到通知后人工恢复证书文件（从备份或其他节点同步）。
		services.Logf("error", "清理失败: DeleteRule 证书文件清理失败，可能存在 DB-文件状态不一致。caddy_id=%s cert_path=%s key_path=%s cleanup_error=%v restore_error=%v。请人工检查证书文件并在必要时从备份恢复",
			caddyID, certPath, keyPath, err, restoreErr)
		recordAudit(c, "清理失败", "证书文件", services.FormatAuditDetail(
			services.AuditRulePart(caddyID),
			fmt.Sprintf("残留路径：%s, %s。错误：%v。请人工检查证书文件，必要时从备份恢复", certPath, keyPath, err),
		))
		if restoreErr != nil {
			services.Logf("error", "恢复失败: DeleteRule certificate cleanup and runtime restore failed for caddy_id=%s: cleanup=%v restore=%v", caddyID, err, restoreErr)
		}
		writeInternalError(c, http.StatusInternalServerError, "清理规则证书文件失败，删除已回滚。规则已恢复但证书文件可能不一致，请检查日志并人工恢复证书", nil)
		return
	}
	if err := commitTx(tx); err != nil {
		//  +：commit 失败统一走已提交视图恢复
		//（回滚事务 + 重渲染 /load + 回退 LKG/投影/证书物化）。
		recovery := h.recoverCommittedViewAfterCommitFailure(tx)
		services.Logf("error", "DeleteRule transaction commit failed for caddy_id=%s: %v", caddyID, err)
		if restoreErr := recovery.err(); restoreErr != nil {
			services.Logf("error", "恢复失败: DeleteRule commit and runtime restore failed for caddy_id=%s: commit=%v restore=%v", caddyID, err, restoreErr)
		}
		reloadNote.auditReload()
		h.recordPostCommitRestoreFailure(commitSaveFailedSubject, err, recovery.runtime, recovery.db)
		// 提交后失败审计：提交失败留痕（补偿结果一并点名）。
		detail := commitUncertainLabel + "：" + err.Error()
		if restoreErr := recovery.err(); restoreErr != nil {
			detail = commitUncertainLabel + "，且恢复失败：" + errors.Join(err, restoreErr).Error()
		}
		recordAudit(c, "删除失败", "负载规则", services.FormatAuditDetail(
			services.AuditRulePart(caddyID), detail, services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: commitUncertainLabel})
		return
	}
	committed = true
	deleteCompleted = true
	if queueManager != nil {
		queueManager.UnblockJobsForRule(caddyID, blockToken)
	}

	if db.MetricsDB != nil {
		if _, err := db.MetricsDB.Exec("DELETE FROM metrics_history WHERE rule_id = ?", caddyID); err != nil {
			// （裁定）：清理失败不阻断删除（规则已提交），
			// 但必须显性化——操作审计留痕 + 周期任务 metrics-orphan-cleanup
			// 按「已删除规则」谓词有界收敛重试（残留行 7 天保留期另兜底）。
			services.Logf("error", "DeleteRule metrics_history delete error for caddy_id=%s: %v", caddyID, err)
			recordAudit(c, "清理失败", "规则指标", services.FormatAuditDetail(
				services.AuditRulePart(caddyID),
				fmt.Sprintf("metrics_history 清理失败：%v（累计残留由孤儿指标清理任务有界重试收敛）", err),
			))
		}
	}

	if err := services.RemoveRuleLogFiles(caddyID); err != nil {
		// 与 metrics/证书任务日志同口径：清理失败不阻断删除（规则已提交），
		// 但残留必须显性化——静默失败的残留文件运维完全不可见。
		services.Logf("error", "DeleteRule rule log cleanup failed for caddy_id=%s: %v", caddyID, err)
		recordAudit(c, "清理失败", "规则日志", services.FormatAuditDetail(
			services.AuditRulePart(caddyID), fmt.Sprintf("路径：%s", services.RuleLogPath(caddyID)), err.Error()))
	}
	if err := services.RemoveCertJobLogFiles(caddyID); err != nil {
		services.Logf("error", "DeleteRule cert-job log cleanup failed for caddy_id=%s: %v", caddyID, err)
		recordAudit(c, "清理失败", "证书日志", services.FormatAuditDetail(services.AuditRulePart(caddyID), fmt.Sprintf("路径：%s", services.CertJobLogPath(caddyID)), err.Error()))
	}

	recordAudit(c, "删除", "负载规则", services.FormatAuditDetail(services.AuditRulePart(caddyID), fmt.Sprintf("协议：%s", protocol), fmt.Sprintf("端口：%d", listenPort), domain))
	reloadNote.finalize()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已删除"})
}

func (h *Handlers) DuplicateRule(c *gin.Context) {
	// 导入窗口 fast-fail：复制要等 caddyOpMu（导入全程持有），
	// 排队到导入后再读源行会复制到导入后的版本（同 CreateRule/UpdateRule）。
	if rejectWriteDuringImport(c, "执行规则写操作") {
		return
	}
	caddyID := c.Param("caddy_id")
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	fail := func(status int, message string) {
		recordAudit(c, "复制失败", "负载规则", services.FormatAuditDetail(
			services.AuditRulePart(caddyID), message, services.AuditResultPart("failure")))
		c.JSON(status, models.APIResponse{Code: status, Message: message})
	}
	// failInternal 5xx 分支：审计/日志保留底层错误，响应只回固定文案。
	failInternal := func(message string, cause error) {
		services.Logf("error", "DuplicateRule failed for caddy_id=%s: %s: %v", caddyID, message, cause)
		detail := message
		if cause != nil {
			detail = message + "：" + cause.Error()
		}
		recordAudit(c, "复制失败", "负载规则", services.FormatAuditDetail(
			services.AuditRulePart(caddyID), detail, services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: message})
	}

	rows, err := db.DB.Query(`SELECT `+lbRuleColumns+` FROM lb_rules WHERE caddy_id = ?`, caddyID)
	if err != nil {
		failInternal("读取规则失败", err)
		return
	}
	rules, err := scanLbRules(rows)
	// 同 ListRules。
	if closeErr := rows.Close(); closeErr != nil {
		services.Logf("error", "DuplicateRule rows close error for caddy_id=%s: %v", caddyID, closeErr)
	}
	if err != nil {
		services.Logf("error", "DuplicateRule scan error for caddy_id=%s: %v", caddyID, err)
		fail(http.StatusInternalServerError, "读取规则失败")
		return
	}
	if len(rules) == 0 {
		fail(http.StatusNotFound, "规则不存在")
		return
	}
	// 复制前补挂载关联数据——scanLbRules 不带 Upstreams/PathRules，
	// EnabledUpstreamCount 恒 0 会让 validateRuleFeatures 的动态 DNS 多上游
	// 预检（DynamicDNS && count>1）在复制路径永不触发。
	// 不再对 rule.Domain 规范化——落库域名已由 Create/Update 与启动迁移规范化。
	if err := hydrateRuleRelations(c.Request.Context(), rules); err != nil {
		failInternal("读取规则关联数据失败", err)
		return
	}
	rule := rules[0]

	// 重试窗口上界自愈——源行携带 >60000 越界值
	//（API/MCP/导入/直改 DB 落库的历史值）时，副本不得原样放大并命中新增
	// 上界门 400 死端（与负值自愈同格；http/tcp 上界同值）。负值
	// 由下方 TCP 块按协议处理（http td=-1 是 NTLM 接管态合法哨兵）。
	// interval 越界归零时 duration 同步归零——td>0+ti=0
	// 是渲染必填门的自相矛盾形态（保存成功但配置生成必败）。
	if rule.TCPTryInterval > 60000 {
		rule.TCPTryInterval = 0
		if rule.TCPTryDuration > 0 {
			rule.TCPTryDuration = 0
		}
	}
	if rule.TCPTryDuration > 60000 {
		rule.TCPTryDuration = 0
	}

	// 审计 + +：tcp-TLS / HTTP 专属死配置字段族归一
	// 与 CreateRule/UpdateRule 共用同一 tcpDeadFieldReset 清单——源行遗留
	// enable_tls=1/tls_source=acme_dns、tls_http_redirect、domain、
	// upstream_force_http1 等死形态时，副本会原样携带（tcp 不终结入站 TLS、
	// ACME 任务永不消费证书、HTTP 专属字段 TCP 渲染零消费）。
	if rule.Protocol == "tcp" {
		tcpDeadFieldReset(rule.Protocol, storedRuleTCPDeadFields(&rule))
		// TCP 死配置族：回源域名仅 HTTP 规则支持（保存门对 TCP 硬拒），
		// 存量 TCP 行残留的 upstreams.origin_domain 不得复制到副本——否则复制
		// 即命中保存门 400 死端（用户看不到该字段、无自救路径），且脏配置随
		// 导出/备份/集群快照放大。
		for index := range rule.Upstreams {
			rule.Upstreams[index].OriginDomain = ""
		}
		// TCP 自愈族：custom_routes_enabled 归零后源行残留 path_rules 不得
		// 进入保存门（TCP 分支对 len(PathRules)>0 显式 400）或复制到副本——
		// hydrateRuleRelations 不按开关过滤，须在此显式清空。
		rule.PathRules = []models.PathRule{}
		// 同族：负值重试窗口不喂进复制校验（td/ti 原样
		// 传入会让直改 DB 残留的 tcp 源行复制即 400 死端），也不放大到副本——
		// 与 UpdateRule 最终协议 tcp 块负值自愈同格；非负窗口是合法 tcp 配置，
		// 原样复制（http 源行 td=-1 是 NTLM 接管态，协议原样复制、不受此门）。
		if rule.TCPTryDuration < 0 {
			rule.TCPTryDuration = 0
		}
		if rule.TCPTryInterval < 0 {
			rule.TCPTryInterval = 0
		}
	} else if rule.Protocol == "http" {
		// HTTP 方向反向归一——Create/Update 已清零 TCP-only
		// 字段（tcp_health_check_port/tcp_proxy_protocol），复制路径此前只处理
		// TCP 源行，HTTP 源行的残留值被原样放大到副本。tcp_try_* 是 http/tcp
		// 共用字段，不在此列。
		rule.TCPProxyProtocol = false
		rule.TCPHealthCheckPort = 0
		// HTTP 源行重试窗口下界同族自愈（与 UpdateRule 的 http 分支同格）：
		// 直改 DB/旧版本残留的 td<-1 或 ti<0 会让副本命中值域门 400 死端；
		// -1 是 NTLM 接管态合法哨兵，保留。interval 非法时 duration 不残留
		// 正值（td>0+ti=0 渲染必败）。
		if rule.TCPTryDuration < -1 {
			rule.TCPTryDuration = 0
		}
		if rule.TCPTryInterval < 0 {
			rule.TCPTryInterval = 0
			if rule.TCPTryDuration > 0 {
				rule.TCPTryDuration = 0
			}
		}
	}
	// 非 acme_dns 来源的残留 acme_config_id 不被消费——副本不放大该
	// 跨模式死引用（与 Create/Update/导入同口径；两协议同判；空来源同理）。
	if rule.TLSSource != "acme_dns" {
		rule.ACMEConfigID = 0
	}
	// 副本同样按生效来源清理跨模式残留——
	// 非 manual 不复制证书材料；非 acme_dns 不复制 CA 提供商引用。
	if rule.TLSSource != "manual" {
		rule.TLSCert, rule.TLSKey = "", ""
	}
	if rule.TLSSource != "acme_dns" {
		rule.CAProviderID = 0
	}

	// 主动健康检查未启用时其专属字段渲染零消费——副本与 Create/Update 同口径
	// 归一清零（复制即新建，没有「未提交沿用存量」语义；源行残留死配置不得
	// 随复制放大到新行，进而污染导出/备份/集群快照）。清零结果进复制审计。
	clearedDeadHealthCheck := normalizeInactiveHealthCheckFields(rule.EnableActiveHealthCheck,
		&rule.HealthCheckPath, &rule.HealthCheckHost, &rule.TCPHealthCheckPort)

	// 复制前把源行投影为共享保存输入并执行字段层校验
	// （host/端口/权重/查重/健康检查/请求体大小）——坏上游/坏值不得原样
	// 放大到副本，400 点名源规则。
	if err := h.validateDuplicateRulePayload(rule); err != nil {
		fail(http.StatusBadRequest, fmt.Sprintf("源规则 %s（%s）：%s", rule.Name, caddyID, err.Error()))
		return
	}

	userIDInt := contextUserID(c)

	newCaddyID, err := services.GenerateCaddyID()
	if err != nil {
		fail(http.StatusInternalServerError, "生成规则 ID 失败")
		return
	}

	nowTime := time.Now().UTC()
	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		fail(http.StatusInternalServerError, "开启复制事务失败")
		return
	}
	committed := false
	defer func() {
		if !committed {
			// 与 CreateRule/UpdateRule/DeleteRule 模式一致，回滚错误需记录。
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				services.Logf("error", "DuplicateRule transaction rollback failed: %v", rollbackErr)
			}
		}
	}()

	// DuplicateRule 必须经过与 CreateRule 一致的校验。
	enabledUpstreamCount := 0
	upstreamHosts := make([]string, 0, len(rule.Upstreams))
	for _, u := range rule.Upstreams {
		if u.Enabled {
			enabledUpstreamCount++
			upstreamHosts = append(upstreamHosts, u.Host)
		}
	}
	if err := validateRuleFeatures(ruleFeatureInput{
		Protocol: rule.Protocol, Strategy: rule.Strategy, DynamicDNS: rule.DynamicDNS,
		EnableDnsServer: rule.EnableDnsServer, DnsServer: rule.DnsServer,
		EnabledUpstreamCount: enabledUpstreamCount,
		// 补 5 字段——80 自环门与地址族门在复制
		// 路径此前因零值恒不触发(注释自述「与 CreateRule 一致」未兑现)。
		ListenPort: rule.ListenPort, EnableTLS: rule.EnableTLS, TLSHTTPRedirect: rule.TLSHTTPRedirect,
		EnabledUpstreamHosts: upstreamHosts, DnsFamily: rule.DnsFamily,
		HealthCheckInterval: rule.HealthCheckInterval, HealthCheckTimeout: rule.HealthCheckTimeout,
		EnableCompress: rule.EnableCompress, CompressTypes: rule.CompressTypes,
		CustomRoutesEnabled: rule.CustomRoutesEnabled, PathRules: rule.PathRules,
		ProxyDialTimeout: rule.ProxyDialTimeout, ProxyResponseHeaderTimeout: rule.ProxyResponseHeaderTimeout,
		ProxyReadTimeout: rule.ProxyReadTimeout, ProxyWriteTimeout: rule.ProxyWriteTimeout,
		ProxyStreamTimeout: rule.ProxyStreamTimeout, ProxyFlushInterval: rule.ProxyFlushInterval,
		ProxyStreamCloseDelay:    rule.ProxyStreamCloseDelay,
		NTLMCompatible:           rule.NTLMCompatible,
		UpstreamForceHTTP1:       rule.UpstreamForceHTTP1,
		UpstreamKeepaliveTimeout: rule.UpstreamKeepaliveTimeout,
		// TCP 三字段随负值门接入——复制路径与 CreateRule/UpdateRule 同校验
		// 不留绕行口。
		TCPHealthCheckPort: rule.TCPHealthCheckPort,
		TCPTryDuration:     rule.TCPTryDuration,
		TCPTryInterval:     rule.TCPTryInterval,
	}); err != nil {
		fail(http.StatusBadRequest, "源规则配置不合法："+err.Error())
		return
	}

	// ACME 引用校验已由上方 validateDuplicateRulePayload →
	// validateRulePayloadBeforeSave（共享 validateRuleACMEReferences）覆盖并
	// 点名源规则；此处原有一次同条件/同文案的重复调用（永不
	// 产生新结果，且重复查库），删除。

	// 源行启用上游池混布同检——保存门只拦新建/更新载荷，复制是对存量混布行
	// （直改 DB 或更早版本落库）的旁路放大通道。
	if err := mixedUpstreamPoolError(rule); err != nil {
		fail(http.StatusBadRequest, "源规则配置不合法："+err.Error())
		return
	}

	// INSERT 列清单与值投影走唯一事实源（services.LbRuleInsertSQL/
	// LbRuleInsertArgs）——复制排除 id（AUTOINCREMENT 分配新主键），审计四列
	// 按复制语义覆写（created_by/updated_by=操作者，created_at/updated_at=现在）。
	duplicate := rule
	duplicate.ID = 0
	duplicate.CaddyID = newCaddyID
	// 规则文本长度上限：副本名累积后缀截断到上限内（源名可能已含后缀或接近上限）。
	duplicate.Name = ruleDuplicateName(rule.Name)
	if err := validateRuleTextLengths(duplicate.Name, rule.Description); err != nil {
		fail(http.StatusBadRequest, fmt.Sprintf("源规则 %s（%s）：%s", rule.Name, caddyID, err.Error()))
		return
	}
	duplicate.Enabled = false
	duplicate.CreatedBy = int(userIDInt)
	duplicate.UpdatedBy = int(userIDInt)
	duplicate.CreatedAt = nowTime
	duplicate.UpdatedAt = models.JSONNullTime{NullTime: sql.NullTime{Time: nowTime, Valid: true}}
	duplicateColumns := services.LbRuleInsertColumns("id")
	if _, err := tx.Exec(services.LbRuleInsertSQL(duplicateColumns), services.LbRuleInsertArgs(&duplicate, duplicateColumns)...); err != nil {
		services.Logf("error", "Failed to duplicate rule %s: %v", caddyID, err)
		failInternal("复制规则失败，已回滚", err)
		return
	}

	// 同 UpdateRule——NULL enabled 行须 IIF 归一化（NULL 视同禁用），
	// 复制出的新行显式落 0，避免裸 scan 500 与复制后意外启用。
	// dynamic_dns 同列同病——legacy NULL 行裸 scan
	// NULL→bool 报错恒 500，按 0 归一（遗留死列，渲染只读规则级值）。
	upstreamRows, err := tx.Query(`
		SELECT host, port, COALESCE(weight,1), COALESCE(dynamic_dns,0), `+services.UpstreamEnabledSQLValue+`, COALESCE(protocol,'http'), COALESCE(max_connections,0), COALESCE(origin_domain,'')
		FROM upstreams u WHERE rule_id = ?
	`, caddyID)
	if err != nil {
		failInternal("读取上游失败，已回滚", err)
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
			OriginDomain   string
		}
		if err := upstreamRows.Scan(&u.Host, &u.Port, &u.Weight, &u.DynamicDNS, &u.Enabled, &u.Protocol, &u.MaxConnections, &u.OriginDomain); err != nil {
			upstreamRows.Close()
			failInternal("扫描上游失败，已回滚", err)
			return
		}
		if rule.Protocol == "tcp" {
			// 复制上游从库内源行重新读取（并不使用上方内存投影）——
			// TCP 零消费的回源域名必须在此一并清零，否则副本携带保存门
			// 硬拒的死配置（与编辑/启用同族）。
			u.OriginDomain = ""
		}
		if _, err := tx.Exec(`
			INSERT INTO upstreams (rule_id, host, port, weight, dynamic_dns, enabled, protocol, max_connections, origin_domain)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, newCaddyID, u.Host, u.Port, u.Weight, false /* dynamic_dns 废弃列：复制时归 0 */, u.Enabled, u.Protocol, u.MaxConnections, u.OriginDomain); err != nil {
			upstreamRows.Close()
			failInternal("复制上游失败，已回滚", err)
			return
		}
	}
	if err := upstreamRows.Err(); err != nil {
		if closeErr := upstreamRows.Close(); closeErr != nil {
			services.Logf("error", "DuplicateRule failed to close upstream cursor for caddy_id=%s: %v", caddyID, closeErr)
		}
		failInternal("遍历上游失败，已回滚", err)
		return
	}
	if err := upstreamRows.Close(); err != nil {
		failInternal("关闭上游游标失败，已回滚", err)
		return
	}

	if rule.CustomRoutesEnabled {
		if _, err := tx.Exec(`
		INSERT INTO path_rules (rule_id, sort_order, match_type, path, upstream_path, upstreams_json, response_mode, response_status, response_body, response_content_type, redirect_to, created_at, updated_at)
		SELECT ?, sort_order, match_type, path, upstream_path, upstreams_json, response_mode, response_status, response_body, response_content_type, redirect_to, datetime('now'), datetime('now') FROM path_rules WHERE rule_id = ?
		`, newCaddyID, caddyID); err != nil {
			failInternal("复制路径规则失败，已回滚", err)
			return
		}
	}

	// 2026-09-20 用户裁定（样式批第 4 项）：副本携带安全策略绑定——不携带
	// 会在「启用副本」时形成零防护静默缺口。同事务 INSERT SELECT（与上游/
	// 路径规则复制同口径），成功消息明示携带数量。
	// TCP 副本不复制绑定——TCP 渲染链零消费策略，复制只会把
	// 存量惰性绑定放大到副本（复制路径与协议切换/导入同口径不自造惰性绑定）。
	if rule.Protocol != "tcp" {
		if _, err := tx.Exec(`
			INSERT INTO security_policy_bindings (rule_caddy_id, policy_id)
			SELECT ?, policy_id FROM security_policy_bindings WHERE rule_caddy_id = ?
		`, newCaddyID, caddyID); err != nil {
			failInternal("复制策略绑定失败，已回滚", err)
			return
		}
	}
	var copiedBindings int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id = ?`, newCaddyID).Scan(&copiedBindings); err != nil {
		failInternal("读取副本绑定失败，已回滚", err)
		return
	}

	if err := commitTx(tx); err != nil {
		// 提交结果不可判定：不得断言「未生效」（会诱导操作者重试并产生重复
		// 副本），文案与审计统一走 commitUncertainLabel（与其余规则端点同源）。
		services.Logf("error", "DuplicateRule transaction commit failed for caddy_id=%s (new=%s): %v", caddyID, newCaddyID, err)
		fail(http.StatusInternalServerError, commitUncertainLabel)
		return
	}
	committed = true

	duplicateAuditParts := []string{fmt.Sprintf("源规则：%s", caddyID), fmt.Sprintf("新规则：%s", newCaddyID), rule.Name}
	if hint := inactiveHealthCheckAuditHint(clearedDeadHealthCheck); hint != "" {
		duplicateAuditParts = append(duplicateAuditParts, hint)
	}
	recordAudit(c, "复制", "负载规则", services.FormatAuditDetail(duplicateAuditParts...))
	successMsg := "副本已创建（已禁用）：域名与源规则相同，启用前请修改域名或端口"
	if copiedBindings > 0 {
		successMsg += fmt.Sprintf("；已携带 %d 条策略绑定", copiedBindings)
	}
	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Message: successMsg, Data: gin.H{"caddy_id": newCaddyID}})
}

// storedUpstream 是 upstreams 的现有行投影（仅收敛判定所需列；表无时间戳列，
// 身份保留 = id 不重建 ⇒ 不触发行级同步触发器）。needsNormalize：存量行在
// COALESCE/IIF 归一读覆盖的列上为 NULL（legacy 可空 schema 残留）——
// 契约要求保存后不再存在 NULL 行，此类行即使内容等价也必须原地 UPDATE 归一。
type storedUpstream struct {
	id             int
	host           string
	port           int
	weight         int
	dynamicDNS     bool
	enabled        bool
	protocol       string
	maxConnections int
	originDomain   string
	needsNormalize bool
}

// replaceUpstreamsTx 以「保留不变行」的方式收敛给定规则的上游集合（历史
// 镜像 replacePathRulesTx 三入口语义）。修复前 UpdateRule 恒 DELETE
// 全删 + INSERT：任何规则编辑（含纯改名）都重建全部上游行（id 递增），且恒
// 触发行级同步触发器（upstreams 在集群版本矩阵内）→ 每次 UpdateRule 多一轮
// 从端同步。现语义：
//   - 内容完全一致的存量行 → 零写入，id 原样保留；
//   - 内容变更但身份一致（host+port+protocol）或显式回传真实 id 的行 →
//     原地 UPDATE 保 id；
//   - 消失的行 DELETE（按 id）、新增的行 INSERT。
//
// 身份判定的两个入口：前端编辑既有行回传真实 id；无 id 的调用方
// （MCP/导出导入/集群 apply）退化为按身份键配对。调用方须先完成归一
// （weight 0→1、protocol 默认、tls 校验），内容比较以终值为准。
// storedUpstreamNullColumnsSQL 判定存量上游行是否含「待归一 NULL 列」
// （legacy 可空 schema / 带外写入残留）：判定依据必须覆盖读侧 COALESCE 的
// **全部**列——漏一列时该行的 NULL 在原样保存后永久保留，导出/集群快照继续
// 携带 NULL，与 schema 的 NOT NULL DEFAULT ” 终态不一致。
const storedUpstreamNullColumnsSQL = `(weight IS NULL OR dynamic_dns IS NULL OR enabled IS NULL OR protocol IS NULL OR max_connections IS NULL OR origin_domain IS NULL)`

func replaceUpstreamsTx(ctx context.Context, tx *sql.Tx, ruleID string, upstreams []models.Upstream) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, host, port, COALESCE(weight,1), COALESCE(dynamic_dns,0),
		`+services.UpstreamEnabledSQLValue+`, COALESCE(protocol,'http'), COALESCE(max_connections,0), COALESCE(origin_domain,''),
		`+storedUpstreamNullColumnsSQL+`
		FROM upstreams u WHERE rule_id = ? ORDER BY id`, ruleID)
	if err != nil {
		return fmt.Errorf("读取规则 %s 的上游: %w", ruleID, err)
	}
	var existing []storedUpstream
	for rows.Next() {
		var row storedUpstream
		if err := rows.Scan(&row.id, &row.host, &row.port, &row.weight, &row.dynamicDNS, &row.enabled, &row.protocol, &row.maxConnections, &row.originDomain, &row.needsNormalize); err != nil {
			rows.Close()
			return fmt.Errorf("解析规则 %s 的上游: %w", ruleID, err)
		}
		existing = append(existing, row)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("遍历规则 %s 的上游: %w", ruleID, err)
	}

	indexByID := make(map[int]int, len(existing))
	for index, row := range existing {
		indexByID[row.id] = index
	}
	consumed := make([]bool, len(existing))
	inserts := make([]storedUpstream, 0, len(upstreams))
	for _, u := range upstreams {
		// 上游级 dynamic_dns 是废弃列（渲染只读规则级 DynamicDNS）：写侧恒 0，
		// 不再把请求里的伪语义落库；存量 1 行在内容比较时与 false 不等，故本轮
		// 保存会原地归零一次（语义无变化，列值收敛）。
		incoming := storedUpstream{
			host: u.Host, port: u.Port, weight: u.Weight,
			enabled: u.Enabled, protocol: u.Protocol, maxConnections: u.MaxConnections, originDomain: u.OriginDomain,
		}
		// ① 显式 id 命中（前端编辑既有行回传真实 id）
		if index, ok := indexByID[u.ID]; ok && !consumed[index] {
			consumed[index] = true
			if err := updateUpstreamTx(ctx, tx, existing[index], incoming); err != nil {
				return fmt.Errorf("更新规则 %s 的上游 %s:%d: %w", ruleID, u.Host, u.Port, err)
			}
			continue
		}
		// ② 内容完全一致且无 NULL 残留 → 原样保留（零写入 ⇒ 不触发同步触发器）；
		// needsNormalize 行落入 ③ 原地 UPDATE 归一。
		if index := matchStoredUpstream(existing, consumed, incoming, true); index >= 0 {
			consumed[index] = true
			continue
		}
		// ③ 身份一致（host+port+protocol）→ 原地 UPDATE 保留 id
		if index := matchStoredUpstream(existing, consumed, incoming, false); index >= 0 {
			consumed[index] = true
			if err := updateUpstreamTx(ctx, tx, existing[index], incoming); err != nil {
				return fmt.Errorf("更新规则 %s 的上游 %s:%d: %w", ruleID, u.Host, u.Port, err)
			}
			continue
		}
		inserts = append(inserts, incoming)
	}
	for index, row := range existing {
		if consumed[index] {
			continue
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM upstreams WHERE id = ?", row.id); err != nil {
			return fmt.Errorf("删除规则 %s 的上游 %d: %w", ruleID, row.id, err)
		}
	}
	for _, insert := range inserts {
		if _, err := tx.ExecContext(ctx, `INSERT INTO upstreams (rule_id, host, port, weight, dynamic_dns, enabled, protocol, max_connections, origin_domain)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			ruleID, insert.host, insert.port, insert.weight, insert.dynamicDNS, insert.enabled, insert.protocol, insert.maxConnections, insert.originDomain); err != nil {
			return fmt.Errorf("写入规则 %s 的上游 %s:%d: %w", ruleID, insert.host, insert.port, err)
		}
	}
	return nil
}

// matchStoredUpstream 在未消费的存量行中定位与 incoming 配对的行：exactContent
// 为 true 时要求全部内容列一致（零写入），否则仅按身份键（host+port+protocol）
// 配对（原地 UPDATE 保 id）。
func matchStoredUpstream(existing []storedUpstream, consumed []bool, incoming storedUpstream, exactContent bool) int {
	for index, row := range existing {
		if consumed[index] {
			continue
		}
		if row.host != incoming.host || row.port != incoming.port || row.protocol != incoming.protocol {
			continue
		}
		if exactContent && (row.needsNormalize || row.weight != incoming.weight || row.dynamicDNS != incoming.dynamicDNS ||
			row.enabled != incoming.enabled || row.maxConnections != incoming.maxConnections || row.originDomain != incoming.originDomain) {
			continue
		}
		return index
	}
	return -1
}

// updateUpstreamTx 内容真有变化（或存量行含待归一 NULL 列）时才 UPDATE
// （保 id ⇒ 不触发同步触发器的 DELETE/INSERT 对）。
func updateUpstreamTx(ctx context.Context, tx *sql.Tx, row, incoming storedUpstream) error {
	if !row.needsNormalize && row.host == incoming.host && row.port == incoming.port && row.protocol == incoming.protocol &&
		row.weight == incoming.weight && row.dynamicDNS == incoming.dynamicDNS &&
		row.enabled == incoming.enabled && row.maxConnections == incoming.maxConnections && row.originDomain == incoming.originDomain {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE upstreams SET host=?, port=?, weight=?, dynamic_dns=?, enabled=?, protocol=?, max_connections=?, origin_domain=? WHERE id=?`,
		incoming.host, incoming.port, incoming.weight, incoming.dynamicDNS, incoming.enabled, incoming.protocol, incoming.maxConnections, incoming.originDomain, row.id); err != nil {
		return err
	}
	return nil
}

// BatchRuleBlockPages 批量设置阶段拦截页（规则列表多选浮动操作条）：
// {rule_ids:[], block_page_stage1_id, block_page_stage1_status,
// block_page_stage3_id, block_page_stage3_status}——同校验（页存在/状态码集，
// validateStageBlockPageRef 共享），单事务逐规则 UPDATE lb_rules 4 列 +
// 一次 finishTxApply（单渲染）。非 http（tcp）规则跳过不 UPDATE——阶段页
// 仅 http 渲染消费（与 batch-bind 同口径）。响应
// {bound:n, unchanged:n, skipped:[{rule_id,reason}]}——bound=RowsAffected>0
// 的真实变更数，unchanged=已在目标态的同值命中数。
func (h *Handlers) BatchRuleBlockPages(c *gin.Context) {
	// 导入窗口 fast-fail：批量改页与导入争同一把写锁，排队后按导入后的
	// 库状态生效会让客户端看到提交漂移（与余下规则写端点同门）。
	if rejectWriteDuringImport(c, "执行规则写操作") {
		return
	}
	var req struct {
		RuleIDs               []string `json:"rule_ids"`
		BlockPageStage1ID     int      `json:"block_page_stage1_id"`
		BlockPageStage1Status int      `json:"block_page_stage1_status"`
		BlockPageStage3ID     int      `json:"block_page_stage3_id"`
		BlockPageStage3Status int      `json:"block_page_stage3_status"`
	}
	// 独立 1MB 请求体上限：本端点只收 ≤500 条 rule_ids + 四个整数，全局
	// 128MB（可配 4096MB）上限会让解析期内存/CPU 放大（条数门在解析之后才
	// 生效）。与 CreateRule/PutCaddyConfig 同口径。
	const maxBatchBlockPagesBodyBytes int64 = 1 << 20
	if c.Request.ContentLength > maxBatchBlockPagesBodyBytes {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "请求体过大"})
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBatchBlockPagesBodyBytes)
	if err := c.ShouldBindJSON(&req); err != nil {
		// chunked/未知长度请求体在解析期被 MaxBytesReader 截断（快路径看不到
		// 长度）：与 CreateRule/UpdateRule 同口径，按 413 回应体积超限，
		// 不得折成「请求参数无效」。
		if isRequestBodyTooLarge(err) {
			c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "请求体过大"})
			return
		}
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	if len(req.RuleIDs) == 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "rule_ids 不能为空"})
		return
	}
	// trim+去重保序——重复 id 只处理一次（修复前逐个
	// UPDATE 并放大计数）；全空白视为空清单。
	dedupedRuleIDs := make([]string, 0, len(req.RuleIDs))
	seenRuleIDs := make(map[string]struct{}, len(req.RuleIDs))
	for _, rawRuleID := range req.RuleIDs {
		ruleID := strings.TrimSpace(rawRuleID)
		if ruleID == "" {
			continue
		}
		if _, duplicate := seenRuleIDs[ruleID]; duplicate {
			continue
		}
		seenRuleIDs[ruleID] = struct{}{}
		dedupedRuleIDs = append(dedupedRuleIDs, ruleID)
	}
	if len(dedupedRuleIDs) == 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "rule_ids 不能为空"})
		return
	}
	req.RuleIDs = dedupedRuleIDs
	// 规则条数上限——逐规则 UPDATE 在单事务/单锁内执行，
	// 请求体只受全局 128MB 上限约束，认证管理员可长时间占用 caddyOpMu。
	const maxBatchRuleBlockPages = 500
	if len(req.RuleIDs) > maxBatchRuleBlockPages {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("单次批量设置最多 %d 条规则（当前 %d 条）", maxBatchRuleBlockPages, len(req.RuleIDs))})
		return
	}
	// 请求体读取/绑定已完成后再取全局写锁：慢速上传不得阻塞全部配置写
	//（与 handlers/caddy.go 的锁序契约一致）。
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	if err := validateStageBlockPageRef(req.BlockPageStage1ID, req.BlockPageStage1Status, "阶段 1（IP 访问控制/地域拦截）"); err != nil {
		var validationErr *configValidationError
		if errors.As(err, &validationErr) {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: validationErr.Error()})
			return
		}
		recordRuleWriteFailure(c, "更新", "校验阶段拦截页引用失败", err)
		writeInternalError(c, http.StatusInternalServerError, "校验阶段拦截页引用失败", err)
		return
	}
	if err := validateStageBlockPageRef(req.BlockPageStage3ID, req.BlockPageStage3Status, "阶段 3（WAF）"); err != nil {
		var validationErr *configValidationError
		if errors.As(err, &validationErr) {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: validationErr.Error()})
			return
		}
		recordRuleWriteFailure(c, "更新", "校验阶段拦截页引用失败", err)
		writeInternalError(c, http.StatusInternalServerError, "校验阶段拦截页引用失败", err)
		return
	}
	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		recordRuleWriteFailure(c, "更新", "开启数据库事务失败", err)
		writeInternalError(c, http.StatusInternalServerError, "开启数据库事务失败", err)
		return
	}
	defer func() { rollbackRuleWriteTx(tx, "BatchRuleBlockPages", "") }()
	type skippedRule struct {
		RuleID string `json:"rule_id"`
		Reason string `json:"reason"`
	}
	bound := 0
	unchanged := 0
	skipped := make([]skippedRule, 0)
	// 一次 IN 预取协议，替代逐规则 SELECT（2N → N+1 次 SQL）。
	placeholders := make([]string, len(req.RuleIDs))
	prefetchArgs := make([]any, len(req.RuleIDs))
	for i, ruleID := range req.RuleIDs {
		placeholders[i] = "?"
		prefetchArgs[i] = ruleID
	}
	protocolByRule := make(map[string]string, len(req.RuleIDs))
	prefetchRows, err := tx.QueryContext(caddyWriteCtx(c),
		"SELECT caddy_id, COALESCE(protocol,'') FROM lb_rules WHERE caddy_id IN ("+strings.Join(placeholders, ",")+")", prefetchArgs...)
	if err != nil {
		recordRuleWriteFailure(c, "更新", "读取规则失败", err)
		writeInternalError(c, http.StatusInternalServerError, "读取规则失败", err)
		return
	}
	for prefetchRows.Next() {
		var caddyID, protocol string
		if err := prefetchRows.Scan(&caddyID, &protocol); err != nil {
			prefetchRows.Close()
			recordRuleWriteFailure(c, "更新", "读取规则失败", err)
			writeInternalError(c, http.StatusInternalServerError, "读取规则失败", err)
			return
		}
		protocolByRule[caddyID] = protocol
	}
	if err := prefetchRows.Close(); err != nil {
		recordRuleWriteFailure(c, "更新", "读取规则失败", err)
		writeInternalError(c, http.StatusInternalServerError, "读取规则失败", err)
		return
	}
	if err := prefetchRows.Err(); err != nil {
		recordRuleWriteFailure(c, "更新", "读取规则失败", err)
		writeInternalError(c, http.StatusInternalServerError, "读取规则失败", err)
		return
	}
	for _, ruleCaddyID := range req.RuleIDs {
		// 阶段页 4 列仅 http 渲染消费——非 http(tcp)先查后跳过不 UPDATE
		// (与 batch-bind 的 TCP 跳过同文案同口径),仅不存在记「规则不存在」。
		ruleProtocol, exists := protocolByRule[ruleCaddyID]
		if !exists {
			skipped = append(skipped, skippedRule{ruleCaddyID, "规则不存在"})
			continue
		}
		if ruleProtocol != "http" {
			skipped = append(skipped, skippedRule{ruleCaddyID, "TCP 规则不经过安全链"})
			continue
		}
		// 同值守卫——四列已在目标态的行不匹配（IS NOT 空安全比较），
		// 同值批量零写入 ⇒ 不触发 lb_rules 行级同步触发器（阶段页四列在 OF 清单
		// 内）；bound 按 RowsAffected>0 计（真实变更），affected=0 即
		// 「已在目标态」计入 unchanged（不再把零写入算作成功/误判「规则不存在」）。
		// 版本列（updated_at/updated_by）与规则×4 写端点同口径一起 bump：阶段页
		// 是渲染输入，不推进版本列时并发打开的编辑向导版本门恒通过，PUT 会
		// 静默覆盖本次批量结果，且列表「更新时间/更新者」停留在批量前的值。
		// 守卫不变 ⇒ 同值批量仍零写入（bump 只随真实变更发生）。
		result, err := tx.ExecContext(caddyWriteCtx(c), `UPDATE lb_rules SET block_page_stage1_id=?, block_page_stage1_status=?, block_page_stage3_id=?, block_page_stage3_status=?, updated_at=datetime('now'), updated_by=?
			WHERE caddy_id=? AND (block_page_stage1_id IS NOT ? OR block_page_stage1_status IS NOT ? OR block_page_stage3_id IS NOT ? OR block_page_stage3_status IS NOT ?)`,
			req.BlockPageStage1ID, req.BlockPageStage1Status, req.BlockPageStage3ID, req.BlockPageStage3Status, contextUserID(c), ruleCaddyID,
			req.BlockPageStage1ID, req.BlockPageStage1Status, req.BlockPageStage3ID, req.BlockPageStage3Status)
		if err != nil {
			recordRuleWriteFailure(c, "更新", "批量设置阶段拦截页失败（规则 "+ruleCaddyID+"）", err)
			writeInternalError(c, http.StatusInternalServerError, "批量设置阶段拦截页失败", err)
			return
		}
		affected, err := result.RowsAffected()
		if err != nil {
			recordRuleWriteFailure(c, "更新", "批量设置阶段拦截页失败（确认影响行数，规则 "+ruleCaddyID+"）", err)
			writeInternalError(c, http.StatusInternalServerError, "批量设置阶段拦截页失败", err)
			return
		}
		if affected > 0 {
			bound++
		} else {
			unchanged++
		}
	}
	h.finishTxApply(c, tx, txApplyFinish{
		Resource: "负载规则", AuditAction: "更新", RulesWrittenInTx: true,
		AuditDetail: fmt.Sprintf("批量设置阶段拦截页（阶段 1 页 %d/码 %d，阶段 3 页 %d/码 %d）：成功 %d 条，不变 %d 条，跳过 %d 条",
			req.BlockPageStage1ID, req.BlockPageStage1Status, req.BlockPageStage3ID, req.BlockPageStage3Status, bound, unchanged, len(skipped)),
		SuccessMsg: "批量设置阶段拦截页完成",
		Data:       gin.H{"bound": bound, "unchanged": unchanged, "skipped": skipped},
	})
}

func (h *Handlers) EnableRule(c *gin.Context) {
	if rejectWriteDuringImport(c, "执行规则写操作") {
		return
	}
	caddyID := c.Param("caddy_id")

	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	var originalEnabled, enableTLS, tlsHTTPRedirect bool
	var ruleProtocol, ruleDomain, tlsSource string
	var rulePort, caProviderID int
	var originalUpdatedBy sql.NullInt64
	var originalUpdatedAt sql.NullString
	err := db.DB.QueryRow(`SELECT IIF(enabled IN ('1',1),1,0), COALESCE(protocol,''), COALESCE(domain,''), listen_port,
		COALESCE(tls_source,''), COALESCE(enable_tls,0), COALESCE(tls_http_redirect,0), COALESCE(ca_provider_id,0), updated_by, updated_at
		FROM lb_rules WHERE caddy_id = ?`, caddyID).Scan(&originalEnabled, &ruleProtocol, &ruleDomain, &rulePort, &tlsSource, &enableTLS, &tlsHTTPRedirect, &caProviderID, &originalUpdatedBy, &originalUpdatedAt)
	if dbQueryNotFound(c, err, "规则不存在", "读取规则") {
		return
	}
	if err != nil {
		recordRuleWriteFailure(c, "启用", "读取规则失败", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则失败"})
		return
	}
	// 补偿需要恢复启用 UPDATE 改写前的原始域名/操作者——
	// ruleDomain 随后被规范化，原值必须单独留存。
	originalDomain := ruleDomain
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
		if errors.Is(err, errStoredRuleMissing) {
			// 放锁窗口内规则被并发删除：启用成功没有对象，按冲突语义回报。
			services.Logf("warn", "EnableRule validation re-read lost rule caddy_id=%s (deleted concurrently)", caddyID)
			recordAudit(c, "启用失败", "负载规则", ruleConflictDetail(caddyID, "规则已被删除或并发变更，请刷新后重试"))
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "规则已被删除或并发变更，请刷新后重试"})
			return
		}
		var validationErr *configValidationError
		if errors.As(err, &validationErr) {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: validationErr.Error()})
			return
		}
		recordRuleWriteFailure(c, "启用", "预校验规则配置失败", err)
		writeInternalError(c, http.StatusInternalServerError, "预校验规则配置失败", err)
		return
	}
	// 2026-09-07 裁定：启用路径与保存路径同口径（叠加本进程真实管理口的
	// 层——包级校验只覆盖默认口 8000/2019）。
	if err := h.validateRuleListenPortForSave(ruleProtocol, rulePort); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "端口冲突，无法启用: " + err.Error()})
		return
	}
	// 同端口 TLS/明文混布拦截(启用方向)。
	if ruleProtocol == "http" {
		if err := checkPortTLSMix(caddyID, rulePort, enableTLS); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "端口冲突，无法启用: " + err.Error()})
			return
		}
	}
	if err := h.validatePortFromDB(ruleProtocol, rulePort, caddyID); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "端口冲突，无法启用: " + err.Error()})
		return
	}
	if ruleProtocol == "http" && ruleDomain != "" {
		conflict, err := enabledRuleDomainConflict(ruleDomain, rulePort, caddyID)
		if err != nil {
			services.Logf("error", "EnableRule domain conflict query failed for caddy_id=%s domain=%s: %v", caddyID, ruleDomain, err)
			recordRuleWriteFailure(c, "启用", "检查域名冲突失败", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "检查域名冲突失败"})
			return
		}
		if conflict {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("域名 %s 已被其他启用中的规则使用，无法启用", ruleDomain)})
			return
		}
		shadowRule, shadowDomain, err := queryRedirectShadowConflict(ruleDomain, rulePort, enableTLS, tlsHTTPRedirect, caddyID)
		if err != nil {
			services.Logf("error", "EnableRule redirect shadow query failed for caddy_id=%s domain=%s: %v", caddyID, ruleDomain, err)
			recordRuleWriteFailure(c, "启用", "检查域名跳转冲突失败", err)
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
	// 协议门控——tcp 规则不终结 TLS，证书任务对 tcp 规则只会产生
	// 永不消费的僵尸签发/续签（certJobRuleApplicable 仅查域名）。
	isACME := ruleProtocol == "http" && enableTLS && tlsSource == "acme_dns" && ruleDomain != ""
	var certJobsSnapshot services.CertJobsSnapshot
	if isACME {
		// 启用路径补 ACME 域名形状校验：v2 导入对禁用行不做该校验（启用行才校验），
		// 非法域名集（如 "a.com,b.com,c.com"）会随导入落库；启用时若不在这里拦下，
		// 入队阶段才以 certEnqueue 的默认映射冒 500。与创建/更新/预校验同口径 400。
		if err := services.ValidateACMEDomainsForIssuance(ruleDomain); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
		// 写前解析生效 CA 提供商：无可用提供商是用户可修复的配置状态
		// （400 + 指引）。此前在提交 + /load 之后才解析——一个可写前判定的
		// 前置条件把已提交的启用整体回滚成 500。解析结果供提交后入队直接使用，
		// 提交后不再有「解析 CA 提供商失败」分支。
		resolvedCAProviderID, resolveErr := services.ResolveCAProviderID(caProviderID)
		if resolveErr != nil {
			respondCAProviderResolveFailure(c, "启用", resolveErr)
			return
		}
		caProviderID = resolvedCAProviderID
		certJobsSnapshot, err = services.SnapshotCertJobsForRule(caddyID)
		if err != nil {
			recordRuleWriteFailure(c, "启用", "备份证书任务失败", err)
			writeInternalError(c, http.StatusInternalServerError, "备份证书任务失败", err)
			return
		}
	}
	runtimeSnapshot, err := h.snapshotImportRuntime([]string{caddyID})
	if err != nil {
		h.respondRuleSnapshotError(c, "启用", err)
		return
	}
	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		recordRuleWriteFailure(c, "启用", "开启数据库事务失败", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				services.Logf("error", "EnableRule transaction rollback failed for caddy_id=%s: %v", caddyID, rollbackErr)
			}
		}
	}()
	userIDInt := contextUserID(c)
	// 与编辑/复制同哲学：启用前在同事务内清除存量 TCP 死字段，
	// 配置应用失败时归一与启用状态一并回滚。
	var droppedBindings int64
	if ruleProtocol == "tcp" {
		if _, err := tx.ExecContext(caddyWriteCtx(c), tcpRuleDeadFieldsResetForRuleSQL, caddyID); err != nil {
			recordRuleWriteFailure(c, "启用", "清理 TCP 死配置失败", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "启用规则失败"})
			return
		}
		if _, err := tx.ExecContext(caddyWriteCtx(c), `DELETE FROM path_rules WHERE rule_id = ?`, caddyID); err != nil {
			recordRuleWriteFailure(c, "启用", "清理 TCP 自定义路径失败", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "启用规则失败"})
			return
		}
		// 同族：TCP 零消费 upstreams.origin_domain（仅 HTTP 回源域名），启用时
		// 一并清零，避免启用成功却把死配置留在库里随导出/备份/集群快照放大。
		if _, err := tx.ExecContext(caddyWriteCtx(c), `UPDATE upstreams SET origin_domain = '' WHERE rule_id = ? AND COALESCE(origin_domain,'') <> ''`, caddyID); err != nil {
			recordRuleWriteFailure(c, "启用", "清理上游回源域名失败", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "启用规则失败"})
			return
		}
		// 同族收口：TCP 渲染链不加载安全策略，存量/带外绑定会在策略页显示
		// 生效而运行态零防护——启用路径同样解除（与 UpdateRule/DeleteRule/
		// 导入的清理对齐）。
		bindingResult, err := tx.ExecContext(caddyWriteCtx(c), `DELETE FROM security_policy_bindings WHERE rule_caddy_id = ?`, caddyID)
		if err != nil {
			services.Logf("error", "EnableRule security_policy_bindings cleanup error for caddy_id=%s: %v", caddyID, err)
			recordRuleWriteFailure(c, "启用", "清理安全策略绑定失败", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "启用规则失败"})
			return
		}
		affected, raErr := bindingResult.RowsAffected()
		if raErr != nil {
			services.Logf("error", "EnableRule security_policy_bindings RowsAffected error for caddy_id=%s: %v", caddyID, raErr)
			recordRuleWriteFailure(c, "启用", "确认安全策略绑定清理结果失败", raErr)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "启用规则失败"})
			return
		}
		droppedBindings = affected
		ruleDomain = ""
	}
	enableResult, err := tx.Exec("UPDATE lb_rules SET enabled = 1, domain = ?, updated_at = datetime('now'), updated_by = ? WHERE caddy_id = ?", ruleDomain, userIDInt, caddyID)
	if err != nil {
		recordRuleWriteFailure(c, "启用", "写入数据库失败（启用规则）", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "启用规则失败"})
		return
	}
	// 放锁窗口（快照/预校验期间）内规则可被并发删除：0 行更新意味着后续
	// 渲染/证书入队都基于一条不存在的规则，事务提交后「启用成功」审计与
	// 真实状态相反。0 行必须显性中止（事务随 defer 回滚）。
	if affected, raErr := enableResult.RowsAffected(); raErr != nil || affected == 0 {
		services.Logf("warn", "EnableRule updated 0 rows for caddy_id=%s (deleted concurrently): affected=%d err=%v", caddyID, affected, raErr)
		recordAudit(c, "启用失败", "负载规则", ruleConflictDetail(caddyID, "规则已被删除或并发变更，请刷新后重试"))
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "规则已被删除或并发变更，请刷新后重试"})
		return
	}
	reloadNote, applyErr := h.applyFromTxNote(c, tx, txReloadDetail("rule_enable", caddyID), true)
	if applyErr != nil {
		// 恢复收口（与创建分支同构）：显式回滚事务 → 快照回退 → LKG 钉回
		// 已提交视图（零 /load）→ 横幅持久化（respondRuleApplyError 内）。
		var sideErr error
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			sideErr = fmt.Errorf("回滚未提交事务失败: %w", rbErr)
		}
		runtimeErr := h.restoreImportRuntime(runtimeSnapshot)
		sideErr = errors.Join(sideErr, h.pinLastGoodAfterCompensation())
		h.respondRuleApplyError(c, applyErr, runtimeErr, sideErr, "启用")
		return
	}
	if err := commitTx(tx); err != nil {
		//  +：commit 失败统一走已提交视图恢复
		//（回滚事务 + 重渲染 /load + 回退 LKG/投影/证书物化）。
		recovery := h.recoverCommittedViewAfterCommitFailure(tx)
		services.Logf("error", "EnableRule transaction commit failed for caddy_id=%s: %v", caddyID, err)
		reloadNote.auditReload()
		h.recordPostCommitRestoreFailure(commitSaveFailedSubject, err, recovery.runtime, recovery.db)
		// 提交后失败审计：Explicit 审计策略下中间件不兜底，提交结果不确定
		// （磁盘满/IO/确认丢失）这一最需追溯的场景必须留痕——与创建/更新/
		// 删除/禁用四端点逐字同口径。
		recordAudit(c, "启用失败", "负载规则", services.FormatAuditDetail(
			services.AuditRulePart(caddyID), commitUncertainLabel+"："+errors.Join(err, recovery.err()).Error(), services.AuditResultPart("failure")))
		writeInternalError(c, http.StatusInternalServerError, commitUncertainLabel, nil)
		return
	}
	committed = true
	if droppedBindings > 0 {
		recordAudit(c, "启用", "安全策略", fmt.Sprintf("规则 %s 为 TCP，已解除 %d 条安全策略绑定（TCP 不参与策略渲染）", caddyID, droppedBindings))
	}

	var enqueuedJobID int
	var queueManager *services.CAQueueManager
	restoreEnabledState := func() (runtimeErr, sideErr error) {
		if enqueuedJobID > 0 && queueManager != nil {
			cancelCertJob(enqueuedJobID)
		}
		var caddyErr, dbErr, jobsErr error
		if isACME {
			caddyErr = h.restoreImportRuntime(runtimeSnapshot)
		}
		// 补偿必须恢复启用 UPDATE 改写过的全部列——此前只恢复
		// enabled，updated_at/updated_by 指向未生效的启用尝试，规范化域名也
		// 被留在行上。
		restoreResult, execErr := db.DB.Exec("UPDATE lb_rules SET enabled = ?, domain = ?, updated_by = ?, updated_at = COALESCE(NULLIF(?, ''), datetime('now')) WHERE caddy_id = ?",
			originalEnabled, originalDomain, originalUpdatedBy, originalUpdatedAt.String, caddyID)
		if execErr != nil {
			dbErr = fmt.Errorf("恢复规则启用状态: %w", execErr)
		} else if affected, raErr := restoreResult.RowsAffected(); raErr != nil {
			dbErr = fmt.Errorf("恢复规则启用状态: 读取影响行数: %w", raErr)
		} else if affected == 0 {
			// 规则已被并发删除——补偿静默 0 行会让调用方以为已回滚。
			dbErr = fmt.Errorf("恢复规则启用状态: 规则已被删除（影响行数为 0）")
		}
		if isACME {
			jobsErr = services.RestoreCertJobsForRule(certJobsSnapshot)
		}
		// 运行配置恢复与附带失败（DB 回退 + 任务行回退 + LKG 钉回）分通道：
		// 只有前者决定横幅两态标签。DB 回退（上方 UPDATE）完成后才能钉回：
		// 已提交视图不得含本次启用。
		runtimeErr = caddyErr
		sideErr = errors.Join(dbErr, jobsErr, h.pinLastGoodAfterCompensation())
		return runtimeErr, sideErr
	}
	failEnableWithStatus := func(message string, status int, cause error) {
		// 启用端点为 Explicit 审计策略，中间件不兜底；此前
		// 提交后的失败（CA 解析/任务读取/Resume 0 行等）只回滚无操作审计，
		// 运维无法追溯谁在何时启用了哪条规则以及失败原因。
		// 5xx 响应只回固定文案：底层错误进运行日志与操作审计，不进响应体。
		if cause != nil {
			services.Logf("error", "EnableRule post-commit failure for caddy_id=%s: %s: %v", caddyID, message, cause)
		}
		runtimeErr, sideErr := restoreEnabledState()
		restoreErr := errors.Join(runtimeErr, sideErr)
		// 真实 /load 已发生（重载审计）+ 补偿恢复失败的分叉横幅。
		reloadNote.auditReload()
		h.recordPostCommitRestoreFailure(caddyApplyFailureSubject(message), errors.New(message), runtimeErr, sideErr)
		detail := message
		if cause != nil {
			detail = message + "：" + cause.Error()
		}
		if restoreErr != nil {
			services.Logf("error", "补偿失败: EnableRule compensation failed for caddy_id=%s: %v", caddyID, restoreErr)
			recordAudit(c, "启用失败", "负载规则", services.FormatAuditDetail(
				services.AuditRulePart(caddyID), detail, "补偿恢复失败: "+restoreErr.Error(), services.AuditResultPart("failure")))
			writeInternalError(c, http.StatusInternalServerError, message+"；规则与 Caddy 恢复失败", nil)
			return
		}
		recordAudit(c, "启用失败", "负载规则", services.FormatAuditDetail(
			services.AuditRulePart(caddyID), detail, services.AuditResultPart("failure")))
		c.JSON(status, models.APIResponse{Code: status, Message: message})
	}
	failEnable := func(message string, cause error) {
		failEnableWithStatus(message, http.StatusInternalServerError, cause)
	}
	// 入队失败按错误种类定状态（证书签发任务未运行 → 409）；4xx 保留细节文案。
	failCertEnqueue := func(prefix string, enqueueErr error) {
		status, message := certEnqueueErrorResponse(prefix, enqueueErr)
		failEnableWithStatus(message, status, enqueueErr)
	}

	domain := ruleDomain
	services.Logf("info", "EnableRule TLS state for caddy_id=%s: enableTLS=%v tlsSource=%s domain=%s caProviderID=%d", caddyID, enableTLS, tlsSource, domain, caProviderID)
	if isACME {
		// CA 提供商已在写前门解析（无可用提供商=400，未提交任何状态），
		// 此处直接使用解析结果，不再引入提交后失败的解析分支。
		queueManager = services.GetCAQueueManager()
		enqueueCertJob := func() error {
			jobID, changed, enqueueErr := createOrRequeueCertJobVerified(caddyID, domain, caProviderID, queueManager)
			if changed {
				enqueuedJobID = jobID
			}
			return enqueueErr
		}

		var jobStatus, jobMsg string
		var jobExpiresAt sql.NullTime
		var jobID, jobProviderID int
		hasJob := false
		err := db.DB.QueryRow("SELECT id, status, COALESCE(message,''), expires_at, COALESCE(ca_provider_id,0) FROM cert_jobs WHERE rule_id=? AND domain=? ORDER BY id DESC LIMIT 1", caddyID, canonicalACMEDomainForJobLookup(domain)).Scan(&jobID, &jobStatus, &jobMsg, &jobExpiresAt, &jobProviderID)
		if err == nil {
			hasJob = true
		} else if !errors.Is(err, sql.ErrNoRows) {
			failEnable("读取证书任务失败", err)
			return
		}
		// 续期天数读取单源（services.GetCertRenewalDays）——
		// 无效值降级与 error 级留痕统一由 helper 承担（<=0 兜底语义
		// 保持：helper 对 <=0 返回默认 30 并留痕）。
		renewalDays := services.GetCertRenewalDays()
		var expiryPtr *time.Time
		if jobExpiresAt.Valid {
			expiry := jobExpiresAt.Time
			expiryPtr = &expiry
		}
		action := ResolveEnableCertJobAction(hasJob, jobStatus, expiryPtr, time.Now(), renewalDays)
		if hasJob {
			resolvedJobProviderID, resolveJobErr := services.ResolveCAProviderID(jobProviderID)
			if resolveJobErr != nil {
				failEnable("解析证书任务 CA 提供商失败", resolveJobErr)
				return
			}
			if resolvedJobProviderID != caProviderID {
				action = EnableCertJobRetry
			}
		}

		switch action {
		case EnableCertJobCreate:
			if queueManager == nil {
				failEnable("CA 队列未初始化，无法创建证书任务", nil)
				return
			}
			err = enqueueCertJob()
			if err != nil {
				failCertEnqueue("创建证书任务失败", err)
				return
			}
			// 与禁用侧同通道留痕（对照 [WARN] cancelled）：入队成功后才写，
			// 用户可在 certjob-<rule>.log 看到任务何时重新排队。
			services.WriteCertJobLogByRule(caddyID, "INFO", "queued", "规则已启用，已创建证书任务")
			recordAudit(c, "创建", "证书任务", fmt.Sprintf("启用规则 %s，创建证书任务 (%s)", caddyID, domain))
		case EnableCertJobKeep:
			services.WriteCertJobLogByRule(caddyID, "INFO", "kept", "规则已启用，证书仍有效，保持现有任务")
			recordAudit(c, "启用", "证书任务", fmt.Sprintf("启用规则 %s，证书有效（过期前%d天续签），保持现有证书", caddyID, renewalDays))
		case EnableCertJobResume:
			if enableCertJobResumePreUpdateHook != nil {
				enableCertJobResumePreUpdateHook(jobID)
			}
			// UPDATE 无状态 CAS，任何未来在上方 SELECT 与此处之间
			// 删除行的路径都会 0 行命中，「启用成功但任务行不存在、续签链断」
			// 被审计文案掩盖——核对 RowsAffected==1，否则按失败补偿。
			resumeResult, err := db.DB.Exec("UPDATE cert_jobs SET status='issued', message='证书有效，已恢复使用', renewal_attempts=0, ca_available_after=NULL, last_error_code=NULL, updated_at=datetime('now') WHERE id=?", jobID)
			if err != nil {
				failEnable("恢复证书任务失败", err)
				return
			}
			resumed, err := resumeResult.RowsAffected()
			if err != nil || resumed != 1 {
				failEnable("恢复证书任务失败：任务行不存在或已被并发变更", nil)
				return
			}
			// Resume 把 'disabled'→'issued' 发生在 ApplyConfigFromTx 之后——
			// 渲染时双层过滤（caddy.go SQL status!='disabled' + certselector 跳过 disabled）
			// 使已应用配置缺 TLS/301/证书文件，且 needJob 被 Resume 抑制不再触发任何
			// re-apply，看门狗只查路由存在性——静默失配无上界。此处已提交视图=规则启用
			// +job issued，立即重渲染重应用使 TLS 恢复；失败走既有 failEnable 补偿
			//（enabled=0 + certJobsSnapshot 恢复 + 运行时快照恢复）。
			// 强制变体 + recordCaddyApplyResult（已持 caddyOpMu，不可用
			// applyCaddyConfigE——重入死锁）。
			reapplyErr := h.caddyService.GenerateAndApplyConfigForceInLock() // 已持锁——InLock 变体防重入死锁
			h.recordCaddyApplyResult(reapplyErr)
			if reapplyErr != nil {
				failEnable("恢复证书任务后重载 Caddy 配置失败", reapplyErr)
				return
			}
			// 第二轮已持久化恢复后的 TLS 配置，首轮 note 不得再回写无 TLS 载荷。
			reloadNote.markLastGoodSuperseded()
			// 恢复成功（DB + 重渲染均已完成）后留痕，补偿分支不写。
			services.WriteCertJobLogByRule(caddyID, "INFO", "resumed", "规则已启用，证书任务已恢复")
			recordAudit(c, "启用", "证书任务", fmt.Sprintf("启用规则 %s，证书仍有效，恢复使用现有证书", caddyID))
		case EnableCertJobRenew:
			if queueManager == nil {
				failEnable("CA 队列未初始化，无法续签证书", nil)
				return
			}
			err = enqueueCertJob()
			if err != nil {
				failCertEnqueue("续签排队失败", err)
				return
			}
			// 与禁用侧同通道留痕（对照 [WARN] cancelled）：入队成功后才写。
			services.WriteCertJobLogByRule(caddyID, "INFO", "renew", "规则已启用，证书即将过期，已重新排队续签")
			recordAudit(c, "续签", "证书任务", fmt.Sprintf("启用规则 %s，证书即将过期，重新排队续签", caddyID))
		case EnableCertJobRetry:
			if queueManager == nil {
				failEnable("CA 队列未初始化，无法重试证书任务", nil)
				return
			}
			err = enqueueCertJob()
			if err != nil {
				failCertEnqueue("重试排队失败", err)
				return
			}
			// 与禁用侧同通道留痕：失败/暂停任务经启用重新排队。
			services.WriteCertJobLogByRule(caddyID, "INFO", "retry", "规则已启用，证书任务已重新排队")
			recordAudit(c, "重试", "证书任务", fmt.Sprintf("启用规则 %s，任务之前已暂停/失败，重新排队", caddyID))
		default:
			// 在途跳过同样留痕——启用动作发生但任务已在签发中（无需操作）。
			services.WriteCertJobLogByRule(caddyID, "INFO", "in_flight", fmt.Sprintf("规则已启用，签发任务已在进行中（状态: %s）", jobStatus))
			recordAudit(c, "启用", "证书任务", fmt.Sprintf("启用规则 %s，签发任务已在进行中 (状态: %s)", caddyID, jobStatus))
		}
	}

	recordAudit(c, "启用", "负载规则", services.FormatAuditDetail(services.AuditRulePart(caddyID), "状态：已启用"))
	reloadNote.finalize()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已启用"})
}

// upstreamWeightPresenceProbe 区分「省略 weight」与「显式 0」
// typed 绑定把省略解码为 0，与显式 0 不可分——省略须落默认 1（与导入侧
// 缺键→schema DEFAULT 1 同口径，config_backup.go 门），显式 0/负值
// 留给 validateRuleUpstreams 响亮 400。
type upstreamWeightPresenceProbe struct {
	Upstreams []struct {
		Weight *int `json:"weight"`
	} `json:"upstreams"`
}

// applyOmittedUpstreamWeightDefaults 把省略 weight 的上游行置默认 1；显式值
// （含 0/负）原样保留给写侧校验判定。探针绑定失败或行数不齐时不做填充
// （主绑定已先行报错，或畸形形态由后续校验兜底）。
func applyOmittedUpstreamWeightDefaults(c *gin.Context, upstreams []models.Upstream) {
	if len(upstreams) == 0 {
		return
	}
	var probe upstreamWeightPresenceProbe
	if err := c.ShouldBindBodyWith(&probe, binding.JSON); err != nil {
		return
	}
	if len(probe.Upstreams) != len(upstreams) {
		return
	}
	for i := range upstreams {
		if probe.Upstreams[i].Weight == nil {
			upstreams[i].Weight = 1
		}
	}
}

// certJobStatusSemantics 是 cert_jobs 状态的守卫语义：两处门从同一张表派生，
// 避免同一状态在两处各自解释（曾把 downloaded——已签发、仅部署退避——在脱离
// ACME 路径判成「证书申请中」，而保存路径早已放行）。
type certJobStatusSemantics struct {
	// blockRuleEdit 保存路径（改名称/上游/证书来源）是否前置 409。
	blockRuleEdit bool
	// blockOrphanACME 规则脱离 ACME 自动签发（改 manual / 关 TLS）是否前置 409。
	blockOrphanACME bool
}

// certJobStatusSemanticTable 是上述语义的单源表。未登记的状态两处都阻塞
// （fail-closed：新增状态默认阻塞，只有显式登记才放行）：
//   - 终态 issued/failed/disabled：历史行，无 worker 在跑。
//   - waiting_ca：CA 限流冷却（可达 1–3 小时，无 worker）。保存路径放行——
//     冷却期内连改名称/上游都 409 与同族端点口径矛盾（caqueue 明文「冷却期
//     不应拦截删除/禁用」），改域风险由提交后迁移与退役补偿覆盖；脱离 ACME
//     路径仍阻塞——CA 排队在途同属在途段（2026-10-19 收窄裁定）。
//   - downloaded：证书已签发、仅部署退避重试（无 worker），材料已在库——两处
//     都放行。
//   - queued/pending：未起动（queue 中可复活）。保存路径阻塞——needJob/入队
//     分支以「不存在非终态任务」为前提，放行会让同一规则重复入队；脱离 ACME
//     路径放行——维持「删除+提交后取消+200」的切换逃生口。
var certJobStatusSemanticTable = map[string]certJobStatusSemantics{
	"issued":     {},
	"failed":     {},
	"disabled":   {},
	"waiting_ca": {blockOrphanACME: true},
	"downloaded": {},
	"queued":     {blockRuleEdit: true},
	"pending":    {blockRuleEdit: true},
}

// certJobStatusesBlocking 从规范枚举（db.CertJobStatuses 单源）派生出满足
// block 判定的状态集。逐调用计算：枚举极小，UpdateRule 非热路径，避免包级
// 缓存漂移。
func certJobStatusesBlocking(block func(certJobStatusSemantics) bool) []string {
	statuses := make([]string, 0, len(db.CertJobStatuses()))
	for _, status := range db.CertJobStatuses() {
		sem, registered := certJobStatusSemanticTable[status]
		if !registered {
			statuses = append(statuses, status) // fail-closed：未登记状态两处都阻塞
			continue
		}
		if block(sem) {
			statuses = append(statuses, status)
		}
	}
	return statuses
}

// executingACMEJobStatuses 派生「执行中/CA 往返在途」cert_jobs 状态集：规则脱离
// ACME 自动签发（orphanACME）时在删除任务行之前用它判定是否 409。
func executingACMEJobStatuses() []string {
	return certJobStatusesBlocking(func(sem certJobStatusSemantics) bool { return sem.blockOrphanACME })
}

// ruleEditBlockingCertJobStatuses 是规则编辑（保存）的证书任务守卫状态集。
func ruleEditBlockingCertJobStatuses() []string {
	return certJobStatusesBlocking(func(sem certJobStatusSemantics) bool { return sem.blockRuleEdit })
}

// disableCertJobsForRuleTx 是「规则禁用/停用」暂停证书任务的单源写点
// UpdateRule（PUT enabled=false 同语义入口）与 DisableRule
// 原两份手写 UPDATE 谓词漂移——前者 status<>'disabled' 会把 failed 终态行
// 改写为 disabled 抹掉失败史实；统一为 NOT IN ('failed','disabled')，与
// config_backup.go pauseCertJobsForImportDisabledRule（导入冲突
// 暂停）谓词逐字一致。返回受影响行数；审计/日志由调用方负责。
func disableCertJobsForRuleTx(tx *sql.Tx, caddyID string) (int64, error) {
	result, err := tx.Exec(`UPDATE cert_jobs SET status='disabled', message='规则已禁用，任务已暂停', updated_at=datetime('now') WHERE rule_id=? AND status NOT IN ('failed','disabled')`, caddyID)
	if err != nil {
		return 0, err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return rowsAffected, nil
}

// ruleExistsByCaddyID 报告规则行是否仍存在。
func ruleExistsByCaddyID(caddyID string) (bool, error) {
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(1) FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

// cleanupUncommittedRuleCertsAfterCommitFailure 在 CreateRule 的 Commit 结果
// 不确定时清理新规则的证书文件。判据是「已提交视图是否引用该规则」：
// Commit 返回错误无法区分未提交与已提交但确认丢失——若提交实际生效，恢复链
// 刚按已提交视图重新物化的 cert/key 正是 /load 已下发的材料，删除会让 DB 与
// 运行配置指向不存在的文件（下一次重载/重启校验失败、该域名 TLS 中断，且无
// 自动收敛路径）。只有规则确实不存在时才删，孤儿形态由证书目录 GC 兜底。
// 存在性查询失败同样不删（误删切证书的代价远高于惰性孤儿）。
func cleanupUncommittedRuleCertsAfterCommitFailure(caddyID string) error {
	exists, err := ruleExistsByCaddyID(caddyID)
	if err != nil {
		services.Logf("error", "CreateRule commit 失败后无法判定规则 %s 是否已提交（跳过证书文件清理，残留由 GC 兜底）: %v", caddyID, err)
		return nil
	}
	if exists {
		return nil
	}
	return services.RemoveCertFiles(caddyID)
}

// abortIfRuleDeleted 复核 UpdateRule 主动放锁窗口结束后规则是否仍存在。
// 域名迁移/证书任务取消路径会临时放开 caddyOpMu，
// 窗口内并发的 DeleteRule 可以完整提交；若本请求随后继续，任何失败分支的
// restoreRuleDBSnapshot/restoreImportRuntime 都会按更新前快照把已删除的规则
// （含上游、路径规则与运行路由）整体复活——删除结果被静默撤销，且
// security_policy_bindings 已随删除清空，复活出的是「零策略」规则。
// 返回 true 表示已写出错误响应，调用方必须立即 return。
func abortIfRuleDeleted(c *gin.Context, caddyID string) bool {
	exists, err := ruleExistsByCaddyID(caddyID)
	if err != nil {
		services.Logf("error", "UpdateRule: 复核规则存在性失败 for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则失败"})
		return true
	}
	if !exists {
		services.Logf("warn", "UpdateRule: 规则 %s 已在放锁窗口内被删除，中止后续迁移/补偿（不复活规则）", caddyID)
		recordAudit(c, "更新失败", "负载规则", ruleConflictDetail(caddyID, "规则已被删除，本次更新已中止"))
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "规则已被删除，本次更新已中止"})
		return true
	}
	return false
}

// updateRuleLockWindowHook / disableRuleLockWindowHook 是测试专用钩子：在
// UpdateRule（window=1 证书取消窗口 / window=2 域名迁移取消窗口）与
// DisableRule 的放锁窗口内触发，用于模拟窗口内并发的规则删除/更新
// （并发修改复核 并发修改复核与 删除复核 删除复核的回归测试）。
var (
	updateRuleLockWindowHook  func(caddyID string, window int)
	disableRuleLockWindowHook func(caddyID string)
)

// ruleMutationFingerprint 计算规则形态指纹（并发修改复核）：lb_rules 行 +
// upstreams + path_rules + security_policy_bindings 四面的完整投影。map 序列化
// 由 encoding/json 按键名排序；关系行按 id/策略 id 排序。用于判定主动放锁窗口
// 内是否有人提交了对同一规则的修改（本请求提交后的指纹为基线）。
//
// 安全策略绑定必须参与指纹：绑定写端点（单条/批量）只改
// security_policy_bindings、不写 lb_rules，漏掉该表会把「他人刚绑定/解绑策略」
// 误判为「无人并发修改」；本请求随后失败时 restoreImportRuntime 会按请求前快照
// 整体恢复运行配置，把他人已生效的防护静默撤掉（DB 保留绑定、运行面回滚）。
func ruleMutationFingerprint(ctx context.Context, caddyID string) (string, error) {
	ruleRow, err := dumpRowByKey(ctx, "lb_rules", "caddy_id", caddyID)
	if err != nil {
		return "", err
	}
	ruleJSON, err := json.Marshal(ruleRow)
	if err != nil {
		return "", fmt.Errorf("序列化规则行指纹: %w", err)
	}
	upstreamRows, err := queryRowsAsMaps(ctx, db.DB, rowQuery{
		label: "上游指纹",
		query: "SELECT * FROM upstreams WHERE rule_id = ? ORDER BY id",
		args:  []any{caddyID},
	})
	if err != nil {
		return "", err
	}
	upstreamJSON, err := json.Marshal(upstreamRows)
	if err != nil {
		return "", fmt.Errorf("序列化上游指纹: %w", err)
	}
	pathRows, err := queryRowsAsMaps(ctx, db.DB, rowQuery{
		label: "路径规则指纹",
		query: "SELECT * FROM path_rules WHERE rule_id = ? ORDER BY id",
		args:  []any{caddyID},
	})
	if err != nil {
		return "", err
	}
	pathJSON, err := json.Marshal(pathRows)
	if err != nil {
		return "", fmt.Errorf("序列化路径规则指纹: %w", err)
	}
	bindingRows, err := queryRowsAsMaps(ctx, db.DB, rowQuery{
		label: "策略绑定指纹",
		query: "SELECT * FROM security_policy_bindings WHERE rule_caddy_id = ? ORDER BY policy_id",
		args:  []any{caddyID},
	})
	if err != nil {
		return "", err
	}
	bindingJSON, err := json.Marshal(bindingRows)
	if err != nil {
		return "", fmt.Errorf("序列化策略绑定指纹: %w", err)
	}
	return string(ruleJSON) + "\n" + string(upstreamJSON) + "\n" + string(pathJSON) + "\n" + string(bindingJSON), nil
}

// abortIfRuleConcurrentlyModified 在放锁窗口结束后复核规则是否被并发修改
// （并发修改复核）：窗口内他人 UpdateRule 可完整提交；本请求若继续并随后失败，
// restoreRuleDBSnapshot/restoreImportRuntime 会按请求前快照把他人已提交内容
// 整体回退。检测到不一致即中止（409 + 审计「并发修改」），并跳过整份恢复
// ——中止时运行态与本请求提交后的 DB 视图一致，恢复反而会回退他人路由。
// 指纹读取失败时不判定（返回 false，维持既有恢复链语义）。
// 返回 true 表示已写出错误响应，调用方必须立即 return。
func abortIfRuleConcurrentlyModified(c *gin.Context, caddyID, baseline string) bool {
	return abortIfRuleConcurrentlyModifiedAs(c, caddyID, baseline, "更新")
}

// abortIfRuleConcurrentlyModifiedAs 与 abortIfRuleConcurrentlyModified 同实现，
// opName 区分调用入口的审计/日志动作词（UpdateRule=更新 / DisableRule=禁用）。
func abortIfRuleConcurrentlyModifiedAs(c *gin.Context, caddyID, baseline, opName string) bool {
	current, err := ruleMutationFingerprint(c.Request.Context(), caddyID)
	if err != nil {
		services.Logf("error", "%s: 复核规则并发修改失败 for caddy_id=%s: %v", opName, caddyID, err)
		return false
	}
	if current == baseline {
		return false
	}
	services.Logf("warn", "%s: 规则 %s 已在放锁窗口内被并发修改，中止后续迁移/补偿（不回退他人已提交内容）", opName, caddyID)
	// 两条出口都在 commitTx 与真实 /load 之后：库与运行配置已是本请求的结果，
	// 被跳过的只有后续证书迁移/补偿。文案必须点明「已保存」——「本次操作已中止」
	// 会让操作者以为什么都没落库，随后重复提交或误判为配置未生效。
	detail := services.FormatAuditDetail(
		services.AuditRulePart(caddyID), "本次变更已保存；放锁窗口内检测到并发修改，已跳过后续迁移/补偿（不回退他人已提交内容）", services.AuditResultPart("failure"))
	// 审计词条必须为字面量（词汇门禁校验），按入口分支各写一次。
	switch opName {
	case "禁用":
		recordAudit(c, "禁用失败", "负载规则", detail)
	default:
		recordAudit(c, "更新失败", "负载规则", detail)
	}
	c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "本次变更已保存，随后检测到并发修改，已跳过后续证书迁移/补偿，请刷新确认"})
	return true
}

func (h *Handlers) DisableRule(c *gin.Context) {
	if rejectWriteDuringImport(c, "执行规则写操作") {
		return
	}
	caddyID := c.Param("caddy_id")

	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	var originalEnabled, enableTLS bool
	var domain, tlsSource string
	err := db.DB.QueryRow("SELECT IIF(enabled IN ('1',1),1,0), COALESCE(domain,''), COALESCE(tls_source,''), COALESCE(enable_tls,0) FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&originalEnabled, &domain, &tlsSource, &enableTLS)
	if dbQueryNotFound(c, err, "规则不存在", "读取规则") {
		return
	}
	if err != nil {
		recordRuleWriteFailure(c, "禁用", "读取规则失败", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则失败"})
		return
	}
	if !originalEnabled {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已禁用"})
		return
	}

	// UX 快路径预检（用户裁决）：与 DeleteRule 同款——有 worker 正在执行签发
	// 时禁用会进入有界取消等待（最长 2 分钟），秒回 409 优于请求悬挂。仅拦
	// 「执行中」；TOCTOU 窗口落入既有超时中止+回滚保护，正确性不变。
	if qm := services.GetCAQueueManager(); qm != nil && qm.HasRunningJobForRule(caddyID) {
		recordAudit(c, "禁用失败", "负载规则", ruleConflictDetail(caddyID, "该规则有正在进行的证书签发任务（约需几分钟），请任务完成后再禁用或稍后重试"))
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "该规则有正在进行的证书签发任务（约需几分钟），请任务完成后再禁用或稍后重试"})
		return
	}

	runtimeSnapshot, err := h.snapshotImportRuntime([]string{caddyID})
	if err != nil {
		h.respondRuleSnapshotError(c, "禁用", err)
		return
	}
	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		recordRuleWriteFailure(c, "禁用", "开启数据库事务失败", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				services.Logf("error", "DisableRule transaction rollback failed for caddy_id=%s: %v", caddyID, rollbackErr)
			}
		}
	}()
	userIDInt := contextUserID(c)
	disableResult, err := tx.Exec("UPDATE lb_rules SET enabled = 0, updated_at = datetime('now'), updated_by = ? WHERE caddy_id = ?", userIDInt, caddyID)
	if err != nil {
		recordRuleWriteFailure(c, "禁用", "写入数据库失败（禁用规则）", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "禁用规则失败"})
		return
	}
	// 同 EnableRule：快照窗口内规则可被并发删除，0 行更新必须中止（事务
	// 回滚），否则会产出「禁用成功」审计并渲染一条不存在的规则。
	if affected, raErr := disableResult.RowsAffected(); raErr != nil || affected == 0 {
		services.Logf("warn", "DisableRule updated 0 rows for caddy_id=%s (deleted concurrently): affected=%d err=%v", caddyID, affected, raErr)
		recordAudit(c, "禁用失败", "负载规则", ruleConflictDetail(caddyID, "规则已被删除或并发变更，请刷新后重试"))
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "规则已被删除或并发变更，请刷新后重试"})
		return
	}
	var disabledJobs int64
	if enableTLS && tlsSource == "acme_dns" && domain != "" {
		// 谓词经 disableCertJobsForRuleTx 单源——与 UpdateRule
		// 禁用入口/config_backup 导入冲突暂停同口径，failed 终态行保留。
		var derr error
		disabledJobs, derr = disableCertJobsForRuleTx(tx, caddyID)
		if derr != nil {
			recordRuleWriteFailure(c, "禁用", "更新证书任务状态失败", derr)
			writeInternalError(c, http.StatusInternalServerError, "更新证书任务状态失败", derr)
			return
		}
	}
	reloadNote, applyErr := h.applyFromTxNote(c, tx, txReloadDetail("rule_disable", caddyID), true)
	if applyErr != nil {
		// 恢复收口（与创建分支同构）：显式回滚事务 → 快照回退 → LKG 钉回
		// 已提交视图（零 /load）→ 横幅持久化（respondRuleApplyError 内）。
		var sideErr error
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			sideErr = fmt.Errorf("回滚未提交事务失败: %w", rbErr)
		}
		runtimeErr := h.restoreImportRuntime(runtimeSnapshot)
		sideErr = errors.Join(sideErr, h.pinLastGoodAfterCompensation())
		h.respondRuleApplyError(c, applyErr, runtimeErr, sideErr, "禁用")
		return
	}
	if err := commitTx(tx); err != nil {
		//  +：commit 失败统一走已提交视图恢复
		//（回滚事务 + 重渲染 /load + 回退 LKG/投影/证书物化）。
		recovery := h.recoverCommittedViewAfterCommitFailure(tx)
		services.Logf("error", "DisableRule transaction commit failed for caddy_id=%s: %v", caddyID, err)
		reloadNote.auditReload()
		h.recordPostCommitRestoreFailure(commitSaveFailedSubject, err, recovery.runtime, recovery.db)
		// 提交后失败审计：提交失败留痕（Explicit 审计策略）。
		recordAudit(c, "禁用失败", "负载规则", services.FormatAuditDetail(
			services.AuditRulePart(caddyID), commitUncertainLabel+"："+errors.Join(err, recovery.err()).Error(), services.AuditResultPart("failure")))
		writeInternalError(c, http.StatusInternalServerError, commitUncertainLabel, nil)
		return
	}
	committed = true
	// 并发修改复核基线=本请求提交后的规则形态指纹（与 UpdateRule 同口径）——
	// 下方放锁取消窗口内并发 EnableRule/UpdateRule 可完整提交，窗口后必须
	// 复核，否则「禁用成功」审计与最终状态可能不一致（启用侧重新入队的
	// 任务已被本请求取消）。指纹读取失败时按既有语义跳过复核（不判定）。
	var disableFingerprintBaseline string
	if baseline, fpErr := ruleMutationFingerprint(c.Request.Context(), caddyID); fpErr != nil {
		services.Logf("error", "DisableRule: 计算并发修改复核基线失败 for caddy_id=%s: %v", caddyID, fpErr)
	} else {
		disableFingerprintBaseline = baseline
	}
	if disabledJobs > 0 {
		services.WriteCertJobLogByRule(caddyID, "WARN", "cancelled", "规则已禁用，证书任务已暂停")
		recordAudit(c, "禁用", "证书任务", fmt.Sprintf("规则 %s 已禁用，%d 个证书任务状态设为已禁用", caddyID, disabledJobs))
	}

	// 取消仍在排队或执行中的签发协程，避免已禁用规则继续占用 CA 配额
	if qm := services.GetCAQueueManager(); qm != nil {
		func() {
			blockToken := qm.BlockJobsForRule(caddyID)
			defer qm.UnblockJobsForRule(caddyID, blockToken)
			h.caddyOpMu.Unlock()
			defer h.caddyOpMu.Lock()
			if disableRuleLockWindowHook != nil {
				disableRuleLockWindowHook(caddyID)
			}
			cancelCtx, cancel := context.WithTimeout(c.Request.Context(), cancelRuleJobsTimeout)
			defer cancel()
			if err := cancelRuleJobs(cancelCtx, qm, caddyID); err != nil {
				services.Logf("error", "DisableRule certificate cancellation timed out for caddy_id=%s: %v", caddyID, err)
			}
		}()
		// 删除复核：放锁窗口内并发的 DeleteRule 可完整提交（含证书任务/绑定
		// 清理）——此时不得再写「禁用」成功审计（会留下指向已不存在规则的
		// 成功留痕），按冲突中止；与 UpdateRule 同用 abortIfRuleDeleted。
		// 中止只跳过成功收尾，本次 /load 已真实发生 → 补重载审计。
		if abortIfRuleDeleted(c, caddyID) {
			reloadNote.auditReload()
			return
		}
		// 并发修改复核：窗口内并发 EnableRule/UpdateRule 完整提交（指纹偏离
		// 基线）时按冲突中止——本请求写入的「禁用」已被他人覆盖，成功审计
		// 会与最终状态矛盾。
		if disableFingerprintBaseline != "" && abortIfRuleConcurrentlyModifiedAs(c, caddyID, disableFingerprintBaseline, "禁用") {
			reloadNote.auditReload()
			return
		}
	}

	recordAudit(c, "禁用", "负载规则", services.FormatAuditDetail(services.AuditRulePart(caddyID), "状态：已禁用"))
	reloadNote.finalize()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已禁用"})
}

// ensureRuleExistsForLogs 规则日志两端点的存在性门：与 metrics-history 同
// 口径（不存在 404、DB 故障 500）。日志文件名直接由 caddy_id 派生，不做此
// 门时任意字符串都会得到 200 + 空结果——规则被删除后前端轮询只能显示「暂无
// 日志」，运维无法区分「没流量」与「规则不存在」。
// 返回 true = 已写响应，调用方立即 return。
func (h *Handlers) ensureRuleExistsForLogs(c *gin.Context, caddyID string) bool {
	var exists int
	err := db.DB.QueryRow(`SELECT 1 FROM lb_rules WHERE caddy_id = ?`, caddyID).Scan(&exists)
	if err == nil {
		return false
	}
	return dbQueryNotFound(c, err, "规则不存在", "读取规则日志前校验规则存在性")
}

func (h *Handlers) GetRuleLogStream(c *gin.Context) {
	caddyID := c.Param("caddy_id")
	if h.ensureRuleExistsForLogs(c, caddyID) {
		return
	}
	// 非法 offset 显式 400——静默按 0 处理会让客户端笔误（非数字/负数）
	// 伪装成「从头全量重读」，日志窗口口径静默漂移且调用方无从察觉；
	// 空参=首次轮询的合法形态（从 0 起）。
	offset := int64(0)
	if raw := c.Query("offset"); raw != "" {
		parsed, parseErr := strconv.ParseInt(raw, 10, 64)
		if parseErr != nil || parsed < 0 {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "offset 参数必须是非负整数"})
			return
		}
		offset = parsed
	}
	lines, next, err := services.ReadRuleLogFrom(caddyID, offset)
	if err != nil {
		services.Logf("warn", "读取规则日志失败（caddy_id=%s offset=%d）: %v", caddyID, offset, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则日志失败"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"offset": next, "lines": lines}})
}

func (h *Handlers) GetRuleLogs(c *gin.Context) {
	caddyID := c.Param("caddy_id")
	if h.ensureRuleExistsForLogs(c, caddyID) {
		return
	}
	content, offset, err := services.ReadRuleLogTail(caddyID, 1000)
	if err != nil {
		services.Logf("warn", "读取规则日志末尾失败（caddy_id=%s）: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则日志失败"})
		return
	}
	// offset must point just past the returned tail so a following stream
	// request continues without re-reading the same lines.
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"content": content, "offset": offset + int64(len(content))}})
}
