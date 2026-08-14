package services

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// crsDirectivesDir is a test seam (mirroring crsLiveDir in crsupdate.go);
// emitted Include directives always use the container path.
var crsDirectivesDir = "/app/waf/crs"

func GetSecurityPolicyForRule(ruleCaddyID string) *models.SecurityPolicy {
	if db.DB == nil {
		return nil
	}
	var policyID int
	err := db.DB.QueryRow("SELECT policy_id FROM security_policy_bindings WHERE rule_caddy_id=? ORDER BY policy_id DESC LIMIT 1", ruleCaddyID).Scan(&policyID)
	if err != nil {
		return nil
	}
	var p models.SecurityPolicy
	var ipWhitelist, ipBlacklist, crsRuleGroups, crsExcludedRules, customRules, geoipCountries string
	err = db.DB.QueryRow(`SELECT id, name, description, mode, anomaly_threshold, ip_acl_mode, ip_acl_list, ip_acl_enabled, ip_whitelist, ip_blacklist,
		rate_limit_enabled, rate_limit_rps, rate_limit_burst, crs_rule_groups, crs_excluded_rules, custom_rules, block_page_id, block_status_code, enabled, created_at, updated_at, geoip_countries, geoip_mode
		FROM security_policies WHERE id=? AND enabled=1`, policyID).
		Scan(&p.ID, &p.Name, &p.Description, &p.Mode, &p.AnomalyThreshold, &p.IPACLMode, &p.IPACLList, &p.IPACLEnabled, &ipWhitelist, &ipBlacklist,
			&p.RateLimitEnabled, &p.RateLimitRPS, &p.RateLimitBurst, &crsRuleGroups, &crsExcludedRules, &customRules, &p.BlockPageID, &p.BlockStatusCode, &p.Enabled, &p.CreatedAt, &p.UpdatedAt, &geoipCountries, &p.GeoIPMode)
	if err != nil {
		return nil
	}
	p.IPWhitelist = json.RawMessage(ipWhitelist)
	p.IPBlacklist = json.RawMessage(ipBlacklist)
	p.CRSExcludedRules = json.RawMessage(crsExcludedRules)
	p.CRSRuleGroups = json.RawMessage(crsRuleGroups)
	p.CustomRules = json.RawMessage(customRules)
	p.GeoIPCountries = json.RawMessage(geoipCountries)
	return &p
}

// geoipCountries parses the policy's geoip_countries JSON array, skipping
// blank entries. A missing or malformed payload yields nil.
func geoipCountries(p *models.SecurityPolicy) []string {
	if p == nil || len(p.GeoIPCountries) == 0 {
		return nil
	}
	var entries []string
	if err := json.Unmarshal(p.GeoIPCountries, &entries); err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if trimmed := strings.TrimSpace(entry); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// PolicyHasGeoIP reports whether the policy configures any geoip countries.
func PolicyHasGeoIP(p *models.SecurityPolicy) bool {
	return len(geoipCountries(p)) > 0
}

func BuildCorazaDirectives(p *models.SecurityPolicy) string {
	var sb strings.Builder
	var ipWL []string
	json.Unmarshal(p.IPWhitelist, &ipWL)
	var ipBL []string
	json.Unmarshal(p.IPBlacklist, &ipBL)
	var ipACLList []string
	json.Unmarshal([]byte(p.IPACLList), &ipACLList)

	// IP-level control (ACL / trust list / legacy bypass & blacklist) runs
	// independently of the WAF mode so that "关闭 WAF" never disables IP control.
	emitIPControl := len(ipWL) > 0 || len(ipBL) > 0 || (p.IPACLEnabled && len(ipACLList) > 0)
	customRules := resolvePolicyCustomRules(p.CustomRules)
	hasCustomRules := false
	for _, cr := range customRules {
		if cr.Enabled {
			hasCustomRules = true
			break
		}
	}

	switch {
	case p.Mode == "blocking":
		sb.WriteString("SecRuleEngine On\n")
	case p.Mode == "detection":
		// Detection mode keeps IP-level control enforcing: the engine starts On
		// so the ACL deny rules below actually block, then a phase:1 SecAction
		// switches the rest of the transaction (CRS + custom rules) to
		// DetectionOnly before the CRS includes are emitted.
		sb.WriteString("SecRuleEngine On\n")
	case emitIPControl || hasCustomRules:
		// WAF (CRS) off, but IP control / custom rules still need the engine.
		sb.WriteString("SecRuleEngine On\n")
	default:
		return ""
	}
	sb.WriteString("SecRequestBodyAccess On\n")
	sb.WriteString("SecAuditEngine RelevantOnly\nSecAuditLog /app/waf/audit/audit.log\nSecAuditLogFormat JSON\nSecAuditLogParts ABIJDEFHKZ\n")

	// SecRule id map: 2 = ACL allow/deny, 3 = bypass-mode (legacy), 4 = legacy
	// blacklist, 5 = trust list. The trust list keeps the historical id:3 unless
	// a bypass-mode rule already owns it. ctl:ruleEngine=Off short-circuits are
	// emitted first so bypassed and trusted clients never reach the ACL denies.
	bypassEmitted := false
	if p.IPACLEnabled && p.IPACLMode == "bypass" && len(ipACLList) > 0 {
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:3,phase:1,pass,nolog,ctl:ruleEngine=Off\"\n", strings.Join(ipACLList, ",")))
		bypassEmitted = true
	}
	if len(ipWL) > 0 {
		trustID := 3
		if bypassEmitted {
			trustID = 5
		}
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:%d,phase:1,pass,nolog,ctl:ruleEngine=Off\"\n", strings.Join(ipWL, ","), trustID))
	}
	if p.IPACLEnabled && len(ipACLList) > 0 {
		if p.IPACLMode == "allow" {
			sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"!@ipMatch %s\" \"id:2,phase:1,deny,status:403,log,msg:'IP 白名单拒绝'\"\n", strings.Join(ipACLList, ",")))
		} else if p.IPACLMode == "deny" {
			sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:2,phase:1,deny,status:403,log,msg:'IP 黑名单拒绝'\"\n", strings.Join(ipACLList, ",")))
		}
	}
	if len(ipBL) > 0 {
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:4,phase:1,deny,status:403,log,msg:'IP 黑名单'\"\n", strings.Join(ipBL, ",")))
	}

	if p.Mode == "detection" {
		sb.WriteString("SecAction \"id:6,phase:1,nolog,pass,ctl:ruleEngine=DetectionOnly\"\n")
	}

	if p.Mode == "blocking" || p.Mode == "detection" {
		var groups []string
		json.Unmarshal(p.CRSRuleGroups, &groups)
		sb.WriteString("Include /app/waf/crs/crs-setup.conf\n")
		if _, err := os.Stat(filepath.Join(crsDirectivesDir, "zz-user-overrides.conf")); err == nil {
			sb.WriteString("Include /app/waf/crs/zz-user-overrides.conf\n")
		}
		if p.AnomalyThreshold > 0 {
			sb.WriteString(fmt.Sprintf("SecAction \"id:900,phase:1,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=%d\"\n", p.AnomalyThreshold))
		}
		if len(groups) == 0 {
			sb.WriteString("Include /app/waf/crs/rules/*.conf\n")
		} else {
			for _, g := range groups {
				sb.WriteString(fmt.Sprintf("Include /app/waf/crs/rules/REQUEST-9%[1]s-*.conf\nInclude /app/waf/crs/rules/RESPONSE-9%[1]s-*.conf\n", g))
			}
		}

		var excludedRules []string
		json.Unmarshal(p.CRSExcludedRules, &excludedRules)
		for _, ruleID := range excludedRules {
			ruleID = strings.TrimSpace(ruleID)
			if ruleID != "" {
				sb.WriteString(fmt.Sprintf("SecRuleRemoveById %s\n", crsFilenameToRuleIDRange(ruleID)))
			}
		}
	}

	targetMap := map[string]string{"uri": "REQUEST_URI", "args": "ARGS", "body": "REQUEST_BODY", "headers": "REQUEST_HEADERS", "user_agent": "REQUEST_HEADERS:User-Agent"}
	opMap := map[string]string{"contains": "@contains", "regex": "@rx", "equals": "@pm", "starts_with": "@beginsWith"}
	for _, cr := range customRules {
		if !cr.Enabled {
			continue
		}
		safeName := strings.ReplaceAll(cr.Name, "'", "")
		// CRS v4 blocking evaluation reads tx.inbound_anomaly_score_pl1..4 —
		// never the legacy tx.anomaly_score.
		action := fmt.Sprintf("pass,log,setvar:tx.inbound_anomaly_score_pl1=+%d,msg:'自定义规则 %s 命中'", cr.Score, safeName)
		if cr.Action == "block" {
			// 统一所有拦截走 coraza 默认 403 → 策略 errors.routes → 拦截页面配置的状态码
			action = fmt.Sprintf("deny,log,setvar:tx.inbound_anomaly_score_pl1=+%d,msg:'自定义规则 %s 命中'", cr.Score, safeName)
		}
		if len(cr.Conditions) > 0 {
			for idx, cond := range cr.Conditions {
				target := targetMap[cond.Target]
				op := opMap[cond.Operator]
				if target == "" || op == "" {
					continue
				}
				// 链式规则仅起始条携带 id/phase/disruptive/msg；coraza v3 拒绝非起始条上的 disruptive 动作
				var actions string
				if idx == 0 {
					actions = fmt.Sprintf("id:%d,phase:1,%s", cr.ID+10000, action)
				} else {
					actions = "phase:1"
				}
				if idx < len(cr.Conditions)-1 {
					actions += ",chain"
				}
				sb.WriteString(fmt.Sprintf("SecRule %s \"%s %s\" \"%s\"\n", target, op, escapeCorazaPattern(cond.Pattern), actions))
			}
		} else {
			target := targetMap[cr.Target]
			op := opMap[cr.Operator]
			if target == "" || op == "" {
				continue
			}
			sb.WriteString(fmt.Sprintf("SecRule %s \"%s %s\" \"id:%d,%s\"\n", target, op, escapeCorazaPattern(cr.Pattern), cr.ID+10000, action))
		}
	}

	return sb.String()
}

// SecurityPolicyHasIPControl reports whether the policy applies any IP-level
// control: an enabled ACL with entries, a non-empty trust list or legacy
// blacklist, or legacy bypass mode carrying an ACL list.
func SecurityPolicyHasIPControl(p *models.SecurityPolicy) bool {
	if p == nil {
		return false
	}
	var ipACLList []string
	json.Unmarshal([]byte(p.IPACLList), &ipACLList)
	var ipWL []string
	json.Unmarshal(p.IPWhitelist, &ipWL)
	if len(ipWL) > 0 {
		return true
	}
	var ipBL []string
	json.Unmarshal(p.IPBlacklist, &ipBL)
	if len(ipBL) > 0 {
		return true
	}
	if p.IPACLMode == "bypass" && len(ipACLList) > 0 {
		return true
	}
	return p.IPACLEnabled && len(ipACLList) > 0
}

func SecurityPolicyHasFeatures(p *models.SecurityPolicy) bool {
	if p == nil {
		return false
	}
	if p.Mode != "off" {
		return true
	}
	var ipWL, ipBL []string
	json.Unmarshal(p.IPWhitelist, &ipWL)
	json.Unmarshal(p.IPBlacklist, &ipBL)
	if len(ipWL) > 0 || len(ipBL) > 0 {
		return true
	}
	if p.RateLimitEnabled {
		return true
	}
	return false
}

// buildWafHandler returns the coraza WAF handler, or nil when the rule is not HTTP or has no active bound policy.
func buildWafHandler(ruleCaddyID string) map[string]interface{} {
	if db.DB == nil {
		return nil
	}
	var protocol string
	if err := db.DB.QueryRow("SELECT protocol FROM lb_rules WHERE caddy_id=?", ruleCaddyID).Scan(&protocol); err != nil || protocol != "http" {
		return nil
	}
	policy := GetSecurityPolicyForRule(ruleCaddyID)
	if policy == nil {
		return nil
	}
	directives := BuildCorazaDirectives(policy)
	if directives == "" {
		return nil
	}
	return map[string]interface{}{
		"handler":    "waf",
		"directives": directives,
	}
}

// resolvePolicyCustomRules 解析策略的自定义规则引用：当前端存储为规则 ID 数组时
// 从 security_custom_rules 表解析为完整规则；兼容早期的对象内嵌形状。
func resolvePolicyCustomRules(raw json.RawMessage) []models.CustomRule {
	if len(raw) == 0 {
		return nil
	}
	var ids []int
	if err := json.Unmarshal(raw, &ids); err == nil {
		if len(ids) == 0 || db.DB == nil {
			return nil
		}
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
		args := make([]interface{}, len(ids))
		for i, id := range ids {
			args[i] = id
		}
		rows, err := db.DB.Query("SELECT id, name, conditions, action, score, status_code, enabled FROM security_custom_rules WHERE id IN ("+placeholders+")", args...)
		if err != nil {
			return nil
		}
		defer rows.Close()
		var rules []models.CustomRule
		for rows.Next() {
			var cr models.CustomRule
			var conditionsJSON string
			if err := rows.Scan(&cr.ID, &cr.Name, &conditionsJSON, &cr.Action, &cr.Score, &cr.StatusCode, &cr.Enabled); err != nil {
				continue
			}
			json.Unmarshal([]byte(conditionsJSON), &cr.Conditions)
			rules = append(rules, cr)
		}
		return rules
	}
	var embedded []models.CustomRule
	if err := json.Unmarshal(raw, &embedded); err == nil {
		return embedded
	}
	return nil
}

func crsFilenameToRuleIDRange(s string) string {
	parts := strings.SplitN(s, "-", 3)
	if len(parts) >= 2 {
		if n, err := strconv.Atoi(parts[1]); err == nil && n >= 100 && n <= 999 {
			return fmt.Sprintf("%d000-%d999", n, n)
		}
	}
	return s
}

func escapeCorazaPattern(pattern string) string {
	// coraza UnescapeQuotedString only unescapes \" — every other backslash
	// sequence (e.g. regex \d) must pass through verbatim, so only quotes are
	// escaped here.
	return strings.ReplaceAll(pattern, "\"", "\\\"")
}
