package services

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func GetSecurityPolicyForRule(ruleCaddyID string) *models.SecurityPolicy {
	if db.DB == nil {
		return nil
	}
	var policyID int
	err := db.DB.QueryRow("SELECT policy_id FROM security_policy_bindings WHERE rule_caddy_id=?", ruleCaddyID).Scan(&policyID)
	if err != nil {
		return nil
	}
	var p models.SecurityPolicy
	err = db.DB.QueryRow(`SELECT id, name, description, mode, anomaly_threshold, ip_whitelist, ip_blacklist,
		rate_limit_enabled, rate_limit_rps, rate_limit_burst, crs_rule_groups, custom_rules, enabled, created_at, updated_at
		FROM security_policies WHERE id=? AND enabled=1`, policyID).
		Scan(&p.ID, &p.Name, &p.Description, &p.Mode, &p.AnomalyThreshold, &p.IPWhitelist, &p.IPBlacklist,
			&p.RateLimitEnabled, &p.RateLimitRPS, &p.RateLimitBurst, &p.CRSRuleGroups, &p.CustomRules, &p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil
	}
	return &p
}

func BuildCorazaDirectives(p *models.SecurityPolicy) string {
	var sb strings.Builder
	switch p.Mode {
	case "blocking":
		sb.WriteString("SecRuleEngine On\n")
	case "detection":
		sb.WriteString("SecRuleEngine DetectionOnly\n")
	default:
		return ""
	}
	sb.WriteString("SecRequestBodyAccess On\n")
	sb.WriteString("SecAuditEngine Relevant\nSecAuditLog /app/waf/audit/audit.log\nSecAuditLogFormat JSON\nSecAuditLogParts ABIJDEFHZ\n")
	if p.BlockPageID > 0 {
		var content string
		var statusCode int
		db.DB.QueryRow("SELECT content, status_code FROM security_block_pages WHERE id=?", p.BlockPageID).Scan(&content, &statusCode)
		if content != "" {
			if statusCode == 0 {
				statusCode = 403
			}
			sb.WriteString(fmt.Sprintf("SecDefaultAction \"phase:1,deny,status:%d,log,msg:'Blocked by security policy'\"\nSecDefaultAction \"phase:2,deny,status:%d,log,msg:'Blocked by security policy'\"\n", statusCode, statusCode))
		}
	}

	var ipWL []string
	json.Unmarshal(p.IPWhitelist, &ipWL)
	var ipBL []string
	json.Unmarshal(p.IPBlacklist, &ipBL)
	var ipACLList []string
	json.Unmarshal([]byte(p.IPACLList), &ipACLList)
	if p.IPACLEnabled && p.IPACLMode != "" {
		if p.IPACLMode == "allow" && len(ipACLList) > 0 {
			sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:1,phase:1,pass,nolog\"\nSecRule REMOTE_ADDR \"@noMatch\" \"id:2,phase:1,deny,status:403,log,msg:'IP 白名单拒绝'\"\n", strings.Join(ipACLList, ",")))
		} else if p.IPACLMode == "deny" && len(ipACLList) > 0 {
			sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:2,phase:1,deny,status:403,log,msg:'IP 黑名单拒绝'\"\n", strings.Join(ipACLList, ",")))
		}
	}
	if len(ipWL) > 0 {
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:3,phase:1,pass,nolog,ctl:ruleEngine=Off\"\n", strings.Join(ipWL, ",")))
	}
	if len(ipBL) > 0 {
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:4,phase:1,deny,status:403,log,msg:'IP 黑名单'\"\n", strings.Join(ipBL, ",")))
	}

	var groups []string
	json.Unmarshal(p.CRSRuleGroups, &groups)
	sb.WriteString("Include /app/waf/crs/crs-setup.conf\n")
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
			sb.WriteString(fmt.Sprintf("SecRuleRemoveById %s\n", ruleID))
		}
	}

	var customRules []models.CustomRule
	json.Unmarshal(p.CustomRules, &customRules)
	targetMap := map[string]string{"uri": "REQUEST_URI", "args": "ARGS", "body": "REQUEST_BODY", "headers": "REQUEST_HEADERS", "user_agent": "REQUEST_HEADERS.User-Agent"}
	opMap := map[string]string{"contains": "@contains", "regex": "@rx", "equals": "@pm", "starts_with": "@beginsWith"}
	for _, cr := range customRules {
		if !cr.Enabled {
			continue
		}
		action := "pass,log"
		if cr.Action == "block" {
			status := cr.StatusCode
			if status == 0 {
				status = 403
			}
			action = fmt.Sprintf("deny,log,status:%d", status)
		}
		if len(cr.Conditions) > 0 {
			chain := "chain"
			for idx, cond := range cr.Conditions {
				target := targetMap[cond.Target]
				op := opMap[cond.Operator]
				if target == "" || op == "" {
					continue
				}
				chainAction := action
				if idx < len(cr.Conditions)-1 {
					chainAction = fmt.Sprintf("%s,chain", chain)
				}
				sb.WriteString(fmt.Sprintf("SecRule %s \"%s %s\" \"id:%d%s%s\"\n", target, op, cond.Pattern, cr.ID+10000, chainAction, ""))
			}
		} else {
			target := targetMap[cr.Target]
			op := opMap[cr.Operator]
			if target == "" || op == "" {
				continue
			}
			sb.WriteString(fmt.Sprintf("SecRule %s \"%s %s\" \"id:%d,%s\"\n", target, op, cr.Pattern, cr.ID+10000, action))
		}
	}

	return sb.String()
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

var _ = sql.ErrNoRows
