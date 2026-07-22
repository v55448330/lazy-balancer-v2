package services

import (
	"fmt"
	"os"
	"path/filepath"
)

const ruleLogDir = "/app/logs/rules"

func RuleLogPath(ruleID string) string {
	return filepath.Join(ruleLogDir, fmt.Sprintf("%s.log", sanitizeRuleLogName(ruleID)))
}

// sanitizeRuleLogName strips anything outside the caddy_id alphabet so an
// imported rule ID cannot escape the rule log directory.
func sanitizeRuleLogName(value string) string {
	out := make([]rune, 0, len(value))
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			out = append(out, r)
		}
	}
	return string(out)
}

func RemoveRuleLogFiles(ruleID string) {
	base := RuleLogPath(ruleID)
	os.Remove(base)
	for i := 1; i <= 5; i++ {
		os.Remove(fmt.Sprintf("%s.%d", base, i))
	}
}
