package services

import (
	"fmt"
	"os"
	"path/filepath"
)

const ruleLogDir = "/app/logs/rules"

func RuleLogPath(ruleID string) string {
	return filepath.Join(ruleLogDir, fmt.Sprintf("%s.log", ruleID))
}

func RemoveRuleLogFiles(ruleID string) {
	base := RuleLogPath(ruleID)
	os.Remove(base)
	for i := 1; i <= 5; i++ {
		os.Remove(fmt.Sprintf("%s.%d", base, i))
	}
}
