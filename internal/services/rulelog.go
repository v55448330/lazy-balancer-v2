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

// ReadRuleLogTail returns the last maxLines lines of the rule's access log
// and the file offset at which they begin, reading backwards in blocks so
// even very large logs cost only a few reads.
func ReadRuleLogTail(ruleID string, maxLines int) (content string, offset int64) {
	path := RuleLogPath(ruleID)
	f, err := os.Open(path)
	if err != nil {
		return "", 0
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() == 0 {
		return "", 0
	}
	size := info.Size()
	const blockSize = int64(64 * 1024)
	var buf []byte
	end := size
	newlines := 0
	for end > 0 && newlines < maxLines+1 {
		start := end - blockSize
		if start < 0 {
			start = 0
		}
		chunk := make([]byte, end-start)
		if _, err := f.ReadAt(chunk, start); err != nil {
			break
		}
		buf = append(chunk, buf...)
		newlines = 0
		for _, b := range chunk {
			if b == '\n' {
				newlines++
			}
		}
		end = start
	}
	// keep only the last maxLines lines
	lines := 0
	cut := len(buf)
	for i := len(buf) - 1; i >= 0; i-- {
		if buf[i] == '\n' {
			lines++
			if lines > maxLines {
				cut = i + 1
				break
			}
		}
	}
	return string(buf[cut:]), size - int64(len(buf)-cut)
}

func RemoveRuleLogFiles(ruleID string) {
	base := RuleLogPath(ruleID)
	os.Remove(base)
	for i := 1; i <= 5; i++ {
		os.Remove(fmt.Sprintf("%s.%d", base, i))
	}
}
