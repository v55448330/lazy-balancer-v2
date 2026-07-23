package services

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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

// ReadRuleLogFrom reads the access log from offset to EOF and returns the new
// lines plus the end offset, so callers can incrementally consume without any
// server-side state. If the file rotated (size < offset), it restarts at 0.
func ReadRuleLogFrom(ruleID string, offset int64) (lines []string, next int64) {
	path := RuleLogPath(ruleID)
	f, err := os.Open(path)
	if err != nil {
		return nil, offset
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, offset
	}
	if info.Size() < offset {
		offset = 0
	}
	if offset < 0 {
		offset = 0
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, offset
	}
	// Cap each poll so a huge or maliciously reset offset cannot force a
	// full-log allocation; the caller continues from the returned offset.
	const maxRead = 2 << 20
	data, err := io.ReadAll(io.LimitReader(f, maxRead+1))
	if err != nil {
		return nil, offset
	}
	if len(data) > maxRead {
		data = data[:maxRead]
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		// Hold back the unterminated trailing record so it is delivered
		// complete on the next poll instead of being skipped forever.
		if i := strings.LastIndex(string(data), "\n"); i >= 0 {
			data = data[:i+1]
		} else {
			data = nil
		}
	}
	next = offset + int64(len(data))
	text := string(data)
	var parts []string
	if text != "" {
		parts = strings.Split(text, "\n")
		if parts[len(parts)-1] == "" {
			parts = parts[:len(parts)-1]
		}
	}
	return parts, next
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
		for _, b := range chunk {
			if b == '\n' {
				newlines++
			}
		}
		end = start
	}
	// keep only the last maxLines lines; when the log holds fewer lines than
	// maxLines, cut stays 0 and everything is returned. An unterminated
	// trailing record still counts as a line.
	lines := 0
	cut := 0
	if len(buf) > 0 && buf[len(buf)-1] != '\n' {
		lines = 1
	}
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
