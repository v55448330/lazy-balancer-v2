package services

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"lazy-balancer-v2/wafiplist"
)

// IPListDataDir 是策略名单投影目录（@ipListFast 算子读取侧）。生产容器默认
// /app/waf/ip-lists（DataDir=/app/data 同级）；本地开发经 ConfigureWafDirs
// 按 data_dir 同级 waf/ 派生。测试可改。
var IPListDataDir = "/app/waf/ip-lists"

// ConfigureWafDirs 按最终 data_dir 派生 WAF 文件目录（容器内 /app/data →
// /app/waf 与既有打包路径逐字节一致；本地开发落到数据目录同级，避免
// /app 只读文件系统写入失败）。算子白名单前缀同步对齐。
func ConfigureWafDirs(dataDir string) {
	if filepath.Dir(dataDir) == "/app" {
		return // 容器默认形态：保持 /app/waf/* 常量
	}
	wafDir := filepath.Join(filepath.Dir(dataDir), "waf")
	IPListDataDir = filepath.Join(wafDir, "ip-lists")
	ThreatDataDir = filepath.Join(wafDir, "threat")
	wafiplist.AllowedPathPrefix = wafDir + string(filepath.Separator)
}

// EnsureIPListDir 启动期建目录（0755）。
func EnsureIPListDir() error {
	if err := os.MkdirAll(IPListDataDir, 0o755); err != nil {
		return fmt.Errorf("创建 IP 名单目录 %s 失败: %w", IPListDataDir, err)
	}
	return nil
}

// writeIPListFile 把聚合后的名单原子写入内容寻址文件（scope-sha256[:12].txt），
// 返回绝对路径；空集合返回空串不写文件（调用方据此不发射规则）。文件已存在
// 直接返回路径（幂等）；写失败返回 error——经渲染错误链路上报（保存侧事务
// 回滚，fail-closed）。
func writeIPListFile(scope string, merged []string) (string, error) {
	merged = wafiplist.AggregateIPEntries(merged)
	if len(merged) == 0 {
		return "", nil
	}
	sum := sha256.Sum256([]byte(strings.Join(merged, "\n")))
	name := fmt.Sprintf("%s-%s.txt", scope, hex.EncodeToString(sum[:])[:12])
	path := filepath.Join(IPListDataDir, name)
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	if err := EnsureIPListDir(); err != nil {
		return "", err
	}
	tmp := path + ".tmp"
	var sb strings.Builder
	for _, entry := range merged {
		sb.WriteString(entry)
		sb.WriteString("\n")
	}
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o644); err != nil {
		return "", fmt.Errorf("写入 IP 名单文件失败 %s: %w", name, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("原子替换 IP 名单文件失败 %s: %w", name, err)
	}
	return path, nil
}

// ipListRuleOperand 把策略名单投影为 @ipListFast 文件并返回 SecRule 算子
// 表达式（negated=true 时前缀 !）；空名单返回空串（调用方跳过发射，
// 维持现状零发射语义）。写失败返回 error 沿渲染链路上报。
func ipListRuleOperand(scope string, entries []string, negated bool) (string, error) {
	path, err := writeIPListFile(scope, entries)
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", nil
	}
	operand := "@ipListFast " + path
	if negated {
		operand = "!" + operand
	}
	return operand, nil
}
