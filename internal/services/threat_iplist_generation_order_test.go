package services

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"lazy-balancer-v2/wafiplist"
)

// 代际判据的真实原因（读侧注释修正的行为钉）：写相位先 replace .fast、后
// replace 文本；rename 不改 mtime，故稳态 .fast 的 mtime 不早于文本，
// readThreatIplistPath 走 .fast 分支。禁止把 rename 顺序改回「先文本后
// fast」——陈旧文本会遮蔽新 fast（新威胁漏拦/已移除误拦）。
func TestWriteThreatIplistCompiled_fastGenerationIsNotOlderThanText(t *testing.T) {
	path := filepath.Join(t.TempDir(), "threat-ustc.iplist")
	if err := writeThreatIplistCompiled(path, []string{"203.0.113.1", "198.51.100.0/24"}); err != nil {
		t.Fatal(err)
	}
	textInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("读取文本代际: %v", err)
	}
	fastInfo, err := os.Stat(wafiplist.FastPath(path))
	if err != nil {
		t.Fatalf("读取 .fast 代际: %v", err)
	}
	if fastInfo.ModTime().Before(textInfo.ModTime()) {
		t.Fatalf("稳态 .fast mtime 早于文本（写相位 rename 顺序被改？）: fast=%v text=%v",
			fastInfo.ModTime(), textInfo.ModTime())
	}
	// 把文本带回上一代，并显式给定 live 代际时间：读取断言不依赖 staging
	// 文件天然的时间顺序，文本与 .fast 内容也必须确实不同。
	if err := os.WriteFile(path, []byte("192.0.2.1\n"), 0o644); err != nil {
		t.Fatalf("构造上一代文本: %v", err)
	}
	staleTextTime := fastInfo.ModTime().Add(-time.Second)
	if err := os.Chtimes(path, staleTextTime, staleTextTime); err != nil {
		t.Fatalf("设置文本代际: %v", err)
	}
	vals, err := readThreatIplistPath(path)
	if err != nil {
		t.Fatalf("按代际读取失败: %v", err)
	}
	if len(vals) != 2 {
		t.Fatalf("按代际应读到 .fast 的 2 条而非上一代文本: %v", vals)
	}
	seen := make(map[string]bool, len(vals))
	for _, val := range vals {
		seen[val] = true
	}
	if !seen["203.0.113.1/32"] || !seen["198.51.100.0/24"] || seen["192.0.2.1"] {
		t.Fatalf("读取结果必须来自新 .fast 代际: %v", vals)
	}
}
