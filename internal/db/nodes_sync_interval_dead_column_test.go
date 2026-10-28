package db

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// nodes.sync_interval 是 legacy 死列（见 db.go 中 nodes 表头注释）：运行期写侧
// 从不写、业务读侧零消费，离线/巡检阈值统一读 global_config.sync_interval。
// 它只在「schema DDL / 表重建复制 / 备份导入导出列清单」中被动携带，属旧备份
// 回放兼容契约。第 76/104 轮曾因巡检误读该列导致「全局 interval>120s 的部署
// 逐轮误报节点离线」，事后只能靠注释提醒。
//
// 本用例把「谁可以提到 nodes 表 + sync_interval 列」变成机器可判定约束：任何
// 新增的、同时触及 nodes 表与 sync_interval 的 SQL 字面量（业务读写）都必须显式
// 出现在白名单里并写明用途——新消费点会被迫在评审时暴露，而不是等到部署误报
// 离线时才被发现。
func TestNodesSyncIntervalHasNoBusinessConsumer(t *testing.T) {
	// 白名单：新增条目必须写明「为什么可以提到该列」。
	allow := map[string]string{
		"internal/db/db.go": "schema DDL + nodes 表重建复制（三列随重建原样搬运，兼容旧备份）",
	}
	root := filepath.Join("..", "..")
	literalPattern := regexp.MustCompile("(?s)`[^`]*`|\"(?:[^\"\\\\\\n]|\\\\.)*\"")
	// 同时出现「nodes 表」与 sync_interval 的字面量=潜在业务读写。
	nodesTargetPattern := regexp.MustCompile(`(?i)\b(from|update|join)\s+nodes\b|\binsert\s+into\s+nodes\b`)

	var violations []string
	for _, base := range []string{"internal", "cmd"} {
		err := filepath.Walk(filepath.Join(root, base), func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			rel = filepath.ToSlash(rel)
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			for _, literal := range literalPattern.FindAllString(string(content), -1) {
				if !strings.Contains(literal, "sync_interval") || !nodesTargetPattern.MatchString(literal) {
					continue
				}
				if _, ok := allow[rel]; ok {
					continue
				}
				snippet := strings.Join(strings.Fields(literal), " ")
				if len(snippet) > 160 {
					snippet = snippet[:160] + "…"
				}
				violations = append(violations, rel+": "+snippet)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("scan %s: %v", base, err)
		}
	}
	sort.Strings(violations)
	if len(violations) > 0 {
		t.Fatalf("nodes.sync_interval 是 legacy 死列（阈值统一读 global_config.sync_interval），发现业务侧消费:\n%s", strings.Join(violations, "\n"))
	}
}
