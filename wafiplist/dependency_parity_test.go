package wafiplist

import (
	"os"
	"regexp"
	"testing"
)

// 根模块与叶模块会分别进入面板/Caddy 两个二进制；共享 coraza 依赖的
// patch 版本必须一致，避免预检与运行引擎的依赖排障口径分叉。
func TestCorazaDependencyVersions_matchRootModule(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return string(raw)
	}
	root := read("../go.mod")
	leaf := read("go.mod")
	plugin := read("../caddygeoip/go.mod")
	for _, module := range []string{"github.com/goccy/go-json", "google.golang.org/protobuf"} {
		pattern := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(module) + `\s+(v[^\s]+)`)
		rootMatch := pattern.FindStringSubmatch(root)
		leafMatch := pattern.FindStringSubmatch(leaf)
		pluginMatch := pattern.FindStringSubmatch(plugin)
		if len(rootMatch) != 2 || len(leafMatch) != 2 || len(pluginMatch) != 2 {
			t.Fatalf("module %s version missing: root=%v leaf=%v plugin=%v", module, rootMatch, leafMatch, pluginMatch)
		}
		if rootMatch[1] != leafMatch[1] || rootMatch[1] != pluginMatch[1] {
			t.Errorf("module %s: root=%s leaf=%s plugin=%s, want identical versions", module, rootMatch[1], leafMatch[1], pluginMatch[1])
		}
	}
}
