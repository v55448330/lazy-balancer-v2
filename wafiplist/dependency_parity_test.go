package wafiplist

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
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
	// coraza 与它的 libinjection 后端同样跨模块共享：预检（面板）与运行引擎
	// （Caddy 插件）版本分叉时，同一份规则集的检测结果会按路径不同——排障口径
	// 直接分家。正则已支持带 /v3 的路径式模块名。
	for _, module := range []string{
		"github.com/goccy/go-json",
		"google.golang.org/protobuf",
		"github.com/corazawaf/coraza/v3",
		"github.com/corazawaf/libinjection-go",
	} {
		// `require` 前缀可有可无：单条 `require X vY` 与 require 块内的裸行都要认
		// （漏认时 leaf 侧恒为空 → 平价断言对该模块静默失效）。
		pattern := regexp.MustCompile(`(?m)^\s*(?:require\s+)?` + regexp.QuoteMeta(module) + `\s+(v[^\s]+)`)
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

func TestCaddyDepsFloors_matchDockerfileAssertions(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return string(raw)
	}
	if drift := dependencyFloorDrift(read("../caddydeps/go.mod"), read("../Dockerfile")); len(drift) != 0 {
		t.Fatalf("caddydeps/Dockerfile dependency floor drift: %v", drift)
	}
}

func TestDependencyFloorDrift_detectsVersionMismatch(t *testing.T) {
	goMod := "require (\n\tgolang.org/x/net v0.59.0\n)\n"
	dockerfile := `awk 'BEGIN { n = split("golang.org/x/net v0.58.0", spec, ";") }'`
	if drift := dependencyFloorDrift(goMod, dockerfile); len(drift) == 0 {
		t.Fatal("mismatched caddydeps and Dockerfile floors must be detected")
	}
}

func TestDependencyFloorDrift_detectsMissingGoModFloor(t *testing.T) {
	goMod := "require (\n\tgolang.org/x/net v0.58.0\n)\n"
	dockerfile := `awk 'BEGIN { n = split("golang.org/x/net v0.58.0;golang.org/x/crypto v0.56.0", spec, ";") }'`
	if drift := dependencyFloorDrift(goMod, dockerfile); len(drift) == 0 {
		t.Fatal("a Docker floor removed from caddydeps must be detected as drift")
	}
}

var (
	moduleFloorPattern = regexp.MustCompile(`(?m)^\s*([a-zA-Z0-9._~/-]+)\s+(v[^\s]+)\s*$`)
	dockerFloorPattern = regexp.MustCompile(`n = split\("([^"]+)", spec, ";"\)`)
)

func dependencyFloorDrift(goMod, dockerfile string) []string {
	floors := map[string]string{}
	for _, match := range moduleFloorPattern.FindAllStringSubmatch(goMod, -1) {
		floors[match[1]] = match[2]
	}
	var drift []string
	dockerMatch := dockerFloorPattern.FindStringSubmatch(dockerfile)
	if len(dockerMatch) != 2 {
		return []string{"Dockerfile floor spec not found"}
	}
	dockerFloors := map[string]string{}
	for _, entry := range strings.Split(dockerMatch[1], ";") {
		parts := strings.Fields(entry)
		if len(parts) == 2 {
			dockerFloors[parts[0]] = parts[1]
		}
	}
	for module, version := range floors {
		dockerVersion, ok := dockerFloors[module]
		if !ok {
			drift = append(drift, fmt.Sprintf("%s %s missing from Dockerfile", module, version))
			continue
		}
		if dockerVersion != version {
			drift = append(drift, fmt.Sprintf("%s go.mod=%s Dockerfile=%s", module, version, dockerVersion))
		}
	}
	// Docker 另有两项有意的独立约束：coraza 是带次版本上限的兼容区间，
	// chi 由 xcaddy --replace 固定；其余 Docker-only floor 都是漂移。
	dockerOnlyAllowed := map[string]bool{
		"github.com/corazawaf/coraza/v3": true,
		"github.com/go-chi/chi/v5":       true,
	}
	for module, version := range dockerFloors {
		if dockerOnlyAllowed[module] {
			continue
		}
		if _, ok := floors[module]; !ok {
			drift = append(drift, fmt.Sprintf("%s %s missing from caddydeps/go.mod", module, version))
		}
	}
	sort.Strings(drift)
	return drift
}
