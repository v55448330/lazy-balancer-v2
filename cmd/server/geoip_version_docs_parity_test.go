package main

// GeoIP 版本口径对表门：镜像内置 xdb 的版本（Dockerfile 固定下载 tag）与
// 海外国家名表的建表基线（geoipnames/tables.go 注释声明的 xdb 代次）是两个
// 不同代的数字，允许并存但必须各自在用户文档里可解释——此前文档只写内置版，
// 国名表基线代次只存在于代码注释，读文档的人无法理解「内置 3.17.0 / 表按
// 3.18.0 国家列建」这组数字为何不同。本门三方对表：
//   Dockerfile 内置版 ↔ docs/security.zh-CN.md 组件表（同源）
//   geoipnames 建表基线 ↔ docs 组件表注记（同源）
//   运行期自动更新源（releases/latest）↔ docs 说明（同源）
// 任一处漂移即红，避免「文档版本号与内置库再次无声分叉」。

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestGeoIPVersionDocsMatchDockerfileAndNameTableBaseline(t *testing.T) {
	root := repoRootForVersionTest(t)

	readFile := func(rel string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		return string(data)
	}

	// 内置 xdb 版本：Dockerfile 的下载 tag（两路下载同 tag）。
	dockerfile := readFile("Dockerfile")
	bundledHits := regexp.MustCompile(`ip2region/v(\d+\.\d+\.\d+)/data/ip2region_v4\.xdb`).FindAllStringSubmatch(dockerfile, -1)
	if len(bundledHits) == 0 {
		t.Fatal("Dockerfile 未找到 ip2region/vX.Y.Z/data/ip2region_v4.xdb 下载地址（解析漂移会让本门空转）")
	}
	bundled := bundledHits[0][1]
	for _, hit := range bundledHits {
		if hit[1] != bundled {
			t.Fatalf("Dockerfile 的 xdb 下载 tag 不一致：%s vs %s（直连/代理两路必须同代）", bundled, hit[1])
		}
	}

	// 海外国家名表的建表基线：散落在 tables.go 的注释里，是「vX.Y.Z xdb 国家列」。
	tables := readFile(filepath.Join("geoipnames", "tables.go"))
	baselineHit := regexp.MustCompile(`v(\d+\.\d+\.\d+) xdb 国家列`).FindStringSubmatch(tables)
	if baselineHit == nil {
		t.Fatal("geoipnames/tables.go 未声明建表基线（形如「vX.Y.Z xdb 国家列」）")
	}
	baseline := baselineHit[1]

	// 运行期自动更新源：代码里的 releases/latest 端点。
	updateSource := readFile(filepath.Join("internal", "services", "ip2regionhttp.go"))
	if !strings.Contains(updateSource, "releases/latest") {
		t.Fatalf("ip2region 自动更新端点已不再走 releases/latest：文档中的更新口径需同步修改")
	}

	docs := readFile(filepath.Join("docs", "security.zh-CN.md"))
	if !strings.Contains(docs, "v"+bundled) {
		t.Fatalf("docs/security.zh-CN.md 未写内置 xdb 版本 v%s（Dockerfile 已固定该代）", bundled)
	}
	if !strings.Contains(docs, "v"+baseline) {
		t.Fatalf("docs/security.zh-CN.md 未写国名表建表基线 v%s（geoipnames/tables.go 声明）", baseline)
	}
	if !strings.Contains(docs, "releases/latest") {
		t.Fatal("docs/security.zh-CN.md 未说明运行期自动更新跟随上游 releases/latest（内置版与运行版可能不同代）")
	}

	if bundled != baseline {
		// 不阻断：两代并存是真实形态，但必须被显式记录，便于日后复核。
		t.Logf("提示：内置 xdb v%s 与国名表基线 v%s 不同代（文档已同时披露两者口径）", bundled, baseline)
	}
}
