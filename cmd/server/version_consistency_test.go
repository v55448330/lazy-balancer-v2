package main

// 版本号硬编码点机械对账：Dockerfile `ARG VERSION` 是基准，其余发布面
// （compose 镜像 tag 与 build.args.VERSION、README 两版 buildx 示例、
// 前端 appVersion 回退值）必须与之一致。漏改一处就是「镜像 tag 与面板版本
// 不一致」的发布事故（历史上连续两版漏传 build-arg 且 README 残留旧版本）。

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// versionAnchor 一个必须与基准版本一致的硬编码位置。
type versionAnchor struct {
	// file 相对仓库根的文件名。
	file string
	// pattern 捕获第 1 组为版本号。
	pattern *regexp.Regexp
	// minimumHits 该锚点必须命中的次数（漂移即红，且不会 0 命中静默通过）。
	minimumHits int
	// note 发布面说明（失败信息用）。
	note string
}

var versionAnchors = []versionAnchor{
	{
		file:        "docker-compose.yml",
		pattern:     regexp.MustCompile(`image:\s*v55448330/lazy-balancer-v2:(v[0-9]+\.[0-9]+\.[0-9]+)(?:-beta)?`),
		minimumHits: 2,
		note:        "compose 两处 image tag（主/从节点）",
	},
	{
		file:        "docker-compose.yml",
		pattern:     regexp.MustCompile(`(?m)^\s*VERSION:\s*(v[0-9]+\.[0-9]+\.[0-9]+)\s*$`),
		minimumHits: 1,
		note:        "compose build.args.VERSION",
	},
	{
		file:        "README.md",
		pattern:     regexp.MustCompile(`(?m)--build-arg VERSION=(v[0-9]+\.[0-9]+\.[0-9]+)(?:\s|$)`),
		minimumHits: 1,
		note:        "README.md 构建示例 build-arg",
	},
	{
		file:        "README.md",
		pattern:     regexp.MustCompile(`-t v55448330/lazy-balancer-v2:(v[0-9]+\.[0-9]+\.[0-9]+)(?:-beta)?`),
		minimumHits: 1,
		note:        "README.md 构建示例镜像 tag",
	},
	{
		file:        "README.en.md",
		pattern:     regexp.MustCompile(`(?m)--build-arg VERSION=(v[0-9]+\.[0-9]+\.[0-9]+)(?:\s|$)`),
		minimumHits: 1,
		note:        "README.en.md 构建示例 build-arg",
	},
	{
		file:        "README.en.md",
		pattern:     regexp.MustCompile(`-t v55448330/lazy-balancer-v2:(v[0-9]+\.[0-9]+\.[0-9]+)(?:-beta)?`),
		minimumHits: 1,
		note:        "README.en.md 构建示例镜像 tag",
	},
	{
		file:        "web/src/utils/branding.ts",
		pattern:     regexp.MustCompile(`appVersion\s*=\s*ref\('(v[0-9]+\.[0-9]+\.[0-9]+)'\)`),
		minimumHits: 1,
		note:        "前端 appVersion 回退值",
	},
}

func repoRootForVersionTest(t *testing.T) string {
	t.Helper()
	// 本测试在 cmd/server 目录下执行，仓库根为上两级。
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "Dockerfile")); err != nil {
		t.Fatalf("repo root %s does not contain Dockerfile: %v", root, err)
	}
	return root
}

func TestVersionHardcodingPointsMatchDockerfileArg(t *testing.T) {
	root := repoRootForVersionTest(t)
	dockerfile, err := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	base := regexp.MustCompile(`(?m)^ARG VERSION=(v[0-9]+\.[0-9]+\.[0-9]+)\s*$`).FindSubmatch(dockerfile)
	if base == nil {
		t.Fatal("Dockerfile 缺少 `ARG VERSION=vX.Y.Z` 基准行")
	}
	version := string(base[1])

	for _, anchor := range versionAnchors {
		data, err := os.ReadFile(filepath.Join(root, anchor.file))
		if err != nil {
			t.Fatalf("read %s: %v", anchor.file, err)
		}
		hits := anchor.pattern.FindAllSubmatch(data, -1)
		if len(hits) < anchor.minimumHits {
			t.Fatalf("%s 的「%s」锚点命中 %d 次，want ≥%d（锚点形式漂移会让对账静默失效）",
				anchor.file, anchor.note, len(hits), anchor.minimumHits)
		}
		for _, hit := range hits {
			if got := string(hit[1]); got != version {
				t.Fatalf("%s 的「%s」= %s，与 Dockerfile ARG VERSION=%s 不一致（发布漏改）",
					anchor.file, anchor.note, got, version)
			}
		}
	}
}

var dockerfileRuntimeVersionBridge = regexp.MustCompile(`(?m)^ENV APP_VERSION=\$\{VERSION\}\s*$`)

func TestReadmeBuildArgRejectsChannelSuffix(t *testing.T) {
	candidate := []byte("docker buildx build --build-arg VERSION=v2.3.10-beta -t v55448330/lazy-balancer-v2:v2.3.10-beta .")
	for _, anchor := range versionAnchors {
		if anchor.file != "README.md" && anchor.file != "README.en.md" {
			continue
		}
		if !strings.Contains(anchor.note, "build-arg") {
			continue
		}
		if anchor.pattern.Match(candidate) {
			t.Errorf("%s build-arg anchor accepts a channel-suffixed version", anchor.file)
		}
	}
}

func TestDockerfileRuntimeVersionBridgePresent(t *testing.T) {
	root := repoRootForVersionTest(t)
	dockerfile, err := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	if hits := dockerfileRuntimeVersionBridge.FindAll(dockerfile, -1); len(hits) != 1 {
		t.Fatalf("Dockerfile ENV APP_VERSION=${VERSION} bridge hits=%d, want 1", len(hits))
	}
	if dockerfileRuntimeVersionBridge.Match([]byte("ARG VERSION=v2.3.10\n")) {
		t.Fatal("bridge anchor must reject a Dockerfile with the ENV line removed")
	}
}
