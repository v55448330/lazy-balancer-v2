package main

// docker run 部署形态的停止宽限门：panel 的关停链预算是 processShutdownBudget
// （最坏路径 25s：HTTP 在途请求 → Caddy 排水 → 引擎排空 → metrics/时区/日志
// 轮转收尾 → ACME 收尾）。compose 的 stop_grace_period 由
// shutdown_budget_test.go 对账，但 README 主推的 docker run 形态此前没有任何
// 机械约束——示例少一个参数，Docker 就会在第 10 秒 SIGKILL，把排水/排空/取
// 证收尾整段截断（die exitCode=137、task_runs 滞留 running、日志尾部丢失）。
// 本门把「文档化默认部署形态的停止宽限 ≥ 进程内预算」钉成可判定断言。

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"
)

// dockerRunBlock 切出一个 `docker run` 命令（含反斜杠续行）。
var dockerRunBlock = regexp.MustCompile(`docker run(?:[^\n]*\\\n)*[^\n]*`)

// stopTimeoutFlag 捕获 --stop-timeout 的秒数（`--stop-timeout 30` 与
// `--stop-timeout=30` 两种写法都认）。
var stopTimeoutFlag = regexp.MustCompile(`--stop-timeout[= ]"?(\d+)"?`)

func TestDockerRunExamplesCarryStopTimeout(t *testing.T) {
	root := repoRootForVersionTest(t)
	minSeconds := int64(processShutdownBudget / time.Second)
	if minSeconds < 25 {
		t.Fatalf("关停预算派生异常：%s → %ds", processShutdownBudget, minSeconds)
	}

	for _, file := range []string{"README.md", "README.en.md"} {
		data, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		blocks := dockerRunBlock.FindAll(data, -1)
		if len(blocks) < 2 {
			t.Fatalf("%s 的 docker run 示例只切出 %d 个（want ≥2）：切块正则漂移会让本门静默空转", file, len(blocks))
		}
		for _, block := range blocks {
			hit := stopTimeoutFlag.FindSubmatch(block)
			if hit == nil {
				t.Fatalf("%s 的 docker run 示例缺 --stop-timeout：Docker 默认 10s 停止宽限会在面板排空完成前 SIGKILL\n%s", file, block)
			}
			seconds, err := strconv.ParseInt(string(hit[1]), 10, 64)
			if err != nil {
				t.Fatalf("%s 的 --stop-timeout 值不可解析：%q", file, hit[1])
			}
			if seconds < minSeconds {
				t.Fatalf("%s 的 --stop-timeout %ds < 关停预算 %ds（排水/排空/收尾会被截断）", file, seconds, minSeconds)
			}
		}
	}

	// 部署文档必须把该要求写成可执行指引（不限定写法，只钉「该参数被提及」，
	// 防止 README 与 docs 再次分叉成「只说 compose 有 30s」）。
	deployDoc, err := os.ReadFile(filepath.Join(root, "docs", "deployment.zh-CN.md"))
	if err != nil {
		t.Fatalf("read docs/deployment.zh-CN.md: %v", err)
	}
	if !stopTimeoutFlag.Match(deployDoc) {
		t.Fatal("docs/deployment.zh-CN.md 未提及 --stop-timeout：裸 docker run 的停止宽限要求无处可查")
	}
}
