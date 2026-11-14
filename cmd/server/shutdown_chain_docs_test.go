package main

// 部署文档关停链描述与 main.go 实际收尾顺序的机械对账：停止宽限指引里的
// 分段清单曾停留旧形态（「威胁大屏停止」「metrics/时区/日志轮转收尾」独立
// 段——这些 daemon 已归口引擎排空段，且漏了安全事件 IPC 关停与引擎句柄
// 清理两段）。运维按旧清单估算宽限/排查截断点会被误导。本门把「文档分段
// 与 cleanup defer 实际顺序逐位一致」钉成可判定断言。

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// shutdownChainStages 是 cleanup defer 的实际收尾段顺序（与 main.go
// 「关停预算」注释的 defer 顺序逐行对应）。新增/调整收尾段必须同步本表
// 与部署文档，否则本门红。
var shutdownChainStages = []string{
	"HTTP 在途请求",
	"Caddy 排水",
	"安全事件 IPC 关停",
	"任务引擎排空",
	"引擎句柄清理",
	"ACME 收尾",
}

// shutdownChainParen 捕获停止宽限段里「（…）」内的分段清单。
var shutdownChainParen = regexp.MustCompile(`（([^）]*→[^）]*)）`)

func TestDeploymentDocShutdownChainMatchesMain(t *testing.T) {
	root := repoRootForVersionTest(t)
	data, err := os.ReadFile(filepath.Join(root, "docs", "deployment.zh-CN.md"))
	if err != nil {
		t.Fatalf("read docs/deployment.zh-CN.md: %v", err)
	}
	doc := string(data)
	idx := strings.Index(doc, "**停止宽限期**")
	if idx < 0 {
		t.Fatal("docs/deployment.zh-CN.md 缺「停止宽限期」段：停止宽限指引无处可查")
	}
	para := doc[idx:]
	if end := strings.Index(para, "\n"); end >= 0 {
		para = para[:end]
	}
	m := shutdownChainParen.FindStringSubmatch(para)
	if m == nil {
		t.Fatal("停止宽限期段未切出分段清单（含 → 的括号块）：描述形态漂移会让本门静默空转")
	}
	chain := m[1]
	// 分段清单可能带尾注（；…），只取 → 串联的分段本体。
	if semi := strings.Index(chain, "；"); semi >= 0 {
		chain = chain[:semi]
	}
	var got []string
	for _, seg := range strings.Split(chain, "→") {
		got = append(got, strings.TrimSpace(seg))
	}
	if len(got) != len(shutdownChainStages) {
		t.Fatalf("文档关停链 %d 段，main.go 实际 %d 段：\n文档=%v\n实际=%v", len(got), len(shutdownChainStages), got, shutdownChainStages)
	}
	for i, want := range shutdownChainStages {
		if got[i] != want {
			t.Fatalf("文档关停链第 %d 段=%q，main.go 实际=%q（分段描述与收尾顺序分叉）", i+1, got[i], want)
		}
	}
	// 旧形态残留不得回流：独立「威胁大屏停止」段与独立「metrics/时区/日志
	// 轮转收尾」段均已归口引擎排空段。
	for _, stale := range []string{"威胁大屏停止", "metrics/时区/日志轮转收尾"} {
		if strings.Contains(para, stale) {
			t.Fatalf("停止宽限期段仍含旧形态分段 %q（已归口任务引擎排空段）", stale)
		}
	}
}
