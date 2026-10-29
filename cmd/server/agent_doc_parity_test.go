package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cmd/server 文档与实现的对账门：AGENTS.md 的 WHERE TO LOOK 只允许引用包内
// 真实存在的符号，且拆分前形态的幻影符号不得回流。文档曾停留在拆分前形态
// （引用不存在的启动/关停阶段函数、STRUCTURE 只列 main.go），照文档找代码会
// 扑空。AGENTS.md 属本地未跟踪文件（CI 检出无此文件），缺失时跳过而非失败。
func TestCmdServerAgentDocReferencesExist(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(".", "AGENTS.md"))
	if err != nil {
		if os.IsNotExist(err) {
			t.Skip("AGENTS.md 为本地未跟踪文件，检出环境缺失时跳过")
		}
		t.Fatalf("read AGENTS.md: %v", err)
	}
	doc := string(data)

	// 拆分前形态的幻影符号：启动/关停实际入口是 runMain/run 与
	// waitForServerStop + cleanup defer + ShutdownWithTimeout。
	for _, phantom := range []string{"startupPhase", "shutdownPhase"} {
		if strings.Contains(doc, phantom) {
			t.Errorf("AGENTS.md 引用不存在的符号 %s（实际入口见 runMain/run/waitForServerStop）", phantom)
		}
	}

	// WHERE TO LOOK 点名的入口符号必须在本包源码中真实存在。
	matches, err := filepath.Glob("./*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	var pkgSrc strings.Builder
	for _, file := range matches {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		pkgSrc.Write(raw)
	}
	for _, symbol := range []string{"runMain", "run", "waitForServerStop", "ShutdownWithTimeout"} {
		if !strings.Contains(doc, symbol) {
			t.Errorf("AGENTS.md WHERE TO LOOK 缺少实际入口 %s", symbol)
		}
		if !strings.Contains(pkgSrc.String(), "func "+symbol) && !strings.Contains(pkgSrc.String(), symbol) {
			t.Errorf("AGENTS.md 引用的 %s 在 cmd/server 源码中不存在", symbol)
		}
	}

	// 「哪一侧启动由 taskengine RunsOn 决定」的口径必须落在文档里——
	// 角色归属的唯一事实源在任务注册项，lifecycle 只负责幂等启停。
	if !strings.Contains(doc, "RunsOn") {
		t.Error("AGENTS.md 缺少 RunsOn 角色门口径（哪一侧启动由任务注册项决定）")
	}
}
