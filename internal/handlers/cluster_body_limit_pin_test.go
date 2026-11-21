package handlers

// 集群机器接口请求体上限钉测：
//   - 既有注册/模式/服务控制端点统一引 clusterMachineBodyLimitBytes（16KiB）；
//   - 2026-11-22 两上报端点（事件/统计，spool 批次可含多事件）统一引
//     clusterReportBodyLimitBytes（128KiB）。
//
// 裸字面量（16<<10 / 128<<10）只允许出现在常量定义处——端点必须引语义名，
// 否则调上限时会漏改某一路径/两族常量漂移。

import (
	"os"
	"regexp"
	"testing"
)

func TestClusterMachineBodyLimitPin(t *testing.T) {
	literalRe := regexp.MustCompile(`16\s*<<\s*10`)
	definitionRe := regexp.MustCompile(`(?m)^const clusterMachineBodyLimitBytes int64 = 16 << 10$`)
	derivedRe := regexp.MustCompile(`(?m)^const registerRequestMaxBytes = clusterMachineBodyLimitBytes$`)

	for _, file := range []string{"cluster_registration.go", "cluster_mode.go", "cluster_service.go"} {
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		hits := literalRe.FindAllStringIndex(string(source), -1)
		if file == "cluster_registration.go" {
			if len(hits) != 1 {
				t.Fatalf("%s 的 16<<10 字面量出现 %d 处，want 仅 clusterMachineBodyLimitBytes 定义处一处（端点必须引语义名）", file, len(hits))
			}
			if !definitionRe.MatchString(string(source)) {
				t.Fatalf("%s 的 clusterMachineBodyLimitBytes 定义形态被改（本钉需同步）", file)
			}
			if !derivedRe.MatchString(string(source)) {
				t.Fatalf("registerRequestMaxBytes 必须派生自 clusterMachineBodyLimitBytes，不得回退硬编码")
			}
			continue
		}
		if len(hits) != 0 {
			t.Fatalf("%s 出现裸 16<<10 字面量 %d 处：请求体上限必须引 clusterMachineBodyLimitBytes 单源", file, len(hits))
		}
	}

	reportLiteralRe := regexp.MustCompile(`128\s*<<\s*10`)
	reportDefinitionRe := regexp.MustCompile(`(?m)^const clusterReportBodyLimitBytes int64 = 128 << 10$`)
	for _, file := range []string{"cluster_events_report.go", "cluster_node_stats_report.go"} {
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		hits := reportLiteralRe.FindAllStringIndex(string(source), -1)
		if file == "cluster_node_stats_report.go" {
			if len(hits) != 1 {
				t.Fatalf("%s 的 128<<10 字面量出现 %d 处，want 仅 clusterReportBodyLimitBytes 定义处一处（端点必须引语义名）", file, len(hits))
			}
			if !reportDefinitionRe.MatchString(string(source)) {
				t.Fatalf("%s 的 clusterReportBodyLimitBytes 定义形态被改（本钉需同步）", file)
			}
			continue
		}
		if len(hits) != 0 {
			t.Fatalf("%s 出现裸 128<<10 字面量 %d 处：请求体上限必须引 clusterReportBodyLimitBytes 单源", file, len(hits))
		}
	}
}
