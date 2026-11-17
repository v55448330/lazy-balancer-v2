package handlers

import (
	"os"
	"regexp"
	"testing"
)

// 集群机器接口族（注册/上报/模式切换/服务控制）请求体防滥用上限必须单源：
// clusterMachineBodyLimitBytes（cluster_registration.go）。此前上限以裸
// 16<<10 字面量散落四处（含 registerRequestMaxBytes 定义处），改值需逐处
// 手改且漏改即口径分叉。本钉为源码钉：三文件中该字面量只允许在定义处出现
// 一次，端点处回潮裸字面量或 registerRequestMaxBytes 退回硬编码即红。
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
}
