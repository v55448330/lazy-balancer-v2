package handlers

// API 文档是对外暴露面（openapi.yaml / Swagger UI）：描述与示例只承载产品
// 语义，不得夹带内部审计过程标识（审计编号 / 轮次编号）。这类标识属于私有
// 审计产物，随文档外发即泄漏内部流程信息。本钉测扫描 apiDocRoutes 的全部
// 文本字段（含派生的 operationDescription），新增路由夹带编号即红。

import (
	"regexp"
	"strings"
	"testing"
)

// apiDocAuditIDPattern 匹配审计编号家族：audit<NN> / round<NN>（含 -/_ 分隔
// 与大小写变体）。产品 token（版本号 v2.3.x、百分位 P95 等）不在此形态内。
var apiDocAuditIDPattern = regexp.MustCompile(`(?i)\b(?:audit|round)[-_]?[0-9]+\b`)

func TestAPIDocRoutes_descriptionsAndExamplesCarryNoAuditIdentifiers(t *testing.T) {
	for _, route := range apiDocRoutes {
		fields := []struct {
			name string
			text string
		}{
			{"Summary", route.Summary},
			{"Request", route.Request},
			{"Response", route.Response},
			{"Description", route.Description},
			{"operationDescription", operationDescription(route)},
		}
		for _, errText := range route.Errors {
			fields = append(fields, struct {
				name string
				text string
			}{"Errors", errText})
		}
		for _, field := range fields {
			if match := apiDocAuditIDPattern.FindString(field.text); match != "" {
				t.Errorf("%s %s 的 %s 含审计标识 %q（对外文档只承载产品语义）: %s",
					route.Method, route.Path, field.name, match, field.text)
			}
		}
	}
}

// 生成器输出的 YAML 同样不得携带审计编号——路由表之外的拼接文案（info /
// components 等）也是对外面，整篇兜底扫描。
func TestBuildOpenAPIYAML_containsNoAuditIdentifiers(t *testing.T) {
	yamlText := buildOpenAPIYAML()
	if match := apiDocAuditIDPattern.FindString(yamlText); match != "" {
		idx := strings.Index(yamlText, match)
		start := idx - 60
		if start < 0 {
			start = 0
		}
		end := idx + len(match) + 60
		if end > len(yamlText) {
			end = len(yamlText)
		}
		t.Errorf("openapi.yaml 含审计标识 %q，上下文: %s", match, yamlText[start:end])
	}
}
