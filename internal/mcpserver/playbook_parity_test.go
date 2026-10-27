package mcpserver

import (
	"regexp"
	"strings"
	"testing"
)

// playbookIdentifierPattern 抓手册里以反引号标注的标识符（工具名、参数名、
// 状态字面量都是这个形态）。
var playbookIdentifierPattern = regexp.MustCompile("`([a-z][a-z0-9_]*)`")

// playbookNonToolIdentifiers 是手册里以反引号标注、但不是工具名的标识符。
// 登记项=参数名/响应字段/任务状态字面量；新增项必须在此说明用途，防止把
// 已改名/删除的工具悄悄塞进白名单掩盖腐化。
var playbookNonToolIdentifiers = map[string]string{
	"caddy_id":     "工具参数：规则 Caddy ID",
	"rule_id":      "工具参数：证书任务的规则过滤",
	"domain":       "工具参数：域名",
	"listen_port":  "工具参数：监听端口",
	"page":         "工具参数：分页页码",
	"page_size":    "工具参数：分页大小",
	"input_schema": "tools/list 响应字段",
	"issued":       "证书任务状态字面量",
	"failed":       "证书任务状态字面量",
	"upstreams":    "工具参数：规则上游数组（update_rule 全量替换语义）",
	"path_rules":   "工具参数：路径路由数组（update_rule 全量替换语义）",
	"enabled":      "工具参数/上游字段：启用开关",
}

// TestPlaybookToolMentionsExist 把手册里提到的工具名与真实工具清单对账：
// 工具改名/删除后手册仍教 Agent 调旧名字时，调用只会反复试错（工具不存在 →
// 协议层错误），而没有任何测试会红。
func TestPlaybookToolMentionsExist(t *testing.T) {
	known := make(map[string]struct{}, len(tools))
	for _, spec := range tools {
		known[spec.name] = struct{}{}
	}
	if len(known) == 0 {
		t.Fatal("工具清单为空——tools 可能已重构，请同步本绊线")
	}
	for name, reason := range playbookNonToolIdentifiers {
		if _, isTool := known[name]; isTool {
			t.Errorf("白名单项 %q 其实是工具名（%s）——请从 playbookNonToolIdentifiers 移除", name, reason)
		}
	}

	mentions := playbookIdentifierPattern.FindAllStringSubmatch(opsPlaybook, -1)
	if len(mentions) == 0 {
		t.Fatal("手册未解析出任何反引号标识符（书写形态被改动？）")
	}
	for _, match := range mentions {
		name := match[1]
		if _, allowlisted := playbookNonToolIdentifiers[name]; allowlisted {
			continue
		}
		if _, isTool := known[name]; !isTool {
			t.Errorf("手册提到的工具 %q 不在工具清单内——工具已改名/删除，手册需同步", name)
		}
	}
}

// 手册「部分更新」口径必须与工具 usage 的全量替换语义一致：update_rule 的
// 标量字段是部分更新，upstreams/path_rules 却是全量替换——手册只说「只传要
// 改的字段」会让 Agent 提交部分上游数组，未列出的上游被删除（流量收窄）。
// 两侧文案必须同时声明同一关键词语义，任一单边改动即红。
func TestPlaybookDocumentsUpstreamFullReplacement(t *testing.T) {
	const keyword = "全量替换"
	if !strings.Contains(opsPlaybook, keyword) {
		t.Fatalf("手册缺少 %q 口径：Agent 会把 upstreams 当部分更新提交，未列出的上游被删除", keyword)
	}
	// 手册里该口径必须落在 update_rule 段落内（不能只是别处偶然出现）。
	sectionStart := strings.Index(opsPlaybook, "### 4.3")
	if sectionStart < 0 {
		t.Fatal("手册缺少 §4.3 修改规则段落（本绊线按段落锚定）")
	}
	sectionEnd := strings.Index(opsPlaybook[sectionStart:], "### 4.4")
	if sectionEnd < 0 {
		t.Fatal("手册 §4.3 与 §4.4 的边界丢失")
	}
	section := opsPlaybook[sectionStart : sectionStart+sectionEnd]
	if !strings.Contains(section, keyword) || !strings.Contains(section, "upstreams") || !strings.Contains(section, "path_rules") {
		t.Fatalf("§4.3 必须点名 upstreams 与 path_rules 的 %q 语义，当前段落：%s", keyword, section)
	}
	// 工具 usage（Agent 的另一份读物）必须同口径。
	usage := toolUsage["update_rule"]
	if !strings.Contains(usage, keyword) || !strings.Contains(usage, "upstreams") {
		t.Fatalf("update_rule 的 usage 缺少 %q 口径：%s", keyword, usage)
	}
}
