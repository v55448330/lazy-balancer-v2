package handlers

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestPlanConfigChangesUnchanged(t *testing.T) {
	logLevel := "info"
	req := models.UpdateConfigRequest{LogLevel: &logLevel, Source: "basic"}
	old := configSnapshot{LogLevel: "info"}

	plan := planConfigChanges(req, old)
	if plan.Changed {
		t.Fatalf("plan.Changed = true, want false; changes = %#v", plan.SectionChanges)
	}
	if plan.Section != "基础设置" {
		t.Fatalf("plan.Section = %q, want 基础设置", plan.Section)
	}
}

func TestPlanConfigChangesGroupsChangedFields(t *testing.T) {
	logLevel := "debug"
	req := models.UpdateConfigRequest{
		LogLevel: &logLevel,
		Source:   "basic",
	}
	old := configSnapshot{LogLevel: "info"}

	plan := planConfigChanges(req, old)
	if !plan.Changed {
		t.Fatal("plan.Changed = false, want true")
	}
	if got := len(plan.SectionChanges["基础设置"]); got != 1 {
		t.Fatalf("basic changes = %d, want 1", got)
	}
}

// 遗留 global_config.dns_credentials：请求体携带该键不再产生变更清单条目
// （写路径已移除，预览面不得对「不会发生的变化」报变更）。
func TestPlanConfigChanges_ignoresLegacyDNSCredentials(t *testing.T) {
	body := `{"source":"acme","dns_provider":"dnspod","dns_credentials":"legacy-id,legacy-token"}`
	var req models.UpdateConfigRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	plan := planConfigChanges(req, configSnapshot{DNSProvider: "dnspod"})
	if plan.Changed {
		t.Fatalf("legacy dns_provider 未变化时报了变更: %#v", plan.SectionChanges)
	}
}

func TestPlanConfigChangesIncludesJWTExpire(t *testing.T) {
	minutes := 30
	req := models.UpdateConfigRequest{JWTExpireMinutes: &minutes, Source: "basic"}
	old := configSnapshot{JWTExpireMinutes: 20}
	plan := planConfigChanges(req, old)
	if !plan.Changed || len(plan.SectionChanges["基础设置"]) != 1 {
		t.Fatalf("JWT expiry change not planned: %#v", plan)
	}
}

// 大屏本站坐标 lat/lon 共用 label——同时变更时变更清单只列一项
// （原实现逐字段 add，同一 label 重复出现）。
func TestPlanConfigChangesDedupesSharedLabel(t *testing.T) {
	lat, lon := 31.2, 121.5
	req := models.UpdateConfigRequest{ServerMapLat: &lat, ServerMapLon: &lon, Source: "basic"}
	old := configSnapshot{ServerMapLat: 0, ServerMapLon: 0}

	plan := planConfigChanges(req, old)
	if !plan.Changed {
		t.Fatal("plan.Changed = false, want true（任一坐标变更）")
	}
	if len(plan.Changes) != 1 || plan.Changes[0] != "大屏本站坐标" {
		t.Fatalf("changes=%v, want 单条「大屏本站坐标」", plan.Changes)
	}
	got := plan.SectionChanges["基础设置"]
	if len(got) != 1 || got[0] != "大屏本站坐标" {
		t.Fatalf("section changes=%v, want 单条", got)
	}
}

func TestPlanConfigChanges_tracksEveryUpdateConfigPointerField(t *testing.T) {
	expected := map[string]bool{}
	typ := reflect.TypeOf(models.UpdateConfigRequest{})
	for i := range typ.NumField() {
		field := typ.Field(i)
		if field.Name == "Source" || field.Type.Kind() != reflect.Ptr {
			continue
		}
		jsonName, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		expected[jsonName] = true
	}

	parsed, err := parser.ParseFile(token.NewFileSet(), "config_changes.go", nil, 0)
	if err != nil {
		t.Fatalf("parse config_changes.go: %v", err)
	}
	actual := map[string]bool{}
	ast.Inspect(parsed, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok || ident.Name != "add" {
			return true
		}
		literal, ok := call.Args[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			t.Fatalf("add first argument must be a field-name string literal, got %T", call.Args[0])
		}
		name, err := strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatalf("unquote add field: %v", err)
		}
		actual[name] = true
		return true
	})
	for name := range expected {
		if !actual[name] {
			t.Errorf("UpdateConfigRequest.%s is missing from planConfigChanges add calls", name)
		}
	}
	for name := range actual {
		if !expected[name] {
			t.Errorf("planConfigChanges tracks %q without an UpdateConfigRequest pointer field", name)
		}
	}
}

// 去重键必须是 (section,label)：跨段复用同一 label 时两个字段都必须保留
// 段落归因（此前按 label 全局去重，第二个字段的变更从清单消失）。
func TestAppendConfigChange_dedupesPerSectionNotGlobally(t *testing.T) {
	plan := configChangePlan{Changes: []string{}, SectionChanges: map[string][]string{}}
	seen := map[string]bool{}
	// task_log_size_mb（基础设置）与 caddy_log_size_mb（Caddy配置）分属两段，
	// 共用「日志大小」label 是现实形态（未来字段复用同一文案）。
	appendConfigChange(&plan, seen, "task_log_size_mb", "日志大小")
	appendConfigChange(&plan, seen, "caddy_log_size_mb", "日志大小")

	if len(plan.SectionChanges["基础设置"]) != 1 || len(plan.SectionChanges["Caddy配置"]) != 1 {
		t.Fatalf("跨段同 label 必须各自归因: %#v", plan.SectionChanges)
	}
	if len(plan.Changes) != 2 {
		t.Fatalf("changes=%v, want 两条（各段一条）", plan.Changes)
	}
	// 同段同 label 仍只列一次（lat/lon 形态）。
	appendConfigChange(&plan, seen, "task_log_size_mb", "日志大小")
	if len(plan.Changes) != 2 || len(plan.SectionChanges["基础设置"]) != 1 {
		t.Fatalf("同段同 label 重复追加: %#v", plan)
	}
}

// 快照 SQL 选择列、Scan 目标与结构字段三者必须等长且一一对应：
// 「两处同漏」可正常编译/启动、多数测试仍绿，而该字段快照恒零值 → 每次保存
// 都判为已变更、预览恒显示变更、字段级审计恒落一条不存在的变更。
func TestLoadConfigSnapshot_columnsAndScanTargetsMatchStructFields(t *testing.T) {
	fields := reflect.TypeOf(configSnapshot{})
	want := fields.NumField()

	parsed, err := parser.ParseFile(token.NewFileSet(), "config_changes.go", nil, 0)
	if err != nil {
		t.Fatalf("parse config_changes.go: %v", err)
	}
	var query string
	var bindArgs int
	scanTargets := map[string]int{}
	scanOrder := []string{}
	var scanCount int
	ast.Inspect(parsed, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch selector.Sel.Name {
		case "QueryRow":
			for _, arg := range call.Args {
				literal, ok := arg.(*ast.BasicLit)
				if ok && literal.Kind == token.STRING {
					if unquoted, uerr := strconv.Unquote(literal.Value); uerr == nil && strings.Contains(unquoted, "FROM global_config") {
						query = unquoted
					}
				}
			}
			// QueryRow 参数 = SQL 字面量 + 绑定值；绑定值个数 = ? 占位符数。
			bindArgs = len(call.Args) - 1
		case "Scan":
			scanCount = len(call.Args)
			for _, arg := range call.Args {
				unary, ok := arg.(*ast.UnaryExpr)
				if !ok {
					t.Fatalf("Scan target must be &old.Field, got %T", arg)
				}
				oldSel, ok := unary.X.(*ast.SelectorExpr)
				if !ok {
					t.Fatalf("Scan target must select a struct field")
				}
				scanTargets[oldSel.Sel.Name]++
				scanOrder = append(scanOrder, oldSel.Sel.Name)
			}
		}
		return true
	})
	if query == "" {
		t.Fatal("loadConfigSnapshot SQL not found")
	}
	if scanCount != want {
		t.Fatalf("Scan targets=%d, configSnapshot fields=%d", scanCount, want)
	}
	for i := range want {
		name := fields.Field(i).Name
		if scanTargets[name] != 1 {
			t.Fatalf("字段 %s 的 Scan 目标数=%d, want 1（漏扫/重扫会让快照零值或错位）", name, scanTargets[name])
		}
	}
	for i := range want {
		if scanOrder[i] != fields.Field(i).Name {
			t.Fatalf("Scan 第 %d 个目标=%s，configSnapshot 第 %d 个字段=%s；同计数但列序错位仍会让快照串列", i+1, scanOrder[i], i+1, fields.Field(i).Name)
		}
	}
	if placeholders := strings.Count(query, "?"); placeholders != bindArgs {
		t.Fatalf("SQL 占位符=%d, 绑定参数=%d（漏绑会让参数错位）", placeholders, bindArgs)
	}
	// 选择列数：SELECT 与 FROM 之间按顶层逗号切分（COALESCE 括号内的逗号不算）。
	body := strings.TrimSpace(query[strings.Index(query, "SELECT")+len("SELECT") : strings.Index(query, "FROM global_config")])
	depth, columns := 0, 1
	for _, r := range body {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				columns++
			}
		}
	}
	if columns != want {
		t.Fatalf("SELECT 列数=%d, configSnapshot fields=%d（两处同漏会静默零值）", columns, want)
	}
}
