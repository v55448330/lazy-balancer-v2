package dnsprovider

// 清理骨架多实现对齐守卫：dnspod、tencent 与 aliyun 的 cleanUp 是有意保留的
// 同构多实现（底层 API 与记录 ID 类型不同，抽象共享的耦合成本高于重复成本），
// 各自维护「选中 → 逐条删除 → 批量移除账本 → 兜底排空 → 失败回填 → 残余
// 排空」骨架。
// 多实现的风险不是重复本身，而是**漂移**：只改一侧（如删除失败仍移除账本
// 条目、兜底排空被删、ctx 取消不再并入错误链）会让各家 provider 在同一事故
// 下的行为不同，而单侧测试永远绿。
//
// 本守卫把骨架的结构标记做成有序清单，所有实现必须两两同现同序；旁路的能力
// （dnspod 的 domain-id 自愈、tencent/aliyun 的记录 ID 解析）作为 provider
// 专属标记只在各自一侧断言，不进入共同清单。provider 侧残余排空自
// 修复起三侧同构（aliyun 先行、dnspod/tencent 对齐），属共同清单。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// cleanupProviderSource 是 cleanUp 多实现的源文件（相对本包目录）。
var cleanupProviderSource = map[string]string{
	"aliyun":  "aliyun/aliyun.go",
	"dnspod":  "dnspod/dnspod.go",
	"tencent": "tencent/tencent.go",
}

// cleanupSharedMarkers 是 cleanUp 骨架的有序结构标记：两侧必须同现且顺序一致。
// 条目描述的是语义不变量（不是注释文本），改语义必须同时改两侧与本清单。
var cleanupSharedMarkers = []struct {
	name   string
	marker string
}{
	{"选中：ownership 账本按值/按规则取候选", "p.ownership.MatchingValue("},
	{"选中：ownership 账本按规则取候选", "p.ownership.Matching("},
	{"选中：内存兜底表过滤保留未选中条目", "kept = append(kept, entry)"},
	{"删除：单条删除回调包 ctx 取消进错误链", "errors.Join(err, ctx.Err())"},
	{"删除：ownership 模式下失败条目不回填死存储", "if p.ownership == nil {"},
	{"归属：删除前先判账户归属", "ownership.DecideRemoval(record, p.account, time.Now())"},
	{"删除失败：保留账本条目（independence）", "record.Value) != nil { continue }"},
	{"批量收敛：一次 RemoveMany 移除已删/已丢弃条目", "p.ownership.RemoveMany(removable)"},
	{"兜底排空：取出并清空兜底表条目", "fallback := p.owned[key] delete(p.owned, key)"},
	{"兜底排空：删除失败回填供下次重试", "p.owned[key] = append(p.owned[key], entry)"},
	{"内存模式：逐条删除选中的内存条目", "for _, entry := range memorySelected {"},
	{"失败回填：仅 ownership==nil 时回填", "if p.ownership == nil && len(failed) > 0 {"},
	{"残余排空：账本/兜底全未命中且零删除尝试才网络枚举", "len(records) == 0 && len(memorySelected) == 0 && attempted == 0"},
	{"残余排空：枚举调用（服务端过滤+客户端 RR 精确匹配）", "p.listChallengeRecords(ctx, zone, subDomain)"},
	{"残余排空：按值清理时只删同值记录", "byValue && match.value != value"},
	{"残余排空：删除失败回填内存兜底表供下次重试", "value: match.value})"},
}

// cleanupProviderOnlyMarkers 是 provider 专属能力（不得扩散/不得要求对侧同现）。
var cleanupProviderOnlyMarkers = map[string][]struct {
	name   string
	marker string
}{
	"aliyun": {
		{"记录 ID 解析失败按不可恢复条目处理", "strconv.ParseUint(record.RecordID, 10, 64)"},
	},
	"dnspod": {
		{"domain-id 陈旧自愈：作废缓存重解析", "p.invalidateDomainIDCache(zone)"},
		{"domain-id 自愈：兜底表键随新 domain_id 迁移", "p.owned[freshKey] = append(p.owned[freshKey], p.owned[key]...)"},
	},
	"tencent": {
		{"记录 ID 解析失败按不可恢复条目处理", "strconv.ParseUint(record.RecordID, 10, 64)"},
	},
}

// cleanUpBody 从源文件里取 cleanUp 方法体文本（AST 定位，注释与字符串内的
// 花括号不干扰边界）。
func cleanUpBody(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s: %v", path, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, data, 0)
	if err != nil {
		t.Fatalf("解析 %s: %v", path, err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "cleanUp" || fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		start := fset.Position(fn.Body.Pos()).Offset
		end := fset.Position(fn.Body.End()).Offset
		return string(data[start:end])
	}
	t.Fatalf("%s 未找到 (p *Provider) cleanUp 方法", path)
	return ""
}

// normalizeCleanupBody 把空白折叠为单空格：标记按「空白无关」形态书写
// （换行/缩进不同的同一条语句在两侧都成立），避免缩进差异伪装成漂移。
func normalizeCleanupBody(body string) string {
	return strings.Join(strings.Fields(body), " ")
}

// cleanupMarkerDrift 返回 markers 在 bodyA/bodyB 中的漂移描述：缺失（任一侧）或
// 相对顺序不一致（两侧都有但顺序不同）。返回空切片=两侧对齐。
func cleanupMarkerDrift(bodyA, bodyB string, markers []string) []string {
	bodyA, bodyB = normalizeCleanupBody(bodyA), normalizeCleanupBody(bodyB)
	var drift []string
	if missing := missingMarkers(bodyA, markers); len(missing) > 0 {
		drift = append(drift, "A 缺失: "+strings.Join(missing, "、"))
	}
	if missing := missingMarkers(bodyB, markers); len(missing) > 0 {
		drift = append(drift, "B 缺失: "+strings.Join(missing, "、"))
	}
	// 顺序：取每个标记首次出现的位置，逐侧检查单调递增。
	for _, side := range []struct {
		name string
		body string
	}{{"A", bodyA}, {"B", bodyB}} {
		previous := -1
		previousMarker := ""
		for _, marker := range markers {
			index := strings.Index(side.body, marker)
			if index < 0 {
				continue
			}
			if index < previous {
				drift = append(drift, side.name+" 顺序漂移: "+marker+" 早于 "+previousMarker)
			}
			previous, previousMarker = index, marker
		}
	}
	return drift
}

// missingMarkers 报告 body（已归一空白）里缺失的标记。
func missingMarkers(body string, markers []string) []string {
	missing := make([]string, 0, len(markers))
	for _, marker := range markers {
		if !strings.Contains(body, marker) {
			missing = append(missing, marker)
		}
	}
	return missing
}

// TestProviderCleanupImplementationsStayInSync 是多实现对齐门禁：只改一侧的
// 骨架（删一段/挪一段）必须在此红灯，而不是在单家 provider 的线上行为里。
func TestProviderCleanupImplementationsStayInSync(t *testing.T) {
	args := make([]string, 0, len(cleanupSharedMarkers))
	for _, entry := range cleanupSharedMarkers {
		args = append(args, entry.marker)
	}
	bodies := make(map[string]string, len(cleanupProviderSource))
	names := make([]string, 0, len(cleanupProviderSource))
	for provider, path := range cleanupProviderSource {
		bodies[provider] = cleanUpBody(t, path)
		names = append(names, provider)
	}
	sort.Strings(names)
	for i := range names {
		for j := i + 1; j < len(names); j++ {
			left, right := names[i], names[j]
			if drift := cleanupMarkerDrift(bodies[left], bodies[right], args); len(drift) > 0 {
				t.Fatalf("cleanUp %s/%s 骨架漂移（任一侧修改删除/自愈/兜底排空逻辑时必须同步全部实现）:\n  %s",
					left, right, strings.Join(drift, "\n  "))
			}
		}
	}
	for provider, entries := range cleanupProviderOnlyMarkers {
		body := bodies[provider]
		for _, entry := range entries {
			if !strings.Contains(body, entry.marker) {
				t.Errorf("%s 的 cleanUp 丢失专属能力「%s」(%s)", provider, entry.name, entry.marker)
			}
		}
	}
}

// TestCleanupMarkerDrift_detectsSingleSideChanges 是守卫自检：比较器必须能对
// 单侧改动报红（缺失 + 同现异序两形态），否则真实源码对比恒绿是无 RED 能力的
// 空转。
func TestCleanupMarkerDrift_detectsSingleSideChanges(t *testing.T) {
	markers := []string{"select", "delete", "remove", "drain"}
	aligned := "func() { select; delete; remove; drain }"
	if drift := cleanupMarkerDrift(aligned, aligned, markers); len(drift) > 0 {
		t.Fatalf("对齐样本被误判漂移: %v", drift)
	}

	// 形态 1：单侧漏掉一段（删掉了“批量移除”）
	droppedOneSide := "func() { select; delete; drain }"
	drift := cleanupMarkerDrift(aligned, droppedOneSide, markers)
	if len(drift) == 0 || !strings.Contains(strings.Join(drift, "|"), "remove") {
		t.Fatalf("单侧缺失未被检出: %v", drift)
	}
	if strings.Contains(strings.Join(drift, "|"), "A 缺失") {
		t.Fatalf("未改动的一侧不得被报告缺失: %v", drift)
	}

	// 形态 2：两侧都在但顺序不同（兜底排空被挪到批量移除之前）
	reordered := "func() { select; delete; drain; remove }"
	drift = cleanupMarkerDrift(aligned, reordered, markers)
	if len(drift) == 0 || !strings.Contains(strings.Join(drift, "|"), "顺序漂移") {
		t.Fatalf("顺序漂移未被检出: %v", drift)
	}
}
