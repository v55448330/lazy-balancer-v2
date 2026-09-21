package handlers

import (
	"strings"
	"testing"
)

// 第 47 轮 F-47-1：导入/还原经 restoreTable 按 dump 行**显式写入 id**，而自定义
// 规则发射 id = DB id + 10000——DB id ≥ 790000 时发射 id 撞入 GeoIP 预检段
// （800000-899999），渲染侧 `security.go:670` 跳过发射并仅告警 → 规则在 UI 显示
// 启用却不生效，违反「只有可渲染配置可落库」不变量。导入侧此前对 id 无任何区间门
// （validateSecurityCustomRule 亦无），故在导入校验漏斗处拒绝。
func TestValidateImportedSecurityCustomRules_rejectsUnrenderableID(t *testing.T) {
	row := func(id any) map[string]any {
		m := map[string]any{"name": "collider", "action": "block", "score": float64(5), "conditions": `[{"target":"uri","operator":"contains","pattern":"/x"}]`}
		if id != nil {
			m["id"] = id
		}
		return m
	}
	// 目标形状：越界 id 拒绝（JSON 解码形态 float64）
	if err := validateImportedSecurityCustomRules([]map[string]any{row(float64(790000))}); err == nil {
		t.Fatal("id=790000 的导入行必须被拒（发射 id 800000 撞 GeoIP 预检段，渲染侧静默跳过）")
	} else if !strings.Contains(err.Error(), "790000") {
		t.Fatalf("错误信息须点名越界 id: %v", err)
	}
	// 边界回归：789999 合法（发射 id 799999）
	if err := validateImportedSecurityCustomRules([]map[string]any{row(float64(789999))}); err != nil {
		t.Fatalf("id=789999 合法行被拒: %v", err)
	}
	// 形态回归：字符串 id 同样受检
	if err := validateImportedSecurityCustomRules([]map[string]any{row("790001")}); err == nil {
		t.Fatal("字符串形态越界 id 亦须被拒")
	}
	// 缺 id（省略/NULL，由 AUTOINCREMENT 分配）不拒
	if err := validateImportedSecurityCustomRules([]map[string]any{row(nil)}); err != nil {
		t.Fatalf("缺 id 行不得被拒（AUTOINCREMENT 分配）: %v", err)
	}
}
