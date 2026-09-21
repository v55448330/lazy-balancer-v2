package services

import (
	"encoding/json"
	"testing"
)

// 上游权重非正值的渲染不变量（第 47 轮 F-47-7 复核后转为永久回归钉）：
// Caddy v2.11.4 WeightedRoundRobinSelection.Provision 仅累加 Weights，
// Select 首行 `currentWeight := int(r.index.Add(1)) % r.totalWeight`——全 0 权重
// 使 totalWeight=0 → 每请求 integer divide by zero panic（net/http 按连接
// recover，连接被重置）。写侧（rules.go 主上游 0→1）与渲染侧
// buildHTTPHandleChain 的 `weight <= 0 → 1` 收集归一共同保证不变量：
// **任何发射到引擎的权重恒 > 0**（含路径规则上游，二者共用本链构建器）。
func TestBuildHTTPHandleChain_nonPositiveWeightsNormalized(t *testing.T) {
	extractWeights := func(t *testing.T, chain []interface{}) []int {
		t.Helper()
		raw, err := json.Marshal(chain)
		if err != nil {
			t.Fatalf("marshal chain: %v", err)
		}
		var generic interface{}
		if err := json.Unmarshal(raw, &generic); err != nil {
			t.Fatalf("unmarshal chain: %v", err)
		}
		var found []int
		var walk func(v interface{})
		walk = func(v interface{}) {
			switch node := v.(type) {
			case map[string]interface{}:
				if w, ok := node["weights"].([]interface{}); ok {
					for _, item := range w {
						if f, ok := item.(float64); ok {
							found = append(found, int(f))
						}
					}
				}
				for _, child := range node {
					walk(child)
				}
			case []interface{}:
				for _, child := range node {
					walk(child)
				}
			}
		}
		walk(generic)
		if len(found) == 0 {
			t.Fatalf("weighted_round_robin 池未发射 weights（路径/主上游链形状变化）:\n%s", raw)
		}
		return found
	}

	cases := []struct {
		name  string
		input []int
		want  []int
	}{
		{name: "全 0（API/导入/集群应用可携带的畸形形状）", input: []int{0, 0}, want: []int{1, 1}},
		{name: "负值（防御性：写侧已拒，渲染仍兜底）", input: []int{-5, 2}, want: []int{1, 2}},
		{name: "混合 0 与正值（回归形状：正值不被改写）", input: []int{0, 3}, want: []int{1, 3}},
		{name: "单上游 0（len<2 早退路径）", input: []int{0}, want: []int{1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := SingleRuleConfig{
				CaddyID:  "lb_weight_gate",
				Domain:   "weight-gate.test",
				Protocol: "http",
				Strategy: "weighted_round_robin",
			}
			ups := make([]UpstreamConfig, 0, len(tc.input))
			for i, w := range tc.input {
				ups = append(ups, UpstreamConfig{
					Host: "127.0.0.1", Port: 9100 + i, Weight: w, Protocol: "http", Enabled: true,
				})
			}
			got := extractWeights(t, mustChain(t, rule, ups))
			if len(got) != len(tc.want) {
				t.Fatalf("weights 数量=%d want=%d (got=%v)", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("weights=%v want=%v", got, tc.want)
				}
			}
			// 不变量：发射值恒 > 0（引擎除零 panic 的唯一入口）
			for i, w := range got {
				if w <= 0 {
					t.Fatalf("weights[%d]=%d ≤ 0 → WRR totalWeight=0 → Select 除零 panic", i, w)
				}
			}
		})
	}
}

func mustChain(t *testing.T, rule SingleRuleConfig, ups []UpstreamConfig) []interface{} {
	t.Helper()
	chain, err := buildHTTPHandleChain(rule, ups)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}
	return chain
}
