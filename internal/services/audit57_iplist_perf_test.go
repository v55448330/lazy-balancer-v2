package services

// 第 57 轮 P5 修复钉测试（用户上报「规则越多保存越慢」根因）：
// expandPolicyIPRefs 合并时聚合（一次），mergedACLList/mergedWhitelist 对
// Merged* 直接返回（不再每次调用全量重聚合 11k 级合并集）。

import (
	"encoding/json"
	"reflect"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestExpandPolicyIPRefs_aggregatesMergedSet(t *testing.T) {
	// Given：引用列表含可聚合条目（/8 覆盖 /24 与裸 IP）
	lists := map[int64][]string{
		7: {"1.0.0.0/8", "1.1.1.0/24", "1.1.1.1"},
	}
	p := &models.SecurityPolicy{
		IPACLEnabled:    true,
		IPACLMode:       "deny",
		IPACLList:       `["9.9.9.9"]`,
		IPACLListRefs:   "[7]",
		IPWhitelist:     json.RawMessage(`["::1"]`),
		IPWhitelistRefs: "[]",
	}
	exp := expandPolicyIPRefs(p, lists)

	want := []string{"1.0.0.0/8", "9.9.9.9/32"} // 裸 IP 规范化为 /32
	if !reflect.DeepEqual(exp.ACLList, want) {
		t.Fatalf("ACLList=%v, want %v（合并即聚合）", exp.ACLList, want)
	}
	if !reflect.DeepEqual(exp.Whitelist, []string{"::1/128"}) {
		t.Fatalf("Whitelist=%v", exp.Whitelist)
	}
}

func TestMergedACLList_prefersAttachedMergedSetVerbatim(t *testing.T) {
	// Given：已聚合的合并集直接附加（渲染主路径形态）
	p := &models.SecurityPolicy{MergedACLList: []string{"1.0.0.0/8"}}
	got := mergedACLList(p)
	if !reflect.DeepEqual(got, []string{"1.0.0.0/8"}) {
		t.Fatalf("mergedACLList=%v, want 原样返回已聚合集", got)
	}

	// And：未附加时回退 inline 口径（含聚合）
	p2 := &models.SecurityPolicy{IPACLList: `["1.0.0.0/8","1.1.1.0/24"]`}
	got2 := mergedACLList(p2)
	if !reflect.DeepEqual(got2, []string{"1.0.0.0/8"}) {
		t.Fatalf("inline 回退=%v, want 聚合后 1.0.0.0/8", got2)
	}
}
