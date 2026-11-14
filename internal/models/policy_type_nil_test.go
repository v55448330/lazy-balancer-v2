package models

import "testing"

// InferPolicyType(nil) 必须与 PolicyTypeFeatures(nil) 的 nil 守卫同口径：
// 零能力→stage3（WAF 是安全策略默认心智），不得 panic。
func TestInferPolicyType_nilPolicyIsDefaultStage(t *testing.T) {
	if got := PolicyTypeFeatures(nil); got != (PolicyFeatureSet{}) {
		t.Fatalf("PolicyTypeFeatures(nil)=%+v, want 零特征", got)
	}
	if got := InferPolicyType(nil); got != PolicyTypeStage3 {
		t.Fatalf("InferPolicyType(nil)=%q, want %q", got, PolicyTypeStage3)
	}
}
