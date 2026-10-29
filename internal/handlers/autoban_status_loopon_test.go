package handlers

import (
	"net/http"
	"strings"
	"testing"
)

// 状态响应的键集不得随任务引擎装配状态漂移：apidocs 示例与前端类型把
// loop_on 当恒有键消费。引擎未装配（或 Lookup 未命中）时整键缺失会让
// 「引擎在/不在」两种响应形状不同——键集恒定后，缺引擎只是取值回退 false。
func TestAutobanStatus_loopOnKeyAlwaysPresent(t *testing.T) {
	router := newAutobanTestEnv(t)

	rec := getRequest(t, router, "/security/autoban/status")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"loop_on":false`) {
		t.Fatalf("body=%s, want loop_on 键恒在（未装配时取值 false）", rec.Body.String())
	}
}
