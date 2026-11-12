package handlers

import (
	"net/http"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 配额限流下线：新旧客户端携带 rate_limit_* 一律忽略（创建归零、更新不改库），
// 避免 UI 已移除但 API 仍能写入「永不生效」的死配置。
func TestSecurityPolicy_ignoresRetiredRateLimitFields(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)

	id := createTestPolicy(t, router, map[string]any{
		"name":               "限流已下线",
		"policy_type":        "stage2",
		"rate_limit_enabled": true,
		"rate_limit_rps":     120,
		"rate_limit_burst":   40,
		"human_verify_mode":  "force",
	})
	var enabled int
	var rps, burst int
	if err := db.DB.QueryRow("SELECT rate_limit_enabled, rate_limit_rps, rate_limit_burst FROM security_policies WHERE id=?", id).Scan(&enabled, &rps, &burst); err != nil {
		t.Fatalf("read created policy: %v", err)
	}
	if enabled != 0 || rps != 0 || burst != 0 {
		t.Fatalf("创建路径必须归零限流字段, got enabled=%d rps=%d burst=%d", enabled, rps, burst)
	}

	recorder := putJSON(t, router, "/security/policies/"+itoa(id), map[string]any{
		"rate_limit_enabled": true,
		"rate_limit_rps":     999,
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := db.DB.QueryRow("SELECT rate_limit_enabled, rate_limit_rps FROM security_policies WHERE id=?", id).Scan(&enabled, &rps); err != nil {
		t.Fatalf("read updated policy: %v", err)
	}
	if enabled != 0 || rps != 0 {
		t.Fatalf("更新路径不得写回限流字段, got enabled=%d rps=%d", enabled, rps)
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	buf := [20]byte{}
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
