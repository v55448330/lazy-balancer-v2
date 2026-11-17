package handlers

// 人机通道迟到插入必须与 WAF 批同构通知 rollup 回退钩子：积压超过修复窗的
// CC 拦截分钟（rate_reject 计攻击面）若无回退通知，大屏/总览 rollup 永久少计。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func TestHandleIngestHuman_lateBatchNotifiesRollupRewrite(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb-rr','拒绝规则','http','rr.test',8443,1)`); err != nil {
		t.Fatal(err)
	}
	var gotMinutes []time.Time
	var gotReclassify [][]time.Time
	services.SetSecurityEventsRollupRewrite(func(m time.Time, rc []time.Time) {
		gotMinutes = append(gotMinutes, m)
		gotReclassify = append(gotReclassify, rc)
	})
	t.Cleanup(func() { services.SetSecurityEventsRollupRewrite(nil) })

	old := time.Date(2026, 11, 15, 8, 1, 30, 0, time.UTC)
	newer := old.Add(2 * time.Minute)
	body := fmt.Sprintf(`[{"ts":%d,"rule_id":"lb-rr","client_ip":"45.77.1.10","method":"GET","uri":"/a","kind":"rate_reject","reason":"rps_spike"},{"ts":%d,"rule_id":"lb-rr","client_ip":"45.77.1.11","method":"GET","uri":"/b","kind":"challenge"}]`,
		old.UnixMilli(), newer.UnixMilli())
	h := &SecurityEventsIPCServer{}
	req := httptest.NewRequest(http.MethodPost, services.SecurityEventsIPCIngestHumanPath, strings.NewReader(body))
	rec := httptest.NewRecorder()
	http.HandlerFunc(h.ingestRouter).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(gotMinutes) != 1 {
		t.Fatalf("提交后必须恰一次回退通知（与 WAF 批同构），实际 %d 次", len(gotMinutes))
	}
	want := old.Truncate(time.Minute)
	if !gotMinutes[0].Equal(want) {
		t.Fatalf("回退分钟=%v, want 批最旧分钟截断 %v", gotMinutes[0], want)
	}
	if len(gotReclassify[0]) != 0 {
		t.Fatalf("纯插入批 reclassify 必须为空（迟到行 id 单调更大增量可覆盖），实际 %v", gotReclassify[0])
	}
}

func TestHandleIngestHuman_emptyBatchNoRewriteNotify(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	var calls int
	services.SetSecurityEventsRollupRewrite(func(time.Time, []time.Time) { calls++ })
	t.Cleanup(func() { services.SetSecurityEventsRollupRewrite(nil) })
	h := &SecurityEventsIPCServer{}
	// 全 pass 批：零落库 → 零通知（无插入无改判=零动作，与 notify 契约一致）。
	body := fmt.Sprintf(`[{"ts":%d,"rule_id":"lb-x","client_ip":"45.77.1.12","method":"GET","uri":"/p","kind":"pass"}]`, time.Now().UnixMilli())
	req := httptest.NewRequest(http.MethodPost, services.SecurityEventsIPCIngestHumanPath, strings.NewReader(body))
	rec := httptest.NewRecorder()
	http.HandlerFunc(h.ingestRouter).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if calls != 0 {
		t.Fatalf("零落库批不得通知回退，实际 %d 次", calls)
	}
}
