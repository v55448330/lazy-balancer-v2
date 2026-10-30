package caddyl4sec

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// TestConnStatsSnapshotShape 契约 C3 JSON 形状：
// {"rules":{"<caddy_id>":{"allowed_total":N,"denied_total":M,"countries":{...}}}}
func TestConnStatsSnapshotShape(t *testing.T) {
	resetConnStatsForTest()
	beginLoad(caddy.Context{Context: context.Background()})
	c := getOrCreateRuleCounters("r-c3")
	c.allowed.Add(16)
	c.denied.Add(3)
	c.recordCountry("中国")
	c.recordCountry("United States")
	c.recordCountry("United States")

	raw := connStatsJSON()
	var doc struct {
		Rules map[string]struct {
			AllowedTotal uint64            `json:"allowed_total"`
			DeniedTotal  uint64            `json:"denied_total"`
			Countries    map[string]uint64 `json:"countries"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("snapshot not JSON: %v\n%s", err, raw)
	}
	rule, ok := doc.Rules["r-c3"]
	if !ok {
		t.Fatalf("r-c3 missing in %s", raw)
	}
	if rule.AllowedTotal != 16 || rule.DeniedTotal != 3 {
		t.Fatalf("allowed/denied = %d/%d, want 16/3", rule.AllowedTotal, rule.DeniedTotal)
	}
	if len(rule.Countries) != 2 || rule.Countries["中国"] != 1 || rule.Countries["United States"] != 2 {
		t.Fatalf("countries = %v, want {中国:1, United States:2}", rule.Countries)
	}
}

// TestConnStatsEmptySnapshot 无规则时 rules 为空对象（消费端差分健壮性）。
func TestConnStatsEmptySnapshot(t *testing.T) {
	resetConnStatsForTest()
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(connStatsJSON(), &doc); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if _, ok := doc["rules"]; !ok {
		t.Fatalf("snapshot must carry rules key: %s", doc)
	}
}

// TestAdminModuleRegistered admin.api 模块注册（/load 重建随 admin 服务实例化
// ——caddygeoip TrafficStatsAdmin 同模式）。
func TestAdminModuleRegistered(t *testing.T) {
	mod, err := caddy.GetModule("admin.api.lb_l4_conn_stats")
	if err != nil {
		t.Fatalf("admin module not registered: %v", err)
	}
	router, ok := mod.New().(caddy.AdminRouter)
	if !ok {
		t.Fatal("module does not implement caddy.AdminRouter")
	}
	patterns := make([]string, 0, 2)
	for _, r := range router.Routes() {
		patterns = append(patterns, r.Pattern)
	}
	if len(patterns) != 2 {
		t.Fatalf("routes = %v, want /lb/l4-conn-stats + /lb/l4-shipper-stats", patterns)
	}
	if patterns[0] != "/lb/l4-conn-stats" || patterns[1] != "/lb/l4-shipper-stats" {
		t.Fatalf("routes = %v, want [/lb/l4-conn-stats /lb/l4-shipper-stats]", patterns)
	}
}

// TestConnStatsEndpointJSON 端点响应：Content-Type JSON + C3 形状逐键。
func TestConnStatsEndpointJSON(t *testing.T) {
	resetConnStatsForTest()
	beginLoad(caddy.Context{Context: context.Background()})
	c := getOrCreateRuleCounters("r-ep")
	c.allowed.Add(5)
	c.denied.Add(2)
	c.recordCountry("中国")

	mod, err := caddy.GetModule("admin.api.lb_l4_conn_stats")
	if err != nil {
		t.Fatal(err)
	}
	router := mod.New().(caddy.AdminRouter)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/lb/l4-conn-stats", nil)
	if err := router.Routes()[0].Handler.ServeHTTP(rec, req); err != nil {
		t.Fatalf("handler = %v", err)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var doc struct {
		Rules map[string]struct {
			AllowedTotal uint64            `json:"allowed_total"`
			DeniedTotal  uint64            `json:"denied_total"`
			Countries    map[string]uint64 `json:"countries"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("endpoint not JSON: %v", err)
	}
	if doc.Rules["r-ep"].AllowedTotal != 5 || doc.Rules["r-ep"].DeniedTotal != 2 {
		t.Fatalf("endpoint counters = %+v", doc.Rules)
	}
}

// TestShipperStatsEndpoint 投递/丢弃计数可观测（丢弃计数可观测要求）：
// ipc_enabled/ipc_sent/ipc_failed/spool_written/spool_errors/queue_len/
// queue_bytes/dropped 逐键断言。
func TestShipperStatsEndpoint(t *testing.T) {
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", "")
	p := acquirePipelineForTest()
	defer p.resetForTest()
	p.enqueueEvent([]byte(`{"transaction":{}}`))
	p.flushQuiescedForTest()

	mod, err := caddy.GetModule("admin.api.lb_l4_conn_stats")
	if err != nil {
		t.Fatal(err)
	}
	router := mod.New().(caddy.AdminRouter)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/lb/l4-shipper-stats", nil)
	if err := router.Routes()[1].Handler.ServeHTTP(rec, req); err != nil {
		t.Fatalf("handler = %v", err)
	}
	var doc struct {
		IPCEnabled  bool   `json:"ipc_enabled"`
		IPCSent     uint64 `json:"ipc_sent"`
		IPCFailed   uint64 `json:"ipc_failed"`
		SpoolWrites uint64 `json:"spool_written"`
		SpoolErrors uint64 `json:"spool_errors"`
		QueueLen    int    `json:"queue_len"`
		QueueBytes  int64  `json:"queue_bytes"`
		Dropped     uint64 `json:"dropped"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, rec.Body.String())
	}
	if doc.IPCEnabled {
		t.Fatal("ipc_enabled = true, want false（env 关闭形态）")
	}
	if doc.Dropped != 1 || doc.IPCSent != 0 {
		t.Fatalf("dropped/ipc_sent = %d/%d, want 1/0", doc.Dropped, doc.IPCSent)
	}
}
