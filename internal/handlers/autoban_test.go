package handlers

// 自动封禁端点与预置名单例外钉
//   GET/PUT /security/autoban 六项配置（校验/审计；保存联动调度启停）
//   POST /security/autoban/run 已废除（2026-10-14 裁定：调度唯一前提=启用）
//   GET  /security/autoban/status 运行态+今日封禁+名单数+观察建议+引用状态
//   预置「自动封禁名单」（system=1）删 400/条目可改 200/删除条目即解封/导出 TXT

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// newAutobanTestEnv：DB 夹具 + 裸路由（镜像 securityiplists_test 形态——
// 名单写路径经 finishTxApply，需要可用 caddyService）。
func newAutobanTestEnv(t *testing.T) *gin.Engine {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		// 同步复位 currentDB，后台循环不得持有已关闭测试库
		db.SetDB(oldDB)
	})
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(fakeCaddy.URL)}
	router := gin.New()
	router.GET("/security/autoban", h.GetAutobanConfig)
	router.PUT("/security/autoban", h.UpdateAutobanConfig)
	router.GET("/security/autoban/status", h.GetAutobanStatus)
	router.GET("/security/ip-lists/:id/export", h.ExportIPList)
	router.PUT("/security/ip-lists/:id", h.UpdateIPList)
	router.DELETE("/security/ip-lists/:id", h.DeleteIPList)
	router.POST("/security/ip-lists/:id/ips", h.AddIPToList)
	router.POST("/security/ip-lists/:id/remove-ip", h.RemoveIPFromList)
	return router
}

func autobanPresetID(t *testing.T) int {
	t.Helper()
	var id int
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=?`, services.AutobanPresetListName).Scan(&id); err != nil {
		t.Fatalf("preset list missing: %v", err)
	}
	return id
}

func seedAutobanListEntries(t *testing.T, entriesJSON string) {
	t.Helper()
	if _, err := db.DB.Exec(`UPDATE security_ip_lists SET entries=? WHERE name=?`, entriesJSON, services.AutobanPresetListName); err != nil {
		t.Fatalf("seed entries: %v", err)
	}
}

func readAutobanListEntries(t *testing.T, id int) []models.IPListEntry {
	t.Helper()
	var raw string
	if err := db.DB.QueryRow(`SELECT COALESCE(entries,'[]') FROM security_ip_lists WHERE id=?`, id).Scan(&raw); err != nil {
		t.Fatalf("read entries: %v", err)
	}
	var entries []models.IPListEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		t.Fatalf("parse entries %q: %v", raw, err)
	}
	return entries
}

func countAuditRows(t *testing.T, action, resource string) int {
	t.Helper()
	var n int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action=? AND resource=?`, action, resource).Scan(&n); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	return n
}

// ---- 配置读写 ----

func TestAutobanConfig_getDefaults(t *testing.T) {
	router := newAutobanTestEnv(t)
	rec := getRequest(t, router, "/security/autoban")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var cfg services.AutobanConfig
	if err := json.Unmarshal(rec.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if cfg.Enabled || !cfg.DryRun || cfg.Threshold != 100 || cfg.WindowMinutes != 5 || cfg.Duration != "1h" || cfg.Scope != "all" {
		t.Fatalf("默认配置失真: %+v", cfg)
	}
}

func TestAutobanConfig_readFailureReturnsErrorInsteadOfDefaults(t *testing.T) {
	router := newAutobanTestEnv(t)
	if _, err := db.DB.Exec(`ALTER TABLE global_config RENAME TO global_config_unavailable`); err != nil {
		t.Fatal(err)
	}
	rec := getRequest(t, router, "/security/autoban")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500 rather than default-looking 200", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"threshold":100`) {
		t.Fatalf("read failure returned a configuration indistinguishable from stored defaults: %s", rec.Body.String())
	}
}

func TestAutobanConfig_putValidRoundtrip(t *testing.T) {
	router := newAutobanTestEnv(t)
	body := map[string]any{"enabled": true, "threshold": 50, "window_minutes": 10, "duration": "6h", "scope": "blocked", "dry_run": false}
	rec := putJSON(t, router, "/security/autoban", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got services.AutobanConfig
	if err := json.Unmarshal(getRequest(t, router, "/security/autoban").Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || got.DryRun || got.Threshold != 50 || got.WindowMinutes != 10 || got.Duration != "6h" || got.Scope != "blocked" {
		t.Fatalf("回读失真: %+v", got)
	}
	if n := countAuditRows(t, "更新", "自动封禁"); n != 1 {
		t.Fatalf("更新审计=%d, want 1", n)
	}
	// 审计详情是事后判读「这次点击把开关开成了什么」的唯一依据：只数行数会让
	// 文案漂移（曾并存 已开启/已停止 与 开启/关闭 两套口径）无声通过。
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新' AND resource='自动封禁' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("read audit detail: %v", err)
	}
	wantDetail := "启用：开；调度：开启；阈值：50 次/10 分钟；时长：6 小时；口径：仅拦截；模式：正式"
	if detail != wantDetail {
		t.Fatalf("审计详情=%q, want %q（开启/关闭 口径由 enabledStateLabel 单源提供）", detail, wantDetail)
	}
}

// 写侧校验矩阵分两类，各自断言**具体归因文案**——只断 400 的矩阵无法区分
// 「哪条校验在生效」：校验按固定顺序短路，缺 threshold 的载荷永远停在第一条，
// 窗口/时长/口径三条边界从未被执行（overlay 删除后仍绿）。
func TestAutobanConfig_putRejectsInvalid(t *testing.T) {
	router := newAutobanTestEnv(t)

	// 合法基线：每个非法用例只破坏一个字段，其余字段齐全，确保被测校验真正
	// 被求值（而非被更早的规则短路）。
	valid := func() map[string]any {
		return map[string]any{"enabled": false, "threshold": 100, "window_minutes": 5, "duration": "1h", "scope": "all", "dry_run": true}
	}

	cases := []struct {
		name    string
		body    map[string]any
		message string
	}{
		// 缺字段：threshold 零值先短路（这是绑定结构的既有语义，单独钉住）。
		{name: "缺 threshold 停在首条校验", body: map[string]any{"window_minutes": 5, "duration": "1h", "scope": "all"}, message: "阈值须在 1-10000 之间"},
		{name: "threshold 下界", body: map[string]any{"threshold": 0}, message: "阈值须在 1-10000 之间"},
		{name: "threshold 上界", body: map[string]any{"threshold": 10001}, message: "阈值须在 1-10000 之间"},
	}
	for _, tc := range []struct {
		name    string
		mutate  func(map[string]any)
		message string
	}{
		{name: "window_minutes 下界", mutate: func(m map[string]any) { m["window_minutes"] = 0 }, message: "统计窗口须在 1-60 分钟之间"},
		{name: "window_minutes 上界", mutate: func(m map[string]any) { m["window_minutes"] = 61 }, message: "统计窗口须在 1-60 分钟之间"},
		{name: "duration 枚举", mutate: func(m map[string]any) { m["duration"] = "2h" }, message: "封禁时长取值无效"},
		{name: "scope 枚举", mutate: func(m map[string]any) { m["scope"] = "deny" }, message: "统计口径取值无效"},
	} {
		body := valid()
		tc.mutate(body)
		cases = append(cases, struct {
			name    string
			body    map[string]any
			message string
		}{name: tc.name, body: body, message: tc.message})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := putJSON(t, router, "/security/autoban", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("body=%v status=%d, want 400", tc.body, rec.Code)
			}
			var resp models.APIResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v body=%s", err, rec.Body.String())
			}
			if !strings.Contains(resp.Message, tc.message) {
				t.Fatalf("body=%v message=%q, want 含 %q", tc.body, resp.Message, tc.message)
			}
		})
	}

	// Then：非法配置不得落库（校验失败即早退，库中仍是默认值）。
	var got services.AutobanConfig
	if err := json.Unmarshal(getRequest(t, router, "/security/autoban").Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Threshold != 100 || got.WindowMinutes != 5 || got.Duration != "1h" || got.Scope != "all" {
		t.Fatalf("非法配置写入了库: %+v", got)
	}
}

// ---- 保存联动调度（2026-10-14 用户裁定：调度唯一前提=业务启用） ----

// Given 引擎装配+PUT /security/autoban 保存。
// When enabled=true / enabled=false。
// Then 联动启停 autoban 循环调度（loop_on 跟随业务开关）。
func TestAutobanConfig_putTogglesLoopScheduling(t *testing.T) {
	router := newAutobanTestEnv(t)
	services.SetConfigLoadRerun(func(operator string) error { return nil })
	t.Cleanup(func() { services.SetConfigLoadRerun(nil) })
	te := services.InitTaskEngine("", t.TempDir()+"/app.log")
	// 收尾必须清全局指针（StopTaskEngine 会 Swap(nil)）：只停实例会把
	// 「已停止但非 nil」的引擎留给后续用例，任何只判 nil 的装配（如
	// 自动备份执行器）都会拿到死引擎，门禁随测试顺序变红。
	t.Cleanup(services.StopTaskEngine)

	base := map[string]any{"threshold": 100, "window_minutes": 5, "duration": "1h", "scope": "all", "dry_run": true}
	body := func(enabled bool) map[string]any {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		m["enabled"] = enabled
		return m
	}
	if rec := putJSON(t, router, "/security/autoban", body(true)); rec.Code != http.StatusOK {
		t.Fatalf("启用保存 status=%d body=%s", rec.Code, rec.Body.String())
	}
	if m, _ := te.Lookup(services.AutobanTaskID); !m.LoopOn {
		t.Fatal("enabled=true 保存应联动开启调度（StartLoop）")
	}
	if rec := putJSON(t, router, "/security/autoban", body(false)); rec.Code != http.StatusOK {
		t.Fatalf("禁用保存 status=%d body=%s", rec.Code, rec.Body.String())
	}
	if m, _ := te.Lookup(services.AutobanTaskID); m.LoopOn {
		t.Fatal("enabled=false 保存应联动停止调度（StopLoop）")
	}
}

// servicesAutobanTodayStr 构造「配置时区的今天」的 created_at（UTC 墙钟串）：
// loc 今天正午 → 转 UTC 存储。
func servicesAutobanTodayStr(t *testing.T) string {
	t.Helper()
	loc := services.CurrentLocation()
	now := time.Now().In(loc)
	noon := time.Date(now.Year(), now.Month(), now.Day(), 12, 0, 0, 0, loc)
	return noon.UTC().Format("2006-01-02 15:04:05")
}

// ---- 状态 ----

func TestAutobanStatus_shape(t *testing.T) {
	router := newAutobanTestEnv(t)
	seedAutobanListEntries(t, `[{"value":"198.51.100.1","remark":"自动封禁","created_at":"`+servicesAutobanTodayStr(t)+`"},{"value":"198.51.100.2","remark":"事件处置"}]`)
	// 今日封禁=审计事件计数（2026-10-15 用户裁定）：与名单条目现状解耦——
	// 种一条今日「自动封禁」审计行，名单条目（含已封禁形态）不再参与计数。
	if _, err := db.AuditDB.Exec(`INSERT INTO audit_log (username, action, resource, detail, ip_address, created_at) VALUES ('system', ?, 'IP 地址列表', 'IP：198.51.100.1', '', ?)`,
		services.AutobanAuditAction, servicesAutobanTodayStr(t)); err != nil {
		t.Fatal(err)
	}
	rec := getRequest(t, router, "/security/autoban/status")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Enabled        bool                         `json:"enabled"`
			DryRun         bool                         `json:"dry_run"`
			Threshold      int                          `json:"threshold"`
			WindowMinutes  int                          `json:"window_minutes"`
			Duration       string                       `json:"duration"`
			Scope          string                       `json:"scope"`
			BannedToday    int                          `json:"banned_today"`
			ListEntries    int                          `json:"list_entries"`
			ListReferenced bool                         `json:"list_referenced"`
			TrackedIPs     int                          `json:"tracked_ips"`
			Suggestions    []services.AutobanSuggestion `json:"suggestions"`
			Running        bool                         `json:"running"`
			LastRun        string                       `json:"last_run"`
			LastStatus     string                       `json:"last_status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	s := resp.Data
	if s.BannedToday != 1 || s.ListEntries != 2 {
		t.Fatalf("今日封禁/名单数=%d/%d, want 1/2", s.BannedToday, s.ListEntries)
	}
	if s.ListReferenced {
		t.Fatal("无引用策略时 list_referenced 应为 false（黄条判据）")
	}
	if s.Running {
		t.Fatal("无引擎/未运行时 running 应为 false")
	}
	if !s.DryRun || s.Enabled {
		t.Fatalf("默认观察态失真: enabled=%v dry_run=%v", s.Enabled, s.DryRun)
	}
}

func TestAutobanStatus_banEffectiveTruthTable(t *testing.T) {
	cases := []struct {
		name        string
		entries     string
		aclEnabled  bool
		aclMode     string
		refsField   string
		bind        bool
		ruleEnabled bool
		upstreams   []bool // 每条上游的 enabled（空=无上游）
		want        bool
	}{
		{name: "bound deny policy with active entries", entries: `[{"value":"198.51.100.8"}]`, aclEnabled: true, aclMode: "deny", refsField: "ip_acl_list_refs", bind: true, ruleEnabled: true, upstreams: []bool{true}, want: true},
		{name: "unbound deny policy", entries: `[{"value":"198.51.100.8"}]`, aclEnabled: true, aclMode: "deny", refsField: "ip_acl_list_refs", ruleEnabled: true, upstreams: []bool{true}, want: false},
		{name: "disabled rule", entries: `[{"value":"198.51.100.8"}]`, aclEnabled: true, aclMode: "deny", refsField: "ip_acl_list_refs", bind: true, ruleEnabled: false, upstreams: []bool{true}, want: false},
		{name: "empty list", entries: `[]`, aclEnabled: true, aclMode: "deny", refsField: "ip_acl_list_refs", bind: true, ruleEnabled: true, upstreams: []bool{true}, want: false},
		{name: "IP ACL disabled", entries: `[{"value":"198.51.100.8"}]`, aclEnabled: false, aclMode: "deny", refsField: "ip_acl_list_refs", bind: true, ruleEnabled: true, upstreams: []bool{true}, want: false},
		{name: "whitelist reference only", entries: `[{"value":"198.51.100.8"}]`, aclEnabled: false, aclMode: "deny", refsField: "ip_whitelist_refs", bind: true, ruleEnabled: true, upstreams: []bool{true}, want: false},
		// 渲染层对零启用上游的规则整条 continue——此时名单
		// 实际不拦截，卡片不得再报 ban_effective=true（否则黄条被抑制）。
		{name: "no upstream", entries: `[{"value":"198.51.100.8"}]`, aclEnabled: true, aclMode: "deny", refsField: "ip_acl_list_refs", bind: true, ruleEnabled: true, upstreams: nil, want: false},
		{name: "only disabled upstream", entries: `[{"value":"198.51.100.8"}]`, aclEnabled: true, aclMode: "deny", refsField: "ip_acl_list_refs", bind: true, ruleEnabled: true, upstreams: []bool{false}, want: false},
		{name: "mixed upstreams with one enabled", entries: `[{"value":"198.51.100.8"}]`, aclEnabled: true, aclMode: "deny", refsField: "ip_acl_list_refs", bind: true, ruleEnabled: true, upstreams: []bool{false, true}, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router := newAutobanTestEnv(t)
			seedAutobanListEntries(t, tc.entries)
			listID := autobanPresetID(t)
			aclRefs, whitelistRefs := "[]", "[]"
			if tc.refsField == "ip_whitelist_refs" {
				whitelistRefs = fmt.Sprintf("[%d]", listID)
			} else {
				aclRefs = fmt.Sprintf("[%d]", listID)
			}
			res, err := db.DB.Exec(`INSERT INTO security_policies (name,enabled,ip_acl_enabled,ip_acl_mode,ip_acl_list_refs,ip_whitelist_refs) VALUES ('ban-effective',1,?,?,?,?)`, tc.aclEnabled, tc.aclMode, aclRefs, whitelistRefs)
			if err != nil {
				t.Fatal(err)
			}
			policyID, _ := res.LastInsertId()
			if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_ban_effective','ban-effective','http','ban-effective.test',8080,?)`, tc.ruleEnabled); err != nil {
				t.Fatal(err)
			}
			for _, upstreamEnabled := range tc.upstreams {
				if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_ban_effective','127.0.0.1',9000,1,?,'http')`, upstreamEnabled); err != nil {
					t.Fatal(err)
				}
			}
			if tc.bind {
				if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_ban_effective',?)`, policyID); err != nil {
					t.Fatal(err)
				}
			}
			response := getRequest(t, router, "/security/autoban/status")
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			var payload struct {
				Data struct {
					BanEffective bool `json:"ban_effective"`
				} `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if payload.Data.BanEffective != tc.want {
				t.Fatalf("ban_effective=%v, want %v", payload.Data.BanEffective, tc.want)
			}
		})
	}

	t.Run("binding query failure is fail closed", func(t *testing.T) {
		router := newAutobanTestEnv(t)
		seedAutobanListEntries(t, `[{"value":"198.51.100.8"}]`)
		if _, err := db.DB.Exec(`DROP TABLE security_policy_bindings`); err != nil {
			t.Fatal(err)
		}
		response := getRequest(t, router, "/security/autoban/status")
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"ban_effective":true`) {
			t.Fatalf("query failure must suppress the misleading warning, status=%d body=%s", response.Code, response.Body.String())
		}
	})
}

// autobanListReferenced / autobanBanEffective 的 fail-closed 构造不变量：
// 未携带名单 id 的状态（构造缺失）必须按「已引用/已生效」处理，不弹误导性
// 黄条。读取故障在 GetAutobanStatus 更早的 AutobanListEntries 已 500 返回，
// 且单源引用判定自身的库故障语义由其内部契约负责，此处只钉构造不变量。
func TestAutobanStatus_listReferencedFailClosed(t *testing.T) {
	newAutobanTestEnv(t)
	h := &Handlers{}
	unset := autobanPresetListState{}
	if !h.autobanListReferenced(unset) {
		t.Fatal("id 缺失必须 fail-closed 返回 true（不弹黄条）")
	}
	if !h.autobanBanEffective(unset) {
		t.Fatal("id 缺失必须 fail-closed 返回 true（不弹黄条）")
	}
}

// TestAutobanStatus_suggestionsCarryIPLocation：观察建议逐条携带归属地——与
// 安全事件列表同源富化（handlers 侧 enrichIPLocation 单源装填）。保留地址无需
// xdb 即可钉装填链路（私网前置拦截），普通 IP 无 xdb 时降级空串、永不报错。
func TestAutobanStatus_suggestionsCarryIPLocation(t *testing.T) {
	// 「无 xdb」必须是显式前置，而不是「测试进程恰好没装载」——导入落盘等
	// 用例会经 Reload 装上真实库，-shuffle 下顺序一变，下面的空串断言即红。
	services.ResetIP2RegionSearcherForTest()
	t.Cleanup(services.ResetIP2RegionSearcherForTest)
	router := newAutobanTestEnv(t)
	services.AutobanSetSuggestionsForTest([]services.AutobanSuggestion{
		{IP: "185.199.109.9", Count: 2},
		{IP: "10.0.0.1", Count: 5},
		{IP: "203.0.113.9", Count: 1}, // RFC 5737 文档段：与私网同判保留地址
	})
	t.Cleanup(func() { services.AutobanSetSuggestionsForTest(nil) })
	rec := getRequest(t, router, "/security/autoban/status")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Suggestions []services.AutobanSuggestion `json:"suggestions"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if len(resp.Data.Suggestions) != 3 {
		t.Fatalf("建议条数=%d, want 3", len(resp.Data.Suggestions))
	}
	// AutobanSuggestions 按 Count 降序：10.0.0.1（保留地址）在前。
	first, second, third := resp.Data.Suggestions[0], resp.Data.Suggestions[1], resp.Data.Suggestions[2]
	if first.IP != "10.0.0.1" || first.Location != "保留地址" {
		t.Fatalf("建议[0] ip/location=%s/%q, want 10.0.0.1/保留地址", first.IP, first.Location)
	}
	if second.IP != "185.199.109.9" || second.Location != "" {
		t.Fatalf("建议[1] ip/location=%s/%q, want 185.199.109.9/\"\"（无 xdb 降级空串）", second.IP, second.Location)
	}
	if third.IP != "203.0.113.9" || third.Location != "保留地址" {
		t.Fatalf("建议[2] ip/location=%s/%q, want 203.0.113.9/保留地址（RFC 5737 段）", third.IP, third.Location)
	}
}

// ---- 预置名单例外 ----

// Given 观察轮尚未产出任何建议（autobanSuggestions 为空）。
// When 读 /security/autoban/status。
// Then 原始响应必须是 suggestions:[]（文档/前端契约是数组），不得是 null——
// 解码成切片断言判不出 nil 与空切片，必须做字节级判定。
func TestAutobanStatus_emptySuggestionsSerializeAsArray(t *testing.T) {
	router := newAutobanTestEnv(t)
	services.AutobanSetSuggestionsForTest(nil)
	t.Cleanup(func() { services.AutobanSetSuggestionsForTest(nil) })

	rec := getRequest(t, router, "/security/autoban/status")

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"suggestions":[]`) {
		t.Fatalf("body=%s, want suggestions 序列化为空数组（null 与文档/前端数组契约不符）", rec.Body.String())
	}
}

func TestAutobanPreset_deleteRejected(t *testing.T) {
	router := newAutobanTestEnv(t)
	rec := deleteRequest(t, router, fmt.Sprintf("/security/ip-lists/%d", autobanPresetID(t)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（预置名单禁删）", rec.Code, rec.Body.String())
	}
}

func TestAutobanPreset_updateEntriesAllowed(t *testing.T) {
	router := newAutobanTestEnv(t)
	id := autobanPresetID(t)
	rec := putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", id), map[string]any{
		"entries": `[{"value":"198.51.100.9","remark":"手动封禁"}]`,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("条目修改 status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	entries := readAutobanListEntries(t, id)
	if len(entries) != 1 || entries[0].Value != "198.51.100.9" {
		t.Fatalf("条目修改未落库: %+v", entries)
	}
	// 改名拒绝（任务按名定位预置行）
	rec = putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", id), map[string]any{"name": "改名"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("改名 status=%d, want 400", rec.Code)
	}
}

func TestAutobanPreset_addAndRemoveEntries(t *testing.T) {
	router := newAutobanTestEnv(t)
	id := autobanPresetID(t)
	rec := postJSON(t, router, fmt.Sprintf("/security/ip-lists/%d/ips", id), map[string]any{"value": "203.0.113.5"})
	if rec.Code != http.StatusOK {
		t.Fatalf("追加 status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	entries := readAutobanListEntries(t, id)
	if len(entries) != 1 || entries[0].Value != "203.0.113.5" || entries[0].Remark != services.AutobanManualUnbanRemark {
		t.Fatalf("追加后条目=%+v（remark 须为手动封禁）", entries)
	}
	// 删除条目即解封（2026-10-15 用户裁定）：removed:true + 条目离开名单，
	// 无抑制表写入——IP 重新达标会被再次封禁。
	rec = postJSON(t, router, fmt.Sprintf("/security/ip-lists/%d/remove-ip", id), map[string]any{"value": "203.0.113.5"})
	if rec.Code != http.StatusOK {
		t.Fatalf("移除 status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, `"removed":true`) {
		t.Fatalf("移除响应须 removed:true, body=%s", body)
	}
	if entries := readAutobanListEntries(t, id); len(entries) != 0 {
		t.Fatalf("移除后条目应清空, 得到 %+v", entries)
	}
}

// 威胁名单（system=1 非自动封禁）保持只读——既有门不因例外放宽。
func TestAutobanPreset_threatListsStayReadOnly(t *testing.T) {
	router := newAutobanTestEnv(t)
	var threatID int
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE system=1 AND name<>?`, services.AutobanPresetListName).Scan(&threatID); err != nil {
		t.Fatalf("threat list missing: %v", err)
	}
	if rec := putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", threatID), map[string]any{"entries": "[]"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("threat update status=%d, want 400", rec.Code)
	}
	if rec := postJSON(t, router, fmt.Sprintf("/security/ip-lists/%d/ips", threatID), map[string]any{"value": "1.2.3.4"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("threat add status=%d, want 400", rec.Code)
	}
	if rec := postJSON(t, router, fmt.Sprintf("/security/ip-lists/%d/remove-ip", threatID), map[string]any{"value": "1.2.3.4"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("threat remove status=%d, want 400", rec.Code)
	}
}

// ---- 导出 ----

func TestExportIPList_txtLines(t *testing.T) {
	router := newAutobanTestEnv(t)
	id := autobanPresetID(t)
	seedAutobanListEntries(t, `[{"value":"198.51.100.1","remark":"自动封禁"},{"value":"198.51.100.2","remark":""}]`)
	rec := getRequest(t, router, fmt.Sprintf("/security/ip-lists/%d/export", id))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("content-type=%q, want text/plain", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "198.51.100.1 自动封禁") || !strings.Contains(body, "198.51.100.2") {
		t.Fatalf("导出内容失真:\n%s", body)
	}
}

func TestExportIPList_missing404(t *testing.T) {
	router := newAutobanTestEnv(t)
	if rec := getRequest(t, router, "/security/ip-lists/424242/export"); rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d, want 404", rec.Code)
	}
}

// ---- 上限常量契约钉 ----

func TestAutobanListEntryCap_matchesHandlerCap(t *testing.T) {
	if services.AutobanListEntryCap != ipListMaxEntries {
		t.Fatalf("services.AutobanListEntryCap=%d != handlers ipListMaxEntries=%d（两值漂移会让任务写入被校验拒绝）",
			services.AutobanListEntryCap, ipListMaxEntries)
	}
}

// 爬虫系统名单上限的跨包契约钉（与上一条同型）：services 侧声明
// CrawlerIPListEntryCap 并注明「与 handlers ipListMaxEntries 同义」，若管理面
// 上限被调整（如降到 1000）而任务仍可写到 2000 条，面板上限与任务写入口径
// 静默分叉；services 不能 import handlers，故只能由 handlers 侧钉住相等。
func TestCrawlerIPListEntryCap_matchesHandlerCap(t *testing.T) {
	if services.CrawlerIPListEntryCap != ipListMaxEntries {
		t.Fatalf("services.CrawlerIPListEntryCap=%d != handlers ipListMaxEntries=%d（爬虫任务写入会越过管理面上限）",
			services.CrawlerIPListEntryCap, ipListMaxEntries)
	}
}

// 内置名单引用门提示语按名单名分流 ----

// Given 自动封禁预置名单（system=1，非威胁情报源）。
// When 信任名单引用它（内置名单引用门拒绝的唯一非法形态之一）。
// Then 400 提示语称「内置自动封禁名单」，不得误称「威胁情报名单」。
func TestCreatePolicy_builtinAutobanListRefMessageNamesAutoban(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/security/policies", h.CreateSecurityPolicy)
	var autobanID int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=?`, services.AutobanPresetListName).Scan(&autobanID); err != nil {
		t.Fatalf("自动封禁预置名单缺失: %v", err)
	}
	body := fmt.Sprintf(`{"name":"au6","policy_type":"stage0","ip_whitelist_refs":"[%d]"}`, autobanID)
	req := httptest.NewRequest(http.MethodPost, "/security/policies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "内置自动封禁名单") {
		t.Fatalf("提示语应按名单名分流（内置自动封禁名单）: %s", resp.Body.String())
	}
	if strings.Contains(resp.Body.String(), "威胁情报") {
		t.Fatalf("自动封禁名单不得被称作威胁情报名单: %s", resp.Body.String())
	}
}

// PUT 禁用路径收尾接线 ----

// Given 名单含已到期自动条目+未到期自动条目；重载回调间谍；名单无任何发射面引用。
// When PUT enabled=false（禁用保存）。
// Then 禁用收尾立即清除已到期条目且无需重载（无引用=零发射面、零 /load）；
// 未到期条目保留；调度照常联动停止。
func TestAutobanConfig_putDisableFlushesExpiredEntries(t *testing.T) {
	router := newAutobanTestEnv(t)
	services.SetConfigLoadRerun(func(operator string) error { return nil })
	t.Cleanup(func() { services.SetConfigLoadRerun(nil) })
	te := services.InitTaskEngine("", t.TempDir()+"/app.log")
	// 同族收尾：清全局指针，不留 stopped 非 nil 引擎给后续用例。
	t.Cleanup(services.StopTaskEngine)
	id := autobanPresetID(t)
	seedAutobanListEntries(t, `[
		{"value":"198.51.100.1","remark":"自动封禁","created_at":"2026-10-13 10:00:00","expires_at":"2020-01-01 00:00:00"},
		{"value":"198.51.100.2","remark":"自动封禁","created_at":"2026-10-14 09:30:00","expires_at":"2099-01-01 00:00:00"}]`)
	reloads := 0
	services.SetAutobanReloader(func() error { reloads++; return nil })
	t.Cleanup(func() { services.SetAutobanReloader(nil) })

	body := map[string]any{"enabled": false, "threshold": 100, "window_minutes": 5, "duration": "1h", "scope": "all", "dry_run": true}
	if rec := putJSON(t, router, "/security/autoban", body); rec.Code != http.StatusOK {
		t.Fatalf("禁用保存 status=%d body=%s", rec.Code, rec.Body.String())
	}
	entries := readAutobanListEntries(t, id)
	if len(entries) != 1 || entries[0].Value != "198.51.100.2" {
		t.Fatalf("禁用收尾必须清除已到期条目并保留未到期条目: %+v", entries)
	}
	if reloads != 0 {
		t.Fatalf("无引用名单的到期清理不得触发 /load，reloads=%d", reloads)
	}
	if m, _ := te.Lookup(services.AutobanTaskID); m.LoopOn {
		t.Fatal("禁用保存仍应联动停止调度")
	}
}

// ---- 预置名单三字段锁定（2026-10-14 用户裁定：名称/分类/描述禁改） ----

// Given 预置「自动封禁名单」（名称已禁改）。
// When PUT 变更分类/描述。
// Then 400（文案与名称同款）；同值提交不受影响（仅「变更」被拦）。
func TestAutobanPreset_categoryDescriptionLocked(t *testing.T) {
	router := newAutobanTestEnv(t)
	id := autobanPresetID(t)

	rec := putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", id), map[string]any{"category": "自定义分类"})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "分类不可修改") {
		t.Fatalf("变更分类 status=%d body=%s, want 400+分类不可修改", rec.Code, rec.Body.String())
	}
	rec = putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", id), map[string]any{"description": "自定义描述"})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "描述不可修改") {
		t.Fatalf("变更描述 status=%d body=%s, want 400+描述不可修改", rec.Code, rec.Body.String())
	}

	// 回归形状：同值提交（分类/描述与种子一致）放行
	rec = putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", id), map[string]any{
		"category":    "自动封禁",
		"description": "自动封禁命中 IP（自动封禁任务维护；可手动追加或删除条目）",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("同值提交 status=%d body=%s, want 200（仅拦「变更」）", rec.Code, rec.Body.String())
	}
}

// 过期自动封禁条目的手动封禁 ----

// Given 预置名单含一条已到期未清理的自动封禁条目（自动封禁关闭时不会清理）。
// When 从事件页对该 IP 手动封禁（AddIPToList）。
// Then 条目必须被覆盖为生效中的手动条目（清空 expires_at），而不是命中即
// added:false 的静默 no-op（渲染生效集仍为空）。
func TestAddIPToList_replacesExpiredAutobanEntry(t *testing.T) {
	router := newAutobanTestEnv(t)
	id := autobanPresetID(t)
	seedAutobanListEntries(t, `[{"value":"198.51.100.9","remark":"自动封禁","created_at":"2026-10-01 00:00:00","expires_at":"2020-01-01 00:00:00"}]`)

	recorder := postJSON(t, router, fmt.Sprintf("/security/ip-lists/%d/ips", id), map[string]any{"value": "198.51.100.9"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"added":true`) {
		t.Fatalf("body=%s, want added:true（覆盖过期条目=实际新增生效封禁）", recorder.Body.String())
	}
	entries := readAutobanListEntries(t, id)
	if len(entries) != 1 {
		t.Fatalf("entries=%+v, want 单条原位覆盖（不得重复追加）", entries)
	}
	if entries[0].Value != "198.51.100.9" || entries[0].ExpiresAt != "" || entries[0].Remark != services.AutobanManualUnbanRemark {
		t.Fatalf("entry=%+v, want 手动封禁条目且 expires_at 清空", entries[0])
	}
	if len(services.AutobanActiveEntries(entries)) != 1 {
		t.Fatalf("渲染生效集仍为空: %+v", entries)
	}

	// 回归形状：已生效条目重复手动封禁仍幂等 added:false。
	recorder = postJSON(t, router, fmt.Sprintf("/security/ip-lists/%d/ips", id), map[string]any{"value": "198.51.100.9"})
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"added":false`) {
		t.Fatalf("重复添加: status=%d body=%s, want 200+added:false", recorder.Code, recorder.Body.String())
	}
}

// 威胁名单导出时文件读取/解析故障必须显式 500——
// 旧实现吞掉非 NotExist 错误返回 200 空 TXT，调用方无法区分「名单为空」。
func TestExportIPList_threatFileReadErrorReturns500(t *testing.T) {
	router := newAutobanTestEnv(t)
	wafDir := t.TempDir()
	t.Cleanup(services.OverrideThreatWafDirForTest(wafDir))
	// .iplist 路径为目录：os.ReadFile 返回 EISDIR（非「文件不存在」）。
	if err := os.Mkdir(filepath.Join(wafDir, "threat-ustc.iplist"), 0o755); err != nil {
		t.Fatal(err)
	}
	name := db.ThreatListNameBySource("ustc")
	// system=1 名单名唯一，威胁库行由 DB 初始化播种；直接取 id。
	var id int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=? AND system=1`, name).Scan(&id); err != nil {
		t.Fatalf("seed threat list row: %v", err)
	}

	rec := getRequest(t, router, fmt.Sprintf("/security/ip-lists/%d/export", id))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（读取故障不得伪装空导出）", rec.Code, rec.Body.String())
	}

	// 回归形状：文件缺失仍按空导出 200（禁用/未更新源）。
	if err := os.Remove(filepath.Join(wafDir, "threat-ustc.iplist")); err != nil {
		t.Fatal(err)
	}
	rec = getRequest(t, router, fmt.Sprintf("/security/ip-lists/%d/export", id))
	if rec.Code != http.StatusOK {
		t.Fatalf("missing file: status=%d body=%s, want 200 空导出", rec.Code, rec.Body.String())
	}
}

// 自动封禁计数由「实时 IPC 入库」与「尾读/补采」两条通道共同喂入，任务调度
// 只拥有后者——用户停止它（或自愈预算用尽停环）后补采/轮转停摆，但实时 IPC
// 入库仍提交（计数仍会增长）。/security/autoban/status 必须暴露降级原因并说明
// 实时入库仍在运行（只做可见性，不自动拉起显式停止的任务）。
func TestGetAutobanStatusExposesFeedHealth(t *testing.T) {
	newBackupTestHandlers(t)
	initTaskEngineForTest(t)
	te := services.TaskEngine()
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.GET("/security/autoban/status", h.GetAutobanStatus)

	get := func() map[string]any {
		t.Helper()
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/security/autoban/status", nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		var payload struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return payload.Data
	}

	// 默认装配：采集任务在调度中 → 不降级。
	if data := get(); data["feed_degraded"] != false {
		t.Fatalf("feed_degraded=%v, want false（采集任务在调度中）", data["feed_degraded"])
	}
	// 用户停止采集任务 → 状态卡必须给出降级原因。
	te.StopLoop(services.AutobanFeedTaskID)
	data := get()
	if data["feed_degraded"] != true {
		t.Fatalf("feed_degraded=%v, want true（喂入源停摆必须可见）", data["feed_degraded"])
	}
	if reason, _ := data["feed_degraded_reason"].(string); !strings.Contains(reason, "调度已停止") {
		t.Fatalf("feed_degraded_reason=%q, want 调度停止说明", reason)
	}
	if m, ok := te.Lookup(services.AutobanFeedTaskID); !ok || m.LoopOn {
		t.Fatal("可见性修复不得自动拉起用户显式停止的任务")
	}
}

// 状态卡读取失败只回泛化文案：驱动/SQLite 错误会带表名/列名/SQL 片段，
// 不得外泄给任意已登录用户（原文只进服务端日志）。
func TestGetAutobanStatus_genericErrorText(t *testing.T) {
	router := newAutobanTestEnv(t)
	if _, err := db.DB.Exec(`DROP TABLE security_ip_lists`); err != nil {
		t.Fatalf("drop table: %v", err)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/security/autoban/status", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500 (body=%s)", rec.Code, rec.Body.String())
	}
	var payload struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Message != "读取自动封禁名单失败" {
		t.Fatalf("message=%q, want 泛化文案", payload.Message)
	}
	if body := rec.Body.String(); strings.Contains(body, "no such table") {
		t.Fatalf("响应体泄漏内部错误原文: %s", body)
	}
}

// DB 写失败必须映射 500 + 泛化文案：与校验失败（400）分出口，不把存储层
// 原文（表/列/SQL 片段）回传给调用方。
func TestAutobanConfig_putDBFailureMapsTo500(t *testing.T) {
	router := newAutobanTestEnv(t)
	if _, err := db.DB.Exec(`CREATE TRIGGER test_fail_autoban_update BEFORE UPDATE ON global_config BEGIN SELECT RAISE(ABORT, 'simulated io failure'); END`); err != nil {
		t.Fatalf("install failure trigger: %v", err)
	}
	body := map[string]any{"threshold": 100, "window_minutes": 5, "duration": "1h", "scope": "all", "dry_run": true}
	rec := putJSON(t, router, "/security/autoban", body)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("DB 写失败须 500，status=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "simulated") || strings.Contains(rec.Body.String(), "global_config") {
		t.Fatalf("响应不得回传存储层原文: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "保存自动封禁配置失败") {
		t.Fatalf("500 文案应为泛化失败提示: %s", rec.Body.String())
	}

	// 故障解除后正常保存（回归：分出口不得把合法请求挡掉）。
	if _, err := db.DB.Exec(`DROP TRIGGER test_fail_autoban_update`); err != nil {
		t.Fatalf("drop failure trigger: %v", err)
	}
	if rec := putJSON(t, router, "/security/autoban", body); rec.Code != http.StatusOK {
		t.Fatalf("故障解除后保存 status=%d body=%s", rec.Code, rec.Body.String())
	}
}
