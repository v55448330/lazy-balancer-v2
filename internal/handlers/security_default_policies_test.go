package handlers

// 默认策略 apply 的 handler 级契约：响应形状、事件发布、导入窗口
// 409、畸形请求体 400、apply 失败 500（单事务→零部分进度）、热路径事件。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/notify"
	"lazy-balancer-v2/internal/services"
)

// defaultPoliciesTestEnv 建库 + fake Caddy + 路由；返回捕获的通知事件。
type defaultPoliciesTestEnv struct {
	h      *Handlers
	router *gin.Engine
	mu     sync.Mutex
	events []notify.Event
}

func (e *defaultPoliciesTestEnv) capturedEvents() []notify.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]notify.Event(nil), e.events...)
}

func newDefaultPoliciesTestEnv(t *testing.T) *defaultPoliciesTestEnv {
	t.Helper()
	// 全局缝隔离（importWindowActive 等）：本文件用例开导入窗口/换全局 seam，
	// 未复位会泄漏到包内后续用例（FixEvents 集成实测 409 串扰）。
	withIsolatedGlobal(t)
	// 导入窗口显式复位：withIsolatedGlobal 只判泄漏不还原；本环境的 409 用例
	// 故意持窗，收尾必须关闭，否则同包后续导入用例拿到「导入进行中」。
	t.Cleanup(func() { importWindowActive.Store(0) })
	setupSecurityPolicyTestDB(t)
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	gin.SetMode(gin.TestMode)
	e := &defaultPoliciesTestEnv{}
	oldPublish := notifyPublish
	notifyPublish = func(evt notify.Event) {
		e.mu.Lock()
		e.events = append(e.events, evt)
		e.mu.Unlock()
	}
	t.Cleanup(func() { notifyPublish = oldPublish })

	e.h = &Handlers{caddyService: services.NewCaddyService(fakeCaddy.URL)}
	e.router = gin.New()
	e.router.Use(func(c *gin.Context) {
		c.Set("user_id", 7)
		c.Set("username", "admin")
		c.Next()
	})
	e.router.POST("/security/default-policies", e.h.ApplyDefaultPolicies)
	e.router.GET("/security/default-policies/catalog", e.h.GetDefaultPolicyCatalog)
	return e
}

func (e *defaultPoliciesTestEnv) post(body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(http.MethodPost, "/security/default-policies", nil)
	} else {
		req = httptest.NewRequest(http.MethodPost, "/security/default-policies", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	e.router.ServeHTTP(rec, req)
	return rec
}

type defaultPoliciesResponse struct {
	Code    int                   `json:"code"`
	Message string                `json:"message"`
	Data    []db.DefaultApplyItem `json:"data"`
}

// Given：空库（无默认策略）。When：apply。Then：200 + 10 项全 created +
// 策略/名单事件各一条（动作与汇总口径）。
func TestApplyDefaultPolicies_successShapeAndEvents(t *testing.T) {
	env := newDefaultPoliciesTestEnv(t)
	rec := env.post("")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp defaultPoliciesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if resp.Code != 0 || len(resp.Data) != 10 {
		t.Fatalf("code=%d data=%d want 0/10 (%s)", resp.Code, len(resp.Data), rec.Body.String())
	}
	for _, it := range resp.Data {
		if it.Status != "created" {
			t.Fatalf("%s status=%q want created", it.Name, it.Status)
		}
	}
	events := env.capturedEvents()
	var policyEvt, listEvt *notify.Event
	for i := range events {
		switch events[i].Type {
		case notify.EvtPolicyChanged:
			policyEvt = &events[i]
		case notify.EvtIPListChanged:
			listEvt = &events[i]
		}
	}
	if policyEvt == nil || listEvt == nil {
		t.Fatalf("events=%+v want EvtPolicyChanged + EvtIPListChanged", events)
	}
	if policyEvt.Fields["2"] != "创建了默认策略" {
		t.Fatalf("policy action=%q want 创建了默认策略", policyEvt.Fields["2"])
	}
	if !strings.Contains(policyEvt.Fields["3"], "新建 8 项") {
		t.Fatalf("policy summary=%q want 新建 8 项", policyEvt.Fields["3"])
	}
	if listEvt.Fields["2"] != "创建了默认名单" || !strings.Contains(listEvt.Fields["3"], "信任名单地址列表") {
		t.Fatalf("list event fields=%v", listEvt.Fields)
	}
	// updated_by = 请求操作者
	var updatedBy int64
	if err := db.DB.QueryRow(`SELECT updated_by FROM security_policies WHERE name='信任名单'`).Scan(&updatedBy); err != nil {
		t.Fatalf("read updated_by: %v", err)
	}
	if updatedBy != 7 {
		t.Fatalf("updated_by=%d want 7（contextUserID）", updatedBy)
	}
}

// 全 exists 的二次 apply 不产生「创建/重置」噪音事件。
func TestApplyDefaultPolicies_secondRunNoEvents(t *testing.T) {
	env := newDefaultPoliciesTestEnv(t)
	if rec := env.post(""); rec.Code != http.StatusOK {
		t.Fatalf("first apply status=%d", rec.Code)
	}
	env.mu.Lock()
	env.events = nil
	env.mu.Unlock()
	if rec := env.post(""); rec.Code != http.StatusOK {
		t.Fatalf("second apply status=%d body=%s", rec.Code, rec.Body.String())
	}
	if events := env.capturedEvents(); len(events) != 0 {
		t.Fatalf("二次 apply 零变更不得发事件: %+v", events)
	}
}

// reset=true 走删除重建：事件动作=「重置了默认策略」。
func TestApplyDefaultPolicies_resetEventAction(t *testing.T) {
	env := newDefaultPoliciesTestEnv(t)
	if rec := env.post(""); rec.Code != http.StatusOK {
		t.Fatalf("first apply status=%d", rec.Code)
	}
	env.mu.Lock()
	env.events = nil
	env.mu.Unlock()
	rec := env.post(`{"reset":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("reset status=%d body=%s", rec.Code, rec.Body.String())
	}
	var policyEvt *notify.Event
	events := env.capturedEvents()
	for i := range events {
		if events[i].Type == notify.EvtPolicyChanged {
			policyEvt = &events[i]
		}
	}
	if policyEvt == nil || policyEvt.Fields["2"] != "重置了默认策略" {
		t.Fatalf("reset event=%+v want 重置了默认策略", policyEvt)
	}
	if !strings.Contains(policyEvt.Fields["3"], "重建 8 项") {
		t.Fatalf("reset summary=%q want 重建 8 项", policyEvt.Fields["3"])
	}
}

// 畸形 body 400（不得静默丢弃 reset）；空 body 兼容 200。
func TestApplyDefaultPolicies_bodyGuard(t *testing.T) {
	env := newDefaultPoliciesTestEnv(t)
	if rec := env.post(`{"reset":`); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed status=%d body=%s want 400", rec.Code, rec.Body.String())
	}
	// 畸形请求不得落库
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policies`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("malformed body 落库 n=%d err=%v", n, err)
	}
	if rec := env.post(""); rec.Code != http.StatusOK {
		t.Fatalf("empty body status=%d want 200（存量调用方兼容）", rec.Code)
	}
}

// 导入窗口内 409 fast-fail，且门在取 caddyOpMu 之前（预持锁不阻塞）。
func TestApplyDefaultPolicies_importWindow409BeforeLock(t *testing.T) {
	env := newDefaultPoliciesTestEnv(t)
	beginImportWindowForTest(t)
	env.h.caddyOpMu.Lock()
	defer env.h.caddyOpMu.Unlock()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- env.post("") }()
	rec := <-done
	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s want 409", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "配置导入进行中") {
		t.Fatalf("body=%s want 导入窗口文案", rec.Body.String())
	}
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policies`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("导入窗口内落库 n=%d err=%v", n, err)
	}
}

// apply DB 失败（单事务回滚）→ 500，响应不带虚假「已建 N 项」。
func TestApplyDefaultPolicies_dbFailure500NoPartial(t *testing.T) {
	env := newDefaultPoliciesTestEnv(t)
	if _, err := db.DB.Exec(`CREATE TRIGGER fail_default_policy BEFORE INSERT ON security_policies
		WHEN NEW.name='手动黑名单' BEGIN SELECT RAISE(ABORT,'injected failure'); END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	rec := env.post("")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s want 500", rec.Code, rec.Body.String())
	}
	var resp defaultPoliciesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Code != 500 || len(resp.Data) != 0 {
		t.Fatalf("code=%d data=%d want 500/0（单事务不得带部分进度）", resp.Code, len(resp.Data))
	}
	for _, query := range []string{
		`SELECT COUNT(*) FROM security_policies`,
		`SELECT COUNT(*) FROM security_ip_lists WHERE system=0`, // 内置 system=1 名单由启动播种，不计
	} {
		var n int
		if err := db.DB.QueryRow(query).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s=%d err=%v want 0（失败整体回滚）", query, n, err)
		}
	}
	if events := env.capturedEvents(); len(events) != 0 {
		t.Fatalf("失败不得发事件: %+v", events)
	}
}

// 目录读故障 500（不得被呈现为全「未创建」）。
func TestGetDefaultPolicyCatalog_dbFailure500(t *testing.T) {
	env := newDefaultPoliciesTestEnv(t)
	if _, err := db.DB.Exec(`DROP TABLE security_policies`); err != nil {
		t.Fatalf("drop table: %v", err)
	}
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/security/default-policies/catalog", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s want 500", rec.Code, rec.Body.String())
	}
}

// 名单被启用策略引用时走投影热路径——事件必须照常发布
// （热路径此前静默丢弃 txApplyFinish.Notify）。
func TestIPListHotPath_publishesNotify(t *testing.T) {
	withIsolatedGlobal(t) // 本函数体直写 notifyPublish seam（守卫按函数体扫描）
	f := newHotPathIPListFixture(t)
	var mu sync.Mutex
	var events []notify.Event
	oldPublish := notifyPublish
	notifyPublish = func(evt notify.Event) {
		mu.Lock()
		events = append(events, evt)
		mu.Unlock()
	}
	t.Cleanup(func() { notifyPublish = oldPublish })

	listID, _ := f.seedReferencedList(`[{"value":"203.0.113.5","remark":""}]`)
	if err := f.h.caddyService.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("首次应用: %v", err)
	}
	rec := f.postJSON(fmt.Sprintf("/security/ip-lists/%d/ips", listID), map[string]any{"value": "192.0.2.44"})
	if rec.Code != http.StatusOK {
		t.Fatalf("add status=%d body=%s", rec.Code, rec.Body.String())
	}
	mu.Lock()
	addCount := len(events)
	lastAdd := notify.Event{}
	if addCount > 0 {
		lastAdd = events[addCount-1]
	}
	mu.Unlock()
	if addCount != 1 || lastAdd.Type != notify.EvtIPListChanged || lastAdd.Fields["2"] != "变更了条目" {
		t.Fatalf("热路径追加未发布事件: %+v", events)
	}
	// 移除条目同族（R-12 兄弟位：此前 remove-ip 无 Notify）
	rec = f.postJSON(fmt.Sprintf("/security/ip-lists/%d/remove-ip", listID), map[string]any{"value": "192.0.2.44"})
	if rec.Code != http.StatusOK {
		t.Fatalf("remove status=%d body=%s", rec.Code, rec.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 || events[1].Type != notify.EvtIPListChanged {
		t.Fatalf("热路径移除未发布事件: %+v", events)
	}
}

// 系统名单名单源锚定：db 侧常量/引用键与 services 层常数必须同名（db 不能
// 反向依赖 services，故用跨包测试锁住唯一可能漂移的字面量）。
func TestSystemListNames_singleSourceAcrossPackages(t *testing.T) {
	if db.AutobanPresetListName != services.AutobanPresetListName {
		t.Fatalf("自动封禁名单名漂移: db=%q services=%q", db.AutobanPresetListName, services.AutobanPresetListName)
	}
	for _, key := range db.ThreatSystemListRefKeys() {
		if !strings.HasPrefix(key, "sys:") {
			t.Fatalf("威胁名单引用键缺 sys: 前缀: %q", key)
		}
	}
}

// 名单未被启用策略引用时 tryIPListHotPathApply 返回 false 落
// 全量链——全量链的 txApplyFinish 必须带 Notify，否则「未引用名单」的增/删/
// 条目改写零通知（热路径分支早已发）。
func TestIPListFullChainFallback_publishesNotify(t *testing.T) {
	withIsolatedGlobal(t) // 本函数体直写 notifyPublish seam（守卫按函数体扫描）
	f := newHotPathIPListFixture(t)
	var mu sync.Mutex
	var events []notify.Event
	oldPublish := notifyPublish
	notifyPublish = func(evt notify.Event) {
		mu.Lock()
		events = append(events, evt)
		mu.Unlock()
	}
	t.Cleanup(func() { notifyPublish = oldPublish })

	// 运行配置基线（与名单无关的规则）：全量链 render+比对可收敛。
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled)
		VALUES ('lb-plain','plain','http','plain.example.test',8080,'weighted_round_robin',1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled,protocol) VALUES ('lb-plain','127.0.0.1',9002,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	if err := f.h.caddyService.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("首次应用: %v", err)
	}
	res, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, category, entries) VALUES ('未引用名单','测试','[]')`)
	if err != nil {
		t.Fatalf("seed list: %v", err)
	}
	listID, _ := res.LastInsertId()

	expectEvent := func(step, action string) {
		t.Helper()
		mu.Lock()
		defer mu.Unlock()
		if len(events) != 1 {
			t.Fatalf("%s 后事件=%+v want 1 条 EvtIPListChanged", step, events)
		}
		evt := events[0]
		if evt.Type != notify.EvtIPListChanged || evt.Fields["2"] != action || evt.Fields["3"] != "未引用名单" {
			t.Fatalf("%s 事件=%+v want %s（未引用名单）", step, evt, action)
		}
		events = nil
	}

	if rec := f.postJSON(fmt.Sprintf("/security/ip-lists/%d/ips", listID), map[string]any{"value": "198.51.100.7"}); rec.Code != http.StatusOK {
		t.Fatalf("追加 status=%d body=%s", rec.Code, rec.Body.String())
	}
	expectEvent("追加", "变更了条目")

	if rec := f.postJSON(fmt.Sprintf("/security/ip-lists/%d/remove-ip", listID), map[string]any{"value": "198.51.100.7"}); rec.Code != http.StatusOK {
		t.Fatalf("移除 status=%d body=%s", rec.Code, rec.Body.String())
	}
	expectEvent("移除", "变更了条目")

	// 条目覆盖式更新同族（同一 finishTxApply 回退位，动作与热路径同参数）。
	if rec := f.putJSON(fmt.Sprintf("/security/ip-lists/%d", listID), map[string]any{"entries": `[{"value":"198.51.100.9","remark":""}]`}); rec.Code != http.StatusOK {
		t.Fatalf("条目改写 status=%d body=%s", rec.Code, rec.Body.String())
	}
	expectEvent("条目改写", "更新了")
}
