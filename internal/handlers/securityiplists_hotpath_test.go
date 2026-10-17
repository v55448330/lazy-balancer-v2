package handlers

// 名单写路径投影热路径（2026-10-15 用户裁定；第 78 轮补注：受信代理网段引用
// 同样走热路径，原「未被受信代理引用」排除项已退役——见
// TestAddIPToList_trustedProxyReferencedHotPathZeroReload）：名单-only 变更
// （条目实际变化）且被启用策略引用时——事务视图渲染重写投影文件 +
// 运行配置结构级比对证实零发射面变化 → 提交即收敛，零 /load（@ipListFast
// 匹配器 ≤1s stat 热感知）；未证实/不可判定 → 落回 finishTxApply 全量链。

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/wafiplist"
)

// hotPathIPListFixture 名单热路径测试夹具：计数 fake admin（GET /config/ 回显
// 最近一次 /load 载荷+补换行，caddy_sameconfig_test.go 同款生产形态）、临时
// 投影目录、安全库路径注入（缺库形态安全链整体不渲染，投影无从谈起）。
type hotPathIPListFixture struct {
	t        *testing.T
	adminSrv *httptest.Server
	mu       sync.Mutex
	posts    int
	lastBody []byte
	// rejectNextLoads >0 时接下来 N 次 /load 返回 400（拒绝分支测试注入）。
	rejectNextLoads int
	h               *Handlers
	router          *gin.Engine
	dir             string
}

func newHotPathIPListFixture(t *testing.T) *hotPathIPListFixture {
	t.Helper()
	setupSecurityPolicyTestDB(t)
	f := &hotPathIPListFixture{t: t}
	f.adminSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			_, _ = w.Write(append(f.lastBody, '\n'))
		case r.Method == http.MethodPost && r.URL.Path == "/load":
			f.posts++
			if f.rejectNextLoads > 0 {
				f.rejectNextLoads--
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte("rejected"))
				return
			}
			f.lastBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(f.adminSrv.Close)

	f.dir = t.TempDir()
	oldDir := services.IPListDataDir
	oldPrefix := wafiplist.AllowedPathPrefix
	services.IPListDataDir = f.dir
	wafiplist.AllowedPathPrefix = f.dir + string(filepath.Separator)
	t.Cleanup(func() {
		services.IPListDataDir = oldDir
		wafiplist.AllowedPathPrefix = oldPrefix
	})
	crsDir := filepath.Join(f.dir, "crs")
	if err := os.MkdirAll(filepath.Join(crsDir, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	xdb := filepath.Join(f.dir, "ip2region.xdb")
	if err := os.WriteFile(xdb, []byte("xdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	restoreLibs := services.SetSecurityLibsDirsForTest(crsDir, xdb)
	t.Cleanup(restoreLibs)

	gin.SetMode(gin.TestMode)
	f.h = &Handlers{caddyService: services.NewCaddyService(f.adminSrv.URL)}
	f.router = gin.New()
	f.router.PUT("/security/ip-lists/:id", f.h.UpdateIPList)
	f.router.POST("/security/ip-lists/:id/ips", f.h.AddIPToList)
	f.router.POST("/security/ip-lists/:id/remove-ip", f.h.RemoveIPFromList)
	return f
}

func (f *hotPathIPListFixture) loadCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.posts
}

// rejectLoads 注入接下来 N 次 /load 的 400 拒绝（Caddy 拒绝配置形态）。
func (f *hotPathIPListFixture) rejectLoads(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rejectNextLoads = n
}

// seed 名单+规则+deny ACL 策略（仅引用名单）+绑定，返回（名单 id, 策略 id）。
func (f *hotPathIPListFixture) seedReferencedList(entries string) (int64, int64) {
	f.t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled)
		VALUES ('lb-hot','hot','http','hot.example.test',8080,'weighted_round_robin',1)`); err != nil {
		f.t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled,protocol) VALUES ('lb-hot','127.0.0.1',9000,1,'http')`); err != nil {
		f.t.Fatalf("seed upstream: %v", err)
	}
	res, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, category, entries) VALUES ('热路径名单', '测试', ?)`, entries)
	if err != nil {
		f.t.Fatalf("seed list: %v", err)
	}
	listID, _ := res.LastInsertId()
	res, err = db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, policy_type, ip_acl_enabled, ip_acl_mode, ip_acl_list, ip_acl_list_refs)
		VALUES ('热路径策略', 'off', 1, 'stage1', 1, 'deny', '[]', ?)`, "["+strconv.FormatInt(listID, 10)+"]")
	if err != nil {
		f.t.Fatalf("seed policy: %v", err)
	}
	policyID, _ := res.LastInsertId()
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb-hot', ?)`, policyID); err != nil {
		f.t.Fatalf("bind policy: %v", err)
	}
	return listID, policyID
}

func (f *hotPathIPListFixture) projectionContent(policyID int64) string {
	f.t.Helper()
	path := filepath.Join(services.IPListDataDir, "p"+strconv.FormatInt(policyID, 10)+"-acl.txt")
	raw, err := os.ReadFile(path)
	if err != nil {
		f.t.Fatalf("读投影文件 %s: %v", path, err)
	}
	return string(raw)
}

// trustedProxyProjectionContent 读受信代理合并网段投影（稳定命名 tp.txt）。
func (f *hotPathIPListFixture) trustedProxyProjectionContent() string {
	f.t.Helper()
	path := filepath.Join(services.IPListDataDir, "tp.txt")
	raw, err := os.ReadFile(path)
	if err != nil {
		f.t.Fatalf("读受信代理投影 %s: %v", path, err)
	}
	return string(raw)
}

func (f *hotPathIPListFixture) postJSON(path string, body any) *httptest.ResponseRecorder {
	f.t.Helper()
	return postJSON(f.t, f.router, path, body)
}

func (f *hotPathIPListFixture) putJSON(path string, body any) *httptest.ResponseRecorder {
	f.t.Helper()
	return putJSON(f.t, f.router, path, body)
}

// Given：规则+策略引用名单已渲染应用（运行配置与投影就位）。
// When：追加 IP（名单-only 变更）。
// Then：200 added:true、零新增 /load、投影文件含新旧全部条目。
func TestAddIPToList_hotPathRewritesProjectionZeroReload(t *testing.T) {
	f := newHotPathIPListFixture(t)
	listID, policyID := f.seedReferencedList(`[{"value":"203.0.113.5","remark":""}]`)
	if err := f.h.caddyService.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("首次应用: %v", err)
	}
	if got := f.loadCount(); got != 1 {
		t.Fatalf("首次 /load=%d, want 1", got)
	}

	rec := f.postJSON(fmt.Sprintf("/security/ip-lists/%d/ips", listID), map[string]any{"value": "192.0.2.44"})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"added":true`) {
		t.Fatalf("追加 status=%d body=%s, want 200 added:true", rec.Code, rec.Body.String())
	}
	if got := f.loadCount(); got != 1 {
		t.Fatalf("热路径后 /load=%d, want 仍 1（零重载）", got)
	}
	content := f.projectionContent(policyID)
	if !strings.Contains(content, "203.0.113.5/32") || !strings.Contains(content, "192.0.2.44/32") {
		t.Fatalf("投影内容=%q, want 含新旧全部条目", content)
	}
}

// Given：名单被受信代理网段引用（trusted_proxy_range_refs）。When：追加 IP。
// Then：受信代理引用面已热路径化（合并网段投影 tp.txt，lb_file 文件源 ≤1s
// stat 热感知）——零 /load，名单投影与受信代理投影双双按新内容重写。
func TestAddIPToList_trustedProxyReferencedHotPathZeroReload(t *testing.T) {
	f := newHotPathIPListFixture(t)
	listID, policyID := f.seedReferencedList(`[{"value":"203.0.113.5","remark":""}]`)
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_enabled=1, trusted_proxy_range_refs=? WHERE id=1`,
		"["+strconv.FormatInt(listID, 10)+"]"); err != nil {
		t.Fatal(err)
	}
	if err := f.h.caddyService.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("首次应用: %v", err)
	}
	if got := f.loadCount(); got != 1 {
		t.Fatalf("首次 /load=%d, want 1", got)
	}
	before := f.trustedProxyProjectionContent()

	rec := f.postJSON(fmt.Sprintf("/security/ip-lists/%d/ips", listID), map[string]any{"value": "192.0.2.44"})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"added":true`) {
		t.Fatalf("追加 status=%d body=%s, want 200 added:true", rec.Code, rec.Body.String())
	}
	if got := f.loadCount(); got != 1 {
		t.Fatalf("受信代理引用名单变化应走热路径零重载: /load=%d, want 仍 1", got)
	}
	content := f.projectionContent(policyID)
	if !strings.Contains(content, "203.0.113.5/32") || !strings.Contains(content, "192.0.2.44/32") {
		t.Fatalf("名单投影内容=%q, want 含新旧全部条目", content)
	}
	if after := f.trustedProxyProjectionContent(); !strings.Contains(after, "192.0.2.44/32") || after == before {
		t.Fatalf("受信代理投影应含新条目: before=%q after=%q", before, after)
	}
}

// Given：名单仅被禁用策略引用（无启用引用方）。When：追加 IP。
// Then：维持现状——全量链渲染 + 同字节短路，零 /load（无投影无重载）。
func TestAddIPToList_unreferencedKeepsExistingPath(t *testing.T) {
	f := newHotPathIPListFixture(t)
	res, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, category, entries) VALUES ('无人引用', '测试', '[{"value":"203.0.113.5","remark":""}]')`)
	if err != nil {
		t.Fatal(err)
	}
	listID, _ := res.LastInsertId()
	if err := f.h.caddyService.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("首次应用: %v", err)
	}

	rec := f.postJSON(fmt.Sprintf("/security/ip-lists/%d/ips", listID), map[string]any{"value": "192.0.2.44"})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"added":true`) {
		t.Fatalf("追加 status=%d body=%s, want 200 added:true", rec.Code, rec.Body.String())
	}
	if got := f.loadCount(); got != 1 {
		t.Fatalf("未被引用名单变化维持现状零重载: /load=%d, want 仍 1", got)
	}
}

// Given：条目未变化（仅元数据更新）。When：PUT 改名。
// Then：名单-only 变更不成立 → 全量链（同字节短路），零 /load、投影不动。
func TestUpdateIPList_metadataOnlySkipsHotPath(t *testing.T) {
	f := newHotPathIPListFixture(t)
	listID, policyID := f.seedReferencedList(`[{"value":"203.0.113.5","remark":""}]`)
	if err := f.h.caddyService.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("首次应用: %v", err)
	}
	before := f.projectionContent(policyID)

	rec := f.putJSON(fmt.Sprintf("/security/ip-lists/%d", listID), map[string]any{"name": "改名后", "description": "只动元数据"})
	if rec.Code != http.StatusOK {
		t.Fatalf("更新 status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	if got := f.loadCount(); got != 1 {
		t.Fatalf("元数据变更零发射面影响: /load=%d, want 仍 1", got)
	}
	if after := f.projectionContent(policyID); after != before {
		t.Fatalf("元数据变更不应触碰投影: before=%q after=%q", before, after)
	}
}

// Given：条目整体替换（full replace）。When：PUT 新 entries。
// Then：热路径——零 /load + 投影按新集合重写。
func TestUpdateIPList_entriesReplaceHotPath(t *testing.T) {
	f := newHotPathIPListFixture(t)
	listID, policyID := f.seedReferencedList(`[{"value":"203.0.113.5","remark":""}]`)
	if err := f.h.caddyService.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("首次应用: %v", err)
	}

	rec := f.putJSON(fmt.Sprintf("/security/ip-lists/%d", listID), map[string]any{
		"entries": `[{"value":"198.51.100.7","remark":"替换"}]`,
	})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "已更新") {
		t.Fatalf("更新 status=%d body=%s, want 200 已更新", rec.Code, rec.Body.String())
	}
	if got := f.loadCount(); got != 1 {
		t.Fatalf("条目替换热路径零重载: /load=%d, want 仍 1", got)
	}
	if content := f.projectionContent(policyID); !strings.Contains(content, "198.51.100.7/32") || strings.Contains(content, "203.0.113.5") {
		t.Fatalf("投影应按新集合重写: %q", content)
	}
}
