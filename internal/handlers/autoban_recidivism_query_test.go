package handlers

// 累犯记录端点增强钉（筛选/分页/单条删除/归属地/行富化）：
//   GET    hide_permanent（默认 true 隐藏 permanent）/ip 子串筛选/分页
//          {records,total,page,page_size}；records[].ip_location 富化
//          （enrichIPLocation 单源，保留地址前置拦截）；records[].ban_status/
//          ban_expires_at（名单生效条目 join 三态）与 hits_24h/last_event_at
//          （metrics security_events 近 24h 按身份键聚合，IPv6 /64 归一）。
//   DELETE /security/autoban/recidivism/:identity 单条取消累犯身份
//          （幂等——不存在也 200）；主节点门+导入窗口门同全量重置；
//          显式审计「删除」；不动已生效封禁条目。

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// recidivismPage 是 GET 分页响应的观测形态。
type recidivismPage struct {
	Code int `json:"code"`
	Data struct {
		Records []struct {
			Identity          string `json:"identity"`
			OffenseCount      int    `json:"offense_count"`
			LastBanAt         string `json:"last_ban_at"`
			EscalatedDuration string `json:"escalated_duration"`
			IPLocation        string `json:"ip_location"`
		} `json:"records"`
		Total    int `json:"total"`
		Page     int `json:"page"`
		PageSize int `json:"page_size"`
	} `json:"data"`
}

func getRecidivismPage(t *testing.T, router *gin.Engine, query string) recidivismPage {
	t.Helper()
	rec := getRequest(t, router, "/security/autoban/recidivism"+query)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var page recidivismPage
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("parse: %v body=%s", err, rec.Body.String())
	}
	if page.Code != 0 {
		t.Fatalf("code=%d body=%s", page.Code, rec.Body.String())
	}
	return page
}

// Given 种子四行（含一行 permanent）。
// When GET 缺省参数。
// Then hide_permanent 默认 true：permanent 行隐藏；total=3；page=1/page_size=20。
func TestAutobanRecidivism_getDefaultsHidePermanentAndPaginate(t *testing.T) {
	router := newAutobanRecidivismRouter(t)
	seedRecidivismTestRows(t)

	page := getRecidivismPage(t, router, "")
	if page.Data.Total != 3 {
		t.Fatalf("total=%d, want 3（默认隐藏 permanent）", page.Data.Total)
	}
	if page.Data.Page != 1 || page.Data.PageSize != 20 {
		t.Fatalf("page/page_size=%d/%d, want 1/20（默认分页）", page.Data.Page, page.Data.PageSize)
	}
	if len(page.Data.Records) != 3 {
		t.Fatalf("records=%d, want 3", len(page.Data.Records))
	}
	for _, r := range page.Data.Records {
		if r.EscalatedDuration == "permanent" {
			t.Fatalf("permanent 行必须默认隐藏: %+v", r)
		}
	}
}

// Given 种子四行。
// When GET hide_permanent=false。
// Then permanent 行可见，total=4。
func TestAutobanRecidivism_getShowPermanent(t *testing.T) {
	router := newAutobanRecidivismRouter(t)
	seedRecidivismTestRows(t)

	page := getRecidivismPage(t, router, "?hide_permanent=false")
	if page.Data.Total != 4 || len(page.Data.Records) != 4 {
		t.Fatalf("total/records=%d/%d, want 4/4（hide_permanent=false 显示全部）", page.Data.Total, len(page.Data.Records))
	}
}

// Given 种子四行。
// When GET ip=45.33.32（子串）。
// Then 只命中两行 45.33.32.*；total=2。
func TestAutobanRecidivism_getIPFilter(t *testing.T) {
	router := newAutobanRecidivismRouter(t)
	seedRecidivismTestRows(t)

	page := getRecidivismPage(t, router, "?ip=45.33.32")
	if page.Data.Total != 2 {
		t.Fatalf("total=%d, want 2（ip 子串筛选）", page.Data.Total)
	}
	for _, r := range page.Data.Records {
		if !strings.Contains(r.Identity, "45.33.32") {
			t.Fatalf("identity=%q 不含筛选子串", r.Identity)
		}
	}
}

// Given 种子四行。
// When GET page=2&page_size=2&hide_permanent=false。
// Then 第二页两条（排序后第 3/4 行）；total=4 不受分页截断。
func TestAutobanRecidivism_getPagination(t *testing.T) {
	router := newAutobanRecidivismRouter(t)
	seedRecidivismTestRows(t)

	page := getRecidivismPage(t, router, "?hide_permanent=false&page=2&page_size=2")
	if page.Data.Total != 4 || page.Data.Page != 2 || page.Data.PageSize != 2 {
		t.Fatalf("total/page/page_size=%d/%d/%d, want 4/2/2", page.Data.Total, page.Data.Page, page.Data.PageSize)
	}
	if len(page.Data.Records) != 2 {
		t.Fatalf("records=%d, want 2", len(page.Data.Records))
	}
	// 全序：permanent(3) → 45.33.32.10(2) → 45.33.32.11(2) → 198.51.100.7(1)。
	if page.Data.Records[0].Identity != "45.33.32.11" || page.Data.Records[1].Identity != "198.51.100.7" {
		t.Fatalf("page2=%v, want [45.33.32.11 198.51.100.7]", page.Data.Records)
	}
}

// Given 种子四行。
// When GET page=abc（非整数）。
// Then 400（parsePaginationParam 统一口径，不静默回落）。
func TestAutobanRecidivism_getInvalidPageRejected(t *testing.T) {
	router := newAutobanRecidivismRouter(t)
	rec := getRequest(t, router, "/security/autoban/recidivism?page=abc")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（非整数分页参数）", rec.Code, rec.Body.String())
	}
}

// Given 种子含保留地址行（198.51.100.7=RFC5737 文档段）与公网行。
// When GET hide_permanent=false。
// Then 逐行 ip_location：保留地址→「保留地址」；公网无 xdb→""（降级不报错）。
func TestAutobanRecidivism_getEnrichesIPLocation(t *testing.T) {
	services.ResetIP2RegionSearcherForTest()
	t.Cleanup(services.ResetIP2RegionSearcherForTest)
	router := newAutobanRecidivismRouter(t)
	seedRecidivismTestRows(t)

	page := getRecidivismPage(t, router, "?hide_permanent=false")
	byID := map[string]string{}
	for _, r := range page.Data.Records {
		byID[r.Identity] = r.IPLocation
	}
	if byID["198.51.100.7"] != "保留地址" {
		t.Fatalf("198.51.100.7 ip_location=%q, want 保留地址（RFC5737 段前置拦截）", byID["198.51.100.7"])
	}
	if byID["45.33.32.10"] != "" {
		t.Fatalf("45.33.32.10 ip_location=%q, want \"\"（无 xdb 降级空串）", byID["45.33.32.10"])
	}
}

// Given 种子四行 + 预置名单生效条目。
// When DELETE /security/autoban/recidivism/45.33.32.10。
// Then 200；仅该行删除；审计「删除/累犯记录」；封禁条目不受影响。
func TestAutobanRecidivism_deleteSingleIdentity(t *testing.T) {
	router := newAutobanRecidivismRouter(t)
	seedRecidivismTestRows(t)
	seedAutobanListEntries(t, `[{"value":"45.33.32.10","remark":"auto","expires_at":"2099-01-01 00:00:00"}]`)

	rec := deleteRequest(t, router, "/security/autoban/recidivism/45.33.32.10")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM autoban_recidivism WHERE identity='45.33.32.10'`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("target identity still present (%d rows)", n)
	}
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM autoban_recidivism`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 3 {
		t.Fatalf("table=%d rows, want 3（只删单条）", n)
	}
	if got := countAuditRows(t, "删除", "累犯记录"); got != 1 {
		t.Fatalf("audit rows=%d, want 1（删除/累犯记录）", got)
	}
	entries := readAutobanListEntries(t, autobanPresetID(t))
	if len(entries) != 1 || entries[0].Value != "45.33.32.10" {
		t.Fatalf("单条删除不得动封禁条目, got %+v", entries)
	}
}

// Given 目标身份不存在（或已删过一次）。
// When 重复 DELETE 同一 identity。
// Then 幂等：仍 200、表状态不变。
func TestAutobanRecidivism_deleteSingleIdempotent(t *testing.T) {
	router := newAutobanRecidivismRouter(t)
	seedRecidivismTestRows(t)
	for i := range 2 {
		rec := deleteRequest(t, router, "/security/autoban/recidivism/203.0.113.99")
		if rec.Code != http.StatusOK {
			t.Fatalf("call %d status=%d body=%s", i+1, rec.Code, rec.Body.String())
		}
	}
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM autoban_recidivism`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 4 {
		t.Fatalf("table=%d rows, want 4（无关行不受影响）", n)
	}
}

// Given IPv6 /64 身份行（identity 带 :: 形态）。
// When DELETE 路径参数 URL 编码后提交。
// Then 精确命中删除（路径参数不解码歧义）。
func TestAutobanRecidivism_deleteSingleIPv6Identity(t *testing.T) {
	router := newAutobanRecidivismRouter(t)
	seedRecidivismTestRows(t)

	rec := deleteRequest(t, router, "/security/autoban/recidivism/"+url.PathEscape("2606:4700:abcd:1234::"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM autoban_recidivism WHERE identity='2606:4700:abcd:1234::'`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("IPv6 identity still present (%d rows)", n)
	}
}

// Given 从节点角色（is_master=0）。
// When DELETE 单条。
// Then 403 主节点门（与全量重置同口径），行不删。
func TestAutobanRecidivism_deleteSingleSlaveRejected(t *testing.T) {
	router := newAutobanRecidivismRouter(t)
	seedRecidivismTestRows(t)
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	rec := deleteRequest(t, router, "/security/autoban/recidivism/45.33.32.10")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s, want 403（从节点写门）", rec.Code, rec.Body.String())
	}
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM autoban_recidivism WHERE identity='45.33.32.10'`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("从节点拒绝后行必须保留, got %d", n)
	}
}

// Given 导入窗口开启。
// When DELETE 单条。
// Then 409（累犯表在 security 节全量替换清单内），行不删。
func TestAutobanRecidivism_deleteSingleImportWindowRejected(t *testing.T) {
	router := newAutobanRecidivismRouter(t)
	seedRecidivismTestRows(t)
	closeWindow := beginImportWindowForTest(t)
	defer closeWindow()

	rec := deleteRequest(t, router, "/security/autoban/recidivism/45.33.32.10")
	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409（导入窗口拒绝写）", rec.Code, rec.Body.String())
	}
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM autoban_recidivism WHERE identity='45.33.32.10'`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("导入窗口拒绝后行必须保留, got %d", n)
	}
}

// recidivismEnrichRow 是行富化字段的观测形态。
type recidivismEnrichRow struct {
	Identity     string `json:"identity"`
	BanStatus    string `json:"ban_status"`
	BanExpiresAt string `json:"ban_expires_at"`
	Hits24h      int    `json:"hits_24h"`
	LastEventAt  string `json:"last_event_at"`
}

func getRecidivismEnrichRows(t *testing.T, router *gin.Engine, query string) []recidivismEnrichRow {
	t.Helper()
	rec := getRequest(t, router, "/security/autoban/recidivism"+query)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Records []recidivismEnrichRow `json:"records"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v body=%s", err, rec.Body.String())
	}
	if resp.Code != 0 {
		t.Fatalf("code=%d body=%s", resp.Code, rec.Body.String())
	}
	return resp.Data.Records
}

func enrichRowByIdentity(t *testing.T, rows []recidivismEnrichRow, identity string) recidivismEnrichRow {
	t.Helper()
	for _, r := range rows {
		if r.Identity == identity {
			return r
		}
	}
	t.Fatalf("identity %s 不在响应行集 %+v", identity, rows)
	return recidivismEnrichRow{}
}

// Given 累犯三身份 + 名单限时/永久/无条目 + metrics 近 24h 事件（IPv4 精确、
// IPv6 同 /64 漂移地址聚合）。
// When GET /security/autoban/recidivism?hide_permanent=false。
// Then 逐行 ban_status/ban_expires_at/hits_24h/last_event_at 富化齐备。
func TestAutobanRecidivism_getEnrichesBanStatusAndHits(t *testing.T) {
	router := newAutobanRecidivismRouter(t)
	if _, err := db.DB.Exec(`INSERT INTO autoban_recidivism (identity, offense_count, last_ban_at, escalated_duration) VALUES
		('203.0.113.10', 2, '2026-11-15 08:00:00', '24h'),
		('203.0.113.11', 3, '2026-11-15 09:00:00', 'permanent'),
		('2606:4700:abcd:1234::', 2, '2026-11-15 07:00:00', '24h')`); err != nil {
		t.Fatalf("seed recidivism: %v", err)
	}
	future := time.Now().UTC().Add(2 * time.Hour).Format("2006-01-02 15:04:05")
	seedAutobanListEntries(t, `[{"value":"203.0.113.10","expires_at":"`+future+`"},{"value":"203.0.113.11"}]`)
	recent := time.Now().UTC().Add(-30 * time.Minute).Format("2006-01-02 15:04:05")
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (client_ip, event_time) VALUES
		('203.0.113.10', ?), ('2606:4700:abcd:1234:9::1', ?), ('2606:4700:abcd:1234::7', ?)`,
		recent, recent, recent); err != nil {
		t.Fatalf("seed events: %v", err)
	}

	rows := getRecidivismEnrichRows(t, router, "?hide_permanent=false")
	timed := enrichRowByIdentity(t, rows, "203.0.113.10")
	if timed.BanStatus != "timed" || timed.BanExpiresAt != future || timed.Hits24h != 1 || timed.LastEventAt != recent {
		t.Fatalf("限时封禁行富化失真: %+v", timed)
	}
	perm := enrichRowByIdentity(t, rows, "203.0.113.11")
	if perm.BanStatus != "permanent" || perm.BanExpiresAt != "" || perm.Hits24h != 0 || perm.LastEventAt != "" {
		t.Fatalf("永久封禁行富化失真: %+v", perm)
	}
	v6 := enrichRowByIdentity(t, rows, "2606:4700:abcd:1234::")
	if v6.BanStatus != "none" || v6.Hits24h != 2 || v6.LastEventAt != recent {
		t.Fatalf("IPv6 /64 身份聚合失真（漂移地址计入本段）: %+v", v6)
	}
}
