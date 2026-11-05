package cloudflare

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/dnsname"
	"lazy-balancer-v2/internal/dnsprovider/internal/retry"
	"lazy-balancer-v2/internal/dnsprovider/ownership"
)

// cfServer 是 Cloudflare REST API v4 的真实 HTTP 形态 mock（httptest 承载，
// 断言走请求序列/请求体/落库终态，不做响应字符串比对）。envelope 成败形态、
// errors[] 数组、404/7003 与 404/81044 的语义差异均按真实 API 契约建模。
type cfServer struct {
	srv *httptest.Server

	mu       sync.Mutex
	zones    map[string]string // zone 名 → zone id
	records  map[string][]cfRecord
	nextID   int
	requests []cfRequestLog

	verifyResult string // /user/tokens/verify 的 result.status（默认 active）
	verifyStatus int    // /user/tokens/verify 的 HTTP 状态（默认 200）
	post429First int    // 前 N 次 POST dns_records 返回 429
	overrides    map[string]cfResponse
	// scriptedRecordPages 非 nil 时按页下发预制包络体（页 i = 第 i-1 个元素，
	// 越界回退最后一个）——构造「中途短页 + total 显示仍有后续」的厂商观测
	// 形态（页间漂移/服务端单页容量波动）。
	scriptedRecordPages []string
}

type cfRecord struct {
	ID      string
	Name    string
	Type    string
	Content string
}

type cfRequestLog struct {
	method string
	path   string // 含 query，不含 /client/v4 前缀
	body   string
	auth   string
}

type cfResponse struct {
	status int
	body   string
}

func newCloudflareTestServer(t *testing.T) *cfServer {
	t.Helper()
	s := &cfServer{
		zones:        map[string]string{},
		records:      map[string][]cfRecord{},
		nextID:       1,
		verifyResult: "active",
		overrides:    map[string]cfResponse{},
	}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *cfServer) handle(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sub := strings.TrimPrefix(r.URL.Path, "/client/v4")
	path := sub
	if r.URL.RawQuery != "" {
		path = sub + "?" + r.URL.RawQuery
	}
	s.requests = append(s.requests, cfRequestLog{method: r.Method, path: path, body: string(body), auth: r.Header.Get("Authorization")})

	if resp, ok := s.overrides[r.Method+" "+sub]; ok {
		s.writeRaw(w, resp.status, resp.body)
		return
	}

	switch {
	case r.Method == http.MethodGet && sub == "/zones":
		name := dnsname.NormalizeName(r.URL.Query().Get("name"))
		results := []map[string]string{}
		for zoneName, id := range s.zones {
			if dnsname.NormalizeName(zoneName) == name {
				results = append(results, map[string]string{"id": id, "name": zoneName})
			}
		}
		s.writeEnvelope(w, http.StatusOK, mustJSON(results))
	case r.Method == http.MethodGet && strings.HasSuffix(sub, "/dns_records"):
		if s.scriptedRecordPages != nil {
			page := 1
			if v, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && v > 0 {
				page = v
			}
			index := page - 1
			if index >= len(s.scriptedRecordPages) {
				index = len(s.scriptedRecordPages) - 1
			}
			s.writeRaw(w, http.StatusOK, s.scriptedRecordPages[index])
			return
		}
		zoneID := zoneIDFromRecordsPath(sub)
		if !s.zoneExists(zoneID) {
			s.writeError(w, http.StatusNotFound, 7003, "No route for that URI")
			return
		}
		name := dnsname.NormalizeName(r.URL.Query().Get("name"))
		filtered := []map[string]string{}
		for _, record := range s.records[zoneID] {
			if record.Type != "TXT" || dnsname.NormalizeName(record.Name) != name {
				continue
			}
			filtered = append(filtered, map[string]string{"id": record.ID, "name": record.Name, "type": record.Type, "content": record.Content})
		}
		// 真实分页形态：per_page 切片 + result_info.total_count。
		perPage := 100
		if v, err := strconv.Atoi(r.URL.Query().Get("per_page")); err == nil && v > 0 {
			perPage = v
		}
		page := 1
		if v, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && v > 0 {
			page = v
		}
		start := (page - 1) * perPage
		pageOut := []map[string]string{}
		if start < len(filtered) {
			end := start + perPage
			if end > len(filtered) {
				end = len(filtered)
			}
			pageOut = filtered[start:end]
		}
		resultInfo := map[string]int{
			"page": page, "per_page": perPage, "count": len(pageOut), "total_count": len(filtered),
		}
		s.writeEnvelopeWithInfo(w, http.StatusOK, mustJSON(pageOut), resultInfo)
	case r.Method == http.MethodPost && strings.HasSuffix(sub, "/dns_records"):
		if s.post429First > 0 {
			s.post429First--
			s.writeError(w, http.StatusTooManyRequests, 429, "rate limited")
			return
		}
		zoneID := zoneIDFromRecordsPath(sub)
		if !s.zoneExists(zoneID) {
			s.writeError(w, http.StatusNotFound, 7003, "No route for that URI")
			return
		}
		var payload struct {
			Type    string `json:"type"`
			Name    string `json:"name"`
			Content string `json:"content"`
			TTL     int    `json:"ttl"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		record := cfRecord{ID: fmt.Sprintf("rec%d", s.nextID), Name: payload.Name, Type: payload.Type, Content: payload.Content}
		s.nextID++
		s.records[zoneID] = append(s.records[zoneID], record)
		s.writeEnvelope(w, http.StatusOK, mustJSON(map[string]string{"id": record.ID}))
	case r.Method == http.MethodDelete && strings.Count(sub, "/") == 4:
		parts := strings.Split(sub, "/") // ["", "zones", zid, "dns_records", rid]
		zoneID, recordID := parts[2], parts[4]
		kept := s.records[zoneID][:0]
		removed := false
		for _, record := range s.records[zoneID] {
			if record.ID == recordID {
				removed = true
				continue
			}
			kept = append(kept, record)
		}
		s.records[zoneID] = kept
		if !removed {
			s.writeError(w, http.StatusNotFound, 81044, "Record does not exist")
			return
		}
		s.writeEnvelope(w, http.StatusOK, mustJSON(map[string]string{"id": recordID}))
	case r.Method == http.MethodGet && sub == "/user/tokens/verify":
		status := s.verifyStatus
		if status == 0 {
			status = http.StatusOK
		}
		if status != http.StatusOK {
			s.writeError(w, status, 9109, "Invalid API Token")
			return
		}
		s.writeEnvelope(w, http.StatusOK, mustJSON(map[string]string{"id": "tok123", "status": s.verifyResult}))
	default:
		s.writeError(w, http.StatusNotFound, 7003, "No route for that URI")
	}
}

func zoneIDFromRecordsPath(sub string) string {
	// /zones/{id}/dns_records → {id}
	parts := strings.Split(sub, "/")
	return parts[2]
}

func (s *cfServer) zoneExists(zoneID string) bool {
	for _, id := range s.zones {
		if id == zoneID {
			return true
		}
	}
	return false
}

func (s *cfServer) writeEnvelope(w http.ResponseWriter, status int, resultJSON string) {
	s.writeRaw(w, status, fmt.Sprintf(`{"success":true,"errors":[],"messages":[],"result":%s}`, resultJSON))
}

// writeEnvelopeWithInfo 在包络中附带 result_info（列表端点的真实分页元数据）。
func (s *cfServer) writeEnvelopeWithInfo(w http.ResponseWriter, status int, resultJSON string, resultInfo map[string]int) {
	s.writeRaw(w, status, fmt.Sprintf(`{"success":true,"errors":[],"messages":[],"result":%s,"result_info":%s}`, resultJSON, mustJSON(resultInfo)))
}

func (s *cfServer) writeError(w http.ResponseWriter, status, code int, message string) {
	s.writeRaw(w, status, fmt.Sprintf(`{"success":false,"errors":[{"code":%d,"message":%q}],"messages":[],"result":null}`, code, message))
}

func (s *cfServer) writeRaw(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func mustJSON(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("marshal test fixture: %v", err))
	}
	return string(data)
}

func (s *cfServer) log() []cfRequestLog {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]cfRequestLog(nil), s.requests...)
}

func (s *cfServer) countRequests(method, pathPrefix string) int {
	count := 0
	for _, entry := range s.log() {
		if entry.method == method && strings.HasPrefix(entry.path, pathPrefix) {
			count++
		}
	}
	return count
}

func (s *cfServer) seedRecord(zoneID, id, name, content string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[zoneID] = append(s.records[zoneID], cfRecord{ID: id, Name: name, Type: "TXT", Content: content})
}

func (s *cfServer) remoteRecords(zoneID string) []cfRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]cfRecord(nil), s.records[zoneID]...)
}

// resetCloudflareCaches 清空进程级 zone 缓存（正/负缓存与 LRU 序）：
// 缓存键含账户摘要，测试互不命中，但容量/负 TTL 是全局态，逐用例复位隔离。
func resetCloudflareCaches(t *testing.T) {
	t.Helper()
	zoneIDCacheMu.Lock()
	zoneIDCache = map[string]string{}
	zoneIDNegativeCache = map[string]time.Time{}
	zoneIDCacheOrder = nil
	zoneIDCacheMu.Unlock()
}

func newCloudflareTestProvider(t *testing.T, token string, s *cfServer) *Provider {
	t.Helper()
	resetCloudflareCaches(t)
	p := New(token)
	p.endpoint = s.srv.URL + "/client/v4"
	// 退避压到毫秒级：429 重试语义保持真实（走 retry.Transport），墙钟快速。
	p.client.Transport = &retry.Transport{Base: http.DefaultTransport, InitialBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond}
	return p
}

func TestProvider_Present_createsChallengeRecordAndCachesZone(t *testing.T) {
	s := newCloudflareTestServer(t)
	s.zones["example.com"] = "z123"
	p := newCloudflareTestProvider(t, "cf-token", s)

	if err := p.Present(t.Context(), "Example.COM.", "_acme-challenge.www.Example.COM", "v1", 600); err != nil {
		t.Fatalf("Present: %v", err)
	}

	// 请求序列：zone 解析（GET /zones?name=，归一后精确查询）→ 幂等预查 →
	// POST 创建；创建体 ttl 固定 120（challengeRecordTTL，不透传调用方 600）。
	zoneLookups := s.countRequests(http.MethodGet, "/zones?name=example.com&")
	if zoneLookups != 1 {
		t.Fatalf("zone 解析请求数=%d, want 1", zoneLookups)
	}
	creates := 0
	var createBody struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Content string `json:"content"`
		TTL     int    `json:"ttl"`
	}
	for _, entry := range s.log() {
		if entry.method != http.MethodPost || !strings.HasPrefix(entry.path, "/zones/z123/dns_records") {
			continue
		}
		creates++
		if err := json.Unmarshal([]byte(entry.body), &createBody); err != nil {
			t.Fatalf("decode create body: %v", err)
		}
	}
	if creates != 1 {
		t.Fatalf("POST 创建请求数=%d, want 1", creates)
	}
	if createBody.Type != "TXT" || createBody.Name != "_acme-challenge.www.example.com" || createBody.Content != "v1" {
		t.Fatalf("create body=%+v, want TXT/_acme-challenge.www.example.com/v1", createBody)
	}
	if createBody.TTL != challengeRecordTTL {
		t.Fatalf("create ttl=%d, want %d（固定 TTL，不透传调用方 600）", createBody.TTL, challengeRecordTTL)
	}
	// 落库终态：TXT 在 z123 下存在。
	found := false
	for _, record := range s.remoteRecords("z123") {
		if record.Content == "v1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("TXT 未落到 Cloudflare: %+v", s.remoteRecords("z123"))
	}

	// 第二次 Present（另一挑战值）命中 zone 缓存：不再发起 GET /zones。
	if err := p.Present(t.Context(), "example.com", "_acme-challenge.example.com", "v2", 600); err != nil {
		t.Fatalf("second Present: %v", err)
	}
	if got := s.countRequests(http.MethodGet, "/zones?name=example.com&"); got != 1 {
		t.Fatalf("第二次 Present 后 zone 解析请求数=%d, want 1（进程内缓存命中）", got)
	}
}

// 幂等：同名同值的挑战 TXT 已存在（并发/重试重复 Present）时复用既有记录
// ID，不再重复创建——重复创建会让同名多值记录越积越多。
func TestProvider_Present_reusesExistingSameValueRecord(t *testing.T) {
	s := newCloudflareTestServer(t)
	s.zones["example.com"] = "z1"
	s.seedRecord("z1", "rec9", "_acme-challenge.example.com", "v-dup")
	p := newCloudflareTestProvider(t, "cf-token", s)

	if err := p.Present(t.Context(), "example.com", "_acme-challenge.example.com", "v-dup", 600); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if got := s.countRequests(http.MethodPost, "/zones/z1/dns_records"); got != 0 {
		t.Fatalf("同值已存在时 POST 创建数=%d, want 0（复用既有记录）", got)
	}
	p.mu.Lock()
	entries := p.owned["z1|_acme-challenge"]
	p.mu.Unlock()
	if len(entries) != 1 || entries[0].recordID != "rec9" || entries[0].value != "v-dup" {
		t.Fatalf("兜底表条目=%+v, want rec9/v-dup（复用 ID 入账）", entries)
	}

	// 不同值仍走创建：同值复用不抑制新值挑战。
	if err := p.Present(t.Context(), "example.com", "_acme-challenge.example.com", "v-new", 600); err != nil {
		t.Fatalf("Present new value: %v", err)
	}
	if got := s.countRequests(http.MethodPost, "/zones/z1/dns_records"); got != 1 {
		t.Fatalf("新值 POST 创建数=%d, want 1", got)
	}
}

// 缓存的 zone id 陈旧（zone 删除后重建）时 zone 侧调用报 404/7003——Present
// 必须作废缓存重解析一次并重试一次，创建落到新 zone id。
func TestProvider_Present_staleZoneIDSelfHeals(t *testing.T) {
	s := newCloudflareTestServer(t)
	s.zones["example.com"] = "z-new"
	p := newCloudflareTestProvider(t, "cf-token", s)
	resetCloudflareCaches(t)
	p.putZoneIDCache(p.zoneIDCacheKey("example.com"), "z-old")

	if err := p.Present(t.Context(), "example.com", "_acme-challenge.example.com", "v1", 600); err != nil {
		t.Fatalf("Present（陈旧缓存须自愈）: %v", err)
	}
	if s.countRequests(http.MethodGet, "/zones/z-old/dns_records") == 0 {
		t.Fatal("陈旧 zone id 的调用未发生（自愈前置缺失）")
	}
	// 自愈后解析并落到新 zone id。
	if got := s.countRequests(http.MethodPost, "/zones/z-new/dns_records"); got != 1 {
		t.Fatalf("新 zone id 创建数=%d, want 1", got)
	}
	if id, ok := p.getZoneIDCache(p.zoneIDCacheKey("example.com")); !ok || id != "z-new" {
		t.Fatalf("自愈后缓存=%q,%v, want z-new", id, ok)
	}
}

// 按值清理：账本自建记录删除（并移除账本条目）、并发挑战的近期他值记录不受
// 牵连；无账本候选时残余排空按值回收同名未追踪记录。
func TestProvider_CleanUpValue_deletesOwnedAndSweepsStale(t *testing.T) {
	s := newCloudflareTestServer(t)
	s.zones["example.com"] = "z1"
	p, err := NewPersistent("cf-token", t.TempDir())
	if err != nil {
		t.Fatalf("NewPersistent: %v", err)
	}
	p.endpoint = s.srv.URL + "/client/v4"
	p.client.Transport = &retry.Transport{Base: http.DefaultTransport, InitialBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond}
	resetCloudflareCaches(t)

	if err := p.Present(t.Context(), "example.com", "_acme-challenge.example.com", "vA", 600); err != nil {
		t.Fatalf("Present vA: %v", err)
	}
	// 模拟并发签发的另一值：账本 + 远端都在（近期，不受清理牵连）。
	if err := p.ownership.Add(ownership.Record{Provider: "cloudflare", Zone: "example.com", FQDN: "_acme-challenge.example.com", Value: "vB", RecordID: "recB", Account: p.account, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("seed ledger vB: %v", err)
	}
	s.seedRecord("z1", "recB", "_acme-challenge.example.com", "vB")
	// 无账本追踪的残余（账本条目退役/丢失形态）。
	s.seedRecord("z1", "recC", "_acme-challenge.example.com", "vC")

	if err := p.CleanUpValue(t.Context(), "example.com", "_acme-challenge.example.com.", "vA"); err != nil {
		t.Fatalf("CleanUpValue vA: %v", err)
	}
	remote := s.remoteRecords("z1")
	if len(remote) != 2 {
		t.Fatalf("远端记录=%+v, want recB/recC 幸存（recA 已删）", remote)
	}
	for _, record := range remote {
		if record.ID == "recA" {
			t.Fatalf("自建记录 recA 未被删除: %+v", remote)
		}
	}
	if records, _ := p.ownership.MatchingValue("cloudflare", "example.com", "_acme-challenge.example.com", "vA"); len(records) != 0 {
		t.Fatalf("vA 账本条目未移除: %+v", records)
	}
	if records, _ := p.ownership.MatchingValue("cloudflare", "example.com", "_acme-challenge.example.com", "vB"); len(records) != 1 {
		t.Fatalf("并发挑战 vB 账本条目被误删: %+v", records)
	}

	// 第二轮：清理 vC——无账本候选触发残余排空，按值回收 recC（recB 幸存）。
	if err := p.CleanUpValue(t.Context(), "example.com", "_acme-challenge.example.com.", "vC"); err != nil {
		t.Fatalf("CleanUpValue vC: %v", err)
	}
	remote = s.remoteRecords("z1")
	if len(remote) != 1 || remote[0].ID != "recB" {
		t.Fatalf("残余排空后远端记录=%+v, want 仅 recB 幸存", remote)
	}
}

// 按名清理（CleanUp）：删除本账户同名全部追踪记录；他账户条目按归属判定只
// 丢弃本地条目、不调用删除（防新账户按旧 ID 误删无关记录）。
func TestProvider_CleanUp_sparesForeignAccountRecords(t *testing.T) {
	s := newCloudflareTestServer(t)
	s.zones["example.com"] = "z1"
	p, err := NewPersistent("cf-token", t.TempDir())
	if err != nil {
		t.Fatalf("NewPersistent: %v", err)
	}
	p.endpoint = s.srv.URL + "/client/v4"
	p.client.Transport = &retry.Transport{Base: http.DefaultTransport, InitialBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond}
	resetCloudflareCaches(t)

	now := time.Now()
	if err := p.ownership.Add(ownership.Record{Provider: "cloudflare", Zone: "example.com", FQDN: "_acme-challenge.example.com", Value: "vA", RecordID: "recA", Account: p.account, CreatedAt: now}); err != nil {
		t.Fatalf("seed ledger recA: %v", err)
	}
	// 他账户（换凭据前）遗留条目：远端同名存在，但 recordID 属旧账户。
	if err := p.ownership.Add(ownership.Record{Provider: "cloudflare", Zone: "example.com", FQDN: "_acme-challenge.example.com", Value: "vB", RecordID: "recB", Account: "deadbeefdeadbeef", CreatedAt: now}); err != nil {
		t.Fatalf("seed ledger recB: %v", err)
	}
	s.seedRecord("z1", "recA", "_acme-challenge.example.com", "vA")
	s.seedRecord("z1", "recB", "_acme-challenge.example.com", "vB")

	if err := p.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com."); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	remote := s.remoteRecords("z1")
	if len(remote) != 1 || remote[0].ID != "recB" {
		t.Fatalf("远端记录=%+v, want 仅他账户 recB 幸存", remote)
	}
	if records, _ := p.ownership.Matching("cloudflare", "example.com", "_acme-challenge.example.com"); len(records) != 0 {
		t.Fatalf("账本条目未全部移除（含他账户丢弃）: %+v", records)
	}
}

// CountCleanupRecords 纯本地计数（零网络往返，接口契约）：账本 MatchingValue
// + 内存兜底表；账本读失败按至少 1 条计（预算宁大勿小）。
func TestProvider_CountCleanupRecords_isPurelyLocal(t *testing.T) {
	s := newCloudflareTestServer(t)
	s.zones["example.com"] = "z1"
	p, err := NewPersistent("cf-token", t.TempDir())
	if err != nil {
		t.Fatalf("NewPersistent: %v", err)
	}
	p.endpoint = s.srv.URL + "/client/v4"
	resetCloudflareCaches(t)

	if err := p.ownership.Add(ownership.Record{Provider: "cloudflare", Zone: "example.com", FQDN: "_acme-challenge.example.com", Value: "vA", RecordID: "recA", Account: p.account, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("seed ledger: %v", err)
	}
	// legacy 空值条目（按值清理 best-effort 命中）。
	if err := p.ownership.Add(ownership.Record{Provider: "cloudflare", Zone: "example.com", FQDN: "_acme-challenge.example.com", RecordID: "recLegacy"}); err != nil {
		t.Fatalf("seed legacy ledger: %v", err)
	}
	p.mu.Lock()
	p.owned["z1|_acme-challenge"] = append(p.owned["z1|_acme-challenge"], ownedRecord{recordID: "recF", value: "vA"})
	p.mu.Unlock()

	before := len(s.log())
	if got := p.CountCleanupRecords("example.com", "_acme-challenge.example.com.", "vA"); got != 3 {
		t.Fatalf("count=%d, want 3（账本 2 + 兜底 1）", got)
	}
	if after := len(s.log()); after != before {
		t.Fatalf("计数引发网络往返（%d → %d），违反纯本地契约", before, after)
	}

	// 账本读失败（文件损坏）→ max(兜底, 1)。
	if err := p.ownership.Add(ownership.Record{Provider: "cloudflare", Zone: "example.com", FQDN: "_acme-challenge.example.com", Value: "vA", RecordID: "recA2", Account: p.account, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("seed again: %v", err)
	}
	if got := p.CountCleanupRecords("example.com", "_acme-challenge.example.com.", "vA"); got < 1 {
		t.Fatalf("count=%d, want ≥1", got)
	}
}

func TestProvider_errorMapping(t *testing.T) {
	t.Run("invalid token 9109", func(t *testing.T) {
		s := newCloudflareTestServer(t)
		s.overrides["GET /zones"] = cfResponse{status: http.StatusForbidden, body: `{"success":false,"errors":[{"code":9109,"message":"Invalid API Token"}],"result":null}`}
		p := newCloudflareTestProvider(t, "cf-token", s)
		err := p.Present(t.Context(), "example.com", "_acme-challenge.example.com", "v", 600)
		if err == nil {
			t.Fatal("Token 无效必须失败")
		}
		if !strings.Contains(err.Error(), "Token 无效") {
			t.Fatalf("error=%v, want Token 无效文案", err)
		}
	})

	t.Run("403 permission denied", func(t *testing.T) {
		s := newCloudflareTestServer(t)
		s.overrides["GET /zones"] = cfResponse{status: http.StatusForbidden, body: `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}],"result":null}`}
		p := newCloudflareTestProvider(t, "cf-token", s)
		err := p.Present(t.Context(), "example.com", "_acme-challenge.example.com", "v", 600)
		if err == nil {
			t.Fatal("权限不足必须失败")
		}
		if !strings.Contains(err.Error(), "权限不足") || !strings.Contains(err.Error(), "Zone → DNS → Edit") {
			t.Fatalf("error=%v, want 权限不足文案点名所需权限", err)
		}
	})

	t.Run("zone 不存在", func(t *testing.T) {
		s := newCloudflareTestServer(t) // 无 zone
		p := newCloudflareTestProvider(t, "cf-token", s)
		err := p.Present(t.Context(), "missing.example", "_acme-challenge.missing.example", "v", 600)
		if err == nil || !strings.Contains(err.Error(), "不存在") || !strings.Contains(err.Error(), "Cloudflare: zone") || !strings.Contains(err.Error(), "请确认") {
			t.Fatalf("error=%v, want 统一文案（provider 名+资源+建议动作）", err)
		}
		// 负缓存：第二次不再发起 HTTP（请求数不增长）。
		before := len(s.log())
		if err := p.Present(t.Context(), "missing.example", "_acme-challenge.missing.example", "v", 600); err == nil {
			t.Fatal("第二次 Present 必须仍失败")
		}
		if after := len(s.log()); after != before {
			t.Fatalf("负缓存未生效（请求数 %d → %d）", before, after)
		}
	})

	t.Run("API errors[] 拼入错误消息", func(t *testing.T) {
		s := newCloudflareTestServer(t)
		s.zones["example.com"] = "z1"
		s.overrides["POST /zones/z1/dns_records"] = cfResponse{status: http.StatusBadRequest, body: `{"success":false,"errors":[{"code":1004,"message":"DNS Validation Error"},{"code":9102,"message":"X bad"}],"result":null}`}
		p := newCloudflareTestProvider(t, "cf-token", s)
		err := p.Present(t.Context(), "example.com", "_acme-challenge.example.com", "v", 600)
		if err == nil {
			t.Fatal("创建失败必须上抛")
		}
		if !strings.Contains(err.Error(), "code=1004") || !strings.Contains(err.Error(), "DNS Validation Error") || !strings.Contains(err.Error(), "code=9102") {
			t.Fatalf("error=%v, want errors[] 逐条拼入", err)
		}
	})

	t.Run("429 重试耗尽", func(t *testing.T) {
		s := newCloudflareTestServer(t)
		s.zones["example.com"] = "z1"
		s.overrides["POST /zones/z1/dns_records"] = cfResponse{status: http.StatusTooManyRequests, body: `{"success":false,"errors":[{"code":429,"message":"limit"}],"result":null}`}
		p := newCloudflareTestProvider(t, "cf-token", s)
		err := p.Present(t.Context(), "example.com", "_acme-challenge.example.com", "v", 600)
		if err == nil || !strings.Contains(err.Error(), "限流") {
			t.Fatalf("error=%v, want 限流文案", err)
		}
		if got := s.countRequests(http.MethodPost, "/zones/z1/dns_records"); got != 3 {
			t.Fatalf("POST 尝试数=%d, want 3（retry.Transport 3 次尝试）", got)
		}
	})

	t.Run("网络失败", func(t *testing.T) {
		closed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		closedURL := closed.URL
		closed.Close()
		resetCloudflareCaches(t)
		p := New("cf-token")
		p.endpoint = closedURL + "/client/v4"
		p.client.Transport = &retry.Transport{Base: http.DefaultTransport, InitialBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond}
		err := p.Present(t.Context(), "example.com", "_acme-challenge.example.com", "v", 600)
		if err == nil || !strings.Contains(err.Error(), "网络请求失败") {
			t.Fatalf("error=%v, want 网络请求失败文案", err)
		}
	})
}

// 限速友好：429 前两次由 retry.Transport 吸收退避重试，第三次成功——挑战
// 不因瞬时限流打挂。
func TestProvider_Present_retries429(t *testing.T) {
	s := newCloudflareTestServer(t)
	s.zones["example.com"] = "z1"
	s.post429First = 2
	p := newCloudflareTestProvider(t, "cf-token", s)

	if err := p.Present(t.Context(), "example.com", "_acme-challenge.example.com", "v", 600); err != nil {
		t.Fatalf("Present（429 重试后须成功）: %v", err)
	}
	if got := s.countRequests(http.MethodPost, "/zones/z1/dns_records"); got != 3 {
		t.Fatalf("POST 尝试数=%d, want 3", got)
	}
	if len(s.remoteRecords("z1")) != 1 {
		t.Fatalf("TXT 未落库: %+v", s.remoteRecords("z1"))
	}
}

// VerifyToken（GET /user/tokens/verify）：Bearer 头承载 Token；仅 active 状态
// 判通过；HTTP 层错误（403/9109）走同一中文映射。
func TestProvider_VerifyToken(t *testing.T) {
	t.Run("active", func(t *testing.T) {
		s := newCloudflareTestServer(t)
		p := newCloudflareTestProvider(t, "cf-token", s)
		if err := p.VerifyToken(t.Context()); err != nil {
			t.Fatalf("VerifyToken: %v", err)
		}
		for _, entry := range s.log() {
			if entry.method == http.MethodGet && strings.HasPrefix(entry.path, "/user/tokens/verify") {
				if entry.auth != "Bearer cf-token" {
					t.Fatalf("Authorization=%q, want Bearer cf-token", entry.auth)
				}
				return
			}
		}
		t.Fatal("verify 请求未发出")
	})

	t.Run("disabled status", func(t *testing.T) {
		s := newCloudflareTestServer(t)
		s.verifyResult = "disabled"
		p := newCloudflareTestProvider(t, "cf-token", s)
		err := p.VerifyToken(t.Context())
		if err == nil || !strings.Contains(err.Error(), "disabled") {
			t.Fatalf("error=%v, want 点名非 active 状态", err)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		s := newCloudflareTestServer(t)
		s.verifyStatus = http.StatusForbidden
		p := newCloudflareTestProvider(t, "cf-token", s)
		err := p.VerifyToken(t.Context())
		if err == nil || !strings.Contains(err.Error(), "Token 无效") {
			t.Fatalf("error=%v, want Token 无效文案", err)
		}
	})
}
