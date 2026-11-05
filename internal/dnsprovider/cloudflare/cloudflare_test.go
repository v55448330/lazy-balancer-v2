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

	verifyResult       string // /user/tokens/verify 的 result.status（默认 active）
	verifyStatus       int    // /user/tokens/verify 的 HTTP 状态（默认 200）
	verifyErrorCode    int    // verify 失败体的错误码（默认 9109）
	verifyErrorMessage string // verify 失败体的错误消息（默认 Invalid API Token；权限类错误形态需配 10000+Authentication error）
	post429First       int    // 前 N 次 POST dns_records 返回 429
	// accounts 是 GET /accounts 可见账户 id 列表（nil=空列表，列表恒 200；
	// accountsStatus 非 0/200 时按该状态返回错误体——5xx 上抛形态注入）。
	accounts       []string
	accountsStatus int
	// accountVerify/accountVerifyStatus 是 /accounts/{id}/tokens/verify 的
	// 逐账户形态：status 缺省 active；statusHTTP 非 0/200 时按该状态返回
	// 错误体（token 对该账户无验证权限的真实形态）。
	accountVerify       map[string]string
	accountVerifyStatus map[string]int
	overrides           map[string]cfResponse
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
	case r.Method == http.MethodGet && sub == "/accounts":
		if s.accountsStatus != 0 && s.accountsStatus != http.StatusOK {
			s.writeError(w, s.accountsStatus, 1000, "internal server error")
			return
		}
		// 真实分页形态：per_page 切片 + result_info.total_count（与
		// dns_records 列表同构）。
		perPage := 50
		if v, err := strconv.Atoi(r.URL.Query().Get("per_page")); err == nil && v > 0 {
			perPage = v
		}
		page := 1
		if v, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && v > 0 {
			page = v
		}
		start := (page - 1) * perPage
		pageOut := []map[string]string{}
		if start < len(s.accounts) {
			end := start + perPage
			if end > len(s.accounts) {
				end = len(s.accounts)
			}
			for _, id := range s.accounts[start:end] {
				pageOut = append(pageOut, map[string]string{"id": id, "name": "acct-" + id})
			}
		}
		resultInfo := map[string]int{"page": page, "per_page": perPage, "count": len(pageOut), "total_count": len(s.accounts)}
		s.writeEnvelopeWithInfo(w, http.StatusOK, mustJSON(pageOut), resultInfo)
	case r.Method == http.MethodGet && strings.HasPrefix(sub, "/accounts/") && strings.HasSuffix(sub, "/tokens/verify"):
		accountID := strings.Split(strings.TrimPrefix(sub, "/accounts/"), "/")[0]
		if status, ok := s.accountVerifyStatus[accountID]; ok && status != http.StatusOK {
			s.writeError(w, status, 1000, "Invalid API Token")
			return
		}
		resultStatus := s.accountVerify[accountID]
		if resultStatus == "" {
			resultStatus = "active"
		}
		s.writeEnvelope(w, http.StatusOK, mustJSON(map[string]string{"id": "tok_" + accountID, "status": resultStatus}))
	case r.Method == http.MethodGet && sub == "/user/tokens/verify":
		status := s.verifyStatus
		if status == 0 {
			status = http.StatusOK
		}
		if status != http.StatusOK {
			code := s.verifyErrorCode
			if code == 0 {
				code = 9109
			}
			message := s.verifyErrorMessage
			if message == "" {
				message = "Invalid API Token"
			}
			s.writeError(w, status, code, message)
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

// countRequestsExact 按「方法+完整路径（含 query）」精确计数：/accounts 与
// /accounts/{id}/tokens/verify 共享前缀，前缀计数无法区分两者。
func (s *cfServer) countRequestsExact(method, path string) int {
	count := 0
	for _, entry := range s.log() {
		if entry.method == method && entry.path == path {
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
		// 9109 属「值无效」信号：除用户级文案外，还必须触发账户级验证尝试
		// （账户自有 Token 的用户级形态即 invalid——harness 默认 /accounts
		// 为空列表，终态是含指引与原始错误的账户级文案）。
		if err == nil || !strings.Contains(err.Error(), "Token 无效") {
			t.Fatalf("error=%v, want Token 无效文案", err)
		}
		// 枚举请求带分页 query，前缀 "/accounts?" 不会命中
		// /accounts/{id}/tokens/verify。
		if got := s.countRequests(http.MethodGet, "/accounts?"); got != 1 {
			t.Fatalf("invalid token 须触发一次 GET /accounts, got %d", got)
		}
	})
}

// 账户自有 Token（Account API Token，cfat_ 前缀）打用户级 verify 端点返回
// 400 code=1000 Invalid API Token（官方 Token formats：cfat_ 的 verify 端点
// 是 /accounts/{account_id}/tokens/verify）。VerifyToken 须两级尝试：用户级
// invalid 失败后枚举 /accounts 逐账户验证，任一 active 即通过。
func TestProvider_VerifyToken_AccountOwnedToken(t *testing.T) {
	const guidance = "账户自有 Token 需在账户级验证，且账户可见性取决于 token 权限"

	t.Run("account token verifies via account level", func(t *testing.T) {
		s := newCloudflareTestServer(t)
		s.verifyStatus = http.StatusBadRequest
		s.verifyErrorCode = 1000
		s.accounts = []string{"acc1"}
		p := newCloudflareTestProvider(t, "cfat_"+strings.Repeat("a", 40), s)
		if err := p.VerifyToken(t.Context()); err != nil {
			t.Fatalf("VerifyToken（账户级 active 须通过）: %v", err)
		}
		for _, entry := range s.log() {
			switch {
			case entry.method == http.MethodGet && entry.path == "/user/tokens/verify":
				if entry.auth != "Bearer "+p.apiToken {
					t.Fatalf("用户级 Authorization=%q", entry.auth)
				}
			case entry.method == http.MethodGet && strings.HasPrefix(entry.path, "/accounts"):
				if entry.auth != "Bearer "+p.apiToken {
					t.Fatalf("账户级 Authorization=%q, want 同 token Bearer", entry.auth)
				}
			}
		}
		if got := s.countRequests(http.MethodGet, "/accounts?"); got != 1 {
			t.Fatalf("GET /accounts 次数=%d, want 1", got)
		}
		if got := s.countRequestsExact(http.MethodGet, "/accounts/acc1/tokens/verify"); got != 1 {
			t.Fatalf("GET /accounts/acc1/tokens/verify 次数=%d, want 1", got)
		}
	})

	t.Run("user token path unchanged", func(t *testing.T) {
		s := newCloudflareTestServer(t)
		p := newCloudflareTestProvider(t, "cfut_"+strings.Repeat("a", 40), s)
		if err := p.VerifyToken(t.Context()); err != nil {
			t.Fatalf("VerifyToken: %v", err)
		}
		if s.countRequests(http.MethodGet, "/accounts") != 0 {
			t.Fatal("用户级 active 不得触发 /accounts 枚举")
		}
	})

	t.Run("any active account passes", func(t *testing.T) {
		s := newCloudflareTestServer(t)
		s.verifyStatus = http.StatusBadRequest
		s.verifyErrorCode = 1000
		s.accounts = []string{"acc1", "acc2"}
		s.accountVerify = map[string]string{"acc1": "disabled"}
		s.accountVerifyStatus = map[string]int{"acc2": http.StatusOK}
		p := newCloudflareTestProvider(t, "cfat_"+strings.Repeat("a", 40), s)
		if err := p.VerifyToken(t.Context()); err != nil {
			t.Fatalf("VerifyToken（acc2 active 须通过）: %v", err)
		}
	})

	t.Run("verify forbidden on one account continues", func(t *testing.T) {
		s := newCloudflareTestServer(t)
		s.verifyStatus = http.StatusBadRequest
		s.verifyErrorCode = 1000
		s.accounts = []string{"acc1", "acc2"}
		s.accountVerifyStatus = map[string]int{"acc1": http.StatusForbidden}
		p := newCloudflareTestProvider(t, "cfat_"+strings.Repeat("a", 40), s)
		if err := p.VerifyToken(t.Context()); err != nil {
			t.Fatalf("VerifyToken（acc1 403 后 acc2 active 须通过）: %v", err)
		}
	})

	t.Run("all accounts fail reports guidance", func(t *testing.T) {
		s := newCloudflareTestServer(t)
		s.verifyStatus = http.StatusBadRequest
		s.verifyErrorCode = 1000
		s.accounts = []string{"acc1"}
		s.accountVerify = map[string]string{"acc1": "disabled"}
		p := newCloudflareTestProvider(t, "cfat_"+strings.Repeat("a", 40), s)
		err := p.VerifyToken(t.Context())
		if err == nil || !strings.Contains(err.Error(), guidance) {
			t.Fatalf("error=%v, want 账户自有指引", err)
		}
	})

	t.Run("zero visible accounts reports guidance", func(t *testing.T) {
		s := newCloudflareTestServer(t)
		s.verifyStatus = http.StatusBadRequest
		s.verifyErrorCode = 1000
		p := newCloudflareTestProvider(t, "cfat_"+strings.Repeat("a", 40), s)
		err := p.VerifyToken(t.Context())
		if err == nil || !strings.Contains(err.Error(), guidance) {
			t.Fatalf("error=%v, want 账户自有指引", err)
		}
	})

	t.Run("accounts 5xx propagates", func(t *testing.T) {
		s := newCloudflareTestServer(t)
		s.verifyStatus = http.StatusBadRequest
		s.verifyErrorCode = 1000
		s.accountsStatus = http.StatusInternalServerError
		p := newCloudflareTestProvider(t, "cfat_"+strings.Repeat("a", 40), s)
		err := p.VerifyToken(t.Context())
		if err == nil {
			t.Fatal("/accounts 5xx 不得吞错")
		}
		if strings.Contains(err.Error(), guidance) {
			t.Fatalf("/accounts 枚举失败须照旧上抛而非报账户级终态: %v", err)
		}
		if !strings.Contains(err.Error(), "500") {
			t.Fatalf("error=%v, want 保留 HTTP 500 形态", err)
		}
	})

	t.Run("permission error does not trigger account attempt", func(t *testing.T) {
		s := newCloudflareTestServer(t)
		// 真实权限不足形态：code=10000 + "Authentication error"（非
		// invalid-token 信号，不得触发账户级尝试）。
		s.verifyStatus = http.StatusForbidden
		s.verifyErrorCode = 10000
		s.verifyErrorMessage = "Authentication error"
		p := newCloudflareTestProvider(t, "cf-token", s)
		err := p.VerifyToken(t.Context())
		if err == nil || !strings.Contains(err.Error(), "权限不足") {
			t.Fatalf("error=%v, want 权限不足文案", err)
		}
		if s.countRequests(http.MethodGet, "/accounts") != 0 {
			t.Fatal("非 invalid 错误不得触发账户级尝试")
		}
	})
}

// tokenDiagnostic 前缀识别：cfut_/cfat_/cfk_ 三类官方前缀给出 Token 形态
// 判定（脱敏：只含前缀与形态，不含凭据内容）。
func TestTokenDiagnostic_prefixRecognition(t *testing.T) {
	cases := []struct {
		token string
		want  string
	}{
		{"cfut_" + strings.Repeat("a", 40), "用户 API Token"},
		{"cfat_" + strings.Repeat("a", 40), "账户自有 API Token（账户级验证）"},
		{"cfk_" + strings.Repeat("a", 34), "Global API Key（不可用于 Bearer）"},
	}
	for _, tc := range cases {
		diag := tokenDiagnostic(tc.token)
		if !strings.Contains(diag, tc.want) {
			t.Fatalf("tokenDiagnostic(%q…)=%q, want 含 %q", tc.token[:5], diag, tc.want)
		}
		if strings.Contains(diag, strings.Repeat("a", 10)) {
			t.Fatalf("诊断不得泄露凭据内容: %q", diag)
		}
	}
}

func TestCloudflare_invalidTokenCode1000ShowsChecklist(t *testing.T) {
	// code=1000（值形态无效，如粘贴 Token ID/Global Key）必须给出可操作的
	// 排查清单，而非笼统「无效或已被撤销」。code=1000 属「值无效」信号，
	// 同时触发账户级验证尝试（账户自有 Token 的用户级形态即 code=1000）：
	// harness 默认 /accounts 为空列表，终态文案=账户自有指引+用户级原始
	// 错误（排查清单随原始错误保留）。
	s := newCloudflareTestServer(t)
	s.verifyResult = "active"
	s.verifyStatus = http.StatusBadRequest
	s.verifyErrorCode = 1000
	p := newCloudflareTestProvider(t, "not-a-real-token", s)
	err := p.VerifyToken(t.Context())
	if err == nil {
		t.Fatal("want error")
	}
	msg := err.Error()
	for _, want := range []string{"code=1000", "Token ID", "Global API Key", "粘贴值长度 16 字符", "账户自有 Token 需在账户级验证"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("消息缺 %q: %s", want, msg)
		}
	}
	if strings.Contains(msg, "not-a-real-token") {
		t.Fatalf("诊断不得泄露凭据内容: %s", msg)
	}
}
