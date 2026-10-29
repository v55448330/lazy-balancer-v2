package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// 受信代理四字段（v2.3.x CDN 真实 IP 支持）：合法值写入成功并经 GET 回读；
// 网段过宽（</8 v4、</29 v6）与非法头名 400；预览端点同校验。
func TestUpdateConfig_trustedProxy_roundtrip(t *testing.T) {
	// Given
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)
	router.GET("/config", handler.GetConfig)

	body := `{"source":"caddy","trusted_proxy_enabled":true,"trusted_proxy_strict":false,` +
		`"trusted_proxy_ranges":"[\"203.0.113.0/24\",\"198.51.100.7\",\"2a06:98c0::/29\"]","trusted_proxy_headers":"[\"CF-Connecting-IP\",\"X-Forwarded-For\"]"}`
	request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}

	// Then GET 回读四字段（裸 IP 归一为 /32）
	getReq := httptest.NewRequest(http.MethodGet, "/config", nil)
	getResp := httptest.NewRecorder()
	router.ServeHTTP(getResp, getReq)
	if getResp.Code != http.StatusOK {
		t.Fatalf("get status=%d", getResp.Code)
	}
	var payload struct {
		Data struct {
			TrustedProxyEnabled bool   `json:"trusted_proxy_enabled"`
			TrustedProxyRanges  string `json:"trusted_proxy_ranges"`
			TrustedProxyHeaders string `json:"trusted_proxy_headers"`
			TrustedProxyStrict  bool   `json:"trusted_proxy_strict"`
		} `json:"data"`
	}
	if err := json.Unmarshal(getResp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !payload.Data.TrustedProxyEnabled || payload.Data.TrustedProxyStrict {
		t.Fatalf("enabled=%v strict=%v, want true/false", payload.Data.TrustedProxyEnabled, payload.Data.TrustedProxyStrict)
	}
	var ranges, headers []string
	if err := json.Unmarshal([]byte(payload.Data.TrustedProxyRanges), &ranges); err != nil {
		t.Fatalf("ranges not JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(payload.Data.TrustedProxyHeaders), &headers); err != nil {
		t.Fatalf("headers not JSON: %v", err)
	}
	if len(ranges) != 3 || ranges[0] != "203.0.113.0/24" || ranges[1] != "198.51.100.7/32" || ranges[2] != "2a06:98c0::/29" {
		t.Fatalf("ranges=%v, want [203.0.113.0/24 198.51.100.7/32 2a06:98c0::/29]", ranges)
	}
	if len(headers) != 2 || headers[0] != "CF-Connecting-IP" || headers[1] != "X-Forwarded-For" {
		t.Fatalf("headers=%v, want [CF-Connecting-IP X-Forwarded-For]", headers)
	}
}

func TestUpdateConfig_trustedProxy_rejectsOverwideRanges(t *testing.T) {
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)

	for _, tc := range []struct {
		name   string
		ranges string
	}{
		{"v4 /7", `["10.0.0.0/7"]`},
		{"v4 /0", `["0.0.0.0/0"]`},
		{"v6 /28", `["2001:db8::/28"]`},
		{"v6 /0", `["::/0"]`},
		// /8 恰好等于下限但覆盖整个 IPv4 空间——
		// 「信任全体 IPv4」形态必须拒绝；v4-mapped /96 同义（Is6 含 mapped，
		// 内嵌全零 v4 = 全体 IPv4）。
		{"v4 全空间 /8", `["0.0.0.0/8"]`},
		{"v4-mapped 全空间 /96", `["::ffff:0:0/96"]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"source":"caddy","trusted_proxy_enabled":true,"trusted_proxy_ranges":"` +
				strings.ReplaceAll(tc.ranges, `"`, `\"`) + `"}`
			request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), "过宽") {
				t.Fatalf("body=%s, want 含「过宽」", response.Body.String())
			}
		})
	}
}

// IPv4-mapped 主机位/位数变体必须与 canonical 形态同判据拒绝：
// ::ffff:0.0.0.1/96 与 ::ffff:0:0/96 是同一网段（网络位相同、仅主机位不同），
// 折算成等价 v4 恰好是 0.0.0.0/0——放行即等于信任任意来源的伪造头。
func TestUpdateConfig_trustedProxyRejectsMappedAllSpaceVariants(t *testing.T) {
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)

	for _, tc := range []struct{ name, value string }{
		{"mapped 主机位 /96", "::ffff:0.0.0.1/96"},
		{"mapped canonical /96", "::ffff:0.0.0.0/96"},
		{"mapped 全零缩写 /96", "::ffff:0:0/96"},
		{"mapped 任意主机位 /96", "::ffff:203.0.113.9/96"},
		{"mapped /104 等价 v4 /8", "::ffff:0.0.0.0/104"},
		{"mapped /97 等价 v4 /1", "::ffff:0.0.0.0/97"},
		{"mapped /95 覆盖整个 v4-mapped 空间", "::ffff:0.0.0.0/95"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"source":"caddy","trusted_proxy_enabled":true,"trusted_proxy_ranges":"[\"` + tc.value + `\"]"}`
			response := putConfig(t, router, body)
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "过宽") {
				t.Fatalf("%s: status=%d body=%s, want 400 含「过宽」", tc.value, response.Code, response.Body.String())
			}
		})
	}
}

// 引用名单通道与内联通道同宽度口径：名单条目写作 mapped 主机位变体同样 400；
// 合法 mapped 精确段（等价 v4 /24）不得被连带拒绝。
func TestUpdateConfig_trustedProxyRefsMappedRangesSameWidthGate(t *testing.T) {
	router := newTrustedProxyRefsRouter(t)
	allSpaceList := seedTrustedRefList(t, "mapped-allspace", `[{"value":"::ffff:0.0.0.1/96","remark":""}]`)
	body := fmt.Sprintf(`{"source":"caddy","trusted_proxy_ranges":"[]","trusted_proxy_range_refs":"[%d]"}`, allSpaceList)
	if rec := putConfig(t, router, body); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "过宽") {
		t.Fatalf("mapped 主机位变体必须 400 含「过宽」, got %d %s", rec.Code, rec.Body.String())
	}

	preciseList := seedTrustedRefList(t, "mapped-precise", `[{"value":"::ffff:198.51.100.0/120","remark":""}]`)
	body = fmt.Sprintf(`{"source":"caddy","trusted_proxy_ranges":"[]","trusted_proxy_range_refs":"[%d]"}`, preciseList)
	if rec := putConfig(t, router, body); rec.Code != http.StatusOK {
		t.Fatalf("合法 mapped 精确段必须 200, got %d %s", rec.Code, rec.Body.String())
	}
}

// 归一与去重同源：Masked 剥主机位、4in6 映射折成等价 v4 前缀；同一网段的
// 不同写法（192.0.2.129/24 与 192.0.2.0/24）只保留一条，精确语义不变。
func TestUpdateConfig_trustedProxyCanonicalizesHostBitsAndMappedForms(t *testing.T) {
	router := newTrustedProxyRefsRouter(t)
	body := `{"source":"caddy","trusted_proxy_enabled":true,` +
		`"trusted_proxy_ranges":"[\"192.0.2.129/24\",\"192.0.2.0/24\",\"::ffff:203.0.113.7/120\",\"::ffff:198.51.100.7\"]"}`
	if rec := putConfig(t, router, body); rec.Code != http.StatusOK {
		t.Fatalf("合法载荷必须 200, got %d %s", rec.Code, rec.Body.String())
	}
	var ranges string
	if err := db.DB.QueryRow(`SELECT COALESCE(trusted_proxy_ranges,'') FROM global_config WHERE id=1`).Scan(&ranges); err != nil {
		t.Fatal(err)
	}
	want := `["192.0.2.0/24","203.0.113.0/24","198.51.100.7/32"]`
	if ranges != want {
		t.Fatalf("ranges=%s, want %s（主机位剥离 + mapped 折等价 v4 + 同网段去重）", ranges, want)
	}
}

func TestUpdateConfig_trustedProxy_rejectsInvalidHeaders(t *testing.T) {
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)

	for _, headers := range []string{
		`["X Bad-Header"]`,
		`["X_Header"]`,
		`["` + strings.Repeat("a", 65) + `"]`,
	} {
		body := `{"source":"caddy","trusted_proxy_enabled":true,"trusted_proxy_headers":"` +
			strings.ReplaceAll(headers, `"`, `\"`) + `"}`
		request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("headers=%s status=%d body=%s, want 400", headers, response.Code, response.Body.String())
		}
	}
}

func TestNormalizeTrustedProxyHeadersDeduplicatesCaseInsensitivelyBeforeLimit(t *testing.T) {
	raw := `["CF-Connecting-IP","cf-connecting-ip","X-One","x-one","X-Two","x-two","X-Three","x-three","X-Four"]`
	normalized, err := normalizeTrustedProxyHeaders(raw)
	if err != nil {
		t.Fatalf("duplicates must be removed before applying the 8-entry limit: %v", err)
	}
	var headers []string
	if err := json.Unmarshal([]byte(normalized), &headers); err != nil {
		t.Fatal(err)
	}
	want := []string{"CF-Connecting-IP", "X-One", "X-Two", "X-Three", "X-Four"}
	if !reflect.DeepEqual(headers, want) {
		t.Fatalf("headers=%v, want %v", headers, want)
	}
}

func TestNormalizeTrustedProxyHeadersRejectsNineUniqueEntries(t *testing.T) {
	raw := `["X-One","X-Two","X-Three","X-Four","X-Five","X-Six","X-Seven","X-Eight","X-Nine"]`
	if _, err := normalizeTrustedProxyHeaders(raw); err == nil {
		t.Fatal("nine unique headers must still be rejected")
	}
}

// 预览端点与保存端点同校验（未过校验的载荷不得给出变更清单）。
func TestPreviewConfigUpdate_trustedProxy_sameValidation(t *testing.T) {
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/preview", handler.PreviewConfigUpdate)

	body := `{"source":"caddy","trusted_proxy_enabled":true,"trusted_proxy_ranges":"[\"0.0.0.0/0\"]"}`
	request := httptest.NewRequest(http.MethodPost, "/config/preview", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
}

// 预览端点与保存端点同口径：mapped 主机位变体同样 400（不得给出变更清单）。
func TestPreviewConfigUpdate_trustedProxyMappedAllSpaceVariant(t *testing.T) {
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/preview", handler.PreviewConfigUpdate)

	body := `{"source":"caddy","trusted_proxy_enabled":true,"trusted_proxy_ranges":"[\"::ffff:0.0.0.1/96\"]"}`
	request := httptest.NewRequest(http.MethodPost, "/config/preview", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "过宽") {
		t.Fatalf("status=%d body=%s, want 400 含「过宽」", response.Code, response.Body.String())
	}
}

// 总量门按规范化前缀集合计数（与渲染去重同源）：同一网段既内联又列在引用
// 名单时只计一次——按条目数累加会把实际展开集合没超限的合法载荷 400 拒绝。
func TestTrustedProxyTotalGate_countsDedupedPrefixes(t *testing.T) {
	h := newBackupTestHandlers(t)
	_ = h
	inlineValues := make([]string, 0, 1501)
	for i := 0; i < 1500; i++ {
		inlineValues = append(inlineValues, fmt.Sprintf("10.1.%d.%d", i/256, i%256))
	}
	entries := make([]models.IPListEntry, 0, 1000)
	for i := 0; i < 500; i++ { // 前 500 条与内联完全重叠
		entries = append(entries, models.IPListEntry{Value: fmt.Sprintf("10.1.%d.%d", i/256, i%256)})
	}
	for i := 0; i < 500; i++ {
		entries = append(entries, models.IPListEntry{Value: fmt.Sprintf("10.2.%d.%d", i/256, i%256)})
	}
	encoded, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (id, name, entries, system) VALUES (321, 'overlap-cdn', ?, 0)`, string(encoded)); err != nil {
		t.Fatalf("seed list: %v", err)
	}

	_, refKeys, err := normalizeTrustedProxyRangeRefsWithSource("[321]", trustedProxyBackupSource{})
	if err != nil {
		t.Fatalf("normalize refs: %v", err)
	}
	inlineKeys := trustedProxyPrefixKeys(inlineValues)
	if got := len(inlineKeys) + len(refKeys); got != 2500 {
		t.Fatalf("条目和=%d, want 2500（前置：确有 500 条重叠）", got)
	}
	if err := trustedProxyTotalGate(inlineKeys, refKeys); err != nil {
		t.Fatalf("去重后合计 2000 必须放行（当前按条目累加=2500 的假拒绝）: %v", err)
	}
	inlineKeys["10.9.9.9/32"] = struct{}{}
	if err := trustedProxyTotalGate(inlineKeys, refKeys); err == nil {
		t.Fatal("去重后合计 2001 必须拒绝")
	}
}
