package handlers

// 大屏本站坐标「自动检测」（v4 规格④）：显式用户触发（无后台轮询）出站获取
// 公网 IP（api.ipify.org 纯文本，5s 超时，直连——GitHub 加速代理仅支持 GitHub
// 路径，ipify 非其代理范围）→ 本地 ip2region 归属地 → 质心表换算经纬度。
// 失败友好报错；回填由前端执行，写侧仍走 PUT /config 既有校验。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func newSiteDetectRouter(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	handler := &Handlers{}
	router := gin.New()
	router.POST("/security/overview/threat-screen/site-detect", handler.DetectThreatScreenSite)
	return router
}

func TestDetectThreatScreenSite_fetchFailureFriendlyError(t *testing.T) {
	// Given: 出站获取公网 IP 失败（离线/超时）
	origFetch := fetchPublicIP
	fetchPublicIP = func() (string, string, error) { return "", "", os.ErrDeadlineExceeded }
	t.Cleanup(func() { fetchPublicIP = origFetch })
	router := newSiteDetectRouter(t)

	// When
	recorder := postJSON(t, router, "/security/overview/threat-screen/site-detect", nil)

	// Then: 502 + 友好文案（不泄漏错误细节，不部分回填）
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s, want 502", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "公网 IP 获取失败") {
		t.Fatalf("body=%s, want friendly message", recorder.Body.String())
	}
}

func TestDetectThreatScreenSite_unresolvableLocationFriendlyError(t *testing.T) {
	// Given: 公网 IP 获取成功，但归属地无法定位（测试环境无 xdb——生产对应
	// 库缺失/未知网段）
	origFetch := fetchPublicIP
	fetchPublicIP = func() (string, string, error) { return "203.0.114.99", "test.source", nil }
	t.Cleanup(func() { fetchPublicIP = origFetch })
	router := newSiteDetectRouter(t)

	// When
	recorder := postJSON(t, router, "/security/overview/threat-screen/site-detect", nil)

	// Then: 422 + 手动填写指引（保留手动路径语义）
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d body=%s, want 422", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "手动填写") {
		t.Fatalf("body=%s, want manual-fill guidance", recorder.Body.String())
	}
}

func TestDetectThreatScreenSite_successReturnsCoords(t *testing.T) {
	// Given: 出站与定位均成功（注入缝：境内 IP→上海质心）
	origFetch, origLocate := fetchPublicIP, locateSiteCoords
	fetchPublicIP = func() (string, string, error) { return "116.9.130.80", "test.source", nil }
	locateSiteCoords = func(ip string) (lat, lon float64, location string, ok bool) {
		return 31.23, 121.47, "中国·上海·上海·电信", true
	}
	t.Cleanup(func() { fetchPublicIP, locateSiteCoords = origFetch, origLocate })
	router := newSiteDetectRouter(t)

	// When
	recorder := postJSON(t, router, "/security/overview/threat-screen/site-detect", nil)

	// Then: 200 + 坐标与归属地（前端回填表单字段，保存仍走 PUT /config 校验）
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Code int `json:"code"`
		Data struct {
			IP       string  `json:"ip"`
			Location string  `json:"location"`
			Lat      float64 `json:"lat"`
			Lon      float64 `json:"lon"`
			Source   string  `json:"source"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	// envelope 契约钉住：code=0 + data 包装（裸 JSON 会被前端 request 封装判
	// 「响应缺失」误走失败分支——v5 实测修复回归）
	if payload.Code != 0 {
		t.Fatalf("code=%d, want 0（APIResponse 包装）", payload.Code)
	}
	if payload.Data.IP != "116.9.130.80" || payload.Data.Location != "中国·上海·上海·电信" || payload.Data.Lat != 31.23 || payload.Data.Lon != 121.47 {
		t.Fatalf("data=%+v, want ip/location/lat/lon 齐备", payload.Data)
	}
	if payload.Data.Source != "test.source" {
		t.Errorf("source=%q, want 源名随响应披露", payload.Data.Source)
	}
}

func TestThreatScreenCentroids_parityWithFrontendTables(t *testing.T) {
	// Given: 后端质心表由前端 TS 表构建期派生（同源生成、提交后仍可能一侧
	// 单独改动）——parity 绊线解析 TS 源断言键覆盖（geoip_mirror_tables_test
	// 同族：跨语言源文本绊线）。
	countryTS, err := os.ReadFile("../../web/src/utils/countryCentroids.ts")
	if err != nil {
		t.Fatalf("read countryCentroids.ts: %v", err)
	}
	provinceTS, err := os.ReadFile("../../web/src/utils/chinaProvinces.ts")
	if err != nil {
		t.Fatalf("read chinaProvinces.ts: %v", err)
	}
	keyRe := regexp.MustCompile(`"([^"]+)": \[`)
	for _, m := range keyRe.FindAllStringSubmatch(string(countryTS), -1) {
		if _, ok := threatScreenCountryCentroids[m[1]]; !ok {
			t.Errorf("国家 %q 在前端质心表存在但后端 threatScreenCountryCentroids 缺失——重跑派生生成", m[1])
		}
	}
	provRe := regexp.MustCompile(`short: "([^"]+)"`)
	for _, m := range provRe.FindAllStringSubmatch(string(provinceTS), -1) {
		if _, ok := threatScreenProvinceCentroids[m[1]]; !ok {
			t.Errorf("省份短名 %q 在前端质心表存在但后端 threatScreenProvinceCentroids 缺失——重跑派生生成", m[1])
		}
	}
	// 反向：后端表不应有前端不存在的一侧单改键
	for key := range threatScreenProvinceCentroids {
		if !strings.Contains(string(provinceTS), `short: "`+key+`"`) {
			t.Errorf("省份短名 %q 仅存在于后端表（前端 chinaProvinces.ts 已无）——两侧漂移", key)
		}
	}
}

func TestFetchIPFromSource_multiLineExtraction(t *testing.T) {
	// Given: myip.ipip.net / cip.cc 形态的多行文本（IP 嵌在正文中）
	client := &http.Client{Timeout: time.Second}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("kind") {
		case "ipip":
			_, _ = w.Write([]byte("当前 IP：123.139.172.192  来自于：中国 陕西 西安  联通\n"))
		case "cip":
			_, _ = w.Write([]byte("IP\t: 223.104.3.11\n地址\t: 中国 广东 深圳\n"))
		default:
			_, _ = w.Write([]byte("not-an-ip\n"))
		}
	}))
	t.Cleanup(srv.Close)

	// When/Then: 正则提取首个 IPv4；非法文本报错
	if ip, err := fetchIPFromSource(client, ipSource{name: "ipip", url: srv.URL + "?kind=ipip", multiLine: true}); err != nil || ip != "123.139.172.192" {
		t.Fatalf("ipip extract=%q err=%v, want 123.139.172.192", ip, err)
	}
	if ip, err := fetchIPFromSource(client, ipSource{name: "cip", url: srv.URL + "?kind=cip", multiLine: true}); err != nil || ip != "223.104.3.11" {
		t.Fatalf("cip extract=%q err=%v, want 223.104.3.11", ip, err)
	}
	if _, err := fetchIPFromSource(client, ipSource{name: "bad", url: srv.URL + "?kind=bad", multiLine: true}); err == nil {
		t.Fatalf("invalid text should error")
	}
}
