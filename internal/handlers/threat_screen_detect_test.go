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

// U13-09（第 78 轮）：键提取正则容忍前端代码风格差异——此前依赖 TS 恰好写作
// `"键": [`（双引号+单空格），Prettier 改单引号/换行/单行对象后匹配数=0 而
// 测试仍然通过（空转）。`\s*` 覆盖冒号与数组括号间的任意空白/换行。
var (
	countryCentroidKeyRe = regexp.MustCompile(`["']([^"']+)["']\s*:\s*\[`)
	provinceShortKeyRe   = regexp.MustCompile(`short\s*:\s*["']([^"']+)["']`)
)

func extractTableKeys(re *regexp.Regexp, source []byte) []string {
	matches := re.FindAllStringSubmatch(string(source), -1)
	keys := make([]string, 0, len(matches))
	for _, m := range matches {
		keys = append(keys, m[1])
	}
	return keys
}

func TestThreatScreenCentroids_parityWithFrontendTables(t *testing.T) {
	// Given: 后端质心表由前端 TS 表构建期派生（同源生成、提交后仍可能一侧
	// 单独改动）——parity 绊线解析 TS 源断言键集合双向相等。
	countryTS, err := os.ReadFile("../../web/src/utils/countryCentroids.ts")
	if err != nil {
		t.Fatalf("read countryCentroids.ts: %v", err)
	}
	provinceTS, err := os.ReadFile("../../web/src/utils/chinaProvinces.ts")
	if err != nil {
		t.Fatalf("read chinaProvinces.ts: %v", err)
	}

	countryKeys := extractTableKeys(countryCentroidKeyRe, countryTS)
	// 下限：匹配数必须等于后端键数——格式漂移导致零匹配/漏匹配即红（防空转）。
	if len(countryKeys) != len(threatScreenCountryCentroids) {
		t.Fatalf("前端国家键解析数=%d，后端威胁大屏国家质心表=%d，want 相等（解析正则失配或两侧漂移）", len(countryKeys), len(threatScreenCountryCentroids))
	}
	countrySet := make(map[string]bool, len(countryKeys))
	for _, key := range countryKeys {
		countrySet[key] = true
		if _, ok := threatScreenCountryCentroids[key]; !ok {
			t.Errorf("国家 %q 在前端质心表存在但后端 threatScreenCountryCentroids 缺失——重跑派生生成", key)
		}
	}
	// 反向：后端多出的国家键同样漂移（此前只检查省份）。
	for key := range threatScreenCountryCentroids {
		if !countrySet[key] {
			t.Errorf("国家 %q 仅存在于后端 threatScreenCountryCentroids（前端 countryCentroids.ts 已无）——两侧漂移", key)
		}
	}

	provinceKeys := extractTableKeys(provinceShortKeyRe, provinceTS)
	if len(provinceKeys) != len(threatScreenProvinceCentroids) {
		t.Fatalf("前端省份短名解析数=%d，后端威胁大屏省份质心表=%d，want 相等（解析正则失配或两侧漂移）", len(provinceKeys), len(threatScreenProvinceCentroids))
	}
	provinceSet := make(map[string]bool, len(provinceKeys))
	for _, key := range provinceKeys {
		provinceSet[key] = true
		if _, ok := threatScreenProvinceCentroids[key]; !ok {
			t.Errorf("省份短名 %q 在前端质心表存在但后端 threatScreenProvinceCentroids 缺失——重跑派生生成", key)
		}
	}
	for key := range threatScreenProvinceCentroids {
		if !provinceSet[key] {
			t.Errorf("省份短名 %q 仅存在于后端表（前端 chinaProvinces.ts 已无）——两侧漂移", key)
		}
	}
}

// 正则自检：单引号 / 冒号与括号间空白换行 / 单行对象三种前端风格都必须命中，
// 防后续「简化」回退为依赖双引号紧邻形态的空转正则。
func TestThreatScreenCentroidKeyRegex_toleratesFormattingVariants(t *testing.T) {
	cases := []struct {
		name    string
		source  string
		want    []string
		pattern *regexp.Regexp
	}{
		{name: "双引号单行", source: `  "不丹": [90.5, 27.5],`, want: []string{"不丹"}, pattern: countryCentroidKeyRe},
		{name: "单引号带空白", source: `  '不丹' :  [90.5, 27.5],`, want: []string{"不丹"}, pattern: countryCentroidKeyRe},
		{name: "冒号后换行", source: "  \"不丹\"\n  : [90.5, 27.5],", want: []string{"不丹"}, pattern: countryCentroidKeyRe},
		{name: "省份单引号", source: `{ name: '北京市', short: '北京', centroid: [116.42, 40.19] }`, want: []string{"北京"}, pattern: provinceShortKeyRe},
		{name: "省份空白", source: `{ short :   "广东" }`, want: []string{"广东"}, pattern: provinceShortKeyRe},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractTableKeys(tc.pattern, []byte(tc.source))
			if len(got) != len(tc.want) {
				t.Fatalf("keys=%v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("keys=%v, want %v", got, tc.want)
				}
			}
		})
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
