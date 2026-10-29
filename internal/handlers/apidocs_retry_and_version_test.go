package handlers

// 文档元数据的三条绊线：
//  ① DELETE 的重试语义必须按方法归族——漏登记会掉进「不可安全重试：重复调用
//     可能创建新资源」，而 DELETE 不创建资源；旧实现靠 switch 逐条枚举，新增
//     DELETE 端点静默掉进通用兜底文案。
//  ② 导入窗口 409 的文案必须按方法派生——GET 被拦的是导出/下发，写端点才是
//     「拒绝写」；此前固定文案把 4 条只读端点描述成拒绝写。
//  ③ 示例里的产品版本必须是占位符——硬编码版本随发版立即过期，且不会有人发现。

import (
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/apipath"
)

const (
	apiDocDeleteRetry           = "不可安全重试：首次删除成功，重复调用返回 404。"
	apiDocDeleteIdempotentRetry = "可安全重试："
)

// 分类穷尽性：每条 DELETE 路由要么拿删除族默认文案，要么在幂等删除白名单
// 登记（后者要有 handler 事实支撑：重复调用返回成功而非 404）。默认分支不得
// 吞未登记路由。
func TestAPIDocRoutes_deleteRetrySemanticsExhaustive(t *testing.T) {
	deletes := 0
	for _, route := range apiDocRoutes {
		if route.Method != http.MethodDelete {
			continue
		}
		deletes++
		key := route.Method + " " + route.Path
		description := operationDescription(route)
		if strings.Contains(description, "可能创建新资源") {
			t.Errorf("%s 重试文案仍称「可能创建新资源」——DELETE 不创建资源: %q", key, description)
			continue
		}
		if strings.Contains(description, apiDocDeleteRetry) {
			if _, idempotent := idempotentDeleteDocRoutes[key]; idempotent {
				t.Errorf("%s 已在幂等删除白名单，却使用资源型删除文案（404 契约）: %q", key, description)
			}
			continue
		}
		if _, idempotent := idempotentDeleteDocRoutes[key]; idempotent {
			if !strings.Contains(description, apiDocDeleteIdempotentRetry) {
				t.Errorf("%s 登记为幂等删除，文案必须声明可安全重试: %q", key, description)
			}
			continue
		}
		t.Errorf("%s 未归入删除族且未登记幂等白名单（掉进通用兜底文案）: %q", key, description)
	}
	if deletes == 0 {
		t.Fatal("apiDocRoutes 中没有任何 DELETE 路由——绊线的输入面已消失")
	}
	if len(idempotentDeleteDocRoutes) == 0 {
		t.Fatal("幂等删除白名单为空——分类失去对照面")
	}
}

// 写方法（POST/PUT/PATCH/DELETE）的重试语义穷尽性：每条写端点的文案必须落在
// 已登记的重试语义词上（新增任意文案即红），且
//   - PUT/PATCH 不得声称「可能创建新资源」（方法派生幂等，除非登记为特例）；
//   - 携带 POST 兜底创建类文案的端点必须登记进 createLikeWriteDocRoutes
//     （默认分支不得吞未登记路由）；
//   - 登记表不得残留已不存在/已改类的端点。
func TestAPIDocRoutes_writeRetrySemanticsExhaustive(t *testing.T) {
	// 语义词登记表：新增一种重试口径必须出现在这里（否则这段文案从未被复审）。
	knownPhrases := []string{
		"可安全重试：",
		"不可安全重试：",
		"不可盲目安全重试：",
		"改密请求不可重放：",
		"是否可安全重试取决于 JSON-RPC 方法",
	}
	createLike := apiDocRetryByMethod[http.MethodPost]
	covered := 0
	usedCreateLike := make(map[string]bool, len(createLikeWriteDocRoutes))
	for _, route := range apiDocRoutes {
		if _, write := apiDocRetryByMethod[route.Method]; !write {
			continue
		}
		covered++
		key := route.Method + " " + route.Path
		description := operationDescription(route)
		matched := false
		for _, phrase := range knownPhrases {
			if strings.Contains(description, phrase) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("%s 的重试语义未落在已登记口径上（新增文案需登记）: %q", key, description)
			continue
		}
		if route.Method == http.MethodPost {
			if strings.Contains(description, createLike) {
				usedCreateLike[key] = true
				if _, registered := createLikeWriteDocRoutes[key]; !registered {
					t.Errorf("%s 落进 POST 兜底创建类文案但未在 createLikeWriteDocRoutes 登记（默认分支不得吞未登记路由）: %q", key, description)
				}
			}
			continue
		}
		if strings.Contains(description, createLike) {
			t.Errorf("%s 是 %s，却用 POST 的「可能创建新资源」文案——PUT/PATCH/DELETE 语义由方法派生，特例请显式 case: %q", key, route.Method, description)
		}
	}
	if covered == 0 {
		t.Fatal("写端点集合为空——绊线的输入面已消失")
	}
	documented := make(map[string]struct{}, covered)
	for _, route := range apiDocRoutes {
		documented[route.Method+" "+route.Path] = struct{}{}
	}
	for key := range createLikeWriteDocRoutes {
		if _, ok := documented[key]; !ok {
			t.Errorf("createLikeWriteDocRoutes 登记了不存在的写端点 %s（拼写漂移会让穷尽性绊线失去对照）", key)
		}
		if !usedCreateLike[key] {
			t.Errorf("%s 已登记但文案不再是创建类兜底（改类后须同步删登记）", key)
		}
	}
}

// 白名单不得残留已删除的路由（登记项必须仍是文档中的 DELETE 端点）。
func TestAPIDocRoutes_idempotentDeleteWhitelistHasNoStaleEntries(t *testing.T) {
	documented := make(map[string]struct{}, len(apiDocRoutes))
	for _, route := range apiDocRoutes {
		documented[route.Method+" "+route.Path] = struct{}{}
	}
	for key := range idempotentDeleteDocRoutes {
		if _, ok := documented[key]; !ok {
			t.Errorf("幂等删除白名单登记了不存在的路由 %s（拼写漂移会让穷尽性绊线失去对照）", key)
		}
	}
}

// 导入窗口门的两类端点：GET 是导出/下发被拒，其余是写被拒。
func TestOpenAPIYAML_importWindowErrorTextByMethod(t *testing.T) {
	yaml := buildOpenAPIYAML()
	segment := func(path string) string {
		start := strings.Index(yaml, "\n  "+apipath.ToOpenAPI(path)+":")
		if start < 0 {
			t.Fatalf("OpenAPI YAML 缺 %s 段", path)
		}
		end := len(yaml)
		if next := strings.Index(yaml[start+1:], "\n  /"); next >= 0 {
			end = start + 1 + next
		}
		return yaml[start:end]
	}
	gatedReads := 0
	for key := range importWindowGatedDocRoutes {
		method, path, _ := strings.Cut(key, " ")
		body := segment(path)
		switch method {
		case http.MethodGet:
			gatedReads++
			if !strings.Contains(body, "（配置导入窗口拒绝导出）") {
				t.Errorf("%s 被导入窗口拦的是导出/下发，文档仍按写入口径描述: %q", key, body)
			}
		default:
			// 写端点默认「拒绝写」；少数端点手写了更细的文案
			// （如「拒绝 MFA 写」），但仍必须落在 import_in_progress 上。
			if !strings.Contains(body, "import_in_progress") {
				t.Errorf("%s 是写端点，文档未登记导入窗口 409", key)
			}
			if strings.Contains(body, "拒绝导出）") {
				t.Errorf("%s 是写端点，不应出现「拒绝导出」口径", key)
			}
		}
		if method == http.MethodGet && strings.Contains(body, "（配置导入窗口拒绝写）") {
			t.Errorf("%s 是只读/导出端点，不应出现「拒绝写」口径", key)
		}
	}
	if gatedReads == 0 {
		t.Fatal("受导入窗口约束的 GET 端点集合为空——推导面已消失")
	}
}

// 示例里的产品版本必须是占位符：硬编码的具体版本在下次发版即与
// APP_VERSION 脱节（文档声称的版本不是服务端返回的版本），且不会有人发现
// ——发布流程的版本锚点只覆盖 compose/README/Dockerfile。
//
// 范围限定在本产品版本字段：第三方版本（caddy_version / crs_version /
// ip2region_version 及其 version 字段）是真实具体版本，不属于本绊线。
func TestAPIDocExamplesDoNotHardcodeProductVersion(t *testing.T) {
	source, err := os.ReadFile("apidocs.go")
	if err != nil {
		t.Fatalf("read apidocs.go: %v", err)
	}
	// app_version 只存在于本产品的备份元数据，最不易误判。
	if hits := regexp.MustCompile(`"app_version":"(?:v)?[0-9]`).FindAllString(string(source), -1); len(hits) > 0 {
		t.Fatalf("文档示例硬编码了产品版本 %v——改用占位符，否则发版即过期", hits)
	}
	if !strings.Contains(string(source), `"app_version":"vX.Y.Z"`) {
		t.Fatal("备份列表示例缺少版本占位符 app_version:vX.Y.Z")
	}
	// /system/info 的 version 字段是产品版本（其余卡片的 version 可能是第三方
	// CRS/IP2Region 版本），逐路由断言，避免全文件正则误伤。
	info := routesEntry(t, "GET /system/info")
	if hits := regexp.MustCompile(`"version":"(?:v)?[0-9]`).FindAllString(info.Response, -1); len(hits) > 0 {
		t.Fatalf("GET /system/info 示例硬编码了产品版本 %v——改用占位符", hits)
	}
	if !strings.Contains(info.Response, `"version":"vX.Y.Z"`) {
		t.Fatalf("GET /system/info 示例缺少版本占位符: %s", info.Response)
	}
}
