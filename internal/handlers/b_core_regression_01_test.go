package handlers

// 规则保存校验镜像 parity、死字段清除、启动守卫业务摘要行。

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

// 配置时区渲染，但过期/未生效两条 warning 仍用 UTC 原值 Format——配置时区与
// UTC 跨日时，warning 文案日期与 not_after/not_before 日期相差一天。
func TestParseTLSCertificateWarnings_followConfiguredTimezone(t *testing.T) {
	previous := services.CurrentLocation()
	if _, err := services.ConfigureLocation("Asia/Shanghai"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = services.ConfigureLocation(previous.String()) })
	shanghai, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("expired", func(t *testing.T) {
		// NotAfter = Asia/Shanghai 2026-01-01 00:30（UTC 2025-12-31 16:30）
		certPEM, keyPEM := selfSignedCertWithExpiry(t, "u13-02-expired.test",
			time.Date(2025, 12, 30, 0, 0, 0, 0, time.UTC),
			time.Date(2026, 1, 1, 0, 30, 0, 0, shanghai))

		info, err := parseTLSCertificate(certPEM, keyPEM)
		if err != nil {
			t.Fatalf("parseTLSCertificate: %v", err)
		}
		if !strings.Contains(info.Warning, "证书已过期") {
			t.Fatalf("warning=%q, want 过期提示", info.Warning)
		}
		if info.NotAfter != "2026-01-01" {
			t.Fatalf("not_after=%q, want 2026-01-01（配置时区）", info.NotAfter)
		}
		if !strings.Contains(info.Warning, info.NotAfter) {
			t.Fatalf("warning=%q, want 日期与 not_after(%s) 一致（配置时区口径）", info.Warning, info.NotAfter)
		}
	})

	t.Run("not yet valid", func(t *testing.T) {
		// NotBefore = Asia/Shanghai 2026-12-31 00:30（UTC 2026-12-30 16:30）
		certPEM, keyPEM := selfSignedCertWithExpiry(t, "u13-02-future.test",
			time.Date(2026, 12, 31, 0, 30, 0, 0, shanghai),
			time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC))

		info, err := parseTLSCertificate(certPEM, keyPEM)
		if err != nil {
			t.Fatalf("parseTLSCertificate: %v", err)
		}
		if !strings.Contains(info.Warning, "证书尚未生效") {
			t.Fatalf("warning=%q, want 未生效提示", info.Warning)
		}
		if info.NotBefore != "2026-12-31" {
			t.Fatalf("not_before=%q, want 2026-12-31（配置时区）", info.NotBefore)
		}
		if !strings.Contains(info.Warning, info.NotBefore) {
			t.Fatalf("warning=%q, want 日期与 not_before(%s) 一致（配置时区口径）", info.Warning, info.NotBefore)
		}
	})
}

// issued 但无到期日（expires_at 为空）会让任务停留在 InProgress——续签扫描的
// 两个查询（均要求 expires_at 非空）都看不到它，任务永不推进。该形态无到期日
// 可判，必须按 Retry 重排队。
func TestResolveEnableCertJobAction_issuedWithoutExpiryRetries(t *testing.T) {
	now := time.Now()
	if action := ResolveEnableCertJobAction(true, "issued", nil, now, 30); action != EnableCertJobRetry {
		t.Fatalf("action=%v, want EnableCertJobRetry（issued 且无到期日不可判定，须重排队）", action)
	}
	// 回归：带到期日的 issued 判定不受影响。
	validExpiry := now.Add(90 * 24 * time.Hour)
	if action := ResolveEnableCertJobAction(true, "issued", &validExpiry, now, 30); action != EnableCertJobKeep {
		t.Fatalf("action=%v, want EnableCertJobKeep（到期日充足）", action)
	}
}

// 契约噪音。删除字段后，/certificates/parse 响应不含 error 键，类型也无该字段。
func TestCertificateInfo_hasNoDeadErrorField(t *testing.T) {
	if field, ok := reflect.TypeOf(CertificateInfo{}).FieldByName("Error"); ok {
		t.Fatalf("CertificateInfo.Error 死字段仍在（JSON 键 %q 在包内零赋值点）", field.Tag.Get("json"))
	}

	certPEM, keyPEM, err := generateTestCert("u13-08.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate cert pair: %v", err)
	}
	body, err := json.Marshal(map[string]string{"cert_pem": certPEM, "key_pem": keyPEM})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/certificates/parse", (&Handlers{cfg: &config.Config{}}).ParseCertificate)
	request := httptest.NewRequest(http.MethodPost, "/certificates/parse", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), `"error"`) {
		t.Fatalf("body=%s, want 无 error 键（前端已自备错误通道）", response.Body.String())
	}
}

// 请求模型平行的第三份字段清单。本台账钉住 parity：models 请求字段必须要么出现在
// rulePayloadInput（本校验门消费），要么显式列在 notMirrored（由其他单源校验/
// 无值域规则承担）；新增字段漏登记即红。归一视图字段也必须真实存在于
// 两个请求模型中（防改名/拼写漂移）。
func TestRulePayload_inputParityWithModels(t *testing.T) {
	notMirrored := map[string]string{
		"Name":                       "仅 binding:required 非空（持久化字段，无格式规则）",
		"Description":                "自由文本（持久化字段，无格式规则）",
		"EnableDnsServer":            "ruleFeatureInput 单源（validateRuleFeatures 校验 TCP 禁用）",
		"TCPHealthCheckPort":         "ruleFeatureInput 单源（TCP 值域校验）",
		"TCPProxyProtocol":           "布尔开关，无值域校验（直读落库）",
		"TCPTryDuration":             "ruleFeatureInput 单源（TCP 值域校验）",
		"TCPTryInterval":             "ruleFeatureInput 单源（TCP 值域校验）",
		"NTLMCompatible":             "ruleFeatureInput 单源（值域/策略约束）",
		"UpstreamForceHTTP1":         "ruleFeatureInput 单源（值域校验）",
		"ForwardAuthEnabled":         "ruleFeatureInput 单源（值域/仅 HTTP/与路径模式互斥校验）",
		"ForwardAuthUpstream":        "ruleFeatureInput 单源（网关地址白名单校验）",
		"ForwardAuthURI":             "ruleFeatureInput 单源（/ 前缀+拒 CRLF 校验）",
		"ForwardAuthCopyHeaders":     "ruleFeatureInput 单源（1-16 头/拒 CRLF 冒号校验）",
		"CustomRoutesEnabled":        "ruleFeatureInput 单源（TCP 禁用）",
		"ProxyDialTimeout":           "ruleFeatureInput 单源（TCP 禁用）",
		"ProxyResponseHeaderTimeout": "ruleFeatureInput 单源（TCP 禁用）",
		"ProxyReadTimeout":           "ruleFeatureInput 单源（TCP 禁用）",
		"ProxyWriteTimeout":          "ruleFeatureInput 单源（TCP 禁用）",
		"ProxyStreamTimeout":         "ruleFeatureInput 单源（TCP 禁用）",
		"ProxyFlushInterval":         "ruleFeatureInput 单源（TCP 禁用）",
		"ProxyStreamCloseDelay":      "ruleFeatureInput 单源（TCP 禁用）",
		"PathRules":                  "ruleFeatureInput 单源（TCP 禁用）",
		"LogEnabled":                 "布尔开关，无值域校验（直读落库）",
		"Enabled":                    "布尔开关，无值域校验（直读落库）",
		"ExpectedUpdatedAt":          "乐观并发前置条件（不落库，仅事务内与 updated_at 比对）",
	}

	mirror := reflect.TypeOf(rulePayloadInput{})
	requests := []reflect.Type{
		reflect.TypeOf(models.CreateRuleRequest{}),
		reflect.TypeOf(models.UpdateRuleRequest{}),
	}
	for _, request := range requests {
		for i := range request.NumField() {
			name := request.Field(i).Name
			if _, ok := mirror.FieldByName(name); ok {
				continue
			}
			if reason, ok := notMirrored[name]; ok && reason != "" {
				continue
			}
			t.Errorf("%s.%s 既不在 rulePayloadInput 也未登记 validatedElsewhere——新增字段默认漏校验", request.Name(), name)
		}
	}
	for i := range mirror.NumField() {
		field := mirror.Field(i)
		for _, request := range requests {
			modelField, ok := request.FieldByName(field.Name)
			if !ok {
				t.Errorf("rulePayloadInput.%s 在 %s 中不存在（镜像漂移/拼写）", field.Name, request.Name())
				continue
			}
			modelType := modelField.Type
			if modelType.Kind() == reflect.Ptr {
				modelType = modelType.Elem()
			}
			if modelType != field.Type {
				t.Errorf("rulePayloadInput.%s 类型 %v 与 %s.%s 类型 %v 不一致", field.Name, field.Type, request.Name(), field.Name, modelType)
			}
		}
	}
}

// 只有 Logf+审计，任务日志无业务结论行——同函数成功/回退分支都有 TaskLogf。
func TestStartupGuard_writesTaskLogSummary(t *testing.T) {
	h := newBackupTestHandlers(t)
	fake, loadCount := foreignRoutesFakeAdmin(t, []string{"lb_foreign777"})
	h.cfg = &config.Config{CaddyAdminURL: fake.URL}
	h.caddyService = services.NewCaddyService(fake.URL)

	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(filepath.Join(t.TempDir(), "tasks"))
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })

	if err := h.ApplyConfigOnStartup(""); err != nil {
		t.Fatalf("ApplyConfigOnStartup: %v", err)
	}
	if *loadCount != 0 {
		t.Fatalf("load count=%d, want 0（守卫命中不应用配置）", *loadCount)
	}
	data, err := os.ReadFile(taskengine.TaskLogPath("startup:config-load"))
	if err != nil {
		t.Fatalf("read startup task log: %v", err)
	}
	if !strings.Contains(string(data), "启动守卫命中") {
		t.Fatalf("task log=%q, want 守卫业务摘要行", string(data))
	}
}

// 若只加入 rulePayloadInput 而漏写 switch 赋值，仍会以零值通过本门并让该字段
// 完全绕过校验。本门用 AST 扫描 validateRulePayloadBeforeSave 的两个 switch
// 分支，要求每个 rulePayloadInput 字段在 Create/Update 两分支都被真实赋值
// （声明→赋值→消费完整链）。
func TestValidateRulePayload_switchesAssignEveryInputField(t *testing.T) {
	source, err := os.ReadFile("handlers.go")
	if err != nil {
		t.Fatalf("read handlers.go: %v", err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "handlers.go", source, 0)
	if err != nil {
		t.Fatalf("parse handlers.go: %v", err)
	}
	assigned := map[string]map[string]bool{
		"models.CreateRuleRequest": {},
		"models.UpdateRuleRequest": {},
	}
	ast.Inspect(file, func(node ast.Node) bool {
		typeSwitch, ok := node.(*ast.TypeSwitchStmt)
		if !ok {
			return true
		}
		for _, statement := range typeSwitch.Body.List {
			clause, ok := statement.(*ast.CaseClause)
			if !ok || len(clause.List) != 1 {
				continue
			}
			selector, ok := clause.List[0].(*ast.SelectorExpr)
			if !ok {
				continue
			}
			pkg, ok := selector.X.(*ast.Ident)
			if !ok || pkg.Name != "models" {
				continue
			}
			key := "models." + selector.Sel.Name
			if _, tracked := assigned[key]; !tracked {
				continue
			}
			for _, inner := range clause.Body {
				ast.Inspect(inner, func(innerNode ast.Node) bool {
					assign, ok := innerNode.(*ast.AssignStmt)
					if !ok {
						return true
					}
					for _, lhs := range assign.Lhs {
						field, ok := lhs.(*ast.SelectorExpr)
						if !ok {
							continue
						}
						if ident, ok := field.X.(*ast.Ident); ok && ident.Name == "data" {
							assigned[key][field.Sel.Name] = true
						}
					}
					return true
				})
			}
		}
		return true
	})
	mirror := reflect.TypeOf(rulePayloadInput{})
	for key, fields := range assigned {
		if len(fields) == 0 {
			t.Fatalf("%s 分支未找到（AST 扫描失靶）", key)
		}
		for i := range mirror.NumField() {
			name := mirror.Field(i).Name
			if !fields[name] {
				t.Errorf("%s 分支缺少 rulePayloadInput.%s 的赋值——该字段将以零值绕过所有校验", key, name)
			}
		}
	}
}
