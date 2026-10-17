package handlers

// 第 78 轮 B 域核心修复（U13-02/03/07/08/11）：证书日期时区、证书任务状态机、
// 规则保存校验镜像 parity、死字段清除、启动守卫业务摘要行。

import (
	"bytes"
	"encoding/json"
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

// U13-02（第 78 轮）：parseTLSCertificate 的 not_before/not_after 字段已按
// 配置时区渲染，但过期/未生效两条 warning 仍用 UTC 原值 Format——配置时区与
// UTC 跨日时，warning 文案日期与 not_after/not_before 日期相差一天。
func TestU13_02_parseTLSCertificateWarningsFollowConfiguredTimezone(t *testing.T) {
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
		certPEM, keyPEM := selfSignedCertForCERT44(t, "u13-02-expired.test",
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
		certPEM, keyPEM := selfSignedCertForCERT44(t, "u13-02-future.test",
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

// U13-03（第 78 轮）：issued + expiresAt==nil（历史/导入遗留形态）此前落
// InProgress——续签扫描两查询（expires_at 非空）均不可见，任务永不推进。该
// 形态无到期日可判，必须按 Retry 重排队。
func TestU13_03_ResolveEnableCertJobAction_issuedWithoutExpiryRetries(t *testing.T) {
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

// U13-08（第 78 轮）：CertificateInfo.Error 在 handlers 包内零赋值点——恒空的
// 契约噪音。删除字段后，/certificates/parse 响应不含 error 键，类型也无该字段。
func TestU13_08_CertificateInfoHasNoDeadErrorField(t *testing.T) {
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

// U13-07（第 78 轮）：validateRulePayloadBeforeSave 的归一视图是与 models
// 请求模型平行的第三份字段清单。本台账钉住 parity：models 请求字段必须要么出现在
// rulePayloadInput（本校验门消费），要么显式列在 notMirrored（由其他单源校验/
// 无值域规则承担）；新增字段漏登记即红。归一视图字段也必须真实存在于
// 两个请求模型中（防改名/拼写漂移）。
func TestU13_07_rulePayloadInputParityWithModels(t *testing.T) {
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

// U13-11（第 78 轮）：F49-15 守卫（未初始化实例遇到非空运行配置）return 前
// 只有 Logf+审计，任务日志无业务结论行——同函数成功/回退分支都有 TaskLogf。
func TestU13_11_startupGuardWritesTaskLogSummary(t *testing.T) {
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
