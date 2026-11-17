package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/services"
)

// 穿越门与尺寸门的回归钉：../ 与 / 形态的 filename 必须 400（此前只有
// 测试缝用例覆盖 200 路径）；超 1MB 文件必须 413 而非静默截断。
func TestGetCRSRuleContent_rejectsTraversalAndOversize(t *testing.T) {
	withIsolatedGlobal(t)
	dir := t.TempDir()
	oldDir := crsRulesDir
	crsRulesDir = dir
	t.Cleanup(func() { crsRulesDir = oldDir })

	for _, filename := range []string{"../x.conf", "..\\x.conf", "a/b.conf"} {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/security/crs/rules/"+filename, nil)
		ctx.Params = gin.Params{{Key: "filename", Value: filename}}
		newBackupTestHandlers(t).GetCRSRuleContent(ctx)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("filename %q = %d body=%s, want 400（路径穿越门）", filename, recorder.Code, recorder.Body.String())
		}
	}

	// 超 1MB 规则文件 → 413（LimitReader 1MB+1 哨兵）
	oversize := strings.Repeat("#", 1<<20+8)
	if err := os.WriteFile(filepath.Join(dir, "REQUEST-999-BIG.conf"), []byte(oversize), 0o644); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/security/crs/rules/REQUEST-999-BIG.conf", nil)
	ctx.Params = gin.Params{{Key: "filename", Value: "REQUEST-999-BIG.conf"}}
	newBackupTestHandlers(t).GetCRSRuleContent(ctx)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize file = %d body=%.200s, want 413", recorder.Code, recorder.Body.String())
	}
}

// （WAF 域划入 handlers/security.go · 批准修复）：GetCRSRuleContent 必须经
// crsRulesDir 测试缝（文件头声明，ListCRSRules 同源）解析规则文件路径——此前
// 局部变量硬编码 "/app/waf/crs/rules" 且遮蔽 filepath 包名，与缝声明构成双真源，
// 规则目录不可注入（测试因此只能钉 400/404 两分支）。
func TestGetCRSRuleContent_resolvesViaCRSRulesDirSeam(t *testing.T) {
	withIsolatedGlobal(t)
	// Given：crsRulesDir 指向临时目录，内含一个规则文件
	dir := t.TempDir()
	const content = "SecRule REQUEST_URI \"@rx /w8-seam\" \"id:942100,phase:1,pass,nolog\"\n"
	if err := os.WriteFile(filepath.Join(dir, "REQUEST-942-SEAM.conf"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	oldDir := crsRulesDir
	crsRulesDir = dir
	t.Cleanup(func() { crsRulesDir = oldDir })

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/security/crs/rules/REQUEST-942-SEAM.conf", nil)
	ctx.Params = gin.Params{{Key: "filename", Value: "REQUEST-942-SEAM.conf"}}

	// When：读取规则文件内容
	newBackupTestHandlers(t).GetCRSRuleContent(ctx)

	// Then：200 且返回注入目录中的文件内容（硬编码 /app 路径下必 404）
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（须经 crsRulesDir 测试缝解析路径）", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "@rx /w8-seam") {
		t.Fatalf("body 不含注入目录中的规则内容: %s", recorder.Body.String())
	}
}

// CRS 配置查看端点的三态（200/404/413）此前无端点级测试，crsSetupConf 测试缝
// 也从未被注入：尺寸上限必须显式 413 而非静默截断。
func TestSecurityCRSSetupConfig_endpointBoundaries(t *testing.T) {
	withIsolatedGlobal(t)
	const route = "/security/crs/setup"
	h := newBackupTestHandlers(t)
	confPath := filepath.Join(t.TempDir(), "crs-setup.conf")
	oldConf := crsSetupConf
	crsSetupConf = confPath
	t.Cleanup(func() { crsSetupConf = oldConf })
	call := func() *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodGet, route, nil)
		h.GetCRSSetupConfig(ctx)
		return recorder
	}

	// 文件不存在 → 404（不得 500，也不得返回空内容 200）
	if rec := call(); rec.Code != http.StatusNotFound {
		t.Fatalf("missing config status=%d body=%s, want 404", rec.Code, rec.Body.String())
	}

	// 正常读取 → 200 且逐字回传
	const content = "SecAction \"id:900000,phase:1,pass\"\n"
	if err := os.WriteFile(confPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := call()
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "id:900000") {
		t.Fatalf("status=%d body=%s, want 200 含配置内容", rec.Code, rec.Body.String())
	}

	// 超 1MB → 413（LimitReader 1MB+1 探针，显式拒绝而非静默截断）
	if err := os.WriteFile(confPath, []byte(strings.Repeat("#", 1<<20+8)), 0o600); err != nil {
		t.Fatal(err)
	}
	if rec := call(); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize status=%d body=%s, want 413", rec.Code, rec.Body.String())
	}
}

// CRS 更新状态端点：manager 未装配时显式 500（不得空对象 200），装配后
// 按 StatusSnapshot 的六字段投影。
func TestSecurityCRSUpdateStatus_projectsSnapshotAndReportsUninitialized(t *testing.T) {
	h := newBackupTestHandlers(t)
	services.ResetCRSUpdateManagerForTest()
	t.Cleanup(services.ResetCRSUpdateManagerForTest)
	call := func() *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/security/crs/update/status", nil)
		h.GetCRSUpdateStatus(ctx)
		return recorder
	}

	rec := call()
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "更新服务未初始化") {
		t.Fatalf("status=%d body=%s, want 500 更新服务未初始化", rec.Code, rec.Body.String())
	}

	services.InitCRSUpdateManager(func() error { return nil })
	rec = call()
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var payload struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	for _, key := range []string{"status", "trigger", "started_at", "finished_at", "message", "version"} {
		if _, ok := payload.Data[key]; !ok {
			t.Fatalf("缺少投影字段 %q: %+v", key, payload.Data)
		}
	}
	if got := payload.Data["status"]; got != string(services.CRSStatusIdle) {
		t.Fatalf("status=%v, want %q（新建 manager 的初始态）", got, services.CRSStatusIdle)
	}
}
