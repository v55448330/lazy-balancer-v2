package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// W8（WAF 域划入 handlers/security.go · 批准修复）：GetCRSRuleContent 必须经
// crsRulesDir 测试缝（文件头声明，ListCRSRules 同源）解析规则文件路径——此前
// 局部变量硬编码 "/app/waf/crs/rules" 且遮蔽 filepath 包名，与缝声明构成双真源，
// 规则目录不可注入（r69 测试因此只能钉 400/404 两分支）。
func TestGetCRSRuleContent_resolvesViaCRSRulesDirSeam(t *testing.T) {
	// Given：crsRulesDir 指向临时目录，内含一个规则文件
	dir := t.TempDir()
	const content = "SecRule REQUEST_URI \"@rx /w8-seam\" \"id:942100,phase:1,pass,nolog\"\n"
	if err := os.WriteFile(filepath.Join(dir, "REQUEST-942-W8-SEAM.conf"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	oldDir := crsRulesDir
	crsRulesDir = dir
	t.Cleanup(func() { crsRulesDir = oldDir })

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/security/crs/rules/REQUEST-942-W8-SEAM.conf", nil)
	ctx.Params = gin.Params{{Key: "filename", Value: "REQUEST-942-W8-SEAM.conf"}}

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
