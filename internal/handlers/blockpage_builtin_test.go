package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 内置拦截页（2026-09-25 用户裁定）：限流 429 / 维护 503 两个内置备选页，与默认
// 403 页同待遇——不可编辑、不可删除；仅作备选模板供策略/阶段拦截页选用，无任何
// 自动绑定（规则默认仍跟随默认 403 页）。本组测试钉住：builtin 行门禁、渲染形状、
// 播种与自愈（内容漂移/标志丢失均归位库存）。

func TestRenderBuiltinBlockPage_variants(t *testing.T) {
	// Given
	cfg := brandingConfig{AppName: "Acme", FooterText: "© 2026 Acme"}

	// When
	ratelimit := renderBuiltinBlockPage(cfg, "ratelimit")
	maintenance := renderBuiltinBlockPage(cfg, "maintenance")

	// Then 限流页：429 胶囊 + 标题 + 琥珀色 + 限宽 + 品牌注入
	for _, token := range []string{"429 Too Many Requests", "Too Many Requests", "width: min(560px", "#d97706", "<svg", "Powered by <span class=\"name\">Acme</span>", "© 2026 Acme"} {
		if !strings.Contains(ratelimit, token) {
			t.Errorf("ratelimit page missing %q", token)
		}
	}
	// 维护页：维护胶囊 + 标题 + 蓝色 + 限宽 + 品牌注入
	for _, token := range []string{"System Maintenance", "Under Maintenance", "width: min(560px", "#2563eb", "<svg", "Powered by <span class=\"name\">Acme</span>"} {
		if !strings.Contains(maintenance, token) {
			t.Errorf("maintenance page missing %q", token)
		}
	}
	// 未知变体必须拒绝（防调用方拼写漂移渲染出无语义页面）
	if got := renderBuiltinBlockPage(cfg, "bogus"); got != "" {
		t.Errorf("unknown variant must render empty, got %d bytes", len(got))
	}
}

func TestSeedDefaultBlockPage_seedsAndRepairsBuiltinPages(t *testing.T) {
	// Given 全新库（schema 播种 9001/9002 内置行）
	initBrandingTestDB(t)
	dataDir := t.TempDir()
	var ratelimitBuiltin, maintenanceBuiltin bool
	var ratelimitContent string
	if err := db.DB.QueryRow(`SELECT COALESCE(is_builtin,0), COALESCE(content,'') FROM security_block_pages WHERE id=9001`).Scan(&ratelimitBuiltin, &ratelimitContent); err != nil {
		t.Fatalf("内置限流页未随 schema 播种: %v", err)
	}
	if !ratelimitBuiltin || !strings.Contains(ratelimitContent, "429 Too Many Requests") || !strings.Contains(ratelimitContent, "min(560px") {
	}
	if err := db.DB.QueryRow(`SELECT COALESCE(is_builtin,0) FROM security_block_pages WHERE id=9002`).Scan(&maintenanceBuiltin); err != nil || !maintenanceBuiltin {
		t.Fatalf("内置维护页未随 schema 播种: builtin=%v err=%v", maintenanceBuiltin, err)
	}

	// Given 内容漂移 + 标志丢失（备份导入/手工改库形态）
	if _, err := db.DB.Exec(`UPDATE security_block_pages SET content='<html>被篡改</html>', is_builtin=0 WHERE id=9001`); err != nil {
		t.Fatal(err)
	}

	// When 播种自愈
	if _, err := SeedDefaultBlockPage(dataDir); err != nil {
		t.Fatalf("SeedDefaultBlockPage: %v", err)
	}

	// Then 内容归位库存（含品牌注入）且标志修复
	var repaired bool
	if err := db.DB.QueryRow(`SELECT COALESCE(is_builtin,0), COALESCE(content,'') FROM security_block_pages WHERE id=9001`).Scan(&repaired, &ratelimitContent); err != nil {
		t.Fatal(err)
	}
	if !repaired || !strings.Contains(ratelimitContent, "429 Too Many Requests") || strings.Contains(ratelimitContent, "被篡改") {
		t.Fatalf("限流页未自愈: builtin=%v content=%.60s", repaired, ratelimitContent)
	}
}

func TestUpdateSecurityBlockPage_rejectsBuiltinPage(t *testing.T) {
	// Given 一个内置页面
	setupSecurityPolicyTestDB(t)
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.PUT("/security/block-pages/:id", h.UpdateSecurityBlockPage)
	res, err := db.DB.Exec(`INSERT INTO security_block_pages (name, content, is_default, is_builtin) VALUES ('内置限流', '<html>stock</html>', 0, 1)`)
	if err != nil {
		t.Fatalf("seed builtin page: %v", err)
	}
	pageID, _ := res.LastInsertId()

	// When
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPut, fmt.Sprintf("/security/block-pages/%d", pageID), strings.NewReader(`{"name":"改名","description":"","content":"<html>x</html>"}`)))

	// Then 403 且内容未被改写
	if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), "内置拦截页面不可编辑") {
		t.Fatalf("status=%d body=%s, want 403 内置拦截页面不可编辑", recorder.Code, recorder.Body.String())
	}
	var name string
	if err := db.DB.QueryRow(`SELECT name FROM security_block_pages WHERE id=?`, pageID).Scan(&name); err != nil || name != "内置限流" {
		t.Fatalf("内置页被改写: name=%q err=%v", name, err)
	}
}

func TestDeleteSecurityBlockPage_rejectsBuiltinPage(t *testing.T) {
	// Given 一个内置页面
	setupSecurityPolicyTestDB(t)
	router := newSecurityR26Router(t)
	res, err := db.DB.Exec(`INSERT INTO security_block_pages (name, content, is_default, is_builtin) VALUES ('内置维护', '<html>stock</html>', 0, 1)`)
	if err != nil {
		t.Fatalf("seed builtin page: %v", err)
	}
	pageID, _ := res.LastInsertId()

	// When
	recorder := deleteRequest(t, router, fmt.Sprintf("/security/block-pages/%d", pageID))

	// Then 403 且行保留
	if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), "内置拦截页面不可删除") {
		t.Fatalf("status=%d body=%s, want 403 内置拦截页面不可删除", recorder.Code, recorder.Body.String())
	}
	var pages int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_block_pages WHERE id=?`, pageID).Scan(&pages); err != nil || pages != 1 {
		t.Fatalf("内置页被删除: rows=%d err=%v", pages, err)
	}
}
