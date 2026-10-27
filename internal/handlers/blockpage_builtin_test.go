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
		t.Fatalf("builtin 429 page missing or content wrong (builtin=%v)", ratelimitBuiltin)
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

func TestSeedDefaultBlockPage_repairsBuiltinPagesWithNullColumns(t *testing.T) {
	// Given 带外改库把内置备选页 content/description 置 NULL——
	// 自愈 UPDATE 的裸 != 比较对 NULL 不命中（NULL != ? 为 NULL），漂移行永不归位；
	// 与:510 默认页修复同口径，须 COALESCE 同防。
	initBrandingTestDB(t)
	dataDir := t.TempDir()
	if _, err := db.DB.Exec(`UPDATE security_block_pages SET content=NULL, description=NULL WHERE id=9001`); err != nil {
		t.Fatal(err)
	}

	// When 播种自愈
	changed, err := SeedDefaultBlockPage(dataDir)
	if err != nil {
		t.Fatalf("SeedDefaultBlockPage: %v", err)
	}

	// Then NULL 漂移行归位库存（内容含 429 标识、描述归位、标志保持）
	if !changed {
		t.Fatal("NULL 漂移行未触发自愈写入")
	}
	var content, description string
	var builtin bool
	if err := db.DB.QueryRow(`SELECT COALESCE(content,''), COALESCE(description,''), COALESCE(is_builtin,0) FROM security_block_pages WHERE id=9001`).Scan(&content, &description, &builtin); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(content, "429 Too Many Requests") || !strings.Contains(description, "限流拦截页面") || !builtin {
		t.Fatalf("NULL 漂移行未自愈: content=%.40s description=%q builtin=%v", content, description, builtin)
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

// 内置页双表一致性：blockPageSpecs（渲染规格）与 builtinBlockPageIdentities
// （播种身份）必须双向对齐——只加 spec 不加 identity 会静默不播种，identity
// 指向不存在的 variant 会渲染空串写入内容库存页。两者均无编译期约束，由本
// 用例做机器门禁。
func TestBuiltinBlockPageSpecsAndIdentitiesStayInSync(t *testing.T) {
	variants := make(map[string]bool, len(builtinBlockPageIdentities))
	for _, bp := range builtinBlockPageIdentities {
		if _, ok := blockPageSpecs[bp.variant]; !ok {
			t.Errorf("内置页 %d（%s）的 variant %q 不在 blockPageSpecs 中（会渲染空内容）", bp.id, bp.name, bp.variant)
		}
		if variants[bp.variant] {
			t.Errorf("内置页 variant %q 重复登记（播种 id 冲突/重复行）", bp.variant)
		}
		variants[bp.variant] = true
	}
	for variant := range blockPageSpecs {
		if variant == "default" {
			continue // 默认 403 页由 is_default=1 行承载，不是内置备选页
		}
		if !variants[variant] {
			t.Errorf("blockPageSpecs 的 variant %q 没有对应的内置页身份（永不播种）", variant)
		}
	}
}

// API 不接受 is_builtin 与显式 id：INSERT 列清单不含这两列，静默丢弃会让调用方
// 以为「已创建内置页/指定了 id」，实际落普通行（伪造内置页本需备份导入门）。
// 与 is_default 同口径：显式拒绝并点名原因。
func TestCreateSecurityBlockPage_rejectsBuiltinAndExplicitID(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newBlockPageContentTypeRouter(t)
	before := countBlockPages(t)

	for _, tc := range []struct {
		name     string
		body     string
		wantText string
	}{
		{"builtin", `{"name":"伪内置页","content":"x","is_builtin":true}`, "内置拦截页由系统管理"},
		{"explicit-id", `{"name":"指定ID页","content":"x","id":42}`, "拦截页 ID 由系统分配"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := blockPageRequest(t, router, http.MethodPost, "/security/block-pages", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.wantText) {
				t.Fatalf("body=%s, want 含 %q", rec.Body.String(), tc.wantText)
			}
			if after := countBlockPages(t); after != before {
				t.Fatalf("拒绝路径落库了行：before=%d after=%d", before, after)
			}
		})
	}
	var builtinRows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_block_pages WHERE is_builtin=1`).Scan(&builtinRows); err != nil {
		t.Fatal(err)
	}
	if builtinRows == 0 {
		t.Fatal("夹具失效：内置页应有播种行")
	}

	// 回归形状：普通创建仍 200 且落普通行
	rec := blockPageRequest(t, router, http.MethodPost, "/security/block-pages", `{"name":"普通页","content":"x"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("normal create status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var isBuiltin bool
	if err := db.DB.QueryRow(`SELECT COALESCE(is_builtin,0) FROM security_block_pages WHERE name='普通页'`).Scan(&isBuiltin); err != nil {
		t.Fatal(err)
	}
	if isBuiltin {
		t.Fatal("普通创建不得落 is_builtin=1")
	}
}

func countBlockPages(t *testing.T) int {
	t.Helper()
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_block_pages`).Scan(&n); err != nil {
		t.Fatalf("count block pages: %v", err)
	}
	return n
}
