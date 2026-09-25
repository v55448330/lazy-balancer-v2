package handlers

// content_type 白名单防线补全（第 52 轮 P2-1，用户裁定按建议处理）：
// 备份导入通道（restoreTable）对 security_block_pages.content_type 加白名单门
// ——非法值归一默认 text/html; charset=utf-8（与 mode 枚举门同口径的
// 「导入侧值域收敛」），杜绝带外 CRLF/任意字符串落库渲染进响应头。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestImportConfigBackup_normalizesInvalidBlockPageContentType(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	gin.SetMode(gin.TestMode)
	h := newBackupTestHandlers(t)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)

	// Given：备份内拦截页 content_type 为白名单外值（CRLF 注入形态）与合法值各一
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"security_block_pages": {
			{"id": 100, "name": "恶意类型页", "content": "x", "content_type": "text/html\r\nX-Injected: 1"},
			{"id": 101, "name": "合法 JSON 页", "content": "{}", "content_type": "application/json; charset=utf-8"},
		},
	})

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200（非法类型应归一放行而非整包拒绝）", response.Code, response.Body.String())
	}

	// Then：非法值归一默认，合法值保留
	var evil, good string
	if err := db.DB.QueryRow(`SELECT COALESCE(content_type,'') FROM security_block_pages WHERE id=100`).Scan(&evil); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRow(`SELECT COALESCE(content_type,'') FROM security_block_pages WHERE id=101`).Scan(&good); err != nil {
		t.Fatal(err)
	}
	if evil != "text/html; charset=utf-8" {
		t.Fatalf("非法 content_type=%q, want 归一 text/html; charset=utf-8", evil)
	}
	if good != "application/json; charset=utf-8" {
		t.Fatalf("合法 content_type=%q, want 原样保留 application/json; charset=utf-8", good)
	}
}

func TestUpdateSecurityPolicy_auditDeltaCoversTypeAndTrustDetection(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if err := db.InitializeAuditDB(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	router := newSecurityRouter(t)
	res, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, policy_type, trust_detection, ip_whitelist_enabled, ip_whitelist, geoip_mode)
		VALUES ('类型信任策略', 'off', 1, 'stage0', 1, 1, '["::1"]', 'off')`)
	if err != nil {
		t.Fatal(err)
	}
	policyID, _ := res.LastInsertId()
	readDetail := func() string {
		var detail string
		if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新' AND resource='安全策略' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
			t.Fatal(err)
		}
		return detail
	}

	// When：单独翻转 trust_detection（真实行为变化：直通↔保留检测）
	r := putJSON(t, router, fmt.Sprintf("/security/policies/%d", policyID), map[string]any{"trust_detection": false})
	if r.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", r.Code, r.Body.String())
	}

	// Then：delta 记录该列（不得落「（无字段变化）」虚假审计）
	d := readDetail()
	if !strings.Contains(d, "信任检测：true→false") {
		t.Fatalf("detail=%q, want 含 信任检测：true→false（delta 漏列=虚假审计）", d)
	}
	if strings.Contains(d, "无字段变化") {
		t.Fatalf("真实变更不得落「（无字段变化）」: %q", d)
	}
}

// UPDATE 列集合 ↔ delta 字段集合静态对照（防「加列忘加 delta」复发，同款
// TestCaddySectionKeys_matchUpdateSQL 文本定位模式）——delta 字段清单以
// delta*/deltaRefs/拦截页 调用点枚举，UPDATE 写入列以 addStr/addInt/addBool/
// 显式 query+= 枚举；两集合必须全等（policy_type/trust_detection 为既有豁免转
// 正项，断言它们在场即锁住缺口）。
func TestSecurityPolicyDeltaCoversAllUpdateColumns(t *testing.T) {
	// When：解析 security.go 中 UPDATE 写列与 delta 覆盖列
	updateCols, deltaCols := securityPolicyUpdateAndDeltaColumns(t)

	// Then：policy_type 与 trust_detection 必须在两侧同时在场（第 52 轮缺口锁）
	for _, col := range []string{"policy_type", "trust_detection"} {
		if !updateCols[col] {
			t.Fatalf("%s 不在 UPDATE 列集合（测试本身失效）", col)
		}
		if !deltaCols[col] {
			t.Fatalf("%s 在 UPDATE 但不在 delta 覆盖集——「加列忘加 delta」复发", col)
		}
	}
	// 真全等（第 53 轮 P3-1：双向）——UPDATE 列都有 delta 覆盖，delta 列也都
	// 在 UPDATE 列集内（防「删掉 delta 测试不报警」盲区）。
	for col := range updateCols {
		if !deltaCols[col] {
			t.Fatalf("UPDATE 列 %s 缺 delta 覆盖", col)
		}
	}
	for col := range deltaCols {
		if !updateCols[col] {
			t.Fatalf("delta 列 %s 不在 UPDATE 列集合（delta 被删或写列形态变更测试须同步）", col)
		}
	}
}

// delta 覆盖集合 = 同函数体内 deltaStr/deltaBool/deltaInt/deltaRefs 调用实参里
// stored.<Field> 的 snake_case 列名（GeoIP→geoip、CIDR→cidr、IP→ip 缩写归一）。
func securityPolicyUpdateAndDeltaColumns(t *testing.T) (updateCols, deltaCols map[string]bool) {
	t.Helper()
	src, err := os.ReadFile("security.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	start := strings.Index(text, "func (h *Handlers) UpdateSecurityPolicy")
	if start < 0 {
		t.Fatal("UpdateSecurityPolicy 未找到")
	}
	if end := strings.Index(text[start:], "\nfunc "); end > 0 {
		text = text[start : start+end]
	} else {
		text = text[start:]
	}
	// UPDATE 写列双形态（第 53 轮 P3-1）：addStr/addInt/addBool + 显式 query+=
	updateCols = map[string]bool{}
	for _, m := range regexp.MustCompile(`add(?:Str|Int|Bool)\("([a-z_]+)"`).FindAllStringSubmatch(text, -1) {
		updateCols[m[1]] = true
	}
	for _, m := range regexp.MustCompile(`query \+= ", ([a-z_]+)=\?"`).FindAllStringSubmatch(text, -1) {
		updateCols[m[1]] = true
	}
	// delta 覆盖双形态：delta* 调用实参里的 stored.<Field> + 裸 if-block
	// （`if req.X != nil && *req.X != stored.X` 形态，如 block_page_id 拦截页 delta）
	deltaCols = map[string]bool{}
	deltaCalls := regexp.MustCompile(`delta(?:Str|Bool|Int|JSON|Refs)\(([^)]*(?:\([^)]*\)[^)]*)*)\)`).FindAllStringSubmatch(text, -1)
	fieldRef := regexp.MustCompile(`stored\.([A-Za-z0-9]+)`)
	for _, call := range deltaCalls {
		for _, f := range fieldRef.FindAllStringSubmatch(call[1], -1) {
			deltaCols[fieldToColumn(f[1])] = true
		}
	}
	for _, m := range regexp.MustCompile(`if req\.\w+ != nil && \*req\.\w+ != stored\.([A-Za-z0-9]+)`).FindAllStringSubmatch(text, -1) {
		deltaCols[fieldToColumn(m[1])] = true
	}
	return updateCols, deltaCols
}

func fieldToColumn(field string) string {
	field = strings.ReplaceAll(field, "GeoIP", "Geoip")
	field = strings.ReplaceAll(field, "CIDR", "Cidr")
	field = strings.ReplaceAll(field, "CRS", "Crs")
	field = strings.ReplaceAll(field, "RPS", "Rps")
	field = strings.ReplaceAll(field, "ACL", "Acl")
	field = strings.ReplaceAll(field, "WAF", "Waf")
	field = strings.ReplaceAll(field, "ID", "Id")
	field = strings.ReplaceAll(field, "IP", "Ip")
	var b strings.Builder
	for i, r := range field {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r + 32)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
