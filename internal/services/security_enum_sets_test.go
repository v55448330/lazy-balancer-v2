package services

import (
	"context"
	"os"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// security_policies 枚举白名单单一出处钉测：mode/ip_acl_mode/geoip_mode/
// block_status_code 的合法值此前并列写在归一回填语句、脏行谓词、渲染守卫与
// ValidBlockStatusCode 四处，新增枚举值漏改任一处即静默分叉（漏改回填=每次
// 启动把用户新启用的值归一关闭）。本组用例钉死「集合变量单源 + 四类消费端
// 全部查同一集合」。
func TestSecurityEnumSets_backfillsAndPredicateConsultSets(t *testing.T) {
	raw, err := os.ReadFile("security_normalize.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	for _, marker := range []string{
		// 归一回填语句与脏行谓词消费集合生成的 IN 片段
		"securityEnumSQLList(securityIPACLModes)",
		"securityEnumSQLList(securityModes)",
		"securityEnumSQLList(securityGeoIPModes)",
		"securityBlockStatusCodeSQLList()",
	} {
		if !strings.Contains(src, marker) {
			t.Errorf("security_normalize.go 缺少集合消费标记 %q（回填/谓词回到字面量白名单即分叉）", marker)
		}
	}
	// ValidBlockStatusCode 必须查同一集合（导入门与集群 apply 门共用本谓词）
	if body, ok := funcBody(src, "func ValidBlockStatusCode(v int) bool {"); !ok || !strings.Contains(body, "securityBlockStatusCodes") {
		t.Errorf("ValidBlockStatusCode 未消费 securityBlockStatusCodes 集合（body=%q）", body)
	}
}

func TestSecurityEnumSets_renderGuardsConsultSets(t *testing.T) {
	raw, err := os.ReadFile("security.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	for _, marker := range []string{
		"!securityEnumValid(securityModes, p.Mode)",
		"!securityEnumValid(securityIPACLModes, p.IPACLMode)",
		"!securityEnumValid(securityGeoIPModes, p.GeoIPMode)",
	} {
		if !strings.Contains(src, marker) {
			t.Errorf("渲染守卫未消费枚举集合：%q（渲染 switch 与谓词/回填必须查同一集合）", marker)
		}
	}
	// 渲染守卫的字面量 switch 白名单不得回归（三处字面量各出现一次即分叉复发）
	for _, literal := range []string{
		"case \"off\", \"custom_only\", \"detection\", \"blocking\":",
		"case \"allow\", \"deny\", \"绕过\":",
		"case \"\", \"off\", \"allow\", \"deny\":",
	} {
		if strings.Contains(src, literal) {
			t.Errorf("渲染守卫字面量白名单回归：%q", literal)
		}
	}
}

// funcBody 截取目标函数体（到下一个顶层 func 声明为止）——与本包
// autobackup_read_ctx_guard_test.go 的 handlerFunctionBody 同手法。
func funcBody(source, signature string) (string, bool) {
	start := strings.Index(source, signature)
	if start < 0 {
		return "", false
	}
	next := strings.Index(source[start+1:], "\nfunc ")
	if next < 0 {
		return source[start:], true
	}
	return source[start : start+1+next], true
}

// 真执行钉：四个枚举列的脏行（带外直写形状）随启动归一到写侧默认值，且
// 合法行原值保留——回填语句的 IN 片段与集合分叉时在此失败。
func TestSecurityEnumSets_normalizeExecutesAgainstSQLite(t *testing.T) {
	setupSecurityEnumTestDB(t)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, ip_acl_mode, geoip_mode, block_status_code) VALUES
		('valid-row', 'blocking', 'allow', 'allow', 403),
		('dirty-row', 'STRICT', 'ALLOW', 'DENY', 418)`); err != nil {
		t.Fatal(err)
	}

	NormalizeLegacySecurityPolicyEnums(context.Background())

	read := func(name string) (mode, acl, geo string, status int) {
		t.Helper()
		if err := db.DB.QueryRow(`SELECT COALESCE(mode,''), COALESCE(ip_acl_mode,''), COALESCE(geoip_mode,''), COALESCE(block_status_code,0)
			FROM security_policies WHERE name=?`, name).Scan(&mode, &acl, &geo, &status); err != nil {
			t.Fatal(err)
		}
		return mode, acl, geo, status
	}
	if mode, acl, geo, status := read("dirty-row"); mode != "off" || acl != "deny" || geo != "deny" || status != 403 {
		t.Fatalf("脏行归一结果 mode=%q acl=%q geo=%q status=%d, want off/deny/deny/403", mode, acl, geo, status)
	}
	if mode, acl, geo, status := read("valid-row"); mode != "blocking" || acl != "allow" || geo != "allow" || status != 403 {
		t.Fatalf("合法行被误归一 mode=%q acl=%q geo=%q status=%d", mode, acl, geo, status)
	}
}

// 拦截状态码谓词与白名单逐值对账：429 已剔除（限流专用语义），枚举外值全拒。
func TestValidBlockStatusCode_matchesWhitelist(t *testing.T) {
	for _, v := range []int{0, 400, 401, 403, 404, 503} {
		if !ValidBlockStatusCode(v) {
			t.Errorf("ValidBlockStatusCode(%d)=false, want true", v)
		}
	}
	for _, v := range []int{-1, 200, 418, 429, 500, 502} {
		if ValidBlockStatusCode(v) {
			t.Errorf("ValidBlockStatusCode(%d)=true, want false", v)
		}
	}
}
