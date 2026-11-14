package handlers

// 备份导入的 human_secret 收敛接线：通用 `UPDATE global_config` 直接改写
// cookie 签名密钥，绕过集群 apply 链的缓存失效（resetHumanSecretCache）。
// 提交成功后必须调用 services.ResetHumanSecretCache，使下一次渲染读取库内
// 新密钥——否则运行 Caddy 的 lb_human.secret 与库分叉至重启，跨节点/还原后
// 已签发挑战凭证校验口径不一致。断言对象是渲染产物（lb_human.secret），
// 不是函数返回值。

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// seedHumanSecretImportFixture 装配「规则+启用上游+force 人机策略+绑定」，
// 使渲染产物携带 lb_human handler；返回规则 caddy_id。
func seedHumanSecretImportFixture(t *testing.T) string {
	t.Helper()
	const ruleID = "lb_human_import"
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled)
		VALUES (?,?,'http','human-import.example.test',8080,'weighted_round_robin',1)`, ruleID, ruleID); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?, '127.0.0.1',9000,1,1,'http')`, ruleID); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	res, err := db.DB.Exec(`INSERT INTO security_policies (name,mode,enabled,policy_type,human_verify_mode,human_verify_type)
		VALUES ('人机导入策略','off',1,'stage2','force','slider')`)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	policyID, _ := res.LastInsertId()
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES (?,?)`, ruleID, policyID); err != nil {
		t.Fatalf("seed binding: %v", err)
	}
	return ruleID
}

// stubHumanSecretRenderLibs 把 CRS/IP2Region 库桩到可用形态（缺库降级时
// 安全链整体不渲染，lb_human 无从断言）——与名单热路径夹具同口径。
func stubHumanSecretRenderLibs(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	crsDir := filepath.Join(dir, "crs")
	if err := os.MkdirAll(filepath.Join(crsDir, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crsDir, "rules", "REQUEST-901-INITIALIZATION.conf"), []byte("# fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	xdb := filepath.Join(dir, "ip2region.xdb")
	if err := os.WriteFile(xdb, []byte("xdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	restore := services.SetSecurityLibsDirsForTest(crsDir, xdb)
	t.Cleanup(restore)
	// 进程级密钥缓存跨用例存活：每个用例从空缓存起步（读当前隔离库），
	// 结束后复位，避免前序用例的密钥串入本用例的「旧值」基线。
	services.ResetHumanSecretCache()
	t.Cleanup(services.ResetHumanSecretCache)
}

// renderedHumanSecrets 从已提交库视图渲染配置，收集全部 lb_human handler
// 的 secret 字段（渲染产物是运行 Caddy 实际消费的口径）。
func renderedHumanSecrets(t *testing.T) []string {
	t.Helper()
	cfg := services.GenerateCaddyConfig()
	if message, failed := cfg["__lazy_balancer_generation_error"].(string); failed {
		t.Fatalf("渲染失败: %s", message)
	}
	var secrets []string
	var walk func(any)
	walk = func(node any) {
		switch v := node.(type) {
		case map[string]any:
			if v["handler"] == "lb_human" {
				if secret, ok := v["secret"].(string); ok {
					secrets = append(secrets, secret)
				}
			}
			for _, child := range v {
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(cfg)
	return secrets
}

// Given 库内已有启动播种的密钥且渲染缓存已装载该值。
// When 导入携带异值 human_secret 的备份（系统数据分类，名单表缺席）。
// Then 提交后渲染产物的 lb_human.secret 必须是备份新值（缓存已失效重读）。
func TestImportConfigBackup_humanSecretChangeInvalidatesRenderCache(t *testing.T) {
	h := newBackupTestHandlers(t)
	stubHumanSecretRenderLibs(t)
	seedHumanSecretImportFixture(t)

	var oldSecret string
	if err := db.DB.QueryRow(`SELECT COALESCE(human_secret,'') FROM global_config WHERE id=1`).Scan(&oldSecret); err != nil {
		t.Fatalf("read seeded secret: %v", err)
	}
	if oldSecret == "" {
		t.Fatal("前置：启动必须已播种 human_secret")
	}
	// 预热缓存：渲染一次使进程缓存装载旧密钥（导入前运行态）。
	if got := renderedHumanSecrets(t); len(got) != 1 || got[0] != oldSecret {
		t.Fatalf("前置渲染 secret=%v, want [%s]", got, oldSecret)
	}

	const newSecret = "imported-human-secret-0123456789abcdef"
	backup := buildBackup(t, backupFixtureOptions{
		FillAll: true,
		Omit:    map[string]struct{}{"security_ip_lists": {}, "lb_rules": {}, "upstreams": {}, "security_policies": {}, "security_policy_bindings": {}},
		Config:  map[string]any{"human_secret": newSecret},
	})
	response := postBackupImport(t, h, backup)
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}

	var stored string
	if err := db.DB.QueryRow(`SELECT COALESCE(human_secret,'') FROM global_config WHERE id=1`).Scan(&stored); err != nil {
		t.Fatalf("read stored secret: %v", err)
	}
	if stored != newSecret {
		t.Fatalf("human_secret=%q, want %q（前置：密钥确实随导入落库）", stored, newSecret)
	}
	got := renderedHumanSecrets(t)
	if len(got) != 1 || got[0] != newSecret {
		t.Fatalf("导入后渲染 secret=%v, want [%s]（缓存未失效：运行配置与库分叉至重启）", got, newSecret)
	}
	if strings.Contains(strings.Join(got, ","), oldSecret) {
		t.Fatalf("渲染产物不得残留旧密钥 %s", oldSecret)
	}
}

// 对照组：备份未携带 human_secret → 密钥与渲染缓存不得被触碰。
func TestImportConfigBackup_humanSecretAbsentKeepsRenderCache(t *testing.T) {
	h := newBackupTestHandlers(t)
	stubHumanSecretRenderLibs(t)
	seedHumanSecretImportFixture(t)

	var oldSecret string
	if err := db.DB.QueryRow(`SELECT COALESCE(human_secret,'') FROM global_config WHERE id=1`).Scan(&oldSecret); err != nil {
		t.Fatalf("read seeded secret: %v", err)
	}
	if got := renderedHumanSecrets(t); len(got) != 1 || got[0] != oldSecret {
		t.Fatalf("前置渲染 secret=%v, want [%s]", got, oldSecret)
	}

	backup := buildBackup(t, backupFixtureOptions{
		FillAll: true,
		Omit:    map[string]struct{}{"security_ip_lists": {}, "lb_rules": {}, "upstreams": {}, "security_policies": {}, "security_policy_bindings": {}},
		Config:  map[string]any{"log_level": "info"},
	})
	response := postBackupImport(t, h, backup)
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if got := renderedHumanSecrets(t); len(got) != 1 || got[0] != oldSecret {
		t.Fatalf("未携带密钥的导入不得改变渲染 secret=%v, want [%s]", got, oldSecret)
	}
}
