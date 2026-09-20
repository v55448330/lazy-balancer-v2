package handlers

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// G（2026-09-20 用户裁定「配置收敛」）：导入含全局配置区但不含 oidc_config
// 键的备份（旧版本/未配置 OIDC 时导出）时，OIDC 配置随备份收敛清空——否则
// 出现「OIDC 启用（live 残留）+ 用户被备份替换清空」的不一致死态
// （PATCH 语义的 UPDATE 只写备份携带键，users 表却是整表替换）。
func TestImportBackup_oidcConfigConvergesWhenAbsent(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	g := gin.New()
	g.POST("/config/import", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("role", "admin")
		c.Set("username", "current-admin")
		h.ImportConfigBackup(c)
	})
	// live：OIDC 已启用 + OIDC 用户 + 本地管理员
	if _, err := db.DB.Exec(`UPDATE global_config SET oidc_config='{"enabled":true,"issuer":"https://idp.example.com","client_id":"lb","client_secret":"sec"}' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,auth_provider,oidc_subject,oidc_issuer) VALUES
		(1,'current-admin','hash','admin',1,'local','',''),
		(2,'oidc-user','', 'user',1,'oidc','sub-1','https://idp.example.com')`); err != nil {
		t.Fatal(err)
	}
	// 备份：含全局配置区（users 节）但 Config 无 oidc_config 键（旧版导出）
	backup := round40BackupJSON(t, []string{"users"}, map[string][]map[string]any{
		"users":      {{"id": 1, "username": "current-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}},
		"api_keys":   nil,
		"lb_rules":   {{"caddy_id": "imp1", "name": "imp", "protocol": "http", "domain": "a.example.com", "listen_port": 80, "enabled": 1}},
		"upstreams":  nil,
		"path_rules": nil,
	})

	rec := postJSONImport(t, g, backup)
	if rec.Code != http.StatusOK {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}
	// Then：OIDC 配置收敛清空（不残留「启用但零用户」死态）
	var oidcConfig string
	if err := db.DB.QueryRow(`SELECT COALESCE(oidc_config,'') FROM global_config WHERE id=1`).Scan(&oidcConfig); err != nil {
		t.Fatal(err)
	}
	if oidcConfig != "" {
		t.Fatalf("oidc_config must converge to empty when backup lacks it (got %q)", oidcConfig)
	}
	// 响应消息明示收敛
	if !strings.Contains(rec.Body.String(), "OIDC") {
		t.Fatalf("import result must mention OIDC convergence, body=%s", rec.Body.String()[:400])
	}
}

func TestImportBackup_oidcConfigPreservedWhenPresent(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	g := gin.New()
	g.POST("/config/import", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("role", "admin")
		c.Set("username", "current-admin")
		h.ImportConfigBackup(c)
	})
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'current-admin','hash','admin',1)`); err != nil {
		t.Fatal(err)
	}
	// 备份：Config 携带 oidc_config（新版导出）——按备份值应用，不得收敛清空
	payload := map[string][]map[string]any{
		"users":    {{"id": 1, "username": "current-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}},
		"lb_rules": {{"caddy_id": "imp1", "name": "imp", "protocol": "http", "domain": "a.example.com", "listen_port": 80, "enabled": 1}},
	}
	oidcCfg := map[string]any{"oidc_config": `{"enabled":true,"issuer":"https://idp2.example.com","client_id":"lb2","client_secret":"s2"}`}
	backup := configBackup{
		Meta:     configBackupMeta{App: "lazy-balancer-v2", Version: 2, ExportedAt: "2026-09-18T00:00:00Z"},
		Config:   oidcCfg,
		Tables:   payload,
		Sections: []string{"users"},
	}
	backup.Meta.Checksum = checksumBackupPayload(t, payload, oidcCfg)
	backupJSON := marshalJSONForTest(t, backup)

	rec := postJSONImport(t, g, backupJSON)
	if rec.Code != http.StatusOK {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}
	var oidcConfig string
	if err := db.DB.QueryRow(`SELECT COALESCE(oidc_config,'') FROM global_config WHERE id=1`).Scan(&oidcConfig); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(oidcConfig, "idp2.example.com") {
		t.Fatalf("oidc_config from backup must be applied (got %q)", oidcConfig)
	}
}
