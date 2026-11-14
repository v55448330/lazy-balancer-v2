package handlers

// 威胁源表随备份全量替换时的文件收敛（删除空/缺席源的本地旧名单）发生在
// 事务提交之前——提交前失败回滚时，被收敛删除的本地 threat-*.iplist/.fast
// 必须同批回到导入前字节。快照覆盖不得以「包内携带文件条目」为前提：
// 只带 config.json 的 lbbak 包（或任何触发表替换的形态）同样会收敛删除。
// 注：纯 JSON（非 lbbak）导入的威胁源表在行准备阶段整表剔除、本地保留，
// 不触发收敛（TestPureJSONThreatPreviewMatchesImport 钉住）；本用例钉
// 「表替换发生」时的快照覆盖。

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func TestLbbakImport_threatReconcileWithoutFileEntriesRollbackRestoresLocalFiles(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedAdminShared(t)
	g := newBackupSectionRouter(h)
	wafDir := t.TempDir()
	t.Cleanup(services.OverrideThreatWafDirForTest(wafDir))
	preImport := []byte("198.51.100.250/32\n")
	preImportFast := []byte("PRE-IMPORT-FAST\n")
	if err := os.WriteFile(filepath.Join(wafDir, "threat-legacy.iplist"), preImport, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wafDir, "threat-legacy.iplist.fast"), preImportFast, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_threat_sources (id,name,display_name,url,format,update_enabled,apply_enabled,entry_count,version,update_status,message)
		VALUES (91,'legacy','本地威胁源','https://example.test/list.txt','plain',1,1,1,'v1','idle','')`); err != nil {
		t.Fatal(err)
	}
	// 包内只有 config.json（无 CRS/xdb/威胁文件条目）；源表不含 legacy →
	// 收敛删除其本地文件。另携带一条合法策略使包非零导入。
	backup := backupJSONFixture(t, map[string][]map[string]any{
		"security_threat_sources": {threatRowShared("firehol_l1")},
		"security_policies": {{
			"name": "pj-policy", "mode": "off", "policy_type": "stage1", "enabled": 1,
			"ip_acl_mode": "deny", "ip_acl_list": "[]", "ip_acl_enabled": 0,
		}},
	}, nil, []string{"security"})
	payload, err := buildLbbakPayload([]byte(backup), &services.WafFileBundle{})
	if err != nil {
		t.Fatal(err)
	}
	// CLI 预检拒绝：收敛已发生、事务尚未提交 → 回滚必须恢复文件。
	h.caddyService.SetCLIValidatorForTest(func([]byte) error { return errors.New("cli: reject import") })

	rec := postLbbakImport(g, t, payload, "")
	if rec.Code == http.StatusOK {
		t.Fatalf("import must fail, got 200 %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "已回退到导入前状态") {
		t.Fatalf("failure response must state the file rollback: %s", rec.Body.String())
	}
	// 文件面终态：本地名单逐字节回到导入前（不是「函数返回了错误」）。
	assertFileBytes(t, filepath.Join(wafDir, "threat-legacy.iplist"), preImport)
	assertFileBytes(t, filepath.Join(wafDir, "threat-legacy.iplist.fast"), preImportFast)
	// 数据库同批回滚：本地威胁源行仍在。
	var name string
	if err := db.DB.QueryRow(`SELECT name FROM security_threat_sources WHERE id=91`).Scan(&name); err != nil {
		t.Fatalf("local threat source row must survive rollback: %v", err)
	}
	if name != "legacy" {
		t.Fatalf("local threat source=%q, want legacy", name)
	}
}
