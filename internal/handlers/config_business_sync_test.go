package handlers

import (
	"lazy-balancer-v2/internal/db"
	"net/http"
	"testing"

	"lazy-balancer-v2/internal/services"
)

func TestImportConfigBackup_realignsBusinessTaskLoops(t *testing.T) {
	// Given：六个业务驱动任务均处于停止态，备份则全部启用。
	h := newBackupTestHandlers(t)
	initTaskEngineForTest(t)
	te := services.TaskEngine()
	for _, id := range []string{"threat", "crs", "ip2region", "crawlerbot-update", "auto-backup", "autoban"} {
		te.StopLoop(id)
	}
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"security_crs_version":       {{"id": 1, "version": "v4.28.0", "auto_update": 1}},
		"security_ip2region_version": {{"id": 1, "version": "v3.17.0", "auto_update": 1}},
	}, Config: map[string]any{
		"threat_auto_update":  true,
		"crawler_auto_update": true,
		"auto_backup_enabled": true,
		"autoban_enabled":     true,
	}})

	// When：导入提交成功。
	response := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", response.Code, response.Body.String())
	}

	// Then：六任务立即按库内启用态恢复调度，无需重启或再次保存。
	for _, id := range []string{"threat", "crs", "ip2region", "crawlerbot-update", "auto-backup", "autoban"} {
		meta, ok := te.Lookup(id)
		if !ok || !meta.LoopOn {
			t.Errorf("%s 导入后 LoopOn=false，业务与调度失配", id)
		}
	}
}

func TestImportConfigBackup_disabledBusinessesKeepTaskLoopsStopped(t *testing.T) {
	h := newBackupTestHandlers(t)
	initTaskEngineForTest(t)
	te := services.TaskEngine()
	ids := []string{"threat", "crs", "ip2region", "crawlerbot-update", "auto-backup", "autoban"}
	for _, id := range ids {
		te.StartLoop(id)
	}
	if _, err := db.DB.Exec(`UPDATE security_crs_version SET auto_update=0 WHERE id=1;
		UPDATE security_ip2region_version SET auto_update=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"security_crs_version":       {{"id": 1, "version": "v4.28.0", "auto_update": 0}},
		"security_ip2region_version": {{"id": 1, "version": "v3.17.0", "auto_update": 0}},
	}, Config: map[string]any{
		"threat_auto_update":  false,
		"crawler_auto_update": false,
		"auto_backup_enabled": false,
		"autoban_enabled":     false,
	}})

	response := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", response.Code, response.Body.String())
	}
	for _, table := range []string{"security_crs_version", "security_ip2region_version"} {
		var autoUpdate int
		if err := db.DB.QueryRow(`SELECT auto_update FROM ` + table + ` WHERE id=1`).Scan(&autoUpdate); err != nil {
			t.Fatal(err)
		}
		if autoUpdate != 0 {
			t.Fatalf("%s.auto_update=%d, want 0（夹具未进入目标形态）", table, autoUpdate)
		}
	}
	for _, id := range ids {
		meta, ok := te.Lookup(id)
		if !ok || meta.LoopOn {
			t.Errorf("%s 全关备份导入后 LoopOn=true，禁用业务不得被同步器拉起", id)
		}
	}
}
