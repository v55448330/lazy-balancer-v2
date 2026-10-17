package handlers

import (
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
	backup := r55BackupJSONWithConfig(t, map[string][]map[string]any{
		"security_crs_version":       {{"id": 1, "version": "v4.28.0", "auto_update": 1}},
		"security_ip2region_version": {{"id": 1, "version": "v3.17.0", "auto_update": 1}},
	}, map[string]any{
		"threat_auto_update":  true,
		"crawler_auto_update": true,
		"auto_backup_enabled": true,
		"autoban_enabled":     true,
	})

	// When：导入提交成功。
	response := r55Post(t, h.ImportConfigBackup, "/config/import", backup)
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
