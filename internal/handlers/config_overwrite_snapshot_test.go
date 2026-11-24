package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 导入/还原都是「整体覆盖配置」，而自动备份默认关闭——覆盖前不留任何退路。
// 本文件钉住覆盖前自动快照：文件导入与备份还原两条路径都必须在覆盖前落一份
// manual 快照；快照失败/并发在跑只能降级披露（导入照常执行），且该行必须能
// 反过来把配置恢复到覆盖前状态。

func seedPreOverwriteRule(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec("INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_pre_overwrite','pre-rule','http','pre-overwrite.example.test',18080,1)"); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec("INSERT INTO upstreams (rule_id,host,port,weight,enabled) VALUES ('lb_pre_overwrite','127.0.0.1',9001,1,1)"); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
}

func countRule(t *testing.T, caddyID string) int {
	t.Helper()
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id=?`, caddyID).Scan(&n); err != nil {
		t.Fatalf("count rule %s: %v", caddyID, err)
	}
	return n
}

// Given 覆盖前存在一条业务规则（自动备份默认关闭）。
// When 通过 /config/import 覆盖导入一份不含该规则的备份。
// Then 覆盖前已落一份 manual 快照：行/文件存在、message 披露来源、分类为全量，
// 且该行跨覆盖存活（auto_backups 不在备份面）。
func TestImportConfigBackup_snapshotsBeforeOverwrite(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	seedPreOverwriteRule(t)

	response := importBackupShared(h, t, buildBackup(t, backupFixtureOptions{FillAll: true, EmptyConfigIfNil: true}))
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if warnings := decodeImportWarnings(t, response); warningsContain(warnings, "覆盖前自动快照未生成") {
		t.Fatalf("快照应成功，warnings 不应含失败披露: %v", warnings)
	}

	rows := autoBackupRows(t, "WHERE trigger_type='manual' AND status='success'")
	if len(rows) != 1 {
		t.Fatalf("覆盖前快照行=%d, want 1（rows=%v）", len(rows), rows)
	}
	message, _ := rows[0]["message"].(string)
	if !strings.Contains(message, "覆盖前自动快照") || !strings.Contains(message, "导入") {
		t.Fatalf("message=%q, want 含「覆盖前自动快照」与触发动作「导入」", message)
	}
	filename, _ := rows[0]["filename"].(string)
	info, err := os.Stat(filepath.Join(h.cfg.BackupDir, filename))
	if err != nil {
		t.Fatalf("快照文件 %s 缺失: %v", filename, err)
	}
	if size, _ := rows[0]["size_bytes"].(int64); size != info.Size() {
		t.Fatalf("行 size_bytes=%d, want 文件大小 %d", size, info.Size())
	}
	if sections, _ := rows[0]["sections"].(string); !strings.Contains(sections, "security") || !strings.Contains(sections, "rules") {
		t.Fatalf("快照分类=%q, want 全部分类（覆盖前退路必须完整）", sections)
	}
	if countRule(t, "lb_pre_overwrite") != 0 {
		t.Fatal("覆盖导入未生效：覆盖前规则仍在")
	}
	if got := len(autoBackupRows(t, "WHERE id=?", rows[0]["id"])); got != 1 {
		t.Fatalf("快照行未跨导入存活（auto_backups 应不在备份面）: %d", got)
	}
}

// Given 一条规则在覆盖前的配置里。
// When 覆盖导入后，用覆盖前快照还原。
// Then 配置回到覆盖前状态（该规则回归），且还原本身也留了新的覆盖前快照。
func TestImportConfigBackup_snapshotRestoresPreOverwriteConfig(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	seedPreOverwriteRule(t)

	response := importBackupShared(h, t, buildBackup(t, backupFixtureOptions{FillAll: true, EmptyConfigIfNil: true}))
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if countRule(t, "lb_pre_overwrite") != 0 {
		t.Fatal("覆盖导入未生效：覆盖前规则仍在")
	}
	rows := autoBackupRows(t, "WHERE trigger_type='manual' AND status='success'")
	if len(rows) != 1 {
		t.Fatalf("覆盖前快照行=%d, want 1", len(rows))
	}
	snapshotID := rows[0]["id"].(int64)

	restore := serveAutoBackupJSON(t, h, http.MethodPost, "/auto-backup/:id/restore", fmt.Sprintf("/auto-backup/%d/restore", snapshotID), "", h.RestoreAutoBackup)
	if restore.Code != http.StatusOK {
		t.Fatalf("restore status=%d body=%s, want 200", restore.Code, restore.Body.String())
	}
	if countRule(t, "lb_pre_overwrite") != 1 {
		t.Fatal("用覆盖前快照还原后规则未回归（快照未捕获覆盖前状态）")
	}
	if restores := autoBackupRows(t, "WHERE trigger_type='manual' AND status='success'"); len(restores) != 2 {
		t.Fatalf("还原自身也必须在覆盖前留快照：manual 行=%d, want 2", len(restores))
	}
}

// Given 快照写盘失败（磁盘故障）。
// When 覆盖导入。
// Then 导入仍成功（快照不阻断覆盖），但 warnings 显性披露失败原因且审计留痕。
func TestImportConfigBackup_snapshotFailureDisclosesAndContinues(t *testing.T) {
	withIsolatedGlobal(t)
	h := newAutoBackupTestHandlers(t)
	seedPreOverwriteRule(t)
	oldWrite := autoBackupWriteFile
	autoBackupWriteFile = func(string, []byte) error { return errors.New("disk full") }
	t.Cleanup(func() { autoBackupWriteFile = oldWrite })

	response := importBackupShared(h, t, buildBackup(t, backupFixtureOptions{FillAll: true, EmptyConfigIfNil: true}))
	if response.Code != http.StatusOK {
		t.Fatalf("快照失败不得阻断导入：status=%d body=%s", response.Code, response.Body.String())
	}
	warnings := decodeImportWarnings(t, response)
	if !warningsContain(warnings, "覆盖前自动快照未生成") || !warningsContain(warnings, "disk full") {
		t.Fatalf("warnings=%v, want 含快照失败披露与原因", warnings)
	}
	if countRule(t, "lb_pre_overwrite") != 0 {
		t.Fatal("导入未生效")
	}
	if rows := autoBackupRows(t, "WHERE status='success' AND trigger_type='manual'"); len(rows) != 0 {
		t.Fatalf("写盘失败不得留成功快照行: %v", rows)
	}
	if got := countAutoBackupAudit(t, "备份失败"); got != 1 {
		t.Fatalf("备份失败审计=%d, want 1（快照失败复用已登记动作词条）", got)
	}
	if detail := autoBackupAuditDetail(t, "备份失败"); !strings.Contains(detail, "覆盖前自动快照未生成") || !strings.Contains(detail, "disk full") {
		t.Fatalf("审计 detail=%q, want 含快照失败披露与原因", detail)
	}
}

// Given 已有备份任务在跑（备份域单飞锁被占）。
// When 覆盖导入。
// Then 快照跳过并披露（不排队、不阻断导入）。
func TestImportConfigBackup_snapshotSkippedWhenBackupRunning(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	seedPreOverwriteRule(t)
	if !autoBackupRunMu.TryLock() {
		t.Fatal("前置锁定失败")
	}
	defer autoBackupRunMu.Unlock()

	response := importBackupShared(h, t, buildBackup(t, backupFixtureOptions{FillAll: true, EmptyConfigIfNil: true}))
	if response.Code != http.StatusOK {
		t.Fatalf("并发跳过不得阻断导入：status=%d body=%s", response.Code, response.Body.String())
	}
	warnings := decodeImportWarnings(t, response)
	if !warningsContain(warnings, "覆盖前自动快照未生成") || !warningsContain(warnings, "已有备份任务正在执行") {
		t.Fatalf("warnings=%v, want 含「已有备份任务正在执行」披露", warnings)
	}
	if rows := autoBackupRows(t, "WHERE status='success' AND trigger_type='manual'"); len(rows) != 0 {
		t.Fatalf("并发跳过不得落快照行: %v", rows)
	}
}

// Given 规则库文件锁被在途更新/同步任务占用（导入的既有锁序契约是
// 「暂停/排空 → wafFileMu」，快照不得阻塞在该锁上）。
// When 覆盖导入（纯 JSON 备份，导入自身不需要文件相位）。
// Then 快照立刻放弃并披露，导入在**持锁期间**完成（阻塞取锁会永久挂住）。
func TestImportConfigBackup_snapshotSkippedWhenWafFilesBusy(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	seedPreOverwriteRule(t)
	services.WafFileLock().Lock()
	defer services.WafFileLock().Unlock()

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- importBackupShared(h, t, buildBackup(t, backupFixtureOptions{FillAll: true, EmptyConfigIfNil: true}))
	}()
	var response *httptest.ResponseRecorder
	select {
	case response = <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("导入被规则库文件锁挂住——快照必须在 wafFileMu 上非阻塞放弃")
	}
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200（快照跳过不阻断覆盖）", response.Code, response.Body.String())
	}
	if warnings := decodeImportWarnings(t, response); !warningsContain(warnings, "规则库文件正被更新或同步任务占用") {
		t.Fatalf("warnings=%v, want 含规则库文件锁占用的快照跳过披露", warnings)
	}
	if rows := autoBackupRows(t, "WHERE status='success' AND trigger_type='manual'"); len(rows) != 0 {
		t.Fatalf("规则库文件锁占用时不得落快照行: %v", rows)
	}
	if countRule(t, "lb_pre_overwrite") != 0 {
		t.Fatal("导入未生效")
	}
}
