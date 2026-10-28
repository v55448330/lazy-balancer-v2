package handlers

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

// lbbak 导入在事务提交前落盘 CRS 整树/xdb/威胁名单；提交（或提交内的 Caddy
// 校验）失败时数据库回滚，文件必须同批回到导入前状态——判据是真文件逐字节
// 比对，不是响应文案。
func TestLbbakImport_commitFailureRestoresWafFilesToPreImportBytes(t *testing.T) {
	// Given 一份可落盘的 CRS/xdb/威胁名单备份，与一份内容不同的导入前现场。
	h := newBackupTestHandlers(t)
	seedAdminShared(t)
	g := newBackupSectionRouter(h)
	t.Cleanup(services.ResetIP2RegionSearcherForTest)
	crsDir, xdbPath := overrideTestWafPaths(t)
	wafDir := t.TempDir()
	t.Cleanup(services.OverrideThreatWafDirForTest(wafDir))

	backupVERSION := []byte("v4.29.0\n")
	if err := os.WriteFile(filepath.Join(crsDir, "VERSION"), backupVERSION, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crsDir, "rules", "crs-setup.conf"), []byte("# backup-crs\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(xdbPath, validXdbBytes(t), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wafDir, "threat-ustc.iplist"), []byte("203.0.113.7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wafDir, "threat-ustc.iplist.fast"), []byte("BACKUP-FAST\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bundle := services.BuildWafFileBundle()
	if bundle == nil || len(bundle.CRSTarGz) == 0 || len(bundle.Xdb) == 0 || len(bundle.ThreatFiles) == 0 {
		t.Fatalf("夹具必须携带 CRS/xdb/威胁名单三面: %+v", bundle)
	}
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Sections: []string{"security"}, Tables: map[string][]map[string]any{
		"security_crs_version":       {{"id": 1, "version": "v4.29.0", "auto_update": 1}},
		"security_ip2region_version": {{"id": 1, "version": "xdb-backup", "auto_update": 1}},
		"security_threat_sources":    {{"name": "ustc", "display_name": "USTC", "url": "https://blackip.ustc.edu.cn/list.php?txt", "format": "plain", "update_enabled": 1, "apply_enabled": 1}},
	}, EmptyConfigIfNil: true})
	payload, err := buildLbbakPayload([]byte(backup), bundle)
	if err != nil {
		t.Fatal(err)
	}

	// 导入前现场：CRS 内容与 VERSION 都不同且多一个只属于本地的文件；xdb
	// 不存在；威胁名单文本与编译产物都与备份不同。VERSION 必须与包内字节不同，
	// 否则「回滚」与「导入已生效」在字节上不可区分。
	preImportVERSION := []byte("v0.9.9-preimport\n")
	preImportCRS := []byte("# pre-import-crs\n")
	preImportThreat := []byte("198.51.100.250/32\n")
	preImportFast := []byte("PRE-IMPORT-FAST\n")
	localOnlyContent := []byte("keep-me\n")
	localOnlyPath := filepath.Join(crsDir, "rules", "local-only.conf")
	if err := os.WriteFile(filepath.Join(crsDir, "rules", "crs-setup.conf"), preImportCRS, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crsDir, "VERSION"), preImportVERSION, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localOnlyPath, localOnlyContent, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(xdbPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wafDir, "threat-ustc.iplist"), preImportThreat, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wafDir, "threat-ustc.iplist.fast"), preImportFast, 0o644); err != nil {
		t.Fatal(err)
	}
	// Caddy 预检拒绝：WAF 文件已落盘、事务尚未提交。
	h.caddyService.SetCLIValidatorForTest(func([]byte) error { return errors.New("cli: reject import") })
	versionRowCountsBefore := map[string]int{}
	versionValuesBefore := map[string]string{}
	readVersionRow := func(table string) (int, string) {
		t.Helper()
		var count int
		if err := db.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		var value string
		if err := db.DB.QueryRow("SELECT COALESCE((SELECT version FROM " + table + " ORDER BY id LIMIT 1),'')").Scan(&value); err != nil {
			t.Fatal(err)
		}
		return count, value
	}
	for _, table := range []string{"security_crs_version", "security_ip2region_version"} {
		versionRowCountsBefore[table], versionValuesBefore[table] = readVersionRow(table)
	}
	// 夹具自检：两份版本表的导入前值与包内值必须可区分，行数 1→1 形态下
	// 只有值级断言能发现「导入已提交而文件已回退」的分裂。
	if versionValuesBefore["security_crs_version"] == "v4.29.0" || versionValuesBefore["security_ip2region_version"] == "xdb-backup" {
		t.Fatalf("pre-import version values=%v 与包内值相同，断言不可判别", versionValuesBefore)
	}

	// When
	response := postLbbakImport(g, t, payload, "")

	// Then 响应显式说明文件已回退（不得谎报分裂，也不得静默）。
	if response.Code == http.StatusOK {
		t.Fatalf("import must fail, got 200 %s", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "已回退到导入前状态") {
		t.Fatalf("failure response must state the file rollback: %s", response.Body.String())
	}
	if strings.Contains(response.Body.String(), "可能分裂") {
		t.Fatalf("rollback succeeded, response must not claim split: %s", response.Body.String())
	}
	// CRS 整树逐字节回到导入前（含仅存在于导入前的本地文件与不同内容）。
	assertFileBytes(t, filepath.Join(crsDir, "rules", "crs-setup.conf"), preImportCRS)
	assertFileBytes(t, localOnlyPath, localOnlyContent)
	assertFileBytes(t, filepath.Join(crsDir, "VERSION"), preImportVERSION)
	// 导入前不存在的 xdb 与其版本标记必须被删除回「不存在」。
	if _, err := os.Stat(xdbPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("xdb must be absent again after rollback, err=%v", err)
	}
	if _, err := os.Stat(xdbPath + ".version"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("xdb .version must be absent again after rollback, err=%v", err)
	}
	// 威胁名单文本与编译产物逐字节回到导入前。
	assertFileBytes(t, filepath.Join(wafDir, "threat-ustc.iplist"), preImportThreat)
	assertFileBytes(t, filepath.Join(wafDir, "threat-ustc.iplist.fast"), preImportFast)
	// 数据库同样已回滚：版本表行数与**值**都与导入前一致（不残留导入行，也不
	// 丢本地行）。行数可能是 1→1 的恒等形态，必须比对值。
	for _, table := range []string{"security_crs_version", "security_ip2region_version"} {
		count, value := readVersionRow(table)
		if count != versionRowCountsBefore[table] {
			t.Fatalf("%s rows=%d after rollback, want pre-import %d", table, count, versionRowCountsBefore[table])
		}
		if value != versionValuesBefore[table] {
			t.Fatalf("%s version=%q after rollback, want pre-import %q", table, value, versionValuesBefore[table])
		}
	}
}

// 导入成功后快照必须被丢弃：临时快照目录不得残留（含字节副本）。
func TestLbbakImport_successDiscardsWafSnapshot(t *testing.T) {
	withIsolatedGlobal(t)
	// Given 一个可成功导入的 xdb 备份与可观测的快照目录。
	h := newBackupTestHandlers(t)
	g := newBackupSectionRouter(h)
	t.Cleanup(services.ResetIP2RegionSearcherForTest)
	_, xdbPath := overrideTestWafPaths(t)
	snapshotRoot := t.TempDir()
	previous := newLbbakWafFileSnapshotDir
	newLbbakWafFileSnapshotDir = func() (string, error) { return os.MkdirTemp(snapshotRoot, "snapshot-") }
	t.Cleanup(func() { newLbbakWafFileSnapshotDir = previous })

	payload := buildTestLbbak(t, completeBackupJSON(t, map[string][]map[string]any{
		"security_ip2region_version": {{"id": 1, "version": "good-xdb", "auto_update": 1}},
	}), validXdbBytes(t))

	// When
	response := postLbbakImport(g, t, payload, "")

	// Then 导入成功、xdb 落盘，且快照目录已被清理。
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if _, err := os.Stat(xdbPath); err != nil {
		t.Fatalf("xdb must land on success: %v", err)
	}
	entries, err := os.ReadDir(snapshotRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("snapshot dirs left after successful import: %v", names)
	}
}

// 失败提示必须区分三态：确定回滚+已回退 / 确定回滚+回退失败或未回退 /
// 提交结果不确定（文件保持导入后状态）。分叉可见性不得回退到固定文案，也不得
// 在不确定态断言「一致」。
func TestLbbakWafRollbackWarning_distinguishesRestoredFromSplit(t *testing.T) {
	if got := lbbakWafRollbackWarning(false, false, nil, false); got != "" {
		t.Fatalf("no landed file must produce no warning, got %q", got)
	}
	restored := lbbakWafRollbackWarning(true, true, nil, false)
	if !strings.Contains(restored, "已回退到导入前状态") || strings.Contains(restored, "可能分裂") {
		t.Fatalf("restored warning=%q, want rollback confirmed without split claim", restored)
	}
	split := lbbakWafRollbackWarning(true, true, errors.New("boom"), false)
	if !strings.Contains(split, "回退失败") || !strings.Contains(split, "可能分裂") {
		t.Fatalf("failed rollback warning=%q, must expose the split", split)
	}
	legacy := lbbakWafRollbackWarning(true, false, nil, false)
	if !strings.Contains(legacy, "可能分裂") {
		t.Fatalf("unattempted rollback warning=%q, must expose the split", legacy)
	}
	// 提交结果不确定：不断言一致、不断言已回退，给人工核对指引。
	indeterminate := lbbakWafRollbackWarning(true, false, nil, true)
	for _, want := range []string{"提交结果不确定", "未回退", "核对"} {
		if !strings.Contains(indeterminate, want) {
			t.Fatalf("indeterminate warning=%q, must contain %q", indeterminate, want)
		}
	}
	for _, forbidden := range []string{"已回退到导入前状态", "（文件与版本记录一致）"} {
		if strings.Contains(indeterminate, forbidden) {
			t.Fatalf("indeterminate warning=%q, must not claim %q（结论不得超出可断言范围）", indeterminate, forbidden)
		}
	}
	// 提交不确定但文件未落盘：无文件面结论可言（库侧不确定由正文阶段描述承担）。
	if got := lbbakWafRollbackWarning(false, false, nil, true); got != "" {
		t.Fatalf("indeterminate commit without landed files must produce no file warning, got %q", got)
	}
}

// 提交结果不确定（tx.Commit 报错）时文件回退必须不执行：文件保持导入后状态，
// 快照丢弃，结论由响应/审计按不确定态给出。对照形态（确定回滚）仍逐字节回退。
func TestLbbakImport_indeterminateCommitKeepsWafFiles(t *testing.T) {
	t.Run("indeterminate_commit_keeps_imported_files", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		crsDir, _ := overrideTestWafPaths(t)
		rulePath := filepath.Join(crsDir, "rules", "crs-setup.conf")
		preImport := []byte("# pre-import-crs\n")
		if err := os.WriteFile(rulePath, preImport, 0o644); err != nil {
			t.Fatal(err)
		}
		snapshot, err := snapshotLbbakWafTargets(&lbbakPayload{CRSTarGz: []byte("x")}, false)
		if err != nil || snapshot == nil {
			t.Fatalf("snapshot: %v (nil=%v)", err, snapshot == nil)
		}
		snapshotRoot := snapshot.root
		// 导入落盘后的现场（事务提交前）。
		imported := []byte("# imported-crs\n")
		if err := os.WriteFile(rulePath, imported, 0o644); err != nil {
			t.Fatal(err)
		}

		session := &configImportSession{h: h, wafSnapshot: snapshot, commitIndeterminate: true}
		_ = session.abort(errors.New("数据库提交结果不确定：disk I/O error"))

		// Then 文件未被回退（不确定态禁止制造确定分叉），快照已丢弃。
		assertFileBytes(t, rulePath, imported)
		if session.wafRestoreAttempted {
			t.Fatal("提交结果不确定时不得执行文件回退（回退只在确定回滚时执行）")
		}
		if _, err := os.Stat(snapshotRoot); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("快照目录必须被丢弃, stat err=%v", err)
		}
		if got := lbbakWafRollbackWarning(true, session.wafRestoreAttempted, session.wafRestoreErr, session.commitIndeterminate); !strings.Contains(got, "提交结果不确定") {
			t.Fatalf("失败响应文件面提示=%q, want 不确定态", got)
		}
	})

	t.Run("determinate_failure_restores_pre_import_files", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		crsDir, _ := overrideTestWafPaths(t)
		rulePath := filepath.Join(crsDir, "rules", "crs-setup.conf")
		preImport := []byte("# pre-import-crs\n")
		if err := os.WriteFile(rulePath, preImport, 0o644); err != nil {
			t.Fatal(err)
		}
		snapshot, err := snapshotLbbakWafTargets(&lbbakPayload{CRSTarGz: []byte("x")}, false)
		if err != nil || snapshot == nil {
			t.Fatalf("snapshot: %v (nil=%v)", err, snapshot == nil)
		}
		if err := os.WriteFile(rulePath, []byte("# imported-crs\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		session := &configImportSession{h: h, wafSnapshot: snapshot}
		_ = session.abort(errors.New("caddy 校验失败"))

		assertFileBytes(t, rulePath, preImport)
		if !session.wafRestoreAttempted || session.wafRestoreErr != nil {
			t.Fatalf("确定回滚必须执行文件回退（attempted=%v err=%v）", session.wafRestoreAttempted, session.wafRestoreErr)
		}
		if got := lbbakWafRollbackWarning(true, session.wafRestoreAttempted, session.wafRestoreErr, session.commitIndeterminate); !strings.Contains(got, "已回退到导入前状态") {
			t.Fatalf("确定回滚+回退成功的文件面提示=%q, want 一致态", got)
		}
	})
}

// assertFileBytes 逐字节断言文件内容（真文件比对）。
func assertFileBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s bytes=%q, want %q", path, got, want)
	}
}
