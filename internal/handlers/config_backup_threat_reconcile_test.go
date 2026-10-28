package handlers

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/services"
)

// 纯 JSON 备份（不带 lbbak 文件条目，payload==nil）同样会整表替换
// security_threat_sources：表里已不存在的源，本地 threat-*.iplist/.fast 必须
// 一起收敛——否则 DB 无记录而文件仍被 WAF 加载（记录与执行面分叉），集群
// ref 也会认为本端持有该源。
func TestReconcileImportedThreatFiles_prunesDeletedSourcesWithoutPayload(t *testing.T) {
	dir := t.TempDir()
	restore := services.OverrideThreatWafDirForTest(dir)
	defer restore()
	for _, name := range []string{"threat-removed.iplist", "threat-removed.iplist.fast", "threat-kept.iplist"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("1.2.3.4\n"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	tables := map[string][]map[string]any{
		"security_threat_sources": {{"name": "kept", "version": "v1", "update_status": "success"}},
	}

	// When：纯 JSON 备份导入（无随包文件）
	warnings, changed := reconcileImportedThreatFiles(tables, nil, nil)

	// Then：已删源的两份本地文件收敛；保留源的文件不动（纯 JSON 不含文件内容，
	// 无法判定其是否与记录一致，不得据此删除）。
	for _, name := range []string{"threat-removed.iplist", "threat-removed.iplist.fast"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s 必须被删除（源已不在导入表内），err=%v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "threat-kept.iplist")); err != nil {
		t.Fatalf("保留源的本地文件不得删除: %v", err)
	}
	if !changed {
		t.Fatalf("删除残留文件必须报告 changed=true（否则调用方不登记文件已落地）")
	}
	for _, warning := range warnings {
		if warning != "" {
			t.Logf("warning: %s", warning)
		}
	}
}

// 表缺席=保留本地现状：不携带 security_threat_sources 的导入不得碰任何文件。
func TestReconcileImportedThreatFiles_keepsLocalFilesWhenTableAbsent(t *testing.T) {
	dir := t.TempDir()
	restore := services.OverrideThreatWafDirForTest(dir)
	defer restore()
	if err := os.WriteFile(filepath.Join(dir, "threat-legacy.iplist"), []byte("1.2.3.4\n"), 0o644); err != nil {
		t.Fatalf("seed local file: %v", err)
	}

	warnings, changed := reconcileImportedThreatFiles(map[string][]map[string]any{}, nil, nil)

	if changed || len(warnings) != 0 {
		t.Fatalf("表缺席时必须零动作，changed=%v warnings=%v", changed, warnings)
	}
	if _, err := os.Stat(filepath.Join(dir, "threat-legacy.iplist")); err != nil {
		t.Fatalf("表缺席时本地文件不得删除: %v", err)
	}
}
