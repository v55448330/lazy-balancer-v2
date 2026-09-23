package services

import (
	"os"
	"path/filepath"
	"testing"
)

// 威胁情报库文件经 waf-files 通道同步（v2.3.x）：主端 ref 携带威胁目录哈希，
// bundle 携带文件内容；从端按通道内容落盘同一路径，幂等，漂移可检出；
// 主端关闭全部应用开关后 intel-merged.txt 删除须传播（从端停止 id:14 生效）。
func TestThreatFiles_wafBundleRoundTrip(t *testing.T) {
	// Given：主端威胁目录（两源文件 + 合并文件）
	masterDir := t.TempDir()
	for name, content := range map[string]string{
		"ustc.txt":         "203.0.113.1/32\n",
		"firehol_l1.txt":   "10.9.0.0/24\n",
		"intel-merged.txt": "10.9.0.0/24\n203.0.113.1/32\n",
	} {
		if err := os.WriteFile(filepath.Join(masterDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	oldDir := ThreatDataDir
	t.Cleanup(func() { ThreatDataDir = oldDir })
	ThreatDataDir = masterDir

	// When：主端 ref + bundle
	ref := BuildWafFileRef()
	if ref == nil || ref.ThreatSha256 == "" {
		t.Fatalf("ref=%+v, want 携带 threat_sha256", ref)
	}
	bundle := BuildWafFileBundle()
	if bundle == nil || len(bundle.ThreatFiles) != 3 {
		t.Fatalf("bundle 须携带 3 个威胁文件: %+v", bundle)
	}
	if bundle.ThreatSha256 != ref.ThreatSha256 {
		t.Fatal("bundle 声明哈希与 ref 不一致")
	}

	// 从端空目录应用
	slaveDir := t.TempDir()
	ThreatDataDir = slaveDir
	if _, _, err := ApplyWafFileBundle(bundle); err != nil {
		t.Fatalf("apply: %v", err)
	}
	for name, want := range bundle.ThreatFiles {
		got, err := os.ReadFile(filepath.Join(slaveDir, name))
		if err != nil || string(got) != want {
			t.Fatalf("从端文件 %s=%q err=%v, want %q", name, got, err, want)
		}
	}
	// 幂等：二次应用同值
	if _, _, err := ApplyWafFileBundle(bundle); err != nil {
		t.Fatalf("二次应用: %v", err)
	}
	// 漂移检出：从端文件被改
	if err := os.WriteFile(filepath.Join(slaveDir, "intel-merged.txt"), []byte("1.1.1.1/32\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !wafFilesRefDiffers(ref) {
		t.Fatal("从端文件分叉必须检出漂移")
	}
}

// 主端全关应用（无 intel-merged.txt 但有源文件）→ 从端陈旧的 intel-merged.txt
// 必须被移除（镜像主端为权威）。
func TestThreatFiles_applyRemovesStaleMergedFile(t *testing.T) {
	masterDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(masterDir, "ustc.txt"), []byte("203.0.113.1/32\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldDir := ThreatDataDir
	t.Cleanup(func() { ThreatDataDir = oldDir })
	ThreatDataDir = masterDir
	bundle := BuildWafFileBundle()
	if bundle == nil || len(bundle.ThreatFiles) != 1 {
		t.Fatalf("bundle 须仅携带 ustc.txt: %+v", bundle)
	}

	slaveDir := t.TempDir()
	// 从端残留：源文件 + 陈旧合并文件
	if err := os.WriteFile(filepath.Join(slaveDir, "intel-merged.txt"), []byte("9.9.9.9/32\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ThreatDataDir = slaveDir
	if _, _, err := ApplyWafFileBundle(bundle); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, err := os.Stat(filepath.Join(slaveDir, "intel-merged.txt")); !os.IsNotExist(err) {
		t.Fatal("主端无合并文件时从端陈旧 intel-merged.txt 必须移除")
	}
	if _, err := os.Stat(filepath.Join(slaveDir, "ustc.txt")); err != nil {
		t.Fatal("ustc.txt 须落盘")
	}
}

// CL9-N3 同族守卫：主端整个威胁目录不存在（从未更新）→ ref 无威胁哈希 →
// 从端残留文件不被触碰。
func TestThreatFiles_absentMasterDirLeavesSlaveAlone(t *testing.T) {
	oldDir := ThreatDataDir
	t.Cleanup(func() { ThreatDataDir = oldDir })
	ThreatDataDir = filepath.Join(t.TempDir(), "nonexistent")
	ref := BuildWafFileRef()
	// 无 CRS/xdb 且无威胁目录 → ref 为 nil 或 threat 哈希为空
	if ref != nil && ref.ThreatSha256 != "" {
		t.Fatalf("无威胁目录不得产出 threat 哈希: %+v", ref)
	}
}
