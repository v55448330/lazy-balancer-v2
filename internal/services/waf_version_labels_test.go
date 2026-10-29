package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// 「同步开关关闭」告警走轻量比对：CRS/ip2region 只读两个小版本文件，威胁库
// 逐源读取紧凑的 .fast（16B 头 + 5B/v4），均不打包整棵规则树；内容级漂移
// 检测仍由 wafFilesRefDiffers 承担。

// 「同步开关关闭」告警的唯一生产路径必须覆盖威胁库段：仅威胁 .fast 更新
// （CRS/ip2region 版本标签不变）同样要产生「同步警告」——它是从节点威胁名单
// 陈旧的唯一信号。反向：三库一致时不得误报。
func TestSyncSwitchGuard_threatOnlyUpdateWarns(t *testing.T) {
	_, database := newClusterTestService(t)
	overrideWafPathsForServicesTest(t)
	threatDir := t.TempDir()
	t.Cleanup(OverrideThreatWafDirForTest(threatDir))
	fastPath := filepath.Join(threatDir, "threat-ustc.iplist.fast")
	if err := os.WriteFile(fastPath, []byte("local-stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE global_config SET applied_waf_ref_version=7 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	masterSum := sha256.Sum256([]byte("master-updated"))
	snapshot := models.ClusterSnapshot{
		Version: 8,
		// 版本标签留空=与本地文件无标签形态等价；唯一信号是威胁 .fast 内容。
		WafFiles: &models.ClusterWafFilesRef{ThreatSha256s: map[string]string{"ustc": hex.EncodeToString(masterSum[:])}},
	}
	sk := &sectionSkips{disabled: map[string]bool{"security": true}, unchanged: map[string]bool{}}

	logSyncSwitchGuards(context.Background(), database, snapshot, sk, SyncSwitches{})

	var action, detail string
	if err := db.AuditDB.QueryRow(`SELECT action,detail FROM audit_log WHERE resource='集群同步' ORDER BY id DESC LIMIT 1`).Scan(&action, &detail); err != nil {
		t.Fatalf("仅威胁库更新必须产生同步警告审计: %v", err)
	}
	if action != "同步警告" || !strings.Contains(detail, "威胁库") {
		t.Fatalf("审计 action=%q detail=%q, want 同步警告/威胁库", action, detail)
	}
	var applied int
	if err := database.QueryRow(`SELECT COALESCE(applied_waf_ref_version,0) FROM global_config WHERE id=1`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 8 {
		t.Fatalf("applied_waf_ref_version=%d, want 8", applied)
	}

	// 反向：本地威胁 .fast 与主端引用一致时不得误报（版本推进也不得刷告警）。
	if err := os.WriteFile(fastPath, []byte("master-updated"), 0o644); err != nil {
		t.Fatal(err)
	}
	var before int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='同步警告'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	snapshot.Version = 9
	logSyncSwitchGuards(context.Background(), database, snapshot, sk, SyncSwitches{})
	var after int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='同步警告'`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("三库一致时告警条数 %d→%d，不得误报", before, after)
	}
}

func TestWafFilesRefVersionLabelsDiffer_labelsOnly(t *testing.T) {
	dir := t.TempDir()
	t.Cleanup(OverrideWafLivePathsForTest(dir, filepath.Join(dir, "ip2region.xdb")))

	if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte("v4.28.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ip2regionLivePath+".version", []byte("2026.09.24"), 0644); err != nil {
		t.Fatal(err)
	}

	same := &models.ClusterWafFilesRef{CRSVersion: "v4.28.0", IP2RegionTag: "2026.09.24"}
	if wafFilesRefVersionLabelsDiffer(same) {
		t.Fatal("版本标签一致时不得判分叉")
	}

	bumped := &models.ClusterWafFilesRef{CRSVersion: "v4.29.0"}
	if !wafFilesRefVersionLabelsDiffer(bumped) {
		t.Fatal("主节点 CRS 版本变化必须触发告警")
	}

	// 只有整树哈希（旧主端/手工构造，无版本标签、无威胁哈希）→ 无可判定信号：
	// 不判分叉（避免用整树哈希回退，代价正是本告警要避免的全树打包）。
	hashesOnly := &models.ClusterWafFilesRef{CRSSha256: "deadbeef"}
	if wafFilesRefVersionLabelsDiffer(hashesOnly) {
		t.Fatal("无版本标签且无威胁哈希时不得误报分叉")
	}
	if wafFilesRefVersionLabelsDiffer(nil) {
		t.Fatal("nil 引用不得判分叉")
	}

	// 威胁库段：ref 逐源声明 .fast 哈希时必须比对本地内容——仅威胁库更新
	// （两个版本标签都不变）也必须判分叉；本地缺失同源文件同样判分叉。
	oldWaf := OverrideThreatWafDirForTest(t.TempDir())
	t.Cleanup(oldWaf)
	threatDir := WafDir()
	ustcPath := filepath.Join(threatDir, "threat-ustc.iplist.fast")
	if err := os.WriteFile(ustcPath, []byte("new-threat-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("new-threat-bytes"))
	threatOnly := &models.ClusterWafFilesRef{ThreatSha256s: map[string]string{"ustc": hex.EncodeToString(sum[:])}}
	if wafFilesRefVersionLabelsDiffer(threatOnly) {
		t.Fatal("威胁 .fast 内容一致时不得判分叉")
	}
	threatBumped := &models.ClusterWafFilesRef{ThreatSha256s: map[string]string{"ustc": "deadbeef"}}
	if !wafFilesRefVersionLabelsDiffer(threatBumped) {
		t.Fatal("仅威胁库内容变化必须判分叉（同族第三段被引用面）")
	}
	threatMissing := &models.ClusterWafFilesRef{ThreatSha256s: map[string]string{"firehol1": "deadbeef"}}
	if !wafFilesRefVersionLabelsDiffer(threatMissing) {
		t.Fatal("本地缺失主端声明的威胁源必须判分叉")
	}
}

// 告警去重版本的推进失败必须留痕：该列是「每版本 bump 至多一条告警」的唯一
// 依据，静默失败会让同一告警按 apply 轮重复刷审计且无信号解释——正是本函数
// 读失败分支注释要防的形态。
func TestSyncSwitchGuard_dedupVersionWriteFailureIsVisible(t *testing.T) {
	_, database := newClusterTestService(t)
	overrideWafPathsForServicesTest(t)
	threatDir := t.TempDir()
	t.Cleanup(OverrideThreatWafDirForTest(threatDir))
	if err := os.WriteFile(filepath.Join(threatDir, "threat-ustc.iplist.fast"), []byte("local-stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE global_config SET applied_waf_ref_version=7 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`CREATE TRIGGER fail_dedup_version BEFORE UPDATE OF applied_waf_ref_version ON global_config
		BEGIN SELECT RAISE(ABORT, '注入的去重版本写失败'); END;`); err != nil {
		t.Fatalf("create failure trigger: %v", err)
	}
	masterSum := sha256.Sum256([]byte("master-updated"))
	snapshot := models.ClusterSnapshot{
		Version:  8,
		WafFiles: &models.ClusterWafFilesRef{ThreatSha256s: map[string]string{"ustc": hex.EncodeToString(masterSum[:])}},
	}
	sk := &sectionSkips{disabled: map[string]bool{"security": true}, unchanged: map[string]bool{}}

	var buffer strings.Builder
	oldWriter := log.Writer()
	log.SetOutput(&buffer)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	logSyncSwitchGuards(context.Background(), database, snapshot, sk, SyncSwitches{})

	if !strings.Contains(buffer.String(), "推进文件态告警去重版本失败") {
		t.Fatalf("推进失败必须留痕（否则重复告警无解释）: %q", buffer.String())
	}
	// 告警本身仍须落审计（推进失败只影响去重，不影响告警的事实）。
	var action string
	if err := db.AuditDB.QueryRow(`SELECT action FROM audit_log WHERE resource='集群同步' ORDER BY id DESC LIMIT 1`).Scan(&action); err != nil {
		t.Fatalf("告警审计缺失: %v", err)
	}
	if action != "同步警告" {
		t.Fatalf("audit action=%q, want 同步警告", action)
	}
	var applied int
	if err := database.QueryRow(`SELECT COALESCE(applied_waf_ref_version,0) FROM global_config WHERE id=1`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 7 {
		t.Fatalf("applied_waf_ref_version=%d, want 7（写失败保持旧值）", applied)
	}
}
