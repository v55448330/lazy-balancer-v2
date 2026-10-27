package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 对账是写路径（写 VERSION 标记 / 恢复快照 / 「校正」DB 版本行 + bump 集群
// 版本），版本读取必须失败可见：展示容错口径（读失败回落镜像捆绑版本）会在
// DB 瞬断时把 bundled 当权威写坏标记/版本行。
func TestReconcileCRSState_versionReadFailureSkipsWrites(t *testing.T) {
	setupIsolatedDB(t)
	liveDir := t.TempDir()
	oldLive, oldSnap := crsLiveDir, crsSnapshotDir
	crsLiveDir, crsSnapshotDir = liveDir, filepath.Join(t.TempDir(), "snapshot")
	t.Cleanup(func() { crsLiveDir, crsSnapshotDir = oldLive, oldSnap })

	// 版本行不可读（表缺失），角色行正常 → 必须在任何写入前跳过。
	if _, err := db.DB.Exec(`ALTER TABLE security_crs_version RENAME TO security_crs_version_offline`); err != nil {
		t.Fatal(err)
	}
	buf := captureLogf(t)

	ReconcileCRSState()

	if !strings.Contains(buf.String(), "版本记录读取失败") {
		t.Fatalf("版本读失败必须显式留痕并跳过: %q", buf.String())
	}
	if _, err := os.Stat(filepath.Join(liveDir, crsVersionFile)); !os.IsNotExist(err) {
		t.Fatalf("版本读失败不得写 VERSION 标记（err=%v）", err)
	}
}
