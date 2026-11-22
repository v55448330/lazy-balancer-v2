package notify

// 角色探测单次契约（性能项收尾）：入队路径此前
// shouldForwardClusterEvent 与 forwardEventToMaster 各探测一次（每事件 2 次
// SELECT）；现在快照随 job 传递，每事件恒 1 次。基线钉（钉既有正确行为，
// 按 R-1 豁免 RED；RED 证据= 审计实读的两处探测点）。

import (
	"testing"
	"time"
)

func TestPublish_probesClusterRoleOncePerEvent(t *testing.T) {
	_ = newNotifySchemaDB(t)
	overrideForwardSpoolDir(t, t.TempDir())
	var probes int
	old := clusterForwardRoleDetectorSnapshot()
	clusterForwardRoleMu.Lock()
	clusterForwardRoleDetector = func() (bool, string, string, string, error) {
		probes++
		return false, "http://127.0.0.1:1", "tok", "slave-x", nil
	}
	clusterForwardRoleMu.Unlock()
	t.Cleanup(func() {
		clusterForwardRoleMu.Lock()
		clusterForwardRoleDetector = old
		clusterForwardRoleMu.Unlock()
	})
	Publish(Event{Type: "cfg.caddy_apply_failed", Level: "warn", Body: "probe-count", Time: time.Now()})
	// 排空 worker：入队同步返回，转发异步——探测次数在入队时即已确定。
	if probes != 1 {
		t.Fatalf("每事件角色探测次数=%d，want 1（快照随 job 传递）", probes)
	}
}
