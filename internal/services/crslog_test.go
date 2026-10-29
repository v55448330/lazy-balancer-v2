package services

import (
	"os"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// 旧 crs-update.log 已退役——WriteCRSUpdateLog 唯一落点=
// tasks/crs.log（tee 单点；收敛后写口导出、无 Append* 别名）。
// 本钉测双守卫：①单点写入口径（曾双写）恰 1 行/次；②旧文件不再产生。
func TestWriteCRSUpdateLog_singleSinkNoDoubleTee(t *testing.T) {
	dir := t.TempDir()
	taskengine.SetLogDir(dir)
	t.Cleanup(func() { taskengine.SetLogDir("") })

	// When: 唯一写口写一条
	WriteCRSUpdateLog("INFO", "sync", "集群同步回放规则库")
	WriteCRSUpdateLog("INFO", "sync", "集群同步回放规则库")

	data, _ := os.ReadFile(taskengine.TaskLogPath("crs"))
	content := string(data)
	n := strings.Count(content, "集群同步回放规则库")
	if n != 2 {
		t.Fatalf("两次写入应恰 2 行（曾双写为 4），got %d:\n%s", n, content)
	}
}

// taskLogsHousekeeping 只做保留期清理；尺寸滚动已统一归写入前检查，
// 不再由每日巡检二次滚动。
func TestTaskLogsHousekeeping_retentionOnlyDoesNotRotate(t *testing.T) {
	setupIsolatedDB(t)
	if _, err := db.DB.Exec("UPDATE global_config SET task_log_size_mb = 1 WHERE id = 1"); err != nil {
		t.Fatal(err)
	}
	InvalidateTaskLogSizeCache()
	t.Cleanup(InvalidateTaskLogSizeCache)

	logsDir := t.TempDir()
	tasksDir := logsDir + "/tasks"
	if err := os.MkdirAll(tasksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// 2MB 文件（>1MB 配置阈值）
	if err := os.WriteFile(tasksDir+"/probe.log", []byte(strings.Repeat("x", 2*1024*1024)), 0644); err != nil {
		t.Fatal(err)
	}

	taskLogsHousekeeping(logsDir + "/app.log")

	if _, err := os.Stat(tasksDir + "/probe.log.1"); !os.IsNotExist(err) {
		t.Fatalf("保留期清理不得再做尺寸滚动: err=%v", err)
	}
}

// 收尾：certjobs/ 尺寸轮转归写入侧预写入轮转
// 单一负责（5 代移位），housekeeping 对 certjobs/ 只做保留期清理、不做尺寸轮转——
// 否则孤儿超阈活动文件会被 rename 覆盖 .1 代际（双轨覆盖丢史窗口的残留面）。
func TestTaskLogsHousekeeping_certjobsExemptFromSizeRotation(t *testing.T) {
	setupIsolatedDB(t)
	if _, err := db.DB.Exec("UPDATE global_config SET task_log_size_mb = 1 WHERE id = 1"); err != nil {
		t.Fatal(err)
	}
	InvalidateTaskLogSizeCache()
	t.Cleanup(InvalidateTaskLogSizeCache)

	logsDir := t.TempDir()
	// 清理面取 CertJobLogDir（与写入侧同源）——必须注入任务日志目录，否则
	// 用例播种的 certjobs 目录不在扫描面内，「不尺寸轮转」断言会空转。
	oldTaskLogDir := taskengine.LogDir()
	taskengine.SetLogDir(logsDir + "/tasks")
	t.Cleanup(func() { taskengine.SetLogDir(oldTaskLogDir) })
	certDir := CertJobLogDir()
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// 孤儿超阈活动文件 + 既有 .1 代际（双轨窗口的历史形态）
	if err := os.WriteFile(certDir+"/lb_orphan.log", []byte(strings.Repeat("x", 2*1024*1024)), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certDir+"/lb_orphan.log.1", []byte("GEN-1"), 0644); err != nil {
		t.Fatal(err)
	}

	taskLogsHousekeeping(logsDir + "/app.log")

	// Then: 不尺寸轮转——活动文件原位、.1 代际不被覆盖、无 .1.1 垃圾
	if _, err := os.Stat(certDir + "/lb_orphan.log"); err != nil {
		t.Fatalf("certjobs 活动文件不应被轮转移走: %v", err)
	}
	data, err := os.ReadFile(certDir + "/lb_orphan.log.1")
	if err != nil || string(data) != "GEN-1" {
		t.Fatalf("certjobs .1 代际不应被覆盖, err=%v 内容=%q", err, data)
	}
	if _, err := os.Stat(certDir + "/lb_orphan.log.1.1"); !os.IsNotExist(err) {
		t.Fatalf("不应产生 .1.1 垃圾文件")
	}
}
