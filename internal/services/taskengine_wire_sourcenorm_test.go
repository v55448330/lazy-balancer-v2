package services

// 启动归一（源表族）的两条契约：
//   - 归一告警必须写进该任务**注册 ID** 的任务日志，不得产生未注册 ID 的游离文件；
//   - 活动态判定单源（sourceUpdateStatusRunning）：词表外状态不得被归一改动。

import (
	"os"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/taskengine"
)

// Given 威胁源表残留「更新中」行（上次进程在更新中退出）。
// When 启动归一。
// Then 归一行写入注册 ID `threat` 的任务日志（任务日志弹框可见），且不产生
// 未注册 ID `threat-update` 的游离日志文件。
func TestNormalizeInterruptedSourceStatusesLogsToRegisteredTaskID(t *testing.T) {
	_, database := newClusterTestService(t)
	newTaskLogDir(t)
	if _, err := database.Exec(`UPDATE security_threat_sources SET update_status='running', message='正在下载' WHERE name='ustc'`); err != nil {
		t.Fatalf("seed threat active: %v", err)
	}

	normalizeInterruptedUpdateStatuses()

	body, err := os.ReadFile(taskengine.TaskLogPath("threat"))
	if err != nil {
		t.Fatalf("归一告警必须写入威胁任务（threat）的日志: %v", err)
	}
	if !strings.Contains(string(body), "残留「更新中」状态已归一") {
		t.Fatalf("威胁任务日志缺少归一告警行:\n%s", string(body))
	}
	if _, err := os.Stat(taskengine.TaskLogPath("threat-update")); !os.IsNotExist(err) {
		t.Fatalf("归一不得写入未注册 ID 的游离日志（tasks/threat-update.log）: err=%v", err)
	}
}

// Given 威胁源表存在活动词表外的状态（idle）。
// When 启动归一。
// Then 该行原样保留——活动态谓词单源（sourceUpdateStatusRunning），归一不得
// 按第二份词表扩大命中面。
func TestNormalizeInterruptedSourceStatusesIgnoresOutOfVocabularyStatus(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE security_threat_sources SET update_status='idle', message='空闲' WHERE name='ustc'`); err != nil {
		t.Fatalf("seed threat idle: %v", err)
	}

	normalizeInterruptedUpdateStatuses()

	var status, message string
	if err := database.QueryRow(`SELECT update_status, message FROM security_threat_sources WHERE name='ustc'`).Scan(&status, &message); err != nil {
		t.Fatalf("read threat row: %v", err)
	}
	if status != "idle" || message != "空闲" {
		t.Fatalf("词表外状态被归一改动: %q/%q, want idle/空闲", status, message)
	}
}
