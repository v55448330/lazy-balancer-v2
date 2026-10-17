package services

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// seedTaskRunForTime 插入一条指定开始时刻的运行行，返回 RunID 与期望的
// UTC 存储时刻；task_runs 为配置时区墙钟，业务状态表统一存 UTC。
func seedTaskRunForTime(t *testing.T, taskID, wantStart string) (int64, string) {
	t.Helper()
	res, err := db.DB.Exec(`INSERT INTO task_runs (task_id,family,trigger,status,started_at)
		VALUES (?, 'security', 'manual', 'running', ?)`, taskID, wantStart)
	if err != nil {
		t.Fatal(err)
	}
	runID, _ := res.LastInsertId()
	instant, err := time.ParseInLocation(crsTimeLayout, wantStart, CurrentLocation())
	if err != nil {
		t.Fatal(err)
	}
	return runID, instant.UTC().Format(crsTimeLayout)
}
