package services

import (
	"context"
	"encoding/json"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// 从主端快照搬运的活动态任务行在从端归一为 failed：状态与文案之外，
// finished_at 必须以主端最后检查时刻收尾——否则页面呈现「已失败但未结束」，
// 任务监控耗时按当前时刻持续增长。
func TestApplySnapshot_activeTaskStateNormalizesFinishedAt(t *testing.T) {
	_, database := newClusterTestService(t)
	threatRows := []map[string]any{{
		"id": 1, "name": "ustc", "display_name": "USTC", "url": "https://example.test/ustc.txt",
		"format": "text", "update_enabled": true, "apply_enabled": true, "entry_count": 1,
		"version": "2026.10.24", "update_status": "running",
		"message": "主端进行中", "last_checked": "2026-10-24 10:00:00",
		"next_update": "2026-10-25 10:00:00", "trigger": "schedule",
		"started_at": "2026-10-24 09:59:00", "finished_at": nil,
		"consecutive_failures": 0, "created_at": "2026-10-01 00:00:00", "updated_at": "2026-10-24 10:00:00",
	}}
	threatJSON, err := json.Marshal(threatRows)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := models.ClusterSnapshot{
		Version: 1,
		SecurityCRSVersion: []models.ClusterSecurityCRSVersion{
			{
				ID: 1, Version: "v4.99", UpdateStatus: "downloading", Message: "主端下载中",
				LastChecked: "2026-10-24 10:00:00", StartedAt: "2026-10-24 09:59:00", FinishedAt: "",
			},
			{
				ID: 2, Version: "v4.98", UpdateStatus: "success", Message: "已完成",
				LastChecked: "2026-10-24 08:00:00", StartedAt: "2026-10-24 07:59:00", FinishedAt: "2026-10-24 08:00:00",
			},
		},
		SecurityThreatSources: json.RawMessage(threatJSON),
	}
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	// 活动态版本行：failed + 归一文案 + finished_at=主端 last_checked
	var status, message, startedAt, finishedAt string
	if err := database.QueryRow(`SELECT update_status, message, COALESCE(started_at,''), COALESCE(finished_at,'') FROM security_crs_version WHERE id=1`).
		Scan(&status, &message, &startedAt, &finishedAt); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || message != snapshotActiveUpdateStatusMessage {
		t.Fatalf("active version row=(%q,%q), want failed + 归一文案", status, message)
	}
	if finishedAt != "2026-10-24 10:00:00" {
		t.Fatalf("active version row finished_at=%q, want 主端 last_checked", finishedAt)
	}
	if startedAt != "2026-10-24 09:59:00" {
		t.Fatalf("active version row started_at=%q, want 主端开始时间", startedAt)
	}

	// 终态版本行原样保留（归一不得改写真实结果）
	if err := database.QueryRow(`SELECT update_status, message, COALESCE(finished_at,'') FROM security_crs_version WHERE id=2`).
		Scan(&status, &message, &finishedAt); err != nil {
		t.Fatal(err)
	}
	if status != "success" || message != "已完成" || finishedAt != "2026-10-24 08:00:00" {
		t.Fatalf("terminal version row=(%q,%q,%q), want 原样", status, message, finishedAt)
	}

	// 活动态威胁源行：同样以 last_checked 收尾
	if err := database.QueryRow(`SELECT update_status, message, COALESCE(finished_at,'') FROM security_threat_sources WHERE name='ustc'`).
		Scan(&status, &message, &finishedAt); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || message != snapshotActiveUpdateStatusMessage || finishedAt != "2026-10-24 10:00:00" {
		t.Fatalf("active threat source row=(%q,%q,%q), want failed + 归一文案 + last_checked", status, message, finishedAt)
	}
}
