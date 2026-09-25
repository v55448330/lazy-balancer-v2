package handlers

// 第 56 轮修复钉测试（F8/F4，用户裁定按建议处理）：
// ①审计日志畸形时间筛选改 400——此前静默丢弃条件返回全量，用户误以为在过滤；
// ②RunAutoBackupOnce 返回本次备份行视图（TryLock 持有区内取，并发手动备份
//   不再回查「最新 manual 行」取到他人行）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestGetAuditLogs_invalidTimeFilterRejected(t *testing.T) {
	router := newAuditLogTestRouter(t, `
		INSERT INTO audit_log (username, action, resource, detail, ip_address, created_at) VALUES
		('admin', '登录成功', '用户认证', '登录成功', '10.0.0.1', '2026-08-01 00:00:00')`)

	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/audit-logs?start_time=not-a-date", nil))

	if resp.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（畸形时间筛选不得静默忽略返回全量）", resp.Code, resp.Body.String())
	}
}

func TestRunAutoBackupOnce_returnsCreatedRowView(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	// When
	view, err := h.RunAutoBackupOnce("manual", "system")
	if err != nil {
		t.Fatalf("RunAutoBackupOnce: %v", err)
	}
	// Then：本次创建行的视图直接返回（Filename/ID 非零，供调用方免回查）
	if view.ID == 0 || view.Filename == "" {
		t.Fatalf("view=%+v, want 本次创建行（ID/Filename 非零）", view)
	}
	var status, filename string
	if err := db.DB.QueryRow(`SELECT status, filename FROM auto_backups WHERE id=?`, view.ID).Scan(&status, &filename); err != nil {
		t.Fatal(err)
	}
	if status != "success" || filename != view.Filename {
		t.Fatalf("DB 行=(%s,%s), view=(success,%s)", status, filename, view.Filename)
	}
	// JSON 形态（前端消费面）可序列化
	if _, err := json.Marshal(view); err != nil {
		t.Fatalf("marshal view: %v", err)
	}
}
