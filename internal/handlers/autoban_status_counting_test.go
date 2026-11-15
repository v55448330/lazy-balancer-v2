package handlers

// status API 证据分层字段契约：counting_mode/suspicion_multiplier/
// confirm_floor_ratio/list_id 恒有键；suggestions 行双分数（classic=count/0）。

import (
	"encoding/json"
	"net/http"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func TestAutobanStatus_carriesEvidenceCountingFields(t *testing.T) {
	router := newAutobanTestEnv(t)
	// 设 evidence 配置（经 PUT 链，含归一/校验）。
	putJSON(t, router, "/security/autoban", map[string]any{
		"enabled": true, "threshold": 50, "window_minutes": 5, "duration": "1h",
		"scope": "blocked,logged,challenge_issued,challenge_failed", "dry_run": true,
		"escalation": "standard", "counting_mode": "evidence",
		"suspicion_multiplier": 8, "confirm_floor_ratio": "0.6",
	})
	rec := getRequest(t, router, "/security/autoban/status")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			CountingMode        string `json:"counting_mode"`
			SuspicionMultiplier int    `json:"suspicion_multiplier"`
			ConfirmFloorRatio   string `json:"confirm_floor_ratio"`
			ListID              int64  `json:"list_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.CountingMode != "evidence" || resp.Data.SuspicionMultiplier != 8 || resp.Data.ConfirmFloorRatio != "0.6" {
		t.Fatalf("evidence fields=%+v, want evidence/8/0.6", resp.Data)
	}
	if resp.Data.ListID <= 0 {
		t.Fatalf("list_id=%d, want 预置名单正整数 id", resp.Data.ListID)
	}
}

func TestAutobanStatus_classicDefaultsAndSuggestionScores(t *testing.T) {
	router := newAutobanTestEnv(t)
	rec := getRequest(t, router, "/security/autoban/status")
	var resp struct {
		Data struct {
			CountingMode        string                       `json:"counting_mode"`
			SuspicionMultiplier int                          `json:"suspicion_multiplier"`
			ConfirmFloorRatio   string                       `json:"confirm_floor_ratio"`
			Suggestions         []services.AutobanSuggestion `json:"suggestions"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.CountingMode != db.DefaultAutobanCountingMode ||
		resp.Data.SuspicionMultiplier != db.DefaultAutobanSuspicionMultiplier ||
		resp.Data.ConfirmFloorRatio != db.DefaultAutobanConfirmFloorRatio {
		t.Fatalf("classic defaults=%+v", resp.Data)
	}
	// 建议行恒携带双分数键（classic 投影 confirmed=count/suspicion=0）。
	for _, s := range resp.Data.Suggestions {
		if s.SuspicionCount != 0 || s.ConfirmedCount != s.Count {
			t.Fatalf("classic suggestion scores confirmed=%d suspicion=%d count=%d, want count/0/count", s.ConfirmedCount, s.SuspicionCount, s.Count)
		}
	}
}
