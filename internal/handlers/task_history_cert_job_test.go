package handlers

// 任务历史 API 的 cert-job:<id> 分支：证书动态行无引擎 task_runs 记录，历史即
// cert_jobs 行本身——按 RunRecord 同形返回（started_at=created_at、
// finished_at=updated_at、duration=两者差、trigger=queue），时间戳由 UTC 转
// 配置时区墙串；不存在/非法的 id 走与相邻分支一致的错误口径而非 500。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

type taskHistoryResponse struct {
	Code int `json:"code"`
	Data struct {
		Runs []struct {
			ID         int64  `json:"id"`
			TaskID     string `json:"task_id"`
			Family     string `json:"family"`
			Trigger    string `json:"trigger"`
			Status     string `json:"status"`
			Message    string `json:"message"`
			StartedAt  string `json:"started_at"`
			FinishedAt string `json:"finished_at"`
			DurationMs int64  `json:"duration_ms"`
		} `json:"runs"`
	} `json:"data"`
}

func getTaskHistory(t *testing.T, handler gin.HandlerFunc, taskID string) (*httptest.ResponseRecorder, taskHistoryResponse) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/system/tasks/:id/history", handler)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/system/tasks/"+taskID+"/history", nil))
	var response taskHistoryResponse
	if recorder.Code == http.StatusOK {
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("decode response: %v body=%s", err, recorder.Body.String())
		}
	}
	return recorder, response
}

func useTaskHistoryShanghaiLocation(t *testing.T) {
	t.Helper()
	previous := services.CurrentLocation().String()
	if _, err := services.ConfigureLocation("Asia/Shanghai"); err != nil {
		t.Fatalf("configure location: %v", err)
	}
	t.Cleanup(func() {
		if previous == "CST" {
			previous = "Asia/Shanghai"
		}
		if _, err := services.ConfigureLocation(previous); err != nil {
			t.Errorf("restore location %q: %v", previous, err)
		}
	})
}

func TestGetSystemTaskHistory_mapsCertJobRowToRunRecord(t *testing.T) {
	h := newBackupTestHandlers(t)
	useTaskHistoryShanghaiLocation(t)

	// Given 一条已签发的证书任务行（UTC 时间戳）。
	result, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, message, created_at, updated_at)
		VALUES ('lb_hist','hist.example.test','issued','签发完成','2026-10-20T04:00:00Z','2026-10-20T04:00:05Z')`)
	if err != nil {
		t.Fatalf("seed cert job: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	// When
	recorder, response := getTaskHistory(t, h.GetSystemTaskHistory, "cert-job:"+strconv.FormatInt(jobID, 10))

	// Then 单行映射为 RunRecord 同形（时区墙串、duration、trigger=queue）。
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	if len(response.Data.Runs) != 1 {
		t.Fatalf("runs=%d, want 1（cert_jobs 行本身）", len(response.Data.Runs))
	}
	run := response.Data.Runs[0]
	if run.TaskID != "cert-job:"+strconv.FormatInt(jobID, 10) || run.Family != "cert-job" || run.Trigger != "queue" {
		t.Fatalf("run identity=(%q,%q,%q), want cert-job/queue", run.TaskID, run.Family, run.Trigger)
	}
	if run.Status != "issued" || run.Message != "签发完成" || run.ID != jobID {
		t.Fatalf("run=(%+v), want status/message/id 取自 cert_jobs 行", run)
	}
	if run.StartedAt != "2026-10-20 12:00:00" || run.FinishedAt != "2026-10-20 12:00:05" {
		t.Fatalf("时间墙串=(%q,%q), want 配置时区(+8)串", run.StartedAt, run.FinishedAt)
	}
	if run.DurationMs != 5000 {
		t.Fatalf("duration_ms=%d, want 5000", run.DurationMs)
	}
	recorder, response = getTaskHistory(t, h.GetSystemTaskHistory, "cert-job:%20"+strconv.FormatInt(jobID, 10))
	if recorder.Code != http.StatusOK || len(response.Data.Runs) != 1 {
		t.Fatalf("trimmed ID status=%d runs=%d, want 200/1", recorder.Code, len(response.Data.Runs))
	}
}

func TestGetSystemTaskHistory_certJobMissingAndInvalidIDs(t *testing.T) {
	h := newBackupTestHandlers(t)

	// Then 不存在的 job → 与相邻「任务不存在」分支同口径 404（不是 500/空 200）。
	recorder, _ := getTaskHistory(t, h.GetSystemTaskHistory, "cert-job:999999")
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("不存在 job status=%d body=%s, want 404", recorder.Code, recorder.Body.String())
	}

	// Then 非法 id → 400。
	recorder, _ = getTaskHistory(t, h.GetSystemTaskHistory, "cert-job:not-a-number")
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("非法 job id status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}

	// 回归形状：时间戳缺失时仍返回该行，duration=0 且时间列留空。
	result, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, message, created_at, updated_at)
		VALUES ('lb_hist2','hist2.example.test','queued','', NULL, NULL)`)
	if err != nil {
		t.Fatalf("seed cert job without timestamps: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	recorder, response := getTaskHistory(t, h.GetSystemTaskHistory, "cert-job:"+strconv.FormatInt(jobID, 10))
	if recorder.Code != http.StatusOK || len(response.Data.Runs) != 1 {
		t.Fatalf("缺失时间戳行 status=%d runs=%d, want 200/1", recorder.Code, len(response.Data.Runs))
	}
	if run := response.Data.Runs[0]; run.DurationMs != 0 || run.StartedAt != "" || run.FinishedAt != "" {
		t.Fatalf("缺失时间戳形态=(%+v), want 空时间列与 duration=0", run)
	}
}

// 平面 UTC 墙串（crsTimeLayout，空格分隔）形态：与 RFC3339 同权解析——
// 仅 RFC3339 的单布局解析在驱动/列表达式形态变化时静默归零（时间列空 +
// duration=0）。双布局单源=services.ParseUTCTimeDual。
func TestGetSystemTaskHistory_certJobFlatUTCLayout(t *testing.T) {
	h := newBackupTestHandlers(t)
	useTaskHistoryShanghaiLocation(t)

	// Given 平面 UTC 布局时间戳（空格分隔、无 T/Z）。
	result, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, message, created_at, updated_at)
		VALUES ('lb_hist3','hist3.example.test','issued','签发完成','2026-10-20 04:00:00','2026-10-20 04:00:05')`)
	if err != nil {
		t.Fatalf("seed cert job: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	// When
	recorder, response := getTaskHistory(t, h.GetSystemTaskHistory, "cert-job:"+strconv.FormatInt(jobID, 10))

	// Then 双布局解析：时间列填充 + duration 正确（UTC→配置时区 +8）。
	if recorder.Code != http.StatusOK || len(response.Data.Runs) != 1 {
		t.Fatalf("status=%d runs=%d, want 200/1", recorder.Code, len(response.Data.Runs))
	}
	run := response.Data.Runs[0]
	if run.StartedAt != "2026-10-20 12:00:00" || run.FinishedAt != "2026-10-20 12:00:05" {
		t.Fatalf("平面 UTC 布局时间墙串=(%q,%q), want 配置时区(+8)串（单布局解析会静默归零）", run.StartedAt, run.FinishedAt)
	}
	if run.DurationMs != 5000 {
		t.Fatalf("duration_ms=%d, want 5000", run.DurationMs)
	}
}

// Given 同一 cert_jobs 行（created_at/updated_at 均存在）；引擎已装配以便取列表。
// When 分别请求任务列表与 cert-job 历史。
// Then 两处口径按 2026-10-30 裁定分叉：历史端点保持完整区间
// （started=created_at/finished=updated_at/duration=区间）；列表行无独立运行
// 轮次——started=finished=updated_at（最近状态变更）、DurationMs=0，语义差异
// 由行 Description 注明（任务名 hover tooltip 呈现）。此前列表与历史曾逐字段
// 相等（同源 CertJobRunTimes started=created_at 口径），裁定后列表的「执行
// 时间」不再读 created_at（排队中的行停在创建时刻，与最近一次实际变化相悖）。
func TestCertJobTimes_listShowsUpdatedAtHistoryKeepsInterval(t *testing.T) {
	h := newBackupTestHandlers(t)
	initTaskEngineForTest(t)
	useTaskHistoryShanghaiLocation(t)

	result, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, message, created_at, updated_at)
		VALUES ('lb_t3','t3.example.test','issued','签发完成','2026-10-20T04:00:00Z','2026-10-20T04:00:05Z')`)
	if err != nil {
		t.Fatalf("seed cert job: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	taskID := "cert-job:" + strconv.FormatInt(jobID, 10)

	recorder, history := getTaskHistory(t, h.GetSystemTaskHistory, taskID)
	if recorder.Code != http.StatusOK || len(history.Data.Runs) != 1 {
		t.Fatalf("历史 status=%d runs=%d, want 200/1", recorder.Code, len(history.Data.Runs))
	}
	run := history.Data.Runs[0]
	// 历史端点：完整区间口径不动（started=created_at/finished=updated_at/duration=差）。
	if run.StartedAt != "2026-10-20 12:00:00" || run.FinishedAt != "2026-10-20 12:00:05" || run.DurationMs != 5000 {
		t.Fatalf("历史时间口径=(%q,%q,%d), want started=created_at/finished=updated_at/duration=5000",
			run.StartedAt, run.FinishedAt, run.DurationMs)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/system/tasks", h.ListSystemTasks)
	listRecorder := httptest.NewRecorder()
	router.ServeHTTP(listRecorder, httptest.NewRequest(http.MethodGet, "/system/tasks", nil))
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("列表 status=%d body=%s", listRecorder.Code, listRecorder.Body.String())
	}
	var payload struct {
		Data struct {
			Tasks []struct {
				ID string `json:"id"`
				// 执行时间口径（2026-10-30 裁定）：最近状态变更，见下断言。
				LastRun *struct {
					StartedAt  string `json:"started_at"`
					FinishedAt string `json:"finished_at"`
					DurationMs int64  `json:"duration_ms"`
				} `json:"last_run"`
			} `json:"tasks"`
		} `json:"data"`
	}
	if err := json.Unmarshal(listRecorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	var lastRun *struct {
		StartedAt  string `json:"started_at"`
		FinishedAt string `json:"finished_at"`
		DurationMs int64  `json:"duration_ms"`
	}
	for _, tk := range payload.Data.Tasks {
		if tk.ID == taskID {
			lastRun = tk.LastRun
			break
		}
	}
	if lastRun == nil {
		t.Fatalf("列表缺少 %s 行", taskID)
	}
	// 列表口径：执行时间=updated_at（配置时区 +8 的同一墙串），无独立轮次语义。
	if lastRun.StartedAt != "2026-10-20 12:00:05" || lastRun.FinishedAt != "2026-10-20 12:00:05" || lastRun.DurationMs != 0 {
		t.Fatalf("列表时间=(%q,%q,%d), want started=finished=updated_at(12:00:05)/duration=0",
			lastRun.StartedAt, lastRun.FinishedAt, lastRun.DurationMs)
	}
}
