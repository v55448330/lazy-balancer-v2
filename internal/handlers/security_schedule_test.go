package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 规则库定时调度端点（v2.3.x）：三库同构 PUT /security/<lib>/schedule——
// 星期多选（1=周一…7=周日，去重后非空）+ HH:MM 时间；保存即重排 next_update。

func newScheduleTestRouter(t *testing.T) *gin.Engine {
	t.Helper()
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/security/crs", h.GetCRSInfo)
	router.PUT("/security/crs/schedule", h.UpdateCRSSchedule)
	router.GET("/security/ip2region", h.GetIP2RegionInfo)
	router.PUT("/security/ip2region/schedule", h.UpdateIP2RegionSchedule)
	router.GET("/security/threat-lib", h.GetThreatLib)
	router.PUT("/security/threat-lib/schedule", h.UpdateThreatSchedule)
	return router
}

func TestUpdateCRSSchedule_saveAndReadBack(t *testing.T) {
	// Given
	router := newScheduleTestRouter(t)

	// When 保存排程（仅周二 04:30）
	recorder := putJSON(t, router, "/security/crs/schedule", map[string]any{"days": []int{2}, "time": "04:30"})

	// Then 200 + 排程列落库 + next_update 已重排
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var days, hhmm, nextUpdate string
	if err := db.DB.QueryRow(`SELECT COALESCE(schedule_days,''), COALESCE(schedule_time,''), COALESCE(next_update,'') FROM security_crs_version WHERE id=1`).
		Scan(&days, &hhmm, &nextUpdate); err != nil {
		t.Fatal(err)
	}
	if days != "2" || hhmm != "04:30" {
		t.Fatalf("schedule=(%q,%q), want (2,04:30)", days, hhmm)
	}
	if nextUpdate == "" {
		t.Fatal("next_update empty after schedule save（保存即重排）")
	}

	// And GET 载荷携带排程字段
	get := getRequest(t, router, "/security/crs")
	if get.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", get.Code, get.Body.String())
	}
	var resp struct {
		Data struct {
			ScheduleDays []int  `json:"schedule_days"`
			ScheduleTime string `json:"schedule_time"`
		} `json:"data"`
	}
	if err := json.Unmarshal(get.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if len(resp.Data.ScheduleDays) != 1 || resp.Data.ScheduleDays[0] != 2 {
		t.Fatalf("schedule_days=%v, want [2]", resp.Data.ScheduleDays)
	}
	if resp.Data.ScheduleTime != "04:30" {
		t.Fatalf("schedule_time=%q, want 04:30", resp.Data.ScheduleTime)
	}
}

func TestUpdateCRSSchedule_validation(t *testing.T) {
	router := newScheduleTestRouter(t)
	for name, payload := range map[string]map[string]any{
		"空星期集":    {"days": []int{}, "time": "04:00"},
		"缺days字段": {"time": "04:00"},
		"全非法星期":   {"days": []int{0, 8}, "time": "04:00"},
		"非法时间格式":  {"days": []int{1}, "time": "9:00"},
		"越界时间":    {"days": []int{1}, "time": "24:00"},
	} {
		recorder := putJSON(t, router, "/security/crs/schedule", payload)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s: status=%d body=%s, want 400", name, recorder.Code, recorder.Body.String())
		}
	}
	// 重复星期去重后非空 → 合法
	recorder := putJSON(t, router, "/security/crs/schedule", map[string]any{"days": []int{1, 1, 1}, "time": "04:00"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("去重后非空: status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
}

func TestUpdateCRSSchedule_slaveForbidden(t *testing.T) {
	// Given 从节点
	router := newScheduleTestRouter(t)
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}

	// When
	recorder := putJSON(t, router, "/security/crs/schedule", map[string]any{"days": []int{2}, "time": "04:30"})

	// Then 403
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s, want 403", recorder.Code, recorder.Body.String())
	}
}

func TestUpdateIP2RegionSchedule_saveAndReadBack(t *testing.T) {
	router := newScheduleTestRouter(t)

	recorder := putJSON(t, router, "/security/ip2region/schedule", map[string]any{"days": []int{1, 3, 5}, "time": "23:15"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	get := getRequest(t, router, "/security/ip2region")
	if get.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", get.Code, get.Body.String())
	}
	var resp struct {
		Data struct {
			ScheduleDays []int  `json:"schedule_days"`
			ScheduleTime string `json:"schedule_time"`
		} `json:"data"`
	}
	if err := json.Unmarshal(get.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if len(resp.Data.ScheduleDays) != 3 || resp.Data.ScheduleDays[0] != 1 || resp.Data.ScheduleDays[2] != 5 {
		t.Fatalf("schedule_days=%v, want [1 3 5]", resp.Data.ScheduleDays)
	}
	if resp.Data.ScheduleTime != "23:15" {
		t.Fatalf("schedule_time=%q, want 23:15", resp.Data.ScheduleTime)
	}
}

func TestUpdateThreatSchedule_saveAndReadBack(t *testing.T) {
	router := newScheduleTestRouter(t)

	recorder := putJSON(t, router, "/security/threat-lib/schedule", map[string]any{"days": []int{7}, "time": "05:00"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	get := getRequest(t, router, "/security/threat-lib")
	if get.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", get.Code, get.Body.String())
	}
	var resp struct {
		Data struct {
			ScheduleDays []int  `json:"schedule_days"`
			ScheduleTime string `json:"schedule_time"`
		} `json:"data"`
	}
	if err := json.Unmarshal(get.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if len(resp.Data.ScheduleDays) != 1 || resp.Data.ScheduleDays[0] != 7 {
		t.Fatalf("schedule_days=%v, want [7]", resp.Data.ScheduleDays)
	}
	if resp.Data.ScheduleTime != "05:00" {
		t.Fatalf("schedule_time=%q, want 05:00", resp.Data.ScheduleTime)
	}
}

func TestUpdateThreatSchedule_validation(t *testing.T) {
	router := newScheduleTestRouter(t)
	recorder := putJSON(t, router, "/security/threat-lib/schedule", map[string]any{"days": []int{}, "time": "04:00"})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("空星期集: status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
}
