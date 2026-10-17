package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

// 威胁情报库（v2.3.2 名单化重构）：内置只读三源的管理面——状态展示、
// 更新开关、手动更新、更新状态/日志。名单内容经 security_ip_lists 的
// system=1 内置行承载（IP 地址列表 tab 查看/导出），策略引用生效。
// 不提供任何源的新建/编辑/删除（用户不可删改）。

type threatSourceDTO struct {
	ID            int    `json:"id"`
	Name          string `json:"name"`
	DisplayName   string `json:"display_name"`
	URL           string `json:"url"`
	Format        string `json:"format"`
	UpdateEnabled bool   `json:"update_enabled"`
	EntryCount    int    `json:"entry_count"`
	Version       string `json:"version"`
	UpdateStatus  string `json:"update_status"`
	Message       string `json:"message"`
	LastChecked   string `json:"last_checked"`
	NextUpdate    string `json:"next_update"`
	// ListID 是该源对应的内置 IP 名单 id（前端「查看」跳转 IP 地址列表 tab）。
	ListID int `json:"list_id"`
}

func (h *Handlers) GetThreatLib(c *gin.Context) {
	rows, err := db.DB.Query(`SELECT t.id, t.name, t.display_name, t.url, t.format, t.update_enabled,
		t.entry_count, t.version, t.update_status, t.message, COALESCE(t.last_checked,''), COALESCE(t.next_update,'')
		FROM security_threat_sources t
		WHERE t.name IN ('ustc','firehol_l1','et_compromised') ORDER BY t.id`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取威胁情报库失败: " + err.Error()})
		return
	}
	defer rows.Close()
	sources := []threatSourceDTO{}
	var rawRows []threatSourceDTO
	for rows.Next() {
		var s threatSourceDTO
		if err := rows.Scan(&s.ID, &s.Name, &s.DisplayName, &s.URL, &s.Format, &s.UpdateEnabled,
			&s.EntryCount, &s.Version, &s.UpdateStatus, &s.Message, &s.LastChecked, &s.NextUpdate); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取威胁情报库失败: " + err.Error()})
			return
		}
		rawRows = append(rawRows, s)
	}
	// SEC-C-N1（第 71 轮 P4·家族漏收敛）：迭代错误（rows.Err）不得以
	// 「部分/空列表 + 200」返回——与 R36/R37 在总览/事件列表建立的
	// 「残缺列表不得以 200」口径对齐（Scan 失败分支同响应形）。
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取威胁情报库失败: " + err.Error()})
		return
	}
	totalEntries := 0
	for _, s := range rawRows {
		listName := db.ThreatListNameBySource(s.Name)
		if listName != "" {
			_ = db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=?`, listName).Scan(&s.ListID)
		}
		totalEntries += s.EntryCount
		sources = append(sources, s)
	}
	days, hhmm := services.ThreatSchedule()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"sources":       sources,
		"total_entries": totalEntries,
		"auto_update":   services.ThreatAutoUpdateEnabled(),
		"schedule_days": days,
		"schedule_time": hhmm,
	}})
}

// UpdateThreatAutoUpdate 任务级总开关（规则库卡片父行开关；镜像
// UpdateCRSAutoUpdate/UpdateIP2RegionAutoUpdate 形态）。逐源 update_enabled
// 决定任务更新哪些源（弹框内开关），与总闸解耦。
func (h *Handlers) UpdateThreatAutoUpdate(c *gin.Context) {
	if !guardConfiguredJSONBody(c) {
		return
	}
	var body struct {
		AutoUpdate *bool `json:"auto_update"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.AutoUpdate == nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求无效"})
		return
	}
	// F49-P5-7：与 UpdateCRSAutoUpdate 同口径主节点门（R57 B-#4）——从节点
	// 状态行在集群同步段内，本地写会被下次快照覆盖。
	if !requireMasterNode(c) {
		return
	}
	if err := services.SetThreatAutoUpdate(*body.AutoUpdate); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新失败: " + err.Error()})
		return
	}
	recordAudit(c, "更新", "威胁情报库", "自动更新总开关")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已更新"})
}

// UpdateThreatSchedule 任务级排程保存（弹框「定时更新」区；镜像
// UpdateCRSSchedule 形态——保存即重排 next_update：WHERE update_enabled=1
// 一律重排（2026-09-25 裁定，含失败源））。
func (h *Handlers) UpdateThreatSchedule(c *gin.Context) {
	days, hhmm, ok := h.updateLibSchedule(c, services.SetThreatSchedule)
	if !ok {
		return
	}
	recordAudit(c, "更新", "威胁情报库", fmt.Sprintf("定时更新设置：每周%s %s", scheduleDaysLabel(days), hhmm))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已更新"})
}

// UpdateThreatSourceFlags 仅允许改 update_enabled——名单化后「应用」=
// 策略引用名单（无独立 apply 开关）。请求体携带的其余字段一律忽略
// （内置源不可变造）。
func (h *Handlers) UpdateThreatSourceFlags(c *gin.Context) {
	if !guardConfiguredJSONBody(c) {
		return
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的源 ID"})
		return
	}
	var body struct {
		UpdateEnabled *bool `json:"update_enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求无效"})
		return
	}
	if body.UpdateEnabled == nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无可更新字段"})
		return
	}
	// F49-P5-7：与 UpdateCRSAutoUpdate 同口径主节点门（R57 B-#4）。
	if !requireMasterNode(c) {
		return
	}
	var name string
	if err := db.DB.QueryRow(`SELECT name FROM security_threat_sources WHERE id=?`, id).Scan(&name); err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "威胁库源不存在"})
		return
	}
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_enabled=?, updated_at=datetime('now') WHERE id=?`, *body.UpdateEnabled, id); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新失败: " + err.Error()})
		return
	}
	if *body.UpdateEnabled {
		services.ArmThreatFirstSlots()
	}
	recordAudit(c, "更新", "威胁情报库", fmt.Sprintf("%s 更新开关", name))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已更新"})
}

// StartThreatLibUpdate 手动触发更新（主节点；镜像 StartCRSUpdate 的受理/
// 重复任务 409 语义）。
func (h *Handlers) StartThreatLibUpdate(c *gin.Context) {
	if !requireMasterNode(c) {
		return
	}
	// V2（第 67 轮用户裁定）：手动触发统一经任务引擎（同 StartCRSUpdate）。
	te := services.TaskEngine()
	if te == nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "任务引擎未初始化"})
		return
	}
	if te.IsTaskInFlight("threat") {
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "任务运行中，请稍后重试"})
		return
	}
	op := auditOperator(c)
	// L01-02：统一异步触发与错误分类（见 services.TriggerTaskAsync）。
	services.TriggerTaskAsync(te, "threat", services.TriggerAuditContext{
		Operator: op, Family: "威胁情报库", Name: "威胁情报库更新",
	})
	// 审计由任务体自记（operator 经 RunContext 归人——2026-09-29 裁定单记口径）
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"status": "running", "trigger": "manual"}})
}

// GetThreatLibUpdateStatus 任务级状态（弹框轮询；镜像 GetCRSUpdateStatus 形态）。
func (h *Handlers) GetThreatLibUpdateStatus(c *gin.Context) {
	mgr := services.GetThreatUpdateManager()
	if mgr == nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "威胁库更新服务未初始化"})
		return
	}
	snap := mgr.StatusSnapshot()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: snap})
}

// GetThreatLibUpdateLogs 更新日志（含上一代轮转文件，镜像 GetCRSUpdateLogs）。
func (h *Handlers) GetThreatLibUpdateLogs(c *gin.Context) {
	// 单一日志数据源：同 GetCRSUpdateLogs。
	logPath := taskengine.TaskLogPath("threat")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]string{"content": readUpdateLogWithRotation(logPath)}})
}
