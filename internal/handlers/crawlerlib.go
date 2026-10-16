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

// crawlerSourceDTO 爬虫源行（与 threatSourceDTO 同构字段，便于规则库卡片复用渲染）。
type crawlerSourceDTO struct {
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
	// ListID 该源对应内置 IP 名单 id（CrawlerIPListName(engine)，前端「查看」跳转 IP 地址列表 tab）。
	ListID int `json:"list_id"`
}

// GetCrawlerLib 爬虫地址库源列表、条目合计与独立配置（规则库卡片数据源：
// 版本/状态/条目数/更新地址/独立总闸与排程；master 写库，slave 只读不写）。
func (h *Handlers) GetCrawlerLib(c *gin.Context) {
	rows, err := db.DB.Query(`SELECT id, name, display_name, url, format, update_enabled,
		entry_count, version, update_status, COALESCE(message,''), COALESCE(last_checked,''), COALESCE(next_update,'')
		FROM security_crawler_sources ORDER BY id`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取爬虫源失败: " + err.Error()})
		return
	}
	defer rows.Close()
	sources := []crawlerSourceDTO{}
	total := 0
	for rows.Next() {
		var s crawlerSourceDTO
		if err := rows.Scan(&s.ID, &s.Name, &s.DisplayName, &s.URL, &s.Format, &s.UpdateEnabled,
			&s.EntryCount, &s.Version, &s.UpdateStatus, &s.Message, &s.LastChecked, &s.NextUpdate); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取爬虫源失败: " + err.Error()})
			return
		}
		sources = append(sources, s)
		total += s.EntryCount
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取爬虫源失败: " + err.Error()})
		return
	}
	for i := range sources {
		_ = db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=? AND system=1`, services.CrawlerIPListName(sources[i].Name)).Scan(&sources[i].ListID)
	}
	days, hhmm := services.CrawlerSchedule()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"sources":       sources,
		"total_entries": total,
		"auto_update":   services.CrawlerAutoUpdateEnabled(),
		"schedule_days": days,
		"schedule_time": hhmm,
	}})
}

// StartCrawlerLibUpdate 手动触发爬虫地址更新（主节点；统一经任务引擎，
// 与独立定时任务同体，同 StartThreatLibUpdate 口径）。
func (h *Handlers) StartCrawlerLibUpdate(c *gin.Context) {
	if !requireMasterNode(c) {
		return
	}
	te := services.TaskEngine()
	if te == nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "任务引擎未初始化"})
		return
	}
	if te.IsTaskInFlight("crawlerbot-update") {
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "任务运行中，请稍后重试"})
		return
	}
	op := auditOperator(c)
	go func() {
		if err := te.Trigger("crawlerbot-update", "manual", op); err != nil {
			services.Logf("error", "手动触发爬虫地址更新失败: %v", err)
			services.RecordAuditLog(op, "触发失败", "爬虫地址库", "手动触发爬虫地址更新失败: "+err.Error(), "")
		}
	}()
	// 审计由任务体 defer 自记（operator 经 RunContext 归人，与威胁库同口径）
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"status": "running", "trigger": "manual"}})
}

// UpdateCrawlerAutoUpdate 爬虫地址库任务级总开关（与威胁库总闸解耦）。
func (h *Handlers) UpdateCrawlerAutoUpdate(c *gin.Context) {
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
	if !requireMasterNode(c) {
		return
	}
	if err := services.SetCrawlerAutoUpdate(*body.AutoUpdate); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新失败: " + err.Error()})
		return
	}
	recordAudit(c, "更新", "爬虫地址库", "自动更新总开关")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已更新"})
}

// UpdateCrawlerSchedule 保存爬虫地址库独立排程并重排全部启用源。
func (h *Handlers) UpdateCrawlerSchedule(c *gin.Context) {
	days, hhmm, ok := h.updateLibSchedule(c, services.SetCrawlerSchedule)
	if !ok {
		return
	}
	recordAudit(c, "更新", "爬虫地址库", fmt.Sprintf("定时更新设置：每周%s %s", scheduleDaysLabel(days), hhmm))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已更新"})
}

// GetCrawlerLibUpdateStatus 爬虫地址库任务状态（直接读 crawlerbot-update
// 自身任务历史，不复用威胁库状态机）。
func (h *Handlers) GetCrawlerLibUpdateStatus(c *gin.Context) {
	te := services.TaskEngine()
	if te == nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "任务引擎未初始化"})
		return
	}
	data := gin.H{
		"running":     te.IsTaskInFlight("crawlerbot-update"),
		"trigger":     "",
		"started_at":  "",
		"finished_at": "",
		"outcome":     "",
	}
	if history := te.History("crawlerbot-update", 1); len(history) > 0 {
		latest := history[0]
		data["trigger"] = latest.Trigger
		data["started_at"] = latest.StartedAt
		data["finished_at"] = latest.FinishedAt
		data["outcome"] = latest.Status
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: data})
}

// UpdateCrawlerLibFlags 更新爬虫源开关（update_enabled 单字段，同 UpdateThreatSourceFlags）。
func (h *Handlers) UpdateCrawlerLibFlags(c *gin.Context) {
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
	if !requireMasterNode(c) {
		return
	}
	var name string
	if err := db.DB.QueryRow(`SELECT name FROM security_crawler_sources WHERE id=?`, id).Scan(&name); err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "爬虫源不存在"})
		return
	}
	if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_enabled=?, updated_at=datetime('now') WHERE id=?`, *body.UpdateEnabled, id); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新失败: " + err.Error()})
		return
	}
	recordAudit(c, "更新", "爬虫地址库", fmt.Sprintf("%s 更新开关", name))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已更新"})
}

// GetCrawlerLibUpdateLogs 爬虫更新任务日志（tasks/crawlerbot-update.log 尾读，含轮转副本）。
func (h *Handlers) GetCrawlerLibUpdateLogs(c *gin.Context) {
	content := readUpdateLogWithRotation(taskengine.TaskLogPath("crawlerbot-update"))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"content": content}})
}
