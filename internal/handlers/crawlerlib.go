package handlers

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

// crawlerLibInternalError 500 统一装配：固定中文文案回客户端，底层错误
// （SQL 文本/表列名等内部结构）只进运行日志——crawler-lib 端点属 business
// 组，任意登录用户可读，与认证域「固定文案 + 服务端留痕」同口径。
func crawlerLibInternalError(message string, err error) models.APIResponse {
	return internalError("爬虫地址库", message, err)
}

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
		c.JSON(http.StatusInternalServerError, crawlerLibInternalError("读取爬虫源失败", err))
		return
	}
	defer rows.Close()
	sources := []crawlerSourceDTO{}
	total := 0
	for rows.Next() {
		var s crawlerSourceDTO
		if err := rows.Scan(&s.ID, &s.Name, &s.DisplayName, &s.URL, &s.Format, &s.UpdateEnabled,
			&s.EntryCount, &s.Version, &s.UpdateStatus, &s.Message, &s.LastChecked, &s.NextUpdate); err != nil {
			c.JSON(http.StatusInternalServerError, crawlerLibInternalError("读取爬虫源失败", err))
			return
		}
		// 活动态只属执行进程：从节点不运行该任务，行内「更新中」是主端镜像
		// 或降级残留，读侧投影为 failed（展示层口径，不写库）。
		s.UpdateStatus, s.Message = services.ProjectActiveUpdateStatusForLocalRole(s.UpdateStatus, s.Message)
		sources = append(sources, s)
		total += s.EntryCount
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, crawlerLibInternalError("读取爬虫源失败", err))
		return
	}
	listIDs, err := loadSystemListIDs()
	if err != nil {
		c.JSON(http.StatusInternalServerError, crawlerLibInternalError("读取爬虫源失败", err))
		return
	}
	for i := range sources {
		sources[i].ListID = listIDs[services.CrawlerIPListName(sources[i].Name)]
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
		respondTaskEngineUnavailable(c)
		return
	}
	if te.IsTaskInFlight(services.CrawlerTaskID) {
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: apimsg.T(c, "k_723ca537"), MessageKey: "k_723ca537"})
		return
	}
	op := auditOperator(c)
	// 响应前同步预占位；自记族成功零 handler 审计，
	// ErrAlreadyRunning/ErrTaskSkipped 静默，真失败留补偿审计。
	if err := services.TriggerTaskAsync(te, services.CrawlerTaskID, services.TriggerAuditContext{
		Operator: op, Family: "爬虫地址库", Name: "爬虫地址更新",
	}); err != nil {
		respondTaskTriggerAdmissionError(c, err)
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"status": "running", "trigger": "manual"}})
}

// UpdateCrawlerAutoUpdate 爬虫地址库任务级总开关（与威胁库总闸解耦）。
func (h *Handlers) UpdateCrawlerAutoUpdate(c *gin.Context) {
	// crawler_auto_update 存在 global_config（导入 Config 区整体改写）、
	// security_crawler_sources 在导入全量替代表内——窗口内写会被导入覆盖或
	// 撞写锁 500，与 CRS/IP2Region/威胁库同口径 409 fast-fail（同一骨架，
	// 门序先于 body 解析）。
	autoUpdate, ok := h.libAutoUpdate(c, libAutoUpdateSpec{
		ImportAction:   "修改爬虫地址库设置（配置导入进行中）",
		InvalidMessage: "请求无效",
	}, services.SetCrawlerAutoUpdate)
	if !ok {
		return
	}
	recordAudit(c, "更新", "爬虫地址库", "自动更新总开关："+enabledStateLabel(autoUpdate))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: apimsg.T(c, "k_573eb966"), MessageKey: "k_573eb966"})
}

// UpdateCrawlerSchedule 保存爬虫地址库独立排程并重排全部启用源。
func (h *Handlers) UpdateCrawlerSchedule(c *gin.Context) {
	days, hhmm, ok := h.updateLibSchedule(c, services.SetCrawlerSchedule)
	if !ok {
		return
	}
	recordAudit(c, "更新", "爬虫地址库", fmt.Sprintf("定时更新设置：每周%s %s", scheduleDaysLabel(days), hhmm))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: apimsg.T(c, "k_573eb966"), MessageKey: "k_573eb966"})
}

// GetCrawlerLibUpdateStatus 爬虫地址库任务状态（直接读 crawlerbot-update
// 自身任务历史，不复用威胁库状态机）。
func (h *Handlers) GetCrawlerLibUpdateStatus(c *gin.Context) {
	te := services.TaskEngine()
	if te == nil {
		respondTaskEngineUnavailable(c)
		return
	}
	data := gin.H{
		"running":     te.IsTaskInFlight(services.CrawlerTaskID),
		"trigger":     "",
		"started_at":  "",
		"finished_at": "",
		"outcome":     "",
	}
	if history := te.History(services.CrawlerTaskID, 1); len(history) > 0 {
		latest := history[0]
		data["trigger"] = latest.Trigger
		data["started_at"] = latest.StartedAt
		data["finished_at"] = latest.FinishedAt
		data["outcome"] = latest.Status
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: data})
}

// UpdateCrawlerLibFlags 更新爬虫源开关（update_enabled 单字段）。状态机与
// 威胁库 UpdateThreatSourceFlags 单源收敛在 updateLibSourceFlags，差异面只有
// 表名/文案/首槽武装/错误装配。
func (h *Handlers) UpdateCrawlerLibFlags(c *gin.Context) {
	updateLibSourceFlags(c, libSourceFlagsSpec{
		Table:         "security_crawler_sources",
		Family:        "爬虫地址库",
		NotFoundMsg:   "爬虫源不存在",
		ReadErrMsg:    "读取爬虫源失败",
		UpdateErrMsg:  "更新失败",
		ArmFirstSlots: services.ArmCrawlerFirstSlots,
		InternalError: crawlerLibInternalError,
	})
}

// GetCrawlerLibUpdateLogs 爬虫更新任务日志（tasks/crawlerbot-update.log 尾读，含轮转副本）。
func (h *Handlers) GetCrawlerLibUpdateLogs(c *gin.Context) {
	content := readUpdateLogWithRotation(taskengine.TaskLogPath(services.CrawlerTaskID))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"content": content}})
}
