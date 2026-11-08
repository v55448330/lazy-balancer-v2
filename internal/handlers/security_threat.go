package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
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
	registry := db.ThreatSystemLists()
	sourceNames := make([]string, 0, len(registry))
	args := make([]interface{}, 0, len(registry))
	for _, sl := range registry {
		sourceNames = append(sourceNames, "?")
		args = append(args, sl.Source)
	}
	where := "0"
	if len(sourceNames) > 0 {
		where = "t.name IN (" + strings.Join(sourceNames, ",") + ")"
	}
	rows, err := db.DB.Query(fmt.Sprintf(`SELECT t.id, t.name, t.display_name, t.url, t.format, t.update_enabled,
		t.entry_count, t.version, t.update_status, t.message, COALESCE(t.last_checked,''), COALESCE(t.next_update,'')
		FROM security_threat_sources t
		WHERE %s ORDER BY t.id`, where), args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("读取威胁情报库失败", err)})
		return
	}
	defer rows.Close()
	sources := []threatSourceDTO{}
	totalEntries := 0
	for rows.Next() {
		var s threatSourceDTO
		if err := rows.Scan(&s.ID, &s.Name, &s.DisplayName, &s.URL, &s.Format, &s.UpdateEnabled,
			&s.EntryCount, &s.Version, &s.UpdateStatus, &s.Message, &s.LastChecked, &s.NextUpdate); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("读取威胁情报库失败", err)})
			return
		}
		// 活动态只属执行进程：从节点不运行该任务，行内「更新中」是主端镜像
		// 或降级残留，读侧投影为 failed（展示层口径，不写库）。
		s.UpdateStatus, s.Message = services.ProjectActiveUpdateStatusForLocalRole(s.UpdateStatus, s.Message)
		sources = append(sources, s)
		totalEntries += s.EntryCount
	}
	// 迭代错误（rows.Err）不得以
	// 「部分/空列表 + 200」返回——与在总览/事件列表建立的
	// 「残缺列表不得以 200」口径对齐（Scan 失败分支同响应形）。
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("读取威胁情报库失败", err)})
		return
	}
	// 与 GetCrawlerLib 共用 loadSystemListIDs：一次预载代替逐源点查；缺行保留
	// list_id=0，查询/扫描/迭代故障均显式 500。
	listIDs, err := loadSystemListIDs()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("读取内置名单失败", err)})
		return
	}
	for i := range sources {
		sources[i].ListID = listIDs[db.ThreatListNameBySource(sources[i].Name)]
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
	// security_threat_sources 在导入全量替换清单内（configBackupTables）：
	// 窗口内写会被导入静默覆盖或撞写锁 500——与同族 CRS/IP2Region 端点
	// 同口径 409 fast-fail（见 libAutoUpdate，先于 body 解析）。
	autoUpdate, ok := h.libAutoUpdate(c, libAutoUpdateSpec{
		ImportAction:   "修改威胁情报库设置（配置导入进行中）",
		InvalidMessage: "请求无效",
	}, services.SetThreatAutoUpdate)
	if !ok {
		return
	}
	recordAudit(c, "更新", "威胁情报库", "自动更新总开关："+enabledStateLabel(autoUpdate))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: apimsg.T(c, "k_573eb966"), MessageKey: "k_573eb966"})
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
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: apimsg.T(c, "k_573eb966"), MessageKey: "k_573eb966"})
}

// UpdateThreatSourceFlags 仅允许改 update_enabled——名单化后「应用」=
// 策略引用名单（无独立 apply 开关）。请求体携带的其余字段一律忽略
// （内置源不可变造）。状态机与爬虫库 UpdateCrawlerLibFlags 单源收敛在
// updateLibSourceFlags，差异面只有表名/文案/首槽武装/错误装配。
func (h *Handlers) UpdateThreatSourceFlags(c *gin.Context) {
	updateLibSourceFlags(c, libSourceFlagsSpec{
		Table:         "security_threat_sources",
		Family:        "威胁情报库",
		NotFoundMsg:   "威胁库源不存在",
		ReadErrMsg:    "读取威胁库源失败",
		UpdateErrMsg:  "更新失败",
		ArmFirstSlots: services.ArmThreatFirstSlots,
		InternalError: func(message string, err error) models.APIResponse {
			return models.APIResponse{Code: http.StatusInternalServerError, Message: serverErrMsg(message, err)}
		},
	})
}

// StartThreatLibUpdate 手动触发更新（主节点；镜像 StartCRSUpdate 的受理/
// 重复任务 409 语义）。
func (h *Handlers) StartThreatLibUpdate(c *gin.Context) {
	// 手动更新仅限主节点；受理/重复任务 409 语义与 CRS/IP2Region 单源。
	h.startLibUpdate(c, "threat", "威胁情报库", "威胁情报库更新")
}

// GetThreatLibUpdateStatus 任务级状态（弹框轮询；镜像 GetCRSUpdateStatus 形态）。
func (h *Handlers) GetThreatLibUpdateStatus(c *gin.Context) {
	libUpdateStatus(c, "威胁库", services.GetThreatUpdateManager(), func(mgr *services.ThreatUpdateManager) any {
		return mgr.StatusSnapshot()
	})
}

// GetThreatLibUpdateLogs 更新日志（含上一代轮转文件，与 CRS/IP2Region 单源）。
func (h *Handlers) GetThreatLibUpdateLogs(c *gin.Context) {
	libUpdateLogs(c, "threat")
}
