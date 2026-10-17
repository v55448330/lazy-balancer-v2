package handlers

// 任务监控 handlers（v2.3.4）：GET /system/tasks 全员可见（从节点只读视图）；
// trigger/toggle/cancel 为管理员操作（adminOnly+readOnlyGuard 路由组）。
// 操作映射到各任务族既有入口（manager StartUpdate/SetAutoUpdate/CancelRunning），
// 本层零新状态。

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"bytes"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
	"os"
)

// ListSystemTasks 聚合全部任务族状态（全员可见）。
func (h *Handlers) ListSystemTasks(c *gin.Context) {
	tasks := services.CollectSystemTasks()
	if tasks == nil {
		tasks = []services.TaskInfo{}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"tasks": tasks}})
}

// requireMasterNode 主节点门（写操作镜像 StartCRSUpdate 口径）。
func requireMasterNode(c *gin.Context) bool {
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		clusterError(c, http.StatusForbidden, "该操作仅允许在主节点执行", err)
		return false
	}
	return true
}

// triggerAuditContext 预取异步触发审计上下文（gin.Context 在 handler 返回后
// 池化复用——goroutine 只能消费快照）。api_key 详情与审计 IP 的取法与
// recordAudit 同口径（中间件 audit_ip 优先）。
func triggerAuditContext(c *gin.Context, family, name string) services.TriggerAuditContext {
	detail := ""
	if c.GetString("auth_type") == "api_key" {
		detail = services.AppendAPIKeyAuditDetail("手动触发任务 "+name, c.GetInt("api_key_id"), c.GetString("api_key_name"))
	}
	ip := c.GetString("audit_ip")
	if ip == "" {
		ip = c.ClientIP()
	}
	return services.TriggerAuditContext{
		Operator: auditOperator(c),
		IP:       ip,
		Family:   family,
		Name:     name,
		Detail:   detail,
	}
}

// TriggerSystemTask 手动触发（admin；仅排程/队列类任务族）。
func (h *Handlers) TriggerSystemTask(c *gin.Context) {
	id := c.Param("id")
	if !requireMasterNode(c) {
		return
	}
	// cert-job 行触发分支（2026-10-11 用户裁定）：证书队列行视为触发任务——
	// 可自动调度（签发守护消费）即可手动调度（证书可重签发）。复用重试核心
	//（在途 409/退役 429/冷却 429/规则禁用 409 同一门），审计「重试」归人。
	if strings.HasPrefix(id, "cert-job:") {
		jobID, err := strconv.Atoi(strings.TrimPrefix(id, "cert-job:"))
		if err != nil || jobID <= 0 {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid job ID"})
			return
		}
		h.retryCertJobByID(c, jobID)
		return
	}
	// 终态：触发全经任务引擎（CanTrigger 语义族——单飞/主节点门/历史统一）
	if te := services.TaskEngine(); te != nil {
		if m, ok := te.Lookup(id); ok { // U1-P4-2：单任务元数据（免全量 DescribeAll）
			if !m.CanTrigger {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "该任务不支持手动触发（常驻族启停即可/镜像族）"})
				return
			}
			// v2.0：单飞由引擎 CAS 强制；L1-3（第 65 轮）：在跑任务同步 409
			// （曾异步吞错恒 200+apidocs 409 不可达——双击假成功）
			if te.IsTaskInFlight(id) {
				c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "任务运行中，请稍后重试"})
				return
			}
			// L01-02/U10-F12：触发与审计统一走 services.TriggerTaskAsync——
			// 「触发」审计只在 Trigger 成功后记录（非自记族），并发双击败者
			// 拿 ErrAlreadyRunning 静默、skipped 终态静默、真失败记补偿审计。
			// gin.Context 在 handler 返回后池化复用：审计上下文必须在此预取。
			services.TriggerTaskAsync(te, id, triggerAuditContext(c, "任务监控", m.Name))
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"status": "running", "trigger": "manual"}})
			return
		}
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "任务不存在"})
		return
	}
	// R63：无引擎时统一 503（回退 switch 删除）。
	c.JSON(http.StatusServiceUnavailable, models.APIResponse{Code: 503, Message: "任务引擎未初始化"})
}

// ToggleSystemTask 调度开关（admin；body {"enabled": bool}）。
// v2.0：统一路由引擎循环开关（StartLoop/StopLoop）——Kind 决定语义：
// 定时/循环=停止/恢复调度；常驻=启停自管理循环；
// 触发=不可调度（前端显示禁用开关）。
func (h *Handlers) ToggleSystemTask(c *gin.Context) {
	id := c.Param("id")
	if !requireMasterNode(c) {
		return
	}
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Enabled == nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效（需 enabled 布尔值）"})
		return
	}
	if te := services.TaskEngine(); te != nil {
		if m, ok := te.Lookup(id); ok {
			if m.Kind == taskengine.KindOneshot {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "触发类任务不可调度——仅手动/代码触发执行"})
				return
			}
			// 业务驱动任务（自动更新/自动备份/自动封禁）只能由对应业务页开关
			// 修改；引擎只同步 loop_on，禁止在任务监控反写业务配置或另开第二入口。
			if services.IsBusinessDrivenTask(id) {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "该任务由对应业务页开关控制，请在业务页修改自动更新设置"})
				return
			}
			if *req.Enabled {
				te.StartLoop(id)
			} else {
				te.StopLoop(id)
			}
			// U10-F02：用户显式启停落节点本地偏好（重启后不得按默认清单复活）。
			if err := services.RecordTaskLoopPref(id, *req.Enabled); err != nil {
				services.Logf("warn", "任务调度偏好写入失败（%s）: %v", id, err)
			}
			if *req.Enabled {
				recordAudit(c, "恢复", "任务监控", m.Name+" 调度")
				c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已恢复 " + m.Name + " 调度"})
			} else {
				recordAudit(c, "停止", "任务监控", m.Name+" 调度")
				c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已停止 " + m.Name + " 调度"})
			}
			return
		}
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "任务不存在"})
		return
	}
	c.JSON(http.StatusServiceUnavailable, models.APIResponse{Code: 503, Message: "任务引擎未初始化"})
}

// CancelSystemTask 取消运行中任务（admin；仅 Cancelable 声明族）。
// U1-P4-2：引擎路径经 te.Cancel（Cancelable+CancelHook 元数据路由），
// 不再硬编码三族清单；无引擎回退（测试环境）直调 manager。
func (h *Handlers) CancelSystemTask(c *gin.Context) {
	id := c.Param("id")
	if !requireMasterNode(c) {
		return
	}
	// 取消与 Trigger/Toggle/Control 共用集群写门；引擎 RunsOn 另管执行角色。
	if te := services.TaskEngine(); te != nil {
		if _, ok := te.Lookup(id); !ok {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "任务不存在"})
			return
		}
		if !te.Cancel(id) {
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "任务未在运行中或不支持取消"})
			return
		}
		recordAudit(c, "取消", "任务监控", "手动取消任务 "+id+"（下载阶段中断，已完成部分保留）")
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已发出取消信号，任务将在当前下载阶段中断"})
		return
	}
	// R63：无引擎时统一 503（回退 switch 删除）。
	c.JSON(http.StatusServiceUnavailable, models.APIResponse{Code: 503, Message: "任务引擎未初始化"})
}

// ControlSystemTask 常驻循环启停（admin；body {"action":"start|stop|restart"}）。
// TASK-L11（第 69 轮）：现形态——Controllable = Kind==Daemon（引擎元数据驱动），
// 仅常驻族（security-events-ingestion/cert-issuance/cluster-sync）可控；Periodic
// 族（cert-waiting-ca 等）启停走 toggle 端点，本端点对其恒 400。v2.0 前
// 「Continuous 族可控」注释已随四类型标准作废。
func (h *Handlers) ControlSystemTask(c *gin.Context) {
	id := c.Param("id")
	if !requireMasterNode(c) {
		return
	}
	var req struct {
		Action string `json:"action"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || (req.Action != "start" && req.Action != "stop" && req.Action != "restart") {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效（action=start|stop|restart）"})
		return
	}
	te := services.TaskEngine()
	if te == nil {
		c.JSON(http.StatusServiceUnavailable, models.APIResponse{Code: 503, Message: "任务引擎未初始化"})
		return
	}
	m, ok := te.Lookup(id)
	if !ok {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "任务不存在"})
		return
	}
	if !m.Controllable {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "该任务不支持启停（角色驱动或纯被动循环）"})
		return
	}
	switch req.Action {
	case "start":
		te.StartLoop(id)
	case "stop":
		te.StopLoop(id)
	case "restart":
		te.StopLoop(id)
		te.StartLoop(id)
	}
	// U10-F02：用户显式启停落节点本地偏好；restart 的终态为运行。
	if err := services.RecordTaskLoopPref(id, req.Action != "stop"); err != nil {
		services.Logf("warn", "任务调度偏好写入失败（%s）: %v", id, err)
	}
	switch req.Action {
	case "start":
		recordAudit(c, "启动", "任务监控", "常驻任务 "+id+" 启动")
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已启动任务 " + id})
	case "stop":
		recordAudit(c, "停止", "任务监控", "常驻任务 "+id+" 停止")
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已停止任务 " + id})
	default:
		recordAudit(c, "重启", "任务监控", "常驻任务 "+id+" 重启")
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已重启任务 " + id})
	}
}

// GetSystemTaskHistory 任务运行历史（task_runs，时间倒序）。
func (h *Handlers) GetSystemTaskHistory(c *gin.Context) {
	id := c.Param("id")
	limit := 50
	if te := services.TaskEngine(); te != nil {
		runs := te.History(id, limit)
		if runs == nil {
			runs = []taskengine.RunRecord{}
		}
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"runs": runs}})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"runs": []struct{}{}}})
}

// GetSystemTaskStats24hSeries 24h 分小时桶成功/失败序列（全员可见）——
// 任务监控「近 24 小时执行」卡片时间序列图数据源（2026-10-11 用户裁定方案 A）。
func (h *Handlers) GetSystemTaskStats24hSeries(c *gin.Context) {
	if te := services.TaskEngine(); te != nil {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"series": te.Stats24hHourlySeries()}})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"series": []taskengine.TaskHourlyStat{}}})
}

// GetSystemTaskLogs 任务文本日志（统一任务引擎管理——tasks/{id}.log；
// 更新族含分阶段流水 tee）。
func (h *Handlers) GetSystemTaskLogs(c *gin.Context) {
	id := c.Param("id")
	path, err := systemTaskLogPath(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "任务日志路径解析失败: " + err.Error()})
		return
	}
	if path == "" {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"content": ""}})
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		// U3-P4-4：文件不存在=空内容（任务尚未产生日志）；读失败=500（曾一律 200
		// 空内容，与不存在不可区分）。
		if errors.Is(err, os.ErrNotExist) {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"content": ""}})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "任务日志读取失败: " + err.Error()})
		return
	}
	// 尾部 256KB（日志弹框消费口径，防超长载荷）
	const tail = 256 << 10
	if len(data) > tail {
		data = data[len(data)-tail:]
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"content": string(data)}})
}
