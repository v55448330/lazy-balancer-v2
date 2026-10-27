package handlers

// 任务监控 handlers（v2.3.4）：GET /system/tasks 全员可见（从节点只读视图）；
// trigger/toggle/cancel 为管理员操作（adminOnly+readOnlyGuard 路由组）。
// 操作映射到各任务族既有入口（manager StartUpdate/SetAutoUpdate/CancelRunning），
// 本层零新状态。

import (
	"database/sql"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

// ListSystemTasks 聚合全部任务族状态（全员可见）。
func (h *Handlers) ListSystemTasks(c *gin.Context) {
	tasks, certJobsTruncated := services.CollectSystemTasks()
	if tasks == nil {
		tasks = []services.TaskInfo{}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"tasks": tasks, "cert_jobs_truncated": certJobsTruncated}})
}

// requireMasterNode 主节点门（写操作镜像 StartCRSUpdate 口径）。
// 角色查询失败（DB 故障/迁移窗口）≠ 从节点——查询失败响亮 500，
// 403「仅允许在主节点执行」会把排障方向指向集群角色（与 requireMaster 及
// requireAutoBackupMaster 的 ② 先例同形）。
func requireMasterNode(c *gin.Context) bool {
	if db.DB == nil {
		clusterError(c, http.StatusInternalServerError, "节点角色查询失败", nil)
		return false
	}
	isMaster, err := services.RoleOf(c.Request.Context(), db.DB)
	return requireMasterResult(c, isMaster, err, masterGateOptions{
		queryFailure: "节点角色查询失败",
		forbidden:    "该操作仅允许在主节点执行",
	})
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

// respondTaskTriggerAdmissionError 统一同步 admission 的 HTTP 映射。
// 审计由触发服务/调用方按既有单记口径处理，本 helper 只写响应。
func respondTaskTriggerAdmissionError(c *gin.Context, err error) {
	if errors.Is(err, taskengine.ErrNotMaster) {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "任务当前不可触发: " + err.Error()})
		return
	}
	if errors.Is(err, taskengine.ErrAlreadyRunning) || errors.Is(err, taskengine.ErrSchedulingPaused) || errors.Is(err, taskengine.ErrEngineStopped) {
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "任务当前不可触发: " + err.Error()})
		return
	}
	c.JSON(http.StatusServiceUnavailable, models.APIResponse{Code: 503, Message: "任务触发失败: " + err.Error()})
}

// respondTaskEngineUnavailable 任务引擎未装配的统一响应。引擎缺失属「服务
// 暂不可用」而非内部错误——与触发/启停/取消路径的 503 同口径，
// 全仓单一出口（库更新触发端点此前 500，与任务监控 503
// 形成家族状态码漂移）。
func respondTaskEngineUnavailable(c *gin.Context) {
	c.JSON(http.StatusServiceUnavailable, models.APIResponse{Code: 503, Message: "任务引擎未初始化"})
}

// respondTaskEngineStopped 引擎已停止（关停窗口/测试装配/嵌入形态）时的统一
// 响应：调度写端点在已停引擎上调用 StartLoop/StopLoop 均为 no-op，回 200 与
// 「已恢复/已停止」文案是假信号（只有偏好落库、下次启动才生效）。
func respondTaskEngineStopped(c *gin.Context) {
	c.JSON(http.StatusServiceUnavailable, models.APIResponse{Code: 503, Message: "任务引擎已停止，调度操作未生效"})
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
		// 已停止引擎：admission 恒 ErrEngineStopped，此前并入 409 Conflict，与
		// toggle/cancel/control 的 503「任务引擎已停止」成为同一事实的两种状态码
		// （违文档 §4.3 写端点状态码统一），且会补记一条误导性「触发失败」审计。
		if te.IsStopped() {
			respondTaskEngineStopped(c)
			return
		}
		if m, ok := te.Lookup(id); ok { // 单任务元数据（免全量 DescribeAll）
			if !m.CanTrigger {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "该任务不支持手动触发（常驻族启停即可/镜像族）"})
				return
			}
			// v2.0：单飞由引擎 CAS 强制；在跑任务同步 409
			// （曾异步吞错恒 200+apidocs 409 不可达——双击假成功）
			if te.IsTaskInFlight(id) {
				c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "任务运行中，请稍后重试"})
				return
			}
			// 触发与审计统一走 services.TriggerTaskAsync（单源）——
			// 「触发」审计只在 Trigger 成功后记录（非自记族），并发双击败者
			// 拿 ErrAlreadyRunning 静默、skipped 终态静默、真失败记补偿审计。
			// gin.Context 在 handler 返回后池化复用：审计上下文必须在此预取。
			// 同步预占位：暂停/停止/角色拒绝必须在写响应前返回 409/503，
			// 不能先 200 再在 goroutine 里吞错。
			actx := triggerAuditContext(c, "任务监控", m.Name)
			if err := services.TriggerTaskAsync(te, id, actx); err != nil {
				respondTaskTriggerAdmissionError(c, err)
				return
			}
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"status": "running", "trigger": "manual"}})
			return
		}
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "任务不存在"})
		return
	}
	// 无引擎时统一 503（回退 switch 删除）。
	respondTaskEngineUnavailable(c)
}

// ToggleSystemTask 调度开关（admin；body {"enabled": bool}）。
// v2.0：统一路由引擎循环开关（StartLoop/StopLoop）——Kind 决定语义：
// 定时/循环=停止/恢复调度；常驻=启停自管理循环；
// 触发=不可调度（前端显示禁用开关）。
func (h *Handlers) ToggleSystemTask(c *gin.Context) {
	if configImportBusy() {
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "配置导入进行中，暂不能调整任务调度"})
		return
	}
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
		// 已停止引擎：StartLoop/StopLoop 恒 no-op，200「已恢复/已停止」与
		// 审计留痕都是假信号（只有偏好落库，下次启动才生效）——统一 503。
		if te.IsStopped() {
			respondTaskEngineStopped(c)
			return
		}
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
			// 用户显式启停落节点本地偏好（重启后不得按默认清单复活）。
			// 先持久化再切换内存态：写失败时调度状态必须原样保留并响亮
			// 500——此前先切换再吞 WARN，响应仍 200 且偏好零行，重启后按
			// 默认清单复活与用户意图相反。
			if err := services.RecordTaskLoopPref(id, *req.Enabled); err != nil {
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "任务调度偏好保存失败，调度状态未改变：" + err.Error()})
				return
			}
			if *req.Enabled {
				te.StartLoop(id)
			} else {
				te.StopLoop(id)
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
	// 无引擎时统一 503（回退 switch 删除）。
	respondTaskEngineUnavailable(c)
}

// CancelSystemTask 取消运行中任务（admin；仅 Cancelable 声明族）。
// 引擎路径经 te.Cancel（Cancelable+CancelHook 元数据路由），
// 不再硬编码三族清单；无引擎回退（测试环境）直调 manager。
func (h *Handlers) CancelSystemTask(c *gin.Context) {
	id := c.Param("id")
	if !requireMasterNode(c) {
		return
	}
	// 配置导入窗口 409（与 toggle/control 同门）：导入/还原期间协调器执行
	// PauseScheduling+CancelInFlightRuns+WaitInFlightRuns 的系统性排空；此时
	// 命中的 auto 轮若被用户取消，Cancel 走 consumeCancelledSlotLocked 消费
	// 已到期槽——与「导入排空不消费槽（恢复后补跑）」语义相反，回滚后该族
	// 自动更新会推迟到下一排程槽。
	if configImportBusy() {
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "配置导入进行中，暂不能取消任务"})
		return
	}
	// 取消与 Trigger/Toggle/Control 共用集群写门；引擎 RunsOn 另管执行角色。
	if te := services.TaskEngine(); te != nil {
		// 已停止引擎：Cancel 恒 false，409「任务未在运行」会把「引擎已停止」
		// 误报成任务状态问题——与 toggle/control 同口径统一 503。
		if te.IsStopped() {
			respondTaskEngineStopped(c)
			return
		}
		if _, ok := te.Lookup(id); !ok {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "任务不存在"})
			return
		}
		if !te.Cancel(id) {
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "任务未在运行中或不支持取消"})
			return
		}
		// 文案中性化：可取消族含 crs/ip2region（检查→拉取→安装/重载），
		// 硬编码「下载阶段」会让审计台账与真实中断阶段不一致。
		recordAudit(c, "取消", "任务监控", "手动取消任务 "+id+"（当前阶段中断，已完成部分保留）")
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已发出取消信号，任务将在当前阶段中断"})
		return
	}
	// 无引擎时统一 503（回退 switch 删除）。
	respondTaskEngineUnavailable(c)
}

// ControlSystemTask 常驻循环启停（admin；body {"action":"start|stop|restart"}）。
// 现形态——Controllable = Kind==Daemon（引擎元数据驱动），
// 仅常驻族（security-events-ingestion/cert-issuance/cluster-sync）可控；Periodic
// 族（cert-waiting-ca 等）启停走 toggle 端点，本端点对其恒 400。v2.0 前
// 「Continuous 族可控」注释已随四类型标准作废。
func (h *Handlers) ControlSystemTask(c *gin.Context) {
	if configImportBusy() {
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "配置导入进行中，暂不能启停任务"})
		return
	}
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
		respondTaskEngineUnavailable(c)
		return
	}
	// 已停止引擎：Start/Stop/Restart 全是 no-op——200「已启动/已重启」是假
	// 信号，统一 503（与 toggle 同口径）。
	if te.IsStopped() {
		respondTaskEngineStopped(c)
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
	// 用户显式启停落节点本地偏好；restart 的终态为运行。与 toggle 同口径：
	// 先持久化再动作——写失败即 500 且内存态不动（否则「已重启」是假信号，
	// 重启后偏好仍是旧值）。
	if err := services.RecordTaskLoopPref(id, req.Action != "stop"); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "任务调度偏好保存失败，调度状态未改变：" + err.Error()})
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
// cert-job:<id> 动态行与 logs/trigger 同族：无引擎 task_runs 记录，历史即
// cert_jobs 行本身（在册签发记录：创建/更新/终态与消息），按 RunRecord 同形
// 返回，API 消费端不再需要为动态行单独走 /certificates/jobs/:id。
func (h *Handlers) GetSystemTaskHistory(c *gin.Context) {
	id := c.Param("id")
	limit := 50
	if strings.HasPrefix(id, "cert-job:") {
		h.certJobRunHistory(c, id)
		return
	}
	if te := services.TaskEngine(); te != nil {
		if _, ok := te.Lookup(id); !ok {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "任务不存在"})
			return
		}
		// 残留 running 行归一在引擎 History/LatestRun 内完成（与列表同一判定
		// 与文案）——列表把该行呈现为失败/已中断，历史不得仍称「运行中」。
		runs := te.History(id, limit)
		if runs == nil {
			runs = []taskengine.RunRecord{}
		}
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"runs": runs}})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"runs": []struct{}{}}})
}

// certJobRunHistory 把 cert_jobs 单行映射为 RunRecord 形状的历史（与面板
// 前端对 cert-job 行的展示映射同口径：started_at=created_at、
// finished_at=updated_at、duration=两者差、trigger=queue）。cert_jobs 时间戳
// 为 UTC（RFC3339），统一转配置时区墙串——与引擎族 started_at 的展示口径一致。
func (h *Handlers) certJobRunHistory(c *gin.Context, taskID string) {
	jobID, err := strconv.Atoi(strings.TrimPrefix(taskID, "cert-job:"))
	if err != nil || jobID <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid job ID"})
		return
	}
	// 库句柄缺失属「服务暂不可用」而非任务不存在——与 requireMasterNode
	// 的角色读失败同口径 500；裸用 db.DB 会 nil 解引用 panic（gin.Recovery
	// 兜成 500 + 栈噪声）。
	if db.DB == nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库未初始化"})
		return
	}
	var status, message string
	var createdAt, updatedAt sql.NullString
	if err := db.DB.QueryRow(`SELECT status, COALESCE(message,''), created_at, updated_at FROM cert_jobs WHERE id=?`, jobID).
		Scan(&status, &message, &createdAt, &updatedAt); dbQueryNotFound(c, err, "任务不存在", "certJobRunHistory query job") {
		return
	}
	// 时间口径与任务监控列表同源（services.CertJobRunTimes）：started=created_at、
	// finished=updated_at、duration=两者差；缺失或不可解析保持零值（不得在
	// 本层另写一份映射——列表与历史曾各自映射导致同一行时间语义冲突）。
	startedAt, finishedAt, durationMs := services.CertJobRunTimes(createdAt.String, updatedAt.String)
	run := taskengine.RunRecord{
		ID:         int64(jobID),
		TaskID:     taskID,
		Family:     "cert-job",
		Trigger:    "queue",
		Status:     status,
		Message:    message,
		StartedAt:  startedAt,
		FinishedAt: finishedAt,
		DurationMs: durationMs,
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"runs": []taskengine.RunRecord{run}}})
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
		// 本路由属业务读面（全部登录用户可读）——原始 DB/驱动错误只入库内
		// 日志，对外保持 500 + 固定文案（不泄露 schema/驱动/挂载路径）。
		services.Logf("error", "任务日志路径解析失败（%s）: %v", id, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "任务日志路径解析失败"})
		return
	}
	if path == "" {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"content": ""}})
		return
	}
	// 尾部 256KB（日志弹框消费口径，防超长载荷）。先 Seek 再限量读，
	// 不把最大 1GB 的任务日志整文件读入内存。
	const tail = 256 << 10
	var data []byte
	// 原始文件系统错误只入库内日志（业务读面对全部登录用户可见，不泄露
	// 挂载路径/权限细节），对外固定文案 + 保留 500 语义（不改为 404/200，
	// 避免与「任务不存在」混淆）。
	failRead := func(stage string, err error) {
		services.Logf("error", "任务日志读取失败（%s, %s）: %v", id, stage, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "任务日志读取失败"})
	}
	info, statErr := os.Stat(path)
	switch {
	case statErr == nil:
		startOffset := int64(0)
		if info.Size() > tail {
			startOffset = info.Size() - tail
		}
		file, err := os.Open(path)
		if err != nil {
			failRead("open", err)
			return
		}
		defer file.Close()
		if _, err := file.Seek(startOffset, io.SeekStart); err != nil {
			failRead("seek", err)
			return
		}
		data, err = io.ReadAll(io.LimitReader(file, int64(tail)))
		if err != nil {
			failRead("read", err)
			return
		}
		data = tailLogWindow(file, data, startOffset)
	case errors.Is(statErr, os.ErrNotExist):
		// 活动文件缺失（外部删除，或轮转 rename 完成后写入失败）不得直接
		// 返回空——轮转副本（.1…）可能仍有内容，落入下方统一拼接。
	default:
		failRead("stat", statErr)
		return
	}
	keep := 1 // 普通任务写侧 RotateTaskLogBeforeWrite(..., 1)
	if strings.HasPrefix(id, "cert-job:") {
		keep = certJobLogMaxRotatedBackups
	}
	content := prependTaskLogRotations(path, string(data), keep, tail)
	// 256KB 是活动文件与轮转副本拼接后的合计预算。必须直接取
	// 拼接串最后 tail 字节，再丢弃首行残段；tailLogWindow 只负责行边界，
	// 不能把全串当成已定位的尾窗（否则仅丢首行，响应仍可数倍超限）。
	if len(content) > tail {
		start := len(content) - tail
		if idx := strings.IndexByte(content[start:], '\n'); idx >= 0 {
			content = content[start+idx+1:]
		} else {
			content = ""
		}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"content": content}})
}
