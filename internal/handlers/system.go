package handlers

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// exitProcess 进程退出测试钩（归位：唯一生产消费方是
// restartProcess 的延迟退出回退，钩随语义属主落户 system.go；前历史
// 落位于 admintls.go）。生产=os.Exit，测试替换为 channel 信号。
var exitProcess = os.Exit

// restartProcess 触发进程重启：优先走 services 统一重启信号——与集群
// 同步的 Admin TLS 热切换同一触发器（main 注入优雅停机信号，HTTP 优雅关停后
// 退出，进程级设置随之生效）；未注入（独立/测试环境）时回退旧行为：延迟
// 500ms 待响应写出后经 exitProcess（测试可替换变量）退出。
func restartProcess() {
	if services.RequestRestart() {
		return
	}
	go func() {
		time.Sleep(500 * time.Millisecond)
		exitProcess(0)
	}()
}

// RestartService exits the process after responding; the container's
// restart policy brings the service back up (used to apply process-level
// settings such as the Caddy log timezone).
func (h *Handlers) RestartService(c *gin.Context) {
	// 与同族写端点同口径：导入窗口内重启会终止提交前已落盘的 WAF 文件/证书
	// 回退路径（abort 只存在于进程内），比任何被 409 拦下的写操作更重。
	// action 只传短动作词——rejectWriteDuringImport 已自带「配置导入进行中，
	// 暂不能」前缀，再带括号短语会得到重复文案。
	if rejectWriteDuringImport(c, "执行服务重启") {
		return
	}
	recordAudit(c, "重启", "系统", "用户触发服务重启")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "服务正在重启"})
	restartProcess()
}

func (h *Handlers) GetSystemInfo(c *gin.Context) {
	brandingCfg := loadBrandingConfig(h.cfg.DataDir)
	version := h.cfg.Version
	if brandingCfg.Version != "" {
		version = brandingCfg.Version
	}
	info := models.SystemInfo{
		NodeMode:     "master",
		IPAddress:    getOutboundIP(),
		Hostname:     getHostname(),
		OSInfo:       getOSInfo(),
		Kernel:       getKernel(),
		Architecture: getArchitecture(),
		NetworkIPs:   getNetworkIPs(),
		CaddyVersion: getCaddyVersion(),
		// 「面板进程存活」——能响应本请求即恒为 running，不反映 Caddy
		// admin 是否可达（Caddy 停摆时本字段仍为 running）。
		RunningStatus: "running",
		Uptime:        getUptime(),
		Version:       version,
	}
	// 角色查询失败/库未装配时不得静默呈现 master——
	// 排障窗口里「显示主节点」会把方向引偏（同域写门 requireMasterNode 对同一
	// 故障响亮 500）。三态化：unknown 并留 warn。
	switch {
	case db.DB == nil:
		services.Logf("warn", "system info: 数据库未装配，节点角色未知（node_mode=unknown）")
		info.NodeMode = "unknown"
	default:
		// 角色读是单行索引查询，与请求生命周期无关：用脱离客户端取消的短超时
		// 上下文，客户端断开不得被记成「角色查询失败」。留痕走状态转换限频
		// （同 getOutboundIP 口径）——否则任一登录用户反复中断本端点即可逐请求
		// 放大一条 warn，污染排障面。
		roleCtx, cancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), 2*time.Second)
		isMaster, err := services.RoleOf(roleCtx, db.DB)
		cancel()
		if err != nil {
			services.LogConfigReadFailure("system-role", err)
			info.NodeMode = "unknown"
		} else {
			services.LogConfigReadRecovered("system-role")
			if !isMaster {
				info.NodeMode = "slave"
			}
		}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: info})
}

// systemInternalFailure 500 统一装配：固定中文文案回客户端，底层错误
// （os/gopsutil 路径、命令输出）只进运行日志——/system 指标与运行日志端点
// 属 business 组，任意登录用户可读，不得把文件布局/内部结构透给客户端。
func systemInternalFailure(message string, err error) models.APIResponse {
	return internalError("系统信息", message, err)
}

func (h *Handlers) GetSystemMetrics(c *gin.Context) {
	metrics, err := getSystemMetrics()
	if err != nil {
		c.JSON(http.StatusInternalServerError, systemInternalFailure("读取系统指标失败", err))
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: metrics})
}

func (h *Handlers) GetRealtimeTraffic(c *gin.Context) {
	traffic, err := getRealtimeTraffic()
	if err != nil {
		c.JSON(http.StatusInternalServerError, systemInternalFailure("读取实时流量失败", err))
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: traffic})
}

func (h *Handlers) GetConnectionStats(c *gin.Context) {
	stats, err := getConnectionStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, systemInternalFailure("读取连接统计失败", err))
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: stats})
}

func (h *Handlers) GetAppLogs(c *gin.Context) {
	// 运行日志路径经 logPaths 统一口径——LOG_FILE 空串
	// 时兜底默认运行日志(与 GetLogStats 同源),消除空串路径读出的恒空 200。
	_, logPath := logPaths(h.cfg)
	maxBytes := int64(128 * 1024)
	const maxLines = 500

	// 只读常规文件：判定必须落在已打开的 fd 上。路径 Stat 与 os.Open 之间目标
	// 被替换为 FIFO/设备节点时，open(2) 对无写端 FIFO 会无超时阻塞（每请求
	// 永久占一个 goroutine/连接，任意登录用户可低成本耗尽资源）。O_NONBLOCK
	// 使打开本身不阻塞（常规文件读取不受该标志影响），随后以 f.Stat() 的
	// mode 判定类型并取 size——不存在「检查后替换」的窗口。
	f, err := os.OpenFile(logPath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		if os.IsNotExist(err) {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]string{"content": ""}})
			return
		}
		c.JSON(http.StatusInternalServerError, systemInternalFailure("打开日志文件失败", err))
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		c.JSON(http.StatusInternalServerError, systemInternalFailure("读取日志失败", err))
		return
	}
	if !info.Mode().IsRegular() {
		c.JSON(http.StatusInternalServerError, systemInternalFailure("读取日志失败", fmt.Errorf("非常规文件: %s mode=%v", logPath, info.Mode())))
		return
	}
	startOffset := int64(0)
	if info.Size() > maxBytes {
		startOffset = info.Size() - maxBytes
	}
	if _, err := f.Seek(startOffset, io.SeekStart); err != nil {
		c.JSON(http.StatusInternalServerError, systemInternalFailure("读取日志失败", err))
		return
	}
	// Stat 与读取之间日志增长/文件被替换为 FIFO 时，
	// 无界 io.ReadAll 会读入远超 maxBytes 的数据。与任务日志/证书任务日志
	// 尾读同口径加上限（窗口本身 ≤128KB）。
	data, err := io.ReadAll(io.LimitReader(f, maxBytes))
	if err != nil {
		c.JSON(http.StatusInternalServerError, systemInternalFailure("读取日志失败", err))
		return
	}
	// 窗口起点可能落在某行中段——切在多字节
	// UTF-8 rune 中间时首行残段带无效字节,JSON 编码后以 U+FFFD 污染输出。
	// 统一口径抽享 tailLogWindow（GetCaddyLogs 同 helper）。
	data = tailLogWindow(f, data, startOffset)
	lines := strings.Split(string(data), "\n")
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]string{"content": strings.Join(lines, "\n")}})
}
