package services

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"lazy-balancer-v2/internal/taskengine"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// currentLocation 保存当前生效时区。init() 与 ConfigureLocation 是唯一
// 两条写入口且都写入非 nil *time.Location——改用 typed atomic.Pointer 后
// Load 的返回值即契约（旧 atomic.Value 版本还带一个「未初始化→UTC」回落，
// 该分支不可达，且会把「未初始化」伪装成一个合法时区，已删除）。
var currentLocation atomic.Pointer[time.Location]
var applicationLogLevel atomic.Int32

const (
	logLevelDebug int32 = iota
	logLevelInfo
	logLevelWarn
	logLevelError
)

var timezoneRefresh backgroundWorker

// timezoneRefreshRestartWaitMax 是重启路径等待旧 worker 退出的预算（与关停
// 路径同量级）。旧 worker 卡在 DB busy_timeout 时不得无界挂起刷新链启动。
const timezoneRefreshRestartWaitMax = 1 * time.Second

const timezoneRefreshLogLabel = "timezone refresh"

func init() {
	currentLocation.Store(time.FixedZone("CST", 8*3600))
	applicationLogLevel.Store(logLevelInfo)
	StartTimezoneRefresh(context.Background())
}

func StartTimezoneRefresh(ctx context.Context) <-chan struct{} {
	workerCtx, done := timezoneRefresh.replace(ctx, timezoneRefreshRestartWaitMax, timezoneRefreshLogLabel)
	go func() {
		defer close(done)
		// 30s tick 下持久失败逐轮同消息（最坏 2880 行/天）——改状态
		// 转换口径（ok→fail 一次 warn、持续静默、fail→ok 一次 info），与
		// metrics 采集族共用 logStateTransition。
		refresh := func() {
			if err := refreshLocation(); err != nil {
				if logStateTransition("timezone-refresh", true) != "" {
					Logf("warn", "refresh timezone: %v", err)
				}
				return
			}
			if logStateTransition("timezone-refresh", false) != "" {
				Logf("info", "refresh timezone recovered")
			}
		}
		refresh()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				refresh()
			case <-workerCtx.Done():
				return
			}
		}
	}()
	return done
}

func StopTimezoneRefresh() {
	timezoneRefresh.stop(timezoneRefreshLogLabel)
}

// StopTimezoneRefreshWithin 有界停止时区刷新 worker：cancel 后最多等待 within
// （within<=0=无界，与 StopTimezoneRefresh 同语义）。超时放弃等待并 warn——
// 进程退出路径用：残留 goroutine 随进程消亡，cancel/done 字段保留，worker
// 最终退出后可再次调用完成清零（可重启语义不变）。返回 true=worker 已退出
// 且状态清零。
func StopTimezoneRefreshWithin(within time.Duration) bool {
	return timezoneRefresh.stopWithin(within, timezoneRefreshLogLabel)
}

func refreshLocation() (err error) {
	// 后台 worker 可能存活到测试/关停收尾之后：此时数据库句柄可能已关闭或
	// 被并发置空，driver 内部会在 conn 阶段 panic。后台刷新不得拖垮进程，
	// 转为错误交由状态机留痕与下轮重试。
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("refresh timezone panic: %v", r)
		}
	}()
	database := db.GetDB()
	if database == nil {
		return nil
	}
	var tz string
	if err := database.QueryRow("SELECT COALESCE(timezone,?) FROM global_config WHERE id=1", db.DefaultTimezone).Scan(&tz); err != nil {
		return fmt.Errorf("read configured timezone: %w", err)
	}
	// 刷新路径与写侧同一校验器：ConfigureLocation 内含 ValidateLocationName
	// （拒绝空/空白串，time.LoadLocation("") 合法返回 UTC——放行会静默把全站
	// 展示/审计窗口切成 UTC）。此处不再前置重复校验：同一时区名三次加载/校验
	// 属纯冗余，单点校验失败同样由调用方状态机留痕（启动迁移已兜底存量脏值）。
	if _, err := ConfigureLocation(tz); err != nil {
		return fmt.Errorf("configured timezone %q rejected (keeping previous): %w", tz, err)
	}
	return nil
}

// ValidateLocationName 校验时区名是否可作为 global_config.timezone 落库。
// 空串必须显式拒绝：time.LoadLocation("") 是 Go 的合法特殊值（返回 UTC），
// 放行后读侧 COALESCE(timezone,?) 绑定 db.DefaultTimezone 只兜 NULL 不兜空串，
// 全站展示/审计窗口会静默切 UTC。写侧（设置保存/备份导入）与启动归一三处同口径。
func ValidateLocationName(name string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("时区不能为空")
	}
	if _, err := time.LoadLocation(name); err != nil {
		return fmt.Errorf("无效的时区: %w", err)
	}
	return nil
}

func ConfigureLocation(name string) (*time.Location, error) {
	// 单源校验：time.LoadLocation("") 合法返回 UTC，放行会让第二写入口静默
	// 把全站切 UTC。读刷新/写侧/启动均已预校验，此处是防御纵深的单点收敛。
	if err := ValidateLocationName(name); err != nil {
		return nil, err
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, err
	}
	taskengine.SetLocation(loc) // 任务引擎时间遵循配置时区（启动+设置变更双路径）
	currentLocation.Store(loc)
	return loc, nil
}

// CurrentLocation 返回当前生效时区（init/ConfigureLocation 保证非 nil）。
func CurrentLocation() *time.Location {
	return currentLocation.Load()
}

func ConfigureLogLevel(level string) error {
	var threshold int32
	switch level {
	case "debug":
		threshold = logLevelDebug
	case "info":
		threshold = logLevelInfo
	case "warn":
		threshold = logLevelWarn
	case "error":
		threshold = logLevelError
	default:
		return fmt.Errorf("unsupported application log level %q", level)
	}
	applicationLogLevel.Store(threshold)
	if threshold == logLevelDebug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}
	return nil
}

func CurrentLogLevel() string {
	switch applicationLogLevel.Load() {
	case logLevelDebug:
		return "debug"
	case logLevelWarn:
		return "warn"
	case logLevelError:
		return "error"
	default:
		return "info"
	}
}

func shouldLog(level string) bool {
	var candidate int32
	switch level {
	case "debug":
		candidate = logLevelDebug
	case "info":
		candidate = logLevelInfo
	case "warn":
		candidate = logLevelWarn
	case "error":
		candidate = logLevelError
	default:
		return false
	}
	return candidate >= applicationLogLevel.Load()
}

func Logf(level, format string, args ...any) {
	if !shouldLog(level) {
		return
	}
	switch level {
	case "warn":
		log.Printf("WARNING: "+format, args...)
	case "error":
		log.Printf("ERROR: "+format, args...)
	default:
		log.Printf(format, args...)
	}
}

// applicationLogWriter 按 "WARNING:"/"ERROR:" 行首前缀做级别过滤
// 历史·声明）——隐式依赖 main.go log.SetFlags(0)：标准 log 的时间戳/
// 文件名前缀会顶掉级别前缀使过滤全数落空。两侧契约互指（见 main.go 同名注释）。
// 多行 payload（Logf 消息内嵌换行）逐行判定后重组——只看首行会把
// 后续低级别行一并放行（warn/error 档过滤被绕过）。
type applicationLogWriter struct {
	w io.Writer
}

func NewApplicationLogWriter(writer io.Writer) io.Writer {
	return &applicationLogWriter{w: writer}
}

func (writer *applicationLogWriter) Write(p []byte) (int, error) {
	threshold := applicationLogLevel.Load()
	if threshold <= logLevelInfo {
		return writer.w.Write(p)
	}
	trailingNewline := len(p) > 0 && p[len(p)-1] == '\n'
	body := p
	if trailingNewline {
		body = p[:len(p)-1]
	}
	if !bytes.ContainsRune(body, '\n') {
		// 单行热路径（标准 log 常态）：行首前缀判定一次，零额外分配。
		if !lineAllowedAtThreshold(body, threshold) {
			return len(p), nil
		}
		return writer.w.Write(p)
	}
	// 多行 payload（Logf 消息内嵌换行）必须逐行判定并
	// 重组——只看首行会让 warn/error 档把后续 info 级行整体放行（级别过滤失效）。
	lines := bytes.Split(body, []byte("\n"))
	kept := make([][]byte, 0, len(lines))
	for _, line := range lines {
		if lineAllowedAtThreshold(line, threshold) {
			kept = append(kept, line)
		}
	}
	if len(kept) == 0 {
		return len(p), nil
	}
	out := bytes.Join(kept, []byte("\n"))
	if trailingNewline {
		out = append(out, '\n')
	}
	written, err := writer.w.Write(out)
	if err != nil {
		return written, err
	}
	// 多行过滤后 out 短于 p，sink 写满 out 即表示入参
	// 全部被消费——必须返回 len(p), nil（此前返回 sink 的 written<len(p) 且
	// err=nil，违反 io.Writer「n<len(p) 必须带 error」契约，短写敏感的消费者
	// （io.Copy/bufio）会把它当截断重试）。sink 自身短写时无法把 sink 字节
	// 映射回入参，按契约报 io.ErrShortWrite。
	if written < len(out) {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

// lineAllowedAtThreshold 报告单行日志是否达到配置阈值（行首级别前缀判定）。
// 调用方不得把多行 payload 直接交给本函数——只看首行会让整体放行。
func lineAllowedAtThreshold(line []byte, threshold int32) bool {
	line = trimLeadingASCIIWhitespace(line)
	if threshold >= logLevelError {
		return hasASCIIPrefixFold(line, "ERROR")
	}
	return hasASCIIPrefixFold(line, "WARN") || hasASCIIPrefixFold(line, "ERROR")
}

func trimLeadingASCIIWhitespace(value []byte) []byte {
	for len(value) > 0 {
		switch value[0] {
		case ' ', '\t', '\n', '\r', '\v', '\f':
			value = value[1:]
		default:
			return value
		}
	}
	return value
}

func hasASCIIPrefixFold(value []byte, prefix string) bool {
	if len(value) < len(prefix) {
		return false
	}
	for index := range len(prefix) {
		candidate := value[index]
		if candidate >= 'a' && candidate <= 'z' {
			candidate -= 'a' - 'A'
		}
		if candidate != prefix[index] {
			return false
		}
	}
	return true
}

// ApplyLogLevel 读取全局日志级别并应用。main 在 db.Initialize 完成后立即调用，
// 集群配置导入（users 节）后亦调用——此装配点同时执行
// 一次即时 refreshLocation。init 期启动的刷新 worker 首查时 DB 未就绪恒空转，
// 配置时区（尤其 DST 时区）此前最长要等 30s ticker 才生效，期间日志时间戳落在
// FixedZone+8 占位时区；装配点即时刷新消除该窗口，导入新时区亦即时生效。
func ApplyLogLevel() {
	level := "info"
	if db.DB != nil {
		if err := db.DB.QueryRow("SELECT COALESCE(log_level,'info') FROM global_config WHERE id=1").Scan(&level); err != nil {
			// 读失败不得静默降级：warn/error 配置失效会放大日志量，与「配置
			// 读失败必须留痕」同族。状态转换口径（首报 warn + 恢复 info）避免
			// 每次装配刷屏。
			if lvl := logStateTransition("log-level-refresh", true); lvl != "" {
				Logf(lvl, "读取日志级别配置失败，按 info 应用: %v", err)
			}
			level = "info"
		} else if lvl := logStateTransition("log-level-refresh", false); lvl != "" {
			Logf(lvl, "读取日志级别配置已恢复")
		}
	}
	if err := ConfigureLogLevel(level); err != nil {
		Logf("error", "apply application log level: %v", err)
	}
	if err := refreshLocation(); err != nil {
		Logf("error", "refresh timezone: %v", err)
	}
}
