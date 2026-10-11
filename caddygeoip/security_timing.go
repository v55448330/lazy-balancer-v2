package caddygeoip

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// securityTimingLogPath 是耗时侧车日志路径——与 coraza 审计日志同目录
// (auditLogPath = /app/logs/waf-audit/audit.log 的同族约定),lazy-balancer
// 进程的摄取管道按行读「<timing_id>:<pre|end> <duration_us>」与审计条目按
// timing ID 关联(读侧 tick 级合并 map,见 securityevents.go securityTimingLoad)。跨进程经文件通信(caddygeoip 编译进 Caddy 二进制,摄取管道在
// lazy-balancer 二进制——不同进程,内存共享不可达)。
var securityTimingLogPath = "/app/logs/waf-audit/security-timing.log"

// securityTimingHeader 是耗时关联头——blocked_counter 注入、coraza 审计日志
// request.headers 收录、摄取管道读出后查耗时侧车文件。渲染链在该头抵达
// reverse_proxy 前删除(caddy.go 渲染层),不上泄上游。
const securityTimingHeader = "X-Lb-Security-Timing-Id"

// securityTimingStartHeader 是起始纳秒时间戳头——blocked_counter 注入,
// SecurityTimingEnd 在安全链末尾读取计算 passed 事件的纯评估耗时(不含
// reverse_proxy 上游往返)。与 timing ID 头同清单剥离。
const securityTimingStartHeader = "X-Lb-Security-Timing-Start-Ns"

// securityTimingFileMu/Fd 惰性打开的追加写句柄——首写时 OpenFile,进程生命周期
// 复用;打开失败静默降级(耗时缺失,不阻断请求);目录不存在时 MkdirAll 兜底。
var (
	securityTimingMu sync.Mutex
	securityTimingFd *os.File
)

// AppendSecurityTiming 追加一行「<id> <us>」到耗时侧车日志(写侧:blocked_counter/timing_pre/timing_end 三点)。
// 任何 I/O 失败静默降级——耗时是增强信息,不产生任何请求路径错误。
func AppendSecurityTiming(id string, durationUs int64) {
	if id == "" {
		return
	}
	securityTimingMu.Lock()
	defer securityTimingMu.Unlock()
	if securityTimingFd == nil {
		_ = os.MkdirAll(filepath.Dir(securityTimingLogPath), 0755)
		f, err := os.OpenFile(securityTimingLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return
		}
		securityTimingFd = f
	}
	_, _ = fmt.Fprintf(securityTimingFd, "%s %d\n", id, durationUs)
}

// recordSecurityTiming 读耗时关联头对（timing ID + 起始纳秒）并记录一段耗时——
// PLUG-R1（第 69 轮 P4）：SecurityTimingPre/End 两 ServeHTTP 原逐字重复，收敛为
// 本 helper，suffix 区分收点（":pre" 预检段 / ":end" 全链）。头对缺失或起始
// 时间戳不可解析时静默跳过（耗时是增强信息，不产生请求路径错误）。
func recordSecurityTiming(r *http.Request, suffix string) {
	timingID := r.Header.Get(securityTimingHeader)
	startNsStr := r.Header.Get(securityTimingStartHeader)
	if timingID != "" && startNsStr != "" {
		if startNs, perr := strconv.ParseInt(startNsStr, 10, 64); perr == nil {
			AppendSecurityTiming(timingID+suffix, (time.Now().UnixNano()-startNs)/1000) // ns→µs
		}
	}
}

// securityTimingID 生成 16 字符随机 hex 作 timing 关联 ID(第 62 轮 F62-29:
// 原 4 字节生日界下 1 万在途即 ~1.2% 任意对碰撞概率——扩到 8 字节对齐
// coraza tx.ID 长度,碰撞面消除;rand 失败返回空串=该请求不计耗时,静默降级)。
func securityTimingID() string {
	b := make([]byte, 8)
	if _, err := cryptorand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}
