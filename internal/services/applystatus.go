package services

import (
	"fmt"
	"sync"
	"time"
)

// 后台数据类重载的失败面（证书/CRS/IP2Region/威胁库/自动封禁）。
//
// 背景：caddy_apply_error 只由 handlers 的写路径（recordCaddyApplyResult）落盘，
// 后台数据类重载（证书部署 / CRS / IP2Region / 威胁库 / 自动封禁名单收敛）走
// services 内的注入回调，失败只在应用日志留一行——面板横幅恒不可见，运行配置
// 与库数据可长期分叉而无人察觉。
//
// 形态：按来源记录最近一次失败，成功只清除该来源（一个来源成功不得掩盖另一
// 来源仍在失败）；快照取最近失败的一条供状态接口与前端横幅消费。零新表：
// 进程内状态，重启后由首轮成功/失败重建（与 LKG 等运行态列同口径）。

// BackgroundApplyFailure 是单个来源的后台重载失败快照。
type BackgroundApplyFailure struct {
	Source  string `json:"source"`
	Message string `json:"message"`
	At      string `json:"at"` // 配置时区墙串（展示用）
	// at 是 At 的时间基准（UTC，秒级），只供选源比较。At 是配置时区墙串，
	// 运行时区变更（30s 刷新）后字符串序不再等价于时间序：UTC+8 → UTC 后
	// 新失败串（UTC 墙钟）可能小于旧失败串（+8 墙钟），横幅会长期展示旧源。
	at time.Time
}

type backgroundApplyState struct {
	mu       sync.Mutex
	failures map[string]BackgroundApplyFailure
}

var backgroundApplyStore = backgroundApplyState{failures: map[string]BackgroundApplyFailure{}}

// BackgroundApplySource 后台重载来源标识（状态接口/横幅展示用）。
type BackgroundApplySource string

const (
	BackgroundApplyCertDeploy BackgroundApplySource = "证书部署"
	BackgroundApplyCRS        BackgroundApplySource = "CRS"
	BackgroundApplyIP2Region  BackgroundApplySource = "IP2Region"
	BackgroundApplyThreat     BackgroundApplySource = "威胁情报库"
	BackgroundApplyAutoban    BackgroundApplySource = "自动封禁"
	// BackgroundApplyClusterSync 从节点集群同步快照提交后的 Caddy 重载。
	// 该路径不走 TrackBackgroundReload（重载在 applySnapshot 内联执行），
	// 失败面由 cluster_apply 经 RecordBackgroundApplyFailure 手工登记——
	// 从节点的 caddy_apply_error 从不由 handlers 写路径落盘，本来源是
	// 从节点「库态≠运行态」分叉的全局可观测信号。
	BackgroundApplyClusterSync BackgroundApplySource = "集群同步重载"
)

// TrackBackgroundReload 返回包装后的后台重载回调：失败登记到失败面并按原样
// 返回，成功清除该来源的失败记录。回调本身错误语义不变（调用方仍据错误决定
// 终态/重试），本包装只负责可观测性。
func TrackBackgroundReload(source BackgroundApplySource, reload func() error) func() error {
	if reload == nil {
		return nil
	}
	return func() error {
		err := reload()
		recordBackgroundApplyResult(source, err)
		return err
	}
}

func recordBackgroundApplyResult(source BackgroundApplySource, err error) {
	backgroundApplyStore.mu.Lock()
	defer backgroundApplyStore.mu.Unlock()
	if err == nil {
		delete(backgroundApplyStore.failures, string(source))
		return
	}
	now := time.Now()
	backgroundApplyStore.failures[string(source)] = BackgroundApplyFailure{
		Source: string(source),
		// Message 经 /caddy/status 与前端横幅展示给全员（含只读 API Key）：
		// 后台重载失败同样来自 /load 传输错误，进仓前剥离 admin 端点。
		Message: RedactCaddyAdminEndpoint(err.Error()),
		At:      now.In(CurrentLocation()).Format("2006-01-02 15:04:05"),
		at:      now.UTC(),
	}
}

// RecordBackgroundApplyFailure 供不走 TrackBackgroundReload 的调用点手工登记
// （例如投影热路径外的直接应用）。
func RecordBackgroundApplyFailure(source BackgroundApplySource, err error) {
	recordBackgroundApplyResult(source, err)
}

// ClearBackgroundApplyFailure 清除某来源的失败记录（成功路径/手工恢复）。
func ClearBackgroundApplyFailure(source BackgroundApplySource) {
	recordBackgroundApplyResult(source, nil)
}

// BackgroundApplyFailureSnapshot 返回最近一次后台重载失败（无失败为 nil）。
// 多来源并存时按失败时刻（UTC 基准 at，秒精度）取最新一条；同一秒内并存时按
// 来源名字典序取最小者——map 遍历顺序随机，缺 tie-break 会让横幅在同秒多来源
// 失败下每次调用换源（前端轮询可见抖动，排障指向不稳定）。
func BackgroundApplyFailureSnapshot() *BackgroundApplyFailure {
	backgroundApplyStore.mu.Lock()
	defer backgroundApplyStore.mu.Unlock()
	var latest *BackgroundApplyFailure
	for _, failure := range backgroundApplyStore.failures {
		current := failure
		if latest == nil {
			latest = &current
			continue
		}
		switch compareBackgroundApplyTime(current, *latest) {
		case 1:
			latest = &current
		case 0:
			if current.Source < latest.Source {
				latest = &current
			}
		}
	}
	return latest
}

// compareBackgroundApplyTime 按时间基准比较两条失败记录（1=前更新、-1=后更新、
// 0=同一秒）。at 未落（外部构造的字面量，如测试/历史形态）时回退解析 At 墙串；
// 都无法解析按「更早」处理（不抢占可比记录）。
func compareBackgroundApplyTime(a, b BackgroundApplyFailure) int {
	ta, tb := backgroundApplyFailureTime(a), backgroundApplyFailureTime(b)
	switch {
	case ta.After(tb):
		return 1
	case ta.Before(tb):
		return -1
	default:
		return 0
	}
}

func backgroundApplyFailureTime(f BackgroundApplyFailure) time.Time {
	if !f.at.IsZero() {
		return f.at.Truncate(time.Second)
	}
	if parsed, err := time.ParseInLocation("2006-01-02 15:04:05", f.At, CurrentLocation()); err == nil {
		return parsed.UTC().Truncate(time.Second)
	}
	return time.Time{}
}

// BackgroundApplyFailureBanner 单行横幅文案（无失败为空串）。
func BackgroundApplyFailureBanner() string {
	failure := BackgroundApplyFailureSnapshot()
	if failure == nil {
		return ""
	}
	return fmt.Sprintf("后台重载失败（%s，%s）：%s", failure.Source, failure.At, failure.Message)
}
