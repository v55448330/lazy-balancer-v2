package notify

// 启动事件接线：完成事实只在「监听建立、服务就绪」后发一次（幂等守卫——
// 进程内不存在第二个合法完成点，重复调用静默忽略）；启动失败路径发异常事件
// 携带原因摘要。启动早期库未装配/分发循环未启动时 Publish 走安全丢弃分支，
// 绝不影响失败退出路径。

import "sync/atomic"

// startupCompletedSent 完成事件幂等标记（进程生命周期一次）。
var startupCompletedSent atomic.Bool

// PublishStartupCompleted 服务就绪后发布启动完成（仅首次生效）。
func PublishStartupCompleted(addr string) {
	if !startupCompletedSent.CompareAndSwap(false, true) {
		return
	}
	Publish(Event{Type: EvtStartupCompleted, Fields: map[string]string{"1": addr}})
}

// PublishStartupAbnormal 启动失败路径发布启动异常（reason=错误摘要）。
func PublishStartupAbnormal(reason string) {
	Publish(Event{Type: EvtStartupAbnormal, Fields: map[string]string{"1": reason}})
}
