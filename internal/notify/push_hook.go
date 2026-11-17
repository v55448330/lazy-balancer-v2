package notify

// 实时推送挂钩：dispatcher 命中订阅（落 pending 投递行的同处）对每用户触发
// 一次，MCP 侧经本回调把已渲染消息推给该用户全部在线 MCP 会话（会话的下一
// 请求响应以 SSE 形态冲刷）。回调注入而非直接调用，避免 notify → mcpserver
// 的 import 环（mcpserver 依赖 notify.Message）。注册为单槽：进程内 MCP 装配
// 唯一，多次注册后者覆盖（测试多装配同口径）。

import (
	"log"
	"sync"
)

var (
	pushHookMu sync.RWMutex
	pushHook   func(userID int64, msg Message)
)

// RegisterPushHook 注册实时推送实现（MCP 装配期一次；单槽，后者覆盖）。
func RegisterPushHook(hook func(userID int64, msg Message)) {
	pushHookMu.Lock()
	defer pushHookMu.Unlock()
	pushHook = hook
}

// firePushHooks 触发推送（分发协程内调用）。异步派发：推送目标不可达或实现
// 慢都不得拖住事件分发主循环；panic 兜底回收，不影响同批其余投递。
func firePushHooks(userID int64, msg Message) {
	pushHookMu.RLock()
	hook := pushHook
	pushHookMu.RUnlock()
	if hook == nil {
		return
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("WARN: notify 实时推送 hook panic（事件 %s 用户 %d）: %v", msg.EventType, userID, r)
			}
		}()
		hook(userID, msg)
	}()
}
