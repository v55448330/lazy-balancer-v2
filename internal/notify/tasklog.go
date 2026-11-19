package notify

// 通知任务业务日志接线：notify 位于 services 下层（不可反向 import），
// 业务事件经 taskengine.TeeTaskLogTimeContext 直落 tasks/{id}.log（与
// services.TaskLogf 同一单源）。taskID 经 ctx 注入（Run 体起点 withTaskID），
// 下游凡持 ctx 的函数无需改签名即可落对任务日志；无 taskID 的调用方
// （REST 直发/测试）回退 runtime 日志，不写任务日志。

import (
	"context"
	"fmt"
	"log"

	"lazy-balancer-v2/internal/taskengine"
)

type notifyTaskIDKey struct{}

// withTaskID 在 Run 体起点把任务 ID 注入 ctx（单实例 Daemon/Scheduled 各持其 ID）。
func withTaskID(ctx context.Context, taskID string) context.Context {
	return context.WithValue(ctx, notifyTaskIDKey{}, taskID)
}

func taskIDFrom(ctx context.Context) string {
	v, _ := ctx.Value(notifyTaskIDKey{}).(string)
	return v
}

// taskLogf 业务摘要行（INFO）：有 taskID 落任务日志，否则回退 runtime。
func taskLogf(ctx context.Context, stage, format string, args ...any) {
	if id := taskIDFrom(ctx); id != "" {
		taskengine.TeeTaskLogTimeContext(ctx, id, "INFO", stage, fmt.Sprintf(format, args...))
		return
	}
	log.Printf("INFO: "+format, args...)
}

// taskLogWarn 业务告警行（WARN）：状态变化/失败类信号。
func taskLogWarn(ctx context.Context, stage, format string, args ...any) {
	if id := taskIDFrom(ctx); id != "" {
		taskengine.TeeTaskLogTimeContext(ctx, id, "WARN", stage, fmt.Sprintf(format, args...))
		return
	}
	log.Printf("WARN: "+format, args...)
}
