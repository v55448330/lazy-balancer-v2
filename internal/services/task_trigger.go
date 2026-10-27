package services

// 任务异步触发统一入口：把「触发」/「触发失败」审计与错误分类
// 收敛到单点，供任务监控、规则库「立即更新」、爬虫地址库、配置导入等全部
// 手动触发面共用——禁止各调用点自行 go func + 各自分类（曾五处实现漂移：
// 部分调用点把 demote skipped / 并发 CAS 落败记成「触发失败」）。

import (
	"context"
	"errors"
	"fmt"

	"lazy-balancer-v2/internal/taskengine"
)

// TriggerAuditContext 异步触发审计上下文快照。
// gin.Context 在 handler 返回后会被池化复用——所有字段必须在启动 goroutine
// 前从请求上下文预取，goroutine 内不得再读 *gin.Context。
type TriggerAuditContext struct {
	Operator string // 操作者（空=system）
	IP       string // 审计 IP（中间件 audit_ip 或 ClientIP）
	Family   string // 审计对象（如「任务监控」「安全防护」）
	Name     string // 任务展示名（审计 detail 用）
	Detail   string // 可选：覆盖默认「手动触发任务 <Name>」文案
}

// TriggerTaskAsync 异步触发任务并统一错误分类：
//   - 成功：非自记族记「触发」审计（自记族由任务体/执行器单记，复记违反
//     单记裁定）；自记族零 handler 审计。
//   - ErrAlreadyRunning：并发双击后到者——任务实际已由先到请求启动，静默
//     （记「触发失败」是语义失真）。
//   - ErrTaskSkipped：Run 体「非故障放弃」（demote 中止等）——task_runs 已落
//     skipped 行，静默。
//   - 其它错误：日志 + 「触发失败」补偿审计（任务未执行/失败不得无痕）。
//
// TriggerTaskAsync 同步完成 admission（暂停/停止/角色/单飞 CAS），成功后
// 才异步执行并统一错误分类。调用方必须在写 HTTP 响应前消费返回错误，
// 不得把未受理任务伪报为 running。
//
// operator 归人：RunAsyncResult 的 operator 参数与审计 username 同源。
func TriggerTaskAsync(te *taskengine.Engine, taskID string, actx TriggerAuditContext) error {
	if te == nil {
		return taskengine.ErrEngineStopped
	}
	err := te.RunAsyncResult(taskID, "manual", actx.Operator, func(runErr error) {
		RecordTaskTriggerResult(taskID, actx, runErr)
	})
	if err != nil {
		// admission 失败没有执行回调；在此处保留原有补偿审计与
		// ErrAlreadyRunning/ErrTaskSkipped 静默分类。
		RecordTaskTriggerResult(taskID, actx, err)
	}
	return err
}

// RecordTaskTriggerResult 供同步预占位（Engine.RunAsyncResult）的完成回调：
// 成功记「触发」，失败（除并发/跳过语义）记「触发失败」；自记族成功不重复记，
// 但任务体失败仍补「触发失败」——执行器可能尚未写入任何失败审计。
func RecordTaskTriggerResult(taskID string, actx TriggerAuditContext, runErr error) {
	if TaskTriggerSelfRecordsAudit(taskID) && runErr == nil {
		return
	}
	if runErr == nil {
		RecordAuditLog(actx.Operator, "触发", actx.Family, triggerAuditDetail(actx), actx.IP)
		return
	}
	if errors.Is(runErr, taskengine.ErrAlreadyRunning) || errors.Is(runErr, taskengine.ErrTaskSkipped) ||
		errors.Is(runErr, taskengine.ErrRunCancelled) || errors.Is(runErr, context.Canceled) ||
		errors.Is(runErr, taskengine.ErrEngineStopped) {
		// 用户取消（ErrRunCancelled/context.Canceled）与并发/跳过语义同级——
		// task_runs 已落 cancelled 行，补记「触发失败」是语义失真。引擎已停止
		// （关停窗口）同理：admission 拒绝不是任务失败，记「触发失败」误导排障。
		return
	}
	Logf("error", "手动触发任务 %s 失败: %v", taskID, runErr)
	RecordAuditLog(actx.Operator, "触发失败", actx.Family,
		fmt.Sprintf("手动触发任务 %s 失败: %v", actx.Name, runErr), actx.IP)
}

// triggerAuditDetail 成功触发审计 detail（调用方可用 Detail 覆盖文案）。
func triggerAuditDetail(actx TriggerAuditContext) string {
	if actx.Detail != "" {
		return actx.Detail
	}
	return "手动触发任务 " + actx.Name
}
