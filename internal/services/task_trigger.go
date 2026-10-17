package services

// 任务异步触发统一入口（L01-02）：把「触发」/「触发失败」审计与错误分类
// 收敛到单点，供任务监控、规则库「立即更新」、爬虫地址库、配置导入等全部
// 手动触发面共用——禁止各调用点自行 go func + 各自分类（曾五处实现漂移：
// 部分调用点把 demote skipped / 并发 CAS 落败记成「触发失败」）。

import (
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
//     U1-P3-2 单记裁定）；自记族零 handler 审计。
//   - ErrAlreadyRunning：并发双击后到者——任务实际已由先到请求启动，静默
//     （记「触发失败」是语义失真）。
//   - ErrTaskSkipped：Run 体「非故障放弃」（demote 中止等）——task_runs 已落
//     skipped 行，静默。
//   - 其它错误：日志 + 「触发失败」补偿审计（任务未执行/失败不得无痕）。
//
// operator 归人：te.Trigger 的 operator 参数与审计 username 同源。
func TriggerTaskAsync(te *taskengine.Engine, taskID string, actx TriggerAuditContext) {
	if te == nil {
		return
	}
	go func() {
		err := te.Trigger(taskID, "manual", actx.Operator)
		switch {
		case err == nil:
			if TaskTriggerSelfRecordsAudit(taskID) {
				return
			}
			RecordAuditLog(actx.Operator, "触发", actx.Family, triggerAuditDetail(actx), actx.IP)
		case errors.Is(err, taskengine.ErrAlreadyRunning), errors.Is(err, taskengine.ErrTaskSkipped):
			// 语义非失败：已由先到请求启动 / 任务体明确放弃（见函数注释）。
		default:
			Logf("error", "手动触发任务 %s 失败: %v", taskID, err)
			RecordAuditLog(actx.Operator, "触发失败", actx.Family,
				fmt.Sprintf("手动触发任务 %s 失败: %v", actx.Name, err), actx.IP)
		}
	}()
}

// triggerAuditDetail 成功触发审计 detail（调用方可用 Detail 覆盖文案）。
func triggerAuditDetail(actx TriggerAuditContext) string {
	if actx.Detail != "" {
		return actx.Detail
	}
	return "手动触发任务 " + actx.Name
}
