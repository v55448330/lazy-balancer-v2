// 业务驱动任务的「停调恢复入口」映射单源：引擎连续失败停调
// （schedule_stopped_reason=fail-streak）后，业务驱动任务的调度开关在任务监控
// 页只读——恢复动作是到对应业务页重新保存那个开关。文案原写死「再到对应业务
// 页重新保存『自动更新』开关」，对自动备份（基础设置 › 自动备份 › 启用）与
// 自动封禁（事件日志页的启用/禁用）都是错的：按任务 id 查「页面名 + 开关名」。
//
// id 集与 internal/services/taskengine_wire.go 的 businessTaskDrivers 唯一清单
// 同集（跨栈对账见 tests/taskMonitorAndAuditLogUi.spec.ts）；未登记 id（后端新增
// 驱动而前端未跟上）由调用方回落到通用「对应业务页」文案，不裸键。
import { hasOwn } from './hasOwn.ts'

/** 业务驱动任务 id → recoveryTargets 词条后缀。 */
export const BUSINESS_TASK_RECOVERY_KEYS: Record<string, string> = {
  threat: 'threat',
  crs: 'crs',
  ip2region: 'ip2region',
  'crawlerbot-update': 'crawlerbotUpdate',
  'auto-backup': 'autoBackup',
  autoban: 'autoban',
}

/** 该任务 id 的恢复入口词条键；非业务驱动/未登记 → null。 */
export const businessTaskRecoveryTargetKey = (taskId: string): string | null =>
  hasOwn(BUSINESS_TASK_RECOVERY_KEYS, taskId)
    ? `app.settings.taskMonitor.stopTip.recoveryTargets.${BUSINESS_TASK_RECOVERY_KEYS[taskId]}`
    : null
