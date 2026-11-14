// 审计动作词 → 色调单源：例外表（精确命中优先）+ 关键词派生 + 未命中告警。
//
// 原为约 150 条「动作词→色调」字面量全表：后端动作词表（db/audit_vocabulary）
// 新增动作时新词静默渲染灰色 info，失败类动作扫不到、映射漂移无信号。
// 现为两层：
//   ① 例外表——与关键词派生结果冲突的词（如「渲染跳过」是 danger 而非
//      warning、「提升完成」是 warning 而非 success），以及不含任何关键词的
//      动作（「删除」「同步」「创建」等）；
//   ② 关键词派生——含「失败/拒绝/阻断/异常」→danger，含「警告/告警/跳过/降级」
//      →warning，含「成功/完成」→success（按此优先级，先命中先生效）。
// 例外表与派生都未命中 → info + console.warn 一次（去重），词表漂移显性化。

import { hasOwn } from './hasOwn.ts'

type AuditActionTone = 'success' | 'danger' | 'warning' | 'info'

// 精确命中优先于关键词派生。仅收录「派生结果不正确」或「不含任何关键词」的词。
const ACTION_TONE_EXCEPTIONS: Record<string, AuditActionTone> = {
  // ── danger（无关键词可派生）──
  '删除': 'danger',
  '禁用': 'danger',
  '停止': 'danger',
  // 集群切从后 cluster-sync 保持用户停止态：节点不再同步（无关键词可派生）。
  '同步停止': 'danger',
  '重启': 'danger',
  '备份删除': 'danger',
  '配置漂移': 'danger',
  // 自动封禁：封禁=阻断（danger），到期自动解封=恢复（success）。
  '自动封禁': 'danger',
  // 「渲染跳过」含「跳过」会派生 warning——跳过渲染是配置错误信号，保持 danger。
  '渲染跳过': 'danger',
  // ── warning（无关键词可派生）──
  '更新': 'warning',
  '手动更新': 'warning',
  '更新信息': 'warning',
  '修改状态': 'warning',
  '重置密码': 'warning',
  // MFA 重绑轮换第二因子：风险操作（旧验证器失效/恢复码重生成），按 warning 呈现。
  '重新绑定': 'warning',
  '重载': 'warning',
  '续签': 'warning',
  // 重新签发（证书重签，与「续签」同族的风险操作）——安全网：后端新动作
  // 落库即渲染为 warning，不必等色调映射补词。
  '重新签发': 'warning',
  '重试': 'warning',
  '签发限流': 'warning',
  '切换': 'warning',
  '提升': 'warning',
  // 「提升完成」含「完成」会派生 success——提升是风险操作，保持 warning。
  '提升完成': 'warning',
  '同步': 'warning',
  '同步下发': 'warning',
  '手动同步': 'warning',
  '同步自愈': 'warning',
  '注册': 'warning',
  // 注册交付确认（集群信任链终结点，注册密钥就此失效）——与「注册」同色调；
  // 失败形态由「失败」关键词派生 danger。
  '确认': 'warning',
  '生成': 'warning',
  '导出': 'warning',
  '导入': 'warning',
  '还原': 'warning',
  '自动备份': 'warning',
  '手动备份': 'warning',
  '备份设置': 'warning',
  '备份下载': 'warning',
  '复制': 'warning',
  '触发签发': 'warning',
  '触发': 'warning',
  '写入': 'warning',
  '恢复排队': 'warning',
  '续签排队': 'warning',
  '重新排队': 'warning',
  '重试排队': 'warning',
  '更新地址': 'warning',
  '下载校验': 'warning',
  '清理': 'warning',
  '清除': 'warning',
  '启动': 'warning',
  '登出': 'warning',
  '重建': 'warning',
  '启动迁移': 'warning',
  // 导入归一：备份携带的 waiting_ca 存量在导入提交后保窗归一为 failed（失败
  // 语义统一的导入路径延伸）——与「启动迁移」同族的状态收敛动作，告警性呈现。
  '导入归一': 'warning',
  '脱离': 'warning',
  '服务控制': 'warning',
  '暂停': 'warning',
  '取消': 'warning',
  // 同步应用不含任何关键词（同步/应用均不入派生词表）——保持原 warning。
  '同步应用': 'warning',
  // 容量收敛：名单触顶挤出/丢弃的告警性系统动作（warning——不是错误，但需关注）。
  '容量收敛': 'warning',
  // 库自愈：指标库损坏后自动隔离重建（恢复成功，但指标与安全事件历史一并
  // 丢弃、需人工取证）——按告警性事件呈现，不按 success 绿标淡化数据丢失。
  '库自愈': 'warning',
  // ── success（无关键词可派生）──
  '创建': 'success',
  '启用': 'success',
  '审批': 'success',
  '恢复': 'success',
  '重置': 'success',
  '载入': 'success',
  '配置恢复': 'success',
  '自动解封': 'success',
  // 自动检测（例行探测成功完成）不含成功/完成字面——保持原 success。
  '自动检测': 'success',
}

const DANGER_WORDS = ['失败', '拒绝', '阻断', '异常'] as const
const WARNING_WORDS = ['警告', '告警', '跳过', '降级'] as const
const SUCCESS_WORDS = ['成功', '完成'] as const

const warnedUnknownActions = new Set<string>()

/** 动作词 → el-tag 色调。例外表 → 关键词派生 → info（并告警一次）。 */
export const actionTagType = (action: string): AuditActionTone => {
  // 例外表是普通对象：直接下标会把原型链上的键（'constructor'/'toString'/
  // '__proto__' 等后端词表异常值）当成命中，把函数当作色调返回。与
  // utils/logStatCap 同一具名守卫（utils/hasOwn 自有属性判定）。
  const exception = hasOwn(ACTION_TONE_EXCEPTIONS, action)
    ? ACTION_TONE_EXCEPTIONS[action]
    : undefined
  if (exception) return exception
  for (const word of DANGER_WORDS) if (action.includes(word)) return 'danger'
  for (const word of WARNING_WORDS) if (action.includes(word)) return 'warning'
  for (const word of SUCCESS_WORDS) if (action.includes(word)) return 'success'
  if (action && !warnedUnknownActions.has(action)) {
    warnedUnknownActions.add(action)
    console.warn(`[audit-log] 未识别的动作词色调，按 info 渲染：${action}`)
  }
  return 'info'
}
