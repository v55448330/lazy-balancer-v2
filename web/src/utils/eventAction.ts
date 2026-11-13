// 安全事件动作（后端 action：blocked | logged）的展示映射单源。
//
// 此前四处各自映射且措辞互斥：事件列表「拦截/检测」、请求详情「已拦截/已记录」、
// 大屏告警「已拦截/仅检测」、触发详情「已拦截/已记录（检测）」——同一事件在四个
// 视图里要读者自行翻译。新增动作时也只改本表。
//
// 未知动作 fail-visible：原样回显后端值（空值兜底「—」），不再把未知动作一律
// 当作「检测」——那会把「拦截语义的新动作」静默呈现为未拦截。

// 色调联合只服务本文件的映射表与返回类型（全仓零外部消费——不导出，避免被
// 误当作跨模块稳定契约而在视图里直接构造动作色）。
import { tSafe as t } from '../i18n/tSafe.ts'

type EventActionTone = 'danger' | 'warning' | 'info' | 'success' | 'primary'


// 挑战结果由 rule_triggered 区分（human_challenge/pass/failed）：动作列与
// 触发详情共用同一分派，避免三态共用「挑战」同色标签无法区分。
const challengeKind = (ruleTriggered: string | undefined | null): 'issued' | 'pass' | 'fail' | null => {
  if (ruleTriggered === 'human_pass') return 'pass'
  if (ruleTriggered === 'human_failed') return 'fail'
  if (ruleTriggered === 'human_challenge') return 'issued'
  return null
}

/** 短标签（列表/筛选等紧凑位）：拦截 / 检测 / 挑战结果。 */
export const eventActionShort = (action: string | undefined | null, _ruleTriggered?: string | null): string => {
  if (!action) return '—'
  if (action === 'blocked') return t('common.app.views.eventAction.blockedShort') || action
  if (action === 'logged') return t('common.app.views.eventAction.loggedShort') || action
  if (action === 'trust') return t('common.app.views.eventAction.trustShort') || action
  if (action === 'challenged') return t('common.app.views.eventAction.challengedShort') || action
  return action
}

/** 完整标签（详情/告警等叙述位）：已拦截 / 已记录 / 挑战结果。 */
export const eventActionFull = (action: string | undefined | null, _ruleTriggered?: string | null): string => {
  if (!action) return '—'
  if (action === 'blocked') return t('common.app.views.eventAction.blockedFull') || action
  if (action === 'logged') return t('common.app.views.eventAction.loggedFull') || action
  if (action === 'trust') return t('common.app.views.eventAction.trustFull') || action
  if (action === 'challenged') return t('common.app.views.eventAction.challengedFull') || action
  return action
}

/** el-tag 色调：拦截 danger、检测 warning；挑战三态 primary(发放)/success(通过)/danger(失败)。 */
export const eventActionTone = (action: string | undefined | null, ruleTriggered?: string | null): EventActionTone => {
  // 字面量分派:表读点曾裸下标,后端外部字符串命中原型键
  // (constructor 等)返回函数被当色调——词表读取契约要求 hasOwn/分派。
  if (action === 'blocked') return 'danger'
  if (action === 'trust') return 'success'
  if (action === 'challenged') {
    const kind = challengeKind(ruleTriggered)
    if (kind === 'pass') return 'success'
    if (kind === 'fail') return 'danger'
    return 'primary'
  }
  return 'warning'
}
