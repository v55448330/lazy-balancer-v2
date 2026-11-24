// 规则列表的定时刷新口径：周期与「轮询让位」判定。
//
// 列表轮询只允许刷新列表数据。编辑面打开或写操作在途期间换掉行对象/快照会
// 干扰用户正在进行的操作：绑定编辑器按打开时刻的绑定快照计算整集替换，流程
// 弹框与向导取打开时刻的投影/水合行，启停开关在途时换行会让开关先回跳旧态。
// 判定抽成纯函数，由行为用例穷举各编辑面（视图侧只负责收集状态）。

/** 可见性轮询周期（毫秒）：后台标签页停表、恢复可见立即补一轮由 createVisibilityIntervals 承担。 */
export const RULE_LIST_POLL_MS = 30_000

export interface RuleListEditActivity {
  /** 编辑/复制向导打开 */
  wizardOpen: boolean
  /** 处理流程弹框打开 */
  flowOpen: boolean
  /** 安全策略绑定弹框打开，或正在为打开而重取快照 */
  bindOpen: boolean
  /** 任一规则启停在途（确认框悬挂或写请求未返回） */
  toggling: boolean
  /** 删除确认悬挂或删除请求在途 */
  deleting: boolean
}

/** 轮询轮次是否让位：任一编辑面打开或写操作在途即跳过本轮。 */
export const ruleListPollPaused = (activity: RuleListEditActivity): boolean =>
  activity.wizardOpen || activity.flowOpen || activity.bindOpen || activity.toggling || activity.deleting
