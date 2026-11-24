// 安全策略列表页的展示判定（纯函数，无 Vue/i18n 依赖；行为测试见
// tests/securityObservability.spec.ts）。

/** 策略列表「状态」列的三态。 */
type PolicyListStatus = 'disabled' | 'enabled' | 'enabledUnbound'

/**
 * 启用 ≠ 生效：策略只有绑定到转发规则才参与流量。已启用但零绑定的策略对任何
 * 请求都不生效（默认策略即以启用态创建、不写绑定），状态列必须把它与「启用且已
 * 关联规则」区分开，不能同样只显示「启用」。
 * ruleCount = 列表行 rule_count（后端按 security_policy_bindings 计数）。
 */
export const policyListStatus = (enabled: boolean, ruleCount: number): PolicyListStatus =>
  !enabled ? 'disabled' : ruleCount > 0 ? 'enabled' : 'enabledUnbound'

/** 状态 → 标签色（success=生效、warning=需注意、info=关闭）与词条键。 */
export const POLICY_LIST_STATUS_TAG: Record<PolicyListStatus, { type: 'info' | 'success' | 'warning'; labelKey: string }> = {
  disabled: { type: 'info', labelKey: 'app.security.policies.status.disabled' },
  enabled: { type: 'success', labelKey: 'app.security.policies.status.enabled' },
  enabledUnbound: { type: 'warning', labelKey: 'app.security.policies.status.enabledUnbound' },
}

/** 删除确认里逐条具名的规则上限（超出部分以「其余 N 条」收口，确认框不铺满整屏）。 */
export const POLICY_DELETE_SCOPE_MAX_NAMES = 10

interface PolicyDeleteScope {
  /** 将被一并解除的绑定数（引导行里的数量）。 */
  count: number
  /** 可具名的规则（页内绑定快照解析得出，至多 POLICY_DELETE_SCOPE_MAX_NAMES 条）。 */
  names: string[]
  /** 未能具名的绑定数（绑定/规则加载失败，或绑定指向的规则已不在规则列表）。 */
  unnamed: number
}

/**
 * 删除策略会同事务删除其全部绑定（规则本身保留）。ruleCount 是列表行 rule_count
 * ——后端将要删除的绑定行数；boundRuleNames 是页内 /security/bindings × /rules
 * 解析出的规则名，只在数据完整时与 ruleCount 相等：
 *   · 名字拿不到（绑定加载失败，调用方传空数组）：披露降级为「只报数量」——不得
 *     因为拿不到名字就不披露，也不得用名字数冒充绑定数；
 *   · 名字多于行计数（绑定快照新于列表）：以名字数为准，引导行的数量不得小于
 *     清单条数。
 */
export const policyDeleteScope = (ruleCount: number, boundRuleNames: readonly string[]): PolicyDeleteScope => {
  const count = Math.max(ruleCount, boundRuleNames.length)
  const names = boundRuleNames.slice(0, POLICY_DELETE_SCOPE_MAX_NAMES)
  return { count, names, unnamed: count - names.length }
}
