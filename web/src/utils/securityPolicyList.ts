// 安全策略列表页的展示判定（纯函数，无 Vue/i18n 依赖；行为测试见
// tests/securityObservability.spec.ts）。

/**
 * 删除策略会同事务删除其全部绑定（规则本身保留）。返回确认框引导行里的绑定数：
 * ruleCount 是列表行 rule_count——后端将要删除的绑定行数；boundCount 是页内
 * /security/bindings × /rules 解析出的绑定数（绑定加载失败时调用方传 0）：
 *   · 绑定快照新于列表时以快照为准——引导行的数量不得小于实际将解除的绑定数；
 *   · 快照拿不到时仍按行计数披露——不得因为读不到绑定就不披露。
 */
export const policyDeleteScope = (ruleCount: number, boundCount: number): number => Math.max(ruleCount, boundCount)
