// 深链 URL 构造单源：页面键受 PageId 类型约束（改名即编译报错），参数键
// 常量化。原五个 window.open 各持 `/?page=xxx&rs=/sp=/sp-search=/tab=` 字面量
// ——页面键改名时 isPageId 拦住类型调用点，URL 形态却零校验，深链静默回落
// dashboard（auth store 兜底）；消费侧（Rules/SecurityPolicies/SecurityRules
// 的 onMounted 解析）也请改用下方参数键常量。事件页的入参解析收敛为
// parseSecurityEventsDeepLink（值域校验：非法值不触发打开弹框）。

import type { PageId } from './pageIds.ts'

/** 跨页交接参数键（生产侧与消费侧共用，禁止另起字面量）。 */
export const DEEP_LINK_PARAMS = {
  /** Rules 页：待检索的规则 caddy_id。 */
  ruleSearch: 'rs',
  /** SecurityPolicies 页：按 id 聚焦策略。 */
  policyId: 'sp',
  /** SecurityPolicies 页：按名称搜索策略。 */
  policySearch: 'sp-search',
  /** SecurityRules 页：目标分页（rules/custom/ip-lists）。 */
  securityRulesTab: 'tab',
  /** SecurityEvents 页：进入后打开自动封禁配置弹框（取值固定为 EVENTS_AUTOBAN_CONFIG）。 */
  eventsAutoban: 'autoban',
} as const

/** eventsAutoban 参数的唯一合法值：进页后打开自动封禁配置弹框。 */
export const EVENTS_AUTOBAN_CONFIG = 'config'

/**
 * 解析事件页深链入参（消费侧传入 window.location.search）。参数值一律过值域：
 * 深链 URL 可被手工改写，任意字符串不得触发打开弹框。
 * openAutobanConfig：是否进页打开自动封禁配置弹框。
 */
export const parseSecurityEventsDeepLink = (search: string): { openAutobanConfig: boolean } => {
  const query = new URLSearchParams(search)
  return {
    openAutobanConfig: query.get(DEEP_LINK_PARAMS.eventsAutoban) === EVENTS_AUTOBAN_CONFIG,
  }
}

/** 构造 `/?page=<page>&k=v…` 形态深链（值经 URL 编码）。 */
export const pageUrl = (page: PageId, params?: Record<string, string | number>): string => {
  const query = new URLSearchParams({ page })
  for (const [key, value] of Object.entries(params ?? {})) query.set(key, String(value))
  return `/?${query.toString()}`
}
