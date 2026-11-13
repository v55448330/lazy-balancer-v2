// 事件「触发规则」筛选的类别 → 后端 token 段映射（单源）。
//
// 该映射原先内联在 SecurityEvents.vue 的 fetchEvents 里，仅靠
// 源码文本钉，任何语义漂移（少一类、段序变化、自定义 tag 被误当类别）都无测试可拦。
// 序列化抽为纯函数后由 triggeredFilter.spec.ts 行为钉住；视图只负责选择与渲染。
//
// 后端契约（internal/handlers/security.go ruleTriggeredFamilyPrefixes）：
// 参数按英文逗号逐段解析，段间 OR；段可以是 family 键、前缀式 token 或纯数字规则 ID；
// 含逗号的消息关键词会整串回退为消息搜索（前端只管连接，不判断语义）。

// 触发阶段筛选为固定预置九类（用户裁定：固定预置值，不接受任意值）。
// 退役配额限流的 429 存量行不设独立筛选项（新 CC 防护事件为 human_*）。
// CC 防护（2026-11-13 用户裁定新增）：人机挑战事件族（human_*），后端
// humanFamilyCondition 承载。

// crawler 族展示词单源：后端 family 键/trigger_type 权威词为「爬虫Bot」
//（internal/handlers/security_threat_screen.go triggerTypeForRule）。
// 筛选类别与事件列表「触发阶段」列同词——原阶段列渲染「爬虫校验」，
// 同页筛选/触发类型列显示「爬虫Bot」，用户需自行判断两词同族。
export const CRAWLER_FAMILY_LABEL = '爬虫Bot'

export const TRIGGERED_CATEGORIES = [CRAWLER_FAMILY_LABEL, '地域拦截', 'IP 访问控制', '信任名单', '威胁情报库', '请求体异常', 'WAF·CRS', 'WAF·自定义', 'CC 防护'] as const
type TriggeredCategory = typeof TRIGGERED_CATEGORIES[number]

// 每类对应的 ruleTriggeredFamilyPrefixes 映射键（值=后端 family 键，与新
// trigger_type 同语义）。
export const TRIGGERED_FAMILY_SEGMENTS: Record<TriggeredCategory, string[]> = {
  '爬虫Bot': ['爬虫Bot'],
  '地域拦截': ['地域拦截'],
  'IP 访问控制': ['IP 访问控制'],
  '信任名单': ['信任名单'],
  '威胁情报库': ['威胁情报库'],
  '请求体异常': ['请求体异常'],
  'WAF·CRS': ['WAF·CRS'],
  // 后端两个 token 落到同一 customRuleFamilyCondition（SQL 等价重复 OR）；
  // 保留双段是历史契约（后端任一侧改名都不至于让筛选失效），勿"优化"成单段。
  'WAF·自定义': ['WAF·自定义', '自定义规则'],
  'CC 防护': ['CC 防护'],
}

const isTriggeredCategory = (value: string): value is TriggeredCategory =>
  (TRIGGERED_CATEGORIES as readonly string[]).includes(value)

/**
 * 序列化「触发规则」多选值为 rule_triggered 参数值。
 *
 * 规则（与视图注释同口径）：
 *  - 空选 = 不过滤 → null；
 *  - 八类全中且无自定义 tag = 全选 → null（不发参数）；
 *  - 其余（类别子集、含自定义 tag）= 选中类别展开为族段 + 自定义 tag 原样并入，
 *    英文逗号连接（后端逐段 OR）。
 */
export const serializeTriggeredFilter = (selected: readonly string[]): string | null => {
  if (selected.length === 0) return null
  const categories = selected.filter(isTriggeredCategory)
  const customTags = selected.filter((v) => !isTriggeredCategory(v))
  const allCategoriesSelected = TRIGGERED_CATEGORIES.every((c) => categories.includes(c))
  if (allCategoriesSelected && customTags.length === 0) return null
  const segments = categories.flatMap((c) => TRIGGERED_FAMILY_SEGMENTS[c])
  return [...segments, ...customTags].join(',')
}
