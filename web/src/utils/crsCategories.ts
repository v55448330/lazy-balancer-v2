/**
 * CRS 规则分类显示：后端只下发语言无关的稳定码（internal/services/crs_rule_index.go
 * 的 CRSCategory*，形如 `ruleset.genericAnomalies`），界面文案由词条提供——
 * 码去掉 `ruleset.` 前缀即 common.app.crsCategory.* 的词条后缀。
 *
 * 未知码（后端新增分类而前端词条未跟上）fail-visible：原样显示码本身并
 * console.warn，便于定位缺失词条，不做静默回落或臆测文案。
 */
import { tSafe } from '../i18n/tSafe.ts'

const CRS_CATEGORY_PREFIX = 'ruleset.'

/** CRS 分类码 → 当前语言的分类标签；空值返回空串。 */
export const crsCategoryLabel = (code?: string): string => {
  if (!code) return code || ''
  if (!code.startsWith(CRS_CATEGORY_PREFIX)) {
    console.warn(`[crsCategory] 分类值不是稳定码（期望 ${CRS_CATEGORY_PREFIX}*）：${code}`)
    return code
  }
  const key = `common.app.crsCategory.${code.slice(CRS_CATEGORY_PREFIX.length)}`
  const label = tSafe(key)
  if (label === key) {
    console.warn(`[crsCategory] 分类码缺少词条：${code}`)
    return code
  }
  return label
}
