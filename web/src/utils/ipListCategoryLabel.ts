/**
 * IP 名单分类 label 单源（三份同构映射收敛）。
 * 词表=common.app.ipListCategory（zh/en 词条）；未命中回退原名。
 * 消费点：SecurityPolicies / SecurityRules / CaddyGlobalSettings。
 * CRS 规则分类是另一套 zh 码（utils/crsCategories 的 crsCategoryLabel），
 * 与名单分类码集不相交——此处不再设 CRS 回退分支（曾与主表全同，恒不可达）。
 */
import { tSafe as t } from '../i18n/tSafe.ts'
import { hasOwn } from './hasOwn'

// 库值（zh 分类码）→ 词条后缀（common.app.ipListCategory.*）
const IP_LIST_CATEGORY_KEYS: Record<string, string> = {
  '搜索引擎爬虫': 'crawler',
  'CDN 节点': 'cdn',
  '云服务商': 'cloud',
  '办公网络': 'office',
  '数据中心': 'dc',
  '可信地址': 'trust',
  '恶意 IP': 'malicious',
  '自动封禁': 'autoban',
  '其他': 'other',
}

/** IP 名单分类 label：命中词条→本地化；未命中回退原名（原型键经 hasOwn 守卫）。 */
export const ipListCategoryLabel = (raw?: string): string => {
  if (!raw) return raw || ''
  const k = hasOwn(IP_LIST_CATEGORY_KEYS, raw) ? IP_LIST_CATEGORY_KEYS[raw] : undefined
  return k ? t(`common.app.ipListCategory.${k}`) : raw
}
