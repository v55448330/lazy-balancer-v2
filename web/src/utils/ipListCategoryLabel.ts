/**
 * IP 名单分类 label 单源（audit140-U2-F4：三份同构映射收敛）。
 * 词表=common.app.ipListCategory（zh/en 词条）；CRS 规则分类走独立词表回退；
 * 未命中回退原名。消费点：SecurityPolicies / SecurityRules / CaddyGlobalSettings。
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

// CRS 规则分类独立码表 → 词条后缀（common.app.crsCategory.*）
const CRS_CATEGORY_KEYS: Record<string, string> = {
  '搜索引擎爬虫': 'crawler',
  'CDN 节点': 'cdn',
  '云服务商': 'cloud',
  '办公网络': 'office',
  '数据中心': 'dc',
  '可信地址': 'trust',
  '恶意 IP': 'malicious',
  '其他': 'other',
}

/** IP 名单分类 label：命中词条→本地化；CRS 分类→crsCategory 词条；未命中回退原名。 */
export const ipListCategoryLabel = (raw?: string): string => {
  if (!raw) return raw || ''
  const k = hasOwn(IP_LIST_CATEGORY_KEYS, raw) ? IP_LIST_CATEGORY_KEYS[raw] : undefined
  if (k) return t(`common.app.ipListCategory.${k}`)
  const ck = hasOwn(CRS_CATEGORY_KEYS, raw) ? CRS_CATEGORY_KEYS[raw] : undefined
  if (ck) return t(`common.app.crsCategory.${ck}`)
  return raw
}
