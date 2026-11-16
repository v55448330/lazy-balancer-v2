import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useCountryNamesCn } from '@/composables/useCountryNamesCn'
import { hasOwn } from '@/utils/hasOwn'

/**
 * 站点坐标下拉的展示标签单源（威胁大屏本站坐标 BasicSettings + 集群节点配置
 * 弹框 ClusterNodeConfigDialog 共用）：
 *  - zh：取值原样（省名/国名即源文）；
 *  - en：中国省份经 geo 省份词条译（未收录回退原名），海外国家名源表
 *    COUNTRY_CENTROIDS 键为中文国名，经 country_names_cn 反查英文名（未收录回退原样）。
 * value 恒为 item.key，提交语义零改动；不翻译选择 key。
 *
 * 注：反转表 cnToEnCountry 是派生缓存（每次映射源变化重建），非展示词表——
 * 不进 vocabularyProtoKeys 扫描面（该守卫面向静态展示词表）；读取仍按原型键
 * 契约走 hasOwn（constructor/toString 等原型键直接下标会返回函数并绕过回退）。
 */
export function useSiteChoiceLabel() {
  const { t, locale } = useI18n()
  const zhCountryNames = useCountryNamesCn()
  const cnToEnCountry = computed(() => {
    const inv: Record<string, string> = {}
    for (const [en, cn] of Object.entries(zhCountryNames.value)) {
      if (!(cn in inv)) inv[cn] = en
    }
    return inv
  })
  const siteChoiceLabel = (item: { key: string; label: string }): string => {
    if (locale.value !== 'en') return item.label
    if (item.key.startsWith('cn:')) {
      const mapped = t(`app.security.policies.geo.provinces.${item.label}`)
      return mapped.includes('app.security.policies') ? item.label : mapped
    }
    const table = cnToEnCountry.value
    return hasOwn(table, item.label) ? table[item.label]! : item.label
  }
  return { siteChoiceLabel }
}
