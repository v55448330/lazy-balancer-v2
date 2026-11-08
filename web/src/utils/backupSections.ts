// 备份分类清单单源：导出/自动备份/还原共用同一份声明（后端 configBackupSections
// 为其镜像）。SFC 内声明会让测试只能靠正则剥类型求值——本模块是可 import 的纯
// 数据模块，前后端对表测试直接消费。
import { hasOwn } from './hasOwn.ts'
import { tSafe as t } from '../i18n/tSafe.ts'

/** 备份分类键 → 展示标签；顺序即 UI 顺序。i18n：标签走 views.impexp 词条键（zh 直出
 *  与原字面量逐字等价，跨栈对表测试不受影响）；确认文案三态同键化。 */
export const BACKUP_SECTIONS = [
  { key: 'users', label: t('common.app.views.impexp.secUsers') },
  { key: 'rules', label: t('common.app.views.impexp.secRules') },
  { key: 'security', label: t('common.app.views.impexp.secSecurity') },
  { key: 'cluster', label: t('common.app.views.impexp.secCluster') },
] as const

/** legacy 分类键别名：升级前的 global_config/waf_files 读出即归一。 */
export const LEGACY_SECTION_ALIASES: Record<string, string> = { global_config: 'users', waf_files: 'security' }

/**
 * 导入最终确认文案（覆盖面差异单源）。
 *
 * V1（nginx 版）备份按后端契约只导入负载规则部分（含内联证书）及其安全策略
 * 绑定；用户、API 密钥、证书任务与其它配置保持不变。V2 全量还包含节点拓扑。
 * 此前 V1 复用「覆盖当前全部配置（规则、用户、API 密钥、证书任务及全部凭证）」
 * ——与同一弹框内预览文案（「仅导入负载均衡规则，其他数据不受影响」）自相矛盾，
 * 会让人误判破坏范围。
 */
export const importConfirmMessage = (type: string | undefined, sections: readonly string[]): string => {
  if (type === 'v1') {
    return t('common.app.views.impexp.importConfirmV1')
  }
  if (sections.length === BACKUP_SECTIONS.length) {
    return t('common.app.views.impexp.importConfirmFull')
  }
  const labels = sections.map((key) => BACKUP_SECTIONS.find((section) => section.key === key)?.label || key)
  return t('common.app.views.impexp.importConfirmPartial', { sections: labels.join(t('common.app.views.impexp.labelJoin')) })
}

/** 归一分类键（映射 legacy 别名、去重、保序、未知键透传）。 */
export const normalizeBackupSectionKeys = (keys: string[]): string[] => {
  const seen = new Set<string>()
  const out: string[] = []
  for (const key of keys) {
    // 别名表是普通对象且键来自备份文件（外部输入）：原型键直接下标会返回函数，
    // 让归一结果失真（后续标签查找/「全选」判定随之误判）。
    const normalized = hasOwn(LEGACY_SECTION_ALIASES, key) ? LEGACY_SECTION_ALIASES[key] : key
    if (seen.has(normalized)) continue
    seen.add(normalized)
    out.push(normalized)
  }
  return out
}
