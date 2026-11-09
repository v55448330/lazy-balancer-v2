// 系统设置分页清单单源：Settings.vue 的页头标题/描述与 AppLayout.vue 的面包屑
// 原各持一份同构映射（标题字符串两处、页键→分页 id 一处），新增/改名时必然漏改
// 其中一处。此处收敛为唯一事实源，两处只做取值与拼接。
//
// 页键形如 `settings-basic`（utils/pageIds 的 PageId 与侧边栏 index 同形）。

export const SETTINGS_TAB_IDS = ['basic', 'cluster', 'certificates', 'apikeys', 'tasks'] as const
export type SettingsTabId = (typeof SETTINGS_TAB_IDS)[number]

// i18n:标题/描述经 tSafe 取词条(键=common.app.views.layout.settingsTab/Desc.*),
// zh 母本钉 locales/{zh,en}/views.ts(契约钉见 tests/settingsPages.spec.ts)。
import { tSafe } from '../i18n/tSafe.ts'

export const settingsTabTitle = (tab: SettingsTabId): string =>
  tSafe(`common.app.views.layout.settingsTab.${tab}`)

export const settingsTabDesc = (tab: SettingsTabId): string =>
  tSafe(`common.app.views.layout.settingsDesc.${tab}`)

/**
 * 分页是否消费 `/config`：基础设置（日志/大屏/安全事件/GitHub）与免费证书
 * （ACME 邮箱、证书天数、CA 提供商）两卡表单来自该端点；集群管理/任务监控/
 * API 密钥不读它。`configLoadFailed` 横幅的「保存已暂停」只在这些分页成立，
 * 否则会让人误判本页保存也失败。
 */
const SETTINGS_TABS_CONSUMING_CONFIG: readonly SettingsTabId[] = ['basic', 'certificates']

/** 分页是否消费 `/config`（决定配置加载失败横幅是否相关） */
export const settingsTabConsumesConfig = (tab: SettingsTabId): boolean =>
  SETTINGS_TABS_CONSUMING_CONFIG.includes(tab)

/** 侧边栏/路由页键 → 分页 id；非系统设置页返回 null */
export const settingsTabOfPage = (page: string): SettingsTabId | null => {
  const prefix = 'settings-'
  if (!page.startsWith(prefix)) return null
  const tab = page.slice(prefix.length)
  return (SETTINGS_TAB_IDS as readonly string[]).includes(tab) ? (tab as SettingsTabId) : null
}

/** 面包屑父级(AppLayout 用):词条化 */
export const settingsBreadcrumbParent = (): string => tSafe('common.app.views.layout.settingsBreadcrumbParent')
