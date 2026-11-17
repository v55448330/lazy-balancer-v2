// 页面键唯一事实源：App.vue 深链/OIDC return_to 校验、威胁大屏全屏分支、
// auth store 的 currentPage 初值共用。禁止另起字面量清单（双源漂移会让深链
// 静默回落 dashboard）。

import { SETTINGS_TAB_IDS } from './settingsPages.ts'

// 非设置页的页面键（设置分页由 SETTINGS_TAB_IDS 派生，见下）。
const CORE_PAGE_IDS = [
  'dashboard',
  'rules',
  'security-policies',
  'security-rules',
  'security-block-pages',
  'security-overview',
  'security-events',
  'threat-screen',
  'caddy',
  'users',
  'audit-log',
  'notifications',
] as const

// 设置分页键由单源派生：新增/改名分页只改 utils/settingsPages 一处，
// PAGE_IDS 与 App.vue 的条件分支同步跟随（曾三处枚举，漏 App.vue 会静默落空页）。
const SETTINGS_PAGE_IDS = SETTINGS_TAB_IDS.map((tab) => `settings-${tab}` as const)

export const PAGE_IDS = [...CORE_PAGE_IDS, ...SETTINGS_PAGE_IDS] as const

export type PageId = (typeof PAGE_IDS)[number]

const validPages: ReadonlySet<string> = new Set(PAGE_IDS)

/** 页面键收窄（深链/URL hash/localStorage 读出值统一经此校验）。 */
export const isPageId = (page: string): page is PageId => validPages.has(page)
