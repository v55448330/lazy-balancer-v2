// 系统设置分页清单单源（utils/settingsPages）：Settings.vue 页头标题/描述与
// AppLayout.vue 面包屑曾各持一份映射——此处钉住单源数据本身（含现有可见文案，
// 改名必须显式改这里）、页键映射，以及两处消费方不再自带第二份字面量。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  SETTINGS_TAB_IDS,
  settingsTabConsumesConfig,
  settingsTabOfPage,
} from '../src/utils/settingsPages.ts'
import { code } from './_helpers.ts'

const zhViewsLayout = (): string => code('src/locales/zh/views.ts')

test('分页清单：页键 ↔ 页头标题/描述一一对应（可见文案即契约）', () => {
  assert.deepEqual([...SETTINGS_TAB_IDS], ['basic', 'cluster', 'certificates', 'apikeys', 'tasks'])
  // i18n:标题经 settingsTabTitle(词条 settingsTab.*);zh 母本钉 views.ts
  const zhViews = code('src/locales/zh/views.ts')
  for (const tab of SETTINGS_TAB_IDS) {
    assert.ok(zhViews.includes(`${tab}:`), `settingsTab 词条缺 ${tab}`)
  }
  assert.ok(zhViewsLayout().includes('settingsBreadcrumbParent'), '面包屑父级词条须存在')
})

test('分页清单：settings-<tab> 页键可逆映射，非设置页与未知分页返回 null', () => {
  for (const tab of SETTINGS_TAB_IDS) {
    assert.equal(settingsTabOfPage(`settings-${tab}`), tab)
  }
  assert.equal(settingsTabOfPage('dashboard'), null)
  assert.equal(settingsTabOfPage('security-policies'), null)
  assert.equal(settingsTabOfPage('settings-unknown'), null)
  assert.equal(settingsTabOfPage('settings-'), null)
})

test('分页清单：两处消费方共用单源，不再自带第二份映射', () => {
  const settings = code('src/views/Settings.vue')
  assert.match(settings, /from '@\/utils\/settingsPages'/)
  assert.match(settings, /settingsTabTitle\(activeTab\.value\)/)
  assert.match(settings, /settingsTabOfPage\(authStore\.currentPage\) \?\? 'basic'/)
  assert.doesNotMatch(settings, /const titles: Record<string, string>/)
  assert.doesNotMatch(settings, /const descs: Record<string, string>/)

  const layout = code('src/components/layout/AppLayout.vue')
  assert.match(layout, /from '@\/utils\/settingsPages'/)
  assert.match(layout, /settingsTabTitle\(tab\)/)
  assert.match(layout, /settingsBreadcrumbParent\(\)/)
  assert.doesNotMatch(layout, /'settings-basic': '系统设置 \/ 基础设置'/)
})

test('分页是否消费 /config：仅基础设置与免费证书（配置失败横幅只在这两页有意义）', () => {
  assert.equal(settingsTabConsumesConfig('basic'), true)
  assert.equal(settingsTabConsumesConfig('certificates'), true)
  for (const tab of ['cluster', 'apikeys', 'tasks'] as const) {
    assert.equal(settingsTabConsumesConfig(tab), false, `${tab} 不读 /config`)
  }
  // 接线：Settings.vue 的失败横幅由该判据门控，不是无条件渲染
  const settings = code('src/views/Settings.vue')
  assert.match(settings, /configBannerVisible = computed\(\(\) => configLoadFailed\.value && settingsTabConsumesConfig\(activeTab\.value\)\)/)
  assert.match(settings, /<el-alert v-if="configBannerVisible"/)
})
