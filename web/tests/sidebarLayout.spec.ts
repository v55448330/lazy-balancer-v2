// 侧栏布局状态机与折叠态账户入口的行为验收。
//   ① 窄屏（≤768px）强制折叠只是默认态：折叠入口此前可聚焦、有完整 aria 语义，
//      点击/回车/空格却完全无效（只翻转宽屏折叠态），读屏恒听「已折叠」。
//   ② 折叠态用户区只剩 24px 无内容、无无障碍名称的可点条带，而「退出登录」只
//      存在于该下拉里——窄屏用户没有可发现的退出入口。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { accountInitial, accountTriggerLabel, sidebarCollapsed, sidebarOverlay, sidebarWidth, toggleSidebarState } from '../src/utils/sidebarLayout.ts'
import { code, section } from './_helpers.ts'

test('宽屏：折叠态由用户显式选择决定', () => {
  assert.equal(sidebarCollapsed({ narrow: false, userCollapsed: false, narrowExpanded: false }), false)
  assert.equal(sidebarCollapsed({ narrow: false, userCollapsed: true, narrowExpanded: true }), true, '窄屏展开态不影响宽屏')
})

test('窄屏：默认折叠，显式展开后覆盖媒体查询（入口真的有可观察效果）', () => {
  assert.equal(sidebarCollapsed({ narrow: true, userCollapsed: false, narrowExpanded: false }), true)
  assert.equal(sidebarCollapsed({ narrow: true, userCollapsed: false, narrowExpanded: true }), false)
  assert.equal(sidebarCollapsed({ narrow: true, userCollapsed: true, narrowExpanded: true }), false, '窄屏展开优先于宽屏折叠记忆')
})

test('折叠入口只翻转当前视口相关的那一维', () => {
  assert.deepEqual(toggleSidebarState({ narrow: false, userCollapsed: false, narrowExpanded: false }), {
    narrow: false, userCollapsed: true, narrowExpanded: false,
  })
  assert.deepEqual(toggleSidebarState({ narrow: true, userCollapsed: true, narrowExpanded: false }), {
    narrow: true, userCollapsed: true, narrowExpanded: true,
  })
  // 连按两次回到原态（可逆、无粘滞）
  const twice = toggleSidebarState(toggleSidebarState({ narrow: true, userCollapsed: false, narrowExpanded: false }))
  assert.deepEqual(twice, { narrow: true, userCollapsed: false, narrowExpanded: false })
})

test('宽度与浮层：窄屏展开是浮层（不挤压内容区），宽度由折叠态单源派生', () => {
  assert.equal(sidebarWidth(true), '64px')
  assert.equal(sidebarWidth(false), '220px')
  assert.equal(sidebarOverlay({ narrow: true, collapsed: false }), true)
  assert.equal(sidebarOverlay({ narrow: true, collapsed: true }), false)
  assert.equal(sidebarOverlay({ narrow: false, collapsed: false }), false, '宽屏展开是常态布局')
})

test('折叠态账户入口必须有无障碍名称与可见标识', () => {
  assert.equal(accountTriggerLabel('运维小王'), '账户菜单：运维小王')
  assert.equal(accountTriggerLabel(''), '账户菜单：当前用户', '用户名缺失时也要有可宣布的名称')
  assert.equal(accountInitial('运维小王'), '运')
  assert.equal(accountInitial(''), '用')
  assert.equal(accountInitial('  '), '用', '空白名不得渲染空标识')
})

test('AppLayout 接线：窄屏入口可切换、状态由单源派生', () => {
  const layout = code('src/components/layout/AppLayout.vue')
  assert.match(layout, /from '@\/utils\/sidebarLayout'/, '布局状态必须走单源')
  const toggle = section(layout, 'const toggleSidebar = ', '\nconst ')
  assert.match(toggle, /toggleSidebarState\(/, '折叠入口必须按视口分派（窄屏翻窄屏展开态）')
  const collapsed = section(layout, 'const effectiveCollapsed = ', '\nconst ')
  assert.match(collapsed, /sidebarCollapsed\(/, '折叠态判定必须来自单源')
  assert.match(layout, /:width="sidebarWidth\(effectiveCollapsed\)"/, '侧栏宽度必须单源派生')
  // 窄屏展开是浮层：遮罩可点击收起，且 aria-hidden（纯视觉层）
  assert.match(layout, /class="sidebar-backdrop"[^>]*aria-hidden="true"/, '浮层遮罩必须存在且对读屏隐藏')
  assert.match(layout, /@click="closeNarrowSidebar"/, '遮罩点击必须收起浮层')
  assert.match(layout, /:class="\{ 'is-overlay': sidebarOverlayVisible \}"/, '窄屏展开必须走浮层样式')
  assert.match(layout, /const sidebarOverlayVisible = computed\(\(\) => sidebarOverlay\(\{ narrow: isNarrowViewport\.value, collapsed: effectiveCollapsed\.value \}\)\)/, '浮层判定必须走单源')
  // 折叠态账户入口：可见标识 + aria-label，且下拉仍含退出登录
  assert.match(layout, /v-if="effectiveCollapsed" class="user-avatar" aria-hidden="true"/, '折叠态必须有可见标识（首字头像）')
  assert.match(layout, /:aria-label="accountTriggerLabel\(menuDisplayName\)"/, '折叠态入口必须有无障碍名称')
  assert.match(layout, /退出登录/)
})

// 子菜单间距的多轮叠加：`.el-sub-menu.is-opened{margin-bottom:0!important}` 曾被
// 同特异性、后置的 `.el-sub-menu.is-opened{margin-bottom:4px!important}` 完全覆盖
// ——前一条恒死，读代码会误判「展开态间距为 0」；随后两条又都是基础规则的同值
// 复述。真源只保留 `.el-sub-menu` 基础规则，展开态不得再单写一份。
test('侧栏子菜单间距：is-opened 不再复述 margin-bottom（无被覆盖的死规则）', () => {
  const layout = code('src/components/layout/AppLayout.vue')
  const style = section(layout, '<style', '</style>')
  assert.match(
    style,
    /\.layout-menu :deep\(\.el-sub-menu\) \{\s*margin-top: 4px !important;\s*margin-bottom: 4px !important;/,
    '基础规则必须是间距唯一真源',
  )
  const openedRules = [...style.matchAll(/\.el-sub-menu\.is-opened\)\s*\{([^}]*)\}/g)]
    .map((match) => match[1] ?? '')
  const withMarginBottom = openedRules.filter((rule) => /margin-bottom/.test(rule))
  assert.equal(
    withMarginBottom.length,
    0,
    `展开态不得再单写 margin-bottom（当前 ${withMarginBottom.length} 处：同特异性后置规则会让其中一条恒死）`,
  )
})
