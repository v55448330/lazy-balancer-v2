// 「检查更新」入口与弹框的组合行为验收（useUpdateCheck）+ 基础设置页接线钉：
//
// 1. 行为：进页一次拉取官网版本目录（零轮询），与 branding APP_VERSION 比较，
//    稳定版/测试版各自仅在「比当前运行版本新」时落定条目（同号 beta 是预发布，
//    不构成测试版更新）；拉取失败静默跳过、console 零噪音；无更新时入口打不开弹框。
// 2. 接线钉：BasicSettings 版本行徽标（键盘可达 AccessibleLink）、弹框
//    DialogHeader + el-tabs（无更新内容的 tab 隐藏）、说明文字一律插值渲染
//    （textContent，禁 v-html）、页脚官网链接与关闭。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, registerModuleHooks } from './_helpers.ts'
import { STUB_API } from './_stubs.ts'

// 动态 import：branding → api.ts 链含字节级依赖（element-plus 的 CSS 导入），
// 测试进程必须先注册 data: 替身钩子再加载模块图——静态 import 会先求值真实
// 依赖。本仓 composable 行为用例的统一形态（见 libUpdateSession.spec.ts）。
registerModuleHooks({ '@/utils/api': STUB_API })

const { appVersion } = await import('../src/utils/branding.ts')
const { useUpdateCheck } = await import('../src/composables/useUpdateCheck.ts')

interface FetchProbe {
  url: unknown
  init?: RequestInit
}

/** 顶替 globalThis.fetch 并回放给定 versions.json 形状；返回请求探针与还原函数。 */
const stubFetch = (
  handler: (probe: FetchProbe) => unknown,
): { probes: FetchProbe[]; restore: () => void } => {
  const real = globalThis.fetch
  const probes: FetchProbe[] = []
  globalThis.fetch = (async (url: string | URL, init?: RequestInit) => {
    probes.push({ url, init })
    return handler({ url, init }) as Response
  }) as typeof fetch
  return { probes, restore: () => { globalThis.fetch = real } }
}

const payloadOf = (versions: Array<{ version: string; channel: string }>): unknown => ({
  updated_at: '2026-11-01',
  versions: versions.map((item) => ({ ...item, channel_label: 'x', notes: [`note of ${item.version}`] })),
})

test('稳定版与测试版都有更新：两条目落定，徽标展示稳定版，弹框默认稳定版 tab', async () => {
  appVersion.value = 'v2.3.9'
  const fetchStub = stubFetch(() => ({
    ok: true,
    json: async () => payloadOf([
      { version: 'v2.4.1-beta', channel: 'beta' },
      { version: 'v2.4.0-beta', channel: 'retired' },
      { version: 'v2.4.1', channel: 'stable' },
    ]),
  }))
  const uc = useUpdateCheck()
  try {
    await uc.check()
    assert.equal(fetchStub.probes.length, 1, '每次 check 恰好一次远端请求（零轮询）')
    assert.equal(uc.stableUpdate.value?.version, 'v2.4.1')
    assert.equal(uc.betaUpdate.value?.version, 'v2.4.1-beta')
    assert.equal(uc.hasUpdate.value, true)
    assert.equal(uc.badgeVersion.value, 'v2.4.1', '徽标优先展示稳定版')
    uc.openDialog()
    assert.equal(uc.dialogVisible.value, true)
    assert.equal(uc.activeTab.value, 'stable')
  } finally {
    fetchStub.restore()
  }
})

test('仅测试版更新（稳定版不比当前新）：稳定版条目为空，弹框落到测试版 tab', async () => {
  appVersion.value = 'v2.4.0'
  const fetchStub = stubFetch(() => ({
    ok: true,
    json: async () => payloadOf([
      { version: 'v2.4.1-beta', channel: 'beta' },
      { version: 'v2.4.0', channel: 'stable' },
    ]),
  }))
  const uc = useUpdateCheck()
  try {
    await uc.check()
    assert.equal(uc.stableUpdate.value, null, '同版本号不构成稳定版更新')
    assert.equal(uc.betaUpdate.value?.version, 'v2.4.1-beta')
    assert.equal(uc.badgeVersion.value, 'v2.4.1-beta')
    uc.openDialog()
    assert.equal(uc.dialogVisible.value, true)
    assert.equal(uc.activeTab.value, 'beta')
  } finally {
    fetchStub.restore()
  }
})

test('仅稳定版更新：远端同号 beta 相对正式版不是更新（预发布语义钉测）', async () => {
  appVersion.value = 'v2.4.0'
  const fetchStub = stubFetch(() => ({
    ok: true,
    json: async () => payloadOf([
      { version: 'v2.4.0-beta', channel: 'beta' },
      { version: 'v2.4.1', channel: 'stable' },
    ]),
  }))
  const uc = useUpdateCheck()
  try {
    await uc.check()
    assert.equal(uc.betaUpdate.value, null, 'v2.4.0-beta 相对 v2.4.0 不是新版本')
    assert.equal(uc.stableUpdate.value?.version, 'v2.4.1')
    uc.openDialog()
    assert.equal(uc.activeTab.value, 'stable')
  } finally {
    fetchStub.restore()
  }
})

test('无更新：条目全空、徽标版本为空串，openDialog 防御性短路', async () => {
  appVersion.value = 'v2.4.0'
  const fetchStub = stubFetch(() => ({
    ok: true,
    json: async () => payloadOf([
      { version: 'v2.4.0-beta', channel: 'beta' },
      { version: 'v2.4.0', channel: 'stable' },
    ]),
  }))
  const uc = useUpdateCheck()
  try {
    await uc.check()
    assert.equal(uc.hasUpdate.value, false)
    assert.equal(uc.badgeVersion.value, '')
    assert.equal(uc.dialogVisible.value, false, '前置：弹框未打开')
    uc.openDialog()
    assert.equal(uc.dialogVisible.value, false, '无更新不得打开弹框')
  } finally {
    fetchStub.restore()
  }
})

test('拉取失败/超时静默跳过：条目保持空、无异常外泄、console 零噪音', async () => {
  appVersion.value = 'v2.4.0'
  const consoleError: unknown[] = []
  const consoleWarn: unknown[] = []
  const consoleInfo: unknown[] = []
  const original = { error: console.error, warn: console.warn, info: console.info }
  console.error = (...args: unknown[]) => { consoleError.push(args) }
  console.warn = (...args: unknown[]) => { consoleWarn.push(args) }
  console.info = (...args: unknown[]) => { consoleInfo.push(args) }
  const failStub = stubFetch(() => { throw new TypeError('fetch failed') })
  const uc = useUpdateCheck()
  try {
    await uc.check()
    assert.equal(uc.hasUpdate.value, false)
    assert.deepEqual([consoleError.length, consoleWarn.length, consoleInfo.length], [0, 0, 0])
    failStub.restore()

    // HTTP 非 2xx 同口径静默
    const httpStub = stubFetch(() => ({ ok: false, status: 503, json: async () => ({}) }))
    try {
      await uc.check()
      assert.equal(uc.hasUpdate.value, false)
      assert.deepEqual([consoleError.length, consoleWarn.length, consoleInfo.length], [0, 0, 0])
    } finally {
      httpStub.restore()
    }
  } finally {
    failStub.restore()
    console.error = original.error
    console.warn = original.warn
    console.info = original.info
  }
})

test('接线钉：版本行徽标经 AccessibleLink 键盘可达，文案与弹框打开动作齐备', () => {
  const src = code('src/views/settings/BasicSettings.vue')
  const badge = src.slice(src.indexOf("t('app.settings.basic.system.version')"), src.indexOf("t('app.settings.basic.system.runMode')"))
  assert.ok(badge.includes('<el-tag type="info" size="small">{{ appVersion }}</el-tag>'), '版本行原样保留')
  assert.ok(badge.includes('v-if="updateAvailable"'), '徽标仅在有更新时渲染')
  assert.ok(badge.includes('<AccessibleLink'), '徽标必须是键盘可达组件（AccessibleLink）')
  assert.ok(badge.includes('@click="openUpdateDialog"'), '点击打开弹框')
  assert.ok(badge.includes("t('app.settings.basic.update.title')") && badge.includes('{{ updateBadgeVersion }}') && badge.includes('，点击查看'), '徽标文案')
})

test('接线钉：弹框 = DialogHeader + el-tabs，无更新内容的 tab 隐藏，说明插值渲染', () => {
  const src = code('src/views/settings/BasicSettings.vue')
  const dialogStart = src.indexOf('v-model="updateDialogVisible"')
  assert.ok(dialogStart > 0, '更新弹框存在')
  const dialog = src.slice(dialogStart, src.indexOf('</el-dialog>', dialogStart))
  assert.ok(dialog.includes('<DialogHeader'), '弹框头使用统一 DialogHeader')
  assert.ok(dialog.includes("title=\"t('app.settings.basic.update.title')\""))
  assert.ok(dialog.includes('<el-tabs v-model="updateActiveTab">'))
  assert.ok(dialog.includes("<el-tab-pane v-if=\"stableUpdate\" :label=\"t('app.settings.basic.update.stable')\" name=\"stable\">"), '稳定版 tab 随条目隐藏')
  assert.ok(dialog.includes("<el-tab-pane v-if=\"betaUpdate\" :label=\"t('app.settings.basic.update.beta')\" name=\"beta\">"), '测试版 tab 随条目隐藏')
  assert.ok(dialog.includes('{{ stableUpdate.version }}'))
  assert.ok(dialog.includes('{{ betaUpdate.version }}'))
  assert.ok(dialog.includes('<li v-for="note in stableUpdate.notes" :key="note">{{ note }}</li>'), '发布说明逐条插值渲染（textContent）')
  assert.ok(dialog.includes('<li v-for="note in betaUpdate.notes" :key="note">{{ note }}</li>'))
  assert.ok(!dialog.includes('v-html'), '弹框禁 v-html（防注入，数据源可信仍按规范）')
  assert.ok(dialog.includes('href="https://www.lazybalancer.org/docs.html#changelog"'), '页脚官网更新日志链接')
  assert.ok(dialog.includes('target="_blank"') && dialog.includes('rel="noopener"'))
  assert.ok(dialog.includes('@click="updateDialogVisible = false"'), '页脚关闭')
})

test('接线钉：进页挂载即检查一次（onMounted → checkForUpdates），无轮询面', () => {
  const src = code('src/views/settings/BasicSettings.vue')
  assert.ok(src.includes('} = useUpdateCheck()'), '组合式状态单源接线')
  const mountedStart = src.indexOf('onMounted(async () => {')
  assert.ok(mountedStart > 0, 'onMounted 存在')
  const mounted = src.slice(mountedStart, src.indexOf('\n})', mountedStart))
  assert.ok(mounted.includes('void checkForUpdates()'), '检查调用必须在 onMounted 内')
  assert.ok(!src.includes('setInterval'), '全文件零轮询')
})

test('静默契约钉：versionCheck 与 useUpdateCheck 均不产生 console 噪音', () => {
  assert.ok(!code('src/utils/versionCheck.ts').includes('console.'), '拉取失败静默（零 console 输出）')
  assert.ok(!code('src/composables/useUpdateCheck.ts').includes('console.'), '检查失败静默（零 console 输出）')
  const vc = code('src/utils/versionCheck.ts')
  assert.ok(vc.includes('signal: AbortSignal.timeout(timeoutMs)'), '拉取必须带超时信号')
  assert.ok(vc.includes('catch {'), '异常必须就地吞并')
})
