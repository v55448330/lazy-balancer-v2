// 通知域三处接线钉（audit152 前端面）：
//  1) 通道卡保存：编辑目标在任何 await 之前捕获（关抽屉会清 editTarget，
//     保存后再判会导致机器人通道「保存即自动测试」整段静默跳过）；
//  2) 事件规则浮层：events=已订阅子集后，选项源必须仍是组内全量
//     （catalog.group 优先，回退 event_titles 键集），events 只作订阅态回显；
//     空勾选=全不选合法保存，非空时确认文案提示将启用 N 个事件；
//  3) 任务监控：通知任务族 6 项的显示名/描述/分类排序与 zh/en 词条齐全。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, member, repoCode, section } from './_helpers.ts'

const CHANNEL_CARDS = code('src/views/notifications/ChannelCards.vue')
const CENTER = code('src/views/notifications/NotificationCenter.vue')
const TASK_MONITOR = code('src/views/settings/TaskMonitor.vue')

/**
 * 通知任务族：事实源=internal/services/notification_tasks.go 的 Descriptor
 * （Family=="notification"）Name；词条键从 TaskMonitor 的 TASK_NAME_KEYS 映射取，
 * 缺映射即红（硬编码期望表会随后端新增任务静默脱节）。
 */
const notificationTasks = (): { names: string[]; keys: string[] } => {
  const go = repoCode('internal/services/notification_tasks.go')
  const blocks = go.split('mustRegisterTask(te, taskengine.Descriptor{').slice(1)
  const names = blocks
    .filter((block) => /Family:\s*"notification"/.test(block))
    .map((block) => block.match(/\bName:\s*"([^"]+)"/)?.[1])
    .filter((name): name is string => !!name)
  const table = section(TASK_MONITOR, 'const TASK_NAME_KEYS: Record<string, string> = {', '\n}')
  const byName = new Map([...table.matchAll(/'([^']+)':\s*'([^']+)'/g)].map((m) => [m[1], m[2]] as const))
  const missing = names.filter((name) => !byName.has(name))
  assert.deepEqual(missing, [], `TaskMonitor.TASK_NAME_KEYS 缺通知任务映射: ${missing.join('、')}`)
  return { names, keys: names.map((name) => byName.get(name) ?? '') }
}

test('通道卡保存：editTarget 在首个 await 前捕获，并按捕获目标类型触发自动测试', () => {
  const fn = member(CHANNEL_CARDS, 'const saveDrawer = async')
  const captureAt = fn.indexOf('const editing = editTarget.value')
  const firstAwaitAt = fn.indexOf('await request.')
  assert.ok(captureAt > 0, '必须在保存前捕获编辑目标')
  assert.ok(firstAwaitAt > captureAt, '捕获必须早于任何写请求 await')
  // 编辑分支与自动测试判型都消费捕获值（不再在 await 之后读 editTarget.value）
  assert.match(fn, /request\.put\(`\/notification\/channels\/\$\{editing\.id\}`/)
  assert.match(fn, /if \(editing\.type === 'qq' \|\| editing\.type === 'wx_clawbot'\)/)
  assert.match(fn, /channels\.value\.find\(c => c\.id === editing\.id\)/)
  assert.doesNotMatch(fn, /editTarget\.value && \(drawerForm/, '保存后判 editTarget 已失效（关抽屉清空）')
})

test('事件规则浮层：选项源=组内全量（catalog 优先，event_titles 键集回退），events 仅订阅态', () => {
  const fn = member(CENTER, 'const rowEventOptions =')
  assert.match(fn, /eventCatalog\.value\.filter\(e => e\.group === rule\.title\)/)
  assert.match(fn, /Object\.keys\(rule\.event_titles \?\? \{\}\)/, '回退必须用组内全量键集')
  const titlesAt = fn.indexOf('Object.keys(rule.event_titles')
  const eventsFallbackAt = fn.indexOf('(rule.events ?? [])')
  assert.ok(titlesAt > 0 && eventsFallbackAt > titlesAt, 'events（已订阅子集）只能作最后回退，不得优先于全量键集')
})

test('事件规则保存：空勾选合法（不拦截），非空确认文案提示将启用 N 个事件', () => {
  const fn = member(CENTER, 'const saveAllRuleDrafts = async')
  assert.match(fn, /eventsToEnable/)
  assert.match(fn, /t\('app\.notification\.rules\.saveRuleConfirmWithEvents', \{ rules: dirty\.length, events: eventsToEnable \}\)/)
  assert.match(fn, /t\('app\.notification\.rules\.saveRuleConfirm'\)/, '零勾选仍可保存（回落普通确认）')
  // 空勾选不得被前置 return 拦截（全不选=取消订阅本组，合法保存）
  assert.doesNotMatch(fn, /events\.length === 0[\s\S]{0,60}return/)
  assert.match(fn, /events: d\.events, channel_ids: d\.channel_ids, min_level: d\.min_level/)
})

test('任务监控：通知任务族映射后端注册名（Go Descriptor 扫描对表，缺/多均红）', () => {
  const { names, keys } = notificationTasks()
  assert.ok(names.length >= 6, `Go 通知任务族解析异常（${names.length}）——扫描器失效`)
  assert.deepEqual(keys, notificationTasks().keys, '重复调用必须稳定')
  assert.equal(new Set(keys).size, keys.length, '通知任务族词条键不得重复')
  for (const key of keys) assert.match(key, /^[a-z][A-Za-z0-9]*$/, `词条键必须是驼峰标识符（${key}）`)
})

test('事件规则草稿：min_level 种子读行值（存量 warn/critical 不因保存被改写）', () => {
  const fn = member(CENTER, 'const newRuleDraft =')
  assert.match(fn, /min_level:\s*rule\.min_level\s*\|\|\s*'info'/, '种子必须读行值，仅空值回落 info')
  assert.doesNotMatch(fn, /min_level:\s*'info'\s*,/, '固定 info 会静默清除存量级别门槛（脏写）')
})

test('任务监控：通知分类可翻译且排入分类序（不落 9 号兜底）', () => {
  assert.match(TASK_MONITOR, /'通知': 'notifications'/, 'categoryLabel 必须登记通知分类')
  assert.match(TASK_MONITOR, /const categoryOrder: Record<string, number> = \{[^}]*'通知': 5/, '通知类必须有显式排序位')
  assert.ok(code('src/locales/zh/settings.ts').includes('"notifications": "通知"'))
  assert.ok(code('src/locales/en/settings.ts').includes('"notifications": "Notifications"'))
})

test('任务监控：6 项显示名与描述 zh/en 成对（不回落后端中文原文）', () => {
  const { keys } = notificationTasks()
  for (const locale of ['zh', 'en']) {
    const names = code(`src/locales/${locale}/misc.ts`)
    const descs = code(`src/locales/${locale}/common.ts`)
    for (const key of keys) {
      assert.match(names, new RegExp(`^\\s*${key}: '`, 'm'), `${locale} taskNames 缺 ${key}`)
      assert.match(descs, new RegExp(`^\\s*${key}: '`, 'm'), `${locale} taskDesc 缺 ${key}`)
    }
  }
})
