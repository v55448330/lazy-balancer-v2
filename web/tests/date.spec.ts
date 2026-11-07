// date.ts 行为验收（生产热路径：规则/安全事件/仪表盘/证书任务全部经它格式化）：
//   - DB 墙钟串（UTC 存储）解析 + `+Z` 规范化（Safari `NaN` 回归守卫）
//   - 非 ISO 串原样透传 / 解析失败返回空串（不猜、不抛）
//   - 配置时区格式化（date / short / 图表轴 HH:mm:ss，h23）
//   - 模块级 formatter 缓存（同 时区×形态 只构造一次）
//   - 非法配置时区回退 DEFAULT_TZ 且只 warn 一次
//
// date.ts 依赖 @/stores/auth（pinia 链）。测试用 registerModuleHooks 把它替换为
// 读取 globalThis.__tz 的替身，并把时区格式化模块替换为「计数构造次数」的
// 等价实现（缓存行为可观测）；真实格式化口径由 timeZoneFormat.spec 覆盖。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { registerModuleHooks } from './_helpers.ts'
import { dataModule } from './_stubs.ts'
// 真实内核（不经替身）：与 date.parseDbTimeMs 逐形态对表用。
import { parseDbDateMs } from '../src/utils/timeZoneFormat.ts'

type Harness = { __tz: string; __formatCalls: number }
const g = globalThis as unknown as Harness
g.__tz = 'Asia/Shanghai'
g.__formatCalls = 0

const stubAuth = dataModule(`
export const useAuthStore = () => ({ timezone: globalThis.__tz })
`)

// 与 utils/timeZoneFormat 等价的实现，额外统计 createTzFormatter 构造次数——
// 用来验证 date.ts 的模块级 formatter 缓存（构造次数不随调用次数增长）。
// DB 墙钟内核（normalizeDbWallClock/parseDbDateMs）不复制：直接回指真实模块，
// 保证「date.parseDbTimeMs 与内核同源」这一契约在测试里也是同源（复刻一份就等于
// 给单源开了第二个实现）。
const tzKernelUrl = new URL('../src/utils/timeZoneFormat.ts', import.meta.url).href
const countingFormat = dataModule(`
export { normalizeDbWallClock, parseDbDateMs } from '${tzKernelUrl}'
export const DEFAULT_TZ = 'Asia/Shanghai'
export const createTzFormatter = (timeZone, withTime) => {
  globalThis.__formatCalls++
  return new Intl.DateTimeFormat('en-US', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    ...(withTime ? { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' } : {}),
  })
}
export const formatDateParts = (d, formatter, withTime) => {
  const parts = formatter.formatToParts(d)
  const get = (type) => parts.find((p) => p.type === type)?.value ?? ''
  const date = get('year') + '-' + get('month') + '-' + get('day')
  return withTime ? date + ' ' + get('hour') + ':' + get('minute') + ':' + get('second') : date
}
`)

registerModuleHooks({
  '@/stores/auth': stubAuth,
  '@/utils/timeZoneFormat': countingFormat,
})

const date = await import('../src/utils/date.ts')

test('DB 墙钟串按 UTC 解析（+Z 规范化，Safari NaN 回归守卫）', () => {
  const expected = Date.UTC(2026, 7, 11, 8, 23, 21)
  const parsed = date.parseDbTimeMs('2026-08-11 08:23:21')
  assert.equal(parsed, expected)
  assert.ok(Number.isFinite(parsed), '不得返回 NaN（Safari 裸 new Date 空格格式的回归）')
  // 秒可省略
  assert.equal(date.parseDbTimeMs('2026-08-11 08:23'), Date.UTC(2026, 7, 11, 8, 23))
  // 已带时区的 RFC3339 原样解析（不重复追加 Z）
  assert.equal(date.parseDbTimeMs('2026-08-11T08:23:21Z'), expected)
  assert.equal(date.parseDbTimeMs('2026-08-11T16:23:21+08:00'), expected)
})

test('不可解析/非字符串一律 null（不猜、不抛）', () => {
  for (const value of [null, undefined, '', 'not-a-date', '2026-08-11', 123, {}, []]) {
    assert.equal(date.parseDbTimeMs(value), null, `${JSON.stringify(value)} 应解析失败`)
  }
})

// DB 墙钟解析曾有「三份实现 + 接受集合分叉」：内核（parseDbDateMs，任何 Date
// 可解析串）、date.ts 的 parseDbTimeMs（叠 ISO 白名单）、threatFlowRules 的
// flowTimestamp（另一份、失败为 NaN）。现在三者共用内核，差异只允许白名单这一层。
test('DB 时间解析与内核同源：四形态逐项对表（差异仅 ISO 白名单）', () => {
  const forms = [
    { input: '2026-08-11 08:23:21', label: 'DB 墙钟（空格分隔）' },
    { input: '2026-08-11 08:23', label: 'DB 墙钟（省略秒）' },
    { input: '2026-08-11T08:23:21Z', label: '带 Z 的 RFC3339' },
    { input: '2026-08-11T16:23:21+08:00', label: '带时区偏移' },
    { input: 'not-a-date', label: '非法串' },
    { input: '', label: '空串' },
  ]
  for (const { input, label } of forms) {
    assert.equal(date.parseDbTimeMs(input), parseDbDateMs(input), `${label} 必须与内核同结果`)
  }
  // 唯一允许的差异：仅日期形态被白名单拒绝（内核不设白名单）。白名单只影响
  // 「是否接受」，不影响已接受输入的解析结果——两者共用规范化与内核。
  assert.equal(date.parseDbTimeMs('2026-08-11'), null)
  assert.equal(parseDbDateMs('2026-08-11'), Date.UTC(2026, 7, 11))
})

test('formatDate：DB 墙钟串转配置时区；非 ISO 文本原样透传；空值返回空串', () => {
  // 08:23:21Z → Asia/Shanghai 16:23:21
  assert.equal(date.formatDate('2026-08-11 08:23:21'), '2026-08-11 16:23:21')
  // 后端已是人读文本 / 前端已格式化：原样返回，不再当时间解析
  assert.equal(date.formatDate('刚刚'), '刚刚')
  assert.equal(date.formatDate(null), '')
  assert.equal(date.formatDate(undefined), '')
  assert.equal(date.formatDate({}), '')
})

test('formatDateShort：仅日期（配置时区），非 ISO 文本同样透传', () => {
  assert.equal(date.formatDateShort('2026-08-11 16:30:00'), '2026-08-12')
  assert.equal(date.formatDateShort('2026-08-11T01:00:00Z'), '2026-08-11')
  assert.equal(date.formatDateShort('昨天'), '昨天')
  assert.equal(date.formatDateShort(''), '')
})

test('formatChartTimeInConfigTz：h23 的 HH:mm:ss（午夜不显示 24 点）', () => {
  // 2026-01-01T16:05:09Z → 北京 2026-01-02 00:05:09
  assert.equal(date.formatChartTimeInConfigTz(Date.UTC(2026, 0, 1, 16, 5, 9)), '00:05:09')
  assert.equal(date.formatChartTimeInConfigTz(Date.UTC(2026, 0, 1, 15, 59, 59)), '23:59:59')
})

test('formatter 缓存：同 时区×形态 只构造一次（轮询高频调用不重复建 Intl）', async () => {
  // 缓存是模块实例状态：独立实例从冷启动验证「首次构造一次、之后命中」。
  const fresh = await import(`../src/utils/date.ts?cache=${Date.now()}`)
  const before = g.__formatCalls
  fresh.formatDate('2026-08-11 08:23:21')
  fresh.formatDate('2026-09-01 00:00:00')
  fresh.formatChartTimeInConfigTz(Date.UTC(2026, 0, 1, 12, 0, 0))
  assert.equal(g.__formatCalls, before + 1, 'withTime 形态首次构造一次、后续命中缓存')

  fresh.formatDateShort('2026-08-11 08:23:21')
  assert.equal(g.__formatCalls, before + 2, 'date-only 形态首次构造一次')
  fresh.formatDateShort('2026-09-01 00:00:00')
  assert.equal(g.__formatCalls, before + 2, 'date-only 形态后续命中缓存')
})

test('非法配置时区 + 图表轴：首个调用即回退 DEFAULT_TZ 并缓存回退实例', async () => {
  g.__tz = 'Mars/Olympus'
  const warnings: string[] = []
  const originalWarn = console.warn
  console.warn = (message?: unknown) => { warnings.push(String(message)) }
  try {
    const fresh = await import(`../src/utils/date.ts?invalid-tz-chart=${Date.now()}`)
    assert.equal(fresh.formatChartTimeInConfigTz(Date.UTC(2026, 0, 1, 16, 5, 9)), '00:05:09')
    const afterFirst = g.__formatCalls
    assert.equal(fresh.formatChartTimeInConfigTz(Date.UTC(2026, 0, 1, 15, 59, 59)), '23:59:59')
    assert.equal(g.__formatCalls, afterFirst, '回退实例同样进入缓存（后续调用不再构造 Intl）')
    assert.equal(warnings.length, 1, '图表轴与文本格式化共用同一 warn 去重位')
    assert.match(warnings[0], /Mars\/Olympus/)
  } finally {
    console.warn = originalWarn
    g.__tz = 'Asia/Shanghai'
  }
})

test('非法配置时区：回退 DEFAULT_TZ 且只 warn 一次（不刷屏、不抛）', async () => {
  g.__tz = 'Mars/Olympus'
  const warnings: string[] = []
  const originalWarn = console.warn
  console.warn = (message?: unknown) => { warnings.push(String(message)) }
  try {
    // 模块级 warnedInvalidTz / 缓存是实例状态：独立查询串加载新实例
    const fresh = await import(`../src/utils/date.ts?invalid-tz=${Date.now()}`)
    assert.equal(fresh.formatDate('2026-08-11 08:23:21'), '2026-08-11 16:23:21')
    assert.equal(fresh.formatDate('2026-09-01 00:00:00'), '2026-09-01 08:00:00')
    assert.equal(fresh.formatDateShort('2026-08-11 08:23:21'), '2026-08-11')
    assert.equal(warnings.length, 1, '同一实例只 warn 一次')
    assert.match(warnings[0], /Mars\/Olympus/)
    assert.match(warnings[0], /Asia\/Shanghai/)
  } finally {
    console.warn = originalWarn
    g.__tz = 'Asia/Shanghai'
  }
})

// 统计起点标签（仪表盘规则卡「统计自 …」，epoch Unix 秒入参）：经 tzFormatter
// 配置时区单源渲染；同日 HH:MM、跨日 MM-DD HH:MM（长期不重载时判定是哪一天）。
// 同卡图表轴 formatChartTimeInConfigTz 同一钟面——跨时区管理员不得出现两个钟面。
test('formatEpochStatLabel：同日 HH:MM、跨日 MM-DD HH:MM（Asia/Shanghai 固定钟）', () => {
  // 2026-11-08 10:30 UTC = 18:30 Asia/Shanghai
  const epoch = Math.floor(Date.UTC(2026, 10, 8, 10, 30, 0) / 1000)
  const sameDayNow = Date.UTC(2026, 10, 8, 12, 0, 0)
  assert.equal(date.formatEpochStatLabel(epoch, sameDayNow), '18:30')
  // 跨日（昨日重载、今天查看）：MM-DD HH:MM
  const nextDayNow = Date.UTC(2026, 10, 9, 2, 0, 0)
  assert.equal(date.formatEpochStatLabel(epoch, nextDayNow), '11-08 18:30')
})
