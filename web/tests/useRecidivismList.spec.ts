// 累犯历史服务端分页状态单源（useRecidivismList）行为验收：
// 携参请求（hide_permanent/ip/page/page_size）、total 取响应驱动分页、
// 筛选变化回首页、页码越界回夹（删末页末条/重置收缩）、乱序响应作废、
// 打开复位筛选、失败态清空。数据面从 RecidivismDialog 前端兜底切片切到
// 后端分页契约（{records,total,page,page_size}），交互形态不变。
//
// watch 为 pre-flush：状态写入后须 nextTick 让回调收敛再断言。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { nextTick } from 'vue'

import { useRecidivismList, type RecidivismFetch, type RecidivismRecord } from '../src/composables/useRecidivismList.ts'
import { flushMicrotasks, waitForMicrotasks } from './_helpers.ts'

const row = (identity: string): RecidivismRecord => ({
  identity, offense_count: 2, last_ban_at: '2026-11-15 10:00:00', escalated_duration: '24h',
})

/** 防抖窗口收尾：真实时钟等待 > 300ms（composable 用 setTimeout(300)），
 * 再排空微任务让 fetch 链收敛。仅搜索防抖用例需要真实时钟。 */
const waitDebounce = async (): Promise<void> => {
  const { promise, resolve } = Promise.withResolvers<void>()
  setTimeout(resolve, 360)
  await promise
  await flushMicrotasks()
}

interface FetchCall { hidePermanent: boolean; ip: string; page: number; pageSize: number }

/** 可控取数面：记录每次携参，按队列返回（缺省空页）。 */
const makeFetch = (pages: Array<{ records: RecidivismRecord[]; total: number }> = []) => {
  const calls: FetchCall[] = []
  let i = 0
  const fetchPage: RecidivismFetch = async (params) => {
    calls.push(params)
    return pages[i++] ?? { records: [], total: 0 }
  }
  return { calls, fetchPage }
}

test('open 携默认参数取数：hide_permanent=true、无 ip、page=1、page_size=20', async () => {
  const { calls, fetchPage } = makeFetch([{ records: [row('198.51.100.7')], total: 1 }])
  const list = useRecidivismList(fetchPage)
  list.open()
  await flushMicrotasks()
  assert.deepEqual(calls, [{ hidePermanent: true, ip: '', page: 1, pageSize: 20 }])
  assert.equal(list.records.value.length, 1)
  assert.equal(list.total.value, 1, 'total 必须取响应（筛选后总数）')
  assert.equal(list.loading.value, false)
  assert.equal(list.loadError.value, false)
})

test('翻页/改页大小/关隐藏永久都携参重取；筛选变化回首页', async () => {
  const { calls, fetchPage } = makeFetch([
    { records: [], total: 120 }, // open
    { records: [], total: 120 }, // page=2
    { records: [], total: 120 }, // pageSize=50（回首页）
    { records: [], total: 300 }, // hidePermanent=false（回首页）
  ])
  const list = useRecidivismList(fetchPage)
  list.open()
  await flushMicrotasks()

  list.page.value = 2
  await nextTick(); await flushMicrotasks()
  assert.deepEqual(calls[1], { hidePermanent: true, ip: '', page: 2, pageSize: 20 })

  // 改页大小：组件侧 onPageSizeChange 同 tick 回首页——只发一次请求
  list.pageSize.value = 50
  list.page.value = 1
  await nextTick(); await flushMicrotasks()
  assert.equal(calls.length, 3, '改页大小+回首页同一 tick 只发一次请求')
  assert.deepEqual(calls[2], { hidePermanent: true, ip: '', page: 1, pageSize: 50 })

  list.hidePermanent.value = false
  await nextTick(); await flushMicrotasks()
  assert.deepEqual(calls[3], { hidePermanent: false, ip: '', page: 1, pageSize: 50 })
  assert.equal(list.total.value, 300, 'total 随筛选响应更新')
})

test('IP 搜索防抖后 trim 携 ip 参数并回首页；空串不带 ip', async () => {
  const { calls, fetchPage } = makeFetch([
    { records: [], total: 5 },
    { records: [row('45.33.32.77')], total: 1 },
    { records: [], total: 5 },
  ])
  const list = useRecidivismList(fetchPage)
  list.open()
  await flushMicrotasks()
  assert.equal('ip' in calls[0] && calls[0].ip, '', '默认不带搜索词')

  list.ipQuery.value = '  45.33  '
  await nextTick(); await flushMicrotasks()
  assert.equal(calls.length, 1, '防抖窗口内键击不立即发请求')
  await waitDebounce()
  assert.deepEqual(calls[1], { hidePermanent: true, ip: '45.33', page: 1, pageSize: 20 })
  assert.equal(list.records.value.length, 1)

  list.ipQuery.value = ''
  await waitDebounce()
  assert.equal(calls[2].ip, '', '清空搜索回到全量')
})

test('脏筛选重开只发一条请求（双发回归）；净筛选重开同样一条', async () => {
  const { calls, fetchPage } = makeFetch()
  const list = useRecidivismList(fetchPage)
  list.open()
  await flushMicrotasks()
  assert.equal(calls.length, 1, '首次 open 一条')

  // 脏筛选：改 hidePermanent + 搜索词 + 翻页，再 open 复位。
  list.hidePermanent.value = false
  list.ipQuery.value = '45.33'
  await waitDebounce()
  list.page.value = 3
  await nextTick(); await flushMicrotasks()
  const before = calls.length
  list.open()
  await nextTick(); await flushMicrotasks()
  await waitDebounce() // 防抖窗口收尾，确认无残留第二条
  assert.equal(calls.length - before, 1, '脏筛选重开只发一条（显式 fetch + watch 双发已修）')
  assert.deepEqual(calls[calls.length - 1], { hidePermanent: true, ip: '', page: 1, pageSize: 20 })

  // 净筛选重开（值未变）：watch 不触发，补一次显式 fetch。
  const before2 = calls.length
  list.open()
  await nextTick(); await flushMicrotasks()
  await waitDebounce()
  assert.equal(calls.length - before2, 1, '净筛选重开补一次显式 fetch')
})

test('IP 搜索连续键击防抖合并：窗口内多次输入只发末值一条', async () => {
  const { calls, fetchPage } = makeFetch()
  const list = useRecidivismList(fetchPage)
  list.open()
  await flushMicrotasks()
  const before = calls.length
  list.ipQuery.value = '4'
  await nextTick()
  list.ipQuery.value = '45'
  await nextTick()
  list.ipQuery.value = '45.33'
  await nextTick(); await flushMicrotasks()
  assert.equal(calls.length, before, '防抖窗口内零请求')
  await waitDebounce()
  assert.equal(calls.length - before, 1, '连续键击合并为末值一条')
  assert.equal(calls[calls.length - 1].ip, '45.33')
})

test('列表收缩页码越界自动回夹并重取（删末页末条/重置不留空页）', async () => {
  const { calls, fetchPage } = makeFetch([
    { records: [row('a')], total: 41 }, // open：3 页（20/页）
    { records: [row('b')], total: 41 }, // page=3
    { records: [], total: 20 },         // 取消/重置后收缩到 1 页
    { records: [row('c')], total: 20 }, // 回夹 page=1 重取
  ])
  const list = useRecidivismList(fetchPage)
  list.open()
  await flushMicrotasks()
  list.page.value = 3
  await nextTick(); await flushMicrotasks()
  assert.equal(list.page.value, 3)

  // 模拟单条取消/重置后的重取：响应 total 收缩 → maxPage=1 → page 回夹
  await list.fetchRecords()
  await waitForMicrotasks(() => list.page.value === 1, 'total 收缩后页码必须回夹到 1')
  await flushMicrotasks()
  assert.equal(calls.at(-1)?.page, 1, '回夹后必须按新页码重取')
  assert.equal(list.records.value[0]?.identity, 'c')
})

test('乱序响应作废：旧请求迟到不得覆盖新会话数据', async () => {
  const gates = [Promise.withResolvers<{ records: RecidivismRecord[]; total: number }>(), Promise.withResolvers<{ records: RecidivismRecord[]; total: number }>()]
  let i = 0
  const list = useRecidivismList(async () => gates[i++].promise)
  const a = list.fetchRecords()  // 请求 A（在途）
  const b = list.fetchRecords()  // 请求 B（在途，seq 更新）
  gates[0].resolve({ records: [row('stale')], total: 99 })
  gates[1].resolve({ records: [row('fresh')], total: 1 })
  await Promise.all([a, b])
  await flushMicrotasks()
  assert.equal(list.records.value[0]?.identity, 'fresh', '旧响应不得写回')
  assert.equal(list.total.value, 1)
})

test('invalidate（关闭）作废在途响应：迟到数据不写回', async () => {
  const gate = Promise.withResolvers<{ records: RecidivismRecord[]; total: number }>()
  const list = useRecidivismList(async () => gate.promise)
  list.open()
  list.invalidate()
  gate.resolve({ records: [row('late')], total: 7 })
  await flushMicrotasks()
  assert.equal(list.records.value.length, 0, '关闭后迟到响应必须作废')
  assert.equal(list.loading.value, false, '作废不得卡住 loading')
})

test('open 复位筛选：非默认 hidePermanent/ipQuery/page 回到默认并取数', async () => {
  const { calls, fetchPage } = makeFetch([
    { records: [], total: 9 },
    { records: [], total: 9 },
  ])
  const list = useRecidivismList(fetchPage)
  list.open()
  await flushMicrotasks()
  list.hidePermanent.value = false
  list.ipQuery.value = '1.2.3'
  list.page.value = 2
  await nextTick(); await flushMicrotasks()

  list.open()
  await flushMicrotasks()
  assert.equal(list.hidePermanent.value, true)
  assert.equal(list.ipQuery.value, '')
  assert.equal(list.page.value, 1)
  assert.deepEqual(calls.at(-1), { hidePermanent: true, ip: '', page: 1, pageSize: 20 })
})

test('取数失败：清空 records/total 并置 loadError；重试恢复', async () => {
  let fail = true
  const list = useRecidivismList(async () => {
    if (fail) throw new Error('network')
    return { records: [row('ok')], total: 1 }
  })
  list.open()
  await flushMicrotasks()
  assert.equal(list.loadError.value, true)
  assert.equal(list.records.value.length, 0)
  assert.equal(list.total.value, 0)
  assert.equal(list.loading.value, false)

  fail = false
  await list.fetchRecords()
  assert.equal(list.loadError.value, false)
  assert.equal(list.records.value.length, 1)
})
