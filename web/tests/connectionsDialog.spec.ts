// 连接监控弹框的视图口径契约：
//   1. 请求视图（lb_reqmon 逐请求）与连接视图（netstat socket）各自的筛选键
//      文案不得串用——请求行分类是窗口区间（active≤1min / closing≤10min /
//      closed≤1h），贴连接态词条（活跃/待关闭/已关闭）会把窗口说成 socket 状态。
//   2. 请求明细触达 500 行展示上限时，总数/分类计数都是封顶值：必须显式写
//      「500+」+ 口径说明，而不是把 500 当窗口总请求数。
//   3. 取数失败不得静默：失败态要上屏（带上次数据时间）+ 可重试。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  REQUEST_VIEW_MAX_ROWS,
  connectionFilterCategories,
  filterRows,
  requestFilterCategories,
  totalRequestsText,
} from '../src/utils/connectionsView.ts'
import { i18n } from '../src/i18n/index.ts'
import { code } from './_helpers.ts'

type LocaleTree = { [key: string]: unknown }

const leaf = (node: unknown, path: string): unknown =>
  path.split('.').reduce<unknown>((acc, key) => (typeof acc === 'object' && acc !== null ? (acc as LocaleTree)[key] : undefined), node)

// 词条回显式 t：把「用了哪个键」变成可断言的返回值。
const echoT = (key: string): string => key

test('请求视图筛选键用窗口区间词条，不套用连接态词条', () => {
  const cats = requestFilterCategories(echoT)
  assert.deepEqual(
    cats.map((c) => c.label),
    [
      'app.dashboard.connCatReqActive',
      'app.dashboard.connCatReqClosing',
      'app.dashboard.connCatReqClosed',
      'app.dashboard.connFilter5xx',
      'app.dashboard.connCatAll',
    ],
  )
  assert.deepEqual(cats.map((c) => c.key), ['active', 'closing', 'closed', '5xx', 'all'])
  // 连接态词条（活跃/待关闭/已关闭）不得出现在请求视图的筛选键里
  for (const connectionOnly of ['app.dashboard.connCatEstablished', 'app.dashboard.connCatTimeWait', 'app.dashboard.connCatClosed']) {
    assert.ok(!cats.some((c) => c.label === connectionOnly), `请求视图误用连接态词条 ${connectionOnly}`)
  }
})

test('连接视图筛选键保留 socket 状态族词条，不含请求窗口/5xx 键', () => {
  const cats = connectionFilterCategories(echoT)
  assert.deepEqual(
    cats.map((c) => c.label),
    ['app.dashboard.connCatEstablished', 'app.dashboard.connCatTimeWait', 'app.dashboard.connCatClosed', 'app.dashboard.connCatAll'],
  )
  assert.ok(!cats.some((c) => c.key === '5xx'), '连接视图无状态码维度，不得出现 5xx 筛选')
})

test('筛选：5xx 只看状态码 ≥500，连接视图 socket 状态族映射到筛选键', () => {
  const requests = [
    { category: 'active', status: 200 },
    { category: 'active', status: 503 },
    { category: 'closed', status: 500 },
  ]
  assert.deepEqual(filterRows(requests, '5xx'), [requests[1], requests[2]])
  assert.deepEqual(filterRows(requests, 'active'), [requests[0], requests[1]])
  assert.equal(filterRows(requests, 'all').length, 3)

  const connections = [
    { category: 'established' },
    { category: 'time_wait' },
    { category: 'closed' },
  ]
  assert.deepEqual(filterRows(connections, 'active'), [connections[0]])
  assert.deepEqual(filterRows(connections, 'closing'), [connections[1]])
  assert.deepEqual(filterRows(connections, 'closed'), [connections[2]])
})

test('总请求数触达展示上限写「500+」，未触达写准确值', () => {
  assert.equal(REQUEST_VIEW_MAX_ROWS, 500)
  assert.equal(totalRequestsText(500, true), '500+')
  assert.equal(totalRequestsText(123, false), '123')
  assert.equal(totalRequestsText(50, true, 50), '50+')
})

test('ConnectionsDialog 消费视图口径单源与截断披露字段', () => {
  const page = code('src/components/ConnectionsDialog.vue')
  assert.match(page, /from '@\/utils\/connectionsView\.ts'/, '筛选/文案差异必须走 connectionsView 单源')
  for (const helper of ['requestFilterCategories', 'connectionFilterCategories', 'filterRows', 'totalRequestsText']) {
    assert.match(page, new RegExp(`\\b${helper}\\b`), `必须消费 ${helper}`)
  }
  assert.match(page, /requests_truncated/, '必须读后端 requests_truncated 披露字段')
  assert.match(page, /requestsTruncated/, '截断标志必须落到本地状态')
  assert.match(page, /REQ_ROWS|REQUEST_VIEW_MAX_ROWS/, '封顶值必须与后端同源常量（不得硬编码 500 于模板）')
})

test('ConnectionsDialog 取数失败上屏并可重试（不再静默吞掉）', () => {
  const page = code('src/components/ConnectionsDialog.vue')
  assert.match(page, /usePollingErrorState/, '复用既有轮询失败态单源')
  assert.match(page, /loadError\.recordError\(/, 'catch 必须记录失败态')
  assert.match(page, /loadError\.clear\(\)/, '成功必须清除失败态')
  assert.match(page, /roundSignal\?\.aborted/, '轮次取消（abort）不得计为取数失败')
  const template = code('src/components/ConnectionsDialog.vue')
  assert.match(template, /polling-error-alert error-banner/, '失败态用站内错误横幅标准类')
  assert.match(template, /app\.dashboard\.connLoadFailPrefix/, '失败横幅标题走词条')
  assert.match(template, /app\.dashboard\.retryNow/, '失败横幅带重试按钮（复用站内重试词条）')
})

test('ConnectionsDialog 域名 chip title 含 5xx、空态分视图、截断口径上屏', () => {
  const template = code('src/components/ConnectionsDialog.vue')
  assert.match(template, /connDomainTip', \{ requests: [^}]*s5xx:/, 'chip title 必须披露 5xx 计数')
  assert.match(template, /app\.dashboard\.connEmptyReq/, '请求视图空态用请求语义词条')
  assert.match(template, /app\.dashboard\.connReqTruncatedNote/, '请求封顶必须上屏口径说明')
  assert.match(template, /app\.dashboard\.connTotalConn/, '连接视图第四卡不得沿用「总请求」标签')
})

test('新增连接监控词条在 zh/en 双侧齐备（键集 parity 之外的落地检查）', () => {
  const messages = i18n.global.messages.value as Record<string, { app?: LocaleTree }>
  const keys = [
    'dashboard.connCatReqActive',
    'dashboard.connCatReqClosing',
    'dashboard.connCatReqClosed',
    'dashboard.connFilter5xx',
    'dashboard.connTotalConn',
    'dashboard.connEmptyReq',
    'dashboard.connColWindow',
    'dashboard.connReqTruncatedNote',
    'dashboard.connTruncatedNote',
    'dashboard.connLoadFailPrefix',
    'dashboard.connLoadFailMeta',
  ]
  for (const locale of ['zh-CN', 'en']) {
    const tree = messages[locale]?.app
    assert.ok(tree, `${locale} app 树缺失`)
    for (const key of keys) {
      const value = leaf(tree, key)
      assert.equal(typeof value, 'string', `${locale} 缺词条 app.${key}`)
      assert.ok((value as string).length > 0, `${locale} 词条 app.${key} 为空`)
    }
  }
})
