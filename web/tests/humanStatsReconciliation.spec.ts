// 人机验证丢失对账 + CC 触发分布的 UI 消费接线：
//   /security/human/stats 透传 events_dropped/events_deliver_failed/
//   events_shutdown_lost（lbhuman/events.go 丢失对账三计数）与 cc_triggers
//   （rps_spike/4xx_ratio/session_anomaly 触发原因分布）。对账闭环不得止于
//   裸 API：丢失合计 >0 必须在 CC 卡片显性披露，触发分布按原因逐项展示。
//   后端字段名册跨栈钉（internal/handlers/human_stats.go JSON tag 逐字对齐）。
//
// 运行：cd web && node --test tests/humanStatsReconciliation.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code, member, repoCode, section } from './_helpers.ts'

const page = code('src/views/security/SecurityOverview.vue')

// 前后端逐字对表的字段名册（单源）：标题里的数量由长度派生，避免
// 「标题写 7、列表 10」这类覆盖声明失真。
const HUMAN_STATS_FIELDS = [
  'challenges', 'passes', 'fails', 'cc_triggers', 'rps_spike', '4xx_ratio',
  'session_anomaly', 'events_dropped', 'events_deliver_failed', 'events_shutdown_lost',
] as const

test(`取数类型与后端 JSON tag 名册逐字对齐（${HUMAN_STATS_FIELDS.length} 字段全量）`, () => {
  const fetch = member(page, 'const fetchHumanStats = async')
  // 三丢失计数 + cc_triggers 三原因 + 既有三计数：任一 tag 改名必红
  for (const tag of HUMAN_STATS_FIELDS) {
    assert.ok(fetch.includes(tag), `取数类型缺字段 ${tag}`)
  }
  const go = repoCode('internal/handlers/human_stats.go')
  for (const tag of HUMAN_STATS_FIELDS) {
    assert.ok(go.includes(`json:"${tag}"`), `后端 JSON tag 漂移: ${tag}`)
  }
})

test('丢失合计 >0 才披露警示行，三分类计数逐项可对账', () => {
  const lost = section(page, 'const humanEventsLost = computed', 'const fetchHumanStats = async')
  assert.match(lost, /events_dropped/, '队列满丢弃计数必须参与合计')
  assert.match(lost, /events_deliver_failed/, '投递失败计数必须参与合计')
  assert.match(lost, /events_shutdown_lost/, '停机丢失计数必须参与合计')
  const card = section(page, '<el-card shadow="always" class="cc-card">', '</el-card>')
  assert.match(card, /v-if="humanEventsLost > 0" class="info-note-bar"/, '丢失警示行按合计条件渲染（零丢失不打扰）')
  assert.match(card, /t\('app\.security\.overview\.cc\.eventsLost', \{ total: humanEventsLost, dropped: humanStats\.events_dropped, failed: humanStats\.events_deliver_failed, shutdown: humanStats\.events_shutdown_lost \}\)/, '警示文案必须携带合计与三分类实数')
})

test('CC 触发分布逐项展示（三原因计数 + 分布标题）', () => {
  const card = section(page, '<el-card shadow="always" class="cc-card">', '</el-card>')
  assert.match(card, /t\('app\.security\.overview\.cc\.triggerTitle'\)/, '触发分布必须有标题行')
  assert.match(card, /t\('app\.security\.overview\.cc\.triggerRps'\) \}\} \{\{ fmtStatNum\(humanStats\.cc_triggers\.rps_spike\) \}\}/, '突刺计数消费 rps_spike')
  assert.match(card, /t\('app\.security\.overview\.cc\.trigger4xx'\) \}\} \{\{ fmtStatNum\(humanStats\.cc_triggers\['4xx_ratio'\]\) \}\}/, '4xx激增计数消费 4xx_ratio')
  assert.match(card, /t\('app\.security\.overview\.cc\.triggerSession'\) \}\} \{\{ fmtStatNum\(humanStats\.cc_triggers\.session_anomaly\) \}\}/, '会话异常计数消费 session_anomaly')
})

test('词条 zh/en 成对且语义与后端归因词一致', () => {
  const zh = code('src/locales/zh/security.ts')
  const en = code('src/locales/en/security.ts')
  for (const key of ['eventsLost', 'triggerTitle', 'triggerRps', 'trigger4xx', 'triggerSession']) {
    assert.ok(zh.includes(`"${key}"`), `zh 缺词条 ${key}`)
    assert.ok(en.includes(`"${key}"`), `en 缺词条 ${key}`)
  }
  // 与后端 AutobanCCTriggerReasonLabel 归因词同语义（突刺/4xx激增/会话异常）
  assert.ok(zh.includes('"triggerRps": "突刺"'), '突刺词条与后端归因词一致')
  assert.ok(zh.includes('"trigger4xx": "4xx激增"'), '4xx激增词条与后端归因词一致')
  assert.ok(zh.includes('"triggerSession": "会话异常"'), '会话异常词条与后端归因词一致')
  const go = repoCode('internal/services/autoban.go')
  for (const word of ['突刺', '4xx激增', '会话异常']) {
    assert.ok(go.includes(`return "${word}"`), `后端归因词漂移: ${word}`)
  }
})
