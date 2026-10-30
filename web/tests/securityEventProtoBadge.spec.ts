// 事件日志/详情弹框的协议口径（2026-10-31 用户二次裁定）：
//   ①事件列表方法列统一纯文本——TCP 事件显示「TCP」，HTTP 显示 GET/POST，
//     不加协议徽标（用户裁定：要加都加，要么都不加；取都不加）；
//   ②触发详情弹框与请求详情弹框显示规则协议类型（TCP/HTTP），
//     数据源 = event_type 既有字段；防御式：字段缺失不显示徽标。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, section } from './_helpers.ts'

const events = code('src/views/security/SecurityEvents.vue')
const trigger = code('src/components/events/TriggerDetailDialog.vue')

test('事件列表：规则列不再放 TCP 徽标', () => {
  const ruleColumn = section(events, 'label="规则"', 'label="触发阶段"')
  assert.doesNotMatch(ruleColumn, /proto-tcp-tag/, '规则列只剩规则名/链接')
  assert.match(ruleColumn, /AccessibleLink/, '规则名链接保持')
})

test('事件列表：方法列两协议统一 chip（span 定宽，翻页零重排）', () => {
  const methodColumn = section(events, 'label="方法"', 'label="URI"')
  assert.match(methodColumn, /row\.event_type === 'tcp'/)
  assert.match(methodColumn, /class="proto-tcp-tag event-method-tag method-chip">TCP<\/span>/)
  assert.match(methodColumn, /class="proto-http-tag event-method-tag method-chip">\{\{ row\.method \|\| '—' \}\}/)
  assert.doesNotMatch(methodColumn, /el-tag/, '不用 el-tag（翻页重排 bug 根源）')
})

test('触发详情弹框：命中概览显示协议徽标（TCP 青 / HTTP 蓝）', () => {
  assert.match(trigger, /row\?\.event_type === 'tcp'/)
  assert.match(trigger, /class="proto-tcp-tag trg-proto-tag">TCP<\/el-tag>/)
  assert.match(trigger, /v-else-if="row\?\.event_type"/, '防御式：event_type 缺失时不显示徽标')
  assert.match(trigger, /type="primary" effect="plain" class="trg-proto-tag">HTTP<\/el-tag>/)
})

test('请求详情弹框：触发规则行显示协议徽标（防御式）', () => {
  const item = section(events, 'label="触发规则"', '</el-descriptions-item>')
  assert.match(item, /ctxEvent\.event_type === 'tcp'/)
  assert.match(item, /proto-tcp-tag event-proto-tag">TCP<\/el-tag>/)
  assert.match(item, /v-else-if="ctxEvent\.event_type"/, 'event_type 缺失时不显示徽标')
})
