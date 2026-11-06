// 退役类样式反向清单钉：重构删除标记类时必须连样式一起退役——
// 「删标记留样式」是本仓反复出现的死 CSS 复发形态。本钉为负向清单：
// 类名再入任何源码（模板或样式块）即红；仍在用的容器/同前缀活类正向钉住，
// 防止清理时连带误删。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code } from './_helpers.ts'

test('SecurityRules 退役类零残留（ip-match-result 族、ip2region-source-* 子行族）', () => {
  const page = code('src/views/security/SecurityRules.vue')
  assert.doesNotMatch(page, /ip-match-result/, '查询行内结果文案退役后样式必须一并退役（含 -none 变体）')
  assert.doesNotMatch(page, /ip2region-source-(row|name|ver|msg)/, '子行标记迁出后其样式必须一并退役（含 --off 变体）')
  // 活类正向钉：容器类仍被弹框信息条使用，不得被连带删除。
  assert.match(page, /class="dialog-panel ip2region-sources"/)
  assert.match(page, /\.ip2region-sources \{/)
})

test('SecurityOverview 旧网格布局类零残留（stat-row/stat-col/lib-stat-row）', () => {
  const page = code('src/views/security/SecurityOverview.vue')
  assert.doesNotMatch(page, /\b(?:lib-)?stat-(?:row|col)\b/, 'KPI 状态条重设计后旧网格布局样式必须一并退役')
  // 活类正向钉：状态条现体系类仍在用。
  assert.match(page, /\.status-strip \{/)
})

test('SecurityPolicies 成功色排位变体零残留（rule-binding-landing--trust）', () => {
  const page = code('src/views/security/SecurityPolicies.vue')
  // 排位提示统一灰字基类（阶段 0 不渲染排位行）——成功色变体无模板消费方，
  // 类名再入（模板或样式块）即红。
  assert.doesNotMatch(page, /rule-binding-landing--trust/, '成功色变体退役后样式必须一并退役')
  // 活类正向钉：基类排位提示仍在模板与样式两侧使用，清理时不得连带删除。
  assert.match(page, /class="rule-binding-landing"/)
  assert.match(page, /\.rule-binding-landing \{/)
})

test('main.css 圆角重置组无 tm-detail-desc 退役片段（tm-log-container 仍在组内）', () => {
  const css = code('src/styles/main.css')
  // 单数片段已退役（TaskMonitor 实际类名为复数 tm-detail-descs，自有 scoped 样式）。
  assert.doesNotMatch(css, /tm-detail-desc/)
  // 同组成员正向钉：删退役片段不得破坏 :is() 选择器组。
  assert.match(css, /\.tm-log-container/)
})
