import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code, section } from './_helpers.ts'

test('IP 快捷弹框：目标名单与下方名单同宽，空策略链接可导航', () => {
  const page = code('src/views/security/IPLocationAction.vue')
  assert.match(page, /\.ipm-target-panel \{ margin: 11px 0 3px;/, '目标名单不得再额外缩进 16px')
  assert.match(page, /@click\.prevent="goSecurityPolicies"/)
  assert.match(page, /const goSecurityPolicies = \(\): void =>/)
  assert.match(page, /authStore\.setCurrentPage\('security-policies'\)/)
  const empty = section(page, '.ipm-no-target {', '\n')
  assert.match(empty, /display: grid/)
  assert.match(page, /\.ipm-no-target a \{ display: inline-block; margin-left: 0;/)
})

test('IP 快捷弹框：展开引用策略时移除按钮固定首行，不随内容下移', () => {
  const page = code('src/views/security/IPLocationAction.vue')
  const source = section(page, '.ipm-source {', '}')
  assert.match(source, /align-items: flex-start/)
  assert.match(page, /\.ipm-source-actions \{ display: flex; flex: none; align-self: flex-start;/)
})
