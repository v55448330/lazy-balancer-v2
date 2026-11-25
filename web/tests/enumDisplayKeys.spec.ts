// 枚举稳定码的渲染契约（2026-11-25 裁定「后端只返回语言无关标识，界面文案由前端
// 词条渲染」）：
//   - 命中码 → 当前语言词条；
//   - 未登记码/缺失词条 → fail-visible：显示码本身（不静默返回空、不臆测文案）；
//   - 用户自定义内容（无码）→ 原样展示。
// 跨栈覆盖（后端全部码 ↔ zh/en 词条）由 Go 守卫
// internal/services/enum_display_keys_guard_test.go 钉住，此处钉运行期渲染行为。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { crsCategoryLabel } from '../src/utils/crsCategories.ts'
import { builtinBlockPageLabel } from '../src/utils/builtinBlockPages.ts'
import { tSafe as t } from '../src/i18n/tSafe.ts'

test('CRS 分类：稳定码按词条渲染', () => {
  assert.equal(crsCategoryLabel('ruleset.sqli'), 'SQL 注入')
  assert.equal(crsCategoryLabel('ruleset.genericAnomalies'), '通用异常')
  assert.equal(crsCategoryLabel('ruleset.methodRestrictions'), '方法限制')
  assert.equal(crsCategoryLabel('ruleset.other'), '其他')
})

test('CRS 分类：未知码与旧中文值 fail-visible 原样返回', () => {
  assert.equal(crsCategoryLabel('ruleset.notRegistered'), 'ruleset.notRegistered')
  // 旧契约（后端下发明文分类）不再是合法输入：不臆测词条，原样暴露
  assert.equal(crsCategoryLabel('方法限制'), '方法限制')
  assert.equal(crsCategoryLabel(''), '')
  assert.equal(crsCategoryLabel(undefined), '')
})

test('内置拦截页：name_key 按词条渲染名称与描述', () => {
  const queue = { id: 9007, name: '限流排队等待页', description: '中文库存描述', name_key: 'block_page.ratelimitQueue' }
  assert.equal(builtinBlockPageLabel(queue, 'name', t), '限流排队等待页')
  assert.equal(builtinBlockPageLabel(queue, 'desc', t), '系统内置限流排队等待页（含倒计时重试组件；CC 触发动作=排队时生效）')
  const slider = { id: 9005, name: '滑块人机验证页面', name_key: 'block_page.humanVerifySlider' }
  assert.equal(builtinBlockPageLabel(slider, 'name', t), '滑块人机验证页面')
})

test('内置拦截页：自定义页（无 name_key）原样展示用户内容', () => {
  const custom = { id: 12, name: '营业时间拦截', description: '自定义说明' }
  assert.equal(builtinBlockPageLabel(custom, 'name', t), '营业时间拦截')
  assert.equal(builtinBlockPageLabel(custom, 'desc', t), '自定义说明')
})

test('内置拦截页：未知码 fail-visible 原样返回码', () => {
  const unknown = { id: 9100, name: 'x', name_key: 'block_page.notRegistered' }
  assert.equal(builtinBlockPageLabel(unknown, 'name', t), 'block_page.notRegistered')
  const malformed = { id: 9101, name: 'x', name_key: 'ratelimitQueue' }
  assert.equal(builtinBlockPageLabel(malformed, 'name', t), 'ratelimitQueue')
})
