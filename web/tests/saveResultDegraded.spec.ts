// 退化 200 的语言无关判定：showSaveResult 首选 messageKey=k_de8cc6aa（en
// 文案无 zh 标记也必须常驻警告），zh 标记仅作无键旧响应兜底；普通成功走
// mfaAwareSuccess；退化 key + 空 message 时回落文案仍按退化呈现（不静默）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { STUB_SAVE_RESULT_DEPS, calls, resetCalls } from './_stubs.ts'
import { registerModuleHooks } from './_helpers.ts'
const host = globalThis as unknown as { __calls: unknown[] }
host.__calls = calls
registerModuleHooks({ 'element-plus': STUB_SAVE_RESULT_DEPS, '@/utils/api': STUB_SAVE_RESULT_DEPS })
// 模块钩子须先于被测模块加载；静态 import 会在替身安装前执行依赖。
const { showSaveResult } = await import('../src/utils/saveResult.ts')
const { CADDY_APPLY_FAILED_MARKER } = await import('../src/utils/bulkApplyResult.ts')
test('en 退化 200（messageKey 判定）：无 zh 标记也必须常驻警告', () => {
  resetCalls()
  const message = 'Policy saved; but Caddy config apply failed: reload timeout'
  showSaveResult({ message, messageKey: 'k_de8cc6aa' }, 'Saved')
  assert.deepEqual(calls, [{ fn: 'ElMessage', arg: { type: 'warning', message, duration: 0, showClose: true } }])
})
test('zh 标记兜底（无 messageKey 的旧响应）：仍走常驻警告', () => {
  resetCalls()
  const message = `已保存；但${CADDY_APPLY_FAILED_MARKER}：reload 超时`
  showSaveResult({ message }, '保存成功')
  assert.deepEqual(calls, [{ fn: 'ElMessage', arg: { type: 'warning', message, duration: 0, showClose: true } }])
})
test('普通成功（en 文案 + 非退化 key）走 mfaAwareSuccess', () => {
  resetCalls()
  showSaveResult({ message: 'Saved', messageKey: 'k_other' }, 'Saved')
  assert.deepEqual(calls, [{ fn: 'mfaAwareSuccess', arg: 'Saved' }])
})
test('退化 key + 空 message：回落文案仍按退化呈现（不静默）', () => {
  resetCalls()
  showSaveResult({ messageKey: 'k_de8cc6aa' }, 'Saved')
  assert.deepEqual(calls, [{ fn: 'ElMessage', arg: { type: 'warning', message: 'Saved', duration: 0, showClose: true } }])
})
