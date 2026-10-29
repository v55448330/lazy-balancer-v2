// requireData 契约守卫验收：200 缺 data 必须抛指定文案（由调用方 catch 显性
// 提示），有 data 时原样透传不复制对象。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { requireData } from '../src/utils/requireData.ts'

test('requireData: 200 缺 data 抛指定文案（契约违约不得静默）', () => {
  assert.throws(() => requireData(undefined, '响应异常，请重试'), /响应异常，请重试/)
  assert.throws(() => requireData(null, '响应异常，请重试'), /响应异常，请重试/)
})

test('requireData: 有 data 原样返回（含空对象/空数组等真值载荷）', () => {
  const payload = { recovery_codes: ['a', 'b'] }
  assert.equal(requireData(payload, '响应异常，请重试'), payload)
  assert.deepEqual(requireData({}, 'x'), {})
  assert.deepEqual(requireData([], 'x'), [])
})
