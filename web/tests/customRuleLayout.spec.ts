import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code, section } from './_helpers.ts'

test('自定义规则条件行各列与首行输入对齐（匹配值列含说明文字时不悬空）', () => {
  const page = code('src/views/security/SecurityRules.vue')
  const row = section(page, '.rule-condition-row {', '}')
  assert.match(row, /align-items: flex-start/)
  const button = section(page, '.rule-condition-row .el-button--danger {', '}')
  assert.match(button, /align-self: flex-start/)
})
