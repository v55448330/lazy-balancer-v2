import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code, section } from './_helpers.ts'

test('自定义规则条件行的删除按钮与输入框垂直居中', () => {
  const page = code('src/views/security/SecurityRules.vue')
  const row = section(page, '.rule-condition-row {', '}')
  assert.match(row, /align-items: center/)
  const button = section(page, '.rule-condition-row .el-button--danger {', '}')
  assert.match(button, /align-self: center/)
})
