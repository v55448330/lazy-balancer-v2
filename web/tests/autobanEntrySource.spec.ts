import test from 'node:test'
import assert from 'node:assert/strict'
import { isAutomaticBanEntry } from '../src/utils/autobanEntry.ts'
import { repoCode } from './_helpers.ts'

test('封禁来源以服务端 automatic 来源位为唯一判据', () => {
  assert.equal(isAutomaticBanEntry({ automatic: true, remark: '突刺' }), true)
  assert.equal(isAutomaticBanEntry({ automatic: true, remark: '累犯·人机验证失败' }), true)
  // 备注字面量不再参与判定：备注写着「自动封禁」但来源位为手动 → 手动
  assert.equal(isAutomaticBanEntry({ automatic: false, remark: '自动封禁' }), false)
  // 来源位缺失（非封禁名单/旧响应）按手动处理，不得抛错
  assert.equal(isAutomaticBanEntry({ value: '198.51.100.9' }), false)
  assert.equal(isAutomaticBanEntry(undefined), false)
})

test('来源位与后端判据单源逐字对齐（跨栈钉）', () => {
  const go = repoCode('internal/handlers/securityiplists.go')
  assert.ok(go.includes('"automatic"'), '名单详情不再输出 automatic 来源位——封禁来源列将恒为手动')
  assert.ok(go.includes('AutobanEntryIsAutomatic('), '来源位必须由 autobanEntryIsAutomatic 单源派生')
})
