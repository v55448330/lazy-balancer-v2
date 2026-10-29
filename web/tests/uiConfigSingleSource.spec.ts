import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, member, section } from './_helpers.ts'
import { createLatestReadSession } from '../src/utils/viewAsyncState.ts'

// 设置/仪表盘配置面的「呈现与真实消费者一致」守卫：
// - 全局 DNS 提供商是无消费者的死配置（签发链按证书配置行读 provider），
//   不得继续呈现为可改并承诺「创建规则时默认使用」；
// - Dashboard 规则列表刷新失败但保留缓存时，必须明示「展示上次结果」；
// - OIDC 配置读取的回填必须只接受最新一轮请求（迟到的旧响应不得回滚表单）。

test('全局 DNS 提供商：表单入口、过度承诺文案与保存传播均已移除', () => {
  // 「不得回流」断言走剥注释视图：注释里写一句历史说明不得把用例改红。
  const page = code('src/views/settings/FreeCertificates.vue')
  assert.doesNotMatch(page, /v-model="global\.dns_provider"/, '死配置不得继续呈现为可改')
  assert.doesNotMatch(page, /创建规则时默认使用/, '文案不得承诺不存在的全局默认机制')
  const save = member(page, 'const handleSave = async')
  assert.doesNotMatch(save, /dns_provider: global\.value\.dns_provider/, '保存不得继续传播退役字段')
})

test('Dashboard 规则卡：刷新失败且有缓存时明示陈旧，首轮失败仍报「采集失败」', () => {
  const page = code('src/views/Dashboard.vue')
  assert.match(page, /<el-tag v-if="rulesUnavailable && rules\.length > 0"[^>]*>规则列表刷新失败：展示上次结果<\/el-tag>/)
  const card = section(page, 'class="rules-card"', '</el-card>')
  const badgeAt = card.indexOf('规则列表刷新失败')
  const tableAt = card.indexOf('<el-table')
  assert.ok(badgeAt > 0, '缺陈旧徽标')
  assert.ok(tableAt > badgeAt, '徽标必须在规则表之前的卡头，不能落到表尾')
  const empty = section(page, 'const rulesEmptyText', 'const hasRuleRequests')
  assert.match(empty, /采集失败/, '无缓存时（首轮失败）仍走采集失败空态')
})

test('OIDC 配置读取：乱序旧成功/失败都不得覆盖新表单或重复通知', async () => {
  for (const staleOutcome of ['success', 'failure'] as const) {
    const session = createLatestReadSession()
    const oldRequest = Promise.withResolvers<string>()
    const newRequest = Promise.withResolvers<string>()
    const state = { form: '', failed: false, notifications: 0 }
    const hooks = {
      onStart: () => {},
      onSuccess: (value: string) => { state.form = value; state.failed = false },
      onError: () => { state.form = ''; state.failed = true },
      onFinally: () => { state.notifications += 1 },
    }
    const stale = session.run(() => oldRequest.promise, hooks)
    const fresh = session.run(() => newRequest.promise, hooks)
    newRequest.resolve('new-form')
    await fresh
    assert.equal(state.form, 'new-form')
    if (staleOutcome === 'success') oldRequest.resolve('old-form')
    else oldRequest.reject(new Error('old failure'))
    await stale
    assert.deepEqual(state, { form: 'new-form', failed: false, notifications: 1 }, `旧${staleOutcome}不得改动新轮次`)
  }

  const page = code('src/views/settings/OIDCSettings.vue')
  const load = member(page, 'const load = async')
  assert.match(load, /await readSession\.run\(/, 'OIDC load 必须消费共享最新会话门')
  assert.match(load, /onSuccess: \(res\) =>/)
  assert.match(load, /onError: \(\) =>/)
  assert.match(load, /onFinally: notify/)
})
