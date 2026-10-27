import { test } from 'node:test'
import assert from 'node:assert/strict'

import { customRuleEventDbID, triggerStageFamily } from '../src/utils/securityStages.ts'
import { code } from './_helpers.ts'

const page = code('src/views/security/SecurityRules.vue')
const trigger = code('src/components/events/TriggerDetailDialog.vue')

test('OR 分支触发 id 归自定义族并回解同一父规则', () => {
  for (const id of ['3642688', '3642689', '3642816', '67000064']) {
    assert.equal(triggerStageFamily(id), 'wafCustom', `id=${id}`)
  }
  assert.equal(customRuleEventDbID('10042'), 42)
  assert.equal(customRuleEventDbID('3642688'), 42)
  assert.equal(customRuleEventDbID('3642689'), 42)
  assert.equal(customRuleEventDbID('3642816'), 44)
  for (const id of ['10000', '800000', '1000001', '2000000', '3000000', 'abc']) {
    assert.ok(Number.isNaN(customRuleEventDbID(id)), `id=${id} 不得回解父规则`)
  }
})

test('旧版合成 OR 事件保留原始触发 id，不展示 NaN 或误报父规则删除', () => {
  assert.match(trigger, /customHasDbParent/)
  assert.match(trigger, /customDisplayID/)
  assert.match(trigger, /v-else-if="!loading && customHasDbParent"/)
  assert.match(trigger, /旧版合成规则/)
  assert.match(trigger, /自定义规则 id:\$\{customDisplayID\.value\}/)
})

test('自定义规则编辑器、列表与事件详情使用一致的条件关系口径', () => {
  assert.match(page, /condition_logic: 'and'/, '新建表单必须默认 AND')
  assert.match(page, /label="条件关系"/)
  assert.match(page, /同时满足（AND）/)
  assert.match(page, /任一满足（OR）/)
  assert.match(page, /v-model="ruleForm\.condition_logic"/)
  assert.match(page, /condition_logic: row\.condition_logic \?\? 'and'/, '编辑旧数据必须按 AND 读回')
  assert.match(page, /row\.condition_logic === 'or' \? '任一满足（OR）' : '同时满足（AND）'/, '列表须展示同一口径')

  assert.match(trigger, /customRuleEventDbID/, '事件详情必须支持 OR 分支 id 回解')
  assert.match(trigger, /customRule\.condition_logic === 'or' \? '任一满足（OR）' : '同时满足（AND）'/, '事件详情须展示同一条件关系')
})
