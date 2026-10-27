// 规则启停的失败收尾：回滚本地开关后必须回读列表。
//
// 失败分两类，处理必须不同：
//   - 请求被拒（4xx / 用户取消确认框）：服务端状态未变，回滚本地开关即正确；
//   - 请求已生效但响应丢失（网关 5xx / 超时）：服务端已切换，只拨回本地开关会让
//     页面与服务端长期相反——规则列表没有轮询兜底，回读是唯一能收敛到服务端
//     事实的路径（与用户页启停失败同口径）。
//
// 真实前提：node --test 无 .vue 装载器（本套件禁止静态 import .vue），
// toggleRule 依赖组件内状态与请求层——用「限段 + 顺序」文本钉住收尾路径。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, member } from './_helpers.ts'

const RULES = 'src/views/Rules.vue'

test('失败分支：先回滚开关，再回读列表', () => {
  const text = code(RULES)
  const toggle = member(text, 'const toggleRule = async (rule: Rule) =>')
  const restore = toggle.indexOf('rule.enabled = !nextEnabled')
  const reread = toggle.indexOf('void fetchRules()')
  assert.ok(restore > 0, '失败必须回滚本地开关（否则界面显示未生效的切换）')
  assert.ok(reread > 0, '回滚后必须回读列表（响应丢失时服务端已切换，只拨开关会长期相反）')
  assert.ok(reread > restore, '回读排在回滚之后——与回滚后的本地状态对齐')
  // `void` 形态：回读失败由 fetchRules 内部收口，不得再次抛进 catch 分支
  assert.doesNotMatch(toggle, /await fetchRules\(\)\s*\n\s*rule\.enabled = !nextEnabled/, '回读不得早于回滚')
})

test('成功分支仍回读列表（服务端归一化后的状态以列表为准）', () => {
  const text = code(RULES)
  const toggle = member(text, 'const toggleRule = async (rule: Rule) =>')
  const success = toggle.slice(toggle.indexOf('mfaAwareSuccess'), toggle.indexOf('} catch'))
  assert.match(success, /await fetchRules\(\)/, '成功后回读列表（不得依赖「等待下次轮询同步」）')
  // 旧注释声称有轮询兜底——规则列表没有轮询，该承诺是错的
  assert.doesNotMatch(text, /等待下次轮询同步/, '规则列表没有轮询兜底，不得保留该承诺')
})

test('在途门与只读门仍在（双击不叠双请求）', () => {
  const text = code(RULES)
  const toggle = member(text, 'const toggleRule = async (rule: Rule) =>')
  assert.match(toggle, /if \(isReadOnly\.value\) return/)
  assert.match(toggle, /if \(ruleTogglePending\.value\[rule\.caddy_id\]\) return/, '在途守卫')
  assert.match(toggle, /ruleTogglePending\.value\[rule\.caddy_id\] = false/, 'finally 释放占位')
})
