// 安全策略行级「绑定规则」的数据就绪门。
//
// 编辑器语义是「整集替换/全量重置」：以加载中/失败时的旧快照（或空快照）打开，
// 会按错误的 delta 提交——界面提示更新成功，实际未被看到的既有绑定仍保留。
// 规则页同名入口早有同门（Rules.vue openBindDialog），策略页必须同源。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, matchBrace, section } from './_helpers.ts'

const page = code('src/views/security/SecurityPolicies.vue')

test('绑定数据门三态就绪：加载中 / 已失败 / 打开中 各自可见', () => {
  assert.match(page, /const securityBindingsLoading = ref\(true\)/)
  assert.match(page, /const securityBindingsFailed = ref\(false\)/)
  assert.match(page, /const bindRulesOpening = ref\(false\)/)
})

test('列表加载全过程置位并释放就绪门', () => {
  const fetchData = section(page, 'const fetchData = async', 'const parseCustomRuleIds')
  assert.match(fetchData, /securityBindingsLoading\.value = true/)
  assert.match(fetchData, /securityBindingsLoading\.value = false/, 'finally 必须释放，否则入口永久禁用')
  assert.match(fetchData, /securityBindingsFailed\.value = true/, '辅助端点失败必须留痕')
  assert.match(fetchData, /securityBindingsFailed\.value = false/, '成功回落必须清错误态')
})

test('行级按钮与打开函数双门（按钮只是呈现层）', () => {
  assert.match(page, /:disabled="securityBindingsLoading \|\| securityBindingsFailed \|\| bindRulesOpening"/)
  const open = section(page, 'const openBindRulesDialog = async', 'const onBindRulesSaved')
  assert.match(open, /if \(securityBindingsLoading\.value \|\| securityBindingsFailed\.value \|\| bindRulesOpening\.value\) \{/)
  assert.match(open, /ElMessage\.warning\(/)
  assert.match(open, /规则绑定数据加载失败，请先点击上方「重新加载」/)
})

test('打开前重取快照，失败则不打开（旧快照的 delta 不等于当前绑定集）', () => {
  const open = section(page, 'const openBindRulesDialog = async', 'const onBindRulesSaved')
  const refreshAt = open.indexOf('await refreshBindingsSnapshot()')
  const visibleAt = open.indexOf('bindRulesVisible.value = true')
  assert.ok(refreshAt > 0, '必须打开前刷新一次快照')
  assert.ok(visibleAt > refreshAt, '刷新成功后才可打开')
  assert.match(open, /ElMessage\.error\('规则绑定数据刷新失败，已取消打开；请稍后重试'\)/)
  // 就绪门的释放必须落在 finally 段内：仅做存在性匹配时，把
  // `bindRulesOpening.value = false` 挪到 try 成功路径（失败/提前 return 时门
  // 永久关闭）或干脆删掉 finally 都照样命中同名片段。按「try 段 → finally 段」
  // 的花括号配对取段后分别断言。
  const tryAt = open.indexOf(' try {')
  assert.ok(tryAt > 0, '打开函数必须有 try 段')
  const tryOpen = open.indexOf('{', tryAt)
  const tryClose = matchBrace(open, tryOpen)
  assert.ok(tryClose > tryOpen, 'try 段括号必须闭合')
  const successPath = open.slice(tryOpen, tryClose + 1)
  assert.doesNotMatch(successPath, /bindRulesOpening\.value = false/, '释放不得写在 try 成功路径（失败/提前 return 时门永久禁用）')
  const finallyAt = open.indexOf(' finally {', tryClose)
  assert.ok(finallyAt > tryClose, '必须有 finally 段并被释放（否则入口永久禁用）')
  const finallyOpen = open.indexOf('{', finallyAt)
  const finallyClose = matchBrace(open, finallyOpen)
  assert.ok(finallyClose > finallyOpen, 'finally 段括号必须闭合')
  assert.match(open.slice(finallyOpen, finallyClose + 1), /bindRulesOpening\.value = false/, 'finally 必须释放就绪门')

  const refresh = section(page, 'const refreshBindingsSnapshot = async', 'const openBindRulesDialog = async')
  assert.match(refresh, /request\.get<APIResponse<Record<string, BindingInfo\[\]>>>\('\/security\/bindings'\)/)
  assert.match(refresh, /securityBindings\.value = res\.data \|\| \{\}/)
  assert.match(refresh, /securityBindingsFailed\.value = false/)
  assert.match(refresh, /catch \{\s*securityBindingsFailed\.value = true\s*return false/)
})
