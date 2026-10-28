// 安全规则/名单的写侧门与前端单源对表：
//   A. 自定义规则条件数 64 / pattern 4KiB（UTF-8 字节）——前端两值必须与 Go 常量同值
//   B. 名单详情失败态：保存与条目增删/导入同门；重试覆盖前须确认未保存条目
//   C. 内置自动封禁名单全量 PUT 前的最终复核（并发新增条目并回载荷，不静默解封）
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  CUSTOM_RULE_MAX_CONDITIONS,
  CUSTOM_RULE_MAX_PATTERN_BYTES,
  canAddCondition,
  patternByteLength,
  patternOverLimit,
} from '../src/utils/customRuleLimits.ts'
import { mergeConcurrentBanEntries } from '../src/utils/ipListSaveGuard.ts'
import { code, openTags, repoCode, section } from './_helpers.ts'

const securityGo = repoCode('internal/services/security.go')
const page = code('src/views/security/SecurityRules.vue')

test('条件数/pattern 上限与 Go 写侧门同值（改门即红）', () => {
  const conditions = /customRuleMaxConditions = (\d+)/.exec(securityGo)
  assert.ok(conditions, '后端缺 customRuleMaxConditions')
  assert.equal(CUSTOM_RULE_MAX_CONDITIONS, Number(conditions[1]), '条件数上限漂移')

  const patternBytes = /customRuleMaxPatternBytes = (\d+) << (\d+)/.exec(securityGo)
  assert.ok(patternBytes, '后端缺 customRuleMaxPatternBytes')
  assert.equal(CUSTOM_RULE_MAX_PATTERN_BYTES, Number(patternBytes[1]) * 2 ** Number(patternBytes[2]), 'pattern 字节上限漂移')
})

test('pattern 上限按 UTF-8 字节求值（字符计数看不出中文超限）', () => {
  assert.equal(patternByteLength('abc'), 3)
  assert.equal(patternByteLength('中'), 3, '中日韩字符 3 字节')
  assert.equal(patternByteLength(''), 0)

  assert.equal(patternOverLimit('a'.repeat(CUSTOM_RULE_MAX_PATTERN_BYTES)), false, '恰好到上限放行')
  assert.equal(patternOverLimit('a'.repeat(CUSTOM_RULE_MAX_PATTERN_BYTES + 1)), true)
  // 字符数远小于上限、字节数超限：只有字节口径能拦住
  const cjk = '中'.repeat(Math.ceil(CUSTOM_RULE_MAX_PATTERN_BYTES / 3) + 1)
  assert.ok(cjk.length < CUSTOM_RULE_MAX_PATTERN_BYTES, '前提：字符数没超')
  assert.equal(patternOverLimit(cjk), true, '字节超限必须拦截')

  assert.equal(canAddCondition(CUSTOM_RULE_MAX_CONDITIONS - 1), true)
  assert.equal(canAddCondition(CUSTOM_RULE_MAX_CONDITIONS), false, '满额后不得再加')
})

test('自定义规则弹框消费同一上限（加条件按钮/字段级字节提示/保存前拦截）', () => {
  assert.match(page, /import \{ CUSTOM_RULE_MAX_CONDITIONS, CUSTOM_RULE_MAX_PATTERN_BYTES, canAddCondition, patternByteLength, patternOverLimit \} from '@\/utils\/customRuleLimits'/)
  assert.match(page, /:disabled="!canAddCondition\(ruleForm\.conditions\.length\) \|\| savingRule"/, '满额/保存中必须禁用「+ 添加条件」')
  assert.match(page, /\{\{ ruleForm\.conditions\.length \}\}\/\{\{ CUSTOM_RULE_MAX_CONDITIONS \}\}/, '条件行数须可见')
  const patternRow = section(page, 'class="pattern-col"', 'cond.target === \'user_agent\'')
  assert.match(patternRow, /patternOverLimit\(cond\.pattern\)/, '字段级字节提示与红框同谓词')

  const save = section(page, 'const saveCustomRule = async', 'const deletingCustomRuleId')
  const countGate = save.indexOf('ruleForm.value.conditions.length > CUSTOM_RULE_MAX_CONDITIONS')
  const loop = save.indexOf('for (const cond of ruleForm.value.conditions)')
  assert.ok(countGate > 0 && countGate < loop, '条件数门必须先于逐条校验')
  assert.match(save, /if \(patternOverLimit\(cond\.pattern\)\) \{/, '保存前必须有字节门（后端 400 前置）')
})

test('名单详情失败态与保存同门：条目录入/导入一并禁用', () => {
  for (const action of ['addIpListEntry', 'triggerImportEntries']) {
    assert.ok(
      openTags(page, 'el-button').some((tag) => tag.includes(':disabled="ipListDetailFailed || savingIpList"') && tag.includes(`@click="${action}"`)),
      `${action} 在失败态/保存中必须禁用（属性顺序无关）`,
    )
  }
  assert.match(page, /保存与条目增删\/导入已禁用/, '横幅必须说明禁用范围')
})

test('名单重试覆盖前确认未保存条目，成功后提示已加载', () => {
  const reload = section(page, 'const reloadIpListDetail = async', 'const saveIpList = async')
  const confirm = reload.indexOf('重新加载将用服务端条目覆盖当前')
  const assign = reload.indexOf('ipListForm.value.entries = (res.data?.entries')
  assert.ok(confirm > 0 && assign > confirm, '覆盖前必须确认（含未保存条目）')
  assert.match(reload, /ElMessage\.success\('已加载最新条目'\)/)
})

test('自动封禁名单新鲜度差集经公开合并入口生效（归一/去重）', () => {
  const entries = (values: readonly string[]) => values.map((value) => ({ value }))
  assert.deepEqual(
    mergeConcurrentBanEntries(entries(['1.1.1.1', '2.2.2.2', '3.3.3.3']), entries([' 1.1.1.1 ', '3.3.3.3']), []).preserved,
    ['2.2.2.2'],
  )
  assert.deepEqual(mergeConcurrentBanEntries(entries(['::1']), [], []).preserved, ['::1'])
  assert.deepEqual(mergeConcurrentBanEntries(entries(['1.1.1.1', '1.1.1.1']), [], []).preserved, ['1.1.1.1'], '重复值只并回一次')
  assert.deepEqual(mergeConcurrentBanEntries(entries(['1.1.1.1']), entries(['1.1.1.1', '9.9.9.9']), []).preserved, [], '载荷已含服务端条目时不并回')
})

test('自动封禁名单最终复核：并发新增并回载荷，主动删除仍生效', () => {
  // 打开快照里没有 → 任务并发新增：并回载荷（不得被整表替换解封）
  const concurrent = mergeConcurrentBanEntries(
    [{ value: '1.1.1.1', remark: '既有' }, { value: '2.2.2.2', remark: '任务' }, { value: '9.9.9.9', remark: '任务' }],
    [{ value: ' 1.1.1.1 ', remark: '既有' }],
    ['1.1.1.1'],
  )
  assert.deepEqual(concurrent.preserved, ['2.2.2.2', '9.9.9.9'])
  assert.deepEqual(concurrent.entries.map((e) => e.value), [' 1.1.1.1 ', '2.2.2.2', '9.9.9.9'])
  // 打开时就存在、用户主动删除 → 不并回（手动解封按用户意图）
  assert.deepEqual(mergeConcurrentBanEntries([{ value: '1.1.1.1' }], [], ['1.1.1.1']).preserved, [])
  // 服务端重复值只并一条；载荷已含（归一后相同）不重复并
  assert.deepEqual(mergeConcurrentBanEntries([{ value: 'FE80::1' }, { value: 'fe80::1' }], [], []).preserved, ['FE80::1'])
  assert.deepEqual(mergeConcurrentBanEntries([{ value: '1.1.1.1' }], [{ value: ' 1.1.1.1' }], []).preserved, [])

  // 接线：复核落在最后一次确认之后、PUT 紧前（确认框停留期新增同样会被解封）
  const save = section(page, 'const saveIpList = async', 'const deletingIpListId')
  const confirmAt = save.indexOf('确定${action} IP 地址列表')
  const verifyAt = save.indexOf('mergeFreshAutobanEntries(editingIpListId.value, entries)')
  const putAt = save.indexOf('await request.put(`/security/ip-lists/')
  assert.ok(confirmAt > 0, '通用确认必须存在')
  assert.ok(verifyAt > confirmAt, '最终复核必须在最后确认之后')
  assert.ok(putAt > verifyAt, '复核必须紧邻 PUT（其间不得有用户确认）')
  assert.match(save, /if \(merged === null\) return/, '无法核对必须中止保存')
  assert.match(save, /JSON\.stringify\(payloadEntries\)/, '提交的必须是并回后的载荷')
  assert.doesNotMatch(save, /confirmAutobanFreshness/, '旧的前置差集不得残留')
  const helper = section(page, 'const mergeFreshAutobanEntries', 'const saveIpList = async')
  assert.match(helper, /mergeConcurrentBanEntries\(serverEntries, entries, ipListOpenSnapshot\.value\)/)
  assert.match(helper, /无法核对最新封禁条目，已中止保存/, '核对失败要显性点名后果')
  assert.match(page, /ipListOpenSnapshot\.value = ipListForm\.value\.entries\.map\(\(e\) => e\.value\)/, '详情落地必须记录打开快照')
})
