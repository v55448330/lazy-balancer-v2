// CRS 规则组归一行为验收（安全策略编辑器打开即归一，归一结果随保存写回库）：
//   可识别形态折算成两位组号；不可识别形态（三字符组码 / 区间遗留 / 残留文本）
//   必须原样保留——丢弃会让一次保存静默裁短用户配置，整组清空时渲染语义还会
//   从「只评估指定组」变成「加载全部 CRS 规则」（WAF 评估面无声扩大）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { CRS_INFRA_GROUP_CODES, isInfraRuleId, normalizeCrsGroups } from '../src/utils/crsGroups.ts'
import { code } from './_helpers.ts'

// 纯函数绿 ≠ 视图还在调用它：本套件的行为用例全绿也不能排除「编辑器不再归一」。
// 接线面 = ①策略行比对用的 `crsGroups:`（两处）②编辑器列表的 `crsRuleGroups.value`
// 写入——三者都从后端字符串形态取值，去掉外层 normalizeCrsGroups 即红。
// 展示面同理：列表摘要与只读详情的「N 组」若按库值原样计数，历史文件名前缀、
// 重复值、系统基础组（01/49/59）都会把组数说大——同一策略在编辑器里显示 2 组、
// 在详情里显示 5 组，用户无从判断哪份是生效配置。
test('视图接线：策略行与编辑器列表的取数都经 normalizeCrsGroups 包裹', () => {
  const page = code('src/views/security/SecurityPolicies.vue')
  const policyRows = [...page.matchAll(/crsGroups: [^,\n]*crs_rule_groups[^,\n]*/g)].map((match) => match[0])
  assert.equal(policyRows.length, 2, `策略行取数点应为 2 处（实际 ${policyRows.length}）——增删须同步本断言`)
  for (const row of policyRows) {
    assert.match(row, /normalizeCrsGroups\(parseUnknownStrings\(p\.crs_rule_groups\)\)/, `策略行必须归一：${row}`)
  }
  assert.match(
    page,
    /crsRuleGroups\.value = normalizeCrsGroups\(parseIPList\(d\.crs_rule_groups\)\)/,
    '编辑器列表写回必须归一：漏掉即「打开即改写基线、保存把旧形态写回库」',
  )
})

// 与上一条同一口径的「计数」接线：展示面的组数必须与编辑器同源（归一后长度），
// 不得按库值原样计数——`REQUEST-942-*.conf`、重复值、01/49/59 会让详情把「全部」
// 说成「3 组」，与列表摘要/编辑器互相矛盾。
test('视图接线：列表摘要与只读详情的「N 组」计数同样经归一', () => {
  const page = code('src/views/security/SecurityPolicies.vue')
  const summary = page.match(/const crsCount = [^\n]*/)
  assert.ok(summary, '列表摘要的 CRS 计数行缺失（重命名须同步本断言）')
  assert.match(
    summary[0],
    /normalizeCrsGroups\(parseUnknownStrings\(row\.crs_rule_groups\)\)\.length/,
    `列表摘要计数必须归一：${summary[0]}`,
  )
  const detail = page.match(/const crsGroupCount = [^\n]*/)
  assert.ok(detail, '只读详情的 CRS 计数行缺失（重命名须同步本断言）')
  assert.match(
    detail[0],
    /normalizeCrsGroups\(parseIPList\(d\.crs_rule_groups\)\)\.length/,
    `只读详情计数必须归一：${detail[0]}`,
  )
})

test('两位组号原样保留，重复值去重且保持首次出现顺序', () => {
  assert.deepEqual(normalizeCrsGroups(['42', '93']), ['42', '93'])
  assert.deepEqual(normalizeCrsGroups(['93', '42', '93']), ['93', '42'])
})

test('历史文件名前缀折算成组号（REQUEST-9<code>-*.conf）', () => {
  assert.deepEqual(
    normalizeCrsGroups(['REQUEST-942-APPLICATION-ATTACK-SQLI.conf', 'RESPONSE-955-WEB-SHELLS.conf']),
    ['42', '55'],
  )
})

test('6 位规则 ID 原样保留，基础设施 ID（901/949/959）剥离', () => {
  assert.deepEqual(normalizeCrsGroups(['942100', '949000']), ['942100'])
  for (const id of ['901001', '949100', '959200']) assert.equal(isInfraRuleId(id), true)
})

test('系统基础组码（01/49/59）剥离——后端强制加载，不作为用户选择', () => {
  for (const code of CRS_INFRA_GROUP_CODES) assert.deepEqual(normalizeCrsGroups([code, '42']), ['42'])
})

test('不可识别形态原样保留：三字符组码 / 区间遗留 / 残留文本', () => {
  // 丢弃这些值 = 编辑器打开即改写基线，保存后策略静默少评估
  assert.deepEqual(normalizeCrsGroups(['942', '42']), ['942', '42'])
  assert.deepEqual(normalizeCrsGroups(['942100-942200']), ['942100-942200'])
  assert.deepEqual(normalizeCrsGroups(['legacy-group']), ['legacy-group'])
})

test('归一幂等：归一后再归一不得再改变取值（保存前后字节级一致）', () => {
  const inputs = [
    ['REQUEST-942-APPLICATION-ATTACK-SQLI.conf', '942', '942100-942200', '901', '42'],
    ['93', 'REQUEST-920-PROTOCOL-ENFORCEMENT.conf', 'legacy'],
  ]
  for (const input of inputs) {
    const once = normalizeCrsGroups(input)
    assert.deepEqual(normalizeCrsGroups(once), once, `非幂等：${input.join(',')}`)
  }
})

test('空集归空（渲染侧「留空=加载全部规则」语义保持不变）', () => {
  assert.deepEqual(normalizeCrsGroups([]), [])
  assert.deepEqual(normalizeCrsGroups(['01', '49', '59']), [])
})
