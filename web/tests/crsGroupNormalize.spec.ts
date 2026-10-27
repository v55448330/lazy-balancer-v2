// CRS 规则组归一行为验收（安全策略编辑器打开即归一，归一结果随保存写回库）：
//   可识别形态折算成两位组号；不可识别形态（三字符组码 / 区间遗留 / 残留文本）
//   必须原样保留——丢弃会让一次保存静默裁短用户配置，整组清空时渲染语义还会
//   从「只评估指定组」变成「加载全部 CRS 规则」（WAF 评估面无声扩大）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { CRS_INFRA_GROUP_CODES, isInfraRuleId, normalizeCrsGroups } from '../src/utils/crsGroups.ts'

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
