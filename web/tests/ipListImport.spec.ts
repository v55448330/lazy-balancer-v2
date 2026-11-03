// 2026-11-02 交互重设计：选择文件只暂存，保存时判定——重复弹窗点名具体条目
// （以 IP 为准，同 IP 不同备注按首条为准），其余合并；非法行计入 invalidLines。
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { computeImportOutcome } from '../src/utils/ipListImport.ts'
import { parseIpListEntryLine } from '../src/utils/ipListCsv.ts'
import { isValidCidr } from '../src/utils/ipAddress.ts'

const parse = (text: string) => parseIpListEntryLine(text, isValidCidr)
const lines = (arr: string[]) => arr.map((t, i) => ({ no: i + 1, text: t }))

test('文件内重复：重复行计数并保留行号/原文，首条备注为准', () => {
  const outcome = computeImportOutcome(new Set(), lines([
    '39.99.222.100,小程序',
    '39.98.76.22,小程序',
    '39.99.222.100,华东-可用区B测试1',
    '39.98.76.22,华东-可用区B测试2',
    '10.0.0.1,唯一',
  ]), parse)
  assert.equal(outcome.newEntries.length, 3)
  assert.equal(outcome.duplicates.length, 2)
  assert.deepEqual(outcome.duplicates.map((d) => d.lineNo), [3, 4])
  assert.equal(outcome.duplicates[0].value, '39.99.222.100')
  assert.equal(outcome.duplicates[0].remark, '华东-可用区B测试1', '重复行保留该行自己的备注（弹窗展示原文）')
  assert.equal(outcome.invalidLines.length, 0)
  // 首条备注为准：新条目备注=首次出现的备注
  assert.equal(outcome.newEntries[0].remark, '小程序')
})

test('与现有列表重复：对照 existingValues 判重', () => {
  const outcome = computeImportOutcome(new Set(['1.1.1.1']), lines(['1.1.1.1,已存在', '2.2.2.2,新增']), parse)
  assert.equal(outcome.newEntries.length, 1)
  assert.equal(outcome.duplicates.length, 1)
  assert.equal(outcome.duplicates[0].value, '1.1.1.1')
})

test('非法行：解析失败计入 invalidLines，不中断后续行', () => {
  const outcome = computeImportOutcome(new Set(), lines(['not-an-ip,x', '3.3.3.3,ok', 'also-bad']), parse)
  assert.deepEqual(outcome.invalidLines, [1, 3])
  assert.equal(outcome.newEntries.length, 1)
})

test('备注超长：parse 返回 error 形态时计入 invalidLines', () => {
  const outcome = computeImportOutcome(new Set(), lines(['1.2.3.4,' + '长'.repeat(200)]), parse)
  assert.deepEqual(outcome.invalidLines, [1])
  assert.equal(outcome.newEntries.length, 0)
})

test('空文件：全部为空结果', () => {
  const outcome = computeImportOutcome(new Set(), [], parse)
  assert.equal(outcome.newEntries.length, 0)
  assert.equal(outcome.duplicates.length, 0)
  assert.equal(outcome.invalidLines.length, 0)
})
