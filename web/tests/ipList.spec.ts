// IP 名单弹框守卫与 CSV 往返验收（第 78 轮 U16-F01 / U16-F18）：
//   A. 详情在途/失败时保存必须禁用（否则空 entries 全量 PUT 清空名单）
//   B. 已有名单 + 空条目需二次确认；新建空名单不弹
//   C. 导出→导入逐字相等，二次往返不累积漂移（备注含逗号/引号/换行）
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { canSaveIpList, needsEmptyListConfirm } from '../src/utils/ipListSaveGuard.ts'
import { formatIpListEntryLine, parseIpListEntryLine } from '../src/utils/ipListCsv.ts'
import {
  ensureSharedEntries,
  invalidateSharedEntriesCache,
  sharedEntriesCache,
  writeSharedEntries,
} from '../src/utils/securityStages.ts'

const isIp = (value: string): boolean => /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(value)

test('A 保存守卫：加载中/失败两种形态均禁止保存', () => {
  assert.equal(canSaveIpList(false, false), true)
  assert.equal(canSaveIpList(true, false), false, '详情在途：entries 为空，禁止保存')
  assert.equal(canSaveIpList(false, true), false, '详情失败：必须禁止保存')
  assert.equal(canSaveIpList(true, true), false)
})

test('B 空条目确认：仅已有名单触发（新建空名单是合法操作）', () => {
  assert.equal(needsEmptyListConfirm(12, 0), true)
  assert.equal(needsEmptyListConfirm(12, 3), false)
  assert.equal(needsEmptyListConfirm(null, 0), false)
})

test('C1 CSV 往返：备注含逗号/引号逐字相等', () => {
  const value = '10.0.0.1'
  const remark = '备注,含逗号"和引号"'
  const line = formatIpListEntryLine(value, remark)
  assert.equal(line, '10.0.0.1,"备注,含逗号""和引号"""')
  assert.deepEqual(parseIpListEntryLine(line, isIp), { value, remark })
})

test('C2 二次往返不累积漂移', () => {
  let remark = 'a,"b",c'
  let line = formatIpListEntryLine('192.168.1.0/24', remark)
  for (let i = 0; i < 3; i++) {
    const parsed = parseIpListEntryLine(line, isIp)
    assert.ok(parsed)
    assert.equal(parsed.remark, remark)
    line = formatIpListEntryLine(parsed.value, parsed.remark)
  }
})

test('C3 旧格式（无引号、逗号/空白分隔）保持兼容', () => {
  assert.deepEqual(parseIpListEntryLine('10.0.0.1,普通备注', isIp), { value: '10.0.0.1', remark: '普通备注' })
  assert.deepEqual(parseIpListEntryLine('10.0.0.1 普通备注', isIp), { value: '10.0.0.1', remark: '普通备注' })
  assert.deepEqual(parseIpListEntryLine('10.0.0.1', isIp), { value: '10.0.0.1', remark: '' })
  assert.deepEqual(parseIpListEntryLine('2001:db8::/32', isIp), null, '非法值由注入校验拒绝')
})

test('C4 畸形行：未闭合引号/空值返回 null（导入计数为非法，不静默吞）', () => {
  assert.equal(parseIpListEntryLine('"10.0.0.1', isIp), null)
  assert.equal(parseIpListEntryLine(',remark', isIp), null)
  assert.equal(parseIpListEntryLine('   ', isIp), null)
  assert.equal(parseIpListEntryLine('10.0.0.1,"未闭合', isIp), null)
})

test('C5 引号包裹的 IP 字段（外部 CSV 工具产物）可解析', () => {
  assert.deepEqual(parseIpListEntryLine('"10.0.0.2","备注"', isIp), { value: '10.0.0.2', remark: '备注' })
})

test('D 共享条目缓存：缺失才拉、并发去重、失败可重试、invalidate 后重拉', async () => {
  invalidateSharedEntriesCache()
  const calls: number[] = []
  const loader = async (id: number): Promise<string[]> => {
    calls.push(id)
    if (id === 9) throw new Error('boom')
    return [`10.0.0.${id}`]
  }
  // 并发两次：同一 id 只发一次请求（in-flight 复用）
  await Promise.all([ensureSharedEntries([1, 2, 9], loader), ensureSharedEntries([1, 2, 9], loader)])
  assert.deepEqual(calls.sort((a, b) => a - b), [1, 2, 9])
  assert.deepEqual(sharedEntriesCache[1], ['10.0.0.1'])
  assert.equal(9 in sharedEntriesCache, false, '失败不得写缓存')
  // 已缓存 id 不再请求；失败 id 重试
  calls.length = 0
  await ensureSharedEntries([1, 2, 9], loader)
  assert.deepEqual(calls, [9])
  // 写回与失效通知
  writeSharedEntries(3, ['10.0.0.3'])
  assert.deepEqual(sharedEntriesCache[3], ['10.0.0.3'])
  invalidateSharedEntriesCache()
  calls.length = 0
  await ensureSharedEntries([1], loader)
  assert.deepEqual(calls, [1])
  invalidateSharedEntriesCache()
})
