// 绑定链执行序语义（链序展平/orders 合并）：
//  - 链序展平 flattenBindingOrder：规则侧绑定编辑器提交序展平——基线（props.bindings，
//    GET /security/bindings rank 序，security.go:5840 ORDER BY rank ASC）中仍被
//    选中的成员按基线相对位次保留（跨阶段交错序不因阶段桶展平而重置）；新增
//    成员锚定其阶段在基线中首个成员之后；无同阶段锚点按阶段桶序尾插。
//    纯展示性重开 + 零改动保存 → 提交序与基线逐位一致（幂等）。
//  - orders 合并 mergeChainOrder：向导顺序保存 orders 载荷 = staged 相对重排应用到
//    最新基线链——staged 未涉及的并发新增成员不再被整链重建语义静默剔除，
//    按策略身份锚定最近同阶段成员后（无锚点尾插），阶段 0 置顶归一不变式保留。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  flattenBindingOrder,
  mergeChainOrder,
  normalizePolicyChainOrder,
  type SecurityPolicyType,
  type StageOrderBucket,
} from '../src/utils/securityStages.ts'

// 阶段归属固定映射（与后端 policy_type 单职化后的现代库同构；11/12/13=阶段1，
// 21/22=阶段2，31/32/33=阶段3，41=阶段0；99=mixed，88=未知/死引用）
const STAGE_OF: Record<number, SecurityPolicyType> = {
  11: 'stage1', 12: 'stage1', 13: 'stage1',
  21: 'stage2', 22: 'stage2',
  31: 'stage3', 32: 'stage3', 33: 'stage3',
  41: 'stage0',
}
const stageOf = (id: number): SecurityPolicyType | undefined => STAGE_OF[id]

test('链序展平 零改动幂等：交错基线原样展平，不聚集回阶段序', () => {
  // 基线 [s1, s3, s1, s2] 为用户在策略向导自定义的交错执行序；纯展示性重开
  // （阶段桶回填同一批成员）后零改动保存，提交序必须与基线逐位一致。
  const baseline = [11, 31, 12, 21]
  const buckets: StageOrderBucket[] = [
    { stage: 'stage0', ids: [] },
    { stage: 'stage1', ids: [11, 12] },
    { stage: 'stage2', ids: [21] },
    { stage: 'stage3', ids: [31] },
  ]
  assert.deepEqual(flattenBindingOrder(baseline, buckets), [11, 31, 12, 21])
})

test('链序展平 新增成员锚定同阶段首个基线成员之后', () => {
  // 基线 [s1, s3]；新增阶段 1 成员 12 → 插在首个阶段 1 基线成员 11 之后
  assert.deepEqual(
    flattenBindingOrder([11, 31], [
      { stage: 'stage0', ids: [] },
      { stage: 'stage1', ids: [11, 12] },
      { stage: 'stage2', ids: [] },
      { stage: 'stage3', ids: [31] },
    ]),
    [11, 12, 31],
  )
  // 基线 [s3, s1]：新增阶段 1 成员的锚点仍是基线序中首个阶段 1 成员（位置随基线）
  assert.deepEqual(
    flattenBindingOrder([31, 11], [
      { stage: 'stage0', ids: [] },
      { stage: 'stage1', ids: [11, 12] },
      { stage: 'stage2', ids: [] },
      { stage: 'stage3', ids: [31] },
    ]),
    [31, 11, 12],
  )
})

test('链序展平 无同阶段锚点的新成员按阶段桶序尾插', () => {
  // 基线仅阶段 3；新增阶段 1 与阶段 2 成员无锚点 → 按桶序（stage1 先于 stage2）尾插
  assert.deepEqual(
    flattenBindingOrder([31], [
      { stage: 'stage0', ids: [] },
      { stage: 'stage1', ids: [11] },
      { stage: 'stage2', ids: [21] },
      { stage: 'stage3', ids: [31] },
    ]),
    [31, 11, 21],
  )
})

test('链序展平 取消勾选保序：剩余成员保持基线相对位次', () => {
  assert.deepEqual(
    flattenBindingOrder([11, 31, 12], [
      { stage: 'stage0', ids: [] },
      { stage: 'stage1', ids: [11, 12] },
      { stage: 'stage2', ids: [] },
      { stage: 'stage3', ids: [] },
    ]),
    [11, 12],
  )
})

test('链序展平 mixed 与死引用不进载荷：不在选择桶即落出', () => {
  // 基线含 mixed（99）与已删除策略（77）：编辑器不回填可写桶，提交亦不携带
  assert.deepEqual(
    flattenBindingOrder([11, 99, 77], [
      { stage: 'stage0', ids: [] },
      { stage: 'stage1', ids: [11] },
      { stage: 'stage2', ids: [] },
      { stage: 'stage3', ids: [] },
    ]),
    [11],
  )
})

test('链序展平 同阶段多新增按桶序整体插锚点后，不逆序', () => {
  assert.deepEqual(
    flattenBindingOrder([11], [
      { stage: 'stage0', ids: [] },
      { stage: 'stage1', ids: [11, 13, 12] },
      { stage: 'stage2', ids: [] },
      { stage: 'stage3', ids: [] },
    ]),
    [11, 13, 12],
  )
})

test('链序展平 空基线：全新绑定按阶段桶序展平', () => {
  assert.deepEqual(
    flattenBindingOrder([], [
      { stage: 'stage0', ids: [41] },
      { stage: 'stage1', ids: [11] },
      { stage: 'stage2', ids: [] },
      { stage: 'stage3', ids: [31] },
    ]),
    [41, 11, 31],
  )
})

test('orders 合并 staged 重排 + 并发新增 C：orders 含 C 不丢榜，无同阶段锚点尾插', () => {
  // 钉测：基线 [A(s3), B(s3)]，staged 对 A/B 重排为 [B, A]，并发新增 C(s1)
  // → C 必须出现在载荷中（整链重建语义下不再被静默剔除），staged 相对序保持
  const merged = mergeChainOrder([32, 31], [31, 32, 12], stageOf)
  assert.ok(merged.includes(12), '并发新增成员必须保留在 orders 载荷中')
  assert.deepEqual(merged, [32, 31, 12])
})

test('orders 合并 staged 未涉及新成员锚定最近同阶段成员之后', () => {
  // 新增 33(s3)：合并结果中最近的同阶段成员是 31（kept 末位）→ 紧随其后
  assert.deepEqual(mergeChainOrder([32, 31], [31, 32, 33], stageOf), [32, 31, 33])
})

test('orders 合并 纯重排零新增：载荷与 staged 逐位一致', () => {
  assert.deepEqual(mergeChainOrder([32, 31], [31, 32], stageOf), [32, 31])
})

test('orders 合并 staged 中已解绑成员落出，不回流进载荷', () => {
  assert.deepEqual(mergeChainOrder([32, 31, 12], [31, 32], stageOf), [32, 31])
})

test('orders 合并 阶段 0 置顶归一不变式保留', () => {
  assert.deepEqual(mergeChainOrder([31, 41, 32], [31, 41, 32], stageOf), [41, 31, 32])
})

test('orders 合并 空 staged 回落最新基线归一（与旧 fallback 行为等价）', () => {
  assert.deepEqual(mergeChainOrder([], [31, 41], stageOf), [41, 31])
})

test('orders 合并 未知类型（死引用）成员尾插不炸路径', () => {
  assert.deepEqual(mergeChainOrder([31], [31, 88], stageOf), [31, 88])
})

test('orders 合并 normalizePolicyChainOrder：阶段 0 稳定置顶，其余相对序不动', () => {
  // 41 置顶；31/12 相对序保持；42（未知类型/死引用）留在 rest 组原位
  assert.deepEqual(normalizePolicyChainOrder([31, 41, 12, 42], stageOf), [41, 31, 12, 42])
  assert.deepEqual(normalizePolicyChainOrder([12, 31], stageOf), [12, 31])
})
