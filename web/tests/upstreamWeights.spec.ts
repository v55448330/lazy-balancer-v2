import { test } from 'node:test'
import assert from 'node:assert/strict'
import { normalizeWeights, payloadWeight, redistributeWeight, weightPercent } from '../src/utils/upstreamWeights.ts'
import { section, code } from './_helpers.ts'

test('重新启用上游至少分配 1，UI 不再显示 0%', () => {
  const rows = [
    { weight: 100, enabled: true },
    { weight: 0, enabled: true },
  ]
  redistributeWeight(rows, 1)
  assert.deepEqual(rows, [
    { weight: 99, enabled: true },
    { weight: 1, enabled: true },
  ])
})

test('禁用行仍为 0，其余启用行合计 100', () => {
  const rows = [
    { weight: 60, enabled: true },
    { weight: 40, enabled: true },
  ]
  rows[1]!.enabled = false
  redistributeWeight(rows, 1)
  assert.deepEqual(rows, [
    { weight: 100, enabled: true },
    { weight: 0, enabled: false },
  ])
})

test('全零权重按行最小值 1 参与比例分配（不走零和特判）；单行边界归一到 100', () => {
  const rows = [{ weight: 0, enabled: true }, { weight: 0, enabled: true }]
  normalizeWeights(rows)
  assert.equal(rows.reduce((sum, row) => sum + row.weight, 0), 100)
  assert.ok(rows.every((row) => row.weight >= 1))

  const single = [{ weight: 0, enabled: true }]
  redistributeWeight(single, 0)
  assert.equal(single[0]!.weight, 100)
})

test('三行全零按最小权重比例分配，生产实现不保留不可达零和分支', () => {
  const rows = [{ weight: 0 }, { weight: 0 }, { weight: 0 }]
  normalizeWeights(rows)
  assert.deepEqual(rows.map((row) => row.weight), [33, 33, 34])
  assert.ok(rows.every((row) => row.weight >= 1), '任何启用行都不得落 0 权重')
  assert.equal(rows.reduce((sum, row) => sum + row.weight, 0), 100)
  assert.doesNotMatch(code('src/utils/upstreamWeights.ts'), /sourceTotal === 0/, 'normalizedWeight 下限为 1，零和兜底永不可达')
})

test('weightPercent 展示口径（禁用行=0、总和≤0→0、四舍五入）', () => {
  assert.equal(weightPercent(undefined, { weight: 1 }), 0)
  assert.equal(weightPercent([], { weight: 1 }), 0)
  assert.equal(weightPercent([{ weight: 0, enabled: true }], { weight: 0, enabled: true }), 0)
  assert.equal(
    weightPercent([{ weight: 1, enabled: true }, { weight: 2, enabled: true }], { weight: 1, enabled: true }),
    33,
    '1/3 四舍五入为 33'
  )
  assert.equal(
    weightPercent([{ weight: 50, enabled: true }, { weight: 50, enabled: false }], { weight: 50, enabled: true }),
    100,
    '禁用行不计入总和'
  )
  assert.equal(
    weightPercent([{ weight: 50, enabled: true }], { weight: 50, enabled: false }),
    0,
    '禁用行自身恒 0'
  )
})

test('超出 100 行编辑器上限的行保留原权重并继续参与分配，不再被清零', () => {
  // 后端对上游条数无上限（API/导入可写入 101+ 行）；编辑器上限只是「添加上游」
  // 按钮门。清零会让改任一权重后「一保存就 400」。
  const rows = Array.from({ length: 101 }, () => ({ weight: 1, enabled: true }))
  normalizeWeights(rows)
  assert.equal(rows[100]!.weight, 1, '第 101 行不得被清零')
  assert.equal(rows.reduce((sum, row) => sum + row.weight, 0), 101, '每行至少 1，合计随行数抬升')
})

test('超限行改权重时预算随行数抬升（每行仍 ≥1，可正常保存）', () => {
  const rows = Array.from({ length: 101 }, () => ({ weight: 1, enabled: true }))
  redistributeWeight(rows, 0)
  assert.ok(rows.every((row) => row.weight >= 1), '任何行都不得落到 0 权重')
  assert.equal(rows.reduce((sum, row) => sum + row.weight, 0), 101)
  const otherTotal = rows.slice(1).reduce((sum, row) => sum + row.weight, 0)
  assert.equal(otherTotal, 100, '其余 100 行按既有语义合计 100，每行各 1')
})

test('编辑器超限提示显性化（可调权重 / 需删至上限或走 API）', () => {
  const editor = code('src/components/rules/PathRulesEditor.vue')
  const overLimitHint = section(editor, '<el-text v-if="rule.upstreams.length > MAX_UPSTREAM_ROWS"', '</el-text>')
  assert.match(overLimitHint, /保存前请删至 \{\{ MAX_UPSTREAM_ROWS \}\} 个以内/, '超限必须给出可操作提示')
  assert.match(overLimitHint, /或通过 API 维护/, '超限提示必须给出替代通道')
  assert.doesNotMatch(editor, /item\.weight = 0|weight = 0/, '组件不得自行清零权重')
})

test('payloadWeight 保存载荷边界——禁用行送 1、启用行原样、缺省 100', () => {
  // 禁用行草稿权重被 participatingItems 写 0，载荷边界送 1（后端 weight<1 响亮 400）
  assert.equal(payloadWeight({ weight: 0, enabled: false }), 1)
  assert.equal(payloadWeight({ weight: 50, enabled: false }), 1)
  // 启用行原样送出（含 redistribute 保证的 ≥1）
  assert.equal(payloadWeight({ weight: 30, enabled: true }), 30)
  // 缺省键回落 100（既有语义）
  assert.equal(payloadWeight({ enabled: true }), 100)
})
