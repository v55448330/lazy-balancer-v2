// 系统指标分项降级展示：后端对失败分项返回零值 + degraded 披露，展示层必须
// 把「没采到」显示为「采集失败」，不得把零值当真实用量（CPU 单点故障时内存/
// 磁盘仍应可用）。纯函数行为求值 + 视图接线钉（真实前提：node --test 无 .vue
// 装载器且模板依赖 element-plus 全局组件，不可挂载）。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  degradedMetricLabels,
  degradedMetricParts,
  pidsTone,
  pidsUsageLabel,
  pidsUsagePercent,
} from '../src/utils/systemMetrics.ts'
import { code } from './_helpers.ts'

test('降级分项解析：已知值成集、未知值忽略、顺序稳定', () => {
  assert.deepEqual([...degradedMetricParts(undefined)], [])
  assert.deepEqual([...degradedMetricParts([])], [])
  assert.deepEqual([...degradedMetricParts(['disk', 'cpu'])], ['disk', 'cpu'])
  assert.deepEqual([...degradedMetricParts(['cpu', 'gpu', 'cpu'])], ['cpu'], '未知分项忽略且去重')
  assert.deepEqual(degradedMetricLabels(['disk', 'memory']), ['内存', '磁盘'], '文案顺序固定为 cpu→memory→disk→pids')
  assert.deepEqual(degradedMetricLabels(['cpu']), ['CPU'])
  assert.deepEqual(degradedMetricLabels(['pids']), ['进程配额'])
})

test('分项成集语义：缺失/空=可用，CPU 失败不牵连内存/磁盘', () => {
  const none = degradedMetricParts(undefined)
  assert.equal(none.size, 0)
  assert.equal(degradedMetricParts([]).size, 0)
  const cpuOnly = degradedMetricParts(['cpu'])
  assert.equal(cpuOnly.has('cpu'), true)
  assert.equal(cpuOnly.has('memory'), false, 'CPU 失败不得连带内存标失败')
  const two = degradedMetricParts(['memory', 'disk'])
  assert.equal(two.has('cpu'), false)
  assert.equal(two.has('disk'), true)
})

test('Dashboard 系统资源卡按分项降级渲染（失败项显「采集失败」且不画进度）', () => {
  const page = code('src/views/Dashboard.vue')
  assert.match(page, /degradedMetricParts\(systemMetrics\.value\?\.degraded\)/)
  assert.match(page, /degradedMetricLabels\(systemMetrics\.value\?\.degraded\)/)
  // 分项提示复用全局 info-note-bar（不得局部新造样式）
  assert.match(page, /class="info-note-bar"/)
  assert.match(page, /部分指标采集失败：\{\{ degradedSystemLabels\.join\('、'\) \}\}/)
  for (const part of ['cpu', 'memory', 'disk', 'pids']) {
    assert.match(
      page,
      new RegExp(`degradedSystemParts\\.has\\('${part}'\\)`),
      `${part} 分项必须按 degraded 判定`,
    )
  }
  // 失败项的值位显示「采集失败」而非零值（三个分项各自绑定）
  for (const part of ['cpu', 'memory', 'disk', 'pids']) {
    assert.match(
      page,
      new RegExp(`degradedSystemParts\\.has\\('${part}'\\) \\? '采集失败'|v-if="degradedSystemParts\\.has\\('${part}'\\)">采集失败`),
      `${part} 失败项必须显式呈现「采集失败」`,
    )
  }
  // 失败项的进度条不得以 0 值继续展示
  assert.match(page, /v-if="!degradedSystemParts\.has\('cpu'\)" :percentage="Math\.min\(systemMetrics\.cpu_percent, 100\)"/)
  // 进程配额：四列网格、不换行数值、ulimit 提示放在 hover 文案中（不占布局）
  assert.match(page, /class="resource-grid"/)
  assert.match(page, /pidsUsageLabel\(systemMetrics\.pids_current, systemMetrics\.pids_max\)/)
  assert.match(page, /el-tooltip :content="pidsTooltip"/)
  assert.match(page, /ulimit -u：\$\{ulimitText\}/)
  assert.doesNotMatch(page, /class="resource-hint"/, 'ulimit 不得以独立行占用卡片布局')
  assert.match(page, /grid-template-columns: repeat\(4, minmax\(0, 1fr\)\)/)
  assert.match(page, /\.resource-value \{[^}]*white-space: nowrap/)
})

test('进程配额展示函数：不限额、百分比与阈值分级', () => {
  assert.equal(pidsUsageLabel(2368, 4096), '2368 / 4096')
  assert.equal(pidsUsageLabel(12, 0), '12 / 不限', 'pids.max=max 归一为 0 时显示「不限」')
  assert.equal(pidsUsagePercent(2048, 4096), 50)
  assert.equal(pidsUsagePercent(10, 0), 0, '不限额不伪造比例')
  assert.equal(pidsUsagePercent(5000, 4096), 100, '超限封顶 100')
  assert.equal(pidsTone(0), 'normal')
  assert.equal(pidsTone(79.9), 'normal')
  assert.equal(pidsTone(80), 'warning')
  assert.equal(pidsTone(95), 'critical')
  assert.equal(pidsTone(120), 'critical')
})
