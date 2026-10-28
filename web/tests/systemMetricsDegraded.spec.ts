// 系统指标分项降级展示：后端对失败分项返回零值 + degraded 披露，展示层必须
// 把「没采到」显示为「采集失败」，不得把零值当真实用量（CPU 单点故障时内存/
// 磁盘仍应可用）。资源进度、文案与阈值走纯函数行为求值；仅组件形态保留
// 少量视图接线钉（node --test 无 .vue 装载器）。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  degradedMetricLabels,
  degradedMetricParts,
  metricProgressPercent,
  nprocLimitLabel,
  pidsTone,
  pidsUsageLabel,
  pidsPercentLabel,
  pidsProgressPercent,
  pidsTooltipText,
  pidsValueTone,
} from '../src/utils/systemMetrics.ts'
import { code, elementSlice } from './_helpers.ts'

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
test('资源卡进度行为：正常值、超限封顶、降级与不限额隐藏', () => {
  assert.equal(metricProgressPercent(41.2, false), 41.2)
  assert.equal(metricProgressPercent(122, false), 100, '普通资源进度条只在视觉层封顶')
  assert.equal(metricProgressPercent(0, true), null, '采集失败不得继续画 0% 进度条')
  assert.equal(pidsProgressPercent(57.8, 4096, false), 57.8)
  assert.equal(pidsProgressPercent(122, 4096, false), 100)
  assert.equal(pidsProgressPercent(12, 0, false), null, '不限额不画进度')
  assert.equal(pidsProgressPercent(12, 4096, true), null, 'pids 采集失败不画进度')
})

test('进程配额展示函数：不限额、原始百分比与进度条封顶', () => {
  assert.equal(pidsUsageLabel(2368, 4096), '2368 / 4096')
  assert.equal(pidsUsageLabel(12, 0), '12 / 不限', 'pids.max=max 归一为 0 时显示「不限」')
  assert.equal(pidsPercentLabel(50), '50')
  assert.equal(pidsPercentLabel(5000 / 4096 * 100), '122', '文本必须保留后端超限程度')
  assert.equal(pidsProgressPercent(50, 4096, false), 50)
  assert.equal(pidsProgressPercent(5000 / 4096 * 100, 4096, false), 100, '仅进度条封顶 100')
  assert.equal(pidsProgressPercent(0, 4096, false), 0, '零用量不伪造比例')
  assert.equal(pidsTone(0), 'normal')
  assert.equal(pidsTone(79.9), 'normal')
  assert.equal(pidsTone(80), 'warning')
  assert.equal(pidsTone(95), 'critical')
  assert.equal(pidsTone(120), 'critical')
})

test('进程配额采集失败使用中性色，恢复后三档色调不变', () => {
  for (const percent of [0, 79.9, 80, 95, 120]) {
    assert.equal(pidsValueTone(percent, true), null)
  }
  assert.equal(pidsValueTone(0, false), 'normal')
  assert.equal(pidsValueTone(80, false), 'warning')
  assert.equal(pidsValueTone(95, false), 'critical')
})

test('ulimit 零值不得把读取失败断言为不限', () => {
  assert.equal(nprocLimitLabel(4096), '4096')
  assert.equal(nprocLimitLabel(0), '未采集或不限')
  assert.equal(nprocLimitLabel(-1), '未采集或不限')
})

test('进程配额帮助文案拼接保留 ulimit 零值歧义', () => {
  assert.match(pidsTooltipText(4096), /含僵尸进程.*fork 失败.*ulimit -u：4096/)
  assert.match(pidsTooltipText(0), /ulimit -u：未采集或不限/)
})

test('进程配额说明复用可聚焦帮助角标', () => {
  const page = code('src/views/Dashboard.vue')
  // 标签组按元素配对取段（不是定长字符窗口）：组内标记增长/换行不再假红，
  // 「角标挪到组外的相邻文本里」也不再假绿。
  const groupAt = page.indexOf('class="resource-label-group"')
  assert.ok(groupAt > 0, '进程配额标签组缺失')
  const openAt = page.lastIndexOf('<span', groupAt)
  const group = elementSlice(page, openAt, 'span')
  assert.ok(group.includes('进程配额'), `标签组必须含「进程配额」：${group}`)
  assert.ok(group.includes('<FieldHelpIcon :content="pidsTooltip"'), `可聚焦帮助角标必须与标签同组：${group}`)
  assert.doesNotMatch(group, /<el-tooltip/, '组内不得用不可聚焦的 tooltip 代替帮助角标')
  assert.match(page, /<span class="resource-value" :class="pidsValueClass">\{\{ systemMetrics\.pids_current \}\}<\/span>\s*<span class="resource-total">/)
  assert.doesNotMatch(page, /<el-tooltip :content="pidsTooltip"/)
})
