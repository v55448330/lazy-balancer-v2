import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, member } from './_helpers.ts'

// 任务监控证书行「运行」tooltip 实门口径钉测：
// trigger 请求不带 force——证书行处于通用冷却期或 CA 退避窗口时，手动触发
// 会被后端 429 拒绝（failed 行 CA 退避窗未到期必然 429）；越窗出口在证书
// 任务页「重签」（确认消耗 CA 配额后携带 force）。冷却文案不得再承诺
// 「手动运行将立即尝试」——那是重签（force）语义，不是本页触发语义。

const vue = code('src/views/settings/TaskMonitor.vue')
const fn = member(vue, 'const runCooldownReason')

test('冷却 tooltip 不再承诺「手动运行将立即尝试」', () => {
  assert.doesNotMatch(fn, /手动运行将立即尝试/, '失真承诺不得回潮：触发无 force，冷却中会被 429 拒绝')
})

test('冷却 tooltip 按行状态披露实门口径：拒绝条件与越窗出口', () => {
  assert.match(fn, /row\.status === 'failed'/, '必须按行状态分支披露（failed 行与非 failed 行拒绝语义不同）')
  // failed 行：CA 退避窗口内触发将被拒绝，越窗出口=证书任务页「重签」
  assert.match(fn, /CA 退避窗口内手动触发将被拒绝/, 'failed 行必须披露 CA 退避窗口内的拒绝语义')
  assert.match(fn, /证书任务页/, '必须披露越窗出口位置：证书任务页')
  assert.match(fn, /「重签」/, '必须披露越窗出口动作：「重签」')
  // 非 failed 行：冷却期内触发将被拒绝
  assert.match(fn, /冷却期内手动触发将被拒绝/, '非 failed 行必须披露冷却期内的拒绝语义')
})

test('永久不可重试禁用判据与冷却分钟数同源不受文案改动影响', () => {
  assert.match(fn, /return '该任务永久不可重试'/, '永久不可重试返回串是按钮禁用判据，不得漂移')
  assert.match(
    vue,
    /runCooldownReason\(row as TaskInfo\) === '该任务永久不可重试'/,
    '按钮禁用比较串必须与返回串精确同源',
  )
  assert.match(fn, /Math\.ceil\(seconds \/ 60\)/, '冷却分钟数换算与证书任务页同源，不得漂移')
})
