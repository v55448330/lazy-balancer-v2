import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, member } from './_helpers.ts'

// 任务监控证书行「运行」tooltip 实门口径钉测：
// trigger 请求不带 force——后端为每行下发 cert_job_ca_cooldown_active（CA 退避
// 窗口判定布尔）：窗口内触发默认 429（可 ?force 越过，出口在证书任务页
// 「重签」）；仅通用冷却的行（如达重签上限后 ca_available_after 为空的 failed
// 行）触发放行并留越冷审计——tooltip 不得声称被拒。冷却文案不得再承诺
// 「手动运行将立即尝试」——那是重签（force）语义，不是本页触发语义。

const vue = code('src/views/settings/TaskMonitor.vue')
const fn = member(vue, 'const runCooldownReason')

test('冷却 tooltip 不再承诺「手动运行将立即尝试」', () => {
  assert.doesNotMatch(fn, /手动运行将立即尝试/, '失真承诺不得回潮：触发无 force，冷却中会被 429 拒绝')
})

test('冷却 tooltip 按后端布尔披露实门口径：拒绝条件与越窗出口', () => {
  assert.match(vue, /cert_job_ca_cooldown_active\?: boolean/, 'TaskInfo 必须声明后端下发的 CA 退避窗口布尔')
  assert.match(fn, /cert_job_ca_cooldown_active/, '必须按后端布尔分支披露（不得按行状态猜测窗口）')
  // 窗口内：触发默认拒绝，越窗出口=证书任务页「重签」。调用点钉键一次，
  // 三语义锚（拒绝/出口位置/出口动作）钉 zh 母本原文——同形断言重复三遍
  // 只钉了键、词条内容零覆盖（出口披露漂移无守卫）。
  assert.match(fn, /app\.settings\.taskMonitor\.cooldown\.caWindow/, 'CA 退避窗口内必须走 caWindow 词条分支')
  const caWindowTip = /"caWindow": "([^"]+)"/.exec(code('src/locales/zh/settings.ts'))?.[1]
  assert.ok(caWindowTip, 'zh 母本缺 cooldown.caWindow 词条')
  assert.ok(caWindowTip.includes('将被拒绝'), 'caWindow 词条必须披露拒绝语义')
  assert.ok(caWindowTip.includes('证书任务页'), 'caWindow 词条必须披露越窗出口位置：证书任务页')
  assert.ok(caWindowTip.includes('重签'), 'caWindow 词条必须披露越窗出口动作：「重签」')
  // 仅通用冷却（布尔=false）：触发放行——不得声称被拒
  assert.match(fn, /app\.settings\.taskMonitor\.cooldown\.normal/, '仅通用冷却的行必须如实披露「冷却期后可直接重试」')
  assert.doesNotMatch(fn, /冷却期内手动触发将被拒绝/, '通用冷却分支「将被拒绝」过声称不得回潮')
})

test('永久不可重试禁用判据与冷却分钟数同源不受文案改动影响', () => {
  assert.match(fn, /return t\('app\.settings\.taskMonitor\.cooldown\.permanent'\)/, '永久不可重试返回串是按钮禁用判据，不得漂移')
  assert.match(
    vue,
    /runCooldownReason\(row as TaskInfo\) === t\('app\.settings\.taskMonitor\.cooldown\.permanent'\)/,
    '按钮禁用比较串必须与返回串精确同源',
  )
  assert.match(fn, /Math\.ceil\(seconds \/ 60\)/, '冷却分钟数换算与证书任务页同源，不得漂移')
})
