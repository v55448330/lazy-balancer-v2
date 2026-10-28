// 任务监控页必须消费 cert_jobs_truncated：证书任务动态行触达采集上限时，列表
// 少行不能与「本来就没有」不可区分（后端 /system/tasks 已下发该标记）。
//
// 提示条文案里的行数上限**不是**前端字面量：权威值在
// `internal/services/taskmonitor.go` 的 `certJobRowsLimit`。后端调大/调小上限而
// 页面仍宣称旧数字时，用户会按错误行数判断「是否被截断」——因此文案数字必须
// 从 Go 常量逐值对表（同 securityBulk 的 D1/D2 范式），改常量即红。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, openTags, repoCode, section } from './_helpers.ts'

/** Go 侧上限常量声明；缺失时硬失败（不得回退到字面量）。 */
const certJobRowsLimit = (): number => {
  const go = repoCode('internal/services/taskmonitor.go')
  const declared = /^const certJobRowsLimit = (\d+)$/m.exec(go)
  assert.ok(declared, '后端缺 certJobRowsLimit 常量声明（前端行数文案的权威值）')
  // 常量必须真的是切片上限：探针 +1 查询、超出即截断——否则「对表」对上的是死值。
  assert.match(go, /certJobRowsLimit\+1\)/, '查询必须多取 1 行作截断探针')
  assert.match(go, /truncated := len\(out\) > certJobRowsLimit/, '超出上限必须置 truncated')
  assert.match(go, /out = out\[:certJobRowsLimit\]/, '输出必须按该常量切片')
  return Number(declared[1])
}

const page = code('src/views/settings/TaskMonitor.vue')

test('证书任务截断标记进入响应类型并被读取', () => {
  assert.match(page, /cert_jobs_truncated\?: boolean/)
  assert.match(page, /certJobsTruncated\.value = !!res\.data\.cert_jobs_truncated/)
})

test('提示条行数文案与后端 certJobRowsLimit 同值（改上限必须同批改文案）', () => {
  const limit = certJobRowsLimit()
  const recent = `最近 ${limit} 条`
  const capNote = `上限 ${limit}`
  assert.equal(page.split(recent).length - 1, 1, `提示条必须恰好一处「${recent}」`)
  assert.equal(page.split(capNote).length - 1, 1, `图表口径必须恰好一处「${capNote}」`)
  // 防第三份副本：任何「最近 N 条 / 上限 N」形态的数字都必须等于 Go 常量值。
  for (const match of page.matchAll(/最近 (\d+) 条|上限 (\d+)/g)) {
    assert.equal(match[1] ?? match[2], String(limit), `文案行数「${match[0]}」与后端上限 ${limit} 漂移`)
  }
})

test('截断时渲染提示条（复用全局 info-note-bar 样式，不写局部 hack）', () => {
  const limit = certJobRowsLimit()
  const match = page.match(/\n\s*<div v-if="certJobsTruncated" class="([^"]+)">([\s\S]*?)<\/div>/)
  assert.ok(match, '缺少 v-if="certJobsTruncated" 提示条')
  const classes = match[1].split(/\s+/)
  assert.ok(classes.includes('info-note-bar'), `提示条必须复用全局 info-note-bar 类，got "${match[1]}"`)
  assert.match(match[2], /info-note-desc/)
  assert.match(match[2], new RegExp(`最近 ${limit} 条`))
  assert.doesNotMatch(page, /:deep\([^)]*\)\s*\{[^}]*info-note/)
})

test('证书行运行按钮按剩余冷却禁用并给出等待提示', () => {
  // /system/tasks 对证书行下发剩余冷却秒数（0=可运行）；前端不得只靠后端 429。
  assert.match(page, /retry_cooldown_seconds\?: number/, 'TaskInfo 必须声明冷却字段')
  assert.match(page, /const runCooldownReason = \(row: TaskInfo\): string =>/, '必须单源计算冷却提示')
  const helper = section(page, 'const runCooldownReason = (row: TaskInfo): string =>', '\nconst onTrigger')
  assert.match(helper, /Math\.ceil\(seconds \/ 60\)/, '提示需换算为分钟')
  assert.match(
    helper,
    /冷却中，约 \$\{Math\.ceil\(seconds \/ 60\)\} 分钟后可运行/,
    '冷却提示文案必须说明还要等待多久',
  )

  // 运行按钮块：禁用态必须真正接线到冷却原因。只要求符号在页面任意位置出现时，
  // 把 helper 从 :disabled 挪到 tooltip / v-if 仍为绿——冷却期按钮可点。
  // 按开标签属性集定位（不看缩进/属性书写顺序）：原 marker 内嵌 18 空格缩进 +
  // `link type` 顺序，纯格式化调整即抛 missing start marker（界面完全没变）。
  const actions = section(page, 'label="操作"', '</el-table-column>')
  const runTextAt = actions.indexOf('>运行</el-button>')
  assert.ok(runTextAt > 0, '操作列缺「运行」按钮')
  const runButton = openTags(actions.slice(actions.lastIndexOf('<el-button', runTextAt)), 'el-button')[0]
  assert.ok(runButton, `运行按钮开标签解析失败: ${actions.slice(runTextAt - 200, runTextAt)}`)
  const disabled = /:disabled="([^"]*)"/.exec(runButton)?.[1]
  assert.ok(disabled, `运行按钮缺 :disabled 绑定: ${runButton}`)
  assert.match(disabled, /Boolean\(runCooldownReason\(row(?: as [A-Za-z]+)?\)\)/, `运行按钮禁用未接线冷却原因（现为 "${disabled}"）`)
  assert.match(disabled, /row\.status === 'running'/, '运行中仍应禁用')

  // tooltip 必须把冷却原因呈现给用户（禁用按钮 hover 是唯一解释面）。
  const tooltip = section(actions, 'v-if="row.triggerable"', '</el-tooltip>')
  assert.match(tooltip, /:content="runCooldownReason\(row(?: as [A-Za-z]+)?\)/, '冷却原因必须进 tooltip content')
})
