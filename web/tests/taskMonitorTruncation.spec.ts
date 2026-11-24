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

import { code, goConstInt, openTags, repoCode, section } from './_helpers.ts'
import { i18n } from '../src/i18n/index.ts'

/** Go 侧上限常量声明；缺失时硬失败（不得回退到字面量）。 */
const certJobRowsLimit = (): number => {
  // 声明提取走 goConstInt 单源（缺失即抛错）。
  const limit = goConstInt('internal/services/taskmonitor.go', 'certJobRowsLimit')
  // 常量必须真的是切片上限：探针 +1 查询、超出即截断——否则「对表」对上的是死值。
  const go = repoCode('internal/services/taskmonitor.go')
  assert.match(go, /certJobRowsLimit\+1\)/, '查询必须多取 1 行作截断探针')
  assert.match(go, /truncated := len\(out\) > certJobRowsLimit/, '超出上限必须置 truncated')
  assert.match(go, /out = out\[:certJobRowsLimit\]/, '输出必须按该常量切片')
  return limit
}

const page = code('src/views/settings/TaskMonitor.vue')

test('证书任务截断标记进入响应类型并被读取', () => {
  assert.match(page, /cert_jobs_truncated\?: boolean/)
  assert.match(page, /certJobsTruncated\.value = !!res\.data\.cert_jobs_truncated/)
})

test('提示条行数文案与后端 certJobRowsLimit 同值（改上限必须同批改文案）', () => {
  const limit = certJobRowsLimit()
  const recent = "t('app.settings.taskMonitor.certQueue.truncatedNote')"
  const capNote = "t('app.settings.taskMonitor.chart.distHint')"
  assert.equal(page.split(recent).length - 1, 1, `提示条必须恰好一处「${recent}」`)
  assert.equal(page.split(capNote).length - 1, 1, `图表口径必须恰好一处「${capNote}」`)
  // 数值钉落在词条行本身：页面只引用键（无内联数字），对页面做数字扫描
  // 恒零命中（空转假绿）。从运行期词表取两条词条值，提取全部数字逐一
  // 与 Go 常量对表——zh/en 双侧同钉（en 侧漂移同样误导用户）。
  const savedLocale = i18n.global.locale.value
  try {
    for (const locale of ['zh-CN', 'en'] as const) {
      i18n.global.locale.value = locale
      for (const key of ['app.settings.taskMonitor.certQueue.truncatedNote', 'app.settings.taskMonitor.chart.distHint']) {
        const text = i18n.global.t(key)
        assert.notEqual(text, key, `${locale} 词条 ${key} 不得裸键回退`)
        // 只钉「上限数本身以独立数字形态出现」（`100 条` / `at 100`）：扫描词条里
        // **所有**数字会把任何无关数字（如「近 24 小时」）当漂移（假红），零命中
        // 又会漏掉上限漂移——边界正则两头都咬得住。
        assert.match(
          text,
          new RegExp(`(?:^|[^0-9])${limit}(?:[^0-9]|$)`),
          `${locale} 词条 ${key} 必须以独立数字形态给出后端上限 ${limit}：${text}`,
        )
      }
    }
  } finally {
    i18n.global.locale.value = savedLocale
  }
})

test('截断时渲染提示条（复用全局 info-note-bar 样式，不写局部 hack）', () => {
  const match = page.match(/\n\s*<div v-if="certJobsTruncated" class="([^"]+)">([\s\S]*?)<\/div>/)
  assert.ok(match, '缺少 v-if="certJobsTruncated" 提示条')
  const classes = match[1].split(/\s+/)
  assert.ok(classes.includes('info-note-bar'), `提示条必须复用全局 info-note-bar 类，got "${match[1]}"`)
  assert.match(match[2], /info-note-desc/)
  assert.match(match[2], /app\.settings\.taskMonitor\.certQueue\.truncatedNote/)
  assert.doesNotMatch(page, /:deep\([^)]*\)\s*\{[^}]*info-note/)
})

test('证书行运行按钮：冷却中可运行（信息提示），仅永久不可重试态禁用', () => {
  // 冷却披露契约（实门口径/词条语义锚/禁用判据同源）单源归
  // taskMonitorTriggerCooldownTip.spec.ts；本文件只钉按钮禁用面与 tooltip 接线。
  assert.match(page, /retry_cooldown_seconds\?: number/, 'TaskInfo 必须声明冷却字段')

  // 运行按钮块：禁用只保留永久不可重试态；冷却原因仍进 tooltip 供解释。
  const actions = section(page, "t('app.settings.taskMonitor.col.actions')", '</el-table-column>')
  const runTextAt = actions.indexOf("t('app.settings.taskMonitor.actions.run')")
  assert.ok(runTextAt > 0, '操作列缺「运行」按钮')
  const runButton = openTags(actions.slice(actions.lastIndexOf('<el-button', runTextAt)), 'el-button')[0]
  assert.ok(runButton, `运行按钮开标签解析失败: ${actions.slice(runTextAt - 200, runTextAt)}`)
  const disabled = /:disabled="([^"]*)"/.exec(runButton)?.[1]
  assert.ok(disabled, `运行按钮缺 :disabled 绑定: ${runButton}`)
  assert.match(disabled, /'app\.settings\.taskMonitor\.cooldown\.permanent'/, '运行按钮禁用只保留永久不可重试态')
  assert.doesNotMatch(disabled, /Boolean\(runCooldownReason/, '冷却不得再作为禁用条件')

  // tooltip 必须把冷却原因呈现给用户（手动运行的解释面）。
  const tooltip = section(actions, 'v-if="row.triggerable"', '</el-tooltip>')
  assert.match(tooltip, /:content="runCooldownReason\(row(?: as [A-Za-z]+)?\)/, '冷却原因必须进 tooltip content')
})
