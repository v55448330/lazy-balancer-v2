import test from 'node:test'
import assert from 'node:assert/strict'
import { code, member, openTags, section } from './_helpers.ts'

// 任务监控常驻（daemon）行操作矩阵：操作面完全由后端派生字段驱动——
// controllable→「重启」（POST /system/tasks/:id/control，action=restart）；
// business_driven 行调度开关只读（引擎停调时以「已停调」标签替代开关，恢复
// 入口在业务页）；常驻行没有下次执行时刻，下次执行列显「—」。结果标签=
// 引擎结果域自有词表（未知值显「未知」），不借用 cert_jobs 状态机——结果列
// 出现「已签发」等证书业务态属域错位。

const vue = code('src/views/settings/TaskMonitor.vue')
const opsColumn = section(vue, '<el-table-column :label="t(\'app.settings.taskMonitor.col.actions\')"', '</el-table-column>')
const scheduleColumn = section(vue, '<el-table-column :label="t(\'app.settings.taskMonitor.col.schedule\')"', '</el-table-column>')
const nextColumn = section(vue, '<el-table-column :label="t(\'app.settings.taskMonitor.detail.nextRun\')"', '</el-table-column>')

test('常驻行：controllable 派生「重启」按钮，走 control restart', () => {
  assert.match(opsColumn, /row\.controllable/, '重启按钮必须以 controllable 字段为门（引擎元数据派生）')
  assert.match(opsColumn, /onRestart\(row as TaskInfo\)/)
  assert.match(vue, /\/system\/tasks\/\$\{row\.id\}\/control/, '重启必须走 control 端点')
  assert.match(vue, /\{ action: 'restart' \}/)
})

// 通用调度分支（cert-waiting-ca 之外）：标签以 schedule_stopped_reason 为门、
// 开关以 isBusinessDrivenTask 为门——两个门互不引用，才能同时表达
// 「业务驱动停调行=只有标签」与「其余停调行=标签 + 开关」。
const scheduleBranch = section(scheduleColumn, 'v-else-if="row.kind !== \'oneshot\'"', '</el-tooltip>')
const scheduleSwitches = openTags(scheduleBranch, 'el-switch')

test('business_driven 行：调度开关只读；引擎停调以「已停调」标签替代开关（无开关）', () => {
  assert.equal(scheduleSwitches.length, 1, '通用调度分支只应有一个开关')
  assert.match(scheduleSwitches[0]!, /v-if="!isBusinessDrivenTask\(row as TaskInfo\)"/, '业务驱动任务不渲染调度开关（业务页单源=只读；停调行自然只剩标签）')
  assert.match(
    scheduleBranch,
    /<el-tag v-if="row\.schedule_stopped_reason"[^>]*>\{\{ t\('app\.settings\.taskMonitor\.schedule\.stoppedTag'\) \}\}<\/el-tag>/,
    '引擎停调的 business_driven 行显示「已停调」标签',
  )
})

test('非业务驱动行停调：「已停调」标签与开关并存（开关保留用于恢复）', () => {
  assert.doesNotMatch(section(scheduleColumn, 'app.settings.taskMonitor.schedule.stoppedTag', '</el-tooltip>'), /v-else/, '停调标签不得以 v-else 排斥开关——否则非业务驱动行停调后无法在本页恢复')
  assert.doesNotMatch(scheduleSwitches[0] ?? '', /schedule_stopped_reason/, '开关不得因引擎停调而隐藏')
  assert.match(scheduleBranch, /:content="scheduleStoppedTip\(row as TaskInfo\) \|\|/, '停调行的提示指向本页开关恢复')
})

test('常驻行无下次执行：下次执行列显「—」', () => {
  assert.match(nextColumn, /row\.kind !== 'daemon'/, '常驻行不展示下次执行时刻')
  assert.match(nextColumn, /tm-dim/)
  assert.match(nextColumn, /—/)
})

test('结果标签=引擎结果域自有映射；未知值显「未知」，不借证书词表', () => {
  assert.doesNotMatch(vue, /certJobStatusLabel/, '结果列不得借用 cert_jobs 状态词表（域错位）')
  // 调用点钉键：六个 result.*/status.running 键必须在渲染面消费（文案口径由
  // 词条函数承载，本 spec 不钉母本原文）。
  for (const key of ['success', 'failed', 'cancelled', 'interrupted', 'skipped']) {
    assert.match(vue, new RegExp("t\\('app\\.settings\\.taskMonitor\\.result\\." + key + "'\\)"), `引擎结果词表缺 result.${key}`)
  }
  assert.match(vue, /t\('app\.settings\.taskMonitor\.status\.running'\)/, '引擎结果词表缺 status.running(运行中)')
  assert.match(vue, /hasOwn\(resultLabels, r\) \? resultLabels\[r\]! : t\('app\.settings\.taskMonitor\.status\.unknown'\)/, '未知值回显「未知」键，不做证书词表兜底')
  const resultTagType = member(vue, 'const resultTagType')
  assert.doesNotMatch(resultTagType, /issued/, '结果色调不得保留证书业务态分支')
})
