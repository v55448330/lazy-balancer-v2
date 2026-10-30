import test from 'node:test'
import assert from 'node:assert/strict'
import { code, member, section } from './_helpers.ts'

// 任务监控常驻（daemon）行操作矩阵：操作面完全由后端派生字段驱动——
// controllable→「重启」（POST /system/tasks/:id/control，action=restart）；
// business_driven 行调度开关只读（引擎停调时以「已停调」标签替代开关，恢复
// 入口在业务页）；常驻行没有下次执行时刻，下次执行列显「—」。结果标签=
// 引擎结果域自有词表（未知值显「未知」），不借用 cert_jobs 状态机——结果列
// 出现「已签发」等证书业务态属域错位。

const vue = code('src/views/settings/TaskMonitor.vue')
const opsColumn = section(vue, '<el-table-column label="操作"', '</el-table-column>')
const scheduleColumn = section(vue, '<el-table-column label="调度"', '</el-table-column>')
const nextColumn = section(vue, '<el-table-column label="下次执行"', '</el-table-column>')

test('常驻行：controllable 派生「重启」按钮，走 control restart', () => {
  assert.match(opsColumn, /row\.controllable/, '重启按钮必须以 controllable 字段为门（引擎元数据派生）')
  assert.match(opsColumn, /onRestart\(row as TaskInfo\)/)
  assert.match(vue, /\/system\/tasks\/\$\{row\.id\}\/control/, '重启必须走 control 端点')
  assert.match(vue, /\{ action: 'restart' \}/)
})

test('business_driven 行：调度开关只读；引擎停调以「已停调」标签替代开关', () => {
  assert.match(scheduleColumn, /:disabled="!canOperate \|\| isBusinessDrivenTask\(row as TaskInfo\)"/, '业务驱动任务调度开关只读（业务页单源）')
  assert.match(scheduleColumn, /row\.schedule_stopped_reason && isBusinessDrivenTask\(row as TaskInfo\)/, '引擎停调的 business_driven 行不再渲染开关')
  assert.match(scheduleColumn, /已停调/)
})

test('常驻行无下次执行：下次执行列显「—」', () => {
  assert.match(nextColumn, /row\.kind !== 'daemon'/, '常驻行不展示下次执行时刻')
  assert.match(nextColumn, /tm-dim/)
  assert.match(nextColumn, /—/)
})

test('结果标签=引擎结果域自有映射；未知值显「未知」，不借证书词表', () => {
  assert.doesNotMatch(vue, /certJobStatusLabel/, '结果列不得借用 cert_jobs 状态词表（域错位）')
  const resultLabels = member(code('src/views/settings/TaskMonitor.vue'), 'const resultLabels')
  for (const label of ['成功', '失败', '已取消', '中断', '运行中', '已跳过']) {
    assert.match(resultLabels, new RegExp(label), `引擎结果词表缺 ${label}`)
  }
  const statusResultLabel = member(code('src/views/settings/TaskMonitor.vue'), 'const statusResultLabel')
  assert.match(statusResultLabel, /hasOwn\(resultLabels, r\) \? resultLabels\[r\]! : '未知'/, '未知值回显「未知」，不做证书词表兜底')
  const resultTagType = member(code('src/views/settings/TaskMonitor.vue'), 'const resultTagType')
  assert.doesNotMatch(resultTagType, /issued/, '结果色调不得保留证书业务态分支')
})
