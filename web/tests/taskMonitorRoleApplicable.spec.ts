import test from 'node:test'
import assert from 'node:assert/strict'
import { code, section } from './_helpers.ts'

// 从节点任务视图：master-only 族在从节点永不投递，页面必须显性标注
// 「仅主节点」并解释调度开关不可用，否则「下次执行」的未来时刻会被误读为
// 即将运行（排障噪音）。

const vue = code('src/views/settings/TaskMonitor.vue')
const scheduleColumn = section(vue, '<el-table-column :label="t(\'app.settings.taskMonitor.col.schedule\')"', '</el-table-column>')
const nextColumn = section(vue, '<el-table-column :label="t(\'app.settings.taskMonitor.detail.nextRun\')"', '</el-table-column>')

test('任务接口声明 role_applicable（服务端派生的角色适用性）', () => {
  assert.match(vue, /role_applicable\?: boolean/)
})

test('从节点不适用的任务在调度列标注「仅主节点」并解释开关不可用', () => {
  assert.match(scheduleColumn, /row\.role_applicable === false/)
  assert.match(scheduleColumn, /app\.settings\.taskMonitor\.schedule\.masterOnlyTag/)
  assert.match(scheduleColumn, /app\.settings\.taskMonitor\.schedule\.masterOnlyTip/)
})

test('不适用的任务不展示下次执行时刻（避免「马上要跑」的误解）', () => {
  assert.match(nextColumn, /row\.role_applicable !== false/)
})

test('详情弹框展示角色适用性结论', () => {
  assert.match(vue, /:label="t\('app\.settings\.taskMonitor\.detail\.roleApplicability'\)"/)
  assert.match(vue, /app\.settings\.taskMonitor\.detail\.masterOnlyRun/)
})
