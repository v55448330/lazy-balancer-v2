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

test('不适用的任务在调度列标示角色方向并解释开关不可用（方向由节点角色补全）', () => {
  // 三态收口：调度列经 roleScopeOf 派生（主节点上的 slave-only 任务不再被标成「仅主节点」）
  assert.match(scheduleColumn, /roleScopeOf\(row as TaskInfo\) !== 'any'/)
  assert.match(scheduleColumn, /roleScopeTag\(row as TaskInfo\)/)
  assert.match(scheduleColumn, /roleScopeTip\(row as TaskInfo\)/)
  assert.ok(!/masterOnlyTag/.test(scheduleColumn), '标签文案不得硬编码方向（由 helpers 按 scope 选择）')
})

test('不适用的任务不展示下次执行时刻（避免「马上要跑」的误解）', () => {
  assert.match(nextColumn, /row\.role_applicable !== false/)
})

test('详情弹框展示角色适用性结论', () => {
  assert.match(vue, /:label="t\('app\.settings\.taskMonitor\.detail\.roleApplicability'\)"/)
  assert.match(vue, /app\.settings\.taskMonitor\.detail\.masterOnlyRun/)
})
