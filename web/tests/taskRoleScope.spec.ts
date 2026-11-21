// 任务角色适用范围三态（后端 role_applicable 布尔 + 当前节点角色 → 方向）：
// 主节点上 role_applicable=false 的任务是 slave-only，旧 UI 一律标
// 「仅主节点运行（本节点不调度）」方向反了（P3 UI154）。此 spec 同时钉纯函数
// 与页面接线（tag/tip/详情文案按 scope 选择）。
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code, section } from './_helpers.ts'
import { taskRoleScope } from '../src/utils/taskRole.ts'

test('三态派生：applies=true → any；主节点 false=slave-only；从节点 false=master-only；角色未知不猜', () => {
  assert.equal(taskRoleScope(true, 'master'), 'any')
  assert.equal(taskRoleScope(undefined, 'slave'), 'any', '缺省（老后端）=不限角色')
  assert.equal(taskRoleScope(false, 'master'), 'slave-only', '主节点上不适用=仅从节点任务')
  assert.equal(taskRoleScope(false, 'slave'), 'master-only', '从节点上不适用=仅主节点任务')
  assert.equal(taskRoleScope(false, 'unknown'), 'unknown', '角色未判定不得猜方向（原「方向反」根因）')
})

const vue = code('src/views/settings/TaskMonitor.vue')

test('页面按 scope 分文案：master-only/slave-only/unknown 各有标签与说明', () => {
  assert.match(vue, /import \{ taskRoleScope, type NodeRole, type TaskRoleScope \} from '@\/utils\/taskRole'/)
  assert.match(vue, /const roleScopeOf = \(row: TaskInfo\): TaskRoleScope => taskRoleScope\(row\.role_applicable, nodeRole\.value\)/)
  for (const [key, entry, branch] of [
    ['masterOnlyRun', 'detail', "case 'master-only'"], ['slaveOnlyRun', 'detail', "case 'slave-only'"],
    ['roleUnknownRun', 'detail', "case 'unknown'"],
    ['masterOnlyTag', 'schedule', "case 'master-only'"], ['slaveOnlyTag', 'schedule', "case 'slave-only'"],
    ['roleUnknownTag', 'schedule', 'default'],
    ['masterOnlyTip', 'schedule', "case 'master-only'"], ['slaveOnlyTip', 'schedule', "case 'slave-only'"],
    ['roleUnknownTip', 'schedule', 'default'],
  ] as const) {
    const re = new RegExp(`${branch}: return t\\('app\\.settings\\.taskMonitor\\.${entry}\\.${key}'\\)`)
    assert.match(vue, re, `${key} 必须在 ${entry} 的 ${branch} 分支映射（不猜方向）`)
  }
})

test('调度列与详情经 scope 渲染（不再硬编码「仅主节点」方向）', () => {
  const scheduleColumn = section(vue, '<el-table-column :label="t(\'app.settings.taskMonitor.col.schedule\')"', '</el-table-column>')
  assert.match(scheduleColumn, /v-if="roleScopeOf\(row as TaskInfo\) !== 'any'"/)
  assert.match(scheduleColumn, /:content="roleScopeTip\(row as TaskInfo\)"/)
  assert.match(scheduleColumn, /\{\{ roleScopeTag\(row as TaskInfo\) \}\}/)
  assert.ok(!/masterOnlyTip/.test(scheduleColumn), '调度列不得直写 master-only 文案（方向由 scope 决定）')
  const detail = section(vue, "t('app.settings.taskMonitor.detail.roleApplicability')", '</el-descriptions-item>')
  assert.match(detail, /\{\{ roleScopeLabel\(detailTask\) \}\}/)
  assert.match(detail, /roleScopeOf\(detailTask\) === 'any' \? 'success' : 'info'/)
})
