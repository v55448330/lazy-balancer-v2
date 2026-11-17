import test from 'node:test'
import assert from 'node:assert/strict'
import { code, codeSection, repoCode, section } from './_helpers.ts'
import { i18n } from '../src/i18n/index.ts'

// 任务监控=通用任务视图（2026-10-22 用户裁定）：任务列表只呈现通用字段——
// 名称/分类/类型/状态（空闲·运行中·失败）/调度/执行时间/计数/操作。
// 证书生命周期态（已签发/限流中/已禁用…）由免费证书页与规则 TLS 列维护，
// 任务列表的任何列（名称列、状态列、状态词表、兜底）均不得引入业务词表。

const vue = code('src/views/settings/TaskMonitor.vue')
const statusColumn = section(vue, '<el-table-column :label="t(\'app.settings.taskMonitor.col.status\')"', '</el-table-column>')
const taskColumn = section(vue, '<el-table-column :label="t(\'app.settings.taskMonitor.col.task\')"', '</el-table-column>')
const svc = repoCode('internal/services/taskmonitor.go')

test('任务名称列只渲染任务名（无业务态子文本/徽标）', () => {
  assert.doesNotMatch(taskColumn, /tm-cert-sub|certJobLabel|certJobRawStatus/, '名称列不得出现证书生命周期态')
  assert.match(taskColumn, /tm-task-name/)
})

test('状态列只由引擎 status 渲染（三态，无业务态覆盖）', () => {
  assert.doesNotMatch(statusColumn, /certJobLabel|certJobToneOf|certJobStatusLabel/, '状态列不得出现证书业务态')
  assert.match(statusColumn, /tm-status/)
  assert.match(statusColumn, /statusLabel\(row\.status\)/)
})

test('statusLabel 兜底不引入证书生命周期词表', () => {
  const fn = codeSection('src/views/settings/TaskMonitor.vue', 'const statusLabels', '// v2.0 四类型')
  assert.doesNotMatch(fn, /certJobStatusLabel/, 'statusLabel 兜底不得把 cert_jobs 状态词表渲染进状态列')
  assert.match(fn, /hasOwn\(statusLabels, s\) \? statusLabels\[s\] : s/, '兜底只回显原值，并经自有属性守卫')
})

test('文件内不存在按行渲染证书状态标签的 helper（certJobLabel/certJobRawStatus）', () => {
  assert.doesNotMatch(vue, /const certJobLabel|const certJobRawStatus/, '任务列表不得有证书态标签 helper')
})

test('服务端 TaskStatus 枚举收敛三态（无 queued/disabled 扩展值）', () => {
  // 全文件扫描 `X TaskStatus = "..."` 声明集合并与期望集**正向**比对：
  // 负断言只覆盖切片内，枚举若以块外独立声明回流（或挪到 type 前后）会静默
  // 通过；正向集合比较对「换声明位置」免疫。
  const declared = [...svc.matchAll(/\b(TaskStatus\w+)\s+TaskStatus\s*=/g)].map((match) => match[1])
  assert.deepEqual(
    [...new Set(declared)].sort(),
    ['TaskStatusFailed', 'TaskStatusIdle', 'TaskStatusRunning'],
    'TaskStatus 枚举只允许 running/idle/failed 三态',
  )
  assert.match(svc, /case "issued", "downloaded", "disabled":/)
  assert.match(svc, /ti\.Status = TaskStatusRunning/)
})

// 三态收敛后的死分支清零：TaskInfo.status 产出恒 ∈ {running,idle,failed}
// （引擎 StatusMirror 仅 "running"/""，cert-job 退役行归 idle），前端任何
// queued/disabled 消费分支、零产出分类「触发」与零产出触发值 slave-sync
// 均不得残留（残留=死代码，且误导后续维护者以为仍有产出）。
test('三态收敛后前端死分支清零', () => {
  const theme = code('src/utils/chartTheme.ts')
  const statusColors = section(theme, 'export const statusColor', '\n}')
  assert.doesNotMatch(statusColors, /queued|disabled/, 'statusColor 不得保留零产出键')
  assert.doesNotMatch(vue, /st === 'disabled'/, 'detailTone 不得保留 disabled 分支')
  assert.doesNotMatch(vue, /\.tm-status\[data-status="disabled"\]/, '状态 CSS 不得保留 disabled 规则')
  assert.doesNotMatch(vue, /'触发': 5|c === '触发'/, '分类序/分类标签不得保留零产出「触发」类')
  assert.doesNotMatch(vue, /'slave-sync'/, '触发标签不得保留零产出 slave-sync 映射')
})

test('类型筛选按钮与类型列徽标同词：oneshot 走 triggerFamily 专键（en 双语一致）', () => {
  // oneshot 筛选档曾消费列头键 col.trigger（en=Trigger），与类型列徽标
  // kind.oneshot（en=Triggered）分叉；五个筛选档必须同走 triggerFamily 域。
  const filterGroup = section(vue, '<el-radio-group v-model="kindFilter"', '</el-radio-group>')
  for (const kind of ['all', 'scheduled', 'daemon', 'periodic', 'oneshot']) {
    assert.match(filterGroup, new RegExp(`value="${kind}">\\{\\{ t\\('app\\.settings\\.taskMonitor\\.triggerFamily\\.${kind}'\\) \\}\\}`), `${kind} 筛选档必须消费 triggerFamily.${kind}`)
  }
  assert.doesNotMatch(filterGroup, /col\.trigger/, '筛选档不得消费列头键 col.trigger')
  // en 词一致钉：筛选档与类型列徽标逐词相等（zh 同词是母本巧合，en 才暴露分叉）
  const messages = i18n.global.messages.value as Record<string, Record<string, unknown>>
  for (const loc of ['zh-CN', 'en'] as const) {
    const tm = ((messages[loc].app as Record<string, unknown>).settings as Record<string, unknown>).taskMonitor as Record<string, Record<string, string>>
    assert.equal(tm.triggerFamily.oneshot, tm.kind.oneshot, `${loc}: oneshot 筛选档与类型列徽标必须同词`)
  }
})

test('taskMonitor.allCategories 顶层死键退役：消费方走 table.allCategories（zh/en 成对）', () => {
  // 分类筛选 placeholder/option 消费 table.allCategories；顶层同名键双语
  // 零消费（收敛残留）。按合并树键存在性判定，裸键名全文件匹配会误命中活键。
  assert.match(vue, /t\('app\.settings\.taskMonitor\.table\.allCategories'\)/, '消费方走 table 域活键')
  assert.doesNotMatch(vue, /t\('app\.settings\.taskMonitor\.allCategories'\)/, '顶层死键不得有消费点')
  const messages = i18n.global.messages.value as Record<string, Record<string, unknown>>
  for (const loc of ['zh-CN', 'en'] as const) {
    const tm = ((messages[loc].app as Record<string, unknown>).settings as Record<string, unknown>).taskMonitor as Record<string, unknown>
    assert.ok(!('allCategories' in tm), `${loc}: taskMonitor.allCategories 顶层死键必须删除`)
    assert.equal(typeof (tm.table as Record<string, unknown>).allCategories, 'string', `${loc}: table.allCategories 活键保留`)
  }
})
