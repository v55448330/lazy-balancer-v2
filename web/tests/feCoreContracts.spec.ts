import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, openTags, section, source } from './_helpers.ts'
import { buildRuleMetricsUnavailable } from '../src/utils/dashboardMetrics.ts'

const MFA = 'src/components/MfaBindingWizard.vue'
const APP = 'src/App.vue'
const FLOW = 'src/components/RuleFlowDialog.vue'
const DASHBOARD = 'src/views/Dashboard.vue'
const TASK_MONITOR = 'src/views/settings/TaskMonitor.vue'

test('MFA 返回扫码步时重新渲染新建画布', () => {
  const text = code(MFA)
  const renderWatch = section(text, 'watch([() => props.modelValue, step]', 'const activate')
  assert.match(renderWatch, /visible && current === 0/)
  assert.match(renderWatch, /void renderQr\(\)/)
})

test('OIDC 拒绝分支只走公共初始化一次', () => {
  const rejected = section(code(APP), 'if (!verdict.ok)', '} else if (authStore.token')
  assert.doesNotMatch(rejected, /authStore\.init\(\)/)
})

test('流程弹框每次打开都使上一会话统计响应失效', () => {
  const flow = code(FLOW)
  const opened = section(flow, 'const onDialogOpen =', 'const loadCertInfo =')
  const invalidateAt = opened.indexOf('statsSeq++')
  const branchAt = opened.indexOf('const caddyId =')
  assert.ok(invalidateAt >= 0, '打开入口必须推进统计序号')
  assert.ok(branchAt > invalidateAt, '无 caddyId 与 TCP 早退之前就必须失效旧统计')
  // 取数本身在 loadStageStats 内（打开与面板「重试」共用），它自带一次序号推进
  // ——调用方不再内联拼接请求。
  assert.match(opened, /loadStageStats\(caddyId\)/, 'HTTP 分支必须走共用取数函数')
  const loader = section(flow, 'const loadStageStats =', 'const retryStageStats =')
  assert.match(loader, /const seq = \+\+statsSeq/, '取数函数必须自带会话序号推进')
  assert.match(loader, /statsFailed\.value = true/, '失败必须置失败位（与空载荷区分）')
})

test('信息横幅注释不引用已删除的样式类（文档钉）', () => {
  // 断言对象是残留注释本身；剥注释后该类名消失，无法区分实现与注释。
  assert.doesNotMatch(source('src/styles/main.css'), /bound-rule-alert/)
})

test('全站直角铁律：信息横幅与产品徽章不得在类自身声明圆角', () => {
  const css = source('src/styles/main.css')
  // teleport 到 body 的宿主（ElMessageBox 根 / ElPopover popper / ElDrawer 根）
  // 不匹配 #app 与 .el-dialog__body 的直角清单——类自身若写圆角，同一 class
  // 在那些上下文会按该值生效，与全站直角裁定相反（放错宿主即突变）。
  for (const cls of ['.info-note-bar', '.v2-badge']) {
    const rule = section(css, `${cls} {`, '}')
    const rounded = rule.match(/border-radius:\s*([^;]+)/)
    assert.equal(rounded, null, `${cls} 不得在规则内声明 border-radius（当前 ${rounded?.[1] ?? ''}）`)
  }
  // 形状由直角清单统一给定：两个类必须仍在 #app 的直角枚举里。
  const appSquare = section(css, '#app :is(', ') { border-radius: 0; }')
  assert.match(appSquare, /\.info-note-bar/, '信息横幅须留在 #app 直角清单')
  assert.match(appSquare, /\.v2-badge/, '产品徽章须留在 #app 直角清单')
})

test('规则先于指标落地时保持待定，不写成采集失败', () => {
  const text = code(DASHBOARD)
  const applied = section(text, 'rules.value = res.data || []', 'const version = ++rulesVersion')
  assert.match(applied, /if \(dashboardMetricsLanded\.value\) \{[\s\S]*buildRuleMetricsUnavailable\(/)
  assert.deepEqual(buildRuleMetricsUnavailable([{ caddy_id: 'x', enabled: true }], undefined, false), { x: true }, '明确失败仍必须显示采集失败')
})

test('慢规则请求不阻塞本轮图表与资源请求', () => {
  const text = code(DASHBOARD)
  const fetchAll = section(text, 'const fetchAllData =', 'const fetchRuleHealth =')
  const settled = section(fetchAll, 'Promise.allSettled([', ']).then(() => undefined)')
  assert.doesNotMatch(settled, /request\.get\('\/rules'/)
  assert.match(fetchAll, /if \(slowLane\) fetchRulesSlowLane\(/)
  assert.match(text, /const fetchRulesSlowLane =[\s\S]*request\.get\('\/rules'/)
})

test('慢车道在途窗口保留 pending 并在收尾立即补跑', () => {
  const text = code(DASHBOARD)
  const due = section(text, 'const slowLaneDue =', 'let rulesSlowLaneInFlight')
  assert.doesNotMatch(due, /lastSlowLaneAt\s*=/, '窗口判定不得提前消费时间窗；只有真正发请求才推进')

  const slowLane = section(text, 'const fetchRulesSlowLane =', 'const fetchAllData =')
  assert.match(slowLane, /if \(rulesSlowLaneInFlight\) \{\s*pendingSlowLane = true\s*return\s*\}/, '在途期间到达的窗口必须记 pending，不得直接丢弃')
  assert.match(slowLane, /rulesSlowLaneInFlight = true\s*lastSlowLaneAt = Date\.now\(\)/, '实际发请求时才推进慢车道时间窗')
  const finallyAt = slowLane.indexOf('}).finally(() => {')
  const pendingResetAt = slowLane.indexOf('pendingSlowLane = false', finallyAt)
  const rerunAt = slowLane.indexOf('fetchRulesSlowLane()', pendingResetAt)
  assert.ok(finallyAt > 0 && pendingResetAt > finallyAt && rerunAt > pendingResetAt, '收尾必须先消费 pending 再补跑，持续失败也不得热循环')
})

test('实时流量图 tooltip 与坐标轴都标明每秒速率', () => {
  const text = code(DASHBOARD)
  assert.match(text, /const formatTrafficRate = \(value: number\): string => `\$\{formatBytes\(value\)\}\/s`/)
  const chart = section(text, 'const trafficChartOption =', 'const connChartOption =')
  assert.equal(chart.match(/formatTrafficRate/g)?.length, 2)
})

test('历史统计只有一个数据桶时显示空态而非空坐标轴', () => {
  assert.match(code(DASHBOARD), /v-if="!ruleHistoryLoading && ruleHistoryDeltas\.deltas\.length === 0"/)
})

test('任务监控首轮失败后结束加载态', () => {
  const refresh = section(code(TASK_MONITOR), 'const refreshNow =', 'onMounted')
  assert.match(refresh, /onFinally:[\s\S]*loaded\.value = true/)
})

test('任务序列失败标记陈旧，空序列显示空态', () => {
  const text = code(TASK_MONITOR)
  assert.match(text, /const seriesStale = ref\(false\)/)
  assert.match(text, /seriesStale\.value = true/)
  assert.match(text, /v-if="seriesStale && series24h\.length" class="chart-stale-hint"/)
  assert.match(text, /v-else-if="loaded && !series24h\.length"/)
})

test('任务日志缺 data 抛错，旧任务响应不得清新任务错误', () => {
  const fetch = section(code(TASK_MONITOR), 'fetch: async () =>', 'onError:')
  assert.match(fetch, /if \(!res\.data\) throw new TypeError\('任务日志响应缺少 data'\)/)
  const guardAt = fetch.indexOf('if (logsTask.value?.id !== task.id) return null')
  const clearAt = fetch.indexOf('logsLoadError.value = false')
  assert.ok(guardAt >= 0 && clearAt > guardAt, '必须先确认仍是同一任务，再清错误态')
})

test('任务手动刷新与轮询共用最新读取会话', () => {
  const text = code(TASK_MONITOR)
  assert.match(text, /createLatestReadSession/)
  const refresh = section(text, 'const refreshNow =', 'onMounted')
  assert.match(refresh, /refreshReadSession\.run/)
  assert.match(refresh, /Promise\.allSettled/)
  assert.match(text, /refreshNow\(signal\)/)
})

test('运行与取消按钮在任一任务操作在途时禁用', () => {
  const buttons = openTags(code(TASK_MONITOR), 'el-button')
  // 插槽 row 是 DefaultRow，调用点带 `as TaskInfo` 断言（不改变「收到整行」语义）。
  for (const action of ['onTrigger', 'onCancel']) {
    const button = buttons.find((tag) => new RegExp(`@click="${action}\\(row(?: as [A-Za-z]+)?\\)"`).test(tag))
    assert.ok(button, `${action}(row) 按钮必须存在`)
    assert.match(button, /taskActionPendingId !== null/)
  }
})

test('证书队列请求窗口与进程内截断共用页面常量', () => {
  const queue = section(code(TASK_MONITOR), 'const fetchCertQueue =', 'const taskFamilyCount =')
  assert.match(queue, /liveJobs\.slice\(0, CERT_QUEUE_PAGE_SIZE\)/)
})

test('永久重试冷却 null 显示原因并禁用运行', () => {
  const cooldown = section(code(TASK_MONITOR), 'const runCooldownReason =', 'const onTrigger =')
  assert.match(cooldown, /retry_cooldown_seconds === null/)
  assert.match(cooldown, /永久不可重试/)
})

test('任务词表与图表色板按自有键读取，原型键回显原值', () => {
  const text = code(TASK_MONITOR)
  assert.match(text, /import \{ hasOwn \} from '@\/utils\/hasOwn'/)
  assert.match(text, /hasOwn\(statusLabels, s\)/)
  assert.match(text, /hasOwn\(kindLabels, k\)/)
  assert.match(text, /hasOwn\(triggerLabels, t\)/)
  assert.match(text, /hasOwn\(resultLabels, r\)/)
  assert.match(text, /hasOwn\(statusColor, k\)/)
})
