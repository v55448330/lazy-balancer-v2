import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, codeSection, member, section } from './_helpers.ts'
import { clampPassiveHealthCheckTimeout } from '../src/utils/ruleWizard.ts'

const page = code('src/views/Rules.vue')

// 模板标记定位改为「容错正则 + 显式失败」——原实现把 el-divider
// 的完整 class 串（含属性顺序）当起点，纯样式调整即假红/截错段。
const markerIndex = (text: string, pattern: RegExp, what: string): number => {
  const at = text.search(pattern)
  assert.ok(at >= 0, `missing ${what}`)
  return at
}

/** 以正则定位起点、以字符串定位终点（终点必须晚于起点）。 */
const sectionFrom = (startPattern: RegExp, endMarker: string, what: string): string => {
  const start = markerIndex(page, startPattern, what)
  const end = page.indexOf(endMarker, start + 1)
  assert.ok(end > start, `missing end marker ${endMarker} after ${what}`)
  return page.slice(start, end)
}

test('健康检查超时只属于主动探测（HTTP/TCP 均隐藏在被动模式）', () => {
  // TCP 段起点必须从「健康检查」分隔符之后取首个 TCP 标记——原实现
  // 从页面头 indexOf，命中的是上游表协议列（:549），随后 enable_active 标记又
  // 命中 HTTP 段（:698），断言对象整体错位（钉空转）。
  const healthStart = markerIndex(page, /<el-divider[^>]*>健康检查<\/el-divider>/, '健康检查分隔符')
  const healthEnd = page.indexOf('<div v-show="currentStep === WIZARD_STEP.CUSTOM_ROUTES"', healthStart)
  assert.ok(healthEnd > healthStart, 'missing custom routes step marker')
  const healthBlock = page.slice(healthStart, healthEnd)
  const activeMarker = '<template v-if="wizardForm.enable_active_health_check">'
  const tcpRel = markerIndex(healthBlock, /<template\s+v-if="wizardForm\.protocol === 'tcp'">/, 'TCP 健康检查段')
  assert.ok(tcpRel > 0, 'TCP 健康检查段必须在健康检查分隔符之后')

  const httpHealth = healthBlock.slice(0, tcpRel)
  const httpActiveAt = httpHealth.indexOf(activeMarker)
  assert.ok(httpActiveAt > 0, 'missing HTTP active health section')
  const httpActive = httpHealth.slice(httpActiveAt)
  assert.match(httpActive, /健康检查超时时间|health_check_timeout/)
  const beforeHttpActive = httpHealth.slice(0, httpActiveAt)
  assert.doesNotMatch(beforeHttpActive, /v-model="wizardForm\.health_check_timeout"/)
  assert.match(httpActive, /主动探测超时/)

  const tcpHealth = healthBlock.slice(tcpRel)
  const tcpActiveStart = tcpHealth.indexOf(activeMarker)
  assert.ok(tcpActiveStart > 0, 'missing TCP active health section')
  const tcpActive = tcpHealth.slice(tcpActiveStart)
  const beforeTcpActive = tcpHealth.slice(0, tcpActiveStart)
  // 独立断言：TCP 被动段（开关 + 提示）不得出现超时输入。
  assert.doesNotMatch(beforeTcpActive, /v-model="wizardForm\.health_check_timeout"/)
  assert.match(tcpActive, /v-model="wizardForm\.health_check_timeout"/)
  assert.match(tcpActive, /主动探测超时/)
  // 锚点自证：TCP 主动段必须含 TCP 专属的检查端口字段（HTTP 主动段没有），
  // 否则说明切段又错位到 HTTP。
  assert.match(tcpActive, /tcp_health_check_port/)
})

test('被动健康检查预览不再宣称超时语义', () => {
  // 预览健康检查行改由 utils/healthCheckSummary 单源生成（阈值与预览同处可见）
  const wizardPreview = sectionFrom(
    /<el-descriptions-item[^>]*label="健康检查"[^>]*>/,
    '<el-descriptions-item label="连接重试"',
    '向导预览健康检查描述项',
  )
  assert.match(wizardPreview, /\{\{ healthCheckSummary\(wizardForm\) \}\}/, '预览必须走健康摘要单源')
  const helper = code('src/utils/healthCheckSummary.ts')
  const passive = section(helper, 'export function passiveHealthCheckSummary', 'export function healthCheckSummary')
  assert.doesNotMatch(passive, /超时/, '被动摘要不得宣称超时语义')
  assert.match(passive, /恢复窗口/)
  const configViewer = section(page, '<el-descriptions-item label="被动健康检查"', '</el-descriptions-item>')
  assert.doesNotMatch(configViewer, /超时/)
  assert.match(configViewer, /passiveHealthCheckSummary\(ruleConfig\)/)
})

test('配置预览的主动健康检查判据是 enable_active_health_check', () => {
  // 查看器的主动行以 enable_active_health_check 判定（不是「path 非空」这类推断），
  // 且主动/被动互斥——主动开启时不再重复打印被动行。
  const preview = sectionFrom(
    /<el-descriptions-item[^>]*label="主动健康检查"[^>]*>/,
    '<el-descriptions-item label="连接重试"',
    '配置预览主动健康检查描述项',
  )
  assert.match(preview, /v-if="ruleConfig\.enable_active_health_check"/)
  assert.match(preview, /activeHealthCheckSummary\(ruleConfig\)/)
  assert.match(preview, /<el-descriptions-item label="主动健康检查" v-else>未启用<\/el-descriptions-item>/)
  assert.match(preview, /v-if="!ruleConfig\.enable_active_health_check"/)
  assert.doesNotMatch(preview, /health_check_path \|\| '\/'/, '口径不得在模板里再写一份')
  // 失败/恢复阈值都在主动摘要里（预览曾只给 path/interval/timeout）
  const active = section(code('src/utils/healthCheckSummary.ts'), 'export function activeHealthCheckSummary', 'export function passiveHealthCheckSummary')
  assert.match(active, /health_check_unhealthy_threshold/)
  assert.match(active, /health_check_healthy_threshold/)
})

test('开启 TCP 主动检查不再自动写首上游端口（0=按各上游自身端口）', () => {
  const watcher = section(page, 'watch(() => wizardForm.enable_active_health_check', 'DEFAULT_DEPLOYMENT_ADMIN_PORTS')
  assert.doesNotMatch(watcher, /tcp_health_check_port = firstUpstream\.port/)
  assert.doesNotMatch(watcher, /firstUpstream/)
  assert.match(watcher, /health_check_path = '\/'/)
})

test('被动模式下隐藏的超时字段越界时保存前钳到合法值', () => {
  // 值域：后端 validateRuleFeatures 要求 0<timeout<interval（不区分主动/被动），
  // 而被动模式不渲染 timeout 输入（被动模式）——存量越界值原本会撞上无处修改
  // 的校验提示。钳制只处理被动模式能自解的区间，其余形态交回原校验。
  assert.deepEqual(clampPassiveHealthCheckTimeout(10, 10), { timeout: 9, clamped: true })
  assert.deepEqual(clampPassiveHealthCheckTimeout(10, 30), { timeout: 9, clamped: true })
  assert.deepEqual(clampPassiveHealthCheckTimeout(5, 2), { timeout: 2, clamped: false }, '合法值不得改动')
  assert.deepEqual(clampPassiveHealthCheckTimeout(1, 1), { timeout: 1, clamped: false }, '无合法解时不得代改')
  assert.deepEqual(clampPassiveHealthCheckTimeout(Number.NaN, 5), { timeout: 5, clamped: false })
  // 生产接线：submitWizard 在 timeout>=interval 校验之前、仅被动模式钳制。
  const submit = section(page, 'const submitWizard = async', 'const allowedProtocols')
  const passiveAt = submit.indexOf('if (!wizardForm.enable_active_health_check) {')
  const clampAt = submit.indexOf('clampPassiveHealthCheckTimeout(wizardForm.health_check_interval, wizardForm.health_check_timeout)')
  const timeoutRuleAt = submit.indexOf('wizardForm.health_check_timeout >= wizardForm.health_check_interval')
  assert.ok(passiveAt > 0, '缺被动模式分支')
  assert.ok(clampAt > passiveAt, '被动模式分支必须调用钳制')
  assert.ok(timeoutRuleAt > clampAt, '钳制必须先于 timeout>=interval 校验（否则仍被拦下）')
  assert.match(submit.slice(clampAt, timeoutRuleAt), /wizardForm\.health_check_timeout = clampedTimeout\.timeout/)
})

test('零启用上游的启用态规则在健康列显示「未发布」信息态徽标', () => {
  // 渲染层对零启用上游的规则跳过发布（warn+跳过），列表若与「已禁用」同显示「-」，
  // 用户无法区分「未生效」与「已关闭」。徽标与健康 popover 互斥（v-else-if），
  // 判据复用既有 getEnabledUpstreams（启用≠false，与后端 Enabled 同口径）。
  const healthColumn = section(page, '<el-table-column label="健康"', '<el-table-column label="更新者"')
  assert.match(healthColumn, /v-if="row\.enabled && Array\.isArray\(row\.upstreams\) && getEnabledUpstreams\(row(?: as [A-Za-z]+)?\)\.length === 0"/)
  assert.match(healthColumn, /未发布/)
  assert.match(healthColumn, /<el-popover v-else-if="row\.enabled && healthStatus\[row\.caddy_id\]"/, '徽标与健康 popover 必须互斥')
})

test('规则更新成功后展示后端 data.warnings（可用性变更不能只进 toast）', () => {
  // 后端在改域等场景把「保存成功后马上会遇到的故障」（旧证书弃用、签发完成前
  // HTTPS 不可用）放在 data.warnings。只弹成功 toast 等于没告知——这里钉住
  // 消费接线：读取 data.warnings，并在弹框里逐条成行展示。
  const wizard = codeSection('src/views/Rules.vue', 'const submitWizard', '\n// ── 规则处理流程弹框')
  assert.match(wizard, /request\.put<APIResponse<\{ warnings\?: string\[\] \}>>\(/, '更新必须声明 warnings 载荷')
  assert.match(wizard, /submitWarnings = updateRes\.data\?\.warnings \?\? \[\]/, '必须读取后端 warnings')
  assert.match(wizard, /if \(submitWarnings\.length > 0\) \{/, '有披露时才弹框（无披露不打扰）')
  // 披露必须逐条成行：断言挂在 alert 的首参上（条件块内按块配对取段），
  // 距离窗口只证明「两段文字在同页且相距 ≤220 字符」——文案换到别的元素/别处
  // 的 `submitWarnings.map` 仍会绿。
  const disclosure = member(wizard, 'if (submitWarnings.length > 0) {')
  assert.match(disclosure, /ElMessageBox\.alert\(\s*h\('div', submitWarnings\.map\(/, '披露必须逐条展示（alert 消息由 warnings 逐条生成）')
})
