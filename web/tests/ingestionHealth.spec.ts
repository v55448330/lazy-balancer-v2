// 采集健康位三面同源（事件列表/安全总览/威胁大屏）+ 后端字段契约。
// 判据/文案只允许出现在 src/utils/ingestionHealth.ts；视图只消费同一 helper。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, enclosingOpenTag, repoCode, section } from './_helpers.ts'
import { ingestionWarningMessage } from '../src/utils/ingestionHealth.ts'

const healthy = {
  observed: true,
  healthy: true,
  consecutive_failures: 0,
  task_state: 'running',
  task_running: true,
}

test('健康位正常时不提示', () => {
  assert.equal(ingestionWarningMessage(healthy), '')
  assert.equal(ingestionWarningMessage(undefined), '')
  assert.equal(ingestionWarningMessage({ observed: false, healthy: false, consecutive_failures: 0 }), '')
})

// 任务停止只暂停「尾读存量 + spool 补采 + 审计日志轮转 + 健康记账」；实时
// IPC 主路径不经任务调度，事件仍入库、自动封禁计数仍在增长。文案不得把
// 「补采任务停止」说成「事件不再更新」——用户会按错误前提做容量/排障决策。
test('任务已停 → 说明补采/轮转暂停且实时 IPC 入库仍在运行', () => {
  const message = ingestionWarningMessage({ ...healthy, healthy: false, task_state: 'stopped', task_running: false })
  assert.match(message, /任务已停止/)
  assert.doesNotMatch(message, /连续失败/)
  assert.match(message, /补采/)
  assert.match(message, /日志轮转/)
  assert.match(message, /IPC/)
  for (const claim of ['事件不再更新', '不再更新', '不再增长']) {
    assert.ok(!message.includes(claim), `任务停止不得声称「${claim}」（实时 IPC 入库仍在运行）：${message}`)
  }
})

test('健康位异常且无归因 → 不得暗示事件停更', () => {
  const message = ingestionWarningMessage({ ...healthy, healthy: false, consecutive_failures: 0 })
  assert.match(message, /补采/)
  assert.match(message, /IPC/)
  assert.ok(!message.includes('事件不再更新'), message)
})

test('自动封禁降级条兜底文案不得声称计数不增长', () => {
  const page = code('src/views/security/SecurityEvents.vue')
  assert.ok(
    !page.includes('自动封禁计数不会增长'),
    '兜底文案不得声称计数不增长（任务只停补采，实时 IPC 入库仍喂入计数器）',
  )
  assert.match(page, /实时 IPC 入库仍在运行/)
})

test('审计写侧降级 → 披露丢弃/写盘错误计数', () => {
  const message = ingestionWarningMessage({
    ...healthy,
    healthy: false,
    writer_degraded: true,
    writer_dropped: 7,
    writer_io_errors: 2,
  })
  assert.match(message, /丢弃 7 条/)
  assert.match(message, /写盘错误 2 次/)
})

test('连续失败 → 携带次数与末次错误', () => {
  const message = ingestionWarningMessage({
    ...healthy,
    healthy: false,
    consecutive_failures: 4,
    last_error: 'read offset: permission denied',
  })
  assert.match(message, /连续失败 4 次/)
  assert.match(message, /read offset: permission denied/)
})

// 判据项各自独立成立（基线 healthy=true）：写侧降级此前必须同时置 healthy=false
// 才会被测到，导致「降级」判据被删也全绿。
test('写侧降级单独成立即提示（不依赖健康位为 false）', () => {
  const message = ingestionWarningMessage({ ...healthy, writer_degraded: true })
  assert.match(message, /审计日志写侧失败/)
  assert.match(message, /累计丢弃 0 条、写盘错误 0 次/)
  // 无格式化失败时不得虚构该分项
  assert.doesNotMatch(message, /格式化失败/)
  assert.match(
    ingestionWarningMessage({ ...healthy, writer_degraded: true, writer_format_errors: 3 }),
    /格式化失败 3 次/,
  )
})

test('写侧计数不可用优先于降级（0 不等于无丢弃）', () => {
  const message = ingestionWarningMessage({ ...healthy, writer_degraded: true, writer_stats_unavailable: true })
  assert.match(message, /计数不可用/)
  assert.match(message, /不代表无丢弃/)
  assert.doesNotMatch(message, /累计丢弃/, '计数不可用时不得把 0 当成已确认无丢弃')
})

// 畸形区跳过与「曾丢失已恢复」两条文案此前零覆盖（含字节档位与逐项归因）。
// 字节精度断言按站内单源 formatBytes（1024 进制、最多两位小数去尾零）：
// 2048 → 2 KB、3 MiB → 3 MB、2 GiB → 2 GB——与日志占用条/备份大小同精度。
test('健康位异常 + 畸形区跳过：披露处数与体量（B/KB/MB/GB 各档）', () => {
  const base = { ...healthy, healthy: false, consecutive_failures: 0, skipped_regions: 3 }
  assert.match(ingestionWarningMessage({ ...base, skipped_bytes: 512 }), /跳过了 3 处畸形区（累计 512 B）/)
  assert.match(ingestionWarningMessage({ ...base, skipped_bytes: 2048 }), /2 KB/)
  assert.match(ingestionWarningMessage({ ...base, skipped_bytes: 3 * 1024 * 1024 }), /3 MB/)
  assert.match(ingestionWarningMessage({ ...base, skipped_bytes: 2 * 1024 ** 3 }), /2 GB/)
  assert.match(
    ingestionWarningMessage({ ...base, skipped_bytes: 1024, last_skip_at: '2026-10-24T01:02:03Z' }),
    /最近 2026-10-24T01:02:03Z/,
  )
  assert.match(ingestionWarningMessage({ ...base, skipped_bytes: 0 }), /永久丢失/, '跳过即永久丢失必须写明')
})

test('data_loss 单独成立：逐项列出曾丢失来源并声明已恢复', () => {
  const message = ingestionWarningMessage({
    ...healthy,
    data_loss: true,
    writer_dropped: 4,
    writer_io_errors: 2,
    writer_format_errors: 1,
    messages_dropped: 5,
    skipped_regions: 1,
    skipped_bytes: 1024,
  })
  assert.match(message, /此前曾发生安全事件丢失/)
  assert.match(message, /丢弃 4 条/)
  assert.match(message, /写盘错误 2 次/)
  assert.match(message, /格式化失败 1 次/)
  assert.match(message, /命中明细截断 5 条/)
  assert.match(message, /跳过畸形区 1 处（1 KB）/)
  assert.match(message, /当前已恢复/)
  // 无任何分项计数时不虚构数字
  assert.match(ingestionWarningMessage({ ...healthy, data_loss: true }), /计数不可用/)
})

test('仅命中明细截断不得说成事件丢失', () => {
  const message = ingestionWarningMessage({
    ...healthy,
    data_loss: true,
    messages_dropped: 819,
  })
  assert.match(message, /此前曾发生安全事件明细截断/)
  assert.match(message, /事件本身已记录/)
  assert.match(message, /命中明细截断 819 条/)
  assert.doesNotMatch(message, /事件可能缺失/)
})

test('三处视图消费同源 helper（禁止各自判定）', () => {
  for (const file of [
    'src/views/security/SecurityEvents.vue',
    'src/views/security/SecurityOverview.vue',
    'src/views/security/ThreatScreen.vue',
  ]) {
    const text = code(file)
    assert.match(text, /import \{ ingestionWarningMessage, type IngestionHealth \} from '@\/utils\/ingestionHealth'/, `${file} 必须导入同源 helper`)
    assert.match(text, /ingestionWarningMessage\(/, `${file} 必须调用同源 helper`)
    // 提示条只用全局 info-note-bar 体系（禁止新造/局部覆盖样式）。
    // 必须按「渲染 ingestionWarning 的那个元素」判类名：距离型窗口
    // （`class="info-note-bar…"[\s\S]*?ingestionWarning`）在事件页恒真——页面上
    // 有多条 info-note-bar（自动封禁/统计窗口/请求体横幅），提示条换成任意
    // 自定义类名也照样命中。
    const template = text.slice(0, text.indexOf('<script'))
    const at = template.indexOf('ingestionWarning')
    assert.ok(at > 0, `${file} 模板必须在元素上消费 ingestionWarning`)
    const bar = enclosingOpenTag(template, 'div', at)
    assert.ok(bar !== null, `${file} ingestionWarning 必须落在提示条元素内`)
    assert.match(bar, /class="info-note-bar(?: [^"]*)?"/, `${file} 提示条必须复用全局 info-note-bar 类`)
  }
})

test('总览/大屏从各自响应消费 ingestion 字段（后端同名字段）', () => {
  const overview = code('src/views/security/SecurityOverview.vue')
  assert.match(overview, /ingestion\?: IngestionHealth/)
  assert.match(overview, /ingestionWarningMessage\(overview\.value\.ingestion\)/)
  const threat = code('src/views/security/ThreatScreen.vue')
  const threatStats = section(threat, 'interface ThreatScreenStats', 'interface FeedEvent')
  assert.match(threatStats, /ingestion\?: IngestionHealth/)
  assert.match(threat, /ingestionWarningMessage\(stats\.value\?\.ingestion\)/)
})

test('前后端字段契约：Go JSON tag 覆盖前端 IngestionHealth 读取面', () => {
  const go = repoCode('internal/services/securityevents.go')
  const statusBlock = section(go, 'type SecurityEventsIngestionStatus struct', '\n}')
  for (const tag of [
    'json:"observed"',
    'json:"healthy"',
    'json:"consecutive_failures"',
    'json:"last_error,omitempty"',
    'json:"task_state"',
    'json:"task_running"',
    'json:"writer_dropped"',
    'json:"writer_io_errors"',
    'json:"writer_degraded"',
    'json:"writer_last_failure_at,omitempty"',
  ]) {
    assert.ok(statusBlock.includes(tag), `后端状态缺少 ${tag}（前端 ingestionHealth.ts 已消费）`)
  }
  // 插件侧车路径契约与根服务读取面必须同后缀（跨 Go module 无共享包）。
  const plugin = repoCode('caddygeoip/auditwriter.go')
  assert.match(plugin, /auditWriterStatsSuffix\s*=\s*"\.writer-stats\.json"/)
  assert.match(go, /securityEventsAuditWriterStatsSuffix\s*=\s*"\.writer-stats\.json"/)
})
