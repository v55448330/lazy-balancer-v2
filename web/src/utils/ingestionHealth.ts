// 采集健康位（后端 services.SecurityEventsIngestionStatus 的镜像）。
// 事件列表 / 安全总览 / 威胁大屏三处同源消费：是否需要提示、提示什么文案
// 只在此处定义，禁止各视图自造判据（口径分叉会让同一后端状态在不同页面
// 呈现不同结论）。字段名与后端 JSON tag 逐字对应。
//
// 字节数人类可读走站内单源 formatBytes（与日志占用条/备份大小/仪表盘同精度）；
// 本模块原持私有 humanBytes（一位小数、上限 GB），同一量级在两处显示不同精度。
import { formatBytes as humanBytes } from './formatBytes.ts'
// 提示文案走 i18n（批次 D ingest 域）：键形与 zh 母本原文由 ingestionHealth.spec
// 双钉承载；判据不动，仅文案改词条参数化。
import { tSafe as t } from '../i18n/tSafe.ts'

export interface IngestionHealth {
  observed: boolean
  healthy: boolean
  consecutive_failures: number
  last_error?: string
  last_error_at?: string
  last_success_at?: string
  task_state?: string
  task_running?: boolean
  writer_dropped?: number
  writer_io_errors?: number
  // 写侧 formatter 契约失败（代码/缺陷方向，与磁盘故障分开披露）。
  writer_format_errors?: number
  writer_degraded?: boolean
  writer_last_failure_at?: string
  writer_stats_unavailable?: boolean
  // 写侧单行上限截断掉的规则命中条数：事件在库，命中明细永久缺失。
  messages_dropped?: number
  // 摄取侧「畸形区跳过」：跳过即该段审计数据对应事件永久丢失，窗口内发生
  // 跳过时后端置 healthy=false（与写侧失败同一位）。
  skipped_bytes?: number
  skipped_regions?: number
  last_skip_at?: string
  data_loss?: boolean
}

/** 整条事件丢失来源（写侧丢弃/写盘/格式化/畸形区跳过）。 */
function eventLossParts(status: IngestionHealth): string[] {
  const parts: string[] = []
  if ((status.writer_dropped ?? 0) > 0) parts.push(t('common.app.views.ingest.lossDropped', { count: status.writer_dropped }))
  if ((status.writer_io_errors ?? 0) > 0) parts.push(t('common.app.views.ingest.lossIoErrors', { count: status.writer_io_errors }))
  if ((status.writer_format_errors ?? 0) > 0) parts.push(t('common.app.views.ingest.lossFormatErrors', { count: status.writer_format_errors }))
  if ((status.skipped_regions ?? 0) > 0) parts.push(t('common.app.views.ingest.lossSkippedRegions', { count: status.skipped_regions, size: humanBytes(status.skipped_bytes ?? 0) }))
  return parts
}

/** 命中明细截断：事件本身在库，只缺部分规则命中明细。 */
function detailLossParts(status: IngestionHealth): string[] {
  return (status.messages_dropped ?? 0) > 0 ? [t('common.app.views.ingest.lossDetailTruncated', { count: status.messages_dropped })] : []
}

/**
 * 丢失事实披露（data_loss 成立时）：区分「整条事件丢失」与「事件在库但规则命中
 * 明细被截断」。独立成段供「任务已停 + 曾丢失」与「单独曾丢失」两分支共用——
 * 任务停止不得掩蔽同帧的永久丢失事实（停止只暂停补采/轮转，丢失是另一回事）。
 */
function lossDisclosureMessage(status: IngestionHealth): string {
  const eventParts = eventLossParts(status)
  const detailParts = detailLossParts(status)
  if (eventParts.length === 0 && detailParts.length > 0) {
    return t('common.app.views.ingest.detailTruncatedOnly', { parts: detailParts.join('、') })
  }
  const parts = [...eventParts, ...detailParts]
  const detailSuffix = detailParts.length > 0 ? t('common.app.views.ingest.detailLossSuffix') : ''
  return t('common.app.views.ingest.dataLoss', { parts: parts.join('、') || t('common.app.views.ingest.lossPartsUnavailable'), suffix: detailSuffix })
}

/** 统一提示文案（空串 = 不提示）：判据与文案同源，三处视图只调这一个函数。 */
export function ingestionWarningMessage(status?: IngestionHealth | null): string {
  if (!status) return ''
  const needsAttention = status.task_state === 'stopped'
    || status.writer_degraded === true
    || status.writer_stats_unavailable === true
    || status.data_loss === true
    || (status.observed === true && status.healthy === false)
  if (!needsAttention) return ''
  if (status.task_state === 'stopped') {
    // 任务只拥有「尾读存量 + spool 补采 + 审计日志轮转 + 健康记账」；实时 IPC
    // 主路径不经调度，事件仍入库。文案不得说成「事件不再更新」。
    const stopped = t('common.app.views.ingest.taskStopped')
    // 同帧 data_loss=true（曾永久丢失）不得被「任务已停」掩蔽——停止与丢失是
    // 两件事，追加丢失披露段（与单独 data_loss 分支同一单源）。
    return status.data_loss === true ? `${stopped}${t('common.app.views.ingest.lossWhileStopped', { detail: lossDisclosureMessage(status) })}` : stopped
  }
  if (status.writer_stats_unavailable === true) {
    return t('common.app.views.ingest.writerStatsUnavailable')
  }
  if (status.writer_degraded === true) {
    const format = status.writer_format_errors ?? 0
    const formatPart = format > 0 ? t('common.app.views.ingest.writerDegradedFormatPart', { count: format }) : ''
    const hint = format > 0
      ? t('common.app.views.ingest.writerDegradedFormatHint')
      : t('common.app.views.ingest.writerDegradedHint')
    return t('common.app.views.ingest.writerDegraded', {
      dropped: status.writer_dropped ?? 0,
      io: status.writer_io_errors ?? 0,
      formatPart,
      hint,
    })
  }
  if (status.observed === true && status.healthy === false) {
    const failures = status.consecutive_failures ?? 0
    if (failures > 0) {
      const detail = status.last_error ? t('common.app.views.ingest.lastErrorSuffix', { error: status.last_error }) : ''
      return t('common.app.views.ingest.consecutiveFailures', { failures, detail })
    }
    if ((status.skipped_regions ?? 0) > 0) {
      const lastSkip = status.last_skip_at ? t('common.app.views.ingest.skipLastSuffix', { at: status.last_skip_at }) : ''
      return t('common.app.views.ingest.skippedRegions', {
        regions: status.skipped_regions,
        size: humanBytes(status.skipped_bytes ?? 0),
        lastSkip,
      })
    }
    // 后端健康位为 false 但前端已知归因均不成立：不虚构「连续失败 0 次」，
    // 也不得暗示事件停更（实时 IPC 入库不经该任务调度）。
    return t('common.app.views.ingest.healthAnomaly')
  }
  // data_loss 单独成立（当前已恢复但曾丢失）：披露段与「任务已停 + 曾丢失」共用单源。
  return lossDisclosureMessage(status)
}
