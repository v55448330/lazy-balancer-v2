// FE18-4(第 18 轮):apply_ok_reload_failed 机内标记的展示层翻译——
// 此前 ClusterSlavePanel/ClusterStatusCard 双份拷贝(后端调整标记格式
// 须双处同步,漂移风险),收敛为单一实现(空守卫口径取 Card 版)。
const RELOAD_FAILURE_MARKER_PREFIX = 'apply_ok_reload_failed'
const FAILURE_COUNT_PATTERN = /已连续 (\d+) 次/

export function formatSyncErrorDisplay(
  status: { last_sync_error?: string | null; sync_error_code?: string | null } | null | undefined,
): string {
  const message = status?.last_sync_error ?? ''
  if (!status || status.sync_error_code !== 'apply_failed' || !message.includes(RELOAD_FAILURE_MARKER_PREFIX)) {
    return message
  }
  const countMatch = message.match(FAILURE_COUNT_PATTERN)
  const retryPart = countMatch ? `（第 ${countMatch[1]} 次）` : ''
  const reasonSegment = message.split(' | ')[0] ?? message
  const reason = reasonSegment
    .replace(`${RELOAD_FAILURE_MARKER_PREFIX}: `, '')
    .replace(RELOAD_FAILURE_MARKER_PREFIX, '')
    .trim()
  return `配置已同步但 Caddy 重载失败，系统将自动重试${retryPart}${reason ? `：${reason}` : ''}`
}
