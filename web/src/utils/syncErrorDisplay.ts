// apply_ok_reload_failed 机内标记的展示层翻译——
// 此前 ClusterSlavePanel/ClusterStatusCard 双份拷贝(后端调整标记格式
// 须双处同步,漂移风险),收敛为单一实现(空守卫口径取 Card 版)。
import { tSafe as t } from '../i18n/tSafe.ts'

const RELOAD_FAILURE_MARKER_PREFIX = 'apply_ok_reload_failed'
// 展示段经 tSafe 词条安全 t():解析段(FAILURE_COUNT_PATTERN)钉后端 zh 契约原文,
// 不得词条化——它是跨栈解析契约,不是展示串。
const FAILURE_COUNT_PATTERN = /已连续 (\d+) 次/

export function formatSyncErrorDisplay(
  status: { last_sync_error?: string | null; sync_error_code?: string | null } | null | undefined,
): string {
  const message = status?.last_sync_error ?? ''
  if (!status || status.sync_error_code !== 'apply_failed' || !message.includes(RELOAD_FAILURE_MARKER_PREFIX)) {
    return message
  }
  const countMatch = message.match(FAILURE_COUNT_PATTERN)
  const retryPart = countMatch ? t('common.app.views.sysOps.syncRetryCount', { n: countMatch[1] }) : ''
  const reasonSegment = message.split(' | ')[0]
  const reason = reasonSegment
    .replace(`${RELOAD_FAILURE_MARKER_PREFIX}: `, '')
    .replace(RELOAD_FAILURE_MARKER_PREFIX, '')
    .trim()
  return t('common.app.views.sysOps.syncReloadFailed') + retryPart + (reason ? t('common.app.views.sysOps.syncReasonSuffix', { reason }) : '')
}
