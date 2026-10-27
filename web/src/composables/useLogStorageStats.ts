import { ref, watch } from 'vue'
import { request } from '@/utils/api'

/** GET /logs/stats 的单行统计（服务端按 key 收窄后返回的条目）。 */
interface LogStorageInfo {
  key: string
  name: string
  size_bytes: number
  rotated_bytes: number
  rotated_count: number
  limit_bytes?: number | null
  limit_rows?: number | null
  db_bytes?: number | null
  keep_count: number
  rows?: number | null
  // 行数读取失败披露：为真时保持条数口径并标注「计数暂不可用」，不再静默
  // 退回字节口径（口径切换会让用户以为统计规则被改）。
  rows_unavailable?: boolean
  retention_note: string
  config_source: string
}

interface LogStorageTarget {
  /** 日志行键（后端统计口径的唯一标识）。 */
  logKey: string
  /** 按站点收窄的服务标识（Caddy 统计行传实例 id）。 */
  caddyId?: string
}

/**
 * 日志存储统计取数（LogStorageBar 的数据层）。
 *
 * 两类触发源语义不同：
 * - `target`（logKey / caddyId）变化 = 换了一行日志：必须**先清空**再取数。
 *   后端只返回所看那一行的统计，旧值不会被覆盖，清空是防止模板继续渲染上一条
 *   日志的名称/字节/百分比（原实现只在 refreshKey 时重取，换行靠调用方重挂
 *   组件规避——隐式契约，破坏后无声显示错行）。
 * - `refreshKey` 变化 = 同一行重取（保留/清理改变占用）：不清空，避免闪烁。
 *
 * 两个触发源合并为单个 watch：同一 tick 内换行 + 刷新号自增只发一次请求
 * （原实现两条独立 watch，并发两次 /logs/stats，序号只保证写回正确不省请求）。
 * 取数序号保证迟到响应不写回（换行后上一行的慢响应被丢弃）。
 *
 * 失败不静默：`error` 置位且保留上一次 `info`，由消费方显性呈现——失败时
 * 整条统计消失与站内「读取失败要显性」口径不一致。**成功但无该 key** 是第三种
 * 事实（`info=null` + `unavailable=true`）：同样不得让统计条整条消失，消费方
 * 须渲染「该日志暂无统计数据」。
 */
export const useLogStorageStats = (options: {
  target: () => LogStorageTarget
  refreshKey?: () => number | undefined
}) => {
  const info = ref<LogStorageInfo | null>(null)
  const error = ref<string | null>(null)
  // 「请求成功但没有所看那一行」：与取数失败（error）分开——失败可重试、
  // 缺行是事实（后端 key 词表与前端不一致 / 该日志尚未注册统计）。两者都不许
  // 让整条统计静默消失：消费方须显式呈现「暂无统计数据」。
  const unavailable = ref<boolean>(false)
  let loadStatsSeq = 0
  let lastTargetKey: string | null = null

  const targetKeyOf = (target: LogStorageTarget): string => `${target.logKey}\u0000${target.caddyId ?? ''}`

  const loadStats = async (): Promise<void> => {
    const { logKey, caddyId } = options.target()
    const seq = ++loadStatsSeq
    try {
      // 服务端按 key 收窄（只统计所看那一行）；缺省全量会为每个弹框
      // 做全部 DB 计数与目录统计。
      const params: Record<string, string> = { key: logKey }
      if (caddyId) params.caddy_id = caddyId
      // silent：失败由本组合子置 error 位、消费方条内呈现「统计暂不可用」——
      // 不 silent 会同时弹全局错误 toast，同一失败两处不同措辞。
      const res = await request.get<{ data?: { logs?: LogStorageInfo[] } }>('/logs/stats', { params, silent: true })
      if (seq === loadStatsSeq) {
        const matched = res.data?.logs?.find((l) => l.key === logKey) ?? null
        info.value = matched
        unavailable.value = matched === null
        error.value = null
      }
    } catch (e) {
      if (seq === loadStatsSeq) {
        error.value = e instanceof Error ? e.message : '日志统计取数失败'
        // 失败是「本轮结果」，缺行标记随之作废：消费方按 error 呈现重试口径，
        // 不得同时挂「暂无统计数据」（两者含义不同）。
        unavailable.value = false
        console.error('Failed to load log stats:', e)
      }
    }
  }

  watch(
    () => [targetKeyOf(options.target()), options.refreshKey?.()] as const,
    ([nextTarget]) => {
      if (nextTarget !== lastTargetKey) {
        lastTargetKey = nextTarget
        // 换行 = 上一条日志的一切展示状态都过期：值与错误位一起清空。
        // 只清值会让新行取数期间顶着上一行的「统计暂不可用」提示
        // （失败位原本只在成功/失败回包时改写）。
        info.value = null
        error.value = null
        unavailable.value = false
      }
      void loadStats()
    },
    { immediate: true },
  )

  return { info, error, unavailable }
}
