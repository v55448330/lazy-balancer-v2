import { useAuthStore } from '@/stores/auth'
// 与后端 COALESCE 默认一致的兜底时区与格式化器单源：抽到无依赖
// 模块供 node 行为测试直测 h23 口径；本文件保留缓存/回退策略。
import { DEFAULT_TZ, createTzFormatter, formatDateParts, normalizeDbWallClock, parseDbDateMs } from '@/utils/timeZoneFormat'

let warnedInvalidTz = false

const configTz = (): string => {
  try {
    return useAuthStore().timezone || DEFAULT_TZ
  } catch {
    return DEFAULT_TZ
  }
}

// 时间筛选口径：el-date-picker 以 value-format="YYYY-MM-DD HH:mm:ss" 产出的墙钟字符串按
// 「浏览器本地时区」生成（element-plus 无 timezone 配置项），后端按「配置时区」解析
// （auditlog.go / security.go 的 parseBoundary → ParseInLocation(configTz) 转 UTC 比较）。
// 仅当浏览器时区 == 配置时区（典型同机房部署）时与展示侧 formatInConfigTz 口径一致；
// 管理员跨时区访问时筛选边界存在系统性偏移（已知限制），根治需改为 RFC3339 传参并同步后端解析契约。

const isIsoLike = (value: string): boolean => value.includes('T') || value.endsWith('Z') || /[+-]\d{2}:?\d{2}$/.test(value)

// 模块级 formatter 缓存：Dashboard 每轮询对 60 点 × 2 图表调用 tzFormatter，
// 每 5s 约构造 120 个 Intl.DateTimeFormat（Intl 构造带 locale 数据解析，纯函数重复计算）。
// key = `${tz}|${withTime}`；只缓存成功构造的实例，非法 tz 回退路径不受影响（回退后同样走缓存）。
const tzFormatterCache = new Map<string, Intl.DateTimeFormat>()

// 共享的受保护格式化器：非法配置时区使 Intl 构造抛 RangeError 时回退 DEFAULT_TZ，
// warnedInvalidTz 防止 warn 刷屏。所有 tz 格式化调用点必须经此入口，不得直接 new Intl.DateTimeFormat。
const tzFormatter = (withTime: boolean): Intl.DateTimeFormat => {
  const tz = configTz()
  const cacheKey = `${tz}|${withTime}`
  const cached = tzFormatterCache.get(cacheKey)
  if (cached) return cached
  try {
    const formatter = createTzFormatter(tz, withTime)
    tzFormatterCache.set(cacheKey, formatter)
    return formatter
  } catch {
    if (!warnedInvalidTz) {
      warnedInvalidTz = true
      console.warn(`[date] 无效的配置时区「${tz}」，已回退为「${DEFAULT_TZ}」`)
    }
    // 回退后同样走缓存：避免每次调用都重建 DEFAULT_TZ 实例
    const fallbackKey = `${DEFAULT_TZ}|${withTime}`
    const fallback = tzFormatterCache.get(fallbackKey) ?? createTzFormatter(DEFAULT_TZ, withTime)
    tzFormatterCache.set(fallbackKey, fallback)
    // 非法键同样缓存回退实例：后续调用命中缓存，不再重复构造/抛 RangeError
    tzFormatterCache.set(cacheKey, fallback)
    return fallback
  }
}

const formatInConfigTz = (d: Date, withTime: boolean): string =>
  formatDateParts(d, tzFormatter(withTime), withTime)

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null

const parseDateValue = (date: unknown): Date | null => {
  if (!date) return null
  // 后端契约统一为 *string / JSONNullTime（RFC3339 字符串或 null），无 sql.Null* 包装对象；
  // 对未知对象形状保持宽容防御，一律按空处理
  if (isRecord(date) || typeof date !== 'string') return null
  // DB datetimes ("2026-08-11 08:23:21") are stored in UTC; normalize to explicit UTC ISO
  const normalized = normalizeDbWallClock(date)
  if (!isIsoLike(normalized)) return null
  const d = new Date(normalized)
  return isNaN(d.getTime()) ? null : d
}

/**
 * 站内时间戳有两族，格式化入口不得混用：
 * - **UTC 存储族**（后端以 UTC 落库 / RFC3339 下发）：audit_logs、cert_jobs、
 *   cluster nodes、security_events 等——用本文件的 formatDate/formatDateShort，
 *   经配置时区换算展示。
 * - **配置时区墙钟族**（后端按配置时区写「无时区」串，不做换算）：task_runs
 *   的 started_at/finished_at、任务日志时间戳。这类串交给 formatDate 会被当作
 *   UTC 再换算一次（曾实证任务时间整体 +8h），必须原样展示（TaskMonitor 的
 *   fmtTime 即此口径）。
 * 新增调用点前先确认该字段属于哪一族；不明确时按后端的存储语义查，不要凭字段
 * 名猜。
 */
export const formatDate = (date: unknown): string => {
  const d = parseDateValue(date)
  if (d) return formatInConfigTz(d, true)
  if (typeof date === 'string' && date) return date
  return ''
}

export const formatDateShort = (date: unknown): string => {
  const d = parseDateValue(date)
  if (d) return formatInConfigTz(d, false)
  if (typeof date === 'string' && date) return date
  return ''
}

// DB 墙钟串（"YYYY-MM-DD HH:mm:ss"，UTC 存储）→ epoch ms。
// 规范化与解析在内核 utils/timeZoneFormat.parseDbDateMs（单一实现）；此处只叠
// isIsoLike 白名单——本入口的语义是「DB 时间串」，不是「任意 Date 可解析文本」，
// 仅日期形态（"2026-08-11"）一律返回 null（对账/冷却判定的调用方按缺失兜底）。
// 解析失败返回 null，调用方自行兜底。
export const parseDbTimeMs = (date: unknown): number | null => {
  if (!date || typeof date !== 'string') return null
  const normalized = normalizeDbWallClock(date)
  if (!isIsoLike(normalized)) return null
  return parseDbDateMs(normalized)
}

// Dashboard 图表轴标签（HH:mm:ss），经 tzFormatter 受保护入口
// 非法配置时区回退 DEFAULT_TZ，不再在 ECharts computed 中抛 RangeError。
export const formatChartTimeInConfigTz = (ms: number): string => {
  const parts = tzFormatter(true).formatToParts(new Date(ms))
  const get = (type: string) => parts.find((p) => p.type === type)?.value ?? ''
  return `${get('hour')}:${get('minute')}:${get('second')}`
}

// 统计起点标签（仪表盘规则卡「统计自 …」）：epoch Unix 秒按配置时区渲染。
// 同一时刻与配置时区「今天」同日 → HH:MM；跨日 → MM-DD HH:MM（长期不重载
// 时避免「统计自 14:32」无法判定是哪一天）。经 tzFormatter 受保护入口，
// 与同卡图表轴同一时区口径（跨时区管理员不得出现两个钟面）。
export const formatEpochStatLabel = (unixSeconds: number, nowMs: number): string => {
  const d = new Date(unixSeconds * 1000)
  const fmt = tzFormatter(true)
  const parts = (date: Date) => {
    const p = fmt.formatToParts(date)
    const get = (type: string) => p.find((x) => x.type === type)?.value ?? ''
    return { year: get('year'), month: get('month'), day: get('day'), hour: get('hour'), minute: get('minute') }
  }
  const t = parts(d)
  const now = parts(new Date(nowMs))
  const hm = `${t.hour}:${t.minute}`
  return t.year === now.year && t.month === now.month && t.day === now.day ? hm : `${t.month}-${t.day} ${hm}`
}
