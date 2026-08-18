import { useAuthStore } from '@/stores/auth'

// 与后端 COALESCE 默认一致的兜底时区：备份导入/集群同步路径可能写入未校验的 tz（如 "GMT+8"），
// 非法值会使 Intl.DateTimeFormat 抛 RangeError，导致所有 formatDate 调用点渲染崩溃（D-1）。
const DEFAULT_TZ = 'Asia/Shanghai'
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

const tzFormat = (timeZone: string, withTime: boolean): Intl.DateTimeFormat =>
  new Intl.DateTimeFormat('en-US', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    ...(withTime ? { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false } : {}),
  })

// 模块级 formatter 缓存（S-01）：Dashboard 每轮询对 60 点 × 2 图表调用 tzFormatter，
// 每 5s 约构造 120 个 Intl.DateTimeFormat（Intl 构造带 locale 数据解析，纯函数重复计算）。
// key = `${tz}|${withTime}`；只缓存成功构造的实例，非法 tz 回退路径不受影响（回退后同样走缓存）。
const tzFormatterCache = new Map<string, Intl.DateTimeFormat>()

// 共享的受保护格式化器（D-1）：非法配置时区使 Intl 构造抛 RangeError 时回退 DEFAULT_TZ，
// warnedInvalidTz 防止 warn 刷屏。所有 tz 格式化调用点必须经此入口，不得直接 new Intl.DateTimeFormat。
const tzFormatter = (withTime: boolean): Intl.DateTimeFormat => {
  const tz = configTz()
  const cacheKey = `${tz}|${withTime}`
  const cached = tzFormatterCache.get(cacheKey)
  if (cached) return cached
  try {
    const formatter = tzFormat(tz, withTime)
    tzFormatterCache.set(cacheKey, formatter)
    return formatter
  } catch {
    if (!warnedInvalidTz) {
      warnedInvalidTz = true
      console.warn(`[date] 无效的配置时区「${tz}」，已回退为「${DEFAULT_TZ}」`)
    }
    return tzFormat(DEFAULT_TZ, withTime)
  }
}

const formatInConfigTz = (d: Date, withTime: boolean): string => {
  const parts = tzFormatter(withTime).formatToParts(d)
  const get = (type: string) => parts.find((p) => p.type === type)?.value ?? ''
  const date = `${get('year')}-${get('month')}-${get('day')}`
  if (!withTime) return date
  return `${date} ${get('hour')}:${get('minute')}:${get('second')}`
}

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null

const parseDateValue = (date: unknown): Date | null => {
  if (!date) return null
  if (isRecord(date) && date.Valid === false) return null
  let raw: unknown = date
  if (isRecord(date) && typeof date.String === 'string' && date.String) raw = date.String
  if (isRecord(date) && typeof date.Time === 'string' && date.Time) raw = date.Time
  if (typeof raw !== 'string') return null
  // DB datetimes ("2026-08-11 08:23:21") are stored in UTC; normalize to explicit UTC ISO
  const normalized = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})?$/.test(raw) ? raw.replace(' ', 'T') + 'Z' : raw
  if (!isIsoLike(normalized)) return null
  const d = new Date(normalized)
  return isNaN(d.getTime()) ? null : d
}

export const formatDate = (date: unknown): string => {
  const d = parseDateValue(date)
  if (d) return formatInConfigTz(d, true)
  if (typeof date === 'string' && date) return date
  if (isRecord(date) && typeof date.String === 'string' && date.String) return date.String
  return ''
}

export const formatDateShort = (date: unknown): string => {
  const d = parseDateValue(date)
  if (d) return formatInConfigTz(d, false)
  if (typeof date === 'string' && date) return date
  if (isRecord(date) && typeof date.String === 'string' && date.String) return date.String
  return ''
}

// Dashboard 图表轴标签（HH:mm:ss），经 tzFormatter 受保护入口（BUG-01）：
// 非法配置时区回退 DEFAULT_TZ，不再在 ECharts computed 中抛 RangeError。
export const formatChartTimeInConfigTz = (ms: number): string => {
  const parts = tzFormatter(true).formatToParts(new Date(ms))
  const get = (type: string) => parts.find((p) => p.type === type)?.value ?? ''
  return `${get('hour')}:${get('minute')}:${get('second')}`
}
