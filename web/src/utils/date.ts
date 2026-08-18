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

const formatInConfigTz = (d: Date, withTime: boolean): string => {
  const tz = configTz()
  let formatter: Intl.DateTimeFormat
  try {
    formatter = tzFormat(tz, withTime)
  } catch {
    if (!warnedInvalidTz) {
      warnedInvalidTz = true
      console.warn(`[date] 无效的配置时区「${tz}」，已回退为「${DEFAULT_TZ}」`)
    }
    formatter = tzFormat(DEFAULT_TZ, withTime)
  }
  const parts = formatter.formatToParts(d)
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
