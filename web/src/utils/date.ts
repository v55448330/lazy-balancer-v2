import { useAuthStore } from '@/stores/auth'

const configTz = (): string => {
  try {
    return useAuthStore().timezone || 'Asia/Shanghai'
  } catch {
    return 'Asia/Shanghai'
  }
}

// 时间筛选口径：el-date-picker 以 value-format="YYYY-MM-DD HH:mm:ss" 产出的墙钟字符串按「配置时区」
// 被后端解析（auditlog.go / security.go 的 parseBoundary → ParseInLocation(configTz) 转 UTC 比较），
// 与下方 formatInConfigTz 的展示口径一致（同为配置时区墙钟），两侧单次换算、口径统一，无需前端换算。

const isIsoLike = (value: string): boolean => value.includes('T') || value.endsWith('Z') || /[+-]\d{2}:?\d{2}$/.test(value)

const formatInConfigTz = (d: Date, withTime: boolean): string => {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: configTz(),
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    ...(withTime ? { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false } : {}),
  }).formatToParts(d)
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
