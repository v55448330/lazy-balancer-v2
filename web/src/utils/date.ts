import { useAuthStore } from '@/stores/auth'

const configTz = (): string => {
  try {
    return useAuthStore().timezone || 'Asia/Shanghai'
  } catch {
    return 'Asia/Shanghai'
  }
}

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
  if (typeof raw === 'string' && !isIsoLike(raw)) return null
  if (typeof raw !== 'string') return null
  const d = new Date(raw)
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
