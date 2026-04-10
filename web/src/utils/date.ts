export const formatDate = (date: any): string => {
  if (!date) return ''
  if (typeof date === 'object' && 'Valid' in date && date.Valid === false) {
    return ''
  }
  if (typeof date === 'string') {
    const d = new Date(date)
    if (isNaN(d.getTime())) return ''
    return d.toLocaleString()
  }
  if (date && typeof date === 'object' && 'String' in date && date.String) {
    const d = new Date(date.String)
    if (isNaN(d.getTime())) return ''
    return d.toLocaleString()
  }
  if (date && typeof date === 'object' && 'Time' in date && date.Time) {
    const d = new Date(date.Time)
    if (isNaN(d.getTime())) return ''
    return d.toLocaleString()
  }
  return ''
}

export const formatDateShort = (date: any): string => {
  if (!date) return ''
  if (typeof date === 'object' && 'Valid' in date && date.Valid === false) {
    return ''
  }
  if (typeof date === 'string') {
    const d = new Date(date)
    if (isNaN(d.getTime())) return ''
    return d.toLocaleDateString()
  }
  if (date && typeof date === 'object' && 'String' in date && date.String) {
    const d = new Date(date.String)
    if (isNaN(d.getTime())) return ''
    return d.toLocaleDateString()
  }
  if (date && typeof date === 'object' && 'Time' in date && date.Time) {
    const d = new Date(date.Time)
    if (isNaN(d.getTime())) return ''
    return d.toLocaleDateString()
  }
  return ''
}