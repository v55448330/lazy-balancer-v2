/**
 * Escape HTML special characters.
 */
export function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

/**
 * Convert ANSI escape sequences in a string to HTML.
 * Handles common SGR codes (reset, text styles, and basic/indexed/RGB colors).
 * Newlines are preserved by the caller via CSS (white-space: pre-wrap).
 */
export function ansiToHtml(text: string): string {
  const fgColors: Record<number, string> = {
    30: '#000000',
    31: '#ef4444',
    32: '#22c55e',
    33: '#eab308',
    34: '#3b82f6',
    35: '#a855f7',
    36: '#06b6d4',
    37: '#e5e7eb',
    90: '#4b5563',
    91: '#f87171',
    92: '#4ade80',
    93: '#facc15',
    94: '#60a5fa',
    95: '#c084fc',
    96: '#22d3ee',
    97: '#ffffff',
  }

  const bgColors: Record<number, string> = {
    40: '#000000',
    41: '#ef4444',
    42: '#22c55e',
    43: '#eab308',
    44: '#3b82f6',
    45: '#a855f7',
    46: '#06b6d4',
    47: '#374151',
    100: '#1f2937',
    101: '#7f1d1d',
    102: '#14532d',
    103: '#713f12',
    104: '#1e3a8a',
    105: '#581c87',
    106: '#164e63',
    107: '#9ca3af',
  }

  const escaped = escapeHtml(text)
  let open = false
  let bold = false
  let italic = false
  let underline = false
  let foreground = ''
  let background = ''

  const ansiColor = (index: number): string => {
    const base = [
      '#000000', '#800000', '#008000', '#808000', '#000080', '#800080', '#008080', '#c0c0c0',
      '#808080', '#ff0000', '#00ff00', '#ffff00', '#0000ff', '#ff00ff', '#00ffff', '#ffffff',
    ]
    if (index < 16) return base[index] ?? ''
    if (index < 232) {
      const value = index - 16
      const levels = [0, 95, 135, 175, 215, 255]
      const r = levels[Math.floor(value / 36)]
      const g = levels[Math.floor((value % 36) / 6)]
      const b = levels[value % 6]
      return `rgb(${r},${g},${b})`
    }
    if (index < 256) {
      const level = 8 + (index - 232) * 10
      return `rgb(${level},${level},${level})`
    }
    return ''
  }

  const html = escaped.replace(/\u001b\[([\d;]*)m/g, (_match, codes) => {
    const codeList: number[] = codes === '' ? [0] : String(codes).split(';').map(code => code === '' ? 0 : Number(code))
    for (let i = 0; i < codeList.length; i += 1) {
      const c = codeList[i]
      if (c === 0) {
        bold = false
        italic = false
        underline = false
        foreground = ''
        background = ''
      } else if (c === 1) bold = true
      else if (c === 3) italic = true
      else if (c === 4) underline = true
      else if (c === 22) bold = false
      else if (c === 23) italic = false
      else if (c === 24) underline = false
      else if (c === 39) foreground = ''
      else if (c === 49) background = ''
      else if ((c === 38 || c === 48) && codeList[i + 1] === 5 && codeList[i + 2] !== undefined) {
        const color = ansiColor(codeList[i + 2])
        if (color) {
          if (c === 38) foreground = color
          else background = color
        }
        i += 2
      } else if ((c === 38 || c === 48) && codeList[i + 1] === 2 && codeList.slice(i + 2, i + 5).length === 3) {
        const [r, g, b] = codeList.slice(i + 2, i + 5).map(value => Math.min(255, Math.max(0, value)))
        const color = `rgb(${r},${g},${b})`
        if (c === 38) foreground = color
        else background = color
        i += 4
      }
      else if (fgColors[c]) foreground = fgColors[c]
      else if (bgColors[c]) background = bgColors[c]
    }

    const close = open ? '</span>' : ''
    const styles: string[] = []
    if (bold) styles.push('font-weight:bold')
    if (italic) styles.push('font-style:italic')
    if (underline) styles.push('text-decoration:underline')
    if (foreground) styles.push(`color:${foreground}`)
    if (background) styles.push(`background-color:${background}`)

    if (styles.length === 0) {
      open = false
      return close
    }
    open = true
    return `${close}<span style="${styles.join(';')}">`
  })

  return open ? html + '</span>' : html
}
