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
 * Handles common SGR codes (reset, bold, italic, underline, 3/4-bit colors).
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

  const html = escaped.replace(/\u001b\[((?:\d+;?)+)m/g, (_match, codes) => {
    const codeList: number[] = String(codes).split(';').map(Number)

    if (codeList.includes(0)) {
      const close = open ? '</span>' : ''
      open = false
      return close
    }

    const styles: string[] = []
    for (const c of codeList) {
      if (c === 1) styles.push('font-weight:bold')
      else if (c === 3) styles.push('font-style:italic')
      else if (c === 4) styles.push('text-decoration:underline')
      else if (fgColors[c]) styles.push(`color:${fgColors[c]}`)
      else if (bgColors[c]) styles.push(`background-color:${bgColors[c]}`)
    }

    const close = open ? '</span>' : ''
    open = true

    if (styles.length === 0) {
      return close + '<span>'
    }
    return `${close}<span style="${styles.join(';')}">`
  })

  return open ? html + '</span>' : html
}
