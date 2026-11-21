// 轻量 Markdown→HTML（模板预览用，覆盖 QQ 客户端渲染子集：#/##/### 标题、
// **加粗**、`code` span、- 与 * 两种列表、> 引用、| 表格、--- 分隔线、段落）。
// 从 NotificationCenter.vue 抽出单源（2026-11-22：定稿模板用 `* ` 列表与
// `---` 分节，预览此前只认 `- ` 列表、不认分隔线——用户实测预览区显示
// 字面星号/横线）。先转义再渲染，禁脚本。
export const mdToHtml = (md: string): string => {
  const esc = (s: string): string => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  const inline = (s: string): string => esc(s).replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>').replace(/`([^`]+?)`/g, '<code>$1</code>')
  const lines = md.split('\n')
  const out: string[] = []
  let i = 0
  while (i < lines.length) {
    const ln = lines[i]
    if (/^\s*\|/.test(ln) && i + 1 < lines.length && /^\s*\|[\s:|-]+\|?\s*$/.test(lines[i + 1])) {
      const header = ln.trim().replace(/^\||\|$/g, '').split('|').map(c => `<th>${inline(c.trim())}</th>`).join('')
      i += 2
      const rows: string[] = []
      while (i < lines.length && /^\s*\|/.test(lines[i])) {
        rows.push(lines[i].trim().replace(/^\||\|$/g, '').split('|').map(c => `<td>${inline(c.trim())}</td>`).join(''))
        i++
      }
      out.push(`<table><thead><tr>${header}</tr></thead><tbody>${rows.map(r => `<tr>${r}</tr>`).join('')}</tbody></table>`)
      continue
    }
    if (/^###\s+/.test(ln)) { out.push(`<h4>${inline(ln.replace(/^###\s+/, ''))}</h4>`); i++; continue }
    if (/^##\s+/.test(ln)) { out.push(`<h3>${inline(ln.replace(/^##\s+/, ''))}</h3>`); i++; continue }
    if (/^#\s+/.test(ln)) { out.push(`<h2>${inline(ln.replace(/^#\s+/, ''))}</h2>`); i++; continue }
    // 分隔线：独立 --- / *** 行（QQ 客户端分节形态；表格分隔行已被上方表格分支消费）
    if (/^\s*(?:-{3,}|\*{3,})\s*$/.test(ln)) { out.push('<hr>'); i++; continue }
    // 列表：- 与 * 两种前缀（定稿模板用 *；**加粗行首不会被匹配——其后非空白）
    if (/^\s*[*-]\s+/.test(ln)) {
      const items: string[] = []
      while (i < lines.length && /^\s*[*-]\s+/.test(lines[i])) { items.push(`<li>${inline(lines[i].replace(/^\s*[*-]\s+/, ''))}</li>`); i++ }
      out.push(`<ul>${items.join('')}</ul>`); continue
    }
    if (/^\s*>\s?/.test(ln)) {
      const items: string[] = []
      while (i < lines.length && /^\s*>\s?/.test(lines[i])) { items.push(inline(lines[i].replace(/^\s*>\s?/, ''))); i++ }
      out.push(`<blockquote>${items.join('<br>')}</blockquote>`); continue
    }
    if (ln.trim() === '') { i++; continue }
    out.push(`<p>${inline(ln)}</p>`); i++
  }
  return out.join('\n')
}
