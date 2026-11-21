// 模板预览 Markdown 渲染（2026-11-22 用户裁定方案 B）：marked（GFM+breaks）
// + DOMPurify 消毒，替代此前手写的 QQ 子集渲染器——预览保真以完整 markdown
// 语义为准（表格对齐/嵌套列表/链接等），不再随 QQ 子集手工追赶。
// breaks=true：模板按行排版（标题/分隔线/键值行），单换行必须保留为 <br>，
// 否则相邻行会被并进同一段落。
// setext 隔断：标准 markdown 里「正文行紧跟 ---」= 二级标题（setext 下划线），
// 但 QQ 把独立 --- 行按分隔线渲染（用户模板以 --- 分节）——解析前给分隔线
// 行补空行隔断，保持与通道侧一致的分节语义。
// 消毒：v-html 注入面（模板文本+样例值）经 DOMPurify 白名单过滤，事件
// 属性与 javascript: 协议一律剥离。浏览器直用 window；Node 测试环境由
// 测试先立 jsdom 窗口（见 tests/mdPreview.spec.ts 顺序约束注释）。
import { marked } from 'marked'
import DOMPurify from 'dompurify'

marked.setOptions({ gfm: true, breaks: true })

export const mdToHtml = (md: string): string => {
  const normalized = md.replace(/^(?:-{3,}|\*{3,}|_{3,})[ \t]*$/gm, m => `\n${m}`)
  const raw = marked.parse(normalized) as string
  return DOMPurify.sanitize(raw) as string
}


// 日报多值变量→语义表格（预览镜像，与后端 mdMultiValueTable 同口径：
// TOP IP/路径=名目/次数、临期证书=域名/到期日、节点摘要=五列）。模板提供
// 上下文标签，变量只出表格本体；解析失败返回 null（预览回退原始多行值）。
const nodesSummaryRe = /^([^：]+)：请求 (\d+) · 拦截 (\d+) · 独立IP (\d+)(.*)$/
export const dailyMultiValueMd = (key: string, value: string): string | null => {
  const cell = (x: string): string => x.split('|').join('｜')
  const lines = value.split('\n')
  if (key === 'nodes_summary') {
    const rows: string[][] = []
    for (const ln of lines) {
      const m = nodesSummaryRe.exec(ln)
      if (!m) return null
      const rest = m[5].trim()
      rows.push([cell(m[1]), m[2], m[3], m[4], rest === '' ? '—' : rest.replace(/^·\s*/, '')])
    }
    return ['| 节点 | 请求 | 拦截 | 独立IP | 备注 |', '| --- | ---: | ---: | ---: | --- |',
      ...rows.map(r => `| ${r.join(' | ')} |`)].join('\n')
  }
  if (key === 'top_ips' || key === 'top_paths') {
    const head = key === 'top_ips' ? '| 攻击源 IP | 次数 |' : '| 攻击路径 | 次数 |'
    const rows: string[] = []
    for (const ln of lines) {
      const i = ln.lastIndexOf('×')
      if (i < 0) return null
      rows.push(`| ${cell(ln.slice(0, i).trim())} | ${ln.slice(i + 1).trim()} |`)
    }
    return [head, '| --- | ---: |', ...rows].join('\n')
  }
  if (key === 'cert_expiring') {
    const rows: string[] = []
    for (const ln of lines) {
      const i = ln.lastIndexOf('·')
      if (i < 0) return null
      rows.push(`| ${cell(ln.slice(0, i).trim())} | ${ln.slice(i + 1).trim()} |`)
    }
    return ['| 域名 | 到期日 |', '| --- | ---: |', ...rows].join('\n')
  }
  return null
}
