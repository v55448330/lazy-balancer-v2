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
