// prismjs 核心在非 manual 模式下挂 DOMContentLoaded 自动高亮：扫描
// code[class*=language-] 并用 textContent 重写 innerHTML。本项目全部高亮走
// v-html（useDebouncedHighlight 单源管线），自动高亮会在挂载后把 v-html 内容
// 重写一遍——trailingBreak 补的尾 `<br>` 不在 textContent 里，被静默吃掉：
// CodeEditor 高亮层比 textarea 少一行，scrollTop 同步在滚动区间末端被钳位，
// 光标/选择相对文本错位（2026-11-22「滚到底才错位」根因）。
// 必须在 prismjs 核心 eval 前执行（core 启动时读 window.Prism.manual），
// 因此本模块作为 highlight.ts 的首个 import。
export {}

// 运行时该全局在 prismjs 核心 eval 前尚不存在，@types/prismjs 却把
// window.Prism 声明为必有完整命名空间——类型与加载时序不符，用窄化局部读取。
const g = globalThis as { Prism?: { manual?: boolean } }
if (g.Prism) {
  g.Prism.manual = true
} else {
  g.Prism = { manual: true }
}
