/**
 * 全局兜底错误留痕（main.ts 的 errorHandler / unhandledrejection 共用）。
 *
 * 只留痕不恢复——局部错误边界仍由 AsyncPageError（异步页面加载）与各调用点
 * 自己的 try/catch 承担。留痕必须保留**原始错误对象**：`String(err)` 只剩一行
 * 文案，Error 的 stack（组件栈/调用栈）是排障唯一线索。上下文（Vue 传入的
 * 生命周期钩子名 info 等）单独成参，不与错误对象拼成字符串。
 */
export const reportGlobalError = (kind: string, error: unknown, info?: string): void => {
  if (info === undefined) console.error(`[global:${kind}]`, error)
  else console.error(`[global:${kind}]`, info, error)
}
