// i18n 单实例原则:vue-i18n 全应用只允许 index.ts 一个实例(app.use(i18n))。
// tSafe 只是 node --test 环境(无 @/ 别名钩子、无 DOM)也能整链解析的薄委托——
// 委托主实例,键路径/词表与组件内 useI18n() 完全一致,杜绝双实例词表分叉
// (历史事故:独立实例只挂 misc+views 子树,settings 域整页裸键)。
// 行为测试进程无 localStorage 时 index.detectLocale 安全回落 zh-CN。
import { i18n } from './index.ts'

export const tSafe = (key: string, params?: Record<string, unknown>): string =>
  i18n.global.t(key, params ?? {})
