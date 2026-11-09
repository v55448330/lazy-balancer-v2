// 全局模板 helper 类型声明：$flw(表单 label 宽度语言感知)。
// 运行时挂载点=main.ts(app.config.globalProperties)——zh 返回设计宽/en 返回
// 加宽 30%(最小 120px)整词换行方案(audit136-U5B-3 注释与实现对齐)。
import 'vue'

declare module 'vue' {
  interface ComponentCustomProperties {
    $flw: (zhWidth: string) => string
  }
}

export {}
