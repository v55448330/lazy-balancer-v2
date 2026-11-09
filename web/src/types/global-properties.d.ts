// 全局模板 helper 类型声明：$flw(表单 label 宽度语言感知)。
// 运行时挂载点=main.ts(app.config.globalProperties)——zh 返回设计宽/en 返回
// 'auto'(EP 卡内取最长 label 统一对齐)。
import 'vue'

declare module 'vue' {
  interface ComponentCustomProperties {
    $flw: (zhWidth: string) => string
  }
}

export {}
