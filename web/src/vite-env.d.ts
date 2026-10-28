/// <reference types="vite/client" />
// Element Plus 的全局组件声明：模板里 el-* 的 props/组件名/指令据此参与 vue-tsc
// （配合 tsconfig 的 vueCompilerOptions.strictTemplates）。删掉这行后 el-* 退化成
// 未知标签，拼错属性（:datas 之类）会重新静默通过——tests/templateTypeGate.spec.ts 钉住。
/// <reference types="element-plus/global" />

// *.vue 模块声明垫片已移除（vite/client 的 shim 也仅在模块解析失败时命中，
// 会把拼错的 .vue 导入静默当成 DefineComponent<{},{},any>，丢失 props/emits
// 类型检查）。vue-tsc 对真实 SFC 走实体解析，缺失导入会报 Cannot find module。
