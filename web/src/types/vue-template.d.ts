/**
 * 模板静态检查的类型补强（配合 tsconfig 的 vueCompilerOptions.strictTemplates）。
 *
 * 开 strictTemplates 后 vue-tsc 会核对模板里组件的 props/组件名/指令（这是唯一能
 * 拦住 `el-table :datas` 这类拼错属性的机制）。但两类「真实生效、却不在组件 props
 * 声明面」的写法会被误报，在此单点登记：
 *
 * 1. `vLoading`：Element Plus 只导出指令实现，不注册 `GlobalDirectives`，模板里
 *    的 `v-loading` 会被判为未知指令。
 * 2. 原生属性透传：Vue 把组件未声明的属性原样落到根元素上（el-form → `<form>`、
 *    el-button `tag="a"` → `<a>` 的 href、el-input → `<input>` 的 min、任意组件的
 *    aria 系列/role/title/id/tabindex 等）。这些是 Vue 的 attrs 语义而非组件契约，
 *    用 DOM 侧的属性表登记（与原生元素同一事实源）；组件自己声明的 props 仍在
 *    组件类型里检查——拼错的组件 prop（例如 `el-table` 的 `:datas`）不在这张表里，
 *    仍会报 TS2561。
 *
 * 刻意**不**登记 DOM 事件处理器（`onClick`/`onChange` 等）：组件已声明的 emits 才是
 * 事件契约，混入 DOM 事件类型会与 emits 交叉成 `((val) => any) & ((evt: Event) =>
 * void)`，把回调参数类型检查搅乱。原生监听器透传由 tsconfig 的
 * `checkUnknownEvents: false` 放行，`data-*` 由 `dataAttributes` 放行。
 *
 * 另见 tsconfig 的 `strictVModel: false`：Element Plus 的模型类型不是泛型，
 * `update:modelValue` 一律声明成宽松联合（ElSwitch 发 `boolean | string | number`、
 * ElInputNumber 发 `number | undefined`、ElRadioGroup 发
 * `string | number | boolean | undefined`、ElTabs 发 `TabPaneName`），逐个核对
 * v-model 的赋值方向只会逼着业务字段退化成可空或把 90 余处绑定改写成
 * `:model-value` + 处理器（其中「输入框清空」的语义会被动改变）。属性名与属性值
 * 的类型检查（例如 `:data` 写成 `:datas`、`:data="123"`）不受此项影响。
 *
 * 表格插槽约定：`<el-table-column>` 的默认插槽 `row` 来自 Element Plus 的
 * `DefaultRow`（`Record<PropertyKey, any>`），不随 `:data` 推断。传进强类型函数时
 * 在调用点收窄即可：`fn(row as Rule)`——断言只抹平插槽类型，不改运行时实参；不要
 * 用 `as any`，也不要给整块模板加诊断屏蔽注释（tests/templateTypeGate.spec.ts 钉住）。
 */
import type { AriaAttributes } from 'vue'
import type { ElLoadingDirective } from 'element-plus'

declare module 'vue' {
  interface GlobalDirectives {
    vLoading: typeof ElLoadingDirective
  }

  interface ComponentCustomProps extends AriaAttributes {
    // WAI-ARIA 里不属于 AriaAttributes 的通用角色属性
    role?: string | undefined
    // HTML 全局属性（透传到组件根元素）
    id?: string | undefined
    title?: string | undefined
    tabindex?: number | string | undefined
    // 渲染为链接/表单元素时的原生属性（el-button tag="a"、el-link、el-form）。
    // `target` 用 unknown：它同时是组件 props 名（如流程弹框的 target 对象），
    // 声明成 string 会与组件 prop 交叉成 `X & string` 反而误报。
    href?: string | undefined
    rel?: string | undefined
    target?: unknown
    // 输入类元素的原生约束属性（el-input type="number" 时转发给内层 <input>）
    min?: number | string | undefined
    max?: number | string | undefined
    step?: number | string | undefined
    // v-loading 指令参数：由指令从元素属性读取，不是组件 props
    elementLoadingText?: string | undefined
    elementLoadingSpinner?: string | undefined
    elementLoadingBackground?: string | undefined
    elementLoadingSvg?: string | undefined
    'element-loading-text'?: string | undefined
    'element-loading-spinner'?: string | undefined
    'element-loading-background'?: string | undefined
    'element-loading-svg'?: string | undefined
  }
}

export {}
