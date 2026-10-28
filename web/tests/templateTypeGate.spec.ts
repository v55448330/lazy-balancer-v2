// 模板类型门验收（Element Plus 组件 props 必须参与 vue-tsc）：
//   `el-table :data` 误写 `:datas` 在启用 strictTemplates 前会静默通过四道前端门，
//   运行期退化成空表——模板属性此前完全不进类型检查。本套件钉住「门开着」以及
//   所有刻意放宽的确切口径，避免有人用注释/any 把门重新关回假绿。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, source, webFiles } from './_helpers.ts'

// 本文件是 raw 视图的登记用途：断言对象是**模板里的诊断屏蔽注释**
// （vue-ignore / ts-expect-error 等指令），剥注释后无法判定是否存在。
test('vue-tsc 模板门：strictTemplates 开启，el-* 组件声明参与检查', () => {
  const tsconfig = JSON.parse(code('tsconfig.json')) as { readonly vueCompilerOptions?: Record<string, unknown> }
  const options = tsconfig.vueCompilerOptions ?? {}
  // strictTemplates 是「未声明属性 / 未知组件 / 未知指令」三类检查的总闸，也是
  // 唯一能拦住 `el-table :datas`（正确写法 :data）的机制——关掉它模板属性重新变成
  // 零检查，四道门仍全绿（历史缺口正是这样进来的）。
  // 刻意不 pin strictVModel：Element Plus 的模型类型不是泛型，
  // `update:modelValue` 一律是宽松联合（ElSwitch 发 boolean|string|number、
  // ElInputNumber 发 number|undefined、ElTabs 发 TabPaneName），赋值方向检查会
  // 逼着业务字段退化成可空或把 90 余处绑定改写成 :model-value + 处理器；理由与
  // 影响面见 src/types/vue-template.d.ts。
  assert.equal(options.strictTemplates, true, 'strictTemplates 必须开启：否则拼错的组件属性不会被 vue-tsc 拦住')
  // el-* 的 props 类型与拼写检查来自 Element Plus 的全局组件声明。删掉这行
  // triple-slash 引用后 el-* 退化成未知标签，props 检查整表失守。
  assert.match(
    source('src/vite-env.d.ts'),
    /^\/\/\/ <reference types="element-plus\/global" \/>$/m,
    'src/vite-env.d.ts 必须引用 element-plus/global（组件 props 类型的唯一来源）',
  )
  // 两处「按 Vue attrs 语义放行」而不是「关检查」，各自钉住口径：
  //  · checkUnknownEvents:false —— 原生监听器透传（@keyup.enter / @submit.prevent /
  //    el-step 的 @click）；组件已声明的 emits 仍按声明类型检查回调参数。
  //  · dataAttributes:['data-*'] —— data-* 是自定义透传属性，不属组件契约。
  assert.equal(options.checkUnknownEvents, false, '原生事件透传必须按 attrs 语义放行（组件 emits 仍检查）')
  assert.deepEqual(options.dataAttributes, ['data-*'], 'data-* 透传属性放行口径')
})

test('模板类型门不得用诊断屏蔽注释或 any 断言绕过', () => {
  const files = webFiles('src', ['.vue'])
  assert.ok(files.length >= 40, `扫描面过小（${files.length} 个 .vue）——目录枚举失效`)
  for (const file of files) {
    const raw = source(file)
    // 插槽 row 是 Element Plus 的 DefaultRow（Record<PropertyKey, any>），只能
    // 用 `as 具体行类型` 收窄（可核验），不得整块屏蔽诊断或裸 any。
    assert.doesNotMatch(raw, /@vue-ignore|@vue-expect-error|@ts-ignore|@ts-expect-error/, `${file} 不得屏蔽模板类型诊断`)
    assert.doesNotMatch(raw, /\bas any\b/, `${file} 不得用 as any 绕过类型检查`)
  }
})
