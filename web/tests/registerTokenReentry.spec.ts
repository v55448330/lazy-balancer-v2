// 集群注册令牌的生成入口必须自带重入守卫（占位先于 await）。
//
// 每枚令牌独立入库、一次性有效，且列表只展示最新一枚：同一 tick 内的双击不会等
// loading 渲染出来（浏览器把两次点击排进同一次宏任务），两次 POST 会留下第二枚
// 界面再也查不到的令牌——不可见、不可撤销、仍然有效，属凭据卫生问题。
//
// 同文件的其它写入口（立即同步 / 清除指纹钉 / 节点操作）都是「只读门 + 在途门 →
// 置位 → await」的同一形态；本入口曾只有只读门。
//
// 真实前提：node --test 无 .vue 装载器（本套件禁止静态 import .vue），该入口依赖
// 组件内 ref 与请求层——用「限段 + 顺序」文本钉住守卫形态。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, member, section } from './_helpers.ts'

const SETTINGS = 'src/views/settings/ClusterSettings.vue'

test('生成注册令牌：在途门与只读门并列，置位先于请求', () => {
  const text = code(SETTINGS)
  const body = member(text, 'const generateRegisterToken = async (): Promise<void> =>')
  const guard = body.indexOf('if (isReadOnlyProp.value || tokenLoading.value) return')
  const setLoading = body.indexOf('tokenLoading.value = true')
  const post = body.indexOf("await request.post<APIResponse<ClusterRegisterToken>>('/cluster/register-tokens')")
  assert.ok(guard > 0, '必须同时把住只读与在途（原实现只有只读门 → 双击发两次）')
  assert.ok(setLoading > guard, '置位必须在守卫之后（否则守卫恒真，永远发不出请求）')
  assert.ok(post > setLoading, '占位必须早于请求（await 之前的双击都看不到 loading）')
  // 收尾释放占位：失败路径也要放开，否则一次 5xx 之后按钮永久卡住
  const finallyBlock = body.slice(body.indexOf('} finally {'))
  assert.match(finallyBlock, /tokenLoading\.value = false/)
})

test('账号变化立即清空注册令牌并关闭弹框', () => {
  const text = code(SETTINGS)
  const identityWatch = section(text, 'watch(() => authStore.user?.id', 'const isReadOnlyProp')
  assert.match(identityWatch, /registerToken\.value = null/)
  assert.match(identityWatch, /tokenDialogVisible\.value = false/)
  assert.doesNotMatch(identityWatch, /immediate:\s*true/, '同账号的初始化或资料刷新不得关闭已打开的令牌弹框')
})

test('与同文件其它写入口同构：只读门 + 在途门 + 置位 + finally 释放', () => {
  const text = code(SETTINGS)
  const shapes = [
    member(text, 'const syncNow = async (): Promise<void> =>'),
    member(text, 'const forgetPins = async (): Promise<void> =>'),
  ]
  for (const body of shapes) {
    assert.match(body, /if \(isReadOnlyProp\.value\) return/, '前置：只读门')
    assert.match(body, /(?:syncing|forgettingPins)\.value\) \{|(?:syncing|forgettingPins)\.value\) return/, '前置：在途门')
    const setAt = body.search(/(?:syncing|forgettingPins)\.value = true/)
    const firstAwait = body.indexOf('await ')
    assert.ok(setAt > 0 && setAt < firstAwait, '前置：占位先于任何 await')
  }
})
