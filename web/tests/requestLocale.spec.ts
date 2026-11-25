// 界面语言只由前端词条决定：后端不按请求语言渲染（中文母本 + message_key +
// message_params 恒定返回，2026-11-25 裁定），因此请求模块不得再发送
// Accept-Language 头；表单标签宽度的语言判断仍须以「实际生效的界面语言」为准
// ——即 i18n 实例的当前 locale（首访跟随浏览器时界面语言是运行期检测出来的、
// 不写入存储，只读存储键会把英文界面判成中文，标签按错误宽度排版）。
//
// 运行：cd web && node --test tests/requestLocale.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code } from './_helpers.ts'

test('请求模块不发送 Accept-Language（响应与请求语言无关）', () => {
  const api = code('src/utils/api.ts')
  assert.doesNotMatch(api, /config\.headers\['Accept-Language'\]/, '请求模块不得发送 Accept-Language——后端不按语言渲染')
  assert.doesNotMatch(api, /lb_locale/, '请求模块不得直接读语言存储键')
})

test('表单标签宽度的语言判断取界面语言实例的当前值', () => {
  const main = code('src/main.ts')
  assert.match(main, /if \(i18n\.global\.locale\.value !== 'en'\) return zhWidth/, '标签宽度按生效语言判定')
  assert.doesNotMatch(main, /lb_locale/, '入口不得直接读语言存储键')
})
