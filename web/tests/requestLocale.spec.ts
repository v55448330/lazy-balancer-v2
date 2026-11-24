// 请求语言头（后端据此返回已翻译的 message / warnings）与表单标签宽度的语言
// 判断，必须以「实际生效的界面语言」为准——即 i18n 实例的当前 locale。
//
// 首访跟随浏览器时，界面语言是运行期检测出来的、不写入存储（只有用户手动切换
// 才落盘）。此前两处都直接读存储键：英文界面被判成中文，后端文案（提示 / 错误 /
// 告警）整批回中文，英文标签按中文窄宽度排版——2026-11-25 在全新环境的英文界面
// 上实测，还原弹框的两条告警是中文，而同一请求带 Accept-Language: en 返回英文。
//
// 运行：cd web && node --test tests/requestLocale.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code } from './_helpers.ts'

test('请求语言头取界面语言实例的当前值，不读语言存储键', () => {
  const api = code('src/utils/api.ts')
  assert.match(api, /^import \{ i18n \} from '@\/i18n\/index'$/m, '请求模块持有界面语言实例')
  assert.match(api, /config\.headers\['Accept-Language'\] = i18n\.global\.locale\.value === 'en' \? 'en' : 'zh-CN'/, '请求语言头直接取 i18n 实例的当前 locale')
  assert.doesNotMatch(api, /function currentLocale/, '单调用点的取值不再包一层函数')
  assert.doesNotMatch(api, /lb_locale/, '请求模块不得直接读语言存储键')
})

test('表单标签宽度的语言判断同样取界面语言实例的当前值', () => {
  const main = code('src/main.ts')
  assert.match(main, /if \(i18n\.global\.locale\.value !== 'en'\) return zhWidth/, '标签宽度按生效语言判定')
  assert.doesNotMatch(main, /lb_locale/, '入口不得直接读语言存储键')
})
