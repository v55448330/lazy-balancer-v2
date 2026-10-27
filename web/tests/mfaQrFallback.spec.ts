// MFA 绑定向导的二维码渲染失败降级：
// 画布上下文不可用（受限 WebView / 隐私模式 / uri 异常）时，原实现让
// QRCode.toCanvas 的 rejection 从 async 函数逃逸——调用点 `void renderQr()`
// 丢弃 promise，结果是「无提示、画布留白」且 unhandled rejection；用户看到的是
// 「卡住了」，而不是「改用下方密钥手动添加」。
//
// 真实前提：node --test 无 .vue 装载器（本套件禁止静态 import .vue），模板依赖
// element-plus 全局组件——失败态的置位与呈现只能用「限段 + 结构」文本钉。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, openTags, section } from './_helpers.ts'

const WIZARD = 'src/components/MfaBindingWizard.vue'

// 每轮渲染先复位：上一次失败后重开向导仍显示失败横幅=把瞬时故障当常态。
test('渲染失败置位并降级：try/catch 收口，不向外抛', () => {
  const text = code(WIZARD)
  const renderQr = section(text, 'const renderQr = async', '\n}\n')
  assert.match(renderQr, /qrError\.value = false/, '每轮渲染先复位失败态')
  assert.match(renderQr, /await QRCode\.toCanvas\(/, '前置：确实在渲染二维码')
  assert.match(renderQr, /try \{[\s\S]*await QRCode\.toCanvas/, '渲染必须包在 try 内（原实现裸 await → unhandled rejection）')
  const catchBlock = section(renderQr, '} catch', '\n  }')
  assert.match(catchBlock, /qrError\.value = true/, '失败必须置位（否则画布留白且无任何提示）')
  assert.match(catchBlock, /console\.warn\(/, '失败需留痕，便于定位画布不可用的运行环境')
  assert.doesNotMatch(catchBlock, /\bthrow\b/, '不得把失败重新抛给 `void renderQr()` 调用点')
})

test('失败态呈现：画布隐藏，改为说明下一步（手动输入密钥）', () => {
  const text = code(WIZARD)
  const frames = openTags(text, 'div').filter((tag) => tag.includes('mfa-qr-frame'))
  assert.equal(frames.length, 1, '二维码容器必须唯一可定位')
  assert.match(frames[0]!, /v-if="!qrError"/, '失败时不得继续挂一块空白画布')

  const banners = openTags(text, 'div').filter((tag) => tag.includes('v-else') && tag.includes('info-note-bar'))
  assert.equal(banners.length, 1, '失败必须渲染说明横幅（v-else 分支）')
  assert.match(banners[0]!, /role="status"/, '降级说明必须对读屏可见（不是纯视觉样式）')

  // 横幅位于密钥与画布之间：说明里承诺「用下方密钥」，密钥必须真的在下方可见。
  const bannerAt = text.indexOf('info-note-bar')
  const frameAt = text.indexOf('mfa-qr-frame')
  const secretAt = text.indexOf('class="mfa-secret"')
  assert.ok(bannerAt > frameAt, '说明横幅排在二维码容器之后')
  assert.ok(secretAt > bannerAt, '手动密钥必须排在说明之后（说明引用「下方密钥」）')
  assert.match(text, /二维码生成失败/, '必须说清失败本身')
  assert.match(text, /请使用下方密钥在 Google\/Microsoft Authenticator 等验证器中手动添加/, '必须给出可执行的下一步')
})

test('关闭向导复位失败态（下次打开是全新一轮）', () => {
  const text = code(WIZARD)
  const closed = section(text, 'const handleClosed = ', '\n}')
  assert.match(closed, /qrError\.value = false/, '关闭必须清失败态，否则下次打开直接显示上一轮的失败横幅')
  // 复位与既有步骤复位同处：harness 只认这一处收尾，分散复位会漏
  assert.match(closed, /step\.value = 0/)
  assert.match(closed, /recoveryCodes\.value = \[\]/)
})
