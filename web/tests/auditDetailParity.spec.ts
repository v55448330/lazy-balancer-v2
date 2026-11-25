// 跨栈渲染对等守卫（方案 C 第 2/3 步，2026-11-25 用户批准）：
//   ① 每个 audit 段键必须有中文母本与前端英文词条（缺英文即红——后端不翻译）；
//   ② zh/en 模板的槽位数必须一致（否则英文渲染会吞槽或留 %s）；
//   ③ 同一夹具（web/tests/fixtures/auditDetailParity.json，Go 侧
//      audit_detail_keys_test.go 共用）按前端渲染器渲染的中文必须与夹具逐字相等；
//   ④ 未知段键 fail-visible：原样显示键本身。
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

import { API_MESSAGE_EN, API_MESSAGE_ZH } from '../src/i18n/apiMessages.ts'
import { auditDetailText } from '../src/utils/auditDetail.ts'
import { templateVerbs } from '../src/utils/apiMessage.ts'

const FIXTURE = new URL('./fixtures/auditDetailParity.json', import.meta.url)
const SEPARATOR = '|'

interface ParityCase {
  readonly name: string
  readonly key: string
  readonly params: unknown
  readonly zh: string
}

const cases = JSON.parse(readFileSync(FIXTURE, 'utf8')) as ParityCase[]

const segments = (key: string): string[] => key.split(SEPARATOR)

const auditKeys = Object.keys(API_MESSAGE_ZH).filter((key) => key.startsWith('audit.'))

test('夹具非空（守卫不得空转）', () => {
  assert.ok(cases.length >= 5, `夹具只有 ${cases.length} 条`)
})

test('每个 audit 段键都有中文母本与前端英文词条', () => {
  assert.ok(auditKeys.length > 300, `只扫到 ${auditKeys.length} 个 audit 段键——扫描面异常`)
  const missingEnglish: string[] = []
  const missingChinese: string[] = []
  const slotMismatch: string[] = []
  for (const key of auditKeys) {
    const zh = API_MESSAGE_ZH[key]
    const en = Object.prototype.hasOwnProperty.call(API_MESSAGE_EN, key) ? API_MESSAGE_EN[key] : undefined
    if (!zh) missingChinese.push(key)
    if (!en) {
      missingEnglish.push(key)
      continue
    }
    if (templateVerbs(zh).length !== templateVerbs(en).length) {
      slotMismatch.push(`${key}: zh=${zh} en=${en}`)
    }
  }
  assert.deepEqual(missingChinese, [], '缺中文母本')
  assert.deepEqual(missingEnglish, [], `缺前端英文词条：\n  ${missingEnglish.join('\n  ')}`)
  assert.deepEqual(slotMismatch, [], `zh/en 槽位数不一致：\n  ${slotMismatch.join('\n  ')}`)
})

test('夹具每条：段键已登记且中文渲染与夹具逐字相等', () => {
  for (const item of cases) {
    for (const segment of segments(item.key)) {
      assert.ok(API_MESSAGE_ZH[segment], `${item.name}: 段键缺中文母本 ${segment}`)
      assert.ok(API_MESSAGE_EN[segment], `${item.name}: 段键缺英文 ${segment}`)
    }
    const rendered = auditDetailText({ detail_key: item.key, detail_params: item.params, detail: item.zh }, 'zh-CN')
    assert.equal(rendered, item.zh, `${item.name}: 中文渲染不一致`)
    const english = auditDetailText({ detail_key: item.key, detail_params: item.params, detail: '' }, 'en')
    assert.ok(english.length > 0, `${item.name}: 英文渲染为空`)
    assert.ok(!/\p{Script=Han}/u.test(english), `${item.name}: 英文渲染残留汉字: ${english}`)
  }
})

test('未知段键 fail-visible（原样显示键本身）', () => {
  const rendered = auditDetailText(
    { detail_key: 'audit.__not_registered__', detail_params: [[]], detail: '母本' },
    'zh-CN',
  )
  assert.equal(rendered, 'audit.__not_registered__')
})

test('无键历史行回落 detail 原文', () => {
  assert.equal(auditDetailText({ detail: '历史明细原文' }, 'en'), '历史明细原文')
})
