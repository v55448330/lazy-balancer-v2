// 跨栈对等守卫：前端的接口消息词条（src/i18n/apiMessages.ts）必须是后端目录的忠实导出。
//
// 背景（web/DESIGN_SPEC.md §25-8）：前端按 message_key 用自己的词条渲染提示文字，词条由
// scripts/gen-api-messages.ts 从后端 internal/i18n/catalog_*.go 导出。两份词条只要有一处
// 分叉，界面提示就与后端不一致——手抄、改了后端忘记重新导出、手改生成文件，都会造成
// 分叉。本守卫把「逐字相等」做成机械断言：
//   - 生成文件必须等于「按后端目录重新生成的结果」；
//   - 英文译文不得含汉字（i18nEnglishValues 只遍历 vue-i18n 词条树，这批词条不在树里）；
//   - 解析器的判别自检——解析悄悄解错时，上面的对等就是假的。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  goUnquote,
  loadBackendCatalog,
  loadFrontendEnglish,
  mergeTranslations,
  parseBackendCatalog,
  readGeneratedModule,
  renderApiMessagesModule,
} from '../scripts/gen-api-messages.ts'

const HAN = /\p{Script=Han}/u

test('前端接口消息词条与两侧来源逐字相等', () => {
  const entries = loadBackendCatalog()
  // 扫描面：后端目录现在是六百余条；骤降说明解析器漏读了大半——对等会假绿。
  assert.ok(entries.length > 600, `后端目录只解析出 ${entries.length} 条——扫描面异常`)
  const committed = readGeneratedModule()
  assert.ok(committed !== null, 'src/i18n/apiMessages.ts 不存在——在 web/ 下运行 npm run gen:api-messages 导出')

  const expected = renderApiMessagesModule(entries, loadFrontendEnglish())
  if (committed !== expected) {
    // 逐行定位第一处差异，报错里直接给出可对照的两行。
    const actualLines = committed.split('\n')
    const expectedLines = expected.split('\n')
    let first = 0
    while (first < actualLines.length && first < expectedLines.length && actualLines[first] === expectedLines[first]) first++
    assert.fail(
      `src/i18n/apiMessages.ts 与来源不一致（第 ${first + 1} 行起）——在 web/ 下运行 npm run gen:api-messages 重新导出\n`
      + `  生成文件: ${actualLines[first] ?? '<无此行>'}\n`
      + `  应为:     ${expectedLines[first] ?? '<无此行>'}`,
    )
  }
})

test('词条归属：中文母本齐全，英文优先前端词条、后端无英文的键前端必须补', () => {
  const entries = loadBackendCatalog()
  const frontendEnglish = loadFrontendEnglish()
  const merged = mergeTranslations(entries, frontendEnglish)
  // 目标：前端词条里不得有后端目录没有的键（目录改名后的死条目）。
  assert.deepEqual(merged.errors, [], '前端英文词条含死条目——后端目录改名后必须同步删除')
  // 目标：每个只有中文兜底的键，前端必须自带英文译文（后端不再翻译）。
  assert.deepEqual(merged.missing, [], `以下键只有中文兜底且前端未提供英文：\n  ${merged.missing.join('\n  ')}`)
  // 回归：后端仍带英文的键，前端未覆盖时沿用后端英文（迁移期次选）。
  const legacy = entries.find((entry) => entry.en)
  assert.ok(legacy, '后端目录里应有遗留英文译文（否则本用例空转）')
  const en = new Map(merged.en)
  assert.equal(en.get(legacy.key), frontendEnglish[legacy.key] ?? legacy.en)
})

test('接口消息的英文译文不得残留汉字', () => {
  const entries = loadBackendCatalog()
  const merged = mergeTranslations(entries, loadFrontendEnglish())
  const offenders = merged.en.filter(([, text]) => HAN.test(text)).map(([key, text]) => `${key} = ${text}`)
  assert.deepEqual(offenders, [], `英文译文有 ${offenders.length} 条残留汉字`)
})

test('判别自检：Go 字符串转义按规则解码，不认识的转义报错而不是解错', () => {
  // 目标：目录里实际出现的转义（\"）与 Go 规则内的其余转义。
  assert.equal(goUnquote('保存 \\"name\\" 配置'), '保存 "name" 配置')
  assert.equal(goUnquote('a\\\\b'), 'a\\b')
  assert.equal(goUnquote('行一\\n行二\\t缩进'), '行一\n行二\t缩进')
  assert.equal(goUnquote('\\u4e2d\\U0001F600\\x41\\101'), '中😀AA')
  // 畸形：残缺或不合法的转义返回 null（parseBackendCatalog 据此抛错）。
  assert.equal(goUnquote('尾随反斜杠\\'), null)
  assert.equal(goUnquote('\\q'), null)
  assert.equal(goUnquote('\\xZZ'), null)
  assert.equal(goUnquote('\\u12'), null)
  assert.equal(goUnquote('\\1'), null) // Go 的八进制必须恰好三位
})

test('判别自检：注释里的 Register 不算词条，跨行的 Register 报错而不是漏读', () => {
  const source = [
    'package i18n',
    '',
    'func init() {',
    '\t// 示例：Register("comment.example", "注释里的不是词条", "not an entry")',
    '\tRegister("rule.x", "规则", "Rule")',
    '\tRegister("rule.y", "a \\"b\\"", "a \\"b\\""),',
    '}',
  ].join('\n')
  // 目标：单行三参数形态的两条被读出，转义已解码，注释行不计。
  assert.deepEqual(parseBackendCatalog(source, 'synthetic.go'), [
    { key: 'rule.x', zh: '规则', en: 'Rule' },
    { key: 'rule.y', zh: 'a "b"', en: 'a "b"' },
  ])
  // 畸形：Register( 起了头却不是单行三参数形态——抛错并指出行号，不静默漏读。
  assert.throws(
    () => parseBackendCatalog('\tRegister("rule.z", "x", "y", "多出一个参数")', 'synthetic.go'),
    /synthetic\.go:1: Register 不是单行三参数形态/,
  )
  assert.throws(
    () => parseBackendCatalog('\tRegister(\n\t\t"rule.z", "跨行", "multi-line",\n\t)', 'synthetic.go'),
    /synthetic\.go:1: Register 不是单行三参数形态/,
    '跨行的 Register 必须报错（单行正则读不全它）',
  )
})
