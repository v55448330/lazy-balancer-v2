// 跨栈对等守卫：前端的接口消息渲染表（src/i18n/apiMessages.ts）必须是「后端键 +
// 前端词条」的忠实拼装。
//
// 职责边界（2026-11-25 项目所有者裁定，web/docs/I18N.md 第 0 节）：后端只下发稳定键
// 与结构化参数，展示文案只归前端。于是：
//   - 后端目录 internal/i18n/catalog_*.go 只有「键 + 中文母本」，不含英文译文；
//   - src/locales/apiMessages.en.json 是英文的唯一维护源（手写）；
//   - 生成文件把两者拼成前端渲染表。
// 两份来源只要有一处分叉，界面提示就与后端契约不一致。本守卫把三件事做成机械断言：
//   1. 生成文件 == 按两侧来源重新拼装的结果（逐字相等）；
//   2. 键集合双向对等——后端每个键前端都有英文词条，前端词条没有后端不存在的死键；
//   3. 英文译文不得含汉字、不得有词间双空格（中文母本不动）；
//   —— 外加解析器的判别自检：解析悄悄解错时，上面的对等就是假的。
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
  // 扫描面：后端目录现在是千余条；骤降说明解析器漏读了大半——对等会假绿。
  assert.ok(entries.length > 1000, `后端目录只解析出 ${entries.length} 条——扫描面异常`)
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

test('键集合双向对等：后端每个键都有前端英文，前端词条无死键', () => {
  const entries = loadBackendCatalog()
  const merged = mergeTranslations(entries, loadFrontendEnglish())
  // 方向一：前端词条里不得有后端目录没有的键（目录改名后的死条目）。
  assert.deepEqual(merged.errors, [], '前端英文词条含死条目——后端目录改名后必须同步删除')
  // 方向二：后端每个键都必须有前端英文词条（后端不再提供英文，缺一条英文界面就露中文）。
  assert.deepEqual(merged.missing, [], `以下键只有中文母本、前端缺英文词条：\n  ${merged.missing.join('\n  ')}`)
  // 两侧条数一致（上面的两个断言已蕴含，此处把契约数字留作可读锚点）。
  const frontendEnglish = loadFrontendEnglish()
  assert.equal(Object.keys(frontendEnglish).length, entries.length)
  assert.equal(merged.en.length, entries.length)
})

test('接口消息的英文译文不得残留汉字', () => {
  const entries = loadBackendCatalog()
  const merged = mergeTranslations(entries, loadFrontendEnglish())
  const offenders = merged.en.filter(([, text]) => HAN.test(text)).map(([key, text]) => `${key} = ${text}`)
  assert.deepEqual(offenders, [], `英文译文有 ${offenders.length} 条残留汉字`)
})

test('接口消息的英文译文不得出现词间双空格', () => {
  // 判据：非空白字符之间的连续 ≥2 空格（行首缩进/行尾空白不属词间形态）。
  const wordDoubleSpace = /\S {2,}\S/
  const offenders = Object.entries(loadFrontendEnglish())
    .filter(([, text]) => wordDoubleSpace.test(text))
    .map(([key, text]) => `${key} = ${text}`)
  assert.deepEqual(offenders, [], `英文译文有 ${offenders.length} 条词间双空格`)
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
    '\t// 示例：Register("comment.example", "注释里的不是词条")',
    '\tRegister("rule.x", "规则")',
    '\tRegister("rule.y", "a \\"b\\""),',
    '}',
  ].join('\n')
  // 目标：单行两参数形态的两条被读出，转义已解码，注释行不计。
  assert.deepEqual(parseBackendCatalog(source, 'synthetic.go'), [
    { key: 'rule.x', zh: '规则' },
    { key: 'rule.y', zh: 'a "b"' },
  ])
  // 畸形：Register( 起了头却不是单行形态——抛错并指出行号，不静默漏读。
  assert.throws(
    () => parseBackendCatalog('\tRegister(\n\t\t"rule.z", "跨行",\n\t)', 'synthetic.go'),
    /synthetic\.go:1: Register 不是单行/,
    '跨行的 Register 必须报错（单行正则读不全它）',
  )
  // 畸形：第三参（英文译文）不得出现在后端目录——英文归前端词条（2026-11-25 裁定）。
  assert.throws(
    () => parseBackendCatalog('\tRegister("rule.z", "中文", "English")', 'synthetic.go'),
    /synthetic\.go:1: Register 不是单行 \(key, zh\) 形态/,
    '后端目录出现英文译文必须报错，而不是被悄悄接受',
  )
})
