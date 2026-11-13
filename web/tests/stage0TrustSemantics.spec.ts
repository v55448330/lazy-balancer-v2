import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

// stage0 信任命中释义在 5 处词条近乎逐字重复（单条最长
// 121 字，跨 rules.ts/security.ts/views.ts 三文件）。i18n 词条架构下强行合一
// 会破坏各处语境（trustTip 含内联/引用尾注、footnote1 嵌 {base} 占位、
// detectOn 带前缀）——降级为**跨文件语义片段一致钉测**：核心语义短语必须
// 在全部变体在场，任一处维护期漂移即红（防单点改动遗漏姊妹变体）。

const read = (rel: string): string =>
  readFileSync(fileURLToPath(new URL('../'+rel, import.meta.url)), 'utf-8')


test('stage0 信任释义语义锚跨文件一致（5 变体）', () => {
  const variants: Array<{ file: string; key: string }> = [
    { file: 'src/locales/zh/rules.ts', key: 'trustModeHttpNote' },
    { file: 'src/locales/zh/security.ts', key: 'detectOn' },
    { file: 'src/locales/zh/security.ts', key: 'projection' },
    { file: 'src/locales/zh/security.ts', key: 'trustTip' },
    { file: 'src/locales/zh/views.ts', key: 'footnote1TrustBound' },
  ]
  for (const { file, key } of variants) {
    const src = read(file)
    const line = src.split('\n').find((l) => l.includes(key))
    assert.ok(line, `${file} 缺词条 ${key}`)
    assert.ok(line.includes('独立轻量检测事务'), `${file}#${key} 缺语义锚「独立轻量检测事务」`)
    const skipsAll = line.includes('跳过全部') || line.includes('跳过本段与全部安全阶段')
    assert.ok(skipsAll, `${file}#${key} 缺跳过语义锚`)
    if (file.endsWith('security.ts')) {
      assert.ok(line.includes('引擎内检测降级'), `${file}#${key} 缺语义锚「引擎内检测降级」（mixed 类型降级语义）`)
    }
  }
})
