// 多语言架构守卫（web/DESIGN_SPEC.md §25；用户 2026-11-25 裁定「后端返回统一标准
// 的状态码，前端根据选择的语言展示即可」）。
//
// 守卫 1「把中文当标识，只减不增」：前端不得拿后端返回的中文文本做判断——
//   a) 与中文字面量比较（x === '绕过'）；
//   b) 对字符串做含中文的子串 / 前缀 / 后缀 / 位置查找（msg.includes('失败')）。
//   这类写法靠后端中文原文工作，后端改一个字就静默失效。需要区分语义时应让后端
//   返回稳定码（接口变更，先呈报）。存量随迁移逐个改掉：新增即红，修掉后把基线调低。
//
// 守卫 2「模板不得写死中文，只减不增」：.vue 模板里的文字与普通属性值必须走 t()。
//   语言名称（「中」「中文」「English」）以本语言书写，属合理例外，不计。
//   指令与绑定（v-if / :value）是代码，其中的中文判断归守卫 1 管。
//
// 两道守卫都是「基线钉」：当前数量必须恰好等于基线——变多=新增违规；变少=基线
// 过松，请在同一提交里把基线调低。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, webFiles } from './_helpers.ts'

const HAN = /\p{Script=Han}/u

// 与中文字面量的比较（任一侧），如 x === '绕过'、'中国' !== country。
const ZH_COMPARISON = /(?:(?:===|!==|==|!=)\s*(['"`])[^'"`\n]*\p{Script=Han}[^'"`\n]*\1|(['"`])[^'"`\n]*\p{Script=Han}[^'"`\n]*\2\s*(?:===|!==|==|!=))/gu
// 含中文字面量的子串 / 前缀 / 后缀 / 位置查找，如 msg.includes('失败')。
const ZH_SUBSTRING = /\.(?:includes|startsWith|endsWith|indexOf)\(\s*(['"`])[^'"`\n]*\p{Script=Han}[^'"`\n]*\1/gu

/** 一行文本里的违规片段（用于报错定位与判别自检）。 */
const snippets = (line: string, pattern: RegExp): string[] => {
  pattern.lastIndex = 0
  return [...line.matchAll(pattern)].map((match) => match[0].trim())
}

/** 逐行扫描，返回 `文件:行: 片段`。 */
const scanLines = (path: string, text: string, pattern: RegExp): string[] => {
  const out: string[] = []
  text.split('\n').forEach((line, index) => {
    for (const snippet of snippets(line, pattern)) out.push(`${path}:${index + 1}: ${snippet}`)
  })
  return out
}

const sourceFiles = (): string[] =>
  webFiles('src', ['.ts', '.vue']).filter((path) => !/(^|\/)locales\//.test(path))

// 语言名称以本语言书写是通行做法。
const LANGUAGE_NAMES: readonly string[] = ['中', '中文', 'EN', 'English', '繁體', '简体']
const I18N_CALL = /(?<![\w$])(?:t|tSafe|tm|tf|te|rt|\$t)\s*\(/

/** 取 .vue 顶层模板（已去掉 HTML 注释）；没有模板返回空串。 */
const templateOf = (text: string): string => {
  const match = /<template>([\s\S]*)<\/template>\s*(?:<script|<style|$)/.exec(text)
  return match ? match[1]!.replace(/<!--[\s\S]*?-->/g, '') : ''
}

/** 模板里写死的中文：文字节点 + 未走词条函数的普通属性值（label="端口"、value="爬虫Bot"）。 */
const hardcodedTemplateHan = (template: string): string[] => {
  const out: string[] = []
  for (const match of template.matchAll(/\s([:@#.]?[\w.-]+)="([^"]*)"/g)) {
    const name = match[1]!
    const value = match[2]!.trim()
    // v-if / :value / @click 是代码不是文案
    if (name.startsWith('v-') || /^[:@#.]/.test(name)) continue
    if (!HAN.test(value) || I18N_CALL.test(value) || LANGUAGE_NAMES.includes(value)) continue
    out.push(`${name}="${value}"`)
  }
  // 文字节点：去掉标签与插值后剩下的可见文字。
  const text = template
    .replace(/\{\{[\s\S]*?\}\}/g, ' ')
    .replace(/<[^>]*>/g, '\n')
  for (const node of text.split('\n')) {
    const visible = node.trim()
    if (!visible || !HAN.test(visible) || LANGUAGE_NAMES.includes(visible)) continue
    out.push(visible)
  }
  return out
}

const collectZhIdentifiers = (): Record<'比较' | '子串判断', string[]> => ({
  比较: sourceFiles().flatMap((path) => scanLines(path, code(path), ZH_COMPARISON)),
  子串判断: sourceFiles().flatMap((path) => scanLines(path, code(path), ZH_SUBSTRING)),
})

const collectTemplateHan = (): string[] => {
  const out: string[] = []
  for (const path of sourceFiles()) {
    if (!path.endsWith('.vue')) continue
    for (const snippet of hardcodedTemplateHan(templateOf(code(path)))) out.push(`${path}: ${snippet}`)
  }
  return out
}

// 当前存量（2026-11-25 基线）。修掉存量后把数字调低；调高即新增违规。
const BASELINE_ZH_COMPARISON = 27
const BASELINE_ZH_SUBSTRING = 12
const BASELINE_TEMPLATE_HAN = 8

test('判别自检：中文比较与子串判断抓得到、也放得行', () => {
  const hits = (line: string): number => snippets(line, ZH_COMPARISON).length + snippets(line, ZH_SUBSTRING).length
  // 抓
  assert.equal(hits(`if (form.ip_acl_mode === '绕过') return 1`), 1)
  assert.equal(hits(`return country === "中国" ? a : b`), 1)
  assert.equal(hits(`if ('海外' !== prov) continue`), 1)
  assert.equal(hits(`status.includes('失败')`), 1)
  assert.equal(hits(`text.startsWith("提供商拒绝授权")`), 1)
  // 放行：与稳定码比较、不含中文的判断、中文只作映射表的键或词条参数
  assert.equal(hits(`if (mode === 'bypass') return 1`), 0)
  assert.equal(hits(`msg.includes('snapshot')`), 0)
  assert.equal(hits(`'删除': 'danger',`), 0)
  assert.equal(hits(`t('app.rules.saved', { name: '规则' })`), 0)
})

test('判别自检：模板写死中文抓得到、语言名称 / 词条函数 / 指令放得行', () => {
  assert.deepEqual(
    hardcodedTemplateHan(`<el-form-item label="端口"><el-option value="爬虫Bot" />访问日志</el-form-item>`),
    ['label="端口"', 'value="爬虫Bot"', '访问日志'],
  )
  assert.deepEqual(
    hardcodedTemplateHan(
      `<el-form-item :label="t('app.rules.port')" v-if="mode === '绕过'"><el-option :value="family" />` +
        `<span>{{ t('app.rules.accessLog') }}</span><el-option label="中文" value="zh-CN" /></el-form-item>`,
    ),
    [],
  )
})

test('守卫 1：前端把中文当标识的写法只减不增（基线钉）', () => {
  const found = collectZhIdentifiers()
  for (const [name, baseline] of [['比较', BASELINE_ZH_COMPARISON], ['子串判断', BASELINE_ZH_SUBSTRING]] as const) {
    const offenders = found[name]
    assert.equal(
      offenders.length,
      baseline,
      `「中文当标识·${name}」现有 ${offenders.length} 处，基线 ${baseline} 处。` +
        `变多了=新增违规：不要拿后端返回的中文文本做判断，改用后端给的稳定码（接口变更先呈报）；` +
        `变少了=基线过松，请把基线调到 ${offenders.length}。清单：\n${offenders.join('\n')}`,
    )
  }
})

test('守卫 2：模板不得写死中文（基线钉）', () => {
  const offenders = collectTemplateHan()
  assert.equal(
    offenders.length,
    BASELINE_TEMPLATE_HAN,
    `模板里写死的中文现有 ${offenders.length} 处，基线 ${BASELINE_TEMPLATE_HAN} 处。` +
      `变多了=新增违规：文字与属性值请走 t()；变少了=请把基线调到 ${offenders.length}。清单：\n${offenders.join('\n')}`,
  )
})
