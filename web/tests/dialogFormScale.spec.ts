// 弹框与表单尺度守卫（web/DESIGN_SPEC.md §26；用户 2026-11-25 裁定「弹框宽度根据
// 弹框内容、样式、布局决定」等四项原则，具体数值由主审定在 §26）。
//
// 四道守卫，都是「基线钉」——当前数量必须恰好等于基线：变多 = 新增违规；变少 =
// 基线过松，请在同一提交里把基线调低。存量随界面统一分批改掉。
//
//   U1 弹框宽度：width 只能是 §26-1 五种写法之一 min(520|640|760|960|1200px, 94vw)。
//   U2 分区标题：分隔线式标题（<el-divider class="section-divider">）废止，改用
//      DialogSectionHeader。
//   U3 直角：样式里白名单外的非零圆角选择器。白名单 = 规范 §26-10 的四个语义图形
//      + 真正的圆点 / 头像 / 加载圈 + 键盘焦点环 + 滚动条滑块。
//   U4 页脚顺序：「取消」等非主操作按钮不得排在主操作（primary）右边。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, openTags, webFiles } from './_helpers.ts'

const CANONICAL_DIALOG_WIDTH = /^min\((520|640|760|960|1200)px, 94vw\)$/

/** 弹框开标签里不合规的宽度写法。 */
const nonCanonicalDialogWidths = (tag: string): string[] => {
  const match = /\swidth="([^"]*)"/.exec(tag)
  if (match && CANONICAL_DIALOG_WIDTH.test(match[1]!)) return []
  return [match ? match[1]! : '(未设 width)']
}

const SECTION_DIVIDER = /<el-divider\b[^>]*\bclass="[^"]*section-divider[^"]*"/g

// 圆角白名单：规范 §26-10 的四个语义图形；圆点 / 头像 / 加载圈；键盘焦点环；滚动条滑块。
const RADIUS_ALLOWLIST = [
  /^\.stat-icon$/,
  /^\.stat-item$/,
  /channel-type-icon/,
  /(?:^|[-_])(?:dot|avatar|spinner|circle)(?=$|[^a-z])/i,
  /:focus-visible$/,
  /scrollbar-thumb/,
  // 在线指示圆点（ThreatScreen 实时状态灯）
  /^\.live-chip i$/,
]

/** 一段 CSS 里的非零圆角（返回 `选择器 { 圆角 }`）；跳过白名单选择器。 */
const nonZeroRadii = (css: string): string[] => {
  const out: string[] = []
  for (const match of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    const selector = match[1]!.trim().split('\n').pop()!.trim()
    if (!selector || RADIUS_ALLOWLIST.some((pattern) => pattern.test(selector))) continue
    for (const radius of match[2]!.match(/border-radius\s*:\s*([^;]+);/g) ?? []) {
      const value = radius.replace(/border-radius\s*:\s*/i, '').replace(/!important/, '').replace(/;$/, '').trim()
      if (value === '0') continue
      out.push(`${selector} { ${value} }`)
    }
  }
  return out
}

/** 页脚模板里排在主操作右侧的其它按钮。 */
const footerButtonsAfterPrimary = (footer: string): string[] => {
  const buttons = openTags(footer, 'el-button')
  const primaryAt = buttons.findIndex((tag) => /\stype="primary"/.test(tag))
  if (primaryAt < 0) return []
  return buttons.slice(primaryAt + 1).filter((tag) => !/\stype="primary"/.test(tag))
}

const vueFiles = (): string[] => webFiles('src', ['.vue'])

const collectDialogWidths = (): string[] => {
  const out: string[] = []
  for (const path of vueFiles()) {
    for (const tag of openTags(code(path), 'el-dialog')) {
      for (const width of nonCanonicalDialogWidths(tag)) out.push(`${path}: width="${width}"`)
    }
  }
  return out
}

const collectSectionDividers = (): string[] => {
  const out: string[] = []
  for (const path of vueFiles()) {
    const count = (code(path).match(SECTION_DIVIDER) ?? []).length
    if (count > 0) out.push(`${path} ×${count}`)
  }
  return out
}

const collectRadii = (): string[] => {
  const out: string[] = []
  for (const path of [...vueFiles(), 'src/styles/main.css']) {
    const text = code(path)
    const blocks = path.endsWith('.css') ? [text] : [...text.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/g)].map((match) => match[1]!)
    for (const block of blocks) {
      for (const hit of nonZeroRadii(block)) out.push(`${path}: ${hit}`)
    }
  }
  return out
}

const collectFooters = (): string[] => {
  const out: string[] = []
  for (const path of vueFiles()) {
    for (const match of code(path).matchAll(/<template\s+#footer>([\s\S]*?)<\/template>/g)) {
      for (const tag of footerButtonsAfterPrimary(match[1]!)) out.push(`${path}: ${tag.replace(/\s+/g, ' ').slice(0, 90)}`)
    }
  }
  return out
}

// 当前存量（2026-11-25 基线）。修掉存量后把数字调低；调高即新增违规。
const BASELINE_DIALOG_WIDTH = 55
const BASELINE_SECTION_DIVIDER = 9
const BASELINE_RADIUS = 36
const BASELINE_FOOTER_ORDER = 2

test('判别自检：弹框宽度只认五种写法', () => {
  assert.deepEqual(nonCanonicalDialogWidths(`<el-dialog width="min(640px, 94vw)" top="6vh">`), [])
  assert.deepEqual(nonCanonicalDialogWidths(`<el-dialog width="min(1200px, 94vw)">`), [])
  assert.deepEqual(nonCanonicalDialogWidths(`<el-dialog width="min(620px, 92vw)">`), ['min(620px, 92vw)'])
  assert.deepEqual(nonCanonicalDialogWidths(`<el-dialog width="min(560px, 94vw)">`), ['min(560px, 94vw)'])
  assert.deepEqual(nonCanonicalDialogWidths(`<el-dialog width="min(900px, 96vw)">`), ['min(900px, 96vw)'])
  assert.deepEqual(nonCanonicalDialogWidths(`<el-dialog :model-value="visible">`), ['(未设 width)'])
})

test('判别自检：分隔线式分区标题、白名单外圆角、页脚顺序', () => {
  assert.equal(('<el-divider content-position="left" class="section-divider">权限</el-divider>'.match(SECTION_DIVIDER) ?? []).length, 1)
  assert.equal(('<DialogSectionHeader title="权限" />'.match(SECTION_DIVIDER) ?? []).length, 0)
  assert.deepEqual(
    nonZeroRadii('.strategy-card { border-radius: 8px; } .stat-icon { border-radius: 8px; } .tm-dot { border-radius: 50%; } .el-link:focus-visible { border-radius: 3px; } .box { border-radius: 0; } .card { padding: 4px; }'),
    ['.strategy-card { 8px }'],
  )
  assert.deepEqual(footerButtonsAfterPrimary(`<el-button>取消</el-button><el-button type="primary">保存</el-button>`), [])
  assert.deepEqual(footerButtonsAfterPrimary(`<el-button @click="test">测试连接</el-button><el-button>取消</el-button><el-button type="primary">保存</el-button>`), [])
  assert.deepEqual(
    footerButtonsAfterPrimary(`<el-button type="primary">保存</el-button><el-button>取消</el-button>`),
    ['<el-button>'],
  )
  assert.deepEqual(footerButtonsAfterPrimary(`<el-button type="primary">确定</el-button>`), [])
})

test('U1 弹框宽度：只允许 §26-1 的五种写法（基线钉）', () => {
  const offenders = collectDialogWidths()
  assert.equal(
    offenders.length,
    BASELINE_DIALOG_WIDTH,
    `宽度不合规的弹框现有 ${offenders.length} 个，基线 ${BASELINE_DIALOG_WIDTH} 个。变多了=新增违规：宽度写作 min(520|640|760|960|1200px, 94vw)；` +
      `变少了=请把基线调到 ${offenders.length}。清单：\n${offenders.join('\n')}`,
  )
})

test('U2 分区标题：分隔线式标题只减不增（基线钉）', () => {
  const offenders = collectSectionDividers()
  const count = offenders.reduce((sum, line) => sum + Number(/×(\d+)$/.exec(line)![1]), 0)
  assert.equal(
    count,
    BASELINE_SECTION_DIVIDER,
    `分隔线式分区标题现有 ${count} 处，基线 ${BASELINE_SECTION_DIVIDER} 处。变多了=新增违规：分区标题请用 DialogSectionHeader；` +
      `变少了=请把基线调到 ${count}。清单：\n${offenders.join('\n')}`,
  )
})

test('U3 直角：白名单外的非零圆角只减不增（基线钉）', () => {
  const offenders = collectRadii()
  assert.equal(
    offenders.length,
    BASELINE_RADIUS,
    `白名单外的非零圆角现有 ${offenders.length} 处，基线 ${BASELINE_RADIUS} 处。变多了=新增违规：容器一律直角（§26-10）；` +
      `变少了=请把基线调到 ${offenders.length}。清单：\n${offenders.join('\n')}`,
  )
})

test('U4 页脚顺序：非主操作不得排在主操作右侧（基线钉）', () => {
  const offenders = collectFooters()
  assert.equal(
    offenders.length,
    BASELINE_FOOTER_ORDER,
    `排在主操作右侧的其它按钮现有 ${offenders.length} 个，基线 ${BASELINE_FOOTER_ORDER} 个。变多了=新增违规：页脚右侧「取消 + 主操作」；` +
      `变少了=请把基线调到 ${offenders.length}。清单：\n${offenders.join('\n')}`,
  )
})
