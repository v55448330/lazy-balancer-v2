// 遮罩层级守卫（web/DESIGN_SPEC.md §26-11）：弹框打开时，页脚与侧栏底部用户块
// 不得浮在遮罩之上——遮罩必须覆盖到视口底部，且层级高于这两块常驻界面。
//
// 约定（三条都能被证伪）：
//   1. Element Plus 的弹框遮罩 `.el-overlay` 是 `position: fixed; inset: 0`，
//      z-index 从 2000 起逐次递增（node_modules 主题表，装包后即可复核）。
//   2. 布局级固定层（窄屏侧栏浮层 + 它的承接遮罩）必须显式取 2000 以下的号段，
//      否则从左下角用户块出发的任何点击/滚动都会落在弹框之外。
//   3. 页脚与侧栏底部用户区不声明 z-index、不做 fixed/sticky/absolute 定位，
//      因此恒处于上述固定遮罩之下。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, cssDeclarations } from './_helpers.ts'

/** Element Plus 弹框遮罩的起始 z-index（useZIndex 默认 initial 2000，逐次 +1）。 */
const EP_OVERLAY_Z_INDEX = 2000

const zIndexOf = (css: string, selector: string): number | null => {
  let decls: Map<string, string>
  try {
    decls = cssDeclarations(css, selector)
  } catch {
    return null
  }
  const raw = decls.get('z-index')
  if (raw === undefined) return null
  const value = Number(raw)
  return Number.isInteger(value) ? value : null
}

/** 一段布局 CSS 里的层级违规（空数组 = 契约成立）。 */
const layerViolations = (css: string): string[] => {
  const out: string[] = []
  for (const selector of ['.layout-aside.is-overlay', '.sidebar-backdrop']) {
    const z = zIndexOf(css, selector)
    if (z === null) {
      out.push(`${selector}: 缺少整数 z-index（无法证明低于弹框遮罩 ${EP_OVERLAY_Z_INDEX}）`)
    } else if (z >= EP_OVERLAY_Z_INDEX) {
      out.push(`${selector}: z-index ${z} ≥ ${EP_OVERLAY_Z_INDEX}——会浮在弹框遮罩之上`)
    }
  }
  for (const selector of ['.layout-footer', '.aside-footer', '.user-info']) {
    let decls: Map<string, string>
    try {
      decls = cssDeclarations(css, selector)
    } catch {
      continue // 该选择器不存在 = 没有可抬高的声明
    }
    if (decls.has('z-index')) out.push(`${selector}: 不得声明 z-index（页脚/用户块必须在遮罩之下）`)
    const position = decls.get('position')
    if (position !== undefined && /^(fixed|sticky|absolute)$/.test(position)) {
      out.push(`${selector}: position: ${position} 会让页脚/用户块脱离文档流并可能高于遮罩`)
    }
  }
  return out
}

test('判别自检：2000+ 号段被判违规，2000 以下放行', () => {
  const bad = `
    .layout-aside.is-overlay { position: fixed; z-index: 2001; }
    .sidebar-backdrop { position: fixed; z-index: 2000; }
    .layout-footer { z-index: 999; }
    .aside-footer { z-index: 5; }
    .user-info { position: sticky; }
  `
  assert.deepEqual(layerViolations(bad), [
    '.layout-aside.is-overlay: z-index 2001 ≥ 2000——会浮在弹框遮罩之上',
    '.sidebar-backdrop: z-index 2000 ≥ 2000——会浮在弹框遮罩之上',
    '.layout-footer: 不得声明 z-index（页脚/用户块必须在遮罩之下）',
    '.aside-footer: 不得声明 z-index（页脚/用户块必须在遮罩之下）',
    '.user-info: position: sticky 会让页脚/用户块脱离文档流并可能高于遮罩',
  ])
  const good = `
    .layout-aside.is-overlay { position: fixed; z-index: 1901; }
    .sidebar-backdrop { position: fixed; z-index: 1900; }
    .layout-footer { height: 44px; background-color: #ffffff; }
    .aside-footer { padding: 0; border-top: 1px solid #f3f4f6; }
    .user-info { display: flex; padding: 12px 16px; }
  `
  assert.deepEqual(layerViolations(good), [])
})

test('布局固定层低于弹框遮罩（窄屏侧栏浮层与其承接遮罩）', () => {
  const layout = code('src/components/layout/AppLayout.vue')
  const violations = layerViolations(layout)
  assert.deepEqual(
    violations,
    [],
    `布局级固定层违反 DESIGN_SPEC §26-11：\n${violations.join('\n')}\n` +
      '弹框遮罩（Element Plus .el-overlay）从 2000 起递增；侧栏浮层/承接遮罩必须取 2000 以下号段，' +
      '页脚与侧栏底部用户区不得声明 z-index 或脱离文档流。',
  )
  // 相对顺序也不能翻转：承接遮罩必须低于侧栏本体，否则点侧栏会先被遮罩吃掉。
  const aside = zIndexOf(layout, '.layout-aside.is-overlay')
  const backdrop = zIndexOf(layout, '.sidebar-backdrop')
  assert.ok(aside !== null && backdrop !== null)
  assert.ok(backdrop < aside, `sidebar-backdrop(${backdrop}) 必须低于 aside(${aside})`)
})

test('Element Plus 遮罩契约：全视口固定 + 半透明底 + 2000 起号段', () => {
  const overlay = code('node_modules/element-plus/theme-chalk/el-overlay.css')
  const decls = cssDeclarations(overlay, '.el-overlay')
  assert.equal(decls.get('position'), 'fixed', '遮罩必须固定定位（相对视口）')
  for (const edge of ['top', 'bottom', 'left', 'right']) {
    assert.equal(decls.get(edge), '0', `遮罩必须贴住视口 ${edge}（覆盖到视口底部，页脚不会露出）`)
  }
  assert.equal(Number(decls.get('z-index')), EP_OVERLAY_Z_INDEX, '遮罩号段基准变了：请复核本守卫的 2000 阈值')
  // 半透明底：既遮住下层界面、又不至于看不见上下文；透明度写在主题变量里。
  assert.equal(decls.get('background-color'), 'var(--el-overlay-color-lighter)')
  const vars = code('node_modules/element-plus/theme-chalk/el-var.css')
  const token = /--el-overlay-color-lighter:\s*(#[0-9a-fA-F]{6}([0-9a-fA-F]{2})?)/.exec(vars)
  assert.ok(token, '找不到 --el-overlay-color-lighter 的定义')
  const alpha = token[2] ?? 'ff'
  assert.notEqual(alpha.toLowerCase(), 'ff', '遮罩不得完全不透明（用户需辨认弹框背后的界面）')
  assert.notEqual(alpha.toLowerCase(), '00', '遮罩不得全透明（页脚与用户块会透亮）')
})
