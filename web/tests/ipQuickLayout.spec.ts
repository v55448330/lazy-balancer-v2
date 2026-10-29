// IP 快捷弹框布局契约：目标名单面板与下方名单同宽（不得再额外缩进 16px）、
// 展开引用策略时移除按钮固定首行。断言走「声明集」判定——单行整串钉
// （`.ipm-target-panel { margin: 11px 0 3px;`）在换行重排、增删声明、属性顺序
// 调整时都会假红，而界面完全没变。
//
// 运行：cd web && node --test tests/ipQuickLayout.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, cssDeclarations } from './_helpers.ts'

// 水平外边距：`margin` 简写与 margin-left/right 长写等价，只判语义。
const horizontalMargins = (decls: Map<string, string>): string[] => {
  const shorthand = decls.get('margin')
  if (shorthand) {
    const parts = shorthand.split(/\s+/)
    return [parts[1] ?? parts[0], parts[3] ?? parts[1] ?? parts[0]]
  }
  return [decls.get('margin-left') ?? '0', decls.get('margin-right') ?? '0']
}

test('IP 快捷弹框：目标名单与下方名单同宽，空策略链接可导航', () => {
  const page = code('src/views/security/IPLocationAction.vue')
  assert.deepEqual(
    horizontalMargins(cssDeclarations(page, '.ip-quick-popper .ipm-target-panel')),
    ['0', '0'],
    '目标名单面板不得再有水平缩进（否则与下方名单不同宽）',
  )
  assert.match(page, /@click\.prevent="goSecurityPolicies"/)
  assert.match(page, /const goSecurityPolicies = \(\): void =>/)
  assert.match(page, /authStore\.setCurrentPage\('security-policies'\)/)
  const noTarget = cssDeclarations(page, '.ip-quick-popper .ipm-no-target')
  assert.equal(noTarget.get('display'), 'grid', '空态按两行堆叠')
  const noTargetLink = cssDeclarations(page, '.ip-quick-popper .ipm-no-target a')
  assert.equal(noTargetLink.get('display'), 'inline-block')
  assert.equal(noTargetLink.get('margin-left'), '0', '空态链接不得再左缩进（与说明文字对齐）')
})

test('IP 快捷弹框：展开引用策略时移除按钮固定首行，不随内容下移', () => {
  const page = code('src/views/security/IPLocationAction.vue')
  const actions = cssDeclarations(page, '.ip-quick-popper .ipm-source-actions')
  assert.equal(actions.get('display'), 'flex')
  assert.equal(actions.get('flex'), 'none', '动作列不得被压缩（内容变宽时按钮会被挤到下一行）')
  assert.equal(actions.get('align-self'), 'flex-start', '动作列必须固定在行首')
  assert.equal(
    cssDeclarations(page, '.ip-quick-popper .ipm-source').get('align-items'),
    'flex-start',
    '行容器按顶部对齐（否则单行内容仍会把按钮列拉伸到居中）',
  )
})
