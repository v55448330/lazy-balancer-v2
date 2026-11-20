// 全仓前端设计守卫（DESIGN_SPEC.md 的机器化落地，用户裁定 2026-11-19 第四轮）：
// 后续任何前端新增/修改违反设计标准即红、无法交付。规则与豁免同口径：
// 豁免必须登记理由（legacy 内嵌面板/百分号输入），条目失效（文件改合规）即红。
//
// 运行：cd web && npm test（node --test 自动纳入）。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, webFiles } from './_helpers.ts'

// shadow="never" 豁免：对话框内嵌面板（dialog-panel--flush），非页面级卡片。
// 页面级 list-card/图表卡一律默认 always（DESIGN_SPEC §2）。
const SHADOW_NEVER_EXEMPT = [
  'src/components/rules/PathRulesEditor.vue', // 规则编辑弹框内嵌路径面板
]
// v-model.number 豁免：权重百分号输入（el-input-number 无 % suffix 形态）。
// 其余数字输入一律 el-input-number（DESIGN_SPEC §8）。
const VMODEL_NUMBER_EXEMPT = [
  'src/components/rules/PathRulesEditor.vue', // upstream.weight 带 % suffix
]

test('设计守卫：禁止 window.confirm/window.alert（确认一律 ElMessageBox）', () => {
  for (const f of webFiles('src', ['.vue', '.ts'])) {
    const src = code(f)
    assert.ok(!/window\.(confirm|alert)\(/.test(src), `${f} 使用 window.confirm/alert，违反 DESIGN_SPEC §7`)
  }
})

test('设计守卫：v-chart 必须经 chartBase/统一 echarts 注册（禁手搓图表）', () => {
  for (const f of webFiles('src', ['.vue'])) {
    const src = code(f)
    if (!src.includes('<v-chart')) continue
    assert.ok(
      src.includes('chartBase') || src.includes('utils/echarts'),
      `${f} 使用 v-chart 但未导入 chartBase/utils/echarts，违反 DESIGN_SPEC §4`,
    )
  }
})

test('设计守卫：shadow="never" 仅限登记的内嵌面板（页面卡默认 always）', () => {
  const hits: string[] = []
  for (const f of webFiles('src', ['.vue'])) {
    if (code(f).includes('shadow="never"')) hits.push(f)
  }
  for (const f of hits) {
    assert.ok(SHADOW_NEVER_EXEMPT.includes(f), `${f} shadow="never" 未登记豁免，违反 DESIGN_SPEC §2`)
  }
  // 豁免条目必须仍在违规（改合规后应删除条目，防豁免漂移）
  for (const f of SHADOW_NEVER_EXEMPT) {
    assert.ok(hits.includes(f), `豁免 ${f} 已无 shadow="never"，请从 SHADOW_NEVER_EXEMPT 删除`)
  }
})

test('设计守卫：v-model.number 仅限登记的百分号输入（其余 el-input-number）', () => {
  const hits: string[] = []
  for (const f of webFiles('src', ['.vue'])) {
    if (code(f).includes('v-model.number')) hits.push(f)
  }
  for (const f of hits) {
    assert.ok(VMODEL_NUMBER_EXEMPT.includes(f), `${f} v-model.number 未登记豁免，违反 DESIGN_SPEC §8`)
  }
  for (const f of VMODEL_NUMBER_EXEMPT) {
    assert.ok(hits.includes(f), `豁免 ${f} 已无 v-model.number，请从 VMODEL_NUMBER_EXEMPT 删除`)
  }
})

test('设计守卫：通知/密钥面表头左对齐（设计标准 bearer，禁 center/right）', () => {
  const bearers = [
    'src/views/notifications/NotificationCenter.vue',
    'src/views/notifications/DeliveryLog.vue',
    'src/views/notifications/ChannelCards.vue',
    'src/views/Keys.vue',
  ]
  for (const f of bearers) {
    const src = code(f)
    assert.ok(!/align="(center|right)"/.test(src), `${f} 表头/列 align=center/right，违反表头左对齐标准`)
  }
})

test('设计守卫：通知面标准（描述类/分区竖条/弹框体高度/预览固定/多选去对号）', () => {
  const nc = code('src/views/notifications/NotificationCenter.vue')
  // 描述必须用标准类，禁自写 hint 覆写
  assert.ok(!/tpl-lang-hint/.test(nc), '描述禁用自写 tpl-lang-hint（应 form-tip-inline）')
  assert.match(nc, /class="form-tip-inline"/, '同行描述必须用 form-tip-inline')
  assert.match(nc, /class="form-tip-line"/, '块级描述必须用 form-tip-line')
  // 分区标题彩色竖条：DialogSectionHeader
  assert.match(nc, /import DialogSectionHeader from '@\/components\/DialogSectionHeader\.vue'/, '分区标题必须用 DialogSectionHeader')
  assert.match(nc, /<DialogSectionHeader :title="tplEditorLabel" \/>/, '内容模板分区标题带竖条')
  // 弹框体高度上限（append-to-body 用全局类）
  assert.match(nc, /\.rule-edit-dialog \.el-dialog__body \{ max-height: calc\(100vh - \d+px\); overflow-y: auto; overflow-x: hidden; \}/, '模板弹框体必须限高滚动')
  assert.match(nc, /\.daily-preview-dialog \.el-dialog__body \{ max-height: calc\(100vh - \d+px\)/, '日报预览弹框体必须限高')
  // 预览固定高度 + 禁横向滚动
  assert.match(nc, /height: 360px; max-height: 46vh/, '预览区必须固定高度')
  assert.match(nc, /\.daily-preview-body \{ height: 420px; max-height: 46vh; overflow-y: auto; overflow-x: hidden;/, '日报预览固定同高且无横向滚动')
  // bordered 多选隐藏勾选对号
  assert.match(nc, /\.notif-pick-group \.el-checkbox\.is-bordered \.el-checkbox__inner \{ display: none; \}/, 'bordered 多选必须隐藏勾选对号')
  // 卡头保存为实体按钮（非 link）
  assert.ok(!/link type="primary" :loading="savingDaily"/.test(nc), '每日摘要保存必须为实体按钮（与规则卡头一致）')
})
