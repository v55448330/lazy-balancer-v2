// 审计动作词色调验收：例外表 + 关键词派生 + 未命中告警。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code } from './_helpers.ts'
import { actionTagType } from '../src/utils/auditActionTone.ts'

test('既有动作词色调不回归（例外表逐类代表）', () => {
  const expectations: Array<[string, string]> = [
    ['删除', 'danger'],
    ['禁用', 'danger'],
    ['配置漂移', 'danger'],
    ['渲染跳过', 'danger'], // 含「跳过」但语义是配置错误
    ['自动封禁', 'danger'],
    ['更新', 'warning'],
    ['重置密码', 'warning'],
    ['提升完成', 'warning'], // 含「完成」但风险操作
    ['同步应用', 'warning'],
    ['签发限流', 'warning'],
    ['创建', 'success'],
    ['重置', 'success'],
    ['自动解封', 'success'],
    ['自动检测', 'success'],
  ]
  for (const [action, tone] of expectations) {
    assert.equal(actionTagType(action), tone, `${action} 色调漂移`)
  }
})

test('关键词派生：新动作词自动归类（不再静默落灰色）', () => {
  assert.equal(actionTagType('突发异常'), 'danger')
  assert.equal(actionTagType('策略阻断'), 'danger')
  assert.equal(actionTagType('导入拒绝'), 'danger')
  assert.equal(actionTagType('导出警告'), 'warning')
  assert.equal(actionTagType('渲染跳过后续'), 'warning')
  assert.equal(actionTagType('缓存降级'), 'warning')
  assert.equal(actionTagType('同步完成'), 'success')
  assert.equal(actionTagType('签发成功'), 'success')
  assert.equal(actionTagType('例行巡检'), 'info')
})

test('判定优先级 danger > warning > success（顺序契约单点钉在此处）', () => {
  // Go 侧跨栈检查只判「动作是否可分类」，不在 Go 里复刻顺序；改序必须
  // 先破坏本用例，避免两侧各按一套顺序双绿。
  assert.equal(actionTagType('同步失败跳过'), 'danger', '同时含 danger/warning 词时 danger 优先')
  assert.equal(actionTagType('同步跳过完成'), 'warning', '同时含 warning/success 词时 warning 优先')
  assert.equal(actionTagType('导出成功跳过'), 'warning', 'success 词不得越过 warning 词')
})

test('原型链键不得冒充例外表命中（constructor 等落 info 兜底，返回字符串）', () => {
  // 例外表是普通对象：直接下标会让 'constructor'/'toString'/'valueOf' 取到
  // Object.prototype 上的函数（真值）并被当作色调返回，渲染层拿到函数值。
  for (const action of ['constructor', 'toString', 'valueOf', 'hasOwnProperty', '__proto__']) {
    const tone: unknown = actionTagType(action)
    assert.equal(typeof tone, 'string', `${action} 不得返回函数`)
    assert.equal(tone, 'info', `${action} 无关键词可派生 → info 兜底`)
  }
})

test('未命中动作词只告警一次（去重）', () => {
  const warnings: string[] = []
  const original = console.warn
  console.warn = (...args: unknown[]) => { warnings.push(args.join(' ')) }
  try {
    assert.equal(actionTagType('神秘新动作'), 'info')
    assert.equal(actionTagType('神秘新动作'), 'info')
  } finally {
    console.warn = original
  }
  assert.equal(warnings.length, 1)
  assert.match(warnings[0], /神秘新动作/)
})

test('视图消费单源（不再自带百行字面量表）', () => {
  const page = code('src/views/AuditLog.vue')
  assert.match(page, /import \{ actionTagType \} from '@\/utils\/auditActionTone'/)
  assert.doesNotMatch(page, /ACTION_TAG_TABLE/)
})

// ── 批次 D(audit 域)双钉:AuditLog 用户可见文案 i18n 接线 ──
// 调用点钉键(common.app.views.audit.*),zh 母本(locales/zh/views.ts)钉原文。
// 母本钉在 integrator 落库 views.ts 前为红(带明确指引),落库后转绿;
// 行为解析钉以 tSafe 相位兜底:接线前=键名自环(拦硬编码/换键),落库后=zh 逐字。

import { tSafe } from '../src/i18n/tSafe.ts'
import { existsSync } from 'node:fs'

const view = (key: string, params?: Record<string, unknown>): string =>
  tSafe(`common.app.views.audit.${key}`, params)

test('审计页文案走 i18n 键(调用点钉键),动作词色调键不词条化、展示词条化', () => {
  const page = code('src/views/AuditLog.vue')
  for (const key of ['title', 'subtitle', 'loadFailedBanner', 'retryNow', 'rangeSeparator', 'rangeStartPlaceholder', 'rangeEndPlaceholder', 'operator', 'action', 'resource', 'keywordPlaceholder', 'filter', 'reset', 'optionsIncomplete', 'retry', 'listLoadFailed', 'emptyLogs', 'colTime', 'colDetail', 'totalStaleHint']) {
    assert.ok(page.includes(`common.app.views.audit.${key}`), `AuditLog 调用点必须含 audit.${key} 词条键`)
  }
  // 三个下拉的 placeholder 都要显性化(wiring 语义保持,键形替换字面量)
  const selects = page.slice(page.indexOf('<div class="filter-bar">'), page.indexOf('<el-table'))
  assert.equal((selects.match(/optionsIncomplete \?/g) ?? []).length, 3, '三个下拉的 placeholder 都要显性化')
  // 动作词是后端审计词表的匹配键/数据原文,不是 UI 文案:actionTagType(row.action)
  // 色调派生保持原文;el-tag 展示内插值经枚举词条函数(en 翻译/zh 原样,表外值
  // 回落原文——audit-i18n 方案 C 第 1 步,枚举钉见 auditVocabularyPairs.spec.ts)。
  assert.match(page, /:type="actionTagType\(row\.action\)"/)
  assert.match(page, /\{\{ auditActionLabel\(row\.action\) \}\}/)
  assert.doesNotMatch(page, /\{\{ row\.action \}\}/, '动作展示不得回退渲染库值原样')
})

test('审计页 zh 母本钉(integrator 词条接线后逐字)', () => {
  const lexicon = new URL('../src/locales/zh/views.ts', import.meta.url)
  assert.ok(existsSync(lexicon), '词条母本 src/locales/zh/views.ts 未落库(integrator 接线);落库后本钉与行为解析钉转绿')
  const zhLexicon = code('src/locales/zh/views.ts')
  for (const text of ['操作日志', '记录系统中所有写操作和配置变更', '操作日志加载失败：列表为空不代表没有日志', '立即重试', '暂无操作日志', '筛选选项未完整加载，下拉列表可能缺项', '统计总数来自缓存，可能滞后数秒']) {
    assert.ok(zhLexicon.includes(text), `audit 词条 zh 原文「${text}」必须在母本中`)
  }
  for (const [key, text] of [
    ['title', '操作日志'], ['loadFailedBanner', '操作日志加载失败：列表为空不代表没有日志'],
    ['emptyLogs', '暂无操作日志'], ['totalStaleHint', '统计总数来自缓存，可能滞后数秒'],
  ] as const) {
    assert.equal(view(key), text, `audit.${key} 必须解析为 zh 原文(接线前=键名自环)`)
  }
})
