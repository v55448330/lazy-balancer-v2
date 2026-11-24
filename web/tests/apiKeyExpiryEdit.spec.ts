// API 密钥有效期可改：功能配置弹框的有效期控件与创建同款；过期时间只在改动时
// 提交（PATCH 语义——已过期的密钥改其它设置不必先续期）；前后端请求形态对表。
// 运行：cd web && node --test tests/apiKeyExpiryEdit.spec.ts
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, member, openTags, repoCode, section } from './_helpers.ts'

const PAGE = 'src/views/Keys.vue'

test('功能配置的有效期控件与创建同款（类型/可清空/格式/禁用过去日期/占位）', () => {
  const pickers = openTags(code(PAGE), 'el-date-picker').map((tag) =>
    tag.replace(/create(Form|ExpiresError)/g, 'X').replace(/feature(Form|ExpiresError)/g, 'X'))
  assert.equal(pickers.length, 2, '创建与功能配置各一个有效期控件')
  assert.match(
    pickers[0],
    /v-model="X\.expiresAt"\s+type="datetime"\s+clearable\s+format="YYYY-MM-DD HH:mm:ss"\s+:disabled-date="disablePastDate"/,
  )
  assert.equal(pickers[0], pickers[1], '功能配置的有效期控件不得与创建漂移')
})

test('打开功能配置带入当前过期时间；列表给的坏值按未设置，不得把 Invalid Date 喂给控件', () => {
  const page = code(PAGE)
  assert.match(member(page, 'const openFeatureDialog = '), /expiresAt: toPickerDate\(key\.expires_at\)/)
  assert.match(member(page, 'const toPickerDate = '), /Number\.isNaN\(date\.getTime\(\)\) \? null : date/)
  const reset = member(page, 'const resetFeatureForm = ')
  assert.match(reset, /expiresAt: null/)
  assert.match(reset, /featureExpiresError\.value = ''/)
})

test('过期时间只在改动时提交；过去的时刻在确认框之前拦截', () => {
  const save = member(code(PAGE), 'const saveFeatures = async ')
  const blockAt = save.indexOf("featureExpiresError.value = t('common.app.views.keys.expiresPastError')")
  const confirmAt = save.indexOf('await ElMessageBox.confirm(')
  assert.ok(blockAt > 0 && confirmAt > blockAt, '过期时间校验必须先于确认框')
  assert.match(
    save,
    /const expiryChanged = \(expiresAt\?\.getTime\(\) \?\? null\) !== \(toPickerDate\(featureTarget\.value\.expires_at\)\?\.getTime\(\) \?\? null\)/,
  )
  assert.match(save, /if \(expiryChanged && expiresAt && expiresAt\.getTime\(\) < Date\.now\(\)\)/)
  assert.match(save, /\.\.\.\(expiryChanged \? \{ expires_at: expiresAt \? expiresAt\.toISOString\(\) : null \} : \{\}\)/)
})

test('功能配置确认文案列明过期时间（zh/en 成对）', () => {
  assert.ok(code('src/locales/zh/views.ts').includes('MCP 开关、只读权限、过期时间和 IP 白名单'))
  assert.ok(code('src/locales/en/views.ts').includes('MCP switch, read-only permission, expiry and IP whitelist'))
})

test('功能配置沿用创建的「有效期与来源限制」分组标题，旧「来源限制」键不残留', () => {
  const dialog = section(code(PAGE), 'v-model="featureDialogVisible"', '<template #footer>')
  assert.match(dialog, /keys\.expirySourceSection/)
  for (const path of [PAGE, 'src/locales/zh/views.ts', 'src/locales/en/views.ts']) {
    assert.doesNotMatch(code(path), /sourceRestrictSection/, `${path} 不得残留旧分组键`)
  }
})

test('前端请求类型与后端更新端点同形：expires_at 可为时间串或 null', () => {
  assert.match(code('src/types/index.ts'), /export interface UpdateAPIKeyInput \{[^}]*readonly expires_at\?: string \| null[^}]*\}/)
  assert.match(repoCode('internal/handlers/apikeys.go'), /ExpiresAt json\.RawMessage `json:"expires_at"`/)
})
