// 写表单「保存中冻结」与破坏性操作「占位先于确认」的接线钉。
//
// ① 保存中冻结：payload 跨多个 await 组装、成功后由父级回填/关窗——在途时的编辑
//    会让「是否生效」取决于编辑落在哪个 await 之后，且成功提示不披露被丢弃的字段。
//    统一口径 formFrozen = isReadOnly || saving（策略向导先例），且内层控件不得用
//    `:disabled="isReadOnly"` 把表单级 disabled 遮掉（EP 取 props.disabled ?? form.disabled）。
// ② 占位先于确认：确认框悬挂期同样没有门，双击/连点会叠出第二个确认框与重复写。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, openTags, section } from './_helpers.ts'

const at = (text: string, needle: string, what: string): number => {
  const index = text.indexOf(needle)
  assert.ok(index >= 0, `missing ${what}: ${needle}`)
  return index
}

test('基础设置卡：整卡 formFrozen，卡内不残留只读门', () => {
  const page = code('src/views/settings/BasicSettings.vue')
  assert.match(page, /const formFrozen = computed\(\(\) => isReadOnly\.value \|\| saving\.value\)/)
  assert.match(page, /<el-form :model="settings" label-width="120px" class="settings-form" :disabled="formFrozen">/)
  const card = section(page, '<el-form :model="settings"', '</el-form>')
  assert.doesNotMatch(card, /:disabled="isReadOnly"/, '内层只读门会遮掉表单级冻结（EP: props.disabled ?? form.disabled）')
})

test('Caddy 全局配置卡：整卡 formFrozen（Caddy 应用可达数秒）', () => {
  const page = code('src/views/settings/CaddyGlobalSettings.vue')
  assert.match(page, /const formFrozen = computed\(\(\) => isReadOnly\.value \|\| saving\.value\)/)
  assert.match(page, /<el-form :model="settings" label-width="140px" class="caddy-form" :disabled="formFrozen">/)
  assert.match(page, /<ProxyTimeoutFields[^>]*:disabled="formFrozen"/)
  const card = section(page, '<el-form :model="settings" label-width="140px"', '</el-form>')
  assert.doesNotMatch(card, /:disabled="isReadOnly"/)
  // 存为地址列表弹框同样在保存中冻结
  assert.match(page, /<el-form label-width="80px" @submit\.prevent :disabled="savingList">/)
})

test('免费证书：ACME 卡与 DNS 配置弹框在保存中冻结', () => {
  const page = code('src/views/settings/FreeCertificates.vue')
  assert.match(page, /<el-form :model="global" label-width="140px" :disabled="isReadOnly \|\| savingGlobal">/)
  assert.match(page, /<el-form :model="form" label-width="120px" class="lb-form" :disabled="savingConfig">/)
})

test('OIDC 弹框：整表单 formFrozen + 保存中不可 ESC/X 关闭', () => {
  const page = code('src/views/settings/OIDCSettings.vue')
  assert.match(page, /const formFrozen = computed\(\(\) => isReadOnly\.value \|\| saving\.value\)/)
  assert.match(page, /<el-form :disabled="formFrozen">/)
  assert.ok(openTags(page, 'el-dialog').some((tag) => tag.includes(':close-on-press-escape="!saving"') && tag.includes(':show-close="!saving"')))
})

test('拦截页编辑器：保存中冻结（含 CodeEditor readonly）', () => {
  const page = code('src/views/security/SecurityBlockPages.vue')
  assert.match(page, /<el-form :model="form" label-width="80px" label-position="right" class="block-page-form" :disabled="saving">/)
  assert.match(page, /<CodeEditor[^>]*:readonly="saving"/)
  assert.match(page, /show-word-limit :readonly="isReadOnly \|\| currentPage\?\.is_default \|\| currentPage\?\.is_builtin \|\| saving"/)
})

test('安全规则页：自定义规则与 IP 名单表单保存中冻结', () => {
  const page = code('src/views/security/SecurityRules.vue')
  assert.match(page, /<el-form :model="ruleForm" label-width="80px" label-position="right" :disabled="isReadOnly \|\| savingRule">/)
  assert.ok(openTags(page, 'el-form').some((tag) => tag.includes('v-loading="loadingIpListDetail"') && tag.includes(':disabled="savingIpList"')))
  assert.ok(page.includes(':disabled="ipListDialogReadOnly || editingIpListPreset || savingIpList"'), '名称/分类/描述字段必须统一冻结表达式')
})

test('自动封禁名单：最终复核 GET 前进入保存态并在 finally 释放', () => {
  const page = code('src/views/security/SecurityRules.vue')
  const save = section(page, 'const saveIpList = async', 'const deletingIpListId')
  const savingAt = at(save, 'savingIpList.value = true', '名单保存占位')
  const verifyAt = at(save, 'mergeFreshAutobanEntries(editingIpListId.value, entries)', '最终复核 GET')
  assert.ok(savingAt < verifyAt, '复核在途时表单必须已经冻结')
  assert.match(save, /finally \{ savingIpList\.value = false \}/)
})

test('共享定时更新编辑器：保存中冻结星期、时间与保存入口', () => {
  const editor = code('src/components/RuleLibScheduleEditor.vue')
  assert.match(editor, /const controlsDisabled = computed\(\(\) => props\.disabled \|\| props\.saving \|\| Boolean\(props\.unavailableHint\)\)/)
  assert.match(section(editor, 'const emitSave = ', '</script>'), /if \(props\.saving\) return/)
})

test('绑定编辑器：保存中冻结策略/规则选择与分页（含函数级守卫）', () => {
  const page = code('src/components/SecurityBindingEditor.vue')
  assert.ok(openTags(page, 'el-select').some((tag) => tag.includes(':multiple="!section.single"') && tag.includes(':disabled="saving"')))
  assert.ok(openTags(page, 'el-input').some((tag) => tag.includes('class="picker-search"') && tag.includes(':disabled="saving"')))
  assert.match(page, /:disabled="pickerSelectableRules\.length === 0 \|\| saving"/)
  assert.match(page, /:disabled="saving \|\| pickerWouldExceed\(rule\)"/)
  assert.match(page, /small\s*:disabled="saving"/)
  const toggleRule = section(page, 'const toggleRule = ', 'const toggleSelectAll = ')
  assert.match(toggleRule, /if \(saving\.value\) return/)
  assert.match(section(page, 'const toggleSelectAll = ', 'const policyTypeById'), /if \(saving\.value\) return/)
})

test('自动封禁配置弹框：保存中禁 ESC/X/取消并冻结表单', () => {
  const page = code('src/views/security/SecurityEvents.vue')
  assert.ok(openTags(page, 'el-dialog').some((tag) => tag.includes(':close-on-press-escape="!autobanSaving"') && tag.includes(':show-close="!autobanSaving"')))
  assert.ok(openTags(page, 'el-form').some((tag) => tag.includes(':model="autobanForm"') && tag.includes(':disabled="autobanSaving"')))
  assert.match(page, /<el-button :disabled="autobanSaving" @click="autobanDialogVisible = false">取消<\/el-button>/)
})

test('自动封禁禁用：占位先于确认并在 finally 释放', () => {
  const page = code('src/views/security/SecurityEvents.vue')
  const toggle = section(page, 'const toggleAutobanEnabled = ', 'const ctxWafFamily')
  const pendingAt = at(toggle, 'autobanToggling.value = true', '禁用占位')
  const confirmAt = at(toggle, 'await ElMessageBox.confirm', '禁用确认')
  assert.ok(pendingAt < confirmAt, '确认阶段必须已经单飞')
  assert.match(toggle, /finally \{ autobanToggling\.value = false \}/)
})

test('规则向导：保存中各步表单冻结、步骤条与前进/后退锁定', () => {
  const page = code('src/views/Rules.vue')
  const wizard = section(page, '<el-dialog v-model="wizardVisible"', '<template #footer>')
  const forms = wizard.match(/<el-form :model="wizardForm"[^>]*>/g) ?? []
  assert.equal(forms.length, 4, `向导应有 4 个可编辑表单，实际 ${forms.length}`)
  for (const form of forms) assert.match(form, /:disabled="saving"/, `表单未冻结：${form}`)
  assert.match(page, /const stepsClickable = computed\(\(\) => editingRule\.value !== null && !saving\.value\)/)
  assert.match(section(page, 'const moveToAdjacentWizardStep = ', 'const findDuplicateUpstream'), /if \(saving\.value\) return/)
  assert.match(page, /<el-button v-if="hasPreviousStep" :disabled="saving" @click="prevStep">/)
  assert.match(page, /<el-button v-if="hasNextStep" type="primary" :disabled="saving" @click="nextStep">/)
  // 策略卡片选择同样在保存中冻结
  assert.match(section(page, 'const selectStrategy = ', 'const applyNtlmTakeover'), /if \(ntlmOn\.value \|\| saving\.value\) return/)
})

test('仪表盘 Caddy 控制：占位先于确认（连点不叠第二次重启/停止）', () => {
  const page = code('src/views/Dashboard.vue')
  const pendingAt = at(page, 'caddyLoading.value = true', 'caddyLoading 置位')
  const confirmAt = at(page, 'await ElMessageBox.confirm(actionDesc', 'Caddy 确认框')
  assert.ok(pendingAt < confirmAt, '占位必须早于确认框')
  assert.match(page, /if \(caddyLoading\.value\) return/)
  assert.match(page, /if \(!disposed\) caddyLoading\.value = false/)
})

test('API 密钥启用/禁用：占位先于确认，finally 释放', () => {
  const page = code('src/views/Keys.vue')
  const pendingAt = at(page, 'togglePendingId.value = key.id', '密钥占位')
  const confirmAt = at(page, '确定要禁用 API 密钥', '密钥禁用确认')
  assert.ok(pendingAt < confirmAt, '占位必须早于确认框')
  assert.match(page, /finally \{\s*togglePendingId\.value = null\s*\}/)
})

test('用户启用/禁用：占位先于确认，取消回滚乐观开关后仍释放占位', () => {
  const page = code('src/views/Users.vue')
  const pendingAt = at(page, 'switchingIds.value.add(id)', '用户占位')
  const confirmAt = at(page, '确定要禁用这个用户吗？', '用户禁用确认')
  assert.ok(pendingAt < confirmAt, '占位必须早于确认框')
  assert.match(page, /finally \{\s*switchingIds\.value\.delete\(id\)\s*\}/)
})
