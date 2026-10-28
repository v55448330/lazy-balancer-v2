// 管理面板 HTTPS 确认门：已保存的上传证书可沿用。
//
// 后端 PUT /admin-tls 在 mode=upload 且未携带 cert_file/key_file 时保留库内
// 证书材料（internal/handlers/admintls.go），故「关闭强制加密 → 再开启」不需要
// 重传文件。前端曾以「弹框里有 certInfo」为唯一放行条件，而 staged 证书在保存
// 成功后即清空 → 再次开启时「确定」恒灰、只能重传或改用自签（后者会清空上传
// 证书材料）。本用例钉住门判据 + 组件接线 + 部分成功披露。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { adminTlsConfirmDisabled, adminTlsPendingChange, adminTlsReusesSavedCert, adminTlsSendsStagedCert } from '../src/utils/adminTlsGate.ts'
import { repoCode, section, code } from './_helpers.ts'

const stored = (overrides: Partial<{ savedMode: string; hasSavedCert: boolean; certError: string }> = {}) => ({
  savedMode: 'upload',
  hasSavedCert: true,
  certError: '',
  ...overrides,
})

const form = (overrides: Partial<{
  mode: string
  certFile: unknown
  keyFile: unknown
  certInfo: { days_left: number } | null
}> = {}) => ({
  mode: 'upload',
  certFile: null,
  keyFile: null,
  certInfo: null,
  ...overrides,
})

test('库内已保存上传证书：未选新文件即可确认启用', () => {
  assert.equal(adminTlsReusesSavedCert(stored(), form()), true)
  assert.equal(adminTlsConfirmDisabled(stored(), form()), false, '关闭后再开启不得要求重传文件')
})

test('库内证书损坏（cert_info_error 非空）必须重传', () => {
  const broken = stored({ certError: '证书已损坏' })
  assert.equal(adminTlsReusesSavedCert(broken, form()), false)
  assert.equal(adminTlsConfirmDisabled(broken, form()), true)
})

test('库内无可解析证书 / 已保存为自签时不沿用', () => {
  assert.equal(adminTlsConfirmDisabled(stored({ hasSavedCert: false }), form()), true)
  assert.equal(adminTlsConfirmDisabled(stored({ savedMode: 'selfsigned' }), form()), true)
})

test('用户选择了新文件但解析失败不得静默沿用旧证书', () => {
  const picked = form({ certFile: {}, keyFile: {} })
  assert.equal(adminTlsReusesSavedCert(stored(), picked), false)
  assert.equal(adminTlsConfirmDisabled(stored(), picked), true)
})

test('新证书已校验且未过期 → 放行；过期 → 拦截', () => {
  assert.equal(adminTlsConfirmDisabled(stored(), form({ certInfo: { days_left: 30 }, certFile: {}, keyFile: {} })), false)
  assert.equal(adminTlsConfirmDisabled(stored(), form({ certInfo: { days_left: 0 }, certFile: {}, keyFile: {} })), true)
})

test('自签模式不需要证书材料', () => {
  assert.equal(adminTlsConfirmDisabled(stored({ savedMode: 'selfsigned', hasSavedCert: true }), form({ mode: 'selfsigned' })), false)
})

test('组件接线：确定按钮与 confirmAdminTls 共用同一门', () => {
  const page = code('src/views/settings/BasicSettings.vue')
  assert.match(page, /:disabled="adminTlsConfirmBlocked"/, '按钮必须消费统一判据')
  const confirm = section(page, 'const confirmAdminTls = async () => {', 'loadAdminTls()')
  assert.match(confirm, /if \(adminTlsConfirmBlocked\.value\) return/)
  assert.match(confirm, /stagedAdminTlsCert\.value = mode === 'upload' && certFile && keyFile && certInfo/)
  // 沿用分支必须保持 staged 为空（载荷只发 enabled+mode，材料由后端保留）
  // 父级刷新改由 onSave 回调 await；TLS 段仍在其后执行，保存门断言覆盖同一区段。
  const save = section(page, 'const handleSave = async', 'const parentRefresh = props.onSave')
  assert.match(save, /adminTlsHasCert\.value/, '保存门必须认「库内已有证书」')
})

test('沿用提示与全局样式类一致（无局部 hack）', () => {
  const page = code('src/views/settings/BasicSettings.vue')
  const reuseBar = section(page, 'v-if="adminTlsReuseSaved', '</div>')
  assert.match(reuseBar, /class="info-note-bar"/)
  assert.match(reuseBar, /info-note-desc/)
})

test('/admin-tls 保存语义：不带材料即保留库内证书（跨栈对照）', () => {
  const go = repoCode('internal/handlers/admintls.go')
  assert.match(go, /cert, key := current\.Cert, current\.Key/, '默认沿用库内证书材料')
  assert.match(go, /if mode == "upload" && input\.hasUploadPayload\(\)/, '仅在带材料时才替换证书')
})

test('两段写：/config 已落库时 TLS 段失败须披露部分成功', () => {
  const page = code('src/views/settings/BasicSettings.vue')
  const save = section(page, 'const handleSave = async', 'const message = (saveResp')
  assert.ok(
    save.indexOf("emit('save')") < save.indexOf("'/admin-tls'"),
    '父级刷新必须先于 TLS 段（否则 TLS 失败让基础设置看起来整单未生效）',
  )
  const tls = section(page, "if (tlsPending) {", '} else {')
  assert.match(tls, /silent: true/, 'TLS 段失败由本段自报部分成功，不得再弹全局「保存失败」')
  assert.match(tls, /基础设置已保存；HTTPS 配置保存失败/)
  const failure = section(tls, 'catch (tlsError)', '\n      }\n')
  assert.doesNotMatch(failure, /stagedAdminTlsCert\.value = null/, '失败时不得清除已暂存证书')
  assert.match(failure, /tlsError instanceof Error/, '失败原因必须取自后端错误文案')
})

// 「已暂存但判净」：adminTlsDirty 曾在 `!enabled` 处提前 false——用户在
// 开启态选好并校验了上传证书后把开关关回禁用态，暂存材料既不算变更也不随保存
// 发送，界面却回「保存成功」，材料静默丢失。判据与材料发送条件均与 enabled 解耦。

test('已暂存证书在禁用态同样是待提交变更（不得提前判净）', () => {
  const state = (overrides: Partial<{
    enabled: boolean
    mode: string
    savedEnabled: boolean
    savedMode: string
    hasStagedCert: boolean
  }> = {}) => ({
    enabled: false,
    mode: 'upload',
    savedEnabled: false,
    savedMode: 'upload',
    hasStagedCert: false,
    ...overrides,
  })
  assert.equal(adminTlsPendingChange(state()), false, '无变更不得虚报暂存')
  assert.equal(adminTlsPendingChange(state({ hasStagedCert: true })), true, '禁用态暂存证书被提前判净→材料静默丢弃')
  assert.equal(adminTlsPendingChange(state({ enabled: true })), true, '开关差异')
  assert.equal(adminTlsPendingChange(state({ enabled: true, mode: 'selfsigned' })), true, '启用态来源差异')
  assert.equal(adminTlsPendingChange(state({ mode: 'selfsigned' })), false, '禁用态来源不参与生效，判净口径保持不变')
})

test('材料发送判据只认「暂存材料 + upload 来源」（与 enabled 解耦）', () => {
  // 后端对「禁用态但本次上传了新证书材料」同样校验配对/有效期并落库
  // （internal/handlers/admintls.go），故发送条件不得串 enabled。
  assert.equal(adminTlsSendsStagedCert({ mode: 'upload', hasStagedCert: true }), true)
  assert.equal(adminTlsSendsStagedCert({ mode: 'upload', hasStagedCert: false }), false)
  assert.equal(adminTlsSendsStagedCert({ mode: 'selfsigned', hasStagedCert: true }), false, '非 upload 来源带材料会被后端 400')
})

test('组件接线：dirty 与材料发送共用上述判据', () => {
  const page = code('src/views/settings/BasicSettings.vue')
  const dirty = section(page, 'const adminTlsDirty = computed', 'const adminTlsLoaded')
  assert.match(dirty, /adminTlsPendingChange\(\{/, '暂存判据必须单源（禁第二实现）')
  assert.match(dirty, /hasStagedCert: stagedAdminTlsCert\.value !== null/)

  const save = section(page, 'const handleSave = async', 'const preview = await request')
  assert.match(save, /adminTlsSendsStagedCert\(\{/, '材料发送条件必须走同一判据')
  const tls = section(page, "if (tlsPending) {", '} else {')
  assert.doesNotMatch(
    tls,
    /adminTls\.value\.enabled && adminTls\.value\.mode === 'upload' && staged/,
    '发送条件串入 enabled → 禁用态暂存证书不提交却提示保存成功',
  )
  assert.match(tls, /fd\.append\('cert_file'/)
  assert.match(tls, /fd\.append\('key_file'/)
})
