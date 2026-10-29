// 管理面板 HTTPS 证书损坏态的 fail-visible 契约：后端以 cert_info_error 显式
// 申报「库内证书不可读」，前端必须消费——否则带外改库/旧版本导入造成的损坏
// 证书在界面上与「未配置证书」无法区分（用户只看到开关开启却查无信息）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { lastSection, section, code } from './_helpers.ts'

test('/admin-tls 响应类型声明 cert_info_error', () => {
  const api = code('src/utils/api.ts')
  assert.match(api, /cert_info_error\?: string/, 'API 类型必须声明 fail-visible 字段')
})

test('设置页消费 cert_info_error 并渲染错误条', () => {
  const page = code('src/views/settings/BasicSettings.vue')
  const draft = code('src/composables/useSettingsDraft.ts')
  // 暂存态（含损坏原因）由设置草稿持有——切分页重挂后横幅与确认门继续成立
  assert.match(draft, /const adminTlsCertError = ref\(''\)/)
  assert.match(page, /adminTlsCertError\.value = res\.data\.cert_info_error \|\| ''/, '读取时必须从响应取值')

  // 仅 upload 模式的存量证书可能损坏（selfsigned 由 ResolveCertificate 自愈），
  // 以已保存的 mode 判定，不受弹框内未提交切换影响。
  // 三个合取项分别断言：整串正则钉会在重排比较项/换行时假红。
  const brokenDecl = section(page, 'const adminTlsCertBroken =', '\n')
  assert.ok(brokenDecl.includes('computed(() =>'), '必须由 saved 派生（computed），不得在读取路径手工补写')
  assert.ok(brokenDecl.includes("adminTlsSaved.value.mode === 'upload'"), '仅 upload 模式判定损坏')
  assert.ok(brokenDecl.includes("adminTlsCertError.value !== ''"), '必须消费 cert_info_error（fail-visible）')
  assert.ok(brokenDecl.includes('&&'), '两个条件必须同时成立（合取）')

  // 错误条复用全局 info-note-bar（禁止局部 :deep 或重定义全局类）。
  const bar = section(page, 'v-if="adminTlsCertBroken"', '</div>')
  assert.match(bar, /class="info-note-bar"/)
  assert.match(bar, /adminTlsCertError/)
  assert.match(bar, /重新上传/, '须给出修复指引')
})

test('/admin-tls 保存成功后回读服务端状态：损坏横幅与复用门随新证书复位', () => {
  const page = code('src/views/settings/BasicSettings.vue')
  // 同一行形态出现两次：`/config/preview` 的 changes 拼装（首个命中）与真正的
  // `/admin-tls` 提交段（最后一处）。从首个命中切会跨过两段之间的 PUT /config、
  // 父级刷新与令牌回写——回读被挪进预览块（早于落库就回读）也能满足断言。
  const tls = lastSection(page, 'if (tlsPending) {', '} else {')
  assert.match(tls, /request\.put\('\/admin-tls'/, '切片必须是 /admin-tls 提交段（身份自检）')
  // 成功态以唯一读路径回填：新证书可解析时后端不再下发 cert_info_error，
  // adminTlsCertBroken / adminTlsConfirmBlocked 随之复位。
  assert.match(tls, /await loadAdminTls\(\)/, '保存成功必须重跑读路径')
  assert.match(tls, /stagedAdminTlsCert\.value = null/, '保存成功后清空暂存证书')
  assert.doesNotMatch(
    tls,
    /adminTlsHasCert\.value = adminTlsHasCert\.value \|\|/,
    '不得以手工补丁代替读路径（旧 cert_info_error 会残留，修复后仍报「坏」）',
  )
  const failure = section(tls, 'catch (tlsError)', '\n      }\n')
  assert.doesNotMatch(failure, /loadAdminTls/, '失败时不得以回读假装已收敛')
})

test('读取路径保留未保存的暂存态（切页重挂不回退）', () => {
  const page = code('src/views/settings/BasicSettings.vue')
  const load = section(page, 'const loadAdminTls = async () => {', 'const retryLoadAdminTls')
  assert.match(load, /const wasStaged = adminTlsDirty\.value/, '暂存判定必须在写入新 saved 之前取')
  assert.match(load, /if \(!wasStaged\) adminTls\.value = \{ \.\.\.saved \}/, '有暂存编辑时不得用服务端值覆盖表单')
  assert.ok(
    load.indexOf('const wasStaged') < load.indexOf('adminTlsSaved.value = saved'),
    '先判定暂存、后写 saved——否则服务端变化会被误当成用户暂存',
  )
  assert.doesNotMatch(load, /stagedAdminTlsCert\.value = null/, '暂存证书只在保存成功后清空')
})
