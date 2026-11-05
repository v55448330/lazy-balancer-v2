// DNS 凭证 select 变更处理器按字段元数据求值。
//
// 原实现把整个 dns_credentials 重置为 `{ auth_mode: 新值 }`——假定唯一 select
// 名为 auth_mode。新增含两个 select 的 provider（如「区域 + 认证模式」）时，改
// 第二个 select 会把第一个 select 与全部文本字段一并清空。新判据：只清理被
// visible_when 隐藏的字段，仍可见的值保留。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  applyCredentialFieldChange,
  credentialFieldVisible,
  type CredentialFieldMeta,
} from '../src/utils/dnsProviderFields.ts'
import { code } from './_helpers.ts'

const doubleSelectFields: readonly CredentialFieldMeta[] = [
  { name: 'region', label: '区域', type: 'select', required: true, options: ['cn', 'global'] },
  { name: 'auth_mode', label: '认证方式', type: 'select', required: true, options: ['token', 'pair'] },
  { name: 'token', label: 'Token', type: 'password', required: false, visible_when: { auth_mode: ['token'] } },
  { name: 'secret_id', label: 'SecretId', type: 'text', required: false, visible_when: { auth_mode: ['pair'] } },
]

const dnspodFields: readonly CredentialFieldMeta[] = [
  { name: 'auth_mode', label: '认证方式', type: 'select', required: true, options: ['dnspod', 'tencent_cloud'] },
  { name: 'app_id', label: 'App ID', type: 'text', required: false, visible_when: { auth_mode: ['dnspod'] } },
  { name: 'app_token', label: 'App Token', type: 'password', required: false, visible_when: { auth_mode: ['dnspod'] } },
  { name: 'secret_id', label: 'SecretId', type: 'text', required: false, visible_when: { auth_mode: ['tencent_cloud'] } },
  { name: 'secret_key', label: 'SecretKey', type: 'password', required: false, visible_when: { auth_mode: ['tencent_cloud'] } },
]

test('切换第二个 select 不清空第一个 select 与文本字段', () => {
  const next = applyCredentialFieldChange(
    doubleSelectFields,
    { region: 'cn', auth_mode: 'token', token: 'abc' },
  )
  assert.deepEqual(next, { region: 'cn', auth_mode: 'token', token: 'abc' })
})

test('双 select：改认证模式保留区域、清理被隐藏的旧模式字段', () => {
  // 从 token 切到 pair：region（另一 select）与仍可见的 secret_id 保留，
  // 仅 token 被 visible_when 隐藏而清理。
  const next = applyCredentialFieldChange(
    doubleSelectFields,
    { region: 'cn', auth_mode: 'pair', token: 'old-token', secret_id: 'sid' },
  )
  assert.deepEqual(next, { region: 'cn', auth_mode: 'pair', secret_id: 'sid' })
})

test('双 select：先填 token 再切 pair 再切回 token，区域始终保留', () => {
  let credentials: Record<string, unknown> = { region: 'cn', auth_mode: 'token', token: 'abc' }
  credentials = applyCredentialFieldChange(doubleSelectFields, {
    ...credentials,
    auth_mode: 'pair',
    secret_id: 'sid',
  })
  assert.deepEqual(credentials, { region: 'cn', auth_mode: 'pair', secret_id: 'sid' })
  credentials = applyCredentialFieldChange(doubleSelectFields, {
    ...credentials,
    auth_mode: 'token',
  })
  assert.deepEqual(credentials, { region: 'cn', auth_mode: 'token' })
})

test('切换认证模式只清理被 visible_when 隐藏的字段', () => {
  const next = applyCredentialFieldChange(
    dnspodFields,
    { auth_mode: 'tencent_cloud', app_id: 'id', app_token: 'tok', secret_id: 'sid', secret_key: 'skey' },
  )
  assert.deepEqual(next, { auth_mode: 'tencent_cloud', secret_id: 'sid', secret_key: 'skey' })
})

test('切回原模式保留新模式下填写的值（仅隐藏面被清理）', () => {
  const next = applyCredentialFieldChange(
    dnspodFields,
    { auth_mode: 'dnspod', app_id: 'id', secret_id: 'sid' },
  )
  assert.deepEqual(next, { auth_mode: 'dnspod', app_id: 'id' })
})

test('未声明字段保留（不静默丢弃非表单键）', () => {
  const next = applyCredentialFieldChange(dnspodFields, { auth_mode: 'dnspod', mode: 'legacy' })
  assert.equal(next.mode, 'legacy')
})

test('求值不修改入参', () => {
  const credentials = { auth_mode: 'tencent_cloud', app_id: 'id' }
  applyCredentialFieldChange(dnspodFields, credentials)
  assert.deepEqual(credentials, { auth_mode: 'tencent_cloud', app_id: 'id' })
})

test('组件接线：select 变更按字段求值，无 auth_mode 字面量重置', () => {
  const page = code('src/views/settings/FreeCertificates.vue')
  assert.match(page, /@change="onCredentialFieldChange"/)
  // 参数顺序与同一调用：允许任意换行/缩进，只钉两个实参按序出现在同一次调用里
  assert.match(page, /applyCredentialFieldChange\([\s\S]{0,240}?selectedProvider\.value\?\.credential_fields \?\? \[\],[\s\S]{0,120}?form\.value\.dns_credentials,/)
  assert.doesNotMatch(page, /onAuthModeChange/)
  assert.doesNotMatch(page, /dns_credentials = \{ auth_mode: authMode\.value \}/)
  assert.doesNotMatch(page, /const authMode = computed\(/)
  // 可见性与变更处理器同源：都走 credentialFieldVisible 的元数据口径
  assert.match(page, /credentialFieldVisible\(field, form\.value\.dns_credentials\)/)
  assert.ok(
    credentialFieldVisible(dnspodFields[1], { auth_mode: 'dnspod' }),
    '元数据可见性契约不变',
  )
})

test('编辑回填不按 provider 名推断认证方式（缺失键交后端 canonical 归一）', () => {
  // 库值 → 规范凭据的唯一实现是后端 dnsprovider.CanonicalCredentials（保存前
  // 验证与签发链共用）；前端复刻该推断会按 provider 名硬编码，第二个 provider
  // 即被注入无关的 auth_mode。回填只做 JSON 解析，不做任何凭证语义推断。
  const page = code('src/views/settings/FreeCertificates.vue')
  // 结构边界取回填块（不依赖空行/缩进形状：格式化工具有引入即批量红）。
  const backfillStart = page.indexOf('if (config) {')
  const backfillEnd = page.indexOf('editingId.value = null', backfillStart)
  assert.ok(backfillStart > 0 && backfillEnd > backfillStart, '编辑回填块边界缺失')
  const backfill = page.slice(backfillStart, backfillEnd)
  assert.doesNotMatch(backfill, /auth_mode\s*=\s*'/, '回填不得注入 auth_mode 字面量')
  assert.doesNotMatch(backfill, /tencent_cloud/, '回填不得按 provider 名分派')
  assert.doesNotMatch(backfill, /secret_id && parsedCreds\.secret_key/, '凭证形态推断属后端单源')
  // 遗留空凭据形态的「不注入、保存省略」契约不变
  assert.match(backfill, /legacyEmptyCredentials\.value = Object\.keys\(parsedCreds\)\.length === 0/)
})

test('凭据字段元数据 description 在输入框下方以标准描述样式渲染', () => {
  // 后端 CredentialField.description（长指引）由 FE 以 form-tip-line 渲染在
  // 输入框下方——placeholder 只承担短占位，长指引进输入框既难读也遮蔽已填值
  // （2026-11-05 用户验收反馈：Cloudflare API Token 创建指引）。
  const meta = code('src/utils/dnsProviderFields.ts')
  assert.match(meta, /readonly description\?: string/, 'CredentialFieldMeta 缺 description 字段')
  const page = code('src/views/settings/FreeCertificates.vue')
  const blockStart = page.indexOf('v-for="field in selectedProvider.credential_fields"')
  const blockEnd = page.indexOf('</template>', blockStart)
  assert.ok(blockStart > 0 && blockEnd > blockStart, '凭据字段渲染块边界缺失')
  const block = page.slice(blockStart, blockEnd)
  assert.match(block, /field\.description/, '凭据字段渲染块未消费 description')
  assert.match(block, /form-tip-line/, '描述必须用标准 form-tip-line 样式（禁 placeholder 长文本/禁局部样式）')
})
