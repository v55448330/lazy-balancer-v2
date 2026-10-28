// DNS 配置保存前的「真实挑战」门：临时写入/删除 _acme-challenge.lb-test 只在
// 凭证需要重新验证时才必要（新建、提供商变更、凭证变更、禁用→启用）。
//
// 修复前编辑既有配置一律先弹「请输入可管理域名」并做真实 DNS 挑战——仅想停用
// 一条配置或改个名字也会被这一步挡住（凭证早已失效/账户已注销时直接死路）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { dnsConfigNeedsChallenge } from '../src/utils/dnsConfigChallenge.ts'
import type { DnsConfigBaseline, DnsConfigDraft } from '../src/utils/dnsConfigChallenge.ts'
import { section, code } from './_helpers.ts'

const baseline = (overrides: Partial<DnsConfigBaseline> = {}): DnsConfigBaseline => ({
  dnsProvider: 'dnspod',
  dnsCredentials: { auth_mode: 'dnspod', app_id: '1', app_key: 'k' },
  enabled: true,
  ...overrides,
})

const draft = (overrides: Partial<DnsConfigDraft> = {}): DnsConfigDraft => ({
  dnsProvider: 'dnspod',
  dnsCredentials: { auth_mode: 'dnspod', app_id: '1', app_key: 'k' },
  enabled: true,
  ...overrides,
})

test('新建配置必须挑战（凭证从未验证过）', () => {
  assert.equal(dnsConfigNeedsChallenge(null, draft()), true)
})

// 死路用例：编辑既有配置只改名——此前仍强制真实挑战，用户在系统里不想再碰
// DNS 账户时无法保存（改个显示名也要写 _acme-challenge 记录）。
test('死路：仅改名不挑战', () => {
  assert.equal(dnsConfigNeedsChallenge(baseline(), draft()), false)
})

// 死路用例：停用一条配置是降级操作，不引入新凭证——凭证已失效/账户已注销时
// 强制挑战会让「停用」永远失败，配置只能继续启用着错。
test('死路：仅禁用不挑战', () => {
  assert.equal(dnsConfigNeedsChallenge(baseline(), draft({ enabled: false })), false)
})

test('禁用 → 启用必须挑战（签发链会立刻使用该凭证）', () => {
  assert.equal(dnsConfigNeedsChallenge(baseline({ enabled: false }), draft({ enabled: true })), true)
})

test('凭证值变更或增删键必须挑战', () => {
  assert.equal(dnsConfigNeedsChallenge(baseline(), draft({ dnsCredentials: { auth_mode: 'dnspod', app_id: '1', app_key: 'rotated' } })), true)
  assert.equal(dnsConfigNeedsChallenge(baseline(), draft({ dnsCredentials: { auth_mode: 'dnspod', app_id: '1' } })), true, '删键也算变更')
  assert.equal(dnsConfigNeedsChallenge(baseline(), draft({ dnsCredentials: { auth_mode: 'dnspod', app_id: '1', app_key: 'k', extra: 'x' } })), true, '增键也算变更')
  assert.equal(dnsConfigNeedsChallenge(baseline(), draft({ dnsCredentials: { auth_mode: 'dnspod', app_id: '1', app_key: ' k ' } })), true, '空白改动同样按变更处理（载荷原样回传）')
})

test('DNS 提供商变更必须挑战（凭证语义随之改变）', () => {
  assert.equal(dnsConfigNeedsChallenge(baseline(), draft({ dnsProvider: 'tencent_cloud' })), true)
})

test('遗留空凭证：未填凭证时改名/禁用不挑战，填入凭证才挑战', () => {
  const empty = baseline({ dnsCredentials: null })
  assert.equal(dnsConfigNeedsChallenge(empty, draft({ dnsCredentials: {}, enabled: false })), false)
  assert.equal(dnsConfigNeedsChallenge(empty, draft({ dnsCredentials: { app_id: '', app_key: '  ' } })), false, '仅空白值视为未填')
  assert.equal(dnsConfigNeedsChallenge(empty, draft({ dnsCredentials: { auth_mode: 'dnspod', app_id: '1', app_key: '' } })), true)
})

// 库值含「当前元数据判为隐藏」的键（导入备份/带外写库/旧版本遗留，或后端未来
// 调整 visible_when 后的全部存量）时，表单按隐藏规则裁剪、基线若快照原样库值，
// 键集差异会让「仅改名/仅停用」重新被判为凭证变更而强制真实 DNS 挑战。
test('基线与表单同源裁剪：隐藏键不得进入基线键集', () => {
  // 修复后形态：基线与表单来自同一次归一（同键集），仅改名不挑战
  const pruned = { auth_mode: 'dnspod', app_id: '1', app_key: 'k' }
  assert.equal(dnsConfigNeedsChallenge(baseline({ dnsCredentials: pruned }), draft({ dnsCredentials: { ...pruned } })), false)
  // 修复前形态（基线含隐藏键、表单不含）：键集不同 → 判定为变更，正是误判来源
  const unstripped = baseline({ dnsCredentials: { ...pruned, stale_token: 'x' } })
  assert.equal(dnsConfigNeedsChallenge(unstripped, draft()), true, '键集差异按变更处理（该形态不得出现在组件基线里）')

  const page = code('src/views/settings/FreeCertificates.vue')
  const open = section(page, 'const openConfigDialog = (config?: CertConfig) => {', '\nconst ')
  assert.match(
    open,
    /const initialCredentials = canPruneHidden \? applyCredentialFieldChange\(providerFields, parsedCreds\) : \{ \.\.\.parsedCreds \}/,
    '表单初值与基线必须来自同一次归一',
  )
  assert.match(open, /dns_credentials: initialCredentials,/, '表单使用归一后的凭证')
  assert.match(open, /dnsCredentials: legacyEmptyCredentials\.value \? null : \{ \.\.\.initialCredentials \}/, '基线取同一份归一结果的拷贝')
  assert.doesNotMatch(
    open,
    /dnsCredentials: legacyEmptyCredentials\.value \? null : \{ \.\.parsedCreds \}/,
    '禁止基线直传未裁剪库值（隐藏键会造成键集差异 → 改名/停用被强制挑战）',
  )
})

test('组件接线：挑战门由快照判定，弹框只在需要时出现', () => {
  const page = code('src/views/settings/FreeCertificates.vue')
  assert.match(page, /const configBaseline = ref<DnsConfigBaseline \| null>\(null\)/)
  const save = section(page, 'const saveConfig = async', '\nconst ')
  assert.match(save, /dnsConfigNeedsChallenge\(configBaseline\.value, \{/, '保存前挑战必须以打开弹框时的快照判定')
  const gateAt = save.indexOf('dnsConfigNeedsChallenge(configBaseline.value')
  const promptAt = save.indexOf('const domain = await promptTestDomain(true)')
  assert.ok(gateAt > 0 && promptAt > gateAt, '域名弹框必须落在挑战门之后（不需要挑战时不得弹框）')
  // 弹框打开即记录基线：改名/禁用的判定必须与「打开时的库值」比较，
  // 而不是与保存时的表单自比（后者恒等）。
  const open = section(page, 'const openConfigDialog = (config?: CertConfig) => {', '\nconst ')
  assert.match(open, /configBaseline\.value = \{\s*dnsProvider: config\.dns_provider/, '编辑态必须回填基线')
  assert.match(open, /configBaseline\.value = null/, '新建态基线为空=首次验证')
})

test('DNS 凭证验证弹框复用全站 DialogHeader 与 el-dialog 版式', () => {
  const page = code('src/views/settings/FreeCertificates.vue')
  const dialog = section(page, 'v-model="dnsVerifyVisible"', '</el-dialog>')
  assert.match(dialog, /DialogHeader :icon="Connection" title="验证 DNS 凭证"/)
  assert.match(dialog, /class="dialog-body-inset"/)
  assert.match(dialog, /v-model="dnsVerifyDomain"/)
  assert.match(dialog, /@click="confirmDnsVerify"/)
  assert.doesNotMatch(page, /ElMessageBox\.prompt\(/, '不得退回原生 MessageBox 的标题/正文/按钮布局')
})

