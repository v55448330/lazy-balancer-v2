import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, section, source } from './_helpers.ts'
import * as configValues from '../src/utils/configValues.ts'
import * as trustedProxyRanges from '../src/utils/trustedProxyRanges.ts'

const basic = () => code('src/views/settings/BasicSettings.vue')
const caddy = () => code('src/views/settings/CaddyGlobalSettings.vue')
const certificates = () => code('src/views/settings/FreeCertificates.vue')

test('admin TLS read failures always disable the untrusted switch', () => {
  const load = section(basic(), 'const loadAdminTls = async', 'const retryLoadAdminTls')
  assert.match(load, /catch \{\s*adminTlsLoaded\.value = false/, 'catch must invalidate an earlier successful read')
  assert.match(load, /adminTlsLoadFailed\.value = true/)
})

test('basic save awaits the parent config refresh while the form stays frozen', () => {
  const page = basic()
  assert.match(page, /onSave\?: \(\) => void \| Promise<void>/)
  const save = section(page, 'const handleSave = async', '</script>')
  // 两次独立匹配 + 顺序：把 `\s*` 当紧邻契约的写法在换行/注释整理后假红。
  const refreshAt = save.indexOf('const parentRefresh = props.onSave')
  assert.ok(refreshAt >= 0, 'save 必须取父级刷新回调')
  assert.match(save, /if \(parentRefresh\)/, '父级刷新必须有存在性守卫')
  const awaitedAt = save.indexOf('await parentRefresh()')
  assert.ok(awaitedAt > refreshAt, 'the parent refresh callback must be awaited')
  assert.doesNotMatch(save, /await props\.onSave\?\.\(\)/)
  assert.match(page, /const formFrozen = computed\(\(\) => isReadOnly\.value \|\| saving\.value\)/)
  const parent = code('src/views/Settings.vue')
  assert.match(section(parent, 'const handleSaveBasic = async', 'const handleSaveCaddy'), /await refreshConfigSection\(applyBasicKeys\)/)
})

test('Caddy and ACME saves await parent refreshes before unfreezing', () => {
  const parent = code('src/views/Settings.vue')
  const cases = [
    { page: caddy(), handler: 'handleSaveCaddy', binding: ':on-save="handleSaveCaddy"' },
    { page: certificates(), handler: 'handleSaveCertificates', binding: ':on-save="handleSaveCertificates"' },
  ]
  for (const item of cases) {
    assert.match(item.page, /onSave\?: \(\) => void \| Promise<void>/)
    const save = section(item.page, 'const handleSave = async', '</script>')
    const refreshAt = save.indexOf('const parentRefresh = props.onSave')
    const awaitedAt = save.indexOf('await parentRefresh()')
    const emitAt = save.indexOf("if (!parentRefresh) emit('save')")
    assert.ok(refreshAt >= 0 && awaitedAt > refreshAt, 'the parent refresh callback must be awaited')
    assert.ok(emitAt > awaitedAt, 'no-callback fallback must follow the awaited refresh')
    assert.ok(save.indexOf('await parentRefresh()') < save.indexOf('} finally {'), 'parent refresh must finish before the finally block unfreezes the form')
    assert.match(parent, new RegExp(item.binding.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
    assert.match(section(parent, `const ${item.handler} = async`, 'const syncActiveTabFromPage'), /await refreshConfigSection\(/)
  }
})

test('threat screen display normalization is submitted only after an actual edit', () => {
  const { threatScreenWritePayload } = configValues
  assert.equal(typeof threatScreenWritePayload, 'function')
  assert.deepEqual(threatScreenWritePayload({ mode: 'map', modeDirty: false, sampleN: -1, sampleDirty: false }), {})
  assert.deepEqual(threatScreenWritePayload({ mode: 'globe', modeDirty: true, sampleN: -1, sampleDirty: false }), { threat_screen_mode: 'globe' })
  assert.deepEqual(threatScreenWritePayload({ mode: 'map', modeDirty: false, sampleN: 0, sampleDirty: true }), { threat_traffic_sample_n: 0 })
  const page = basic()
  assert.match(page, /const threatScreenModeDirty = computed\(/)
  assert.match(page, /const trafficSampleNDirty = computed\(/)
  assert.match(page, /props\.savedThreatScreenMode/)
  assert.match(page, /props\.savedThreatTrafficSampleN/)
  const parent = code('src/views/Settings.vue')
  assert.match(parent, /const savedThreatScreenMode = ref<'map' \| 'globe'>\('map'\)/)
  assert.match(parent, /savedThreatScreenMode\.value = threatMode/)
  assert.match(parent, /savedThreatTrafficSampleN\.value = sampleN/)
})

test('backup export filenames use the configured timezone rather than UTC', () => {
  const page = basic()
  assert.match(page, /formatDateShort/)
  const exportBackup = section(page, 'const exportBackup = async', 'const AUTO_BACKUP_WEEKDAYS')
  assert.match(exportBackup, /formatDateShort\(new Date\(\)\)/)
  assert.doesNotMatch(exportBackup, /toISOString\(\)/)
})

test('display-only proxy and backup defaults retain an explicit legacy caveat（文档钉）', () => {
  const page = source('src/views/settings/BasicSettings.vue')
  assert.match(page, /留档：GitHub 代理与自动备份表单的展示默认值仅兼容正常读写路径/)
  assert.match(page, /带外清空库值时不得把这些展示默认值当作真实配置/)
})

test('auto-backup save rechecks node mode after the dialog is open', () => {
  const page = basic()
  const save = section(page, 'const saveAutoBackupSettings = async', 'const runAutoBackupNow')
  assert.match(save, /if \(backupDisabled\.value \|\| !autoBackupSectionsValid\.value \|\| autoBackupSaving\.value\) return false/)
  assert.match(page, /const autoBackupCanRunNow = computed\(\(\) => !backupDisabled\.value/)
  assert.match(section(page, 'const runAutoBackupNow = async', 'const downloadAutoBackup'), /if \(backupDisabled\.value \|\| autoBackupRunning\.value\) return/)
})

test('deselecting every import category keeps chips available and invalidates older reads', () => {
  const revalidate = section(basic(), 'const revalidateImport = async', 'const confirmImport')
  const emptySelection = section(revalidate, 'if (sections.length === 0) {', "if (importValidation.value?.type === 'v1') return")
  assert.match(emptySelection, /importValidationSeq\+\+/)
  assert.doesNotMatch(emptySelection, /importValidation\.value = null/, 'clearing validation removes the only controls that can restore a category')
})

test('Caddy numeric clear operations produce numbers instead of null payload values', () => {
  const { numberOr } = configValues
  assert.equal(typeof numberOr, 'function')
  assert.equal(numberOr(null, 0), 0)
  assert.equal(numberOr(undefined, 0), 0)
  assert.equal(numberOr(37, 0), 37)
  const save = section(caddy(), 'const handleSave = async', 'const preview = await request.post')
  for (const field of [
    'caddy_log_size_mb',
    'request_body_max_size_mb',
    'http_read_timeout',
    'http_write_timeout',
    'http_idle_timeout',
    'upstream_keepalive_timeout',
    'proxy_dial_timeout',
    'proxy_response_header_timeout',
    'proxy_read_timeout',
    'proxy_write_timeout',
    'proxy_stream_timeout',
    'proxy_flush_interval',
    'proxy_stream_close_delay',
  ]) {
    assert.match(save, new RegExp(`${field}: numberOr\\(settings\\.value\\.${field}, 0\\)`), `${field} must normalize a cleared input`)
  }
  assert.match(save, /caddy_log_size_mb: numberOr/)
})

test('trusted proxy text normalization writeback has an explicit legacy caveat（文档钉）', () => {
  const page = source('src/views/settings/CaddyGlobalSettings.vue')
  assert.match(page, /留档：表单数组回写会规范化存量 JSON 文本/)
  assert.match(page, /带外非规范文本可能在无关保存时触发变更确认/)
})

test('referenced trusted-proxy lists reuse range validation and name invalid entries', () => {
  const { trustedProxyReferencedRangesError } = trustedProxyRanges
  assert.equal(typeof trustedProxyReferencedRangesError, 'function')
  assert.equal(trustedProxyReferencedRangesError([{ name: 'CDN', values: ['203.0.113.0/24'], entryCount: 1 }]), '')
  assert.equal(trustedProxyReferencedRangesError([{ name: 'pending', values: null, entryCount: 1 }]), '')
  const message = trustedProxyReferencedRangesError([{ name: 'bad CDN', values: ['0.0.0.0/0', '10.0.0.0/4'], entryCount: 2 }])
  assert.match(message, /bad CDN/)
  assert.match(message, /0\.0\.0\.0\/0/)
  assert.match(message, /10\.0\.0\.0\/4/)
  const page = caddy()
  assert.match(page, /const trustedReferencedRangesError = computed\(\(\) => trustedProxyReferencedRangesError\(referencedLists\.value\)\)/)
  assert.match(page, /v-if="trustedReferencedRangesError"/)
  assert.match(section(page, 'const handleSave = async', 'const preview = await request.post'), /if \(trustedReferencedRangesError\.value\)/)
})

test('manual trusted-header edits detach the selected CDN preset', () => {
  const page = caddy()
  // 先脱钩预设、后回写头列表（顺序是契约，单行形态与右侧字面不是）。
  const edit = section(page, 'const onTrustedHeadersEdit = ', 'const applyTrustedPreset')
  const detachAt = /trustedPresetKey\.value = ['"]{2}/.exec(edit)?.index ?? -1
  const writeAt = /trustedHeaders\.value\s*=/.exec(edit)?.index ?? -1
  assert.ok(detachAt >= 0, '手动编辑必须清空预设选择')
  assert.ok(writeAt > detachAt, '清预设必须先于回写头列表（否则预设会被重新套用）')
  assert.match(page, /:model-value="trustedHeaders"[\s\S]*@update:model-value="onTrustedHeadersEdit"/)
})

// 清空 el-input-number 回写 null：此前按 0 提交，而写侧门 cert_expiry_days 1-365、
// cert_renewal_attempts 1-10（cert_renewal_days 0 虽合法但语义是「每次扫描都重签」）
// ——整卡保存被拒/被静默改义。未提供的数值必须省略键，由后端 COALESCE 保持现值。
test('ACME numeric clear operations omit the key instead of submitting 0', () => {
  const { acmeGlobalWritePayload } = configValues
  assert.equal(typeof acmeGlobalWritePayload, 'function')
  const payload = acmeGlobalWritePayload({
    email: ' admin@example.com ',
    expiryDays: null,
    renewalDays: undefined,
    renewalAttempts: 5,
    defaultCAProviderId: 2,
  })
  assert.equal('cert_expiry_days' in payload, false, '清空的有效期天数必须省略键（0 撞后端 1-365 门）')
  assert.equal('cert_renewal_days' in payload, false, '清空的续签天数必须省略键（0=每次扫描重签）')
  assert.equal(payload.cert_renewal_attempts, 5, '未清空的数值照常携带')
  assert.equal(payload.acme_email, 'admin@example.com')
  assert.match(certificates(), /acmeGlobalWritePayload\(\{/)
  // 三个数值输入都必须能表达「清空」（v-model 回写 null 时省略键）
  const allCleared = acmeGlobalWritePayload({
    email: 'admin@example.com', expiryDays: null, renewalDays: null, renewalAttempts: null, defaultCAProviderId: 2,
  })
  assert.equal('cert_expiry_days' in allCleared || 'cert_renewal_days' in allCleared || 'cert_renewal_attempts' in allCleared, false, '三个数值全部清空时一个都不许携带')
  assert.match(code('src/utils/configValues.ts'), /const acmeNumberField = /, '省略逻辑必须收敛到单处 helper，不得逐字段各写一遍')
})

test('retired global ACME DNS provider is never propagated', () => {
  const { acmeGlobalWritePayload } = configValues
  const payload = acmeGlobalWritePayload({ email: 'admin@example.com', expiryDays: 30, renewalDays: 30, renewalAttempts: 5, defaultCAProviderId: 2 })
  assert.equal('dns_provider' in payload, false)
})

test('certificate dialog entry functions defend read-only mode', () => {
  const page = certificates()
  assert.match(section(page, 'const openCAProviderDialog =', 'const beforeCADialogClose'), /if \(isReadOnly\.value \|\| savingCA\.value\) return/)
  assert.match(section(page, 'const openConfigDialog =', 'const closeConfigDialog'), /if \(isReadOnly\.value \|\| savingConfig\.value\) return/)
})

test('cluster node dialogs follow polled baselines without overwriting dirty edits', () => {
  const parent = code('src/views/settings/ClusterSettings.vue')
  assert.match(parent, /const editingNodeConfigLive = computed(?:<[^>]+>)?\(\(\) =>/)
  assert.match(parent, /nodes\.value\.find\(\(node\) => node\.id === snapshot\.id\) \?\? snapshot/)
  assert.match(parent, /:node="editingNodeConfigLive"/)
  assert.match(section(parent, 'const updateNodeConfig = async', 'const clusterPollingError ='), /const node = editingNodeConfigLive\.value/)
  const dialog = code('src/views/settings/cluster/ClusterNodeConfigDialog.vue')
  assert.match(dialog, /const accessBaseline = ref\(''\)/)
  assert.match(dialog, /const accessDirty = continuing && form\.access_url !== accessBaseline\.value/)
  assert.match(dialog, /const siteDirty = continuing && nodeSiteCoordsChanged\(baseline, form\)/)
  assert.match(dialog, /if \(!accessDirty\) form\.access_url = node\.access_url/)
  assert.match(dialog, /if \(!siteDirty\) \{/)
})
