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
  assert.match(save, /const parentRefresh = props\.onSave\s*if \(parentRefresh\) await parentRefresh\(\)/, 'the parent refresh callback must be awaited')
  assert.doesNotMatch(save, /await props\.onSave\?\.\(\)/)
  assert.match(page, /const formFrozen = computed\(\(\) => isReadOnly\.value \|\| saving\.value\)/)
  const parent = code('src/views/Settings.vue')
  assert.match(section(parent, 'const handleSaveBasic = async', 'const handleSaveCaddy'), /await refreshConfigSection\(applyBasicKeys\)/)
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

test('deselecting every import category clears stale validation and invalidates older reads', () => {
  const revalidate = section(basic(), 'const revalidateImport = async', 'const confirmImport')
  assert.match(revalidate, /if \(sections\.length === 0\) \{\s*importValidationSeq\+\+\s*importValidation\.value = null\s*return\s*\}/)
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
  assert.match(page, /const onTrustedHeadersEdit = \(values: string\[\]\): void => \{\s*trustedPresetKey\.value = ''\s*trustedHeaders\.value = values\s*\}/)
  assert.match(page, /:model-value="trustedHeaders"[\s\S]*@update:model-value="onTrustedHeadersEdit"/)
})

test('ACME numeric clear operations produce numbers instead of null payload values', () => {
  const { acmeGlobalWritePayload } = configValues
  assert.equal(typeof acmeGlobalWritePayload, 'function')
  const payload = acmeGlobalWritePayload({
    email: ' admin@example.com ',
    expiryDays: null,
    renewalDays: undefined,
    renewalAttempts: 5,
    defaultCAProviderId: 2,
    dns_provider: 'dnspod',
  })
  assert.equal(payload.cert_expiry_days, 0)
  assert.equal(payload.cert_renewal_days, 0)
  assert.equal(payload.cert_renewal_attempts, 5)
  assert.equal(payload.acme_email, 'admin@example.com')
  assert.match(certificates(), /acmeGlobalWritePayload\(\{/)
})

test('unsupported legacy ACME DNS providers are omitted instead of rejected or rewritten', () => {
  const { acmeGlobalWritePayload } = configValues
  const base = { email: 'admin@example.com', expiryDays: 30, renewalDays: 30, renewalAttempts: 5, defaultCAProviderId: 2 }
  assert.equal(acmeGlobalWritePayload({ ...base, dns_provider: 'dnspod' }).dns_provider, 'dnspod')
  assert.equal('dns_provider' in acmeGlobalWritePayload({ ...base, dns_provider: 'local-dns' }), false)
  assert.equal('dns_provider' in acmeGlobalWritePayload({ ...base, dns_provider: '' }), false)
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
