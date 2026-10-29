// 设置页暂存态生存周期：基础设置卡在页内切换设置分页时会被卸载
// （Settings.vue 按 activeTab 挂载 BasicSettings+CaddyGlobalSettings），组件内
// ref 的暂存内容随之复位——与同卡直绑 settings（父级共享模型）的字段行为不
// 一致。需要「提交前只存在于本地」的状态提升到 useSettingsDraft 模块单例：
// 页内切分页不丢，离开系统设置（Settings.vue 卸载）才复位。可落父级模型的
// 字段（大屏视觉模式/流量采样/保留与行数编辑值）改为写回 settings。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { resetSettingsDraft, syncSettingsDraftIdentity, useSettingsDraft } from '../src/composables/useSettingsDraft.ts'
import { securityEventsWritePayload } from '../src/utils/configValues.ts'
import { code, section } from './_helpers.ts'

const certInfo = { domain: 'example.com', issuer: 'fixture', not_after: '2027-01-01', days_left: 365 }

test('暂存态跨基础设置卡挂载保留（切分页不丢），离开设置页才复位', () => {
  resetSettingsDraft()
  const certFile = new File(['cert'], 'cert.pem')
  const keyFile = new File(['key'], 'key.pem')
  const first = useSettingsDraft()
  first.githubTokenInput.value = 'ghp_fixture'
  first.githubTokenClearPending.value = true
  first.securityEventsRetentionDirty.value = true
  first.securityEventsRowCapDirty.value = true
  first.adminTls.value = { enabled: true, mode: 'upload' }
  // 非默认值才能区分「跨挂载保留」与「已复位」（此前写入默认值，断言恒真）。
  first.adminTlsSaved.value = { enabled: true, mode: 'upload' }
  first.adminTlsHasCert.value = true
  first.adminTlsCertError.value = 'bad pem'
  first.adminTlsUnavailable.value = true
  first.stagedAdminTlsCert.value = { certFile, keyFile, certInfo }

  // 模拟切到别的设置分页再切回：BasicSettings 重新 setup，取到同一份草稿
  const second = useSettingsDraft()
  assert.equal(second.githubTokenInput.value, 'ghp_fixture', '令牌输入不得在切页后丢失')
  assert.equal(second.githubTokenClearPending.value, true, '清除标记同样不得丢失')
  assert.equal(second.securityEventsRetentionDirty.value, true)
  assert.equal(second.securityEventsRowCapDirty.value, true)
  assert.deepEqual(second.adminTls.value, { enabled: true, mode: 'upload' }, '暂存的强制加密开关不得回退')
  assert.deepEqual(second.adminTlsSaved.value, { enabled: true, mode: 'upload' }, '服务端派生缓存（已暂存判定）不得在切页后回退')
  assert.equal(second.adminTlsHasCert.value, true, '「已有证书」派生缓存不得在切页后丢失')
  assert.equal(second.adminTlsCertError.value, 'bad pem')
  assert.equal(second.adminTlsUnavailable.value, true, '降级标记在切页时必须保留，复位前哨兵不得为默认值')
  assert.equal(second.stagedAdminTlsCert.value?.certFile, certFile, '已暂存证书材料必须仍是同一对象')

  // 离开系统设置（Settings.vue 卸载）→ 复位
  resetSettingsDraft()
  const third = useSettingsDraft()
  assert.equal(third.githubTokenInput.value, '')
  assert.equal(third.githubTokenClearPending.value, false)
  assert.equal(third.securityEventsRetentionDirty.value, false)
  assert.equal(third.securityEventsRowCapDirty.value, false)
  assert.deepEqual(third.adminTls.value, { enabled: false, mode: 'selfsigned' })
  assert.deepEqual(third.adminTlsSaved.value, { enabled: false, mode: 'selfsigned' })
  assert.equal(third.adminTlsHasCert.value, false, '复位必须覆盖 adminTlsHasCert（否则残留「已有证书」）')
  assert.equal(third.adminTlsCertError.value, '')
  assert.equal(third.stagedAdminTlsCert.value, null)
  // 复位覆盖面 = 导出键集合（新增字段漏进 reset 即红）。
  const keys = Object.keys(third) as Array<keyof typeof third>
  assert.deepEqual(
    keys.sort(),
    ['adminTls', 'adminTlsCertError', 'adminTlsHasCert', 'adminTlsSaved', 'adminTlsUnavailable', 'githubTokenClearPending', 'githubTokenInput', 'securityEventsRetentionDirty', 'securityEventsRowCapDirty', 'stagedAdminTlsCert'],
    '导出键集合变化必须同步复位与断言（漏复位字段会跨页残留）',
  )
  assert.equal(third.adminTlsUnavailable.value, false)
})

test('安全事件编辑：编辑值写回共享模型，dirty 跨挂载保留，保存载荷携带编辑值', () => {
  resetSettingsDraft()
  // 父级共享模型（Settings.vue 持有，切分页不卸载）
  const settings = { security_events_retention_days: 90, security_events_row_cap: 1_000_000 }
  // BasicSettings 的 v-model 写回共享模型并置 dirty（computed setter 同形）
  settings.security_events_retention_days = 120
  useSettingsDraft().securityEventsRetentionDirty.value = true

  // 切页重挂：值在共享模型、dirty 在草稿，两者都不随组件卸载消失
  const remounted = useSettingsDraft()
  const payload = securityEventsWritePayload({
    retentionDays: settings.security_events_retention_days,
    retentionDirty: remounted.securityEventsRetentionDirty.value,
    rowCap: settings.security_events_row_cap,
    rowCapDirty: remounted.securityEventsRowCapDirty.value,
  })
  assert.deepEqual(payload, { security_events_retention_days: 120 }, '切页后保存必须写入编辑值而非旧值')
  resetSettingsDraft()
})

test('BasicSettings 接线：暂存态取草稿单例，可落父级模型的字段写回 settings', () => {
  // 「不得在组件内重建暂存」是死代码断言，走剥注释视图（注释提及不算消费）。
  const page = code('src/views/settings/BasicSettings.vue')
  const draft = code('src/composables/useSettingsDraft.ts')
  assert.match(draft, /const githubTokenInput = ref\(''\)/, '令牌输入必须由草稿持有')
  assert.match(draft, /const adminTlsCertError = ref\(''\)/, '证书损坏原因必须由草稿持有')
  assert.match(draft, /const stagedAdminTlsCert = ref<StagedAdminTlsCert \| null>\(null\)/, '证书暂存必须由草稿持有')
  assert.match(page, /\} = useSettingsDraft\(\)/, '设置卡必须消费草稿单例')
  assert.doesNotMatch(page, /const githubTokenInput = ref\(''\)/, '不得在组件内重建令牌暂存')
  assert.doesNotMatch(page, /const stagedAdminTlsCert = ref/, '不得在组件内重建证书暂存')
  assert.doesNotMatch(page, /const adminTls = ref/, '不得在组件内重建管理面板 HTTPS 暂存')

  // 可直绑父级模型的字段：写回 settings（卸载即复位的问题消失）
  const mode = section(page, 'const threatScreenMode = computed', '\n})')
  assert.match(mode, /settings\.value\.threat_screen_mode = value/)
  const sample = section(page, 'const trafficSampleN = computed', '\n})')
  assert.match(sample, /settings\.value\.threat_traffic_sample_n = value/)
  const retention = section(page, 'const seRetentionDays = computed', '\n})')
  assert.match(retention, /settings\.value\.security_events_retention_days = value/)
  assert.match(retention, /securityEventsRetentionDirty\.value = true/, '编辑必须置 dirty（保存载荷才携带该键）')
  const rowCap = section(page, 'const seRowCap = computed', '\n})')
  assert.match(rowCap, /settings\.value\.security_events_row_cap = value/)
  assert.match(rowCap, /securityEventsRowCapDirty\.value = true/)
  assert.doesNotMatch(
    page,
    /watch\(\(\) => \[settings\.value\.security_events_retention_days/,
    '「settings → 本地」单向同步 watcher 必须退役',
  )
})

test('会话身份切换必须清空设置草稿（同标签页票据换号不卸载设置页）', () => {
  const draft = code('src/composables/useSettingsDraft.ts')
  const settings = code('src/views/Settings.vue')
  assert.match(draft, /syncSettingsDraftIdentity/, '草稿单例必须提供身份同步入口')
  assert.match(settings, /syncSettingsDraftIdentity/, '设置页必须在身份变化时调用同步')
  assert.match(settings, /watch\(\(\) => authStore\.user\?\.id/, '必须监听实际用户 ID，而非仅在卸载时复位')
})

test('会话身份进入 null 或换成不同用户时都清空草稿，首次记录身份保留页内暂存', () => {
  resetSettingsDraft()
  const draft = useSettingsDraft()
  draft.githubTokenInput.value = 'initial-input'
  syncSettingsDraftIdentity(11)
  assert.equal(draft.githubTokenInput.value, 'initial-input', '首次挂载只记录身份')

  syncSettingsDraftIdentity(null)
  assert.equal(draft.githubTokenInput.value, '', '退出到 null 中间态必须立即清空')
  assert.equal(draft.stagedAdminTlsCert.value, null)
  assert.deepEqual(draft.adminTlsSaved.value, { enabled: false, mode: 'selfsigned' })

  draft.githubTokenInput.value = 'account-b-input'
  syncSettingsDraftIdentity(12)
  assert.equal(draft.githubTokenInput.value, '', 'null 后进入新账号仍从干净草稿开始')

  draft.githubTokenInput.value = 'account-b-next-input'
  syncSettingsDraftIdentity(13)
  assert.equal(draft.githubTokenInput.value, '', '不经过 null 的直接换号也必须清空')
  resetSettingsDraft()
})

test('换号后管理面板证书派生缓存必须重新读取', () => {
  const basic = code('src/views/settings/BasicSettings.vue')
  const identityWatch = section(basic, 'watch(() => authStore.user?.id', '\n})')
  assert.match(identityWatch, /loadAdminTls\(\)/, '新账号不得沿用上一账号的证书读态')
})

test('Settings.vue 仅在离开设置页时复位草稿', () => {
  const page = code('src/views/Settings.vue')
  assert.match(page, /import \{ resetSettingsDraft, syncSettingsDraftIdentity \} from '@\/composables\/useSettingsDraft'/)
  const unmounted = section(page, 'onUnmounted(', '</script>')
  assert.match(unmounted, /resetSettingsDraft\(\)/)
  assert.doesNotMatch(
    unmounted,
    /syncActiveTabFromPage|activeTab/,
    '页内切分页不得复位草稿（否则暂存内容仍会丢）',
  )
})
