<template>
  <!-- v2.3.0 OIDC 认证集成:受控弹框(入口在用户列表卡头) -->
  <el-dialog :model-value="modelValue" width="min(720px, 92vw)" :close-on-click-modal="false"
    destroy-on-close append-to-body class="oidc-dialog" @update:model-value="emit('update:modelValue', $event)">
    <template #header>
      <div class="oidc-dialog-header">
        <el-icon class="oidc-dialog-icon"><Connection /></el-icon>
        <div>
          <div class="oidc-dialog-title">登录认证（OIDC）</div>
          <div class="oidc-dialog-sub">{{ configured ? (enabled ? '已启用——登录页展示认证服务入口' : '已配置未启用') : '配置企业认证服务,本地账号登录始终保留' }}</div>
        </div>
      </div>
    </template>
    <el-alert v-if="!configured" type="info" :closable="false" class="mb12"
      title="通过企业认证服务（OIDC）登录——配置仅 3 项，端点自动发现；本地账号登录始终保留。" />
    <el-alert v-else-if="enabled" type="success" :closable="false" class="mb12"
      :title="`OIDC 已启用（${displayName || 'OIDC'}）——登录页默认展示认证服务入口，本地账号可折叠进入。`" />

    <!-- ① 服务地址 -->
    <div class="oidc-step">
      <div class="oidc-step-badge">1</div>
      <div class="oidc-step-body">
      <div class="step-title">服务地址</div>
      <el-input v-model="form.issuer" placeholder="https://auth.example.com（企业认证服务地址）" clearable @blur="probeOnBlur">
        <template #suffix>
          <el-icon v-if="probe.ok" color="#67c23a"><CircleCheckFilled /></el-icon>
          <el-icon v-else-if="probe.checked && !probe.ok" color="#f56c6c"><CircleCloseFilled /></el-icon>
        </template>
      </el-input>
      <div v-if="probe.ok" class="probe-ok">
        发现成功：{{ probe.providerName }} · 授权/令牌/JWKS 端点已自动获取
        <template v-if="probe.credentialsChecked === true">｜凭证校验通过</template>
        <template v-else-if="probe.credentialsChecked === false && (form.clientId || hasSecret)">｜该服务不支持离线凭证校验</template>
      </div>
      <div v-else-if="probe.checked && !probe.ok && probe.error" class="probe-err">{{ probe.error }}</div>
      </div>
    </div>

    <!-- ② 提供商后台登记信息（前置引导） -->
    <div class="oidc-step">
      <div class="oidc-step-badge">2</div>
      <div class="oidc-step-body">
      <div class="step-title">在认证服务后台创建应用，填入以下信息</div>
      <div class="reg-info">
          <div v-for="node in callbackNodes" :key="node.url" class="reg-row">
            <span class="reg-label">{{ node.label }}</span>
            <code class="reg-value">{{ node.url }}</code>
            <el-button size="small" text type="primary" @click="copy(node.url)">复制</el-button>
          </div>
        </div>
      </div>
    </div>

    <!-- ③ 应用凭证 -->
    <div class="oidc-step">
      <div class="oidc-step-badge">3</div>
      <div class="oidc-step-body">
      <div class="step-title">应用凭证</div>
      <el-row :gutter="12">
        <el-col :span="12">
          <el-input v-model="form.clientId" placeholder="Client ID" clearable />
        </el-col>
        <el-col :span="12">
          <el-input v-model="form.clientSecret" type="password" show-password
            :placeholder="hasSecret ? '已保存（留空保持不变）' : 'Client Secret'" />
        </el-col>
      </el-row>
      <el-input v-model="form.displayName" placeholder="登录按钮显示名（选填，默认取服务域名）" class="mt8" maxlength="30" />
      </div>
    </div>

    <el-alert v-if="lastTest" :type="lastTest.ok ? 'success' : 'error'" :closable="false" class="mt8"
      :title="lastTest.ok
          ? `连接正常：${lastTest.providerName ?? ''}${lastTest.credentialsChecked ? '（凭证校验通过）' : ''}`
          : `连接失败：${lastTest.error ?? '未知错误'}`" />

    <template #footer>
      <div class="dialog-footer">
        <el-button :loading="testing" :disabled="isReadOnly" @click="test">测试连接</el-button>
        <el-button v-if="enabled" plain type="warning" :loading="saving" :disabled="isReadOnly" @click="toggleEnabled(false)">暂停使用</el-button>
        <el-button v-if="configured" plain type="danger" :disabled="saving || isReadOnly" @click="remove">删除配置</el-button>
        <el-button type="primary" :loading="saving" :disabled="isReadOnly" @click="save">{{ enabled ? '更新配置' : '保存并启用' }}</el-button>
      </div>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { CircleCheckFilled, CircleCloseFilled, Connection } from '@element-plus/icons-vue'
import { request, ApiRequestError } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.readOnlyReason !== null)

const props = defineProps<{ modelValue: boolean }>()
const emit = defineEmits<{ (e: 'update:modelValue', v: boolean): void; (e: 'status', st: { enabled: boolean; configured: boolean }): void }>()

const form = reactive({ issuer: '', clientId: '', clientSecret: '', displayName: '' })
const enabled = ref(false)
const displayName = ref('')
const hasFetchedConfig = ref(false)
const configured = computed(() => form.issuer !== '' || hasFetchedConfig.value)
const hasSecret = ref(false)
const probe = reactive<{ ok: boolean; checked: boolean; error?: string; providerName?: string; credentialsChecked?: boolean }>({ ok: false, checked: false })
const lastTest = ref<{ ok: boolean; providerName?: string; error?: string; credentialsChecked?: boolean } | null>(null)
const testing = ref(false)
const saving = ref(false)

const CALLBACK_PATH = '/api/v1/auth/oidc/callback'
const callbackUrl = computed(() => `${window.location.origin}${CALLBACK_PATH}`)
// 从节点清单(GET /cluster/nodes,主节点才返回;单机/失败=空,静默降级只显示本节点)
const slaveOrigins = ref<{ label: string; url: string }[]>([])
const callbackNodes = computed(() => [
  { label: '回调地址（本节点）', url: callbackUrl.value },
  ...slaveOrigins.value,
])

const loadSlaves = async () => {
  try {
    // silent:从节点 403(仅主节点)不弹全局 toast——回调清单静默降级为本节点
    // (2026-09-18 用户裁定:从节点只保留只读标记,不出现「仅允许在主节点执行」提示)
    const res = await request.get<{ data?: { name?: string; ip_address?: string; port?: number; protocol?: string; access_url?: string; is_approved?: boolean }[] }>('/cluster/nodes', { silent: true } as never)
    slaveOrigins.value = (res.data || [])
      .filter(n => n.is_approved)
      .map(n => {
        const base = n.access_url?.trim() || `${n.protocol || 'http'}://${n.ip_address}:${n.port}`
        const trimmed = base.replace(/\/+$/, '')
        return { label: `回调地址（${n.name || n.ip_address}）`, url: `${trimmed}${CALLBACK_PATH}` }
      })
  } catch { /* 单机部署或非主节点——只显示本节点 */ }
}
// C3-P2/C2-9:弹框打开时才拉取(懒加载),且每次重开刷新——挂载即拉会令
// Users 页每次访问多发 2 请求(从节点 /cluster/nodes 必 403 白跑),重开
// 不刷新会让陈旧 probe.ok 绕过重测直接保存(多人管理脏写)。
watch(() => props.modelValue, (open) => {
  if (open) { void loadSlaves(); void load() }
})

const notify = () => emit('status', { enabled: enabled.value, configured: configured.value })

const load = async () => {
  try {
    // C2-3:silent——非管理员打开入口时 403 不弹全局 toast(入口按角色收口)
    const res = await request.get<{ data?: { enabled?: boolean; issuer?: string; client_id?: string; display_name?: string; has_secret?: boolean } }>('/settings/oidc', { silent: true } as never)
    if (res.data) {
      enabled.value = !!res.data.enabled
      displayName.value = res.data.display_name || ''
      hasSecret.value = !!res.data.has_secret
      form.issuer = res.data.issuer || ''
      form.clientId = res.data.client_id || ''
      form.displayName = res.data.display_name || ''
      hasFetchedConfig.value = !!res.data.issuer
      form.clientSecret = ''
      // 保存门基线:已保存的配置视为「曾经可用」但不免检——改动任一字段后
      // probe 复位为未测试,保存前强制重测(watch 联动)
      probe.checked = false; probe.ok = false; lastTest.value = null
    }
  } catch { /* 未配置/无权限 */ }
  notify()
}

let probeInFlight: Promise<boolean> | null = null

const runProbe = async (): Promise<boolean> => {
  // C2-8:在途去重——blur+click 双触发不重复探测(对 IdP 双倍 discovery 流量)
  if (probeInFlight) return probeInFlight
  probeInFlight = doRunProbe()
  try { return await probeInFlight } finally { probeInFlight = null }
}

const doRunProbe = async (): Promise<boolean> => {
  const issuer = form.issuer.trim()
  if (!issuer) { probe.checked = true; probe.ok = false; probe.error = '请先填写服务地址'; return false }
  if (!/^https?:\/\//.test(issuer)) { probe.checked = true; probe.ok = false; probe.error = '服务地址须为 http(s) URL'; return false }
  testing.value = true
  try {
    const body: Record<string, string> = { issuer }
    if (form.clientId.trim()) body.client_id = form.clientId.trim()
    if (form.clientSecret) body.client_secret = form.clientSecret
    const res = await request.post<{ data?: { ok: boolean; error?: string; provider_name?: string; credentials_checked?: boolean } }>('/settings/oidc/test', body, { silent: true } as never)
    probe.checked = true
    probe.ok = !!res.data?.ok
    probe.error = res.data?.error
    probe.providerName = res.data?.provider_name
    probe.credentialsChecked = res.data?.credentials_checked
    return probe.ok
  } catch (err) {
    probe.checked = true; probe.ok = false
    probe.error = err instanceof ApiRequestError && err.message ? err.message : '探测请求失败'
    return false
  } finally {
    testing.value = false
  }
}

const probeOnBlur = () => { if (form.issuer.trim() || probe.checked) void runProbe() }

// 任一凭证/地址字段变动→探测结果与上次测试立即失效(表单值≠已测值)
watch(() => [form.issuer, form.clientId, form.clientSecret], () => {
  probe.ok = false
  probe.checked = false
  probe.credentialsChecked = undefined
  lastTest.value = null
})

const test = async () => {
  const ok = await runProbe()
  lastTest.value = ok
    ? { ok: true, providerName: probe.providerName, credentialsChecked: probe.credentialsChecked }
    : { ok: false, error: probe.error || '未知错误' }
}

const save = async () => {
  if (!form.issuer.trim()) { ElMessage.warning('请填写服务地址'); return }
  if (!form.clientId.trim()) { ElMessage.warning('请填写 Client ID'); return }
  if (!hasSecret.value && !form.clientSecret) { ElMessage.warning('请填写 Client Secret'); return }
  // 保存门:以「当前表单值」测试通过才允许保存——防止改了凭证未测就落库
  if (!probe.ok) {
    const ok = await runProbe()
    if (!ok) { ElMessage.warning('测试连接未通过，请先修正配置再保存'); return }
  }
  if (configured.value) {
    try {
      await ElMessageBox.confirm(
        enabled.value ? '确认更新 OIDC 配置？' : '确认保存并启用 OIDC 登录？',
        enabled.value ? '更新配置' : '保存并启用',
        { type: 'warning' },
      )
    } catch { return }
  }
  saving.value = true
  try {
    const payload: Record<string, unknown> = { issuer: form.issuer, client_id: form.clientId, enabled: true, display_name: form.displayName }
    if (form.clientSecret) payload.client_secret = form.clientSecret
    await request.put('/settings/oidc', payload)
    await load()
    form.clientSecret = '' // 已保存,清空避免下次测试误带旧输入
    // load() 已回填最新启用态,按回填值提示(修复保存后恒走启用分支的死文案)
    ElMessage.success(enabled.value ? 'OIDC 已启用——登录页将出现认证服务入口' : '配置已更新')
    emit('update:modelValue', false) // 成功即关闭;失败留在弹框由拦截器报错
  } catch { /* 拦截器已提示 */ } finally {
    saving.value = false
  }
}

const toggleEnabled = async (on: boolean) => {
  saving.value = true
  try {
    await request.put('/settings/oidc', { enabled: on })
    ElMessage.success(on ? '已启用' : '已暂停（本地账号登录不受影响）')
    await load()
  } finally {
    saving.value = false
  }
}

const remove = async () => {
  try {
    await ElMessageBox.confirm('删除后 OIDC 登录入口消失（已创建的 OIDC 用户保留，可另行管理）。确认删除？', '删除 OIDC 配置', { type: 'warning' })
  } catch { return }
  await request.delete('/settings/oidc')
  ElMessage.success('已删除')
  form.issuer = ''; form.clientId = ''; form.clientSecret = ''; form.displayName = ''
  probe.checked = false; probe.ok = false; lastTest.value = null
  hasFetchedConfig.value = false
  await load()
}

const copy = async (text: string) => {
  try {
    await navigator.clipboard.writeText(text)
    ElMessage.success('已复制')
  } catch { /* 剪贴板被拒(非安全上下文等)——静默 */ }
}
</script>

<style scoped>
.mb12 { margin-bottom: 12px; }
.oidc-dialog-header { display: flex; align-items: center; gap: 12px; }
.oidc-dialog-icon {
  width: 38px; height: 38px; border-radius: 10px;
  display: flex; align-items: center; justify-content: center;
  background: var(--el-color-primary-light-9); color: var(--el-color-primary);
  font-size: 18px; flex-shrink: 0;
}
.oidc-dialog-title { font-size: 16px; font-weight: 600; color: var(--el-text-color-primary); }
.oidc-dialog-sub { font-size: 12.5px; color: var(--el-text-color-secondary); margin-top: 2px; }
.oidc-step {
  display: flex; gap: 12px;
  border: 1px solid var(--el-border-color-lighter); border-radius: 10px;
  padding: 14px; margin-bottom: 14px;
  background: var(--el-fill-color-blank);
}
.oidc-step-badge {
  width: 24px; height: 24px; border-radius: 50%; flex-shrink: 0;
  display: flex; align-items: center; justify-content: center;
  background: var(--el-color-primary); color: #fff;
  font-size: 13px; font-weight: 600;
}
.oidc-step-body { flex: 1; min-width: 0; }
.step { margin-bottom: 18px; }
.step-title { font-size: 13px; font-weight: 600; margin-bottom: 6px; }
.probe-ok { margin-top: 6px; font-size: 12.5px; color: var(--el-color-success); }
.probe-err { margin-top: 6px; font-size: 12.5px; color: var(--el-color-danger); }
.reg-info { border: 1px solid var(--el-border-color-lighter); border-radius: 8px; padding: 8px 12px; background: var(--el-fill-color-light); }
.reg-row { display: flex; align-items: center; gap: 10px; padding: 4px 0; }
.reg-label { width: 130px; font-size: 12.5px; color: var(--el-text-color-secondary); flex-shrink: 0; }
.reg-value { font-family: ui-monospace, Menlo, monospace; font-size: 12px; color: var(--el-color-primary); word-break: break-all; }
.mt8 { margin-top: 8px; }
.dialog-footer { display: flex; gap: 8px; justify-content: flex-end; flex-wrap: wrap; }
</style>
