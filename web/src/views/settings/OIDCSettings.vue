<template>
  <div class="oidc-settings">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>认证集成（OIDC）</span>
          <el-tag v-if="config.enabled" type="success" size="small" effect="light">已启用</el-tag>
          <el-tag v-else-if="configured" type="info" size="small" effect="plain">已配置未启用</el-tag>
          <el-tag v-else type="info" size="small" effect="plain">未配置</el-tag>
        </div>
      </template>

      <el-alert v-if="!configured" type="info" :closable="false" class="top-alert"
        title="通过企业认证服务（OIDC）登录本系统——配置仅 3 项，端点自动发现；本地账号登录始终保留。" />

      <!-- ① 服务地址 -->
      <div class="step">
        <div class="step-title">① 服务地址</div>
        <el-input v-model="form.issuer" placeholder="https://auth.example.com（企业认证服务地址）" size="large" clearable
          @blur="probeOnBlur">
          <template #suffix>
            <el-icon v-if="probe.ok" color="#67c23a"><CircleCheckFilled /></el-icon>
            <el-icon v-else-if="probe.checked && !probe.ok" color="#f56c6c"><CircleCloseFilled /></el-icon>
          </template>
        </el-input>
        <div v-if="probe.ok" class="probe-ok">
          发现成功：{{ probe.providerName }} · 授权/令牌/JWKS 端点已自动获取
          <span v-if="probe.scopes?.length" class="probe-sub">（作用域：{{ probe.scopes.slice(0, 5).join(' · ') }}）</span>
        </div>
        <div v-else-if="probe.checked && probe.error" class="probe-err">{{ probe.error }}</div>
      </div>

      <!-- ② 提供商后台登记信息（前置引导） -->
      <div class="step">
        <div class="step-title">② 在认证服务后台创建应用，填入以下信息</div>
        <div class="reg-info">
          <div class="reg-row">
            <span class="reg-label">回调地址（本节点）</span>
            <code class="reg-value">{{ callbackUrl }}</code>
            <el-button size="small" text type="primary" @click="copy(callbackUrl)">复制</el-button>
          </div>
          <div v-if="slaveUrl" class="reg-row">
            <span class="reg-label">回调地址（从节点）</span>
            <code class="reg-value">{{ slaveUrl }}</code>
            <el-button size="small" text type="primary" @click="copy(slaveUrl)">复制</el-button>
          </div>
          <div class="reg-row">
            <span class="reg-label">授权范围</span>
            <code class="reg-value">openid · profile · email</code>
          </div>
        </div>
      </div>

      <!-- ③ 应用凭证 -->
      <div class="step">
        <div class="step-title">③ 应用凭证</div>
        <el-row :gutter="12">
          <el-col :span="12">
            <el-input v-model="form.clientId" placeholder="Client ID" size="large" clearable />
          </el-col>
          <el-col :span="12">
            <el-input v-model="form.clientSecret" type="password" show-password size="large"
              :placeholder="hasSecret ? '已保存（留空保持不变）' : 'Client Secret'" />
          </el-col>
        </el-row>
        <el-input v-model="form.displayName" placeholder="登录按钮显示名（选填，默认取服务域名）" size="large" class="mt8" maxlength="30" />
      </div>

      <!-- ④ 操作 -->
      <div class="actions">
        <el-button :loading="testing" @click="test">测试连接</el-button>
        <el-button type="primary" :loading="saving" :disabled="!probe.ok && !configured" @click="save">{{ config.enabled ? '更新配置' : '保存并启用' }}</el-button>
        <el-button v-if="config.enabled" plain type="warning" @click="toggleEnabled(false)">暂停使用</el-button>
        <el-button v-if="configured" plain type="danger" @click="remove">删除配置</el-button>
      </div>

      <el-alert v-if="lastTest && lastTest.ok" type="success" :closable="false" class="mt8"
        :title="`连接正常：${lastTest.providerName}（令牌端点 ${lastTest.token_endpoint}）`" />
      <el-alert v-else-if="lastTest && !lastTest.ok" type="error" :closable="false" class="mt8"
        :title="`连接失败：${lastTest.error}`" />
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { CircleCheckFilled, CircleCloseFilled } from '@element-plus/icons-vue'
import { request } from '@/utils/api'

const form = reactive({ issuer: '', clientId: '', clientSecret: '', displayName: '' })
const config = ref({ enabled: false, issuer: '', client_id: '', display_name: '' })
const hasSecret = ref(false)
const configured = computed(() => !!config.value.issuer)
const probe = reactive<{ ok: boolean; checked: boolean; error?: string; providerName?: string; scopes?: string[] }>({ ok: false, checked: false })
const lastTest = ref<{ ok: boolean; providerName?: string; token_endpoint?: string; error?: string } | null>(null)
const testing = ref(false)
const saving = ref(false)

const callbackUrl = computed(() => `${window.location.origin}/api/v1/auth/oidc/callback`)
const slaveUrl = computed(() => {
  const { protocol, hostname } = window.location
  const port = window.location.port === '8001' ? '8000' : '8001'
  return `${protocol}//${hostname}:${port}/api/v1/auth/oidc/callback`
})

const load = async () => {
  try {
    const res = await request.get<{ data?: typeof config.value & { has_secret?: boolean } }>('/settings/oidc')
    if (res.data) {
      config.value = { enabled: !!res.data.enabled, issuer: res.data.issuer || '', client_id: res.data.client_id || '', display_name: res.data.display_name || '' }
      hasSecret.value = !!res.data.has_secret
      form.issuer = config.value.issuer
      form.clientId = config.value.client_id
      form.displayName = config.value.display_name
      if (form.issuer) probe.checked = probe.ok = true
    }
  } catch { /* 未配置 */ }
}
onMounted(load)

const probeOnBlur = async () => {
  if (!form.issuer.trim()) { probe.checked = false; probe.ok = false; return }
  testing.value = true
  try {
    const res = await request.post<{ data?: { ok: boolean; error?: string; provider_name?: string; scopes?: string[] } }>('/settings/oidc/test', { issuer: form.issuer }, { silent: true } as never)
    probe.checked = true
    probe.ok = !!res.data?.ok
    probe.error = res.data?.error
    probe.providerName = res.data?.provider_name
    probe.scopes = res.data?.scopes
  } finally {
    testing.value = false
  }
}

const test = async () => { await probeOnBlur(); lastTest.value = probe.ok ? { ok: true, providerName: probe.providerName, token_endpoint: '' } : { ok: false, error: probe.error } }

const save = async () => {
  saving.value = true
  try {
    const payload: Record<string, unknown> = {
      issuer: form.issuer, client_id: form.clientId, enabled: !config.value.enabled || config.value.enabled,
      display_name: form.displayName,
    }
    if (form.clientSecret) payload.client_secret = form.clientSecret
    if (configured.value) payload.enabled = true
    await request.put('/settings/oidc', payload)
    ElMessage.success(config.value.enabled ? '配置已更新' : 'OIDC 已启用——登录页将出现认证服务入口')
    await load()
  } finally {
    saving.value = false
  }
}

const toggleEnabled = async (on: boolean) => {
  await request.put('/settings/oidc', { enabled: on })
  ElMessage.success(on ? '已启用' : '已暂停（本地账号登录不受影响）')
  await load()
}

const remove = async () => {
  await ElMessageBox.confirm('删除后 OIDC 登录入口消失（已创建的 OIDC 用户保留，可另行管理）。确认删除？', '删除 OIDC 配置', { type: 'warning' })
  await request.delete('/settings/oidc')
  ElMessage.success('已删除')
  form.issuer = ''; form.clientId = ''; form.clientSecret = ''; form.displayName = ''
  probe.checked = false; probe.ok = false; lastTest.value = null
  await load()
}

const copy = async (text: string) => {
  await navigator.clipboard.writeText(text)
  ElMessage.success('已复制')
}
</script>

<style scoped>
.oidc-settings { max-width: 760px; }
.card-header { display: flex; align-items: center; gap: 10px; }
.top-alert { margin-bottom: 16px; }
.step { margin-bottom: 20px; }
.step-title { font-size: 13.5px; font-weight: 600; color: var(--el-text-color-primary); margin-bottom: 8px; }
.probe-ok { margin-top: 6px; font-size: 12.5px; color: var(--el-color-success); }
.probe-sub { color: var(--el-text-color-secondary); }
.probe-err { margin-top: 6px; font-size: 12.5px; color: var(--el-color-danger); }
.reg-info { border: 1px solid var(--el-border-color-lighter); border-radius: 8px; padding: 10px 14px; background: var(--el-fill-color-light); }
.reg-row { display: flex; align-items: center; gap: 10px; padding: 5px 0; }
.reg-label { width: 140px; font-size: 12.5px; color: var(--el-text-color-secondary); flex-shrink: 0; }
.reg-value { font-family: ui-monospace, Menlo, monospace; font-size: 12px; color: var(--el-color-primary); word-break: break-all; }
.actions { display: flex; gap: 10px; flex-wrap: wrap; }
.mt8 { margin-top: 8px; }
</style>
