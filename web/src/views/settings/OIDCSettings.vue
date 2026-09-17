<template>
  <!-- v2.3.0 OIDC 认证集成:用户与认证页内按钮+弹框交互(不干扰用户列表) -->
  <div class="oidc-entry">
    <div class="oidc-entry-row">
      <span class="oidc-entry-label">登录认证（OIDC）</span>
      <el-tag v-if="enabled" type="success" size="small" effect="light">已启用 · {{ displayName || 'OIDC' }}</el-tag>
      <el-tag v-else-if="configured" type="info" size="small" effect="plain">已配置未启用</el-tag>
      <el-tag v-else type="info" size="small" effect="plain">未配置</el-tag>
      <el-button size="small" text type="primary" @click="open">{{ configured ? '编辑' : '配置' }}</el-button>
    </div>

    <el-dialog v-model="visible" title="登录认证（OIDC）" width="680px" :close-on-click-modal="false" destroy-on-close>
      <el-alert v-if="!configured" type="info" :closable="false" class="mb12"
        title="通过企业认证服务（OIDC）登录——配置仅 3 项，端点自动发现；本地账号登录始终保留。" />

      <!-- ① 服务地址 -->
      <div class="step">
        <div class="step-title">① 服务地址</div>
        <el-input v-model="form.issuer" placeholder="https://auth.example.com（企业认证服务地址）" clearable
          @blur="probeOnBlur">
          <template #suffix>
            <el-icon v-if="probe.ok" color="#67c23a"><CircleCheckFilled /></el-icon>
            <el-icon v-else-if="probe.checked && !probe.ok" color="#f56c6c"><CircleCloseFilled /></el-icon>
          </template>
        </el-input>
        <div v-if="probe.ok" class="probe-ok">
          发现成功：{{ probe.providerName }} · 授权/令牌/JWKS 端点已自动获取
        </div>
        <div v-else-if="probe.checked && !probe.ok && probe.error" class="probe-err">{{ probe.error }}</div>
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
          <div class="reg-row">
            <span class="reg-label">回调地址（另一节点）</span>
            <code class="reg-value">{{ peerUrl }}</code>
            <el-button size="small" text type="primary" @click="copy(peerUrl)">复制</el-button>
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
            <el-input v-model="form.clientId" placeholder="Client ID" clearable />
          </el-col>
          <el-col :span="12">
            <el-input v-model="form.clientSecret" type="password" show-password
              :placeholder="hasSecret ? '已保存（留空保持不变）' : 'Client Secret'" />
          </el-col>
        </el-row>
        <el-input v-model="form.displayName" placeholder="登录按钮显示名（选填，默认取服务域名）" class="mt8" maxlength="30" />
      </div>

      <el-alert v-if="lastTest" :type="lastTest.ok ? 'success' : 'error'" :closable="false" class="mt8"
        :title="lastTest.ok ? `连接正常：${lastTest.providerName ?? ''}` : `连接失败：${lastTest.error ?? '未知错误'}`" />

      <template #footer>
        <div class="dialog-footer">
          <el-button :loading="testing" @click="test">测试连接</el-button>
          <el-button v-if="enabled" plain type="warning" :loading="saving" @click="toggleEnabled(false)">暂停使用</el-button>
          <el-button v-if="configured" plain type="danger" :disabled="saving" @click="remove">删除配置</el-button>
          <el-button type="primary" :loading="saving" @click="save">{{ enabled ? '更新配置' : '保存并启用' }}</el-button>
        </div>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { CircleCheckFilled, CircleCloseFilled } from '@element-plus/icons-vue'
import { request, ApiRequestError } from '@/utils/api'

const form = reactive({ issuer: '', clientId: '', clientSecret: '', displayName: '' })
const enabled = ref(false)
const displayName = ref('')
const configured = computed(() => form.issuer !== '' || hasFetchedConfig.value)
const hasFetchedConfig = ref(false)
const hasSecret = ref(false)
const visible = ref(false)
const probe = reactive<{ ok: boolean; checked: boolean; error?: string; providerName?: string }>({ ok: false, checked: false })
const lastTest = ref<{ ok: boolean; providerName?: string; error?: string } | null>(null)
const testing = ref(false)
const saving = ref(false)

const callbackUrl = computed(() => `${window.location.origin}/api/v1/auth/oidc/callback`)
const peerUrl = computed(() => {
  const { protocol, hostname, port } = window.location
  const peerPort = port === '8001' ? '8000' : '8001'
  return `${protocol}//${hostname}:${peerPort}/api/v1/auth/oidc/callback`
})

const load = async () => {
  try {
    const res = await request.get<{ data?: { enabled?: boolean; issuer?: string; client_id?: string; display_name?: string; has_secret?: boolean } }>('/settings/oidc')
    if (res.data) {
      enabled.value = !!res.data.enabled
      displayName.value = res.data.display_name || ''
      hasSecret.value = !!res.data.has_secret
      form.issuer = res.data.issuer || ''
      form.clientId = res.data.client_id || ''
      form.displayName = res.data.display_name || ''
      hasFetchedConfig.value = !!res.data.issuer
      if (form.issuer) { probe.checked = true; probe.ok = true }
    }
  } catch { /* 未配置 */ }
}
onMounted(load)

const open = () => { lastTest.value = null; visible.value = true }

const runProbe = async (): Promise<boolean> => {
  // 前端校验:服务地址必填且须 http(s)——空值/非法值直接本地提示,不发请求
  const issuer = form.issuer.trim()
  if (!issuer) {
    probe.checked = true; probe.ok = false; probe.error = '请先填写服务地址'
    return false
  }
  if (!/^https?:\/\//.test(issuer)) {
    probe.checked = true; probe.ok = false; probe.error = '服务地址须为 http(s) URL'
    return false
  }
  testing.value = true
  try {
    const res = await request.post<{ data?: { ok: boolean; error?: string; provider_name?: string } }>('/settings/oidc/test', { issuer }, { silent: true } as never)
    probe.checked = true
    probe.ok = !!res.data?.ok
    probe.error = res.data?.error
    probe.providerName = res.data?.provider_name
    return probe.ok
  } catch (err) {
    // 后端 4xx/5xx(如未登录/权限)——展示真实 message,不再 undefined
    probe.checked = true; probe.ok = false
    probe.error = err instanceof ApiRequestError && err.message ? err.message : '探测请求失败'
    return false
  } finally {
    testing.value = false
  }
}

const probeOnBlur = () => { if (form.issuer.trim() || probe.checked) void runProbe() }

const test = async () => {
  const ok = await runProbe()
  lastTest.value = ok
    ? { ok: true, providerName: probe.providerName }
    : { ok: false, error: probe.error || '未知错误' }
}

const save = async () => {
  // 前端校验:启用前 issuer+client_id 必填(后端同门:三项齐备才允许 enabled)
  if (!form.issuer.trim()) { ElMessage.warning('请填写服务地址'); return }
  if (!form.clientId.trim()) { ElMessage.warning('请填写 Client ID'); return }
  if (!hasSecret.value && !form.clientSecret) { ElMessage.warning('请填写 Client Secret'); return }
  saving.value = true
  try {
    const payload: Record<string, unknown> = {
      issuer: form.issuer, client_id: form.clientId, enabled: true, display_name: form.displayName,
    }
    if (form.clientSecret) payload.client_secret = form.clientSecret
    await request.put('/settings/oidc', payload)
    ElMessage.success(enabled.value ? '配置已更新' : 'OIDC 已启用——登录页将出现认证服务入口')
    await load()
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
  await ElMessageBox.confirm('删除后 OIDC 登录入口消失（已创建的 OIDC 用户保留，可另行管理）。确认删除？', '删除 OIDC 配置', { type: 'warning' })
  await request.delete('/settings/oidc')
  ElMessage.success('已删除')
  form.issuer = ''; form.clientId = ''; form.clientSecret = ''; form.displayName = ''
  probe.checked = false; probe.ok = false; lastTest.value = null
  hasFetchedConfig.value = false
  await load()
}

const copy = async (text: string) => {
  await navigator.clipboard.writeText(text)
  ElMessage.success('已复制')
}
</script>

<style scoped>
.oidc-entry-row { display: flex; align-items: center; gap: 10px; padding: 4px 0; }
.oidc-entry-label { font-size: 13.5px; font-weight: 600; }
.mb12 { margin-bottom: 12px; }
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
