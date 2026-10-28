<template>
  <!-- v2.3.0 OIDC 认证集成:受控弹框(入口在用户列表卡头) -->
  <el-dialog :model-value="modelValue" width="min(720px, 92vw)" :close-on-click-modal="false" :close-on-press-escape="!saving" :show-close="!saving"
    destroy-on-close append-to-body class="oidc-dialog" @update:model-value="emit('update:modelValue', $event)">
    <template #header>
      <DialogHeader :icon="Connection" title="登录认证（OIDC）"
        :subtitle="loadFailed ? '配置读取失败' : configured ? (enabled ? '已启用——登录页展示认证服务入口' : '已配置未启用') : '配置企业认证服务,本地账号登录始终保留'" />
    </template>
    <!-- 读取失败显性化（此前静默呈现上一轮残留状态或空白表单）-->
    <el-alert v-if="loadFailed" type="error" :closable="false" show-icon class="mb12"
      title="OIDC 配置读取失败——当前按「未配置」展示，读取成功前无法保存；请关闭弹框后重试" />
    <div v-else-if="!configured" class="info-note-bar"><span class="info-note-desc">通过企业认证服务（OIDC）登录——必需配置 3 项，端点自动发现；访问白名单可选；本地账号登录始终保留。</span></div>
    <el-alert v-else-if="enabled" type="success" :closable="false" class="mb12"
      :title="`OIDC 已启用（${displayName || 'OIDC'}）——登录页默认展示认证服务入口，本地账号可折叠进入。`" />

    <!-- 只读（从节点/非管理员）时整表单禁用：footer 按钮禁用是双保险而非唯一面，
         与 FreeCertificates/BasicSettings 的整表单 :disabled 口径一致。
         保存中同样冻结（formFrozen）：保存成功会关弹框，在途编辑静默丢失。 -->
    <el-form :disabled="formFrozen">
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
      <div class="dialog-panel reg-info">
          <!-- 两行样式(2026-09-19 用户裁定):第一行=回调地址(节点名)标题,
               第二行=地址+复制按钮——防节点名过长时行内挤压换行错位 -->
          <div v-for="node in callbackNodes" :key="node.url" class="reg-row">
            <div class="reg-label">{{ node.label }}</div>
            <div class="reg-value-row">
              <code class="reg-value">{{ node.url }}</code>
              <el-button size="small" text type="primary" @click="copy(node.url)">复制</el-button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ③ 应用凭证 -->
    <div class="oidc-step">
      <div class="oidc-step-badge">3</div>
      <div class="oidc-step-body">
      <div class="step-title">应用凭证</div>
      <div class="cred-form">
        <div class="cred-row">
          <div class="cred-row__label">Client ID</div>
          <div class="cred-row__field"><el-input v-model="form.clientId" placeholder="认证服务后台的 Client ID" clearable /></div>
        </div>
        <div class="cred-row">
          <div class="cred-row__label">Client Secret</div>
          <div class="cred-row__field">
            <el-input v-model="form.clientSecret" type="password" show-password
              :placeholder="hasSecret ? '已保存（留空保持不变）' : '认证服务后台的 Client Secret'" />
          </div>
        </div>
        <div class="cred-row">
          <div class="cred-row__label">登录按钮显示名</div>
          <div class="cred-row__field"><el-input v-model="form.displayName" placeholder="选填，默认取服务域名" maxlength="30" /></div>
        </div>
      </div>
      </div>
    </div>

    <!-- ④ 访问白名单（选填）——开启 OIDC 即对 IdP 全体可认证用户开放面板只读
         （含证书私钥，已裁定设计），白名单是面板侧唯一收口。 -->
    <div class="oidc-step">
      <div class="oidc-step-badge">4</div>
      <div class="oidc-step-body">
      <div class="step-title">访问白名单（选填）</div>
      <div class="cred-form">
        <div class="cred-row">
          <div class="cred-row__label">邮箱域</div>
          <div class="cred-row__field">
            <el-input v-model="form.allowedEmailDomains" placeholder="example.com, corp.example.org（逗号分隔；留空=不限制）" clearable />
            <div class="form-tip-line">仅这些邮箱域的用户可登录（写入侧自动去空白、转小写并去重）；邮箱还须由认证服务标记为已验证（email_verified=true），未验证的邮箱一律拒登</div>
          </div>
        </div>
        <div class="cred-row">
          <div class="cred-row__label">用户组</div>
          <div class="cred-row__field">
            <el-input v-model="form.allowedGroups" placeholder="ops, Domain Admins（逗号分隔；留空=不限制）" clearable />
            <div class="form-tip-line">仅这些 IdP 用户组的成员可登录（组名大小写敏感；组名可含空格，仅按逗号/分号/换行分隔）</div>
          </div>
        </div>
      </div>
      <div class="form-tip-line">两项都填写时须同时满足；IdP 未返回 email/groups 声明时直接拒登（fail-visible），不会静默放行</div>
      </div>
    </div>
    </el-form>

    <el-alert v-if="lastTest" :type="lastTest.ok ? 'success' : 'error'" :closable="false" class="mt8"
      :title="lastTest.ok
          ? `连接正常：${lastTest.providerName ?? ''}${lastTest.credentialsChecked ? '（凭证校验通过）' : ''}`
          : `连接失败：${lastTest.error ?? '未知错误'}`" />

    <template #footer>
      <div class="dialog-footer">
        <el-button :loading="testing" :disabled="isReadOnly || saving" @click="test">测试连接</el-button>
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
import DialogHeader from '@/components/DialogHeader.vue'
import { request, mfaAwareSuccess, ApiRequestError } from '@/utils/api'
import { copyText } from '@/utils/copy'
import { useAuthStore } from '@/stores/auth'
import { formatAllowList, parseDomainAllowList, parseGroupAllowList } from '@/utils/oidcAllowList'
import { createOidcProbeGuard, isOidcProbeFresh, oidcProbeKey } from '@/utils/oidcProbe'
import { createLatestReadSession, runExclusive } from '@/utils/viewAsyncState'
import type { OidcProbeToken, OidcProbeValues } from '@/utils/oidcProbe'

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.readOnlyReason !== null)

const props = defineProps<{ modelValue: boolean }>()
const emit = defineEmits<{ (e: 'update:modelValue', v: boolean): void; (e: 'status', st: { enabled: boolean; configured: boolean }): void }>()

const form = reactive({
  issuer: '',
  clientId: '',
  clientSecret: '',
  displayName: '',
  // 访问白名单以「逗号/空格/换行分隔文本」编辑，保存时解析为数组——
  // 契约：PUT 携带数组（[]=清除），缺省键=不动（toggleEnabled/remove 不携带）。
  allowedEmailDomains: '',
  allowedGroups: '',
})

// 白名单文本 ↔ 数组：解析/格式化单源 utils/oidcAllowList（域条目含空白当分隔，
// 用户组名保留内部空格——两侧口径有意不同，见该模块头注释）。
const enabled = ref(false)
const displayName = ref('')
const hasFetchedConfig = ref(false)
const configured = computed(() => form.issuer !== '' || hasFetchedConfig.value)
const hasSecret = ref(false)
const probe = reactive<{ ok: boolean; checked: boolean; key?: string; error?: string; providerName?: string; credentialsChecked?: boolean }>({ ok: false, checked: false })
const lastTest = ref<{ ok: boolean; providerName?: string; error?: string; credentialsChecked?: boolean } | null>(null)
const testing = ref(false)
const saving = ref(false)
// 保存中冻结整表单（与设置卡同口径）：保存成功即关弹框，在途编辑无处落账。
const formFrozen = computed(() => isReadOnly.value || saving.value)

const CALLBACK_PATH = '/api/v1/auth/oidc/callback'
const callbackUrl = computed(() => `${window.location.origin}${CALLBACK_PATH}`)
// 从节点清单(GET /cluster/nodes,主节点才返回;单机/失败=空,静默降级只显示本节点)
const slaveOrigins = ref<{ label: string; url: string }[]>([])
const callbackNodes = computed(() => [
  { label: '回调地址（本节点）', url: callbackUrl.value },
  ...slaveOrigins.value,
])

const probeGuard = createOidcProbeGuard()
const currentProbeValues = (): OidcProbeValues => ({
  issuer: form.issuer,
  clientId: form.clientId,
  clientSecret: form.clientSecret,
})
const invalidateProbe = (): void => {
  probeGuard.invalidate()
  probe.ok = false
  probe.checked = false
  probe.key = undefined
  probe.error = undefined
  probe.providerName = undefined
  probe.credentialsChecked = undefined
  lastTest.value = null
}

const loadSlaves = async () => {
  try {
    // silent:从节点 403(仅主节点)不弹全局 toast——回调清单静默降级为本节点
    // (2026-09-18 用户裁定:从节点只保留只读标记,不出现「仅允许在主节点执行」提示)
    const res = await request.get<{ data?: { name?: string; ip_address?: string; port?: number; protocol?: string; access_url?: string; is_approved?: boolean }[] }>('/cluster/nodes', { silent: true })
    slaveOrigins.value = (res.data || [])
      .filter(n => n.is_approved)
      .map(n => {
        const base = n.access_url?.trim() || `${n.protocol || 'http'}://${n.ip_address}:${n.port}`
        const trimmed = base.replace(/\/+$/, '')
        return { label: `回调地址（${n.name || n.ip_address}）`, url: `${trimmed}${CALLBACK_PATH}` }
      })
  } catch { /* 单机部署或非主节点——只显示本节点 */ }
}
// 弹框打开时才拉取(懒加载),且每次重开刷新——挂载即拉会令
// Users 页每次访问多发 2 请求(从节点 /cluster/nodes 必 403 白跑),重开
// 不刷新会让陈旧 probe.ok 绕过重测直接保存(多人管理脏写)。
watch(() => props.modelValue, (open) => {
  invalidateProbe()
  if (open) { void loadSlaves(); void load() }
})

const notify = () => emit('status', { enabled: enabled.value, configured: configured.value })

// 读取失败不得沿用上一轮残留状态（二次打开弹框 GET 失败时仍显示
// 「已启用/删除配置/暂停使用」，父级标签也被回填旧值）。catch 清空为未配置态
// 并显性提示；保存门同时拦截，避免用户以「空表单」覆盖现有配置。
const loadFailed = ref(false)
// 读取回填只接受最新一轮请求；成功、失败与父级通知共用同一会话乱序门。
const readSession = createLatestReadSession()
const load = async () => {
  await readSession.run(
    // silent——非管理员打开入口时 403 不弹全局 toast(入口按角色收口)
    (signal) => request.get<{ data?: { enabled?: boolean; issuer?: string; client_id?: string; display_name?: string; has_secret?: boolean; allowed_email_domains?: string[]; allowed_groups?: string[] } }>('/settings/oidc', { silent: true, signal }),
    {
      onStart: () => {
        invalidateProbe()
        loadFailed.value = false
      },
      onSuccess: (res) => {
        if (res.data) {
          enabled.value = !!res.data.enabled
          displayName.value = res.data.display_name || ''
          hasSecret.value = !!res.data.has_secret
          form.issuer = res.data.issuer || ''
          form.clientId = res.data.client_id || ''
          form.displayName = res.data.display_name || ''
          form.allowedEmailDomains = formatAllowList(res.data.allowed_email_domains)
          form.allowedGroups = formatAllowList(res.data.allowed_groups)
          hasFetchedConfig.value = !!res.data.issuer
          form.clientSecret = ''
          // load 开始已推进探测世代；响应回填的字段 watcher 会再次失效旧快照。
        }
      },
      onError: () => {
        // 未配置/无权限/网络失败：一律回到「未配置」可见态（fail-visible）
        enabled.value = false
        displayName.value = ''
        hasSecret.value = false
        form.issuer = ''
        form.clientId = ''
        form.displayName = ''
        form.clientSecret = ''
        form.allowedEmailDomains = ''
        form.allowedGroups = ''
        hasFetchedConfig.value = false
        lastTest.value = null
        loadFailed.value = true
      },
      onFinally: notify,
    },
  )
}

let probeInFlight: { token: OidcProbeToken; promise: Promise<boolean> } | null = null

const runProbe = async (): Promise<boolean> => {
  const values = currentProbeValues()
  const token = probeGuard.token(values)
  // 仅复用仍是当前世代且快照相同的在途探测；输入变化/关闭/load 后必须新测。
  if (probeInFlight && probeGuard.isCurrent(probeInFlight.token, values)) return probeInFlight.promise
  const promise = doRunProbe(values, token)
  probeInFlight = { token, promise }
  testing.value = true
  try { return await promise } finally {
    if (probeInFlight?.promise === promise) {
      probeInFlight = null
      testing.value = false
    }
  }
}

const doRunProbe = async (values: OidcProbeValues, token: OidcProbeToken): Promise<boolean> => {
  const issuer = values.issuer.trim()
  if (!issuer) { probe.checked = true; probe.ok = false; probe.error = '请先填写服务地址'; return false }
  if (!/^https?:\/\//.test(issuer)) { probe.checked = true; probe.ok = false; probe.error = '服务地址须为 http(s) URL'; return false }
  try {
    const body: Record<string, string> = { issuer }
    if (values.clientId.trim()) body.client_id = values.clientId.trim()
    if (values.clientSecret) body.client_secret = values.clientSecret
    const res = await request.post<{ data?: { ok: boolean; error?: string; provider_name?: string; credentials_checked?: boolean } }>('/settings/oidc/test', body, { silent: true })
    if (!probeGuard.isCurrent(token, currentProbeValues())) return false
    probe.checked = true
    probe.key = token.key
    probe.ok = !!res.data?.ok
    probe.error = res.data?.error
    probe.providerName = res.data?.provider_name
    probe.credentialsChecked = res.data?.credentials_checked
    return probe.ok
  } catch (err) {
    if (!probeGuard.isCurrent(token, currentProbeValues())) return false
    probe.checked = true
    probe.key = token.key
    probe.ok = false
    probe.error = err instanceof ApiRequestError && err.message ? err.message : '探测请求失败'
    return false
  }
}

// 已通过且表单值未变时直接复用结果——原每次失焦都触发一次 discovery+
// JWKS（+ 可选凭证校验）外部请求，字段间来回切换会重复打 IdP。
const probeOnBlur = () => {
  if (!form.issuer.trim() && !probe.checked) return
  if (isOidcProbeFresh(probe, currentProbeValues())) return
  void runProbe()
}

// 任一凭证/地址字段变动→探测结果与上次测试立即失效(表单值≠已测值)
watch(() => [form.issuer, form.clientId, form.clientSecret], () => {
  invalidateProbe()
})

const test = async () => {
  const token = probeGuard.token(currentProbeValues())
  const ok = await runProbe()
  if (!probeGuard.isCurrent(token, currentProbeValues())) return
  lastTest.value = ok
    ? { ok: true, providerName: probe.providerName, credentialsChecked: probe.credentialsChecked }
    : { ok: false, error: probe.error || '未知错误' }
}

const save = async () => {
  // 函数级守卫 + 读取未成功时禁止保存（空表单会覆盖现有配置）
  if (isReadOnly.value || saving.value) return
  if (loadFailed.value) { ElMessage.warning('OIDC 配置读取失败，请关闭弹框后重试'); return }
  if (!form.issuer.trim()) { ElMessage.warning('请填写服务地址'); return }
  if (!form.clientId.trim()) { ElMessage.warning('请填写 Client ID'); return }
  if (!hasSecret.value && !form.clientSecret) { ElMessage.warning('请填写 Client Secret'); return }
  // 在途门须先于探测与二次确认置位——discovery 常 0.2–2s，这段窗口内
  // 按钮 loading 缺席会让连点叠出两个确认框与两条 PUT。
  saving.value = true
  try {
    // 保存门:以「当前表单值」测试通过才允许保存——防止改了凭证未测就落库
    if (!isOidcProbeFresh(probe, currentProbeValues())) {
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
    if (!probe.ok || probe.key !== oidcProbeKey(currentProbeValues())) {
      ElMessage.warning('配置已变更，请重新测试连接后再保存')
      return
    }
    const payload: Record<string, unknown> = {
      issuer: form.issuer,
      client_id: form.clientId,
      enabled: true,
      display_name: form.displayName,
      // 整表保存始终携带白名单（[]=清除）；缺省键语义仅用于局部 PUT（启用/暂停/删除）。
      allowed_email_domains: parseDomainAllowList(form.allowedEmailDomains),
      allowed_groups: parseGroupAllowList(form.allowedGroups),
    }
    if (form.clientSecret) payload.client_secret = form.clientSecret
    await request.put('/settings/oidc', payload)
    await load()
    form.clientSecret = '' // 已保存,清空避免下次测试误带旧输入
    // load() 已回填最新启用态,按回填值提示(修复保存后恒走启用分支的死文案)
    mfaAwareSuccess(enabled.value ? 'OIDC 已启用——登录页将出现认证服务入口' : '配置已更新')
    emit('update:modelValue', false) // 成功即关闭;失败留在弹框由拦截器报错
  } catch { /* 拦截器已提示 */ } finally {
    saving.value = false
  }
}

const toggleEnabled = async (on: boolean) => {
  if (isReadOnly.value || saving.value || loadFailed.value) return
  saving.value = true
  try {
    await request.put('/settings/oidc', { enabled: on })
    mfaAwareSuccess(on ? '已启用' : '已暂停（本地账号登录不受影响）')
    await load()
  } catch { /* 拦截器已提示 */ } finally {
    saving.value = false
  }
}

const remove = async () => {
  if (isReadOnly.value || saving.value || loadFailed.value) return
  await runExclusive(() => saving.value, (locked) => { saving.value = locked }, async () => {
    try {
      await ElMessageBox.confirm('删除后 OIDC 登录入口消失（已创建的 OIDC 用户保留，可另行管理）。确认删除？', '删除 OIDC 配置', { type: 'warning' })
    } catch { return }
    try {
      await request.delete('/settings/oidc')
    } catch { /* 拦截器已提示 */ return }
    mfaAwareSuccess('已删除')
    form.issuer = ''; form.clientId = ''; form.clientSecret = ''; form.displayName = ''
    form.allowedEmailDomains = ''; form.allowedGroups = ''
    probe.checked = false; probe.ok = false; lastTest.value = null
    hasFetchedConfig.value = false
    await load()
  })
}

const copy = async (text: string) => {
  // 复用 utils/copy 的 copyText（clipboard API + textarea 降级双通道，与全站一致）。
  if (await copyText(text)) {
    ElMessage.success('已复制')
    return
  }
  ElMessage.error('复制失败，请手动复制')
}
</script>

<style scoped>
.mb12 { margin-bottom: 12px; }
.oidc-step {
  display: flex; gap: 10px;
  border: 1px solid var(--el-border-color-lighter); border-radius: 10px;
  padding: 12px; margin-bottom: 14px;
  background: var(--el-fill-color-blank);
}
.oidc-step-badge {
  width: 24px; height: 24px; border-radius: 50%; flex-shrink: 0;
  display: flex; align-items: center; justify-content: center;
  background: var(--el-color-primary); color: #fff;
  font-size: 13px; font-weight: 600;
}
.oidc-step-body { flex: 1; min-width: 0; padding-right: 34px; }
.step-title { font-size: 13px; font-weight: 600; margin-bottom: 6px; }
.cred-form { display: flex; flex-direction: column; gap: 14px; margin-top: 4px; }
.cred-row { display: flex; align-items: flex-start; gap: 12px; }
.cred-row__label { width: 100px; flex-shrink: 0; white-space: nowrap; font-size: 13px; color: var(--el-text-color-regular); line-height: 32px; text-align: right; }
.cred-row__field { flex: 1; min-width: 0; }
.probe-ok { margin-top: 6px; font-size: 12.5px; color: var(--el-color-success); }
.probe-err { margin-top: 6px; font-size: 12.5px; color: var(--el-color-danger); }
.reg-info { margin-top: 4px; }
.reg-row { display: flex; flex-direction: column; gap: 2px; padding: 6px 0; }
.reg-row + .reg-row { border-top: 1px dashed var(--el-border-color-lighter); }
.reg-label { font-size: 12.5px; color: var(--el-text-color-secondary); word-break: break-all; }
.reg-value-row { display: flex; align-items: center; gap: 8px; min-width: 0; }
.reg-value { font-family: ui-monospace, Menlo, monospace; font-size: 12px; color: var(--el-color-primary); word-break: break-all; min-width: 0; }
.mt8 { margin-top: 8px; }
.dialog-footer { display: flex; gap: 8px; justify-content: flex-end; flex-wrap: wrap; }
</style>
