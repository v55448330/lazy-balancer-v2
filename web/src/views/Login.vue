<template>
  <div class="login-container">
    <el-card class="login-card" v-loading="checkingSetup" element-loading-text="正在检查登录状态...">
      <div class="login-header">
        <div class="logo-wrapper">
          <AppLogo :size="64" />
        </div>
        <h1 class="login-title">
          {{ appName }} <span class="v2-badge">V2</span>
        </h1>
        <p class="login-subtitle">Caddy 负载均衡管理平台</p>
      </div>

      <template v-if="!checkingSetup">
        <el-form v-if="setupMode" ref="setupFormRef" :model="setupForm" :rules="setupRules" @submit.prevent="handleSetup" class="login-form">
          <div class="info-note-bar"><span class="info-note-desc">首次启动，请创建管理员账号</span></div>
          <el-form-item prop="username">
            <el-input v-model="setupForm.username" name="username" autocomplete="username" placeholder="管理员用户名（小写英文开头，仅限小写字母和数字）" size="large" :prefix-icon="User" maxlength="50" clearable />
          </el-form-item>
          <el-form-item prop="display_name">
            <el-input v-model="setupForm.display_name" placeholder="显示名（选填）" size="large" :prefix-icon="Postcard" maxlength="50" clearable />
          </el-form-item>
          <el-form-item prop="password">
            <el-input v-model="setupForm.password" type="password" name="new-password" autocomplete="new-password" placeholder="密码（8-24 位，仅限数字、大小写字母和特殊字符）" size="large" :prefix-icon="Lock" maxlength="24" show-password />
          </el-form-item>
          <el-form-item prop="confirm">
            <el-input v-model="setupForm.confirm" type="password" name="new-password-confirm" autocomplete="new-password" placeholder="确认密码" size="large" :prefix-icon="Lock" maxlength="24" show-password />
          </el-form-item>
          <el-alert v-if="error" :title="error" type="error" show-icon :closable="false" class="login-error" />
          <el-form-item>
            <el-button type="primary" native-type="submit" :loading="loading" size="large" class="login-btn">
              {{ loading ? '创建中...' : '创建管理员并登录' }}
            </el-button>
          </el-form-item>
        </el-form>

        <el-form v-else-if="mfaStage" @submit.prevent="handleMfaVerify" class="login-form">
          <div class="mfa-step-title">两步验证</div>
          <el-form-item v-if="!mfaUseRecovery">
            <el-input-otp
              ref="mfaOtpRef"
              v-model="mfaCode"
              :length="6"
              inputmode="numeric"
              :validator="isOtpDigitChar"
              class="mfa-otp"
              @finish="handleMfaVerify"
            />
          </el-form-item>
          <el-form-item v-else>
            <el-input
              v-model="mfaCode"
              placeholder="请输入恢复代码"
              size="large"
              :prefix-icon="Key"
              maxlength="200"
              autofocus
              @input="mfaCode = normalizeMfaCodeInput(mfaCode)"
            />
          </el-form-item>
          <el-alert v-if="error" :title="error" type="error" show-icon :closable="false" class="login-error" />
          <el-form-item>
            <el-button type="primary" native-type="submit" :loading="loading" size="large" class="login-btn">
              {{ loading ? '验证中...' : '验 证' }}
            </el-button>
          </el-form-item>
          <div class="mfa-switch">
            <AccessibleLink type="primary" underline="never" @click="mfaUseRecovery = !mfaUseRecovery; mfaCode = ''">
              {{ mfaUseRecovery ? '使用验证码' : '使用恢复代码' }}
            </AccessibleLink>
            <AccessibleLink type="info" underline="never" @click="resetToPasswordStep">返回重新登录</AccessibleLink>
          </div>
        </el-form>

        <template v-else>
          <div v-if="oidcStatusError" class="oidc-status-error">
            <el-alert :title="oidcStatusError" type="error" show-icon :closable="false" class="login-error" />
            <el-button text type="primary" :loading="oidcStatusLoading" @click="loadOidcStatus">重试</el-button>
          </div>
          <!-- v2.3.0 OIDC:品牌主按钮;本地账号次级入口,可双向切换 -->
          <div v-if="oidcEnabled && !showLocalForm" class="oidc-login">
            <button class="oidc-sso-btn" :disabled="oidcRedirecting" @click="goOIDCLogin">
              <span class="oidc-sso-title">使用 {{ oidcDisplayName }} 登录</span>
              <span class="oidc-sso-sub">企业认证服务 · 单点登录</span>
            </button>
            <div class="login-alt-divider"><span>或</span></div>
            <el-button text size="default" class="local-toggle" :icon="User" @click="showLocalForm = true">使用本地账号登录</el-button>
          </div>
          <template v-else>
          <el-form v-show="!oidcEnabled || showLocalForm" ref="formRef" :model="form" :rules="rules" @submit.prevent="handleLogin" class="login-form">
          <el-form-item prop="username">
            <el-input
              v-model="form.username"
              name="username"
              autocomplete="username"
              placeholder="请输入用户名"
              size="large"
              :prefix-icon="User"
              clearable
            />
          </el-form-item>

          <el-form-item prop="password">
            <el-input
              v-model="form.password"
              type="password"
              name="password"
              autocomplete="current-password"
              placeholder="请输入密码"
              size="large"
              :prefix-icon="Lock"
              maxlength="72"
              show-password
            />
          </el-form-item>

          <el-alert v-if="error" :title="error" type="error" show-icon :closable="false" class="login-error" />

          <el-form-item>
            <el-button
              type="primary"
              native-type="submit"
              :loading="loading"
              size="large"
              class="login-btn"
            >
              {{ loading ? '登录中...' : '登 录' }}
            </el-button>
          </el-form-item>
          </el-form>
            <div v-if="oidcEnabled" class="back-to-oidc">
              <el-button text size="small" @click="showLocalForm = false">
                <el-icon><ArrowLeft /></el-icon>
                返回 {{ oidcDisplayName }} 登录
              </el-button>
            </div>
          </template>
        </template>
      </template>


      <div class="login-footer">
        <span class="version">版本 {{ appVersion }}</span>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { nextTick, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { useAuthStore } from '@/stores/auth'
import { ApiRequestError, normalizeMfaCodeInput, request } from '@/utils/api'
import { User, Lock, Postcard, Key, ArrowLeft } from '@element-plus/icons-vue'
import AppLogo from '@/components/AppLogo.vue'
import AccessibleLink from '@/components/common/AccessibleLink.vue'
import { appName, appVersion } from '@/utils/branding'
import { validatePassword, validateUsername } from '@/utils/credentials'
import { OIDC_APP_NONCE_KEY, createOidcAppNonce, withOidcAppNonce } from '@/utils/oidcCallback'
import type { FormInstance, FormRules, InputOtpInstance } from 'element-plus'

interface SetupStatusResponse {
  code: number
  data: { needs_setup: boolean }
}

const authStore = useAuthStore()
const formRef = ref<FormInstance>()
const setupFormRef = ref<FormInstance>()

const setupMode = ref(false)
const checkingSetup = ref(true)

const form = reactive({
  username: '',
  password: '',
})

const setupForm = reactive({
  username: '',
  display_name: '',
  password: '',
  confirm: '',
})

const rules: FormRules = {
  username: [
    { required: true, message: '请输入用户名', trigger: 'blur' },
  ],
  password: [
    { required: true, message: '请输入密码', trigger: 'blur' },
  ],
}

const setupRules: FormRules = {
  username: [
    { required: true, message: '请输入管理员用户名', trigger: 'blur' },
    {
      validator: (_rule: unknown, value: string, callback: (error?: Error) => void) => {
        const message = validateUsername(value)
        callback(message ? new Error(message) : undefined)
      },
      trigger: 'blur',
    },
  ],
  display_name: [
    { max: 50, message: '显示名最多50位', trigger: 'blur' },
  ],
  password: [
    { required: true, message: '请输入密码', trigger: 'blur' },
    {
      validator: (_rule: unknown, value: string, callback: (error?: Error) => void) => {
        const message = validatePassword(value)
        callback(message ? new Error(message) : undefined)
      },
      trigger: 'blur',
    },
  ],
  confirm: [
    { required: true, message: '请再次输入密码', trigger: 'blur' },
    {
      validator: (_rule: unknown, value: string, callback: (error?: Error) => void) => {
        if (value !== setupForm.password) {
          callback(new Error('两次输入的密码不一致'))
          return
        }
        callback()
      },
      trigger: 'blur',
    },
  ],
}

const error = ref('')
const loading = ref(false)
// v2.1.8 MFA 两步登录状态
const mfaStage = ref(false)
const mfaToken = ref('')
const mfaCode = ref('')
const mfaUseRecovery = ref(false)
// MFA 验证码输入：el-input-otp（6 位数字，validator 逐字符拦截非数字）；
// 恢复代码（6-16 位字母数字）走普通输入框
const mfaOtpRef = ref<InputOtpInstance>()
const isOtpDigitChar = (char: string): boolean => /^\d$/.test(char)

// OTP 自动聚焦：进入 MFA 步骤或从恢复代码切回验证码时（el-input-otp 无 autofocus
// 属性，expose 的 focus() 需在 nextTick 待其挂载后调用）
watch([mfaStage, mfaUseRecovery], async ([stage, useRecovery]) => {
  if (stage && !useRecovery) {
    await nextTick()
    mfaOtpRef.value?.focus()
  }
})

// 通道切换（验证码 ⇄ 恢复代码）即清空上一通道的输入与错误：
// 输错后输入框残留同一串错误码，用户回车会重复提交同一失败值。
watch(mfaUseRecovery, () => {
  mfaCode.value = ''
  error.value = ''
})

const resetToPasswordStep = () => {
  mfaStage.value = false
  mfaToken.value = ''
  mfaCode.value = ''
  mfaUseRecovery.value = false
  error.value = ''
}

const handleMfaVerify = async () => {
  if (loading.value || !mfaCode.value) return
  error.value = ''
  loading.value = true
  try {
    // 与 step-up/管理员重置同口径——归一化后仅提交首个 token，
    // 兼容整段粘贴恢复代码块（@input 已在恢复模式归一化，此处兜底）。
    const result = await authStore.verifyMfaLogin(mfaToken.value, normalizeMfaCodeInput(mfaCode.value))
    // store 重入护栏命中（请求未发出）——显式提示而非静默无事发生。
    if (result.skipped) error.value = '登录请求进行中，请稍候'
  } catch (caught: unknown) {
    // 失败即清空验证码（watch 已自动 refocus）：残留同一串错误码会让
    // 用户回车重复提交同一失败值。
    mfaCode.value = ''
    error.value = errorMessage(caught, '验证失败，请重试')
  } finally {
    loading.value = false
  }
}

const errorMessage = (caught: unknown, fallback: string): string => caught instanceof Error ? caught.message : fallback

// v2.3.0 OIDC 登录态
const oidcEnabled = ref(false)
const oidcDisplayName = ref('OIDC')
const showLocalForm = ref(false)
const oidcRedirecting = ref(false)
const oidcStatusError = ref('')
const oidcStatusLoading = ref(false)
const loadOidcStatus = async (): Promise<void> => {
  if (oidcStatusLoading.value) return
  oidcStatusLoading.value = true
  try {
    const res = await request.get<{ data?: { enabled?: boolean; display_name?: string } }>('/auth/oidc/status', { silent: true })
    oidcEnabled.value = res.data?.enabled === true
    if (oidcEnabled.value) oidcDisplayName.value = res.data?.display_name || 'OIDC'
    oidcStatusError.value = ''
  } catch (caught: unknown) {
    const status = caught instanceof ApiRequestError ? caught.status : undefined
    if (status === 403) {
      oidcEnabled.value = false
      oidcStatusError.value = ''
    } else {
      // 状态未知不等于未启用：纯 OIDC 账户必须看到故障与重试入口，
      // 本地表单仍保留给已有本地密码的账户使用。
      oidcStatusError.value = '无法获取企业登录状态，请重试或使用本地账号登录'
    }
  } finally {
    oidcStatusLoading.value = false
  }
}
onMounted(async () => {
  // oidc_error 通道由 App 的 hash 预处理单源消费（本预处理先于路由视图执行，
  // 已持有效会话、本组件不挂载的形态也能提示并从 hash 剥离）；回调失败不经
  // sessionStorage 传递——App 解析 hash 时当场提示，这两条读取通道随之删除。
  await loadOidcStatus()
})
let oidcRedirectTimer: ReturnType<typeof setTimeout> | null = null
const clearOidcRedirectTimer = (): void => {
  if (oidcRedirectTimer !== null) clearTimeout(oidcRedirectTimer)
  oidcRedirectTimer = null
}
const goOIDCLogin = () => {
  if (oidcRedirecting.value) return
  clearOidcRedirectTimer()
  oidcRedirecting.value = true
  // 顶层导航若被浏览器/扩展中止，pageshow 不会触发；十秒后恢复入口。
  oidcRedirectTimer = setTimeout(() => {
    oidcRedirecting.value = false
    oidcRedirectTimer = null
  }, 10_000)
  // 深链保持：登录前停留的页面键（首屏 ?page= 已由 auth store 消费进
  // currentPage）随 return_to 回跳；后端只放行站内相对路径，App 侧再按
  // isPageId 白名单兜底（未知值回 dashboard）。
  // 回跳来源绑定：nonce 先写本标签页 sessionStorage，再随 return_to 往返
  //（后端原样回显到回调 fragment）——App 侧只有命中同值才接受令牌，构造链接
  // 里塞别人的令牌不可能知道受害者浏览器的 nonce。
  const nonce = createOidcAppNonce()
  try {
    sessionStorage.setItem(OIDC_APP_NONCE_KEY, nonce)
  } catch { /* 隐私模式：无 nonce 时回调侧一律拒绝并提示重新登录 */ }
  const returnTo = encodeURIComponent(withOidcAppNonce(`/${authStore.currentPage}`, nonce))
  window.location.href = `/api/v1/auth/oidc/login?return_to=${returnTo}`
}
// IdP 侧「返回」经 bfcache 恢复时 JS 状态保留——复位跳转锁,防 SSO
// 按钮永久禁用(整页跳转本无重复提交面,disabled 仅作点击反馈)。
// 监听器与计时器随组件卸载清理(防登出-登录循环渐进累积)。
const onPageShow = (e: PageTransitionEvent) => {
  if (!e.persisted) return
  clearOidcRedirectTimer()
  oidcRedirecting.value = false
}
window.addEventListener('pageshow', onPageShow)
onUnmounted(() => {
  clearOidcRedirectTimer()
  window.removeEventListener('pageshow', onPageShow)
})

const handleLogin = async () => {
  if (loading.value) return
  if (!formRef.value) return

  await formRef.value.validate(async (valid) => {
    if (!valid || loading.value) return

    error.value = ''
    loading.value = true
    try {
      const result = await authStore.login(form.username, form.password)
      // 重入护栏命中时不再伪装成功——分流前先判 skipped。
      if (result.skipped) {
        error.value = '登录请求进行中，请稍候'
        return
      }
      if (result.mfaRequired && result.mfaToken) {
        mfaToken.value = result.mfaToken
        mfaStage.value = true
        mfaCode.value = ''
        return
      }
    } catch (caught: unknown) {
      error.value = errorMessage(caught, '登录失败，请稍后重试')
    } finally {
      loading.value = false
    }
  })
}

const handleSetup = async () => {
  if (loading.value) return
  if (!setupFormRef.value) return

  await setupFormRef.value.validate(async (valid) => {
    if (!valid || loading.value) return

    error.value = ''
    loading.value = true
    try {
      // silent 抑制全局拦截器 toast——403「已完成初始化」竞态时
      // 全局 toast 与 inline alert 双通道呈现同一文案；改为单通道 inline。
      await request.post('/auth/setup', {
        username: setupForm.username,
        password: setupForm.password,
        display_name: setupForm.display_name,
      }, { silent: true })
    } catch (caught: unknown) {
      // 403 = 提交期间系统已被另一路径初始化——复探状态并切换
      // 登录表单（后端文案即指引），而非停在 setup 表单要求手动刷新。
      if (caught instanceof ApiRequestError && caught.status === 403) {
        // 复探失败时回显可行动提示（原代码清空错误但注释称「仍呈现」，
        // 复探失败态下用户停留 setup 表单且无任何提示）；复探成功才切换登录表单。
        try {
          const res = await request.get<SetupStatusResponse>('/auth/setup', { silent: true })
          if (!res.data.needs_setup) setupMode.value = false
          error.value = ''
        } catch {
          error.value = '初始化状态确认失败，请重试或刷新页面'
        }
      } else {
        error.value = errorMessage(caught, '创建管理员失败，请稍后重试')
      }
      loading.value = false
      return
    }
    // 创建已成功：后续自动登录是独立阶段，其失败不得报成「创建管理员失败」
    // （管理员实际已创建，重填提交只会得到 403 并让用户重输密码）。
    setupMode.value = false
    try {
      const loginResult = await authStore.login(setupForm.username, setupForm.password)
      // 管理员已创建但登录被重入护栏跳过（防御路径）——切回登录表单提示手动登录。
      if (loginResult.skipped) error.value = '管理员已创建，请登录'
    } catch (caught: unknown) {
      error.value = `管理员已创建，请手动登录（自动登录失败：${errorMessage(caught, '请重试')}）`
    } finally {
      loading.value = false
    }
  })
}

onMounted(async () => {
  try {
    // silent：初始化探测失败由本组件自行提示，避免全局拦截器叠加一条重复 toast
    const res = await request.get<SetupStatusResponse>('/auth/setup', { silent: true })
    setupMode.value = res.data.needs_setup
  } catch (caught) {
    // 429 限流/网络异常时无法判定系统是否已初始化，静默降级为登录页会让
    // 未初始化系统的管理员误以为已有账号；此时保持登录表单但给出可见提示，
    // 仅 403/404（已有管理员语义）才无提示切换
    setupMode.value = false
    const status = caught instanceof ApiRequestError ? caught.status : undefined
    if (status !== 403 && status !== 404) {
      ElMessage.error('无法确认初始化状态，请稍后刷新')
    }
  } finally {
    checkingSetup.value = false
  }
})
</script>

<style scoped>
.login-container {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #f0f4f8 0%, #e2e8f0 100%);
  padding: 20px;
}

.login-card {
  width: 100%;
  max-width: 400px;
  border-radius: 12px;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
}

.login-header {
  text-align: center;
  margin-bottom: 28px;
}

/* 直角标识：外层半径会把 SVG 方块的四角裁圆，必须与 AppLogo 的 rx=0 同口径。 */
.logo-wrapper {
  width: 64px;
  height: 64px;
  margin: 0 auto 16px;
  border-radius: 0;
  overflow: hidden;
  box-shadow: 0 4px 12px rgba(59, 130, 246, 0.25);
}

.login-title {
  font-size: 22px;
  font-weight: 600;
  color: #111827;
  margin: 0 0 6px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
}


.login-subtitle {
  font-size: 14px;
  color: #6b7280;
  margin: 0;
}

.login-error {
  margin-bottom: 16px;
}

.login-btn {
  width: 100%;
  height: 42px;
  font-size: 15px;
  font-weight: 500;
}


/* v2.3.0 OIDC 品牌主按钮 */
.oidc-login { text-align: center; }
.oidc-sso-btn {
  width: 100%;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 4px;
  padding: 14px 18px;
  border: none;
  border-radius: 10px;
  cursor: pointer;
  background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
  box-shadow: 0 4px 14px rgba(37, 99, 235, 0.28);
  color: #fff;
  transition: transform .15s ease, box-shadow .15s ease;
}
.oidc-sso-btn:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 6px 18px rgba(37, 99, 235, 0.36); }
.oidc-sso-btn:active:not(:disabled) { transform: translateY(0); }
.oidc-sso-btn:disabled { opacity: .75; cursor: default; }


.oidc-sso-title { font-size: 15px; font-weight: 600; letter-spacing: .3px; }
.oidc-sso-sub { font-size: 11.5px; opacity: .82; }

.login-alt-divider {
  display: flex; align-items: center; gap: 12px;
  margin: 20px 0 6px;
  color: #9ca3af; font-size: 12.5px;
}
.login-alt-divider::before, .login-alt-divider::after {
  content: ''; flex: 1; height: 1px; background: #e5e7eb;
}
.local-toggle { margin-top: 6px; color: #4b5563; font-weight: 500; }
.back-to-oidc { margin-top: 14px; text-align: center; }

.login-footer {
  text-align: center;
  margin-top: 20px;
  padding-top: 16px;
  border-top: 1px solid #e5e7eb;
}

.version {
  font-size: 12px;
  color: #9ca3af;
}

.mfa-step-title {
  text-align: center;
  font-size: 16px;
  font-weight: 600;
  margin-bottom: 20px;
  color: var(--el-text-color-primary);
}
/* OTP 输入框在表单项内居中：el-form-item__content 为 flex 容器，组件根（inline-flex）
   作为 flex 项宽度收缩为内容宽——flex:1 撑满整行后 justify-content 才有居中空间 */
.mfa-otp {
  display: flex;
  flex: 1 1 auto;
  min-width: 0;
  justify-content: center;
}
.mfa-switch {
  display: flex;
  justify-content: space-between;
  padding: 0 2px;
}
</style>
