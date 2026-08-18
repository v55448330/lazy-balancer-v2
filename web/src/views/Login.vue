<template>
  <div class="login-container">
    <el-card class="login-card">
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
          <el-alert title="首次启动，请创建管理员账号" type="info" show-icon :closable="false" class="login-error" />
          <el-form-item prop="username">
            <el-input v-model="setupForm.username" placeholder="管理员用户名" size="large" :prefix-icon="User" maxlength="50" clearable />
          </el-form-item>
          <el-form-item prop="display_name">
            <el-input v-model="setupForm.display_name" placeholder="显示名（选填）" size="large" :prefix-icon="Postcard" maxlength="50" clearable />
          </el-form-item>
          <el-form-item prop="password">
            <el-input v-model="setupForm.password" type="password" placeholder="密码（至少 6 位）" size="large" :prefix-icon="Lock" maxlength="72" show-password />
          </el-form-item>
          <el-form-item prop="confirm">
            <el-input v-model="setupForm.confirm" type="password" placeholder="确认密码" size="large" :prefix-icon="Lock" maxlength="72" show-password />
          </el-form-item>
          <el-alert v-if="error" :title="error" type="error" show-icon :closable="false" class="login-error" />
          <el-form-item>
            <el-button type="primary" native-type="submit" :loading="loading" size="large" class="login-btn">
              {{ loading ? '创建中...' : '创建管理员并登录' }}
            </el-button>
          </el-form-item>
        </el-form>

        <el-form v-else ref="formRef" :model="form" :rules="rules" @submit.prevent="handleLogin" class="login-form">
          <el-form-item prop="username">
            <el-input
              v-model="form.username"
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
      </template>

      <div class="login-footer">
        <span class="version">版本 {{ appVersion }}</span>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { useAuthStore } from '@/stores/auth'
import { ApiRequestError, request } from '@/utils/api'
import { User, Lock, Postcard } from '@element-plus/icons-vue'
import AppLogo from '@/components/AppLogo.vue'
import { appName, appVersion } from '@/utils/branding'
import type { FormInstance, FormRules } from 'element-plus'

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
    { min: 6, message: '密码至少6位', trigger: 'blur' },
  ],
}

const setupRules: FormRules = {
  username: [
    { required: true, message: '请输入管理员用户名', trigger: 'blur' },
    { min: 3, message: '用户名至少3位', trigger: 'blur' },
    { max: 50, message: '用户名最多50位', trigger: 'blur' },
  ],
  display_name: [
    { max: 50, message: '显示名最多50位', trigger: 'blur' },
  ],
  password: [
    { required: true, message: '请输入密码', trigger: 'blur' },
    { min: 6, message: '密码至少6位', trigger: 'blur' },
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

const errorMessage = (caught: unknown, fallback: string): string => caught instanceof Error ? caught.message : fallback

const handleLogin = async () => {
  if (loading.value) return
  if (!formRef.value) return

  await formRef.value.validate(async (valid) => {
    if (!valid || loading.value) return

    error.value = ''
    loading.value = true
    try {
      await authStore.login(form.username, form.password)
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
      await request.post('/auth/setup', {
        username: setupForm.username,
        password: setupForm.password,
        display_name: setupForm.display_name,
      })
      await authStore.login(setupForm.username, setupForm.password)
    } catch (caught: unknown) {
      error.value = errorMessage(caught, '创建管理员失败，请稍后重试')
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

.logo-wrapper {
  width: 64px;
  height: 64px;
  margin: 0 auto 16px;
  border-radius: 14px;
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

.v2-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 10px;
  font-weight: 700;
  color: white;
  background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
  padding: 2px 6px;
  border-radius: 3px;
  letter-spacing: 0.5px;
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
</style>
