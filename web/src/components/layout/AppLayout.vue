<template>
  <el-container class="layout-container">
    <el-aside :width="effectiveCollapsed ? '64px' : '220px'" class="layout-aside">
      <div class="aside-header">
        <div class="logo-area" role="button" tabindex="0" aria-label="切换侧边栏" @click="collapsed = !collapsed" @keydown.enter.prevent="collapsed = !collapsed" @keydown.space.prevent="collapsed = !collapsed">
          <AppLogo :size="28" />
          <transition name="fade">
            <span v-if="!effectiveCollapsed" class="logo-text">
              {{ appName }} <span class="v2-badge">V2</span>
            </span>
          </transition>
        </div>
      </div>

      <el-menu
        :default-active="currentPage"
        class="layout-menu"
        :collapse="effectiveCollapsed"
        :collapse-transition="false"
        background-color="#ffffff"
        text-color="#6b7280"
        active-text-color="#3b82f6"
        border-right="none"
      >
        <el-menu-item index="dashboard" @click="goPage('dashboard')">
          <el-icon><DataAnalysis /></el-icon>
          <template #title>仪表盘</template>
        </el-menu-item>
        <el-menu-item index="rules" @click="goPage('rules')">
          <el-icon><List /></el-icon>
          <template #title>负载均衡</template>
        </el-menu-item>
        <el-sub-menu index="security">
          <template #title>
            <el-icon><Lock /></el-icon>
            <span>安全防护</span>
          </template>
          <el-menu-item index="security-overview" @click="goPage('security-overview')">
            <el-icon><DataAnalysis /></el-icon>
            <template #title>安全总览</template>
          </el-menu-item>
          <el-menu-item index="security-policies" @click="goPage('security-policies')">
            <el-icon><Lock /></el-icon>
            <template #title>安全策略</template>
          </el-menu-item>
          <el-menu-item index="security-rules" @click="goPage('security-rules')">
            <el-icon><Notebook /></el-icon>
            <template #title>规则集</template>
          </el-menu-item>
          <el-menu-item index="security-block-pages" @click="goPage('security-block-pages')">
            <el-icon><Document /></el-icon>
            <template #title>拦截页面</template>
          </el-menu-item>
          <el-menu-item index="security-events" @click="goPage('security-events')">
            <el-icon><Warning /></el-icon>
            <template #title>事件日志</template>
          </el-menu-item>
        </el-sub-menu>
        <el-menu-item index="caddy" @click="goPage('caddy')">
          <el-icon><Cpu /></el-icon>
          <template #title>配置预览</template>
        </el-menu-item>
        <el-sub-menu index="settings">
          <template #title>
            <el-icon><Setting /></el-icon>
            <span>系统设置</span>
          </template>
          <el-menu-item index="settings-basic" @click="goPage('settings-basic')">
            <el-icon><Setting /></el-icon>
            <template #title>基础设置</template>
          </el-menu-item>
          <el-menu-item index="settings-cluster" @click="goPage('settings-cluster')">
            <el-icon><Connection /></el-icon>
            <template #title>集群管理</template>
          </el-menu-item>
          <el-menu-item index="settings-certificates" @click="goPage('settings-certificates')">
            <el-icon><Lock /></el-icon>
            <template #title>免费证书</template>
          </el-menu-item>
          <el-menu-item index="settings-apikeys" @click="goPage('settings-apikeys')">
            <el-icon><Key /></el-icon>
            <template #title>API 密钥</template>
          </el-menu-item>
          <el-menu-item index="users" @click="goPage('users')">
            <el-icon><User /></el-icon>
            <template #title>用户管理</template>
          </el-menu-item>
        </el-sub-menu>
        <el-menu-item index="audit-log" @click="goPage('audit-log')">
          <el-icon><Document /></el-icon>
          <template #title>操作日志</template>
        </el-menu-item>
      </el-menu>

      <div class="aside-footer">
        <el-dropdown trigger="click" @command="handleCommand">
          <div class="user-info">
            <el-avatar :size="36" class="user-avatar">
              <el-icon><User /></el-icon>
            </el-avatar>
            <transition name="fade">
              <div v-if="!effectiveCollapsed" class="user-detail">
                <div class="user-name">{{ menuDisplayName }}</div>
                <div v-if="hasCustomDisplayName" class="user-role">{{ authStore.user?.username || '-' }}</div>
              </div>
            </transition>
          </div>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="profile">个人资料</el-dropdown-item>
              <el-dropdown-item command="logout" divided>退出登录</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </div>
    </el-aside>

    <el-container class="main-container">
      <el-header class="layout-header">
        <div class="header-left">
          <el-breadcrumb separator="/">
            <el-breadcrumb-item>{{ appName }}</el-breadcrumb-item>
            <el-breadcrumb-item>{{ pageTitle[currentPage] || '仪表盘' }}</el-breadcrumb-item>
          </el-breadcrumb>
        </div>
        <div class="header-right">
          <el-tooltip v-if="authStore.readOnlyReason" :content="authStore.readOnlyMessage" placement="bottom">
            <el-tag type="warning" size="small" effect="plain" class="readonly-tag">只读</el-tag>
          </el-tooltip>
          <div class="node-tag" :class="authStore.nodeMode">
            <el-icon><Connection /></el-icon>
            <span>{{ authStore.nodeMode === 'master' ? '主节点' : '从节点' }}</span>
          </div>
        </div>
      </el-header>

      <el-alert
        v-if="configDrift && authStore.nodeMode === 'master'"
        type="error"
        :closable="false"
        class="config-drift-banner"
      >
        <template #title>
          <span class="drift-text">运行配置与规则数据不一致：{{ configDrift }}</span>
          <el-button v-if="authStore.readOnlyReason === null" size="small" type="danger" plain :loading="restarting" @click="handleRestartForDrift">重启服务恢复</el-button>
        </template>
      </el-alert>

      <el-main class="layout-main">
        <slot />
      </el-main>
      <el-footer class="layout-footer">
        <span class="footer-text" v-html="footerHtml"></span>
      </el-footer>
    </el-container>

    <el-dialog v-model="showProfile" title="个人资料" width="min(480px, 92vw)" :close-on-click-modal="false" :before-close="beforeProfileClose">
      <el-alert v-if="isReadOnly" :title="authStore.readOnlyMessage" type="info" :closable="false" show-icon class="profile-readonly-alert" />
      <el-form :model="profileForm" label-width="80px" class="profile-form" :disabled="saving">
        <el-form-item label="用户名">
          <el-input v-model="profileForm.username" disabled />
        </el-form-item>
        <el-form-item label="显示名">
          <el-input v-model="profileForm.display_name" :disabled="isReadOnly" placeholder="选填" maxlength="50" />
        </el-form-item>
        <el-form-item label="新密码">
          <el-input v-model="profileForm.password" :disabled="isReadOnly" type="password" minlength="6" maxlength="72" placeholder="如不修改请留空（至少6位）" show-password />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button :disabled="saving" @click="closeProfile">取消</el-button>
        <el-button type="primary" :loading="saving" :disabled="isReadOnly || saving" @click="saveProfile">保存</el-button>
      </template>
    </el-dialog>
  </el-container>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useMediaQuery } from '@vueuse/core'
import { useAuthStore } from '@/stores/auth'
import type { PageId } from '@/stores/auth'
import { request, mfaAwareSuccess } from '@/utils/api'
import { ElMessageBox } from 'element-plus'
import { DataAnalysis, List, Setting, Cpu, User, Connection, Lock, Key, Document, Warning, Notebook } from '@element-plus/icons-vue'
import AppLogo from '@/components/AppLogo.vue'
import { appName, footerHtml } from '@/utils/branding'
import { reloadAfterRestart } from '@/utils/restart'

const authStore = useAuthStore()
const collapsed = ref(false)
const isNarrowViewport = useMediaQuery('(max-width: 768px)')
const effectiveCollapsed = computed(() => collapsed.value || isNarrowViewport.value)
const showProfile = ref(false)
const saving = ref(false)
const loggingOut = ref(false)

const currentPage = computed(() => authStore.currentPage)
const isReadOnly = computed(() => authStore.readOnlyReason === 'slave')
const menuDisplayName = computed(() => authStore.user?.display_name || authStore.user?.username || '用户')
const hasCustomDisplayName = computed(() => {
  const displayName = authStore.user?.display_name || ''
  return displayName !== '' && displayName !== authStore.user?.username
})

const pageTitle: Record<string, string> = {
  dashboard: '仪表盘',
  rules: '负载均衡',
  caddy: '配置预览',
  users: '系统设置 / 用户管理',
  'audit-log': '操作日志',
  'settings-basic': '系统设置 / 基础设置',
  'settings-cluster': '系统设置 / 集群管理',
  'settings-certificates': '系统设置 / 免费证书',
  'settings-apikeys': '系统设置 / API 密钥',
  'security-overview': '安全防护 / 安全总览',
  'security-policies': '安全防护 / 安全策略',
  'security-rules': '安全防护 / 规则集',
  'security-block-pages': '安全防护 / 拦截页面',
  'security-events': '安全防护 / 事件日志',
}

const profileForm = ref({
  username: '',
  display_name: '',
  password: '',
})

const syncProfileForm = () => {
  profileForm.value = {
    username: authStore.user?.username || '',
    display_name: authStore.user?.display_name || '',
    password: '',
  }
}

const goPage = (page: PageId) => {
  authStore.setCurrentPage(page)
}

const logout = async (): Promise<void> => {
  if (loggingOut.value) return
  loggingOut.value = true
  try {
    await authStore.logout()
  } finally {
    loggingOut.value = false
  }
}

const handleCommand = async (command: string): Promise<void> => {
  if (command === 'profile') {
    if (saving.value) return
    syncProfileForm()
    showProfile.value = true
  } else if (command === 'logout') {
    await logout()
  }
}

const beforeProfileClose = (done: () => void): void => {
  if (!saving.value) done()
}

const closeProfile = (): void => {
  if (!saving.value) showProfile.value = false
}

const saveProfile = async () => {
  if (isReadOnly.value || saving.value) return
  if (profileForm.value.password && profileForm.value.password.length < 6) {
    authStore.showToast('warning', '密码长度至少6位')
    return
  }
  saving.value = true
  const passwordChanged = Boolean(profileForm.value.password)
  try {
    await request.patch('/users/me', {
      display_name: profileForm.value.display_name,
      ...(profileForm.value.password && { password: profileForm.value.password }),
    })
    showProfile.value = false
    if (passwordChanged) {
      authStore.showToast('success', '密码已修改，请重新登录')
      await logout()
    } else {
      mfaAwareSuccess('保存成功')
      await authStore.fetchUser()
    }
  } catch (error: unknown) {
    // Error toast is already shown by the global axios interceptor.
    console.error('Failed to save profile:', error)
  } finally {
    saving.value = false
  }
}

// 配置一致性看门狗横幅：轮询 /caddy/status，漂移时展示并给出重启恢复入口。
const configDrift = ref('')
const restarting = ref(false)
let driftTimer: number | undefined
let disposed = false

const fetchDriftStatus = async () => {
  try {
    const res = await request.get('/caddy/status', { silent: true })
    configDrift.value = res.data?.config_consistent === 'false' ? (res.data?.config_drift || '规则路由与运行配置不一致') : ''
  } catch {
    // 状态查询失败静默——网络层错误已有全局处理
  }
}

const handleRestartForDrift = async () => {
  try {
    await ElMessageBox.confirm(
      '将重启服务以重新应用全部规则配置，期间服务短暂不可用。确认重启？',
      '重启服务恢复',
      { confirmButtonText: '确认重启', cancelButtonText: '取消', type: 'warning' },
    )
  } catch {
    return
  }
  restarting.value = true
  try {
    await request.post('/system/restart')
  } catch {
    // 重启请求失败（全局拦截器已提示），复位按钮允许重试
    restarting.value = false
    return
  }
  mfaAwareSuccess('服务正在重启，就绪后自动刷新页面')
  // 保持 restarting=true 直到 reload（防就绪等待窗口内二次点击）；超时或失败才复位
  const reloaded = await reloadAfterRestart(() => disposed)
  if (!reloaded) restarting.value = false
}

onMounted(() => {
  syncProfileForm()
  fetchDriftStatus()
  driftTimer = window.setInterval(fetchDriftStatus, 60000)
})

onUnmounted(() => {
  disposed = true
  if (driftTimer) clearInterval(driftTimer)
})
</script>

<style scoped>
.layout-container { height: 100vh; }

.config-drift-banner {
  border-radius: 0;
}
.config-drift-banner .drift-text {
  margin-right: 12px;
  font-weight: 500;
}

.layout-aside {
  background: #ffffff;
  border-right: 1px solid #e5e7eb;
  display: flex;
  flex-direction: column;
  transition: width 0.2s;
}

.aside-header {
  padding: 16px;
  border-bottom: 1px solid #f3f4f6;
}

.logo-area {
  display: flex;
  align-items: center;
  gap: 12px;
  cursor: pointer;
}

.logo-text {
  font-size: 16px;
  font-weight: 600;
  color: #111827;
  white-space: nowrap;
  display: flex;
  align-items: center;
  gap: 6px;
}

.v2-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 10px;
  font-weight: 700;
  color: white;
  background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
  padding: 2px 5px;
  border-radius: 3px;
  letter-spacing: 0.5px;
}

.layout-menu {
  border-right: none;
  flex: 1;
}

.layout-menu :deep(.el-menu),
.layout-menu :deep(.el-sub-menu) {
  border: none !important;
}

.layout-menu :deep(.el-menu-item),
.layout-menu :deep(.el-sub-menu__title) {
  height: 44px;
  line-height: 44px;
  margin: 4px 8px;
  border-radius: 6px;
  padding-right: 16px !important;
}

.layout-menu :deep(.el-menu-item .el-icon),
.layout-menu :deep(.el-sub-menu__title .el-icon) {
  margin-right: 10px;
  font-size: 18px;
  width: 18px;
  text-align: center;
}

.layout-menu :deep(.el-sub-menu__title) {
  display: flex;
  align-items: center;
}

.layout-menu :deep(.el-sub-menu__icon-arrow) {
  position: static;
  margin-left: auto;
  margin-top: 0;
  transform: none;
}

.layout-menu :deep(.el-menu-item.is-active) {
  background: #eff6ff !important;
  color: #3b82f6;
}

.layout-menu :deep(.el-menu-item:hover),
.layout-menu :deep(.el-sub-menu__title:hover) {
  background: #f9fafb;
}

.layout-menu :deep(.el-sub-menu.is-active .el-sub-menu__title) {
  color: #3b82f6;
}

.layout-menu :deep(.el-sub-menu .el-menu) {
  background-color: transparent !important;
  padding: 0 !important;
  margin: 0 !important;
  border: none !important;
}

.layout-menu :deep(.el-sub-menu .el-menu-item) {
  height: 40px;
  line-height: 40px;
  margin: 4px 8px;
  border-radius: 6px;
  min-width: 0;
}

.layout-menu :deep(.el-sub-menu .el-menu-item .el-icon) {
  margin-right: 8px;
  font-size: 17px;
  width: 17px;
}

.layout-menu :deep(.el-sub-menu.is-opened) {
  margin-bottom: 0 !important;
}

.layout-menu :deep(.el-sub-menu__title + .el-menu) {
  margin-top: 0 !important;
  padding-top: 0 !important;
}

.layout-menu :deep(.el-sub-menu) {
  margin-top: 4px !important;
  margin-bottom: 4px !important;
}

.layout-menu :deep(.el-sub-menu.is-opened) {
  margin-bottom: 4px !important;
}

.layout-menu :deep(.el-sub-menu .el-menu-item) {
  margin-top: 4px !important;
}

.layout-menu :deep(.el-sub-menu .el-menu-item:first-child) {
  margin-top: 0 !important;
}

.aside-footer {
  padding: 0;
  border-top: 1px solid #f3f4f6;
}

.aside-footer :deep(.el-dropdown) {
  display: block;
  width: 100%;
}

.aside-footer :deep(.el-dropdown .el-dropdown__caret-button),
.aside-footer :deep(.el-dropdown > span),
.aside-footer :deep(.el-dropdown > div) {
  width: 100%;
}

.user-info {
  display: flex;
  align-items: center;
  gap: 10px;
  width: 100%;
  box-sizing: border-box;
  padding: 12px 16px;
  border-radius: 0;
  cursor: pointer;
  transition: background-color 0.2s;
}

.user-info:hover {
  background: #f9fafb;
}

.user-avatar {
  background: #eff6ff;
  color: #3b82f6;
  flex-shrink: 0;
}

.user-detail { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 2px; }

.user-name {
  font-size: 14px;
  font-weight: 500;
  color: #111827;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  line-height: 1.3;
}

.user-role {
  font-size: 12px;
  color: #9ca3af;
  line-height: 1.3;
  margin-top: 0;
}

.main-container { background: #f3f4f6; }

.layout-header {
  background: #ffffff;
  border-bottom: 1px solid #e5e7eb;
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0 24px;
}

.header-left { flex: 1; }

.header-right { display: flex; align-items: center; gap: 12px; }
.readonly-tag { cursor: default; }

.node-tag {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 6px 14px;
  border-radius: 8px;
  font-size: 13px;
  font-weight: 500;
  border: 1px solid transparent;
}

.node-tag.master {
  background: #ecfdf5;
  color: #047857;
  border-color: #a7f3d0;
}

.node-tag.slave {
  background: #fffbeb;
  color: #b45309;
  border-color: #fed7aa;
}

.node-tag .el-icon {
  font-size: 14px;
}

.layout-main {
  padding: 20px;
  overflow-y: auto;
}

.layout-footer {
  height: 44px;
  line-height: 44px;
  text-align: center;
  font-size: 13px;
  font-weight: 500;
  color: var(--el-text-color-regular);
  letter-spacing: 0.2px;
  flex-shrink: 0;
  background-color: #ffffff;
}

.footer-text :deep(.footer-link) {
  color: var(--el-color-primary);
  text-decoration: none;
}
.footer-text :deep(.footer-link:hover) {
  text-decoration: underline;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.2s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

.profile-form { padding: 0 20px; }
.profile-readonly-alert { margin-bottom: 20px; }
</style>
