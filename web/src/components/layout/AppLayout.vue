<template>
  <el-container class="layout-container">
    <el-aside :width="collapsed ? '64px' : '220px'" class="layout-aside">
      <div class="aside-header">
        <div class="logo-area" @click="collapsed = !collapsed">
          <div class="logo-icon">
            <el-icon :size="24"><Monitor /></el-icon>
          </div>
          <transition name="fade">
            <span v-if="!collapsed" class="logo-text">
              Lazy Balancer <span class="v2-badge">V2</span>
            </span>
          </transition>
        </div>
      </div>

      <el-menu
        :default-active="currentPage"
        class="layout-menu"
        :collapse="collapsed"
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
        <el-menu-item index="caddy" @click="goPage('caddy')">
          <el-icon><Cpu /></el-icon>
          <template #title>全局配置</template>
        </el-menu-item>
        <el-menu-item v-if="authStore.user?.role === 'admin'" index="users" @click="goPage('users')">
          <el-icon><User /></el-icon>
          <template #title>用户管理</template>
        </el-menu-item>
        <el-menu-item index="settings" @click="goPage('settings')">
          <el-icon><Setting /></el-icon>
          <template #title>系统设置</template>
        </el-menu-item>
      </el-menu>

      <div class="aside-footer">
        <el-dropdown trigger="click" @command="handleCommand">
          <div class="user-info">
            <el-avatar :size="36" class="user-avatar">
              <el-icon><User /></el-icon>
            </el-avatar>
            <transition name="fade">
              <div v-if="!collapsed" class="user-detail">
                <div class="user-name">{{ authStore.displayName || '用户' }}</div>
                <div class="user-role">{{ authStore.userRole }}</div>
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
            <el-breadcrumb-item>Lazy Balancer</el-breadcrumb-item>
            <el-breadcrumb-item>{{ pageTitle[currentPage] || '仪表盘' }}</el-breadcrumb-item>
          </el-breadcrumb>
        </div>
        <div class="header-right">
          <div class="node-tag" :class="authStore.nodeMode">
            <el-icon><Connection /></el-icon>
            <span>{{ authStore.nodeMode === 'master' ? '主节点' : '从节点' }}</span>
          </div>
        </div>
      </el-header>

      <el-main class="layout-main">
        <slot />
      </el-main>
    </el-container>

    <el-dialog v-model="showProfile" title="个人资料" width="480px" :close-on-click-modal="false">
      <el-form :model="profileForm" label-width="80px" class="profile-form">
        <el-form-item label="用户名">
          <el-input v-model="profileForm.username" disabled />
        </el-form-item>
        <el-form-item label="显示名">
          <el-input v-model="profileForm.display_name" placeholder="选填" />
        </el-form-item>
        <el-form-item label="新密码">
          <el-input v-model="profileForm.password" type="password" placeholder="如不修改请留空" show-password />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showProfile = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveProfile">保存</el-button>
      </template>
    </el-dialog>
  </el-container>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { request } from '@/utils/api'
import { Monitor, DataAnalysis, List, Setting, Cpu, User } from '@element-plus/icons-vue'

const authStore = useAuthStore()
const collapsed = ref(false)
const showProfile = ref(false)
const saving = ref(false)

const currentPage = computed(() => authStore.currentPage)

const pageTitle: Record<string, string> = {
  dashboard: '仪表盘',
  rules: '负载均衡',
  caddy: '全局配置',
  users: '用户管理',
  settings: '系统设置',
}

const profileForm = ref({
  username: '',
  display_name: '',
  password: '',
})

const goPage = (page: string) => {
  authStore.setCurrentPage(page)
}

const handleCommand = (command: string) => {
  if (command === 'profile') {
    showProfile.value = true
  } else if (command === 'logout') {
    authStore.logout()
  }
}

const saveProfile = async () => {
  saving.value = true
  try {
    await request.put('/users/me', {
      display_name: profileForm.value.display_name,
      ...(profileForm.value.password && { password: profileForm.value.password }),
    })
    authStore.showToast('success', '保存成功')
    showProfile.value = false
    await authStore.fetchUser()
  } finally {
    saving.value = false
  }
}

onMounted(() => {
  profileForm.value = {
    username: authStore.user?.username || '',
    display_name: authStore.user?.display_name || '',
    password: '',
  }
})
</script>

<style scoped>
.layout-container { height: 100vh; }

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

.logo-icon {
  width: 36px;
  height: 36px;
  background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  flex-shrink: 0;
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

.layout-menu :deep(.el-menu-item) {
  height: 44px;
  line-height: 44px;
  margin: 4px 8px;
  border-radius: 6px;
}

.layout-menu :deep(.el-menu-item.is-active) {
  background: #eff6ff !important;
  color: #3b82f6;
}

.layout-menu :deep(.el-menu-item:hover) {
  background: #f9fafb;
}

.aside-footer {
  padding: 12px;
  border-top: 1px solid #f3f4f6;
}

.user-info {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px;
  border-radius: 8px;
  cursor: pointer;
}

.user-info:hover {
  background: #f9fafb;
}

.user-avatar {
  background: #eff6ff;
  color: #3b82f6;
  flex-shrink: 0;
}

.user-detail { flex: 1; min-width: 0; }

.user-name {
  font-size: 14px;
  font-weight: 500;
  color: #111827;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  line-height: 1.5;
}

.user-role {
  font-size: 12px;
  color: #9ca3af;
  line-height: 1.5;
  margin-top: 6px;
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

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.2s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

.profile-form { padding: 0 20px; }
</style>