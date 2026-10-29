<template>
  <el-container class="layout-container">
    <!-- 窄屏展开为浮层：遮罩承接「点空白收起」（纯视觉层，对读屏隐藏） -->
    <div v-if="sidebarOverlayVisible" class="sidebar-backdrop" aria-hidden="true" @click="closeNarrowSidebar" />
    <el-aside :width="sidebarWidth(effectiveCollapsed)" class="layout-aside" :class="{ 'is-overlay': sidebarOverlayVisible }">
      <div class="aside-header">
        <!-- 折叠入口的展开状态必须对读屏可见：折叠只由宽度表达，此前读屏无从得知
             （aria-expanded + aria-controls 指向被折叠的导航）。长按 Enter/Space
             经 activateOnce 去重，否则按系统重复率反复切换。 -->
        <div class="logo-area" role="button" tabindex="0" aria-label="切换侧边栏" :aria-expanded="!effectiveCollapsed" aria-controls="app-sidebar-nav" @click="toggleSidebar" @keydown.enter.prevent="activateOnce($event, toggleSidebar)" @keydown.space.prevent="activateOnce($event, toggleSidebar)">
          <AppLogo :size="28" />
          <transition name="fade">
            <span v-if="!effectiveCollapsed" class="logo-text">
              {{ appName }} <span class="v2-badge">V2</span>
            </span>
          </transition>
        </div>
      </div>

      <el-menu
        id="app-sidebar-nav"
        :default-active="currentPage"
        class="layout-menu"
        :collapse="effectiveCollapsed"
        :collapse-transition="false"
        background-color="#ffffff"
        text-color="#6b7280"
        active-text-color="#3b82f6"
      >
        <el-menu-item index="dashboard" @click="goPage('dashboard')">
          <el-icon><DataAnalysis /></el-icon>
          <template #title>{{ NAV_LABELS.dashboard }}</template>
        </el-menu-item>
        <el-menu-item index="rules" @click="goPage('rules')">
          <el-icon><List /></el-icon>
          <template #title>{{ NAV_LABELS.rules }}</template>
        </el-menu-item>
        <el-sub-menu index="security">
          <template #title>
            <el-icon><Lock /></el-icon>
            <span>{{ SECURITY_PARENT }}</span>
          </template>
          <el-menu-item index="security-overview" @click="goPage('security-overview')">
            <el-icon><DataAnalysis /></el-icon>
            <template #title>{{ NAV_LABELS['security-overview'] }}</template>
          </el-menu-item>
          <el-menu-item index="security-policies" @click="goPage('security-policies')">
            <el-icon><Lock /></el-icon>
            <template #title>{{ NAV_LABELS['security-policies'] }}</template>
          </el-menu-item>
          <el-menu-item index="security-rules" @click="goPage('security-rules')">
            <el-icon><Notebook /></el-icon>
            <template #title>{{ NAV_LABELS['security-rules'] }}</template>
          </el-menu-item>
          <el-menu-item index="security-block-pages" @click="goPage('security-block-pages')">
            <el-icon><Document /></el-icon>
            <template #title>{{ NAV_LABELS['security-block-pages'] }}</template>
          </el-menu-item>
          <el-menu-item index="security-events" @click="goPage('security-events')">
            <el-icon><Warning /></el-icon>
            <template #title>{{ NAV_LABELS['security-events'] }}</template>
          </el-menu-item>
        </el-sub-menu>
        <el-menu-item index="caddy" @click="goPage('caddy')">
          <el-icon><Cpu /></el-icon>
          <template #title>{{ NAV_LABELS.caddy }}</template>
        </el-menu-item>
        <el-sub-menu index="settings">
          <template #title>
            <el-icon><Setting /></el-icon>
            <span>{{ SETTINGS_BREADCRUMB_PARENT }}</span>
          </template>
          <el-menu-item index="settings-basic" @click="goPage('settings-basic')">
            <el-icon><Setting /></el-icon>
            <template #title>{{ NAV_LABELS['settings-basic'] }}</template>
          </el-menu-item>
          <el-menu-item index="settings-cluster" @click="goPage('settings-cluster')">
            <el-icon><Connection /></el-icon>
            <template #title>{{ NAV_LABELS['settings-cluster'] }}</template>
          </el-menu-item>
          <el-menu-item index="settings-certificates" @click="goPage('settings-certificates')">
            <el-icon><Lock /></el-icon>
            <template #title>{{ NAV_LABELS['settings-certificates'] }}</template>
          </el-menu-item>
          <el-menu-item index="settings-apikeys" @click="goPage('settings-apikeys')">
            <el-icon><Key /></el-icon>
            <template #title>{{ NAV_LABELS['settings-apikeys'] }}</template>
          </el-menu-item>
          <el-menu-item index="settings-tasks" @click="goPage('settings-tasks')">
            <el-icon><Timer /></el-icon>
            <template #title>{{ NAV_LABELS['settings-tasks'] }}</template>
          </el-menu-item>
          <el-menu-item index="users" @click="goPage('users')">
            <el-icon><User /></el-icon>
            <template #title>{{ NAV_LABELS.users }}</template>
          </el-menu-item>
        </el-sub-menu>
        <el-menu-item index="audit-log" @click="goPage('audit-log')">
          <el-icon><Document /></el-icon>
          <template #title>{{ NAV_LABELS['audit-log'] }}</template>
        </el-menu-item>
      </el-menu>

      <div class="aside-footer">
        <el-dropdown trigger="click" @command="handleCommand">
          <div class="user-info" :class="{ 'is-collapsed': effectiveCollapsed }" :aria-label="accountTriggerLabel(menuDisplayName)" :title="accountTriggerLabel(menuDisplayName)">
            <!-- 折叠态必须有可见标识与无障碍名称：此前只剩 24px 无内容条带，
                 而「退出登录」只存在于本下拉里（窄屏等于没有可发现的退出入口） -->
            <span v-if="effectiveCollapsed" class="user-avatar" aria-hidden="true">{{ accountInitial(menuDisplayName) }}</span>
            <transition name="fade">
              <div v-if="!effectiveCollapsed" class="user-detail">
                <div class="user-name">
                  <span class="user-name-text">{{ menuDisplayName }}</span>
                  <!-- v2.3.0:来源标签——与用户列表列同款(warning/OIDC、info/本地);
                       flex 同行居中,缩放用字号而非 transform(避免基线漂移) -->
                  <el-tag :type="isOIDCUser ? 'warning' : 'info'" size="small" effect="plain" class="user-source-tag">{{ isOIDCUser ? 'OIDC' : '本地' }}</el-tag>
                </div>
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
            <el-breadcrumb-item>{{ hasOwn(pageTitle, currentPage) ? pageTitle[currentPage] : '仪表盘' }}</el-breadcrumb-item>
          </el-breadcrumb>
        </div>
        <div class="header-right">
          <el-tooltip v-if="authStore.readOnlyReason" :content="authStore.readOnlyMessage" placement="bottom">
            <el-tag type="warning" size="small" effect="plain" class="readonly-tag">只读</el-tag>
          </el-tooltip>
          <div class="node-tag" :class="authStore.nodeMode">
            <el-icon><Connection /></el-icon>
            <span>{{ authStore.nodeMode === 'master' ? '主节点' : authStore.nodeMode === 'slave' ? '从节点' : '加载中' }}</span>
          </div>
        </div>
      </el-header>

      <!-- Caddy 进程停摆全局横幅：/caddy/status 的 status 字段（running|stopped）——
           只有仪表盘消费该字段时，停留在规则/设置/日志页完全看不到停摆
           （apply_error 可能为空）。全节点全页面可见，带重启入口。 -->
      <el-alert
        v-if="caddyStopped"
        type="error"
        :closable="false"
        show-icon
        class="error-banner"
      >
        <template #title>
          <div class="polling-error-title">
            <span>Caddy 服务未运行：站点当前无法提供服务（面板操作不受影响）</span>
            <el-button v-if="authStore.readOnlyReason === null" link type="danger" :loading="restarting" @click="handleRestartForDrift">重启服务</el-button>
          </div>
        </template>
      </el-alert>

      <el-alert
        v-if="configDrift && authStore.nodeMode === 'master'"
        type="error"
        :closable="false"
        show-icon
        class="config-drift-banner error-banner"
      >
        <template #title>
          <div class="polling-error-title">
            <span class="drift-text">运行配置与规则数据不一致：{{ configDrift }}</span>
            <el-button v-if="authStore.readOnlyReason === null" link type="danger" :loading="restarting" @click="handleRestartForDrift">重启服务恢复</el-button>
          </div>
          <!-- 高度稳定（2026-09-25：安全总览偶发 43px 塌缩实证）——Since 未回填的瞬时窗口
               meta 行不卸载，横幅恒两行，杜绝跨页/轮询周期内的高度跳变 -->
          <div class="polling-error-meta error-banner-meta">{{ configDriftSince ? `检测于 ${configDriftSince} UTC（重启服务后按数据库重新应用全部规则配置）` : '检测中…（重启服务后按数据库重新应用全部规则配置）' }}</div>
        </template>
      </el-alert>

      <!-- 配置应用失败全局横幅：写路径保存分叉（apply_error，含「已保存但
           未生效」退化提交两态文案）与后台重载失败（background_apply_error，
           含从节点集群同步重载失败）同源轮询——全部节点全部页面可见 -->
      <el-alert
        v-if="applyErrorBanner"
        :type="applyErrorBannerKind"
        :closable="false"
        show-icon
        class="error-banner"
      >
        <template #title>
          <span>{{ applyErrorBanner }}</span>
          <div v-if="backgroundApplyErrorBanner" class="polling-error-meta error-banner-meta">另有后台重载失败：{{ backgroundApplyErrorBanner }}</div>
        </template>
      </el-alert>

      <el-main class="layout-main">
        <slot />
      </el-main>
      <el-footer class="layout-footer">
        <span class="footer-text" v-html="footerHtml"></span>
      </el-footer>
    </el-container>

    <ProfileDialog v-model="showProfile" />
  </el-container>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted } from 'vue'
import { useMediaQuery } from '@vueuse/core'
import { useAuthStore } from '@/stores/auth'
import { accountInitial, accountTriggerLabel, sidebarCollapsed, sidebarOverlay, sidebarWidth, toggleSidebarState } from '@/utils/sidebarLayout'
import type { PageId } from '@/utils/pageIds'
import { request } from '@/utils/api'
import {Timer,  DataAnalysis, List, Setting, Cpu, User, Connection, Lock, Key, Document, Warning, Notebook } from '@element-plus/icons-vue'
import ProfileDialog from '@/components/ProfileDialog.vue'
import AppLogo from '@/components/AppLogo.vue'
import { appName, footerHtml } from '@/utils/branding'
import { restartServiceWithFeedback } from '@/utils/restart'
import { createVisibilityIntervals } from '@/composables/useVisibilityIntervals'
import { SETTINGS_BREADCRUMB_PARENT, SETTINGS_TAB_IDS, SETTINGS_TAB_TITLES } from '@/utils/settingsPages'
import { activateOnce } from '@/utils/keyboardActivate'
import { hasOwn } from '@/utils/hasOwn'

const authStore = useAuthStore()
// 宽屏用户折叠记忆与窄屏显式展开分开持有：窄屏强制折叠只是默认态，折叠入口
// 必须真的有可观察效果（此前点击/回车/空格只翻转 collapsed，窄屏下完全无效）。
const userCollapsed = ref(false)
const narrowExpanded = ref(false)
const isNarrowViewport = useMediaQuery('(max-width: 768px)')
const effectiveCollapsed = computed(() => sidebarCollapsed({
  narrow: isNarrowViewport.value,
  userCollapsed: userCollapsed.value,
  narrowExpanded: narrowExpanded.value,
}))
// 窄屏展开走浮层（不挤压内容区），遮罩点击收起
const sidebarOverlayVisible = computed(() => sidebarOverlay({ narrow: isNarrowViewport.value, collapsed: effectiveCollapsed.value }))
const toggleSidebar = (): void => {
  const next = toggleSidebarState({
    narrow: isNarrowViewport.value,
    userCollapsed: userCollapsed.value,
    narrowExpanded: narrowExpanded.value,
  })
  userCollapsed.value = next.userCollapsed
  narrowExpanded.value = next.narrowExpanded
}
const closeNarrowSidebar = (): void => { narrowExpanded.value = false }
// 视口回到宽屏后复位窄屏展开态：下次拉窄应回到默认折叠，而不是沿用旧选择
watch(isNarrowViewport, (narrow) => { if (!narrow) narrowExpanded.value = false })
const showProfile = ref(false)
const loggingOut = ref(false)

const currentPage = computed(() => authStore.currentPage)
// unknown（用户信息尚未拉取成功）窗口期 fail-closed，与 slave 同口径锁定
// 自助资料编辑；非管理员的自我显示名/改密是自助能力而非管理员操作，不随此收紧
//（后端恢复后仍按自身身份正确鉴权）。
const isOIDCUser = computed(() => authStore.user?.auth_provider === 'oidc')
const menuDisplayName = computed(() => authStore.user?.display_name || authStore.user?.username || '用户')
const hasCustomDisplayName = computed(() => {
  const displayName = authStore.user?.display_name || ''
  return displayName !== '' && displayName !== authStore.user?.username
})

// 侧栏文案与顶栏面包屑唯一事实源：键→label（parent=面包屑前缀分组）。
// 此前侧栏 menu 与 pageTitle 各持一份页面名字面量，改名必漏一侧（菜单与
// 面包屑不一致）；现在模板与面包屑都从本表取值，settings 段继续复用
// utils/settingsPages 的标题单源。
const SECURITY_PARENT = '安全防护'
const NAV_ITEMS: ReadonlyArray<{ id: string; label: string; parent?: string }> = [
  { id: 'dashboard', label: '仪表盘' },
  { id: 'rules', label: '负载均衡' },
  { id: 'security-overview', label: '安全总览', parent: SECURITY_PARENT },
  { id: 'security-policies', label: '安全策略', parent: SECURITY_PARENT },
  { id: 'security-rules', label: '规则集', parent: SECURITY_PARENT },
  { id: 'security-block-pages', label: '拦截页面', parent: SECURITY_PARENT },
  { id: 'security-events', label: '事件日志', parent: SECURITY_PARENT },
  { id: 'caddy', label: '配置预览' },
  { id: 'users', label: '用户认证', parent: SETTINGS_BREADCRUMB_PARENT },
  { id: 'audit-log', label: '操作日志' },
]

// 系统设置五个分页标题与 Settings.vue 页头同源（utils/settingsPages）——原两处
// 各持一份同构映射，改名必然漏改其一。
const settingsPageTitles: Record<string, string> = Object.fromEntries(
  SETTINGS_TAB_IDS.map((tab) => [`settings-${tab}`, `${SETTINGS_BREADCRUMB_PARENT} / ${SETTINGS_TAB_TITLES[tab]}`]),
)

const NAV_LABELS: Record<string, string> = {
  ...Object.fromEntries(NAV_ITEMS.map((item) => [item.id, item.label])),
  ...Object.fromEntries(SETTINGS_TAB_IDS.map((tab) => [`settings-${tab}`, SETTINGS_TAB_TITLES[tab]])),
}

const pageTitle: Record<string, string> = {
  ...Object.fromEntries(NAV_ITEMS.map((item) => [item.id, item.parent ? `${item.parent} / ${item.label}` : item.label])),
  ...settingsPageTitles,
}

const goPage = (page: PageId) => {
  authStore.setCurrentPage(page)
  // 窄屏浮层选完页面即收起（否则浮层挡住新页内容）
  if (isNarrowViewport.value) narrowExpanded.value = false
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
    showProfile.value = true
  } else if (command === 'logout') {
    await logout()
  }
}

// 配置一致性看门狗横幅：轮询 /caddy/status，漂移时展示并给出重启恢复入口。
const configDrift = ref('')
const configDriftSince = ref('')
// 配置应用失败全局横幅（全部节点、全部页面）：apply_error=写路径
// 「保存失败/已保存未生效」（库态分叉），background_apply_error=后台数据类
// 重载失败（证书部署/CRS/IP库/威胁库/自动封禁/集群同步重载——从节点
// 「快照已提交但运行配置未收敛」分叉的唯一全局信号）。此前两者都只在
// 仪表盘以标签呈现，非仪表盘页面与从节点完全不可见。
const applyErrorBanner = ref('')
const backgroundApplyErrorBanner = ref('')
const applyErrorBannerKind = ref<'error' | 'warning'>('error')
// Caddy 进程状态（running|stopped）：非仪表盘页面的停摆信号（Dashboard 另有一处
// 消费）。查询失败时不改写旧值——保留最后一次已知状态，避免横幅闪烁。
const caddyStopped = ref(false)
const restarting = ref(false)
let disposed = false

const fetchDriftStatus = async () => {
  // 节点模式未知（/config 未就绪窗口）仍查询——apply 失败横幅全节点有效；
  // 漂移看门狗语义主节点权威，漂移文案仍仅 master 渲染。
  try {
    const res = await request.get('/caddy/status', { silent: true })
    const drifted = res.data?.config_consistent === 'false' && authStore.nodeMode === 'master'
    configDrift.value = drifted ? (res.data?.config_drift || '规则路由与运行配置不一致') : ''
    configDriftSince.value = drifted ? (res.data?.config_drift_since || '') : ''
    const applyErr = res.data?.apply_error || ''
    const bgErr = res.data?.background_apply_error || ''
    caddyStopped.value = res.data?.status === 'stopped'
    applyErrorBanner.value = applyErr || bgErr
    // 两者触发源不同且 apply_error 仅在下一次成功保存时清空：并存时后台失败
    // 必须单独成行，否则在 apply_error 清空前完全不可见（从节点同步重载失败即此类）。
    backgroundApplyErrorBanner.value = applyErr ? bgErr : ''
    applyErrorBannerKind.value = applyErr ? 'error' : 'warning'
  } catch {
    // 状态查询失败静默——网络层错误已有全局处理
  }
}

const handleRestartForDrift = async () => {
  if (restarting.value) return
  restarting.value = true
  // 确认/重启/就绪轮询流程单源（utils/restart），与设置页同一实现
  const result = await restartServiceWithFeedback({
    confirmMessage: '将重启服务以重新应用全部规则配置，期间服务短暂不可用。确认重启？',
    confirmTitle: '重启服务恢复',
    confirmButtonText: '确认重启',
    successMessage: '服务正在重启，就绪后自动刷新页面',
    isDisposed: () => disposed,
  })
  if (result !== 'reloaded') restarting.value = false
}

// 漂移轮询接可见性间隔单源（与 usePollingTask/
// useLogTailPolling 同范式）——hidden 停表、恢复可见立即补查；原手写
// setInterval+document.hidden 只跳过轮次，返回页后横幅最长 60s 陈旧。
// immediate:true = 挂载即首查（替代原显式 fetchDriftStatus 调用）。
const driftPolling = createVisibilityIntervals({
  intervals: [{ tick: () => { void fetchDriftStatus() }, ms: 60000, immediate: true }],
})

onMounted(() => {
  driftPolling.start()
})

onUnmounted(() => {
  disposed = true
  driftPolling.stop()
})
</script>

<style scoped>
.layout-container { height: 100vh; }

.config-drift-banner {
  border-radius: 0;
  /* 垂直留白由全局 .error-banner（main.css）供给（去双份）*/
}
/* 与站内 polling-error-alert 统一模式（Rules/CertJobs/ClusterSettings）同构：
   图标+标题 flex（文案左、动作右）+ 12px meta 次行——flex/字号/行高全部由全局
   .polling-error-title / .error-banner .error-banner-meta（main.css）供给，此处不重复声明。 */
.config-drift-banner .drift-text { font-weight: 500; }

.layout-aside {
  background: #ffffff;
  border-right: 1px solid #e5e7eb;
  display: flex;
  flex-direction: column;
  transition: width 0.2s;
}

/* 窄屏展开=浮层：不挤压内容区，抬到内容之上；遮罩承接「点空白收起」。
   height/inset 用固定定位脱离 el-container 流式布局。 */
.layout-aside.is-overlay {
  position: fixed;
  top: 0;
  bottom: 0;
  left: 0;
  z-index: 2001;
  box-shadow: 0 8px 24px rgba(17, 24, 39, 0.16);
}

.sidebar-backdrop {
  position: fixed;
  inset: 0;
  z-index: 2000;
  background: rgba(17, 24, 39, 0.32);
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

.layout-menu :deep(.el-sub-menu__title + .el-menu) {
  margin-top: 0 !important;
  padding-top: 0 !important;
}

.layout-menu :deep(.el-sub-menu) {
  margin-top: 4px !important;
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

/* 折叠态：只余头像标识，水平居中（原实现是无内容的热区） */
.user-info.is-collapsed {
  justify-content: center;
  padding: 12px 8px;
}

.user-avatar {
  width: 32px;
  height: 32px;
  flex: 0 0 32px;
  border-radius: 50%;
  background: #eff6ff;
  color: #3b82f6;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 14px;
  font-weight: 600;
}


.user-detail { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 2px; }

.user-name {
  display: flex;
  align-items: center;
  gap: 6px;
  min-width: 0;
  font-size: 14px;
  font-weight: 500;
  color: #111827;
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

.user-name-text { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.user-source-tag { flex-shrink: 0; height: 18px; padding: 0 6px; font-size: 11px; line-height: 16px; }
</style>
