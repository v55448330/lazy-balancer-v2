<template>
  <el-config-provider :locale="zhCn">
    <div v-if="loading" class="app-loading">
      <div class="app-loading__inner">
        <div class="app-loading__spinner"></div>
        <div class="app-loading__text">加载中...</div>
      </div>
    </div>

    <Login v-else-if="!authStore.token || isTokenExpired(authStore.token || '')" />
    <!-- 威胁大屏：全屏模式分支——不进 AppLayout（隐藏侧栏顶栏），ESC 在页内退出 -->
    <ThreatScreen v-else-if="currentPage === 'threat-screen'" />
    <AppLayout v-else>
      <Dashboard v-if="currentPage === 'dashboard'" />
      <Rules v-else-if="currentPage === 'rules'" />
      <SecurityPolicies v-else-if="currentPage === 'security-policies'" />
      <SecurityRules v-else-if="currentPage === 'security-rules'" />
      <SecurityBlockPages v-else-if="currentPage === 'security-block-pages'" />
      <SecurityOverview v-else-if="currentPage === 'security-overview'" />
      <SecurityEvents v-else-if="currentPage === 'security-events'" />
      <Settings v-else-if="settingsTabOfPage(currentPage) !== null" />
      <CaddyConfig v-else-if="currentPage === 'caddy'" />
      <Users v-else-if="currentPage === 'users'" />
      <AuditLog v-else-if="currentPage === 'audit-log'" />
      <!-- 兜底：PAGE_IDS 新增键但漏接线（或深链带旧键）时给出可见提示，不留白屏 -->
      <el-empty v-else description="页面不存在" />
    </AppLayout>
  </el-config-provider>
</template>

<script setup lang="ts">
import { ref, onMounted, computed, defineAsyncComponent } from 'vue'
import type { AsyncComponentLoader } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { isPageId } from '@/utils/pageIds'
import { settingsTabOfPage } from '@/utils/settingsPages'
import { ApiRequestError, isTokenExpired } from '@/utils/api'
import { OIDC_APP_NONCE_KEY, OIDC_REJECTION_TEXT, oidcErrorMessage, splitOidcReturnTo, verifyOidcCallbackToken } from '@/utils/oidcCallback'
import { ElMessage, ElMessageBox } from 'element-plus'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import AppLayout from '@/components/layout/AppLayout.vue'
import Login from '@/views/Login.vue'
import AsyncPageError from '@/views/AsyncPageError.vue'

const createAsyncPage = (loader: AsyncComponentLoader) => defineAsyncComponent({
  loader,
  errorComponent: AsyncPageError,
  onError: (_error, retry, fail, attempts) => {
    if (attempts <= 1) {
      retry()
      return
    }
    fail()
  },
})

const Dashboard = createAsyncPage(() => import('@/views/Dashboard.vue'))
const Rules = createAsyncPage(() => import('@/views/Rules.vue'))
const SecurityPolicies = createAsyncPage(() => import('@/views/security/SecurityPolicies.vue'))
const SecurityRules = createAsyncPage(() => import('@/views/security/SecurityRules.vue'))
const SecurityBlockPages = createAsyncPage(() => import('@/views/security/SecurityBlockPages.vue'))
const SecurityOverview = createAsyncPage(() => import('@/views/security/SecurityOverview.vue'))
const ThreatScreen = createAsyncPage(() => import('@/views/security/ThreatScreen.vue'))
const SecurityEvents = createAsyncPage(() => import('@/views/security/SecurityEvents.vue'))
const Settings = createAsyncPage(() => import('@/views/Settings.vue'))
const CaddyConfig = createAsyncPage(() => import('@/views/CaddyConfig.vue'))
const Users = createAsyncPage(() => import('@/views/Users.vue'))
const AuditLog = createAsyncPage(() => import('@/views/AuditLog.vue'))

const authStore = useAuthStore()
const loading = ref(true)

const currentPage = computed(() => authStore.currentPage)

onMounted(async () => {
  const url = new URL(window.location.href)
  // hash 形态二种:「#login_ticket=x」(无路径)与「#/oidc/callback?token=x」
  // (带路径)——先剥路径段再解析查询串,否则 key 变成 "/oidc/callback?token"
  const hashBody = url.hash.startsWith('#') ? url.hash.slice(1) : ''
  const qIdx = hashBody.indexOf('?')
  const fragment = new URLSearchParams(qIdx >= 0 ? hashBody.slice(qIdx + 1) : hashBody)
  const hasLoginTicket = fragment.has('login_ticket')
  const loginTicket = fragment.get('login_ticket') ?? ''
  // v2.3.0 OIDC 回跳:#/oidc/callback?token=...&return_to=...——后端回调以
  // fragment 携带令牌(不发服务器),此处接收建会话(与票据登录同型)。
  // 令牌本身不可信（任意链接都能携带别人的有效 JWT），只接受同时满足
  // 「本浏览器发起过这一轮登录的 nonce + auth_method=oidc + expires_at 与 exp
  // 一致」的令牌：见 utils/oidcCallback 的来源绑定契约。
  const oidcCallback = url.hash.includes('/oidc/callback')
  const oidcToken = oidcCallback ? (fragment.get('token') ?? '') : ''
  const oidcExpiresAt = oidcCallback ? (fragment.get('expires_at') ?? '') : ''
  const oidcReturn = splitOidcReturnTo(oidcCallback ? (fragment.get('return_to') ?? '') : '')
  // 后端回调失败以 error 片段 302 回前端。必须当场提示——
  // 原实现写入 sessionStorage 只在 Login 挂载时消费一次；已持有效会话的用户
  // 回跳时 init() 成功、Login 不挂载，错误既不提示也不清除，等之后登出才看到
  // 一条过期的「OIDC 登录失败」。此处提示后即从 hash 剥离（下方 delete），
  // sessionStorage 通道不再使用。文案经白名单映射：fragment 内容不可信，
  // 任意链接都能在面板里投放提示文案（见 oidcErrorMessage）。
  const oidcError = oidcCallback ? (fragment.get('error') ?? '') : ''
  if (oidcError) ElMessage.error(`OIDC 登录失败：${oidcErrorMessage(oidcError)}`)
  if (hasLoginTicket || oidcCallback) {
    fragment.delete('login_ticket')
    fragment.delete('token')
    fragment.delete('return_to')
    fragment.delete('expires_at')
    fragment.delete('oidc')
    fragment.delete('error')
    const remainingHash = fragment.toString()
    window.history.replaceState({}, '', `${url.pathname}${url.search}${remainingHash ? `#${remainingHash}` : ''}`)
  }

  try {
    if (oidcToken) {
      // 本浏览器本轮登录的 nonce（一次性）：缺失=没发起过登录，不匹配=构造链接。
      let expectedNonce = ''
      try {
        expectedNonce = sessionStorage.getItem(OIDC_APP_NONCE_KEY) ?? ''
        sessionStorage.removeItem(OIDC_APP_NONCE_KEY)
      } catch { /* 隐私模式：无 nonce 一律按失败处理 */ }
      const verdict = verifyOidcCallbackToken({
        token: oidcToken,
        expiresAt: oidcExpiresAt,
        nonce: oidcReturn.nonce,
        expectedNonce,
      })
      // 本轮令牌是否真正落到会话（拒绝/取消都保持 false）——return_to 导航的门。
      let tokenApplied = false
      if (!verdict.ok) {
        ElMessage.error(`OIDC 登录失败：${OIDC_REJECTION_TEXT[verdict.reason]}`)
        // 拒绝分支与成功分支共用下方无条件 init()，不得再发起一轮 /users/me+/config
      } else if (authStore.token && !isTokenExpired(authStore.token)) {
        // 已登录会话被 URL 令牌替换=一次身份切换：必须显式确认（换人/账号被
        // 顶替不该由一条链接决定），取消则完全不动现有会话。
        const target = verdict.username ? `「${verdict.username}」` : '另一个账号'
        const confirmed = await ElMessageBox.confirm(
          `当前浏览器的登录链接将切换到${target}的会话，是否继续？`,
          '切换登录账号',
          { type: 'warning', confirmButtonText: '切换', cancelButtonText: '保持当前登录' },
        ).then(() => true).catch(() => false)
        if (confirmed) {
          authStore.applyOIDCToken(oidcToken)
          tokenApplied = true
        } else ElMessage.info('已保持当前登录')
      } else {
        // OIDC 登录:令牌直接建会话,return_to 回跳(缺省 dashboard)
        authStore.applyOIDCToken(oidcToken)
        tokenApplied = true
      }
      // return_to 只在令牌真正落地（新建会话 / 确认换号）后生效：拒绝分支与
      // 「保持当前登录」都不得跳页——否则提示与行为自相矛盾（先告诉用户
      // 「已拒绝 / 已保持」，界面却仍跳到链接指定的页面）。
      if (tokenApplied) {
        // return_to 仅接受已知页面键,未知回 dashboard(防任意页注入)——
        // 清单复用 utils/pageIds 的 isPageId(页面键唯一事实源)
        const target = oidcReturn.path.replace(/^\//, '')
        if (isPageId(target)) authStore.setCurrentPage(target)
      }
      await authStore.init()
    } else if (hasLoginTicket) {
      const hadValidSession = authStore.isLoggedIn
      try {
        const result = await authStore.loginWithTicket(loginTicket)
        // 重入护栏命中（挂载期为单次调用，防御性判断）——未建立会话时不导航。
        if (!result.skipped) authStore.setCurrentPage('dashboard')
      } catch (error: unknown) {
        if (hadValidSession) await authStore.init()
        ElMessage.error(error instanceof ApiRequestError && (error.status === 400 || error.status === 401) ? '票据无效或已过期' : '登录服务异常')
      }
    } else {
      await authStore.init()
    }
  } finally {
    loading.value = false
  }
})
</script>

<style scoped>
.app-loading {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #0f172a;
}
.app-loading__inner {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 16px;
}
.app-loading__spinner {
  width: 48px;
  height: 48px;
  border: 4px solid #3b82f6;
  border-top-color: transparent;
  border-radius: 50%;
  animation: app-loading-spin 0.8s linear infinite;
}
.app-loading__text {
  color: #94a3b8;
  font-size: 14px;
}
@keyframes app-loading-spin {
  to { transform: rotate(360deg); }
}
</style>
