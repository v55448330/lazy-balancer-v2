import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import type { APIResponse, ClusterNodeMode, CurrentUser, GlobalConfigData } from '@/types'
import { isTokenExpired, request, ApiRequestError } from '@/utils/api'
import { ElMessage } from 'element-plus'
import { isPageId, type PageId } from '@/utils/pageIds'
import { DEFAULT_CERT_RENEWAL_DAYS } from '@/utils/configValues'
import { advanceSessionGeneration, currentSessionGeneration, isSameTokenIdentity } from '@/utils/sessionIdentity'

const queryPage = new URLSearchParams(location.search).get('page')
const queryPageValid: PageId | null = queryPage && isPageId(queryPage) ? queryPage : null
// URL hash 优先（刷新/多标签页可靠；导航用 replaceState 不产生历史条目，浏览器返回键会离开面板）；localStorage 作为后备。
const hashMatch = window.location.hash.match(/^#\/(.+)$/)
const hashPage = hashMatch ? hashMatch[1] : null
const storedCurrentPage = localStorage.getItem('currentPage')
const initialCurrentPage: PageId =
  queryPageValid ??
  (hashPage && isPageId(hashPage) ? hashPage :
   storedCurrentPage && isPageId(storedCurrentPage) ? storedCurrentPage : 'dashboard')
// 深链?page= 仅作首屏入口——消费后立即剥离并同步 localStorage，
// 否则参数永久留在 URL 上遮蔽 hash 导航（深链标签页导航后刷新被拉回原页）。
if (storedCurrentPage !== initialCurrentPage) localStorage.setItem('currentPage', initialCurrentPage)
if (queryPageValid) {
  const url = new URL(window.location.href)
  url.searchParams.delete('page')
  window.history.replaceState(null, '', `${url.pathname}${url.search}${url.hash}`)
}

interface AuthResponse {
  readonly token: string
  readonly node_mode: ClusterNodeMode
  readonly user?: CurrentUser
}

export const useAuthStore = defineStore('auth', () => {
  const user = ref<CurrentUser | null>(null)
  const token = ref<string | null>(localStorage.getItem('token'))
  // 节点模式三态化——null=未知（/config 未成功拉取），
  // 不再默认 'master'：从节点刷新+瞬时失败窗口曾按主节点 fail-open 渲染写控件。
  const nodeMode = ref<ClusterNodeMode | null>(null)
  const timezone = ref<string>('Asia/Shanghai')
  // cert_renewal_days 并入 /config 消费面（CertJobs 曾挂载整取单键）；
  // ≤0（含 0）时按 DEFAULT_CERT_RENEWAL_DAYS 展示，与后端口径对齐
  // （默认值单源在 utils/configValues，跨栈钉住 db.DefaultCertRenewalDays）。
  const certRenewalDays = ref(DEFAULT_CERT_RENEWAL_DAYS)
  // 与 cert_renewal_days 同源：mfa_write_guard 随 /config 投影（Users 页曾为此
  // 单独挂载整取 GET /config 单键，与 15s 轮询的 /config 请求重复）。
  // 首值 false = 守卫关闭的保守形态（读取失败/未就绪时对话框维持验码形态）。
  const mfaWriteGuard = ref(false)
  const loading = ref(false)
  const intentionalLogout = ref(false)
  const currentPage = ref<PageId>(initialCurrentPage)
  // 会话代际：登录/登出/换令牌/跨标签同步各推进一档。在途的 /users/me 以
  // 「发起时代际 + 发起时令牌」为身份，await 之后任一不符即整条丢弃——否则
  // 「退出 A 登录 B」时 A 的迟到响应会把 user 重建为上一位用户，界面按旧角色
  // 渲染写控件（后端仍按新令牌鉴权，故仅 UI 误导，但会持续到刷新）。

  const isLoggedIn = computed(() => !!token.value && !isTokenExpired(token.value))
  const readOnlyReason = computed<'slave' | 'non-admin' | 'unknown' | null>(() => {
    if (nodeMode.value === 'slave') return 'slave'
    // 角色未判定（登录响应 node_mode=unknown，或 /config 未成功拉取给 null）
    // 一律 fail-closed 只读：授权侧本就拒绝写请求，UI 不得呈现为可写主节点。
    if (nodeMode.value === 'unknown') return isLoggedIn.value ? 'unknown' : null
    if (user.value) {
      if (user.value.role !== 'admin') return 'non-admin'
      // admin 用户但节点模式未知（/config 未成功拉取）同样按只读呈现
      // （fail-closed），与下方用户信息未知窗口同口径。
      if (nodeMode.value === null) return isLoggedIn.value ? 'unknown' : null
      return null
    }
    // token 有效但用户信息尚未成功拉取（如 /users/me 瞬时失败）：权限未知按只读
    // 呈现（fail-closed），避免该窗口期按 admin 视图放行（fail-open）
    return isLoggedIn.value ? 'unknown' : null
  })
  const readOnlyMessage = computed(() => {
    if (readOnlyReason.value === 'slave') return '从节点只读，请在主节点操作'
    if (readOnlyReason.value === 'non-admin') return '非管理员用户只读'
    if (readOnlyReason.value === 'unknown') return '信息加载中，暂以只读模式呈现'
    return ''
  })
  // 从节点判定单一事实源——Keys/Users/SecurityRules 曾各自
  // 复写 `nodeMode==='slave'`/`readOnlyReason==='slave'` 派生，收敛到本 getter。
  const isSlaveNode = computed(() => nodeMode.value === 'slave')

  // ── 跨标签页会话同步 ──
  // 令牌是 localStorage 与内存 ref 的双源：同标签页登出只清本页两份，其余
  // 标签页的 store 仍握着旧 JWT（界面继续渲染主界面），而请求层只读
  // localStorage（已无令牌）→ 后续每次操作静默 401：既不弹错误也不弹重登，
  // 用户只能手动刷新。storage 事件由**其它**标签页写 localStorage 时触发，
  // 正是补上这一跳的时机（本标签页自己的写入不会触发本事件）。
  const onStorageChange = (event: StorageEvent): void => {
    // key === null = 另一标签页执行了 localStorage.clear()（会话同样失效）
    if (event.key !== null && event.key !== 'token') return
    const stored = localStorage.getItem('token')
    if (stored === token.value) return
    // 换账号推进代际；同账号 MFA 刷新保持代际，但仍在下方换令牌并重拉投影。
    if (!isSameTokenIdentity(token.value, stored)) advanceSessionGeneration()
    clearUserRetryTimer()
    clearConfigRetryTimer()
    if (!stored) {
      // 另一标签页已登出（或会话失效清理）：本页同步退出，App.vue 的登录页
      // 判据（!authStore.token）立即生效。intentionalLogout 抑制在途请求的
      // 「会话失效」弹窗——这是主动同步，不是会话异常。
      intentionalLogout.value = true
      user.value = null
      token.value = null
      nodeMode.value = null
      return
    }
    // 另一标签页建立了新会话（登录 / 切换账号 / MFA step-up 刷新令牌）：跟随
    // 令牌并重拉用户与节点模式——沿用本页旧 user 会把上一账号的权限继续渲染。
    intentionalLogout.value = false
    user.value = null
    nodeMode.value = null
    token.value = stored
    void init()
  }

  // 仅浏览器环境绑定（node 单测/SSR 无 window）。
  if (typeof window !== 'undefined') window.addEventListener('storage', onStorageChange)

  let userRetryTimer: number | null = null
  // 隐藏页停表留下的待补查标记：定时器在后台到期时只记标记、不排下一轮，
  // 由 visibilitychange 补查消费（与 /config 的「hidden 停表 + visible 补查」
  // 同范式，避免后台标签页每 15s 唤醒一次）。
  let userRetryDeferred = false

  const clearUserRetryTimer = (): void => {
    userRetryDeferred = false
    if (userRetryTimer !== null) {
      window.clearTimeout(userRetryTimer)
      userRetryTimer = null
    }
  }

  const scheduleUserRetry = (): void => {
    if (userRetryTimer !== null || !token.value) return
    bindVisibilityRefresh()
    userRetryTimer = window.setTimeout(() => {
      userRetryTimer = null
      // 后台标签页不发请求，也不顺延定时器；改记待补查标记，恢复可见时
      // 由 visibilitychange 立即补拉，回来时不必再等一个周期。
      if (typeof document !== 'undefined' && document.hidden) {
        userRetryDeferred = true
        return
      }
      void fetchUser()
    }, 15_000)
  }

  async function fetchUser() {
    if (!token.value) return
    // 发起时的会话身份：await 之后代际或令牌任一变化即表示已换会话（登录他人/
    // 登出/跨标签同步），响应与失败都不得写回或排重试。
    const issuedGeneration = currentSessionGeneration()
    const issuedToken = token.value
    try {
      // 静默拉取——失败态已由 15s 重试循环与 readOnlyMessage 横幅（AppLayout
      // 只读标签）持续反馈，与其余轮询体系的 silent 口径一致，不再叠加 toast 噪音。
      const res = await request.get<APIResponse<CurrentUser>>('/users/me', { silent: true })
      if (currentSessionGeneration() !== issuedGeneration || token.value !== issuedToken) return
      if (res.data) {
        user.value = {
          id: res.data.id,
          username: res.data.username,
          role: res.data.role,
          is_enabled: res.data.is_enabled,
          display_name: res.data.display_name,
          mfa_enabled: res.data.mfa_enabled ?? false,
          auth_provider: res.data.auth_provider ?? 'local',
          is_setup_admin: res.data.is_setup_admin ?? false,
        }
      } else {
        // 200 但 data 为空——user 仍为 null（unknown 只读窗口）且原先此处
        // 不安排重试（静默死亡，永不恢复）。与瞬时失败同口径：定时重试拉取。
        scheduleUserRetry()
      }
    } catch (error: unknown) {
      // 换会话后旧请求的失败同样丢弃：否则会为**新**会话排一条本不该有的重试链。
      if (currentSessionGeneration() !== issuedGeneration || token.value !== issuedToken) return
      // 瞬时失败（非 401）保留最近一次已知的用户与权限，不清空；显式 401 由全局
      // 拦截器「会话失效」流统一处理（清 token 重载），logout 才主动清除。
      // 用户信息尚无已知值时定时重试拉取，使 fail-closed 的只读窗口自动恢复。
      if (!(error instanceof ApiRequestError && error.status === 401)) scheduleUserRetry()
      console.error(error)
    }
  }

  let configRetryTimer: number | null = null
  let configVisibilityBound = false
  // 在途门：visibilitychange 补查与 15s 轮询可能同时点火（回前台瞬间定时器
  // 恰好到期），同一轮 /config 不得双发；在飞时新触发直接跳过（补查语义
  // 已被在途轮覆盖）。
  let configFetchInFlight = false

  const clearConfigRetryTimer = (): void => {
    if (configRetryTimer !== null) {
      window.clearTimeout(configRetryTimer)
      configRetryTimer = null
    }
  }

  // 恢复可见立即补查（与 usePollingTask/useLogTailPolling 的
  // 「hidden 暂停 + visible 立即补拉」同范式）——15s 轮询在隐藏页被顺延，
  // 回来时不必再等一个周期。单次绑定（store 生命周期内常驻；token 已清时空转）。
  // /config 与 /users/me 两条重试链共用此监听，停表后都必须有人补查。
  const bindVisibilityRefresh = (): void => {
    if (configVisibilityBound || typeof document === 'undefined') return
    configVisibilityBound = true
    document.addEventListener('visibilitychange', () => {
      if (document.hidden || !token.value) return
      clearConfigRetryTimer()
      void fetchConfig(true)
      // 用户信息只在「隐藏期间有待补查」时补拉：已成功拉取且无待重试时，
      // 每次回前台都打一发 /users/me 属无谓出站。
      if (userRetryDeferred) {
        userRetryDeferred = false
        void fetchUser()
      }
    })
  }

  // 成功后每 15s 刷新全站 nodeMode；空数据/瞬时失败复用同一定时器重试。
  // 单定时器防重让登录、设置保存与后台刷新可以共用此入口而不叠加轮询。
  const scheduleConfigRetry = (): void => {
    if (configRetryTimer !== null || !token.value) return
    bindVisibilityRefresh()
    configRetryTimer = window.setTimeout(() => {
      configRetryTimer = null
      // 后台标签页不发请求，也不顺延定时器：隐藏页每 15s 唤醒一次等于永久
      // 空转（浏览器再节流也非零开销）。恢复可见由 visibilitychange 立即补查，
      // 回来时不必等一个周期。
      if (typeof document !== 'undefined' && document.hidden) return
      void fetchConfig(true)
    }, 15_000)
  }

  // /config 投影 = GlobalConfigData 消费字段子集 + 集群专属 is_master。
  type ConfigProjection = { readonly is_master: boolean } & Partial<Pick<GlobalConfigData, 'timezone' | 'cert_renewal_days' | 'mfa_write_guard'>>

  async function fetchConfig(silent = false) {
    if (!token.value || configFetchInFlight) return
    configFetchInFlight = true
    try {
      // 投影复用 GlobalConfigData 声明（该接口为 GET /config 响应单一事实源）；
      // is_master 是集群专属字段、不在 GlobalConfigData 面内，store 侧并集补充。
      const res = await request.get<APIResponse<ConfigProjection>>('/config', { silent })
      if (res.data) {
        nodeMode.value = res.data.is_master ? 'master' : 'slave'
        if (res.data.timezone) timezone.value = res.data.timezone
        const renewalDays = res.data.cert_renewal_days ?? DEFAULT_CERT_RENEWAL_DAYS
        certRenewalDays.value = renewalDays > 0 ? renewalDays : DEFAULT_CERT_RENEWAL_DAYS
        mfaWriteGuard.value = res.data.mfa_write_guard === true
        scheduleConfigRetry()
      } else {
        scheduleConfigRetry()
      }
    } catch (e) {
      // 瞬时失败保留最近一次已知模式，未知态由重试循环收敛（401 走全局拦截器）
      if (!(e instanceof ApiRequestError && e.status === 401)) scheduleConfigRetry()
      console.error(e)
    } finally {
      configFetchInFlight = false
    }
  }

// 重入护栏显式化——loading 期间的重复调用不再伪装成「登录成功」
//（原 login 重入返回 { mfaRequired:false } 与成功形态无法区分），
// skipped:true 表示本次请求未发出，调用方应提示并中止。
interface LoginResult {
  skipped: boolean
  mfaRequired: boolean
  mfaToken?: string
}

  async function login(username: string, password: string): Promise<LoginResult> {
    if (loading.value) return { skipped: true, mfaRequired: false }
    loading.value = true
    try {
      const res = await request.post<AuthResponse>('/auth/login', { username, password }, { silent: true })
      // v2.1.8 MFA 两步登录：后端返回 mfa_required 时无 token——调用方（Login.vue）
      // 切换到验证码步骤；silent 抑制拦截器把 200 的 mfa_required 形态当错误 toast。
      if ((res as unknown as { mfa_required?: boolean }).mfa_required) {
        return { skipped: false, mfaRequired: true, mfaToken: (res as unknown as { mfa_token: string }).mfa_token }
      }
      applyAuthResponse(res)
      await fetchConfig()
      return { skipped: false, mfaRequired: false }
    } finally {
      loading.value = false
    }
  }

  // v2.1.8 MFA step-up：验证码刷新 mfa_ts（新 JWT 替换当前 token，身份不变）。
  async function refreshMfaStep(code: string) {
    const res = await request.post<AuthResponse>('/auth/mfa/verify-step', { code }, { silent: true })
    applyAuthResponse(res, true)
  }

  // v2.1.8 MFA 第二步：验证码换 JWT。重入护栏与 login 同口径（skipped 显式判别）。
  async function verifyMfaLogin(mfaToken: string, code: string): Promise<{ skipped: boolean }> {
    if (loading.value) return { skipped: true }
    loading.value = true
    try {
      const res = await request.post<AuthResponse>('/auth/mfa/verify', { mfa_token: mfaToken, code }, { silent: true })
      applyAuthResponse(res)
      await fetchConfig()
      return { skipped: false }
    } finally {
      loading.value = false
    }
  }

  function applyAuthResponse(res: AuthResponse, preserveSession = false) {
    // 登录/票据登录换会话；MFA step-up 仅刷新同账号令牌，必须保持请求身份代际。
    if (!preserveSession) advanceSessionGeneration()
    intentionalLogout.value = false
    clearUserRetryTimer()
    clearConfigRetryTimer()
    token.value = res.token
    nodeMode.value = res.node_mode
    localStorage.setItem('token', res.token)
    if (res.user) {
      user.value = {
        id: res.user.id,
        username: res.user.username,
        role: res.user.role,
        is_enabled: res.user.is_enabled,
        display_name: res.user.display_name,
        mfa_enabled: res.user.mfa_enabled ?? false,
        // 票据登录响应携带的来源标记——缺失按本地,避免从节点 UI 误判
        auth_provider: res.user.auth_provider ?? 'local',
        is_setup_admin: res.user.is_setup_admin ?? false,
      }
    }
  }

  // v2.3.0 OIDC:后端回调跳转携带的令牌直接建会话(用户信息由 init 拉取)。
  function applyOIDCToken(rawToken: string) {
    // 换令牌即换身份：与跨标签切换分支同口径——旧 user/nodeMode 必须先清空，
    // 否则 init 拉取完成前界面仍按上一账号的角色渲染写控件。
    advanceSessionGeneration()
    intentionalLogout.value = false
    clearUserRetryTimer()
    clearConfigRetryTimer()
    user.value = null
    nodeMode.value = null
    token.value = rawToken
    localStorage.setItem('token', rawToken)
  }

  async function loginWithTicket(ticket: string): Promise<{ skipped: boolean }> {
    if (loading.value) return { skipped: true }
    loading.value = true
    try {
      const res = await request.post<AuthResponse>('/auth/ticket-login', { ticket })
      applyAuthResponse(res)
      await fetchConfig()
      return { skipped: false }
    } finally {
      loading.value = false
    }
  }

  async function logout() {
    // 会话在此刻结束（服务端吊销只是清理）：立即作废在途 /users/me，
    // 否则吊销请求期间落地的响应会把 user 写回，登出后仍按已登录渲染。
    advanceSessionGeneration()
    intentionalLogout.value = true
    try {
      if (token.value) await request.post('/auth/logout')
    } catch (caught: unknown) {
      console.warn('服务端注销失败，已执行本地退出', caught)
    } finally {
      clearUserRetryTimer()
      clearConfigRetryTimer()
      user.value = null
      token.value = null
      nodeMode.value = null
      localStorage.removeItem('token')
    }
  }

  // token 已在客户端判定过期（或本就不存在）时，服务端吊销毫无意义——
  // 撤销表只对仍有效的 jti 有价值，过期令牌必吃 401 并在后端认证拒绝审计记
  // 一条 jwt_expired 噪音。此路径仅做本地清理；手动登出（logout）仍走服务端吊销。
  // intentionalLogout 语义与 logout() 一致：抑制后续在途请求 401 的全局弹窗。
  function localLogout(): void {
    // 与 logout 同口径：会话立即作废，在途 /users/me 不得再写回。
    advanceSessionGeneration()
    intentionalLogout.value = true
    clearUserRetryTimer()
    clearConfigRetryTimer()
    user.value = null
    token.value = null
    nodeMode.value = null
    localStorage.removeItem('token')
  }

  function showToast(type: 'success' | 'error' | 'info' | 'warning', message: string) {
    ElMessage({
      message,
      type,
      duration: 3000,
    })
  }

  function setCurrentPage(page: PageId) {
    if (!isPageId(page)) return
    currentPage.value = page
    localStorage.setItem('currentPage', page)
    if (window.location.hash !== `#/${page}`) {
      window.history.replaceState(null, '', `#/${page}`)
    }
  }

  function setNodeMode(mode: ClusterNodeMode) {
    nodeMode.value = mode
  }

  async function init() {
    if (!token.value || isTokenExpired(token.value)) {
      localLogout()
      return
    }
    // 两个请求并行：首屏 loading 覆盖整页，串行等待会把最坏路径叠成两次全局
    // 30s 超时（60s 白屏）；二者互不依赖（/config 定节点模式，/users/me 定
    // 身份），任一方未就绪都由 readOnlyReason 的 fail-closed 只读态兜底，
    // 失败重试由各自 15s 链负责。
    await Promise.all([fetchUser(), fetchConfig()])
  }

  return {
    user,
    token,
    nodeMode,
    timezone,
    certRenewalDays,
    mfaWriteGuard,
    loading,
    intentionalLogout,
    currentPage,
    isLoggedIn,
    isSlaveNode,
    readOnlyReason,
    readOnlyMessage,
    login,
    verifyMfaLogin,
    refreshMfaStep,
    loginWithTicket,
    applyOIDCToken,
    logout,
    fetchUser,
    fetchConfig,
    setNodeMode,
    init,
    setCurrentPage,
    showToast,
  }
})
