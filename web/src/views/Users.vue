<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><UserFilled /></el-icon>
          用户认证
        </h2>
        <p class="page-desc">管理系统用户、权限与登录认证（OIDC）</p>
      </div>
      <el-tooltip :disabled="!isReadOnly" :content="readOnlyMessage">
        <div>
          <el-button type="primary" :disabled="isReadOnly || submitting" @click="openCreateForm">
            <el-icon><Plus /></el-icon>
            新建用户
          </el-button>
        </div>
      </el-tooltip>
    </div>

    <el-alert v-if="loadError" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
      <template #title>
        <div class="polling-error-title">
          <span>用户列表加载失败：表格为空不代表没有用户</span>
          <el-button link type="danger" @click="fetchUsers">立即重试</el-button>
        </div>
      </template>
    </el-alert>

    <el-card v-if="showForm" class="form-card">
      <template #header>
        <div class="card-header">
          <div class="card-title">
            <el-icon><User /></el-icon>
            <span>{{ editingUser ? '编辑用户' : '新增用户' }}</span>
          </div>
        </div>
      </template>
      <el-form :model="form" label-width="90px" :disabled="isReadOnly || submitting">
        <!-- 2026-09-19 用户裁定布局:左列 用户名/显示名称/角色;右列 密码组
             (编辑=新密码+确认新密码,创建=密码+确认密码);OIDC 用户右列示数据来源 -->
        <el-row :gutter="16">
          <el-col :span="12">
            <el-form-item label="用户名">
              <el-input v-model="form.username" :placeholder="editingUser ? '用户名不可修改' : '请输入用户名'" :disabled="!!editingUser" maxlength="50" />
            </el-form-item>
            <el-form-item label="显示名称">
              <el-input v-if="!editingIsOIDC" v-model="form.display_name" placeholder="选填" maxlength="50" />
              <el-input v-else :model-value="form.display_name" disabled />
            </el-form-item>
            <el-form-item label="角色">
              <!-- 初始化管理员（break-glass 入口）后端不可降级：编辑弹框直接禁用
                   角色控件并在下方给出原因——否则提交必 400，且只有全局 toast 无
                   字段定位，与同页「不可删除/禁用」的显式禁用口径不一致 -->
              <el-select v-model="form.role" style="width: 100%" :disabled="roleLocked">
                <el-option label="管理员" value="admin">
                  <el-tag type="danger" size="small">管理员</el-tag>
                </el-option>
                <el-option label="普通用户" value="user">
                  <el-tag type="info" size="small">普通用户</el-tag>
                </el-option>
              </el-select>
              <div v-if="editingUser?.is_setup_admin && !editingSelf" class="form-tip-line">系统初始化管理员不可降级</div>
              <div v-else-if="editingSelf" class="form-tip-line">不能修改自己的角色</div>
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <!-- v2.3.0:OIDC 用户密码/显示名源自 IdP,不可本地改(用户裁定) -->
            <template v-if="!editingIsOIDC">
              <el-form-item :label="editingUser ? '新密码' : '密码'">
                <el-input v-model="form.password" type="password" show-password minlength="8" maxlength="24" :placeholder="editingUser ? '留空则不修改密码（8-24位，仅限数字、大小写字母和特殊字符）' : '请输入8-24位，仅限数字、大小写字母和特殊字符密码'" />
              </el-form-item>
              <el-form-item label="确认新密码">
                <el-input v-model="form.password_confirm" type="password" show-password minlength="8" maxlength="24" placeholder="再次输入新密码" />
              </el-form-item>
            </template>
            <el-form-item v-else label="数据来源">
              <el-tag type="primary" effect="plain" size="small">OIDC 企业认证</el-tag>
            </el-form-item>
          </el-col>
        </el-row>
        <el-form-item>
          <el-button type="primary" :loading="submitting" :disabled="submitting" @click="handleSubmit">保存</el-button>
          <el-button :disabled="submitting" @click="closeForm">取消</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card>
      <template #header>
        <div class="card-header">
          <div class="card-title">
            <el-icon><User /></el-icon>
            <span>用户列表</span>
          </div>
          <div v-if="authStore.user?.role === 'admin'" class="oidc-entry-inline">
            <el-tag v-if="oidcEnabled" type="success" size="small" effect="light">OIDC 已启用</el-tag>
            <el-tag v-else-if="oidcConfigured" type="info" size="small" effect="plain">OIDC 已配置</el-tag>
            <el-tag v-if="oidcStatusError" type="info" size="small" effect="plain">OIDC 状态读取失败</el-tag>
            <el-button v-if="oidcStatusError" size="small" text @click="fetchOIDCStatus()">重试</el-button>
            <el-button size="small" text type="primary" :disabled="isReadOnly" @click="oidcOpen = true">{{ oidcConfigured ? 'OIDC 设置' : '配置 OIDC' }}</el-button>
          </div>
        </div>
      </template>
      <el-table :data="paginatedUsers" stripe :header-cell-style="{ background: '#f9fafb' }">
        <el-table-column label="用户" min-width="160">
          <template #default="{ row }">
            <div class="user-cell">
              <div class="user-avatar">
                <el-icon><User /></el-icon>
              </div>
              <div class="user-info">
                <div class="user-name">{{ row.username }}</div>
                <div class="user-display">{{ getDisplayName(row as UserListItem) || '-' }}</div>
              </div>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="角色" width="90">
          <template #default="{ row }">
            <el-tag :type="row.role === 'admin' ? 'danger' : 'info'" size="small" effect="plain">
              {{ row.role === 'admin' ? '管理员' : '用户' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="80" align="center">
          <template #default="{ row }">
            <!-- 只读态全部渲染但禁用，tooltip 显示原因（与规则页同构） -->
            <el-tooltip :disabled="!isReadOnly && !row.is_setup_admin" :content="row.is_setup_admin ? '系统初始化管理员不可禁用' : readOnlyMessage">
              <div>
                <el-switch
                  v-model="row.is_enabled"
                  :aria-label="`用户 ${row.username} 的启用状态`"
                  :loading="switchingIds.has(row.id)"
                  :disabled="isReadOnly || row.is_setup_admin || switchingIds.has(row.id) || submittingUserId === row.id || row.id === authStore.user?.id"
                  @change="(val: string | number | boolean) => handleToggleStatus(row.id, val === true)"
                />
              </div>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="创建时间" min-width="160">
          <template #default="{ row }">
            <span class="text-secondary">{{ formatDate(row.created_at) || '-' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="最后登录" min-width="160">
          <template #default="{ row }">
            <span class="text-secondary">{{ formatDate(row.last_login) || '-' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="来源" width="90" align="center">
          <template #default="{ row }">
            <el-tag :type="row.auth_provider === 'oidc' ? 'warning' : 'info'" size="small" effect="plain">{{ row.auth_provider === 'oidc' ? 'OIDC' : '本地' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="MFA" width="110" align="center">
          <template #default="{ row }">
            <!-- 用户页只做账户管理（重置 MFA）；启用/关闭/重置的个人自助在个人资料弹框。
                 只读态保留操作位并禁用，不隐藏。 -->
            <el-tooltip :disabled="!isReadOnly && row.auth_provider !== 'oidc' && row.mfa_enabled" :content="row.auth_provider === 'oidc' ? 'OIDC 用户的 MFA 由身份提供商管理' : (!row.mfa_enabled ? '该用户未启用 MFA' : readOnlyMessage)">
              <div>
                <el-button type="warning" link size="small" :disabled="isReadOnly || row.auth_provider === 'oidc' || !row.mfa_enabled || submitting || submittingUserId === row.id || operatingUserIds.has(row.id) || switchingIds.has(row.id)" @click="resetMfa(row as UserListItem)">
                  重置 MFA
                </el-button>
              </div>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="200" fixed="right" align="center">
          <template #default="{ row }">
            <div class="operation-buttons">
            <el-tooltip :disabled="!isReadOnly" :content="readOnlyMessage">
              <div>
                <el-button type="primary" link size="small" :disabled="isReadOnly || submitting" @click="editUser(row as UserListItem)">
                  编辑
                </el-button>
              </div>
            </el-tooltip>
            <el-tooltip :disabled="!isReadOnly && row.auth_provider !== 'oidc'" :content="row.auth_provider === 'oidc' ? 'OIDC 用户的密码由身份提供商管理' : readOnlyMessage">
              <div>
                <el-button type="warning" link size="small" :disabled="isReadOnly || row.auth_provider === 'oidc' || submitting || submittingUserId === row.id || operatingUserIds.has(row.id) || switchingIds.has(row.id)" @click="resetPassword(row as UserListItem)">
                  重置密码
                </el-button>
              </div>
            </el-tooltip>
            <el-tooltip :disabled="!isReadOnly && row.id !== authStore.user?.id && !row.is_setup_admin" :content="row.is_setup_admin ? '系统初始化管理员不可删除' : (row.id === authStore.user?.id ? '不能删除当前登录账户' : readOnlyMessage)">
              <div>
                <el-button type="danger" link size="small" :disabled="isReadOnly || row.is_setup_admin || row.id === authStore.user?.id || submitting || submittingUserId === row.id || operatingUserIds.has(row.id) || switchingIds.has(row.id)" @click="deleteUser(row as UserListItem)">
                  删除
                </el-button>
              </div>
            </el-tooltip>
            </div>
          </template>
        </el-table-column>
      </el-table>
      <div style="margin-top: 16px; display: flex; justify-content: flex-end;">
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :total="users.length"
          :page-sizes="[10, 20, 50]"
          layout="total, sizes, prev, pager, next"
          background
        />
      </div>
    </el-card>


    <OIDCSettings v-model="oidcOpen" @status="onOIDCStatus" />

    <!-- 统一确认/输入弹框:重置密码 / 修改密码 / 重置 MFA(替代 ElMessageBox,
         与全站 icon+标题+副标题弹框语言一致)。 -->
    <el-dialog v-model="lbDialog.visible" width="min(500px, 92vw)" :close-on-click-modal="false" @update:model-value="lbCancel()">
      <template #header>
        <DialogHeader
          :icon="lbDialog.spec?.icon === 'key' ? Key : lbDialog.spec?.icon === 'warning' ? Warning : Lock"
          :title="lbDialog.spec?.title || ''" :subtitle="lbDialog.spec?.subtitle"
          :tone="lbDialog.spec?.tone || 'primary'"
        />
      </template>
      <div v-if="lbDialog.spec?.message" class="lb-message">{{ lbDialog.spec.message }}</div>
      <div v-if="lbDialog.spec?.mode === 'reset-pwd'" class="lb-fields">
        <div class="lb-field">
          <div class="lb-field__label">新密码</div>
          <el-input v-model="lbDialog.newPwd" type="password" show-password maxlength="24" placeholder="8-24位，仅限数字、大小写字母和特殊字符，最长 24 位" />
        </div>
        <div class="lb-field">
          <div class="lb-field__label">确认新密码</div>
          <el-input v-model="lbDialog.newPwd2" type="password" show-password maxlength="24" placeholder="再次输入新密码" />
        </div>
      </div>
      <div v-else-if="lbDialog.spec?.mode === 'mfa-code'" class="lb-fields">
        <div class="lb-field">
          <div class="lb-field__label">验证码</div>
          <el-input v-model="lbDialog.code" placeholder="当前 MFA 的 6 位验证码或恢复代码" />
        </div>
      </div>
      <template #footer>
        <el-button @click="lbCancel">取消</el-button>
        <el-button type="primary" @click="lbConfirm">{{ lbDialog.spec?.confirmText || '确定' }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import OIDCSettings from '@/views/settings/OIDCSettings.vue'
import { computed, reactive, ref, watch, onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { request, ApiRequestError, mfaAwareSuccess, normalizeMfaCodeInput, validateMfaCodeInput } from '@/utils/api'
import { formatDate } from '@/utils/date'
import { ElMessageBox, ElMessage } from 'element-plus'
import { UserFilled, User, Plus, Key, Lock, Warning } from '@element-plus/icons-vue'
import DialogHeader from '@/components/DialogHeader.vue'
import { useClampedPagination } from '@/composables/useClampedPagination'
import { missingNewPasswordMessage, validatePassword, validateUsername } from '@/utils/credentials'
import { rollbackUserStatus } from '@/utils/userStatus'
import type { APIResponse, UserListItem } from '@/types'
const oidcOpen = ref(false)
const oidcEnabled = ref(false)
const oidcConfigured = ref(false)
// 状态读取失败（403 之外）：标签区提供重试入口，不再静默留白。
const oidcStatusError = ref(false)
const onOIDCStatus = (st: { enabled: boolean; configured: boolean }) => {
  oidcEnabled.value = st.enabled
  oidcConfigured.value = st.configured
}
// 挂载即拉取 OIDC 状态——此前仅靠弹框 emit 回填,标签/按钮文案在打开
// 「配置 OIDC」前恒为初始 false(已启用标签不显示、按钮误显「配置 OIDC」)。
// 与弹框 load 同源(/settings/oidc),configured 口径 = issuer 或 secret 非空。
const fetchOIDCStatus = async () => {
  try {
    const res = await request.get<{ data?: { enabled?: boolean; issuer?: string; has_secret?: boolean } }>('/settings/oidc', { silent: true })
    oidcEnabled.value = !!res.data?.enabled
    oidcConfigured.value = !!(res.data?.issuer || res.data?.has_secret)
    oidcStatusError.value = false
  } catch (error: unknown) {
    // 403=角色权限面（非管理员/从节点），属预期而非故障——静默；网络/5xx 等
    // 真实失败显性化并在标签区给重试入口（silent 下无全局 toast，不留白）。
    oidcStatusError.value = !(error instanceof ApiRequestError && error.status === 403)
  }
}

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.readOnlyReason !== null)
const users = ref<UserListItem[]>([])
// 列表加载失败与真实空列表不可区分 → 显性错误态 + 重试
const loadError = ref(false)
// 同口径：mfa_write_guard 读 authStore.fetchConfig 消费面（曾挂载单取
// GET /config 只为一个键，与 /config 的 15s 刷新重复；store ref 响应式，
// 挂载早于 fetchConfig 完成也会随后收敛）。首值 false = 守卫关闭的保守形态。
const mfaWriteGuard = computed(() => authStore.mfaWriteGuard)
const showForm = ref(false)

// 只读原因文案（从节点只读/非管理员只读/加载中）——操作列禁用 tooltip 统一口径
const readOnlyMessage = computed(() => authStore.readOnlyMessage)
const submitting = ref(false)
const submittingUserId = ref<number | null>(null)
const operatingUserIds = ref(new Set<number>())
const currentPage = ref(1)
const pageSize = ref(10)
// （复用优先）：分页切片 + 页越界夹紧收敛到 useClampedPagination 单源——
// 原实现手写 slice 并在 fetchUsers 内手工夹紧 maxPage（与 Rules/BlockPages/
// Policies 的共享范式并存两份）。
const { pagedItems: paginatedUsers } = useClampedPagination(users, currentPage, pageSize)

const openCreateForm = () => {
  if (isReadOnly.value || submitting.value) return
  editingUser.value = null
  form.value = { username: '', password: '', password_confirm: '', display_name: '', role: 'user' }
  showForm.value = true
}
const editingIsOIDC = computed(() => editingUser.value?.auth_provider === 'oidc')
const editingSelf = computed(() => editingUser.value !== null && editingUser.value.id === authStore.user?.id)
const editingUser = ref<UserListItem | null>(null)
// 角色不可改：编辑自己（会把自己降级/失权）与初始化管理员（后端 protected 恒 400）
// 两条同因不同源的锁合流——模板与提交载荷共用本判据。
const roleLocked = computed(() => editingSelf.value || editingUser.value?.is_setup_admin === true)
const switchingIds = ref(new Set<number>())
let usersRequestSeq = 0
const form = ref({
  username: '',
  password: '',
  // 2026-09-19 用户裁定:密码修改需二次确认——填写新密码时须一致
  password_confirm: '',
  display_name: '',
  role: 'user',
})

const getDisplayName = (row: UserListItem): string => {
  return row.display_name || ''
}

const fetchUsers = async () => {
  const requestSeq = ++usersRequestSeq
  try {
    const res = await request.get<APIResponse<UserListItem[]>>('/users')
    if (requestSeq === usersRequestSeq) {
      users.value = res.data || []
      loadError.value = false
      // 页越界夹紧归 useClampedPagination——不再手工重算 maxPage。
    }
  } catch (error: unknown) {
    // Error toast is already shown by the global axios interceptor; swallow here
    // so fire-and-forget refresh calls don't surface as unhandled rejections.
    console.error('Failed to fetch users:', error)
    if (requestSeq === usersRequestSeq) loadError.value = true
  }
}

const handleSubmit = async () => {
  if (isReadOnly.value || submitting.value) return
  // 用户名前置校验（对齐后端 CreateUser 的 min=3,max=50、字符集
  // ^[a-z][a-z0-9]*$ 与 Login.vue setup 口径）——仅创建路径：编辑态用户名
  // 输入恒禁用（后端支持改名，但 UI 不提供入口），不存在改名校验分支。
  if (!editingUser.value && !form.value.username) {
    ElMessage.warning('请输入用户名')
    return
  }
  if (!editingUser.value) {
    const usernameError = validateUsername(form.value.username)
    if (usernameError) {
      ElMessage.warning(usernameError)
      return
    }
  }
  if (!editingUser.value && !form.value.password) {
    ElMessage.warning('请输入密码')
    return
  }
  const passwordError = validatePassword(form.value.password)
  if (passwordError) {
    ElMessage.warning(passwordError)
    return
  }
  // 只填「确认新密码」而「新密码」留空：载荷会省略 password（后端=不修改），
  // 却回报「更新成功」——管理员会误信已重置。必须在「两次不一致」判定之前拦下。
  const missingPassword = missingNewPasswordMessage(form.value.password, form.value.password_confirm)
  if (missingPassword) {
    ElMessage.warning(missingPassword)
    return
  }
  if (form.value.password && form.value.password !== form.value.password_confirm) {
    ElMessage.warning('两次输入的新密码不一致')
    return
  }
  submittingUserId.value = editingUser.value?.id ?? null
  submitting.value = true
  try {
    try {
      await ElMessageBox.confirm(
        editingUser.value
          ? `将更新用户「${form.value.username}」的账号资料与权限，是否继续？`
          : `将创建用户「${form.value.username}」（角色：${form.value.role === 'admin' ? '管理员' : '普通用户'}），是否继续？`,
        editingUser.value ? '确认编辑用户' : '确认创建用户',
        { type: 'warning', confirmButtonText: '确认保存', cancelButtonText: '取消' },
      )
    } catch { return }
    if (editingUser.value) {
      const editingSelfRow = editingUser.value.id === authStore.user?.id
      // OIDC 用户的 username/display_name/password 源自 IdP(后端守卫必 400)——
      // 管理员编辑仅提交本地管理语义字段(角色),undefined 不会被序列化。
      const oidcTarget = editingUser.value.auth_provider === 'oidc'
      await request.put(`/users/${editingUser.value.id}`, {
        username: oidcTarget ? undefined : form.value.username,
        role: roleLocked.value ? undefined : form.value.role,
        display_name: oidcTarget ? undefined : form.value.display_name,
        password: oidcTarget ? undefined : (form.value.password || undefined),
      })
      // admin 编辑本人行且提交了密码：同，干净登出替代死 token 误报。
      if (editingSelfRow && form.value.password) {
        authStore.showToast('success', '密码已重置，请重新登录')
        await authStore.logout()
        return
      }
      mfaAwareSuccess('更新成功')
    } else {
      // 创建用户显式白名单字段上行——form 含 password_confirm
      // 仅前端二次确认用,不随请求提交。
      await request.post('/users', {
        username: form.value.username,
        password: form.value.password,
        display_name: form.value.display_name,
        role: form.value.role,
      })
      mfaAwareSuccess('创建成功')
    }
  } catch (error: unknown) {
    // Error toast is already shown by the global axios interceptor.
    console.error('Failed to submit user:', error)
    return
  } finally {
    submitting.value = false
    submittingUserId.value = null
  }
  closeForm()
  fetchUsers()
}


const editUser = (user: UserListItem) => {
  // 非管理员整页只读（个人自助在个人资料弹框）
  if (isReadOnly.value || submitting.value) return
  // 复审回归修复：编辑必须置 editingUser，否则 handleSubmit 走 POST 误建用户
  editingUser.value = user
  form.value = {
    username: user.username,
    password: '',
    password_confirm: '',
    display_name: getDisplayName(user),
    role: user.role,
  }
  showForm.value = true
}

const closeForm = () => {
  if (submitting.value) return
  showForm.value = false
  editingUser.value = null
  form.value = { username: '', password: '', password_confirm: '', display_name: '', role: 'user' }
}

const isCancelError = (error: unknown): boolean => error === 'cancel' || error === 'close'

const deleteUser = async (row: UserListItem) => {
  const id = row.id
  if (isReadOnly.value || submitting.value || submittingUserId.value === id || operatingUserIds.value.has(id) || switchingIds.value.has(id)) return
  operatingUserIds.value.add(id)
  try {
    const consequence = row.auth_provider === 'oidc'
      ? '同一身份下次 SSO 登录会重新开户（默认普通用户，原角色与禁用状态不继承）。如需撤销访问并保留原身份，请取消并改用禁用。'
      : '删除后无法恢复，该用户的会话与 API 密钥将失效。'
    await ElMessageBox.confirm(`将删除用户「${row.username}」。${consequence}`, '删除用户', { type: 'warning', confirmButtonText: '确认删除', cancelButtonText: '取消' })
    const res = await request.delete<APIResponse>(`/users/${id}`)
    mfaAwareSuccess(res.message || '删除成功')
    fetchUsers()
  } catch (error: unknown) {
    if (isCancelError(error)) return
    // HTTP/network failures are toasted globally; retain a local failure branch
    // for unexpected non-Error rejections instead of misclassifying them as cancel.
    console.error('Failed to delete user:', error)
    if (!(error instanceof Error)) ElMessage.error('删除失败，请重试')
  } finally {
    operatingUserIds.value.delete(id)
  }
}

const handleToggleStatus = async (id: number, isEnabled: boolean) => {
  if (isReadOnly.value || switchingIds.value.has(id) || submittingUserId.value === id || operatingUserIds.value.has(id)) return
  // 占位先于确认（同 TaskMonitor 范式）：确认框悬挂期也属「操作在途」，
  // 没有门时连点会叠出第二个确认框并重复写状态。
  switchingIds.value.add(id)
  const row = users.value.find((item) => item.id === id)
  try {
    if (!isEnabled) {
      // 禁用与删除同为破坏性操作，与 deleteUser/toggleRule 保持同款二次确认。
      try {
        const consequence = row?.auth_provider === 'oidc'
          ? 'SSO 登录将被拒绝；原身份、角色与绑定保留，重新启用即可恢复。'
          : '禁用后该用户无法登录，但账号与配置保留。'
        await ElMessageBox.confirm(`将禁用用户「${row?.username || id}」。${consequence}`, '禁用用户', { type: 'warning', confirmButtonText: '确认禁用', cancelButtonText: '取消' })
      } catch {
        // 取消确认时回滚乐观开关——el-switch 已先行翻转 row.is_enabled。
        rollbackUserStatus(users.value, id, isEnabled)
        return
      }
    }
    const res = await request.put<APIResponse>(`/users/${id}/status`, { is_enabled: isEnabled })
    mfaAwareSuccess(res.message || (isEnabled ? '已启用用户' : '已禁用用户'))
    fetchUsers()
  } catch (e) {
    rollbackUserStatus(users.value, id, isEnabled)
    fetchUsers()
  } finally {
    switchingIds.value.delete(id)
  }
}

// ── 统一确认/输入弹框(重置密码 / 修改密码 / 重置 MFA)──
type LbDialogSpec = {
  title: string
  subtitle?: string
  message?: string
  icon: 'lock' | 'key' | 'warning'
  tone?: 'primary' | 'warning'
  mode: 'reset-pwd' | 'mfa-code' | 'confirm'
  confirmText?: string
}
const lbDialog = reactive({
  visible: false,
  spec: null as LbDialogSpec | null,
  newPwd: '',
  newPwd2: '',
  code: '',
  resolve: null as ((r: { ok: boolean; newPwd?: string; code?: string }) => void) | null,
})
function lbOpen(spec: LbDialogSpec): Promise<{ ok: boolean; newPwd?: string; code?: string }> {
  lbDialog.spec = spec
  lbDialog.newPwd = ''
  lbDialog.newPwd2 = ''
  lbDialog.code = ''
  lbDialog.visible = true
  return new Promise((resolve) => { lbDialog.resolve = resolve })
}
function lbCancel() {
  lbDialog.visible = false
  lbDialog.resolve?.({ ok: false })
  lbDialog.resolve = null
}
function lbConfirm() {
  const mode = lbDialog.spec?.mode
  if (mode === 'reset-pwd') {
    const passwordError = validatePassword(lbDialog.newPwd)
    if (passwordError) { ElMessage.error(passwordError); return }
    if (!lbDialog.newPwd) { ElMessage.error('请输入密码'); return }
    if (lbDialog.newPwd !== lbDialog.newPwd2) { ElMessage.error('两次输入的新密码不一致'); return }
  } else if (mode === 'mfa-code') {
    if (!validateMfaCodeInput(lbDialog.code)) { ElMessage.error('请输入验证码或恢复代码'); return }
  }
  lbDialog.visible = false
  lbDialog.resolve?.({
    ok: true,
    newPwd: lbDialog.newPwd || undefined,
    code: lbDialog.code ? normalizeMfaCodeInput(lbDialog.code) : undefined,
  })
  lbDialog.resolve = null
}

// 签名与调用点同口径：表格行整体传入，函数内统一取 row.id。（历史事故：签名收
// id、调用点传整行，请求路径变成 /users/[object Object]/reset-password——当时
// 模板属性不参与类型检查故未被拦，现已由 strictTemplates + 插槽 `as UserListItem`
// 收窄兜住：签名与调用点不一致即 typecheck 失败。）
const resetPassword = async (row: UserListItem) => {
  const id = row.id
  if (isReadOnly.value || submitting.value || submittingUserId.value === id || operatingUserIds.value.has(id) || switchingIds.value.has(id)) return
  operatingUserIds.value.add(id)
  const isSelf = id === authStore.user?.id
  // 用户管理端点重置密码（不验当前密码，重置后吊销全部会话）；权限=admin——
  // 非管理员整页只读，个人改密走个人资料弹框（需当前密码）。
  try {
    let newPassword = ''
    const r = await lbOpen({
      title: '重置密码',
      subtitle: `为「${row.username}」设置新密码`,
      message: '重置后该用户的全部登录会话将被吊销，账户锁定状态一并清除。',
      icon: 'key', tone: 'warning', mode: 'reset-pwd', confirmText: '确认重置',
    })
    if (!r.ok) return
    newPassword = r.newPwd ?? ''
    if (newPassword) {
      await request.post(`/users/${row.id}/reset-password`, { new_password: newPassword })
      if (isSelf) {
        // 管理员重置本人密码:重置端点递增 pwd_ver 吊销自身会话——干净登出
        // (对齐 AppLayout.saveProfile / ),避免死 token 误报会话失效
        authStore.showToast('success', '密码已重置，请重新登录')
        await authStore.logout()
        return
      }
      mfaAwareSuccess('密码重置成功')
    }
  } catch (e) {
    // lbOpen 取消/关闭以 {ok:false} **resolve**（不走 reject），上面已
    // `if (!r.ok) return` 处理——此处不存在 'cancel'/'close' 字符串拒绝（那些是
    // ElMessageBox 时代残留）。请求本身不带 silent，失败已由全局拦截器 toast，
    // 此处仅记录；仅对无法归因到拦截器的意外拒绝（非 Error 值）兜底提示。
    console.error('Failed to reset password:', e)
    if (!(e instanceof Error)) {
      ElMessage.error('密码重置失败，请重试')
    }
  } finally {
    operatingUserIds.value.delete(id)
  }
}

// 调整（用户裁决）：重置需确认 + 操作者 MFA 校验（自己启用过 MFA 则
// 弹码验证——后端同门校验）；admin 或本人可重置。
const resetMfa = async (row: UserListItem): Promise<void> => {
  if (isReadOnly.value || submitting.value || submittingUserId.value === row.id || operatingUserIds.value.has(row.id) || switchingIds.value.has(row.id)) return
  operatingUserIds.value.add(row.id)
  try {
    const selfRow = users.value.find(u => u.id === authStore.user?.id)
    const operatorMfa = row.id === authStore.user?.id ? true : (selfRow?.mfa_enabled ?? false)
    let code = ''
    if (operatorMfa) {
      if (mfaWriteGuard.value) {
        // 守卫开启时后端第一层已豁免（守卫完成验码），对话框退化为纯确认——
        // 保留后果说明与确认/取消，不再索取当前时间片验证码（索取也无码可用：
        // 同片刚被守卫/登录消费，重放保护必拒）。
        const r = await lbOpen({
          title: '重置 MFA',
          subtitle: `重置「${row.username}」的两步验证`,
          message: '重置后该用户登录不再需要验证码，需重新绑定。',
          icon: 'warning', tone: 'warning', mode: 'confirm', confirmText: '确认重置',
        })
        if (!r.ok) return
      } else {
        // 用户裁决（N+10）：重置 MFA 与登录是仅有的两个允许恢复码的入口
        //（后端 MFAVerifyCode 消费口径）；step-up 写守卫链已收口为仅 TOTP。
        const r = await lbOpen({
          title: '重置 MFA',
          subtitle: `重置「${row.username}」的两步验证`,
          message: '重置后该用户登录不再需要验证码，需重新绑定。',
          icon: 'warning', tone: 'warning', mode: 'mfa-code', confirmText: '确认重置',
        })
        if (!r.ok) return
        code = r.code ?? ''
      }
    } else {
      const r = await lbOpen({
        title: '重置 MFA',
        subtitle: `重置用户「${row.username}」的两步验证`,
        message: '重置后该用户登录不再需要验证码，需自行重新绑定。',
        icon: 'warning', tone: 'warning', mode: 'confirm', confirmText: '确认重置',
      })
      if (!r.ok) return
    }
    await request.post(`/users/${row.id}/mfa/reset`, { code }, { silent: true })
    mfaAwareSuccess('已重置 MFA')
    await fetchUsers()
  } catch (error: unknown) {
    if (isCancelError(error)) return
    // api.ts 全局 428 重试流已 toast 并打标——此处跳过二次弹窗；
    // 未打标的（如锁定开关关闭时端点自身的 401「验证码错误」）仍在此展示。
    if ((error as { mfaSurfaced?: boolean }).mfaSurfaced) {
      console.error('MFA reset failed:', error)
      return
    }
    ElMessage.error(error instanceof Error ? error.message : '重置失败')
  } finally {
    operatingUserIds.value.delete(row.id)
  }
}

// /settings/oidc 挂在 admin 组（非管理员必 403）且 OIDC 入口仅管理员渲染——
// 请求与消费面同门。以 store 角色为响应式通道（immediate）：fetchUser 瞬时
// 失败时角色先为 undefined、由 store 15s 重试补回，一次性 onMounted 判定会
// 永久错过该窗口（标签不出现、按钮误显「配置 OIDC」）。
watch(() => authStore.user?.role, (role) => {
  if (role === 'admin') void fetchOIDCStatus()
}, { immediate: true })

onMounted(() => {
  fetchUsers()
})
</script>

<style scoped>
.lb-message { font-size: 13.5px; color: var(--text-regular, #374151); line-height: 1.7; margin-bottom: 4px; }
.lb-fields { display: flex; flex-direction: column; gap: 14px; margin-top: 12px; }
.lb-field__label { font-size: 13px; color: var(--text-regular, #374151); margin-bottom: 6px; }
.oidc-entry-inline { display: flex; align-items: center; gap: 8px; margin-left: auto; }

.form-card { margin-bottom: 20px; }

.card-header {
  display: flex;
  align-items: center;
}

.card-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 14px;
  font-weight: 600;
  color: #111827;
}

.user-cell { display: flex; align-items: center; gap: 12px; }

.user-avatar {
  width: 36px;
  height: 36px;
  border-radius: 6px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #eff6ff;
}

.user-name { font-weight: 500; color: #111827; font-size: 14px; }
.user-display { font-size: 12px; color: #9ca3af; }


/* 操作列横向一行（与 Rules.vue 同款 flex 布局；禁用项保持占位 + hover 原因） */
.operation-buttons { display: flex; gap: 2px; justify-content: center; align-items: center; flex-wrap: wrap; }
.operation-buttons :deep(.el-button) { margin: 0; padding: 2px 4px; min-width: auto; }
</style>
