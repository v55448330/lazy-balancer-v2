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
      <el-button type="primary" :disabled="isReadOnly || submitting" @click="openCreateForm">
        <el-icon><Plus /></el-icon>
        新建用户
      </el-button>
    </div>

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
              <el-select v-model="form.role" style="width: 100%">
                <el-option label="管理员" value="admin">
                  <el-tag type="danger" size="small">管理员</el-tag>
                </el-option>
                <el-option label="普通用户" value="user">
                  <el-tag type="info" size="small">普通用户</el-tag>
                </el-option>
              </el-select>
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <!-- v2.3.0:OIDC 用户密码/显示名源自 IdP,不可本地改(用户裁定) -->
            <template v-if="!editingIsOIDC">
              <el-form-item :label="editingUser ? '新密码' : '密码'">
                <el-input v-model="form.password" type="password" show-password minlength="6" maxlength="72" :placeholder="editingUser ? '留空则不修改密码（至少6位）' : '请输入至少6位密码'" />
              </el-form-item>
              <el-form-item label="确认新密码">
                <el-input v-model="form.password_confirm" type="password" show-password minlength="6" maxlength="72" placeholder="再次输入新密码" />
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
                <div class="user-display">{{ getDisplayName(row) || '-' }}</div>
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
            <el-switch
              v-model="row.is_enabled"
              :loading="switchingIds.has(row.id)"
              :disabled="isReadOnly || switchingIds.has(row.id) || submittingUserId === row.id || row.id === authStore.user?.id"
              @change="(val: boolean) => handleToggleStatus(row.id, val)"
            />
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
        <el-table-column label="MFA" width="80" align="center">
          <template #default="{ row }">
            <el-tag v-if="row.auth_provider === 'oidc'" type="info" size="small" effect="plain">—</el-tag>
            <el-tag v-else :type="row.mfa_enabled ? 'success' : 'info'" size="small" effect="plain">
              {{ row.mfa_enabled ? '已启用' : '未启用' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="240" fixed="right" align="center">
          <template #default="{ row }">
            <el-button type="primary" link size="small" :disabled="isReadOnly || submitting" @click="editUser(row)">
              编辑
            </el-button>
            <el-button v-if="row.auth_provider !== 'oidc'" type="warning" link size="small" :disabled="isReadOnly || submittingUserId === row.id || operatingUserIds.has(row.id) || switchingIds.has(row.id)" @click="resetPassword(row.id)">
              重置密码
            </el-button>
            <el-button v-if="!row.mfa_enabled && row.auth_provider !== 'oidc' && row.id === authStore.user?.id" type="success" link size="small" :disabled="nodeModeSlave || submitting" @click="openMfaBinding(row)">
              启用 MFA
            </el-button>
            <el-button v-if="row.mfa_enabled && row.auth_provider !== 'oidc' && authStore.user?.role === 'admin'" type="warning" link size="small" :disabled="isReadOnly || submitting || submittingUserId === row.id || operatingUserIds.has(row.id) || switchingIds.has(row.id)" @click="resetMfa(row)">
              重置 MFA
            </el-button>
            <el-button v-if="row.id !== authStore.user?.id" type="danger" link size="small" :disabled="isReadOnly || submittingUserId === row.id || operatingUserIds.has(row.id) || switchingIds.has(row.id)" @click="deleteUser(row.id)">
              删除
            </el-button>
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

    <!-- R72 三次调整（用户裁决）：MFA 绑定向导从基础设置卡片迁到用户管理——
         点「启用 MFA」发起绑定：扫码 → 输码 → 恢复码。 -->
    <el-dialog v-model="mfaBinding.visible" width="min(520px, 92vw)" :close-on-click-modal="false" @closed="mfaBindingClosed">
      <template #header>
        <div class="dialog-header">
          <div class="dialog-header__icon dialog-header__icon--primary"><el-icon :size="18"><Lock /></el-icon></div>
          <div class="dialog-header__text">
            <div class="dialog-header__title">启用 MFA（两步验证）</div>
            <div class="dialog-header__subtitle">扫码绑定验证器 → 输码验证 → 保存恢复码</div>
          </div>
        </div>
      </template>
      <el-steps :active="mfaBinding.step" simple style="margin-bottom: 18px">
        <el-step title="扫码" />
        <el-step title="验证" />
        <el-step title="恢复码" />
      </el-steps>
      <div v-if="mfaBinding.step === 0" style="display: flex; flex-direction: column; align-items: center; gap: 10px">
        <div style="background: #fff; padding: 8px; border: 1px solid var(--el-border-color-lighter); border-radius: 4px">
          <canvas ref="mfaQrCanvas" width="220" height="220" />
        </div>
        <el-text type="info" size="small">无法扫码时手动输入密钥：</el-text>
        <el-text size="small" selectable style="font-family: monospace; background: var(--el-fill-color-light); padding: 4px 10px; border-radius: 3px; letter-spacing: 1px">{{ mfaBinding.secret }}</el-text>
        <el-text type="info" size="small">使用 Google/Microsoft Authenticator 等扫码</el-text>
      </div>
      <div v-else-if="mfaBinding.step === 1" style="display: flex; flex-direction: column; align-items: center; gap: 14px">
        <el-input
          v-model="mfaBinding.code"
          placeholder="请输入 6 位验证码"
          size="large"
          maxlength="6"
          style="width: 240px; text-align: center; font-size: 18px; letter-spacing: 6px"
          @input="mfaBinding.code = mfaBinding.code.replace(/\D/g, '')"
        />
        <el-text type="info" size="small">为「{{ mfaBinding.username }}」绑定</el-text>
      </div>
      <div v-else style="display: flex; flex-direction: column; gap: 10px">
        <el-alert type="warning" :closable="false" show-icon title="恢复代码仅此一次显示"
          description="每个恢复代码只能使用一次，请妥善保存。丢失验证器时用于登录。" />
        <div style="display: grid; grid-template-columns: repeat(2, 200px); gap: 8px 24px; margin-top: 6px">
          <div v-for="code in mfaBinding.recoveryCodes" :key="code" style="font-family: monospace; font-size: 14px; background: var(--el-fill-color-light); padding: 6px 10px; border-radius: 3px; text-align: center; user-select: all">{{ code }}</div>
        </div>
      </div>
      <template #footer>
        <el-button v-if="mfaBinding.step === 0" @click="mfaBinding.visible = false">取消</el-button>
        <el-button v-if="mfaBinding.step === 0" type="primary" @click="mfaBinding.step = 1">下一步</el-button>
        <el-button v-if="mfaBinding.step === 1" @click="mfaBinding.step = 0">上一步</el-button>
        <el-button v-if="mfaBinding.step === 1" type="primary" :loading="mfaBinding.loading" @click="activateMfa">验证并启用</el-button>
        <el-button v-if="mfaBinding.step === 2" @click="copyMfaRecovery">复制全部</el-button>
        <el-button v-if="mfaBinding.step === 2" type="primary" @click="mfaBinding.visible = false">我已保存</el-button>
      </template>
    </el-dialog>
    <!-- 统一确认/输入弹框:重置密码 / 修改密码 / 重置 MFA(替代 ElMessageBox,
         与全站 icon+标题+副标题弹框语言一致)。 -->
    <el-dialog v-model="lbDialog.visible" width="min(500px, 92vw)" :close-on-click-modal="false" @update:model-value="lbCancel()">
      <template #header>
        <div class="dialog-header">
          <div class="dialog-header__icon" :class="`dialog-header__icon--${lbDialog.spec?.tone || 'primary'}`">
            <el-icon :size="18"><component :is="lbDialog.spec?.icon === 'key' ? Key : lbDialog.spec?.icon === 'warning' ? Warning : Lock" /></el-icon>
          </div>
          <div class="dialog-header__text">
            <div class="dialog-header__title">{{ lbDialog.spec?.title }}</div>
            <div v-if="lbDialog.spec?.subtitle" class="dialog-header__subtitle">{{ lbDialog.spec.subtitle }}</div>
          </div>
        </div>
      </template>
      <div v-if="lbDialog.spec?.message" class="lb-message">{{ lbDialog.spec.message }}</div>
      <div v-if="lbDialog.spec?.mode === 'reset-pwd'" class="lb-fields">
        <div class="lb-field">
          <div class="lb-field__label">新密码</div>
          <el-input v-model="lbDialog.newPwd" type="password" show-password maxlength="72" placeholder="至少 6 位，最长 72 位" />
        </div>
        <div class="lb-field">
          <div class="lb-field__label">确认新密码</div>
          <el-input v-model="lbDialog.newPwd2" type="password" show-password maxlength="72" placeholder="再次输入新密码" />
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
const oidcOpen = ref(false)
const oidcEnabled = ref(false)
const oidcConfigured = ref(false)
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
  } catch {
    // 静默降级:非管理员/从节点 403 不弹 toast,标签维持隐藏(入口本身按角色收口)
  }
}
import { computed, nextTick, reactive, ref, onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { request, mfaAwareSuccess, normalizeMfaCodeInput, validateMfaCodeInput } from '@/utils/api'
import { formatDate } from '@/utils/date'
import { ElMessageBox, ElMessage } from 'element-plus'
import { UserFilled, User, Plus, Key, Lock, Warning } from '@element-plus/icons-vue'
import QRCode from 'qrcode'
import type { APIResponse, UserListItem } from '@/types'

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.readOnlyReason !== null)
const users = ref<UserListItem[]>([])
const mfaWriteGuard = ref(false)
const showForm = ref(false)
const submitting = ref(false)
const submittingUserId = ref<number | null>(null)
const operatingUserIds = ref(new Set<number>())
const currentPage = ref(1)
const pageSize = ref(10)
const paginatedUsers = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  return users.value.slice(start, start + pageSize.value)
})

const openCreateForm = () => {
  if (submitting.value) return
  editingUser.value = null
  form.value = { username: '', password: '', password_confirm: '', display_name: '', role: 'user' }
  showForm.value = true
}
const editingIsOIDC = computed(() => editingUser.value?.auth_provider === 'oidc')
const editingUser = ref<UserListItem | null>(null)
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
      const maxPage = Math.max(1, Math.ceil(users.value.length / pageSize.value))
      if (currentPage.value > maxPage) currentPage.value = maxPage
    }
  } catch (error: unknown) {
    // Error toast is already shown by the global axios interceptor; swallow here
    // so fire-and-forget refresh calls don't surface as unhandled rejections.
    console.error('Failed to fetch users:', error)
  }
}

const handleSubmit = async () => {
  if (isReadOnly.value || submitting.value) return
  if ((!editingUser.value && !form.value.password) || (form.value.password && form.value.password.length < 6)) {
    ElMessage.warning('密码长度至少6位')
    return
  }
  if (form.value.password && form.value.password !== form.value.password_confirm) {
    ElMessage.warning('两次输入的新密码不一致')
    return
  }
  submittingUserId.value = editingUser.value?.id ?? null
  submitting.value = true
  try {
    if (editingUser.value) {
      const editingSelf = editingUser.value.id === authStore.user?.id
      // OIDC 用户的 username/display_name/password 源自 IdP(后端守卫必 400)——
      // 管理员编辑仅提交本地管理语义字段(角色),undefined 不会被序列化。
      const oidcTarget = editingUser.value.auth_provider === 'oidc'
      await request.put(`/users/${editingUser.value.id}`, {
        username: oidcTarget ? undefined : form.value.username,
        role: form.value.role,
        display_name: oidcTarget ? undefined : form.value.display_name,
        password: oidcTarget ? undefined : (form.value.password || undefined),
      })
      // admin 编辑本人行且提交了密码：同 B4-I2，干净登出替代死 token 误报。
      if (editingSelf && form.value.password) {
        authStore.showToast('success', '密码已修改，请重新登录')
        await authStore.logout()
        return
      }
      mfaAwareSuccess('更新成功')
    } else {
      // FE43-5(第 43 轮):创建用户显式白名单字段上行——form 含 password_confirm
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

const nodeModeSlave = computed(() => authStore.readOnlyReason === 'slave')

const editUser = (user: UserListItem) => {
  // 2026-09-19 用户裁定（覆盖 R72 六次）：非管理员只读范围含用户认证页——
  // 不允许编辑任何行（含本人），修改密码/个人资料只走右上角个人资料弹框；
  // 编辑表单（含其密码字段=重置语义，不验当前密码）为管理员专属，统一走
  // admin PUT 端点。
  if (isReadOnly.value || submitting.value) return
  // 复审 P1 回归修复：编辑必须置 editingUser，否则 handleSubmit 走 POST 误建用户
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

const deleteUser = async (id: number) => {
  if (isReadOnly.value || submittingUserId.value === id || operatingUserIds.value.has(id) || switchingIds.value.has(id)) return
  operatingUserIds.value.add(id)
  try {
    await ElMessageBox.confirm('确定要删除这个用户吗？', '警告', { type: 'warning' })
    await request.delete(`/users/${id}`)
    mfaAwareSuccess('删除成功')
    fetchUsers()
  } catch (e) {
    // User cancelled, do nothing
  } finally {
    operatingUserIds.value.delete(id)
  }
}

const handleToggleStatus = async (id: number, isEnabled: boolean) => {
  if (isReadOnly.value || switchingIds.value.has(id) || submittingUserId.value === id || operatingUserIds.value.has(id)) return
  if (!isEnabled) {
    // 禁用与删除同为破坏性操作，与 deleteUser/toggleRule 保持同款二次确认。
    try {
      await ElMessageBox.confirm('确定要禁用这个用户吗？禁用后该用户将无法登录。', '警告', { type: 'warning' })
    } catch {
      // R62 D-2：取消确认时回滚乐观开关——el-switch 已先行翻转 row.is_enabled，
      // 不回滚则 UI 显示「已禁用」而服务端仍启用，直到下次 fetchUsers 才自愈。
      const row = users.value.find(u => u.id === id)
      if (row) row.is_enabled = !isEnabled
      return
    }
  }
  switchingIds.value.add(id)
  try {
    await request.put(`/users/${id}/status`, { is_enabled: isEnabled })
    mfaAwareSuccess(isEnabled ? '已启用用户' : '已禁用用户')
    fetchUsers()
  } catch (e) {
    fetchUsers() // revert on failure
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
    if (!lbDialog.newPwd || lbDialog.newPwd.length < 6) { ElMessage.error('密码长度至少6位'); return }
    if (lbDialog.newPwd.length > 72) { ElMessage.error('密码长度不能超过72位'); return }
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

const resetPassword = async (id: number) => {
  if (isReadOnly.value || submittingUserId.value === id || operatingUserIds.value.has(id) || switchingIds.value.has(id)) return
  operatingUserIds.value.add(id)
  const isSelf = id === authStore.user?.id
  // 2026-09-19 用户裁定:重置密码为管理员专属(经用户管理端点重置任意用户含
  // 本人,不验当前密码——重置语义);非管理员的密码修改只走右上角个人资料
  // 弹框(AppLayout,当前密码确认),本页对其只读。
  try {
    let newPassword = ''
    const username = users.value.find((u) => u.id === id)?.username ?? ''
    const r = await lbOpen({
      title: '重置密码',
      subtitle: `为「${username}」设置新密码`,
      message: '重置后该用户的全部登录会话将被吊销，账户锁定状态一并清除。',
      icon: 'key', tone: 'warning', mode: 'reset-pwd', confirmText: '确认重置',
    })
    if (!r.ok) return
    newPassword = r.newPwd ?? ''
    if (newPassword) {
      await request.post(`/users/${id}/reset-password`, { new_password: newPassword })
      if (isSelf) {
        // 管理员重置本人密码:重置端点递增 pwd_ver 吊销自身会话——干净登出
        // (对齐 AppLayout.saveProfile / B4-I2),避免死 token 误报会话失效
        authStore.showToast('success', '密码已重置，请重新登录')
        await authStore.logout()
        return
      }
      mfaAwareSuccess('密码重置成功')
    }
  } catch (e) {
    // ElMessageBox 取消/关闭以字符串形式 reject，静默放行；请求本身不带 silent，
    // 失败已由全局拦截器 toast（此处仅记录防吞线索）；仅对无法归因到拦截器的
    // 意外拒绝（非 Error 值）兜底提示，避免二次弹窗。
    if (e === 'cancel' || e === 'close') return
    console.error('Failed to reset password:', e)
    if (!(e instanceof Error)) {
      ElMessage.error('密码重置失败，请重试')
    }
  } finally {
    operatingUserIds.value.delete(id)
  }
}

// R72 三次调整（用户裁决）：重置需确认 + 操作者 MFA 校验（自己启用过 MFA 则
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
        // R73：守卫开启时后端第一层已豁免（守卫完成验码），对话框退化为纯确认——
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
    if (error === 'cancel' || error === 'close') return
    // D5 IMP-1：api.ts 全局 428 重试流已 toast 并打标——此处跳过二次弹窗；
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

// ============ MFA 绑定向导（用户管理操作列发起） ============
const mfaQrCanvas = ref<HTMLCanvasElement | null>(null)
const mfaBinding = ref({
  visible: false,
  step: 0,
  username: '',
  secret: '',
  code: '',
  recoveryCodes: [] as string[],
  loading: false,
})

const mfaBindingClosed = () => {
  mfaBinding.value.step = 0
  mfaBinding.value.code = ''
  // A6-S4：secret 一并清空——TOTP 种子不再滞留于关闭后的响应式状态。
  mfaBinding.value.secret = ''
  mfaBinding.value.recoveryCodes = []
}

const openMfaBinding = async (row: UserListItem): Promise<void> => {
  try {
    const res = await request.post<APIResponse<{ secret: string; uri: string }>>('/auth/mfa/setup', {}, { silent: true })
    if (!res.data) return
    mfaBinding.value.username = row.username
    mfaBinding.value.secret = res.data.secret
    mfaBinding.value.code = ''
    mfaBinding.value.recoveryCodes = []
    mfaBinding.value.step = 0
    mfaBinding.value.visible = true
    await nextTick()
    if (mfaQrCanvas.value) {
      await QRCode.toCanvas(mfaQrCanvas.value, res.data.uri, { width: 220, margin: 1 })
    }
  } catch (error: unknown) {
    ElMessage.error(error instanceof Error ? error.message : '生成 MFA 密钥失败')
  }
}

const activateMfa = async (): Promise<void> => {
  if (mfaBinding.value.code.length !== 6 || mfaBinding.value.loading) return
  mfaBinding.value.loading = true
  try {
    const res = await request.post<APIResponse<{ recovery_codes: string[] }>>('/auth/mfa/activate', { code: mfaBinding.value.code }, { silent: true })
    if (!res.data) return
    mfaBinding.value.recoveryCodes = res.data.recovery_codes
    mfaBinding.value.step = 2
    await fetchUsers()
    mfaAwareSuccess('MFA 已启用')
  } catch (error: unknown) {
    ElMessage.error(error instanceof Error ? error.message : '验证失败')
  } finally {
    mfaBinding.value.loading = false
  }
}

const copyMfaRecovery = async (): Promise<void> => {
  try {
    await navigator.clipboard.writeText(mfaBinding.value.recoveryCodes.join('\n'))
    ElMessage.success('恢复代码已复制')
  } catch {
    ElMessage.warning('复制失败，请手动选择复制')
  }
}

onMounted(() => {
  fetchUsers()
  void fetchOIDCStatus()
  void (async () => {
    try {
      const res = await request.get('/config')
      mfaWriteGuard.value = !!res.data?.mfa_write_guard
    } catch {
      // 读取失败按守卫关闭处理——重置对话框维持原有验码形态（保守）
    }
  })()
})
</script>

<style scoped>
/* ── 通用弹框头部 ── */
.dialog-header { display: flex; align-items: flex-start; gap: 12px; }
.dialog-header__icon {
  flex-shrink: 0; width: 36px; height: 36px; border-radius: 8px;
  background: #ecf5ff; color: #409eff;
  display: flex; align-items: center; justify-content: center;
}
.dialog-header__icon--primary { background: #ecf5ff; color: #409eff; }
.dialog-header__icon--warning { background: #fdf6ec; color: #e6a23c; }
.dialog-header__title { font-size: 16px; font-weight: 600; color: var(--text-primary, #111827); line-height: 1.4; }
.dialog-header__subtitle { font-size: 12px; color: var(--text-secondary, #6b7280); margin-top: 2px; }
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
  color: #3b82f6;
}

.user-info { display: flex; flex-direction: column; }

.user-name { font-weight: 500; color: #111827; font-size: 14px; }
.user-display { font-size: 12px; color: #9ca3af; }

.text-secondary { color: #6b7280; font-size: 13px; }
</style>
