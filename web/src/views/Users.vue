<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><UserFilled /></el-icon>
          用户管理
        </h2>
        <p class="page-desc">管理系统用户和权限</p>
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
        <el-row :gutter="16">
          <el-col :span="12">
            <el-form-item label="用户名">
              <el-input v-model="form.username" :placeholder="editingUser ? '用户名不可修改' : '请输入用户名'" :disabled="!!editingUser" maxlength="50" />
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="密码">
              <el-input v-model="form.password" type="password" show-password minlength="6" maxlength="72" :placeholder="editingUser ? '留空则不修改密码（至少6位）' : '请输入至少6位密码'" />
            </el-form-item>
          </el-col>
        </el-row>
        <el-row :gutter="16">
          <el-col :span="12">
            <el-form-item label="显示名称">
              <el-input v-model="form.display_name" placeholder="选填" maxlength="50" />
            </el-form-item>
          </el-col>
          <el-col :span="12">
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
        </el-row>
        <el-form-item>
          <el-button type="primary" :loading="submitting" :disabled="submitting" @click="handleSubmit">保存</el-button>
          <el-button :disabled="submitting" @click="closeForm">取消</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card>
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
        <el-table-column label="MFA" width="80" align="center">
          <template #default="{ row }">
            <el-tag :type="row.mfa_enabled ? 'success' : 'info'" size="small" effect="plain">
              {{ row.mfa_enabled ? '已启用' : '未启用' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="240" fixed="right" align="center">
          <template #default="{ row }">
            <el-button v-if="row.id !== authStore.user?.id" type="primary" link size="small" :disabled="isReadOnly || submitting" @click="editUser(row)">
              编辑
            </el-button>
            <el-button v-if="row.id !== authStore.user?.id" type="warning" link size="small" :disabled="isReadOnly || submittingUserId === row.id || operatingUserIds.has(row.id) || switchingIds.has(row.id)" @click="resetPassword(row.id)">
              重置密码
            </el-button>
            <el-button v-if="!row.mfa_enabled && row.id === authStore.user?.id" type="success" link size="small" :disabled="isReadOnly || submitting" @click="openMfaBinding(row)">
              启用 MFA
            </el-button>
            <el-button v-if="row.mfa_enabled && (row.id === authStore.user?.id || authStore.user?.role === 'admin')" type="warning" link size="small" :disabled="isReadOnly || submitting" @click="resetMfa(row)">
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
    <!-- R72 三次调整（用户裁决）：MFA 绑定向导从基础设置卡片迁到用户管理——
         点「启用 MFA」发起绑定：扫码 → 输码 → 恢复码。 -->
    <el-dialog v-model="mfaBinding.visible" title="启用 MFA（两步验证）" width="520px" :close-on-click-modal="false" @closed="mfaBindingClosed">
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
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, ref, onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { request } from '@/utils/api'
import { formatDate } from '@/utils/date'
import { ElMessageBox, ElMessage } from 'element-plus'
import { UserFilled, User, Plus } from '@element-plus/icons-vue'
import QRCode from 'qrcode'
import type { APIResponse, UserListItem } from '@/types'

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.readOnlyReason !== null)
const users = ref<UserListItem[]>([])
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
  form.value = { username: '', password: '', display_name: '', role: 'user' }
  showForm.value = true
}
const editingUser = ref<UserListItem | null>(null)
const switchingIds = ref(new Set<number>())
let usersRequestSeq = 0
const form = ref({
  username: '',
  password: '',
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
  submittingUserId.value = editingUser.value?.id ?? null
  submitting.value = true
  try {
    if (editingUser.value) {
      await request.put(`/users/${editingUser.value.id}`, {
        username: form.value.username,
        role: form.value.role,
        display_name: form.value.display_name,
        password: form.value.password || undefined,
      })
      ElMessage.success('更新成功')
    } else {
      await request.post('/users', form.value)
      ElMessage.success('创建成功')
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
  if (isReadOnly.value || submitting.value) return
  editingUser.value = user
  form.value = {
    username: user.username,
    password: '',
    display_name: getDisplayName(user),
    role: user.role,
  }
  showForm.value = true
}

const closeForm = () => {
  if (submitting.value) return
  showForm.value = false
  editingUser.value = null
  form.value = { username: '', password: '', display_name: '', role: 'user' }
}

const deleteUser = async (id: number) => {
  if (isReadOnly.value || submittingUserId.value === id || operatingUserIds.value.has(id) || switchingIds.value.has(id)) return
  operatingUserIds.value.add(id)
  try {
    await ElMessageBox.confirm('确定要删除这个用户吗？', '警告', { type: 'warning' })
    await request.delete(`/users/${id}`)
    ElMessage.success('删除成功')
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
    ElMessage.success(isEnabled ? '已启用用户' : '已禁用用户')
    fetchUsers()
  } catch (e) {
    fetchUsers() // revert on failure
  } finally {
    switchingIds.value.delete(id)
  }
}

const resetPassword = async (id: number) => {
  if (isReadOnly.value || submittingUserId.value === id || operatingUserIds.value.has(id) || switchingIds.value.has(id)) return
  operatingUserIds.value.add(id)
  try {
    // 说明：Element Plus 2.x 的 ElMessageBox.prompt 不支持 inputAttributes/maxlength，
    // 因此与后端 max=72 对齐的上限校验只能通过 inputValidator 提示文案兜底。
    const { value } = await ElMessageBox.prompt('请输入新密码', '重置密码', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      inputType: 'password',
      inputValidator: (value) => {
        if (!value || value.length < 6) {
          return '密码长度至少6位'
        }
        if (value.length > 72) {
          return '密码长度不能超过72位'
        }
        return true
      }
    })
    if (value) {
      await request.post(`/users/${id}/reset-password`, { new_password: value })
      ElMessage.success('密码重置成功')
    }
  } catch (e) {
    // User cancelled, do nothing
  } finally {
    operatingUserIds.value.delete(id)
  }
}

// R72 三次调整（用户裁决）：重置需确认 + 操作者 MFA 校验（自己启用过 MFA 则
// 弹码验证——后端同门校验）；admin 或本人可重置。
const resetMfa = async (row: UserListItem): Promise<void> => {
  try {
    const selfRow = users.value.find(u => u.id === authStore.user?.id)
    const operatorMfa = row.id === authStore.user?.id ? true : (selfRow?.mfa_enabled ?? false)
    let code = ''
    if (operatorMfa) {
      const { value } = await ElMessageBox.prompt(
        `重置「${row.username}」的 MFA 后该用户登录不再需要验证码，需重新绑定。\n请输入你当前 MFA 的验证码以确认：`,
        '重置 MFA',
        { type: 'warning', confirmButtonText: '确认重置', inputPattern: /^.{6,16}$/, inputErrorMessage: '请输入验证码或恢复代码' },
      )
      code = value.trim()
    } else {
      await ElMessageBox.confirm(
        `确定重置用户「${row.username}」的 MFA 吗？重置后该用户登录不再需要验证码，需自行重新绑定。`,
        '重置 MFA',
        { type: 'warning', confirmButtonText: '确认重置' },
      )
    }
    await request.post(`/users/${row.id}/mfa/reset`, { code }, { silent: true })
    ElMessage.success('已重置 MFA')
    await fetchUsers()
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    ElMessage.error(error instanceof Error ? error.message : '重置失败')
  }
}

// ============ MFA 绑定向导（用户管理操作列发起） ============
const mfaQrCanvas = ref<HTMLCanvasElement | null>(null)
const mfaBinding = ref({
  visible: false,
  step: 0,
  userId: 0,
  username: '',
  secret: '',
  code: '',
  recoveryCodes: [] as string[],
  loading: false,
})

const mfaBindingClosed = () => {
  mfaBinding.value.step = 0
  mfaBinding.value.code = ''
  mfaBinding.value.recoveryCodes = []
}

const openMfaBinding = async (row: UserListItem): Promise<void> => {
  try {
    const res = await request.post<APIResponse<{ secret: string; uri: string }>>('/auth/mfa/setup', {}, { silent: true })
    if (!res.data) return
    mfaBinding.value.userId = row.id
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
    ElMessage.success('MFA 已启用')
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
})
</script>

<style scoped>
.page { max-width: 1500px; margin: 0 auto; }

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.header-left { flex: 1; }

.page-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 18px;
  font-weight: 600;
  color: #111827;
  margin: 0;
}

.title-icon { color: #3b82f6; font-size: 20px; }

.page-desc {
  font-size: 13px;
  color: #6b7280;
  margin: 4px 0 0 28px;
}

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
