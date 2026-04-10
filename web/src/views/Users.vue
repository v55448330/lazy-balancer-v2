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
      <el-button type="primary" @click="showForm = true">
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
      <el-form :model="form" label-width="90px">
        <el-row :gutter="16">
          <el-col :span="12">
            <el-form-item label="用户名">
              <el-input v-model="form.username" :placeholder="editingUser ? '用户名不可修改' : '请输入用户名'" :disabled="!!editingUser" />
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="密码">
              <el-input v-model="form.password" type="password" show-password :placeholder="editingUser ? '留空则不修改密码' : '请输入密码'" />
            </el-form-item>
          </el-col>
        </el-row>
        <el-row :gutter="16">
          <el-col :span="12">
            <el-form-item label="显示名称">
              <el-input v-model="form.display_name" placeholder="选填" />
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
          <el-button type="primary" @click="handleSubmit">保存</el-button>
          <el-button @click="closeForm">取消</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card>
      <el-table :data="users" stripe :header-cell-style="{ background: '#f9fafb' }">
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
              :loading="switchingId === row.id"
              :disabled="row.id === authStore.user?.id"
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
        <el-table-column label="操作" width="180" fixed="right" align="center">
          <template #default="{ row }">
            <el-button v-if="row.id !== authStore.user?.id" type="primary" link size="small" @click="editUser(row)">
              编辑
            </el-button>
            <el-button v-if="row.id !== authStore.user?.id" type="warning" link size="small" @click="resetPassword(row.id)">
              重置密码
            </el-button>
            <el-button v-if="row.id !== authStore.user?.id" type="danger" link size="small" @click="deleteUser(row.id)">
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { request } from '@/utils/api'
import { formatDate } from '@/utils/date'
import { ElMessageBox, ElMessage } from 'element-plus'
import { UserFilled, User, Plus } from '@element-plus/icons-vue'

const authStore = useAuthStore()
const users = ref<any[]>([])
const showForm = ref(false)
const editingUser = ref<any>(null)
const switchingId = ref<number | null>(null)
const form = ref({
  username: '',
  password: '',
  display_name: '',
  role: 'user',
})

const getDisplayName = (row: any) => {
  const name = row.display_name
  if (typeof name === 'string') return name
  if (name && typeof name === 'object' && 'String' in name) return name.String
  return ''
}

const fetchUsers = async () => {
  const res = await request.get('/users')
  users.value = res.data || []
}

const handleSubmit = async () => {
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
  closeForm()
  fetchUsers()
  form.value = { username: '', password: '', display_name: '', role: 'user' }
}

const editUser = (user: any) => {
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
  showForm.value = false
  editingUser.value = null
  form.value = { username: '', password: '', display_name: '', role: 'user' }
}

const deleteUser = async (id: number) => {
  try {
    await ElMessageBox.confirm('确定要删除这个用户吗？', '警告', { type: 'warning' })
    await request.delete(`/users/${id}`)
    ElMessage.success('删除成功')
    fetchUsers()
  } catch (e) {
    // User cancelled, do nothing
  }
}

const handleToggleStatus = async (id: number, isEnabled: boolean) => {
  switchingId.value = id
  try {
    await request.put(`/users/${id}/status`, { is_enabled: isEnabled })
    ElMessage.success(isEnabled ? '已启用用户' : '已禁用用户')
    fetchUsers()
  } catch (e) {
    fetchUsers() // revert on failure
  } finally {
    switchingId.value = null
  }
}

const resetPassword = async (id: number) => {
  try {
    const { value } = await ElMessageBox.prompt('请输入新密码', '重置密码', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      inputType: 'password',
      inputValidator: (value) => {
        if (!value || value.length < 6) {
          return '密码长度至少6位'
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
  }
}

onMounted(() => {
  fetchUsers()
})
</script>

<style scoped>
.page { max-width: 1400px; margin: 0 auto; }

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