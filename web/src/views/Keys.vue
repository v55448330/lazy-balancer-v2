<template>
  <div class="page" :class="{ 'hide-header': hideHeader }">
    <div v-if="!hideHeader" class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Key /></el-icon>
          API 密钥
        </h2>
        <p class="page-desc">仅显示和管理当前登录用户的 API 访问密钥</p>
      </div>
      <div class="header-actions">
        <el-button tag="a" href="/api/v1/docs" target="_blank" rel="noopener noreferrer">
          <el-icon><Document /></el-icon>
          接口文档
        </el-button>
        <el-button type="primary" @click="createKey">
          <el-icon><Plus /></el-icon>
          创建密钥
        </el-button>
      </div>
    </div>

    <div v-else class="toolbar">
      <el-button type="primary" @click="createKey">
        <el-icon><Plus /></el-icon>
        创建密钥
      </el-button>
    </div>

    <el-row v-loading="loading" :gutter="20">
      <el-col v-for="key in keys" :key="key.id" :span="8" class="key-col">
        <el-card class="key-card" shadow="hover" :class="{ 'key-card-disabled': !key.is_enabled }">
          <template #header>
            <div class="key-title-row">
              <span class="key-name">{{ key.name }}</span>
              <el-tag :type="key.is_enabled ? 'success' : 'info'" size="small">
                {{ key.is_enabled ? '已启用' : '已禁用' }}
              </el-tag>
            </div>
          </template>
          <el-descriptions :column="1" size="small" border>
            <el-descriptions-item label="密钥前缀">
              <code>{{ key.key_prefix || '-' }}</code>
            </el-descriptions-item>
            <el-descriptions-item label="创建时间">
              {{ formatDateShort(key.created_at) || '-' }}
            </el-descriptions-item>
            <el-descriptions-item label="最后使用">
              {{ formatDate(key.last_used) || '从未使用' }}
            </el-descriptions-item>
            <el-descriptions-item label="过期时间">
              {{ formatDate(key.expires_at) || '永不过期' }}
            </el-descriptions-item>
          </el-descriptions>
          <div class="key-actions">
            <el-button
              size="small"
              :type="key.is_enabled ? 'warning' : 'success'"
              :loading="togglePendingId === key.id"
              @click="toggleKey(key)"
            >
              <el-icon><SwitchButton v-if="key.is_enabled" /><VideoPlay v-else /></el-icon>
              {{ key.is_enabled ? '禁用' : '启用' }}
            </el-button>
            <el-button size="small" type="danger" @click="deleteKey(key.id)">
              <el-icon><Delete /></el-icon>
              删除
            </el-button>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-card v-if="!loading && keys.length === 0" class="empty-card">
      <el-empty description="暂无 API 密钥" :image-size="80" />
    </el-card>

    <el-dialog
      v-model="createdKeyVisible"
      title="API 密钥已创建"
      width="560px"
      :close-on-click-modal="false"
      @closed="createdKey = ''"
    >
      <el-alert
        title="此密钥仅显示一次，请立即复制并妥善保存。"
        type="warning"
        :closable="false"
        show-icon
      />
      <div class="created-key-box">
        <code class="created-key-text">{{ createdKey }}</code>
        <el-button type="primary" @click="copyCreatedKey">
          <el-icon><CopyDocument /></el-icon>
          复制密钥
        </el-button>
      </div>
      <template #footer>
        <el-button type="primary" @click="createdKeyVisible = false">我已保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import api, { request } from '@/utils/api'
import { formatDate, formatDateShort } from '@/utils/date'
import { ElMessageBox, ElMessage } from 'element-plus'
import { CopyDocument, Delete, Document, Key, Plus, SwitchButton, VideoPlay } from '@element-plus/icons-vue'

interface NullableTime {
  readonly Time: string
  readonly Valid: boolean
}

interface APIKey {
  readonly id: number
  readonly name: string
  readonly key_prefix: string
  readonly created_by: number
  readonly username: string
  readonly is_enabled: boolean
  readonly last_used?: string | NullableTime | null
  readonly expires_at?: string | NullableTime | null
  readonly created_at: string
}

interface APIKeyListResponse {
  readonly data?: readonly APIKey[]
}

interface CreateAPIKeyResponse {
  readonly data?: {
    readonly id: number
    readonly key: string
    readonly message: string
  }
}

defineProps<{
  hideHeader?: boolean
}>()

defineExpose({
  createKey,
})

const keys = ref<readonly APIKey[]>([])
const loading = ref(false)
const togglePendingId = ref<number | null>(null)
const createdKey = ref('')
const createdKeyVisible = ref(false)

const fetchKeys = async () => {
  loading.value = true
  try {
    const res = await request.get<APIKeyListResponse>('/users/me/api-keys')
    keys.value = res.data || []
  } finally {
    loading.value = false
  }
}

async function createKey() {
  let result
  try {
    result = await ElMessageBox.prompt('请输入密钥名称', '创建 API 密钥', {
      confirmButtonText: '创建',
      cancelButtonText: '取消',
      inputValidator: (value) => value.trim().length > 0 || '请输入密钥名称',
    })
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    throw error
  }

  const name = result.value.trim()
  if (!name) return

  const res = await request.post<CreateAPIKeyResponse>('/users/me/api-keys', { name })
  ElMessage.success('密钥创建成功')
  if (res.data?.key) {
    createdKey.value = res.data.key
    createdKeyVisible.value = true
  }
  await fetchKeys()
}

const deleteKey = async (id: number) => {
  try {
    await ElMessageBox.confirm('确定要删除这个 API 密钥吗？删除后无法恢复。', '警告', { type: 'warning' })
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    throw error
  }

  await request.delete(`/users/me/api-keys/${id}`)
  ElMessage.success('删除成功')
  await fetchKeys()
}

const toggleKey = async (key: APIKey) => {
  const isEnabled = !key.is_enabled

  if (!isEnabled) {
    try {
      await ElMessageBox.confirm(`确定要禁用 API 密钥“${key.name}”吗？禁用后该密钥将无法访问接口。`, '禁用确认', {
        type: 'warning',
        confirmButtonText: '确认禁用',
        cancelButtonText: '取消',
      })
    } catch (error: unknown) {
      if (error === 'cancel' || error === 'close') return
      throw error
    }
  }

  togglePendingId.value = key.id
  try {
    await api.patch(`/users/me/api-keys/${key.id}`, { is_enabled: isEnabled })
    ElMessage.success(isEnabled ? '密钥已启用' : '密钥已禁用')
    await fetchKeys()
  } finally {
    togglePendingId.value = null
  }
}

const copyCreatedKey = async () => {
  try {
    await navigator.clipboard.writeText(createdKey.value)
    ElMessage.success('密钥已复制')
  } catch (error: unknown) {
    if (error instanceof Error) {
      ElMessage.error('复制失败，请手动复制密钥')
      return
    }
    throw error
  }
}

onMounted(() => {
  fetchKeys()
})
</script>

<style scoped>
.page { max-width: 1500px; margin: 0 auto; }

.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }

.toolbar { display: flex; justify-content: flex-end; margin-bottom: 20px; }

.hide-header .page-header,
.hide-header .toolbar { display: none; }

.header-left { flex: 1; }
.header-actions { display: flex; gap: 8px; }

.page-title { display: flex; align-items: center; gap: 8px; font-size: 18px; font-weight: 600; color: #111827; margin: 0; }

.title-icon { color: #3b82f6; font-size: 20px; }

.page-desc { font-size: 13px; color: #6b7280; margin: 4px 0 0 28px; }

.key-col { margin-bottom: 20px; }

.key-card-disabled { opacity: 0.72; }

.key-title-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.key-name { min-width: 0; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.key-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 16px; }
.key-actions :deep(.el-icon) { margin-right: 4px; }

.created-key-box { display: flex; align-items: center; gap: 12px; margin-top: 20px; padding: 12px; border-radius: 6px; background: #f9fafb; }

.created-key-text { flex: 1; min-width: 0; color: #111827; font-family: 'SF Mono', monospace; font-size: 12px; word-break: break-all; }

.empty-card { padding: 20px; }
.empty-card :deep(.el-empty__bottom) { margin-top: 16px; }
</style>
