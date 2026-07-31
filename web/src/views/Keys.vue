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
        <el-button type="primary" :disabled="isSlave || creating" @click="openCreateDialog">
          <el-icon><Plus /></el-icon>
          创建密钥
        </el-button>
      </div>
    </div>

    <div v-else class="toolbar">
      <el-button type="primary" :disabled="isSlave || creating" @click="openCreateDialog">
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
            <el-descriptions-item label="功能">
              <div class="feature-tags">
                <el-tag :type="key.mcp_enabled ? 'primary' : 'info'" size="small" effect="plain">
                  MCP {{ key.mcp_enabled ? '开启' : '关闭' }}
                </el-tag>
                <el-tag :type="key.read_only ? 'warning' : 'success'" size="small" effect="plain">
                  {{ key.read_only ? '只读' : '读写' }}
                </el-tag>
              </div>
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
              type="primary"
              plain
              :disabled="isSlave || togglePendingId === key.id || deletingIds.has(key.id)"
              @click="openFeatureDialog(key)"
            >
              <el-icon><Setting /></el-icon>
              功能配置
            </el-button>
            <el-button
              size="small"
              :type="key.is_enabled ? 'warning' : 'success'"
              :loading="togglePendingId === key.id"
              :disabled="isSlave || deletingIds.has(key.id)"
              @click="toggleKey(key)"
            >
              <el-icon><SwitchButton v-if="key.is_enabled" /><VideoPlay v-else /></el-icon>
              {{ key.is_enabled ? '禁用' : '启用' }}
            </el-button>
            <el-button size="small" type="danger" :loading="deletingIds.has(key.id)" :disabled="isSlave || togglePendingId === key.id || deletingIds.has(key.id)" @click="deleteKey(key.id)">
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
      v-model="createDialogVisible"
      title="创建 API 密钥"
      width="min(620px, 92vw)"
      :close-on-click-modal="false"
      :close-on-press-escape="!creating"
      :show-close="!creating"
      @closed="resetCreateForm"
    >
      <el-form label-width="100px" :disabled="creating">
        <el-form-item label="密钥名称" :error="createNameError">
          <el-input v-model="createForm.name" maxlength="100" show-word-limit placeholder="请输入密钥名称" @input="createNameError = ''" />
        </el-form-item>
        <el-form-item label="MCP 功能">
          <el-switch v-model="createForm.mcp_enabled" />
        </el-form-item>
        <el-form-item label="只读模式">
          <el-switch v-model="createForm.read_only" />
        </el-form-item>
        <el-alert
          v-if="createForm.read_only"
          class="readonly-alert"
          title="只读模式开启后，该密钥的所有写操作都将被拒绝（包括 MCP 写操作）。"
          type="warning"
          :closable="false"
          show-icon
        />
        <el-form-item v-if="createForm.mcp_enabled" label="IP 白名单" :error="createWhitelistError">
          <el-input
            v-model="createForm.whitelistText"
            type="textarea"
            :rows="5"
            resize="vertical"
            placeholder="一行一个 CIDR，例如：10.0.0.0/8 或 192.168.1.10\n留空表示不限制来源 IP"
            @input="createWhitelistError = ''"
          />
        </el-form-item>
        <el-alert
          title="MCP 服务地址为 /api/v1/mcp，使用 API Key 认证。IP 白名单仅在 MCP 功能开启时生效。"
          type="info"
          :closable="false"
          show-icon
        />
      </el-form>
      <template #footer>
        <el-button :disabled="creating" @click="createDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="creating" @click="createKey">创建</el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="featureDialogVisible"
      :title="`功能配置 — ${featureTarget?.name || ''}`"
      width="min(620px, 92vw)"
      :close-on-click-modal="false"
      :close-on-press-escape="!featureSaving"
      :show-close="!featureSaving"
      @closed="resetFeatureForm"
    >
      <el-form label-width="100px" :disabled="featureSaving">
        <el-form-item label="MCP 功能">
          <el-switch v-model="featureForm.mcp_enabled" />
        </el-form-item>
        <el-form-item label="只读模式">
          <el-switch v-model="featureForm.read_only" />
        </el-form-item>
        <el-alert
          v-if="featureForm.read_only"
          class="readonly-alert"
          title="只读模式开启后，该密钥的所有写操作都将被拒绝（包括 MCP 写操作）。"
          type="warning"
          :closable="false"
          show-icon
        />
        <el-form-item v-if="featureForm.mcp_enabled" label="IP 白名单" :error="featureWhitelistError">
          <el-input
            v-model="featureForm.whitelistText"
            type="textarea"
            :rows="5"
            resize="vertical"
            placeholder="一行一个 CIDR，例如：10.0.0.0/8 或 192.168.1.10\n留空表示不限制来源 IP"
            @input="featureWhitelistError = ''"
          />
        </el-form-item>
        <el-alert
          title="MCP 服务地址为 /api/v1/mcp，使用 API Key 认证。IP 白名单仅在 MCP 功能开启时生效。"
          type="info"
          :closable="false"
          show-icon
        />
      </el-form>
      <template #footer>
        <el-button :disabled="featureSaving" @click="featureDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="featureSaving" @click="saveFeatures">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="createdKeyVisible"
      title="API 密钥已创建"
      width="min(560px, 92vw)"
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
import { computed, ref, onMounted } from 'vue'
import { request } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import { formatDate, formatDateShort } from '@/utils/date'
import { isValidCidr } from '@/utils/ruleValidation'
import { ElMessageBox, ElMessage } from 'element-plus'
import { CopyDocument, Delete, Document, Key, Plus, Setting, SwitchButton, VideoPlay } from '@element-plus/icons-vue'
import type { APIKey, CreateAPIKeyInput, UpdateAPIKeyInput } from '@/types'

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

const authStore = useAuthStore()
const isSlave = computed(() => authStore.nodeMode === 'slave')

const keys = ref<readonly APIKey[]>([])
const loading = ref(false)
const creating = ref(false)
const createDialogVisible = ref(false)
const createNameError = ref('')
const createWhitelistError = ref('')
const createForm = ref({ name: '', mcp_enabled: false, read_only: false, whitelistText: '' })
const featureDialogVisible = ref(false)
const featureSaving = ref(false)
const featureTarget = ref<APIKey | null>(null)
const featureWhitelistError = ref('')
const featureForm = ref({ mcp_enabled: false, read_only: false, whitelistText: '' })
const togglePendingId = ref<number | null>(null)
const deletingIds = ref(new Set<number>())
const createdKey = ref('')
const createdKeyVisible = ref(false)
let keysRequestSeq = 0

const fetchKeys = async () => {
  const requestSeq = ++keysRequestSeq
  loading.value = true
  try {
    const res = await request.get<APIKeyListResponse>('/users/me/api-keys')
    if (requestSeq === keysRequestSeq) keys.value = res.data || []
  } finally {
    if (requestSeq === keysRequestSeq) loading.value = false
  }
}

const normalizeCidr = (rawValue: string): string => {
  const value = rawValue.trim()
  if (!value || value.includes('/')) return value
  return value.includes(':') ? `${value}/128` : `${value}/32`
}

const parseWhitelist = (value: string[] | string): string => {
  if (Array.isArray(value)) return value.join('\n')
  if (!value) return ''
  try {
    const parsed: unknown = JSON.parse(value)
    return Array.isArray(parsed) && parsed.every((item) => typeof item === 'string') ? parsed.join('\n') : ''
  } catch {
    return ''
  }
}

const serializeWhitelist = (value: string): { readonly value: string[]; readonly error: string } => {
  const rows = value.split(/\r?\n/)
    .map((cidr, originalIndex) => ({ cidr: normalizeCidr(cidr), originalIndex }))
    .filter((row) => row.cidr !== '')
  const invalidRow = rows.find((row) => !isValidCidr(row.cidr))
  if (invalidRow) return { value: [], error: `第 ${invalidRow.originalIndex + 1} 行 IP 或 CIDR 格式不正确` }
  return { value: rows.map((row) => row.cidr), error: '' }
}

const openCreateDialog = (): void => {
  if (isSlave.value || creating.value) return
  resetCreateForm()
  createDialogVisible.value = true
}

const resetCreateForm = (): void => {
  createForm.value = { name: '', mcp_enabled: false, read_only: false, whitelistText: '' }
  createNameError.value = ''
  createWhitelistError.value = ''
}

async function createKey() {
  if (isSlave.value || creating.value) return
  const name = createForm.value.name.trim()
  if (!name) {
    createNameError.value = '请输入密钥名称'
    return
  }
  const whitelist = serializeWhitelist(createForm.value.whitelistText)
  if (createForm.value.mcp_enabled && whitelist.error) {
    createWhitelistError.value = whitelist.error
    return
  }

  creating.value = true
  try {
    const payload: CreateAPIKeyInput = {
      name,
      mcp_enabled: createForm.value.mcp_enabled,
      read_only: createForm.value.read_only,
      mcp_ip_whitelist: whitelist.value,
    }
    const res = await request.post<CreateAPIKeyResponse>('/users/me/api-keys', payload)
    ElMessage.success('密钥创建成功')
    createDialogVisible.value = false
    if (res.data?.key) {
      createdKey.value = res.data.key
      createdKeyVisible.value = true
    }
    await fetchKeys()
  } finally {
    creating.value = false
  }
}

const openFeatureDialog = (key: APIKey): void => {
  if (isSlave.value || featureSaving.value) return
  featureTarget.value = key
  featureForm.value = {
    mcp_enabled: key.mcp_enabled,
    read_only: key.read_only,
    whitelistText: parseWhitelist(key.mcp_ip_whitelist),
  }
  featureWhitelistError.value = ''
  featureDialogVisible.value = true
}

const resetFeatureForm = (): void => {
  featureTarget.value = null
  featureForm.value = { mcp_enabled: false, read_only: false, whitelistText: '' }
  featureWhitelistError.value = ''
}

const saveFeatures = async (): Promise<void> => {
  if (isSlave.value || featureSaving.value || !featureTarget.value) return
  const whitelist = serializeWhitelist(featureForm.value.whitelistText)
  if (featureForm.value.mcp_enabled && whitelist.error) {
    featureWhitelistError.value = whitelist.error
    return
  }

  featureSaving.value = true
  try {
    const payload: UpdateAPIKeyInput = {
      mcp_enabled: featureForm.value.mcp_enabled,
      read_only: featureForm.value.read_only,
      mcp_ip_whitelist: whitelist.value,
    }
    await request.patch(`/users/me/api-keys/${featureTarget.value.id}`, payload)
    ElMessage.success('功能配置已更新')
    featureDialogVisible.value = false
    await fetchKeys()
  } finally {
    featureSaving.value = false
  }
}

const deleteKey = async (id: number) => {
  if (isSlave.value || togglePendingId.value === id || deletingIds.value.has(id)) return
  deletingIds.value.add(id)
  try {
    await ElMessageBox.confirm('确定要删除这个 API 密钥吗？删除后无法恢复。', '警告', { type: 'warning' })
    await request.delete(`/users/me/api-keys/${id}`)
    ElMessage.success('删除成功')
    await fetchKeys()
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    throw error
  } finally {
    deletingIds.value.delete(id)
  }
}

const toggleKey = async (key: APIKey) => {
  if (isSlave.value || togglePendingId.value !== null || deletingIds.value.has(key.id)) return
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
    const payload: UpdateAPIKeyInput = { is_enabled: isEnabled }
    await request.patch(`/users/me/api-keys/${key.id}`, payload)
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

.feature-tags { display: flex; flex-wrap: wrap; gap: 6px; }

.key-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 16px; }
.key-actions :deep(.el-icon) { margin-right: 4px; }

.readonly-alert { margin: -2px 0 18px; }

.created-key-box { display: flex; align-items: center; gap: 12px; margin-top: 20px; padding: 12px; border-radius: 6px; background: #f9fafb; }

.created-key-text { flex: 1; min-width: 0; color: #111827; font-family: 'SF Mono', monospace; font-size: 12px; word-break: break-all; }

.empty-card { padding: 20px; }
.empty-card :deep(.el-empty__bottom) { margin-top: 16px; }

@media (max-width: 767px) {
  .page-header { align-items: flex-start; flex-direction: column; gap: 12px; }
  .header-actions { width: 100%; flex-wrap: wrap; }
  .key-actions { flex-wrap: wrap; }
}
</style>
