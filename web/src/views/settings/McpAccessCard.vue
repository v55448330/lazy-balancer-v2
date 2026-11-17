<template>
  <el-card shadow="never">
    <template #header>
      <div class="card-header-row">
        <span>{{ t('app.notification.keysAccess.title') }}</span>
        <el-tooltip v-if="isAdmin" :disabled="writeBlocked" :content="writeBlockedReason">
          <div>
            <el-switch
              v-model="mcpEnabled"
              :disabled="writeBlocked || toggleSaving"
              :active-text="t('app.notification.creds.mcpEnabled')"
              @update:model-value="(val: string | number | boolean) => toggleMcp(val === true)"
            />
          </div>
        </el-tooltip>
      </div>
    </template>

    <el-form label-position="top">
      <el-form-item :label="t('app.notification.keysAccess.endpointLabel')">
        <el-input :model-value="mcpServiceURL" readonly>
          <template #append>
            <el-button :aria-label="t('common.app.views.keys.copyMcpUrlAria')" @click="copyEndpoint">
              <el-icon><CopyDocument /></el-icon>
              {{ t('common.app.views.keys.copy') }}
            </el-button>
          </template>
        </el-input>
      </el-form-item>
      <el-form-item :label="t('app.notification.keysAccess.authExampleLabel')">
        <div style="width: 100%">
          <pre class="mcp-auth-pre">{{ authExample }}</pre>
          <div class="mcp-config-toolbar">
            <el-button size="small" @click="copyAuthExample">
              <el-icon><CopyDocument /></el-icon>
              {{ t('common.app.views.keys.copy') }}
            </el-button>
          </div>
          <div class="info-note-bar">
            <span class="info-note-desc">{{ t('common.app.views.keys.apiKeyHeaderNote') }}</span>
          </div>
        </div>
      </el-form-item>
      <el-form-item>
        <el-button :loading="playbookDownloading" @click="downloadPlaybook">
          <el-icon><Download /></el-icon>
          {{ t('app.notification.keysAccess.playbookLink') }}
        </el-button>
        <span class="playbook-hint">{{ t('app.notification.keysAccess.playbookHint') }}</span>
      </el-form-item>
    </el-form>

    <el-row v-if="isAdmin && stats" :gutter="16" class="stat-row">
      <el-col :xs="8">
        <div class="stat-card">
          <div class="stat-value">{{ stats.today_calls }}</div>
          <div class="stat-label">{{ t('app.notification.keysAccess.statTodayCalls') }}</div>
        </div>
      </el-col>
      <el-col :xs="8">
        <div class="stat-card">
          <div class="stat-value">{{ stats.active_sessions }}</div>
          <div class="stat-label">{{ t('app.notification.keysAccess.statActiveSessions') }}</div>
        </div>
      </el-col>
      <el-col :xs="8">
        <div class="stat-card">
          <div class="stat-value">{{ formatErrorRate(stats.error_rate) }}</div>
          <div class="stat-label">{{ t('app.notification.keysAccess.statErrorRate') }}</div>
        </div>
      </el-col>
    </el-row>
  </el-card>
</template>

<script setup lang="ts">
import { computed, ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { CopyDocument, Download } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { request } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import { copyText } from '@/utils/copy'
import { saveBlob } from '@/utils/download'
import type { NotificationSettingsResponse } from '@/types/notifications.ts'

// 管理员统计卡数据（Keys.vue 单次拉取传入；null=隐藏统计卡）
defineProps<{
  stats: { today_calls: number; active_sessions: number; error_rate: number } | null
}>()

const { t } = useI18n()
const authStore = useAuthStore()

const isAdmin = computed(() => authStore.user?.role === 'admin')
// MCP 全局开关是平台级管理员写路径：从节点/角色未知 fail-closed
const writeBlocked = computed(() => authStore.isSlaveNode || authStore.readOnlyReason === 'unknown')
const writeBlockedReason = computed(() =>
  authStore.isSlaveNode
    ? t('common.app.views.keys.slaveReadOnly')
    : t('common.app.views.keys.nodeUnknownReadOnly'),
)

const mcpServiceURL = new URL('/api/v1/mcp', window.location.origin).toString()

const authExample = computed(() =>
  [
    `curl -X POST ${mcpServiceURL} \\`,
    `  -H "Content-Type: application/json" \\`,
    `  -H "X-API-Key: <YOUR_API_KEY>" \\`,
    `  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'`,
  ].join('\n'),
)

const mcpEnabled = ref(false)
const toggleSaving = ref(false)

const formatErrorRate = (rate: number): string => `${(rate * 100).toFixed(1)}%`

const fetchMcpEnabled = async (): Promise<void> => {
  if (!isAdmin.value) return
  try {
    const res = await request.get<NotificationSettingsResponse>('/notification/settings')
    mcpEnabled.value = res.data?.mcp_enabled === true
  } catch (error: unknown) {
    // 开关态读取失败不阻断页面（静默，与面板其余 silent 拉取同口径）
    console.error('Failed to fetch MCP global switch:', error)
  }
}

const toggleMcp = async (on: boolean): Promise<void> => {
  if (toggleSaving.value || writeBlocked.value) return
  toggleSaving.value = true
  try {
    // 最小 PUT：仅全局开关（凭据其余字段不动）
    await request.put('/notification/settings', { mcp_enabled: on })
    ElMessage.success(on ? t('app.notification.keysAccess.mcpEnabledToast') : t('app.notification.keysAccess.mcpDisabledToast'))
  } catch (error: unknown) {
    mcpEnabled.value = !on
    console.error('Failed to toggle MCP global switch:', error)
  } finally {
    toggleSaving.value = false
  }
}

const playbookDownloading = ref(false)
const downloadPlaybook = async (): Promise<void> => {
  if (playbookDownloading.value) return
  playbookDownloading.value = true
  try {
    const blob = await request.get<Blob>('/mcp/ops-playbook', { responseType: 'blob' })
    saveBlob(blob, 'lazy-balancer-mcp-ops-playbook.md')
  } catch (error: unknown) {
    // 全局拦截器已弹 toast（blob 错误体会被解析出后端 message）
    console.error('Failed to download MCP playbook:', error)
  } finally {
    playbookDownloading.value = false
  }
}

const copyEndpoint = async (): Promise<void> => {
  if (await copyText(mcpServiceURL)) {
    ElMessage.success(t('common.app.views.keys.mcpUrlCopied'))
    return
  }
  ElMessage.error(t('common.app.views.keys.copyUrlFailed'))
}

const copyAuthExample = async (): Promise<void> => {
  if (await copyText(authExample.value)) {
    ElMessage.success(t('app.notification.keysAccess.authCopied'))
    return
  }
  ElMessage.error(t('common.app.views.keys.copyUrlFailed'))
}

onMounted(() => {
  void fetchMcpEnabled()
})

defineExpose({ fetchMcpEnabled })
</script>

<style scoped>
.card-header-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.mcp-auth-pre { background: #f6f8fa; border-radius: 0; padding: 12px; font-family: 'SF Mono', Menlo, monospace; font-size: 12px; line-height: 1.55; overflow-x: auto; white-space: pre; margin: 0; }
.mcp-config-toolbar { display: flex; justify-content: flex-end; margin-top: 8px; }
.playbook-hint { margin-left: 10px; font-size: 12px; color: var(--text-secondary, #6b7280); }
.stat-row { margin-top: 8px; }
.stat-card { background: var(--bg-secondary, #f9fafb); border-radius: 4px; padding: 12px 16px; text-align: center; }
.stat-value { font-size: 22px; font-weight: 700; line-height: 1.3; }
.stat-label { font-size: 12px; color: var(--text-secondary, #6b7280); margin-top: 2px; }
</style>
