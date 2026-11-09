<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Key /></el-icon>
          {{ t('common.app.views.keys.pageTitle') }}
        </h2>
        <p class="page-desc">{{ t('common.app.views.keys.pageDesc') }}</p>
      </div>
      <div class="header-actions">
        <el-button tag="a" href="/api/v1/docs" target="_blank" rel="noopener noreferrer">
          <el-icon><Document /></el-icon>
          {{ t('common.app.views.keys.apiDocs') }}
        </el-button>
        <el-button @click="mcpDocsVisible = true">
          <el-icon><Connection /></el-icon>
          {{ t('common.app.views.keys.mcpDocs') }}
        </el-button>
        <el-tooltip :disabled="!nodeWriteBlocked" :content="nodeWriteBlockedReason">
          <div>
            <el-button type="primary" :disabled="nodeWriteBlocked || creating" @click="openCreateDialog">
              <el-icon><Plus /></el-icon>
              {{ t('common.app.views.keys.createKey') }}
            </el-button>
          </div>
        </el-tooltip>
      </div>
    </div>

    <el-alert v-if="loadError" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
      <template #title>
        <div class="polling-error-title">
          <span>{{ t('common.app.views.keys.loadErrorBanner') }}</span>
          <el-button link type="danger" @click="fetchKeys">{{ t('common.app.views.keys.retryNow') }}</el-button>
        </div>
      </template>
    </el-alert>

    <el-row v-loading="loading" :gutter="20">
      <el-col v-for="key in keys" :key="key.id" :span="8" class="key-col">
        <el-card class="key-card" shadow="hover" :class="{ 'key-card-disabled': !key.is_enabled }">
          <template #header>
            <div class="key-title-row">
              <span class="key-name">{{ key.name }}</span>
              <el-tag v-if="keyExpired(key)" type="danger" size="small">{{ t('common.app.views.keys.expiredTag') }}</el-tag>
              <el-tag v-else :type="key.is_enabled ? 'success' : 'info'" size="small">
                {{ key.is_enabled ? t('common.app.views.keys.enabledTag') : t('common.app.views.keys.disabledTag') }}
              </el-tag>
            </div>
          </template>
          <el-descriptions :column="1" size="small" border>
            <el-descriptions-item :label="t('common.app.views.keys.keyPrefix')">
              <code>{{ key.key_prefix || '-' }}</code>
            </el-descriptions-item>
            <el-descriptions-item :label="t('common.app.views.keys.features')">
              <div class="feature-tags">
                <el-tag :type="key.mcp_enabled ? 'primary' : 'info'" size="small" effect="plain">
                  MCP {{ key.mcp_enabled ? t('common.app.views.keys.on') : t('common.app.views.keys.off') }}
                </el-tag>
                <el-tag :type="key.read_only ? 'warning' : 'success'" size="small" effect="plain">
                  {{ key.read_only ? t('common.app.views.keys.readOnly') : t('common.app.views.keys.readWrite') }}
                </el-tag>
                <el-tooltip v-if="whitelistEntries(key.mcp_ip_whitelist).length" :content="whitelistSummary(key.mcp_ip_whitelist)" placement="top">
                  <el-tag type="warning" size="small" effect="plain">{{ t('common.app.views.keys.ipWhitelist') }}</el-tag>
                </el-tooltip>
              </div>
            </el-descriptions-item>
            <el-descriptions-item :label="t('common.app.views.keys.createdAt')">
              {{ formatDateShort(key.created_at) || '-' }}
            </el-descriptions-item>
            <el-descriptions-item :label="t('common.app.views.keys.lastUsed')">
              {{ formatDate(key.last_used) || t('common.app.views.keys.neverUsed') }}
            </el-descriptions-item>
            <el-descriptions-item :label="t('common.app.views.keys.expiresAt')">
              {{ formatDate(key.expires_at) || t('common.app.views.keys.neverExpires') }}
            </el-descriptions-item>
          </el-descriptions>
          <div class="key-actions">
            <el-tooltip :disabled="!nodeWriteBlocked" :content="nodeWriteBlockedReason">
              <div>
                <el-button
                  size="small"
                  type="primary"
                  plain
                  :disabled="nodeWriteBlocked || togglePendingId === key.id || deletingIds.has(key.id)"
                  @click="openFeatureDialog(key)"
                >
                  <el-icon><Setting /></el-icon>
                  {{ t('common.app.views.keys.featureConfig') }}
                </el-button>
              </div>
            </el-tooltip>
            <el-tooltip :disabled="!nodeWriteBlocked" :content="nodeWriteBlockedReason">
              <div>
                <el-button
                  size="small"
                  :type="key.is_enabled ? 'warning' : 'success'"
                  :loading="togglePendingId === key.id"
                  :disabled="nodeWriteBlocked || (togglePendingId !== null && togglePendingId !== key.id) || deletingIds.has(key.id)"
                  @click="toggleKey(key)"
                >
                  <el-icon><SwitchButton v-if="key.is_enabled" /><VideoPlay v-else /></el-icon>
                  {{ key.is_enabled ? t('common.app.views.keys.disable') : t('common.app.views.keys.enable') }}
                </el-button>
              </div>
            </el-tooltip>
            <el-tooltip :disabled="!nodeWriteBlocked" :content="nodeWriteBlockedReason">
              <div>
                <el-button size="small" type="danger" :loading="deletingIds.has(key.id)" :disabled="nodeWriteBlocked || togglePendingId === key.id || deletingIds.has(key.id)" @click="deleteKey(key.id)">
                  <el-icon><Delete /></el-icon>
                  {{ t('common.app.views.keys.delete') }}
                </el-button>
              </div>
            </el-tooltip>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-card v-if="!loading && keys.length === 0 && !loadError" class="empty-card">
      <el-empty :description="t('common.app.views.keys.emptyText')" :image-size="80" />
    </el-card>

    <el-dialog
      v-model="mcpDocsVisible"
      class="mcp-docs-dialog dialog-body-inset"
      width="min(1000px, 96vw)"
      top="5vh"
      @opened="fetchMCPTools"
    >
      <template #header>
        <DialogHeader :icon="SetUp" :title="t('common.app.views.keys.mcpDocsTitle')" :subtitle="t('common.app.views.keys.mcpDocsSubtitle')" />
      </template>
      <section class="dialog-panel mcp-connection-panel">
        <DialogSectionHeader :title="t('common.app.views.keys.connectionSection')" :description="t('common.app.views.keys.connectionDesc')" />
      <el-form label-position="top">
        <el-form-item :label="t('common.app.views.keys.mcpUrlLabel')">
          <el-input :model-value="mcpServiceURL" readonly>
            <template #append>
              <el-button :aria-label="t('common.app.views.keys.copyMcpUrlAria')" @click="copyMCPServiceURL">
                <el-icon><CopyDocument /></el-icon>
                {{ t('common.app.views.keys.copy') }}
              </el-button>
            </template>
          </el-input>
        </el-form-item>
        <el-form-item :label="t('common.app.views.keys.mcpConfigLabel')">
          <div style="width: 100%">
            <el-input
              class="mcp-config-json"
              type="textarea"
              :model-value="mcpConfigJSON"
              readonly
              :rows="13"
            />
            <div class="mcp-config-toolbar">
              <el-button size="small" @click="copyMCPConfig">
                <el-icon><CopyDocument /></el-icon>
                {{ t('common.app.views.keys.copyConfig') }}
              </el-button>
            </div>
            <div class="info-note-bar">
              <span class="info-note-desc">{{ t('common.app.views.keys.certHint') }}</span>
            </div>
          </div>
        </el-form-item>
      </el-form>
      </section>

      <div class="info-note-bar"><span class="info-note-desc">{{ t('common.app.views.keys.apiKeyHeaderNote') }}</span></div>

      <el-collapse class="mcp-agent-guide">
        <el-collapse-item :title="t('common.app.views.keys.agentGuideTitle')" name="agent-guide">
          <div class="mcp-guide-block">
            <section class="dialog-panel">
              <DialogSectionHeader :title="t('common.app.views.keys.protocolFlowTitle')" :description="t('common.app.views.keys.protocolFlowDesc', { url: mcpServiceURL })" />
            <pre class="mcp-guide-pre">{{ t('common.app.views.keys.flowInitStep') }}
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"your-agent","version":"1.0"}}}

{{ t('common.app.views.keys.flowListStep') }}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}

{{ t('common.app.views.keys.flowCallStep') }}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_metrics_overview","arguments":{}}}</pre>
            </section>
            <section class="dialog-panel">
              <DialogSectionHeader :title="t('common.app.views.keys.selfSignedTitle')" :description="t('common.app.views.keys.optionalConfig')" />
            <div class="mcp-guide-text">{{ t('common.app.views.keys.certFixA') }} <code>NODE_TLS_REJECT_UNAUTHORIZED=0</code>{{ t('common.app.views.keys.certFixB') }}</div>
            </section>
            <section class="dialog-panel">
              <DialogSectionHeader :title="t('common.app.views.keys.commonErrorsTitle')" />
            <div class="mcp-guide-text">{{ t('common.app.views.keys.commonErrorsBody') }}</div>
            </section>
            <section class="dialog-panel">
              <DialogSectionHeader :title="t('common.app.views.keys.scopeTitle')" />
            <div class="mcp-guide-text">{{ t('common.app.views.keys.scopeBodyA') }} <code>lazy-balancer://docs/ops-playbook</code> {{ t('common.app.views.keys.scopeBodyB') }}</div>
            </section>
            <section class="dialog-panel">
              <DialogSectionHeader :title="t('common.app.views.keys.commonFlowsTitle')" />
            <pre class="mcp-guide-pre">{{ t('common.app.views.keys.commonFlowsBody') }}</pre>
            </section>
            <section class="dialog-panel">
              <DialogSectionHeader :title="t('common.app.views.keys.playbookTitle')" />
            <div class="mcp-guide-text">{{ t('common.app.views.keys.playbookA') }} <code>resources/read</code> {{ t('common.app.views.keys.playbookRead') }} <code>lazy-balancer://docs/ops-playbook</code> {{ t('common.app.views.keys.playbookC') }}</div>
            <el-button size="small" :loading="mcpPlaybookDownloading" @click="downloadMCPPlaybook">{{ t('common.app.views.keys.downloadPlaybook') }}</el-button>
            </section>
          </div>
        </el-collapse-item>
        <el-collapse-item :title="t('common.app.views.keys.toolListTitle')" name="tools-list">
          <div class="info-note-bar mcp-table-scroll-hint"><span class="info-note-desc">{{ t('common.app.views.keys.toolListScrollHint') }}</span></div>
          <div v-loading="mcpToolsLoading" class="mcp-tools-table">
            <div v-if="mcpToolsError" class="info-note-bar">
              <span class="info-note-desc">{{ mcpToolsError }}</span>
              <span class="info-note-sub"><el-button size="small" @click="fetchMCPTools">{{ t('common.app.views.keys.reload') }}</el-button></span>
            </div>
            <div v-else class="dialog-panel dialog-panel--flush">
            <el-table :data="mcpTools" stripe max-height="38vh" :empty-text="t('common.app.views.keys.noTools')">
              <el-table-column type="expand">
                <template #default="scope">
                  <div class="mcp-tool-expand">
                    <div v-if="scope.row.usage" class="mcp-tool-usage"><span class="mcp-expand-label">{{ t('common.app.views.keys.usageLabel') }}</span>{{ scope.row.usage }}</div>
                    <template v-if="scope.row.input_schema">
                      <div class="mcp-expand-label">{{ t('common.app.views.keys.schemaLabel') }}</div>
                      <pre class="mcp-schema-pre">{{ formatSchema(scope.row.input_schema) }}</pre>
                    </template>
                    <div v-else class="mcp-tool-usage"><span class="mcp-expand-label">{{ t('common.app.views.keys.paramsLabel') }}</span>{{ t('common.app.views.keys.noParams') }}</div>
                  </div>
                </template>
              </el-table-column>
              <el-table-column prop="name" :label="t('common.app.views.keys.nameCol')" min-width="180" />
              <el-table-column :label="t('common.app.views.keys.descCol')" min-width="260">
                <template #default="scope">
                  <span class="mcp-tool-description">{{ scope.row.description }}</span>
                </template>
              </el-table-column>
              <el-table-column :label="t('common.app.views.keys.methodPathCol')" min-width="260">
                <template #default="scope">
                  <code>{{ scope.row.method }} {{ scope.row.path }}</code>
                </template>
              </el-table-column>
              <el-table-column :label="t('common.app.views.keys.typeCol')" width="90" align="center">
                <template #default="scope">
                  <el-tag :type="scope.row.read_only ? 'success' : 'warning'" size="small">
                    {{ scope.row.read_only ? t('common.app.views.keys.readOnly') : t('common.app.views.keys.write') }}
                  </el-tag>
                </template>
              </el-table-column>
            </el-table>
            </div>
          </div>
        </el-collapse-item>
      </el-collapse>
    </el-dialog>

    <el-dialog
      v-model="createDialogVisible"
      class="dialog-body-inset"
      width="min(620px, 92vw)"
      :close-on-click-modal="false"
      :close-on-press-escape="!creating"
      :show-close="!creating"
      top="6vh"
      @closed="resetCreateForm"
    >
      <template #header>
        <DialogHeader :icon="Key" :title="t('common.app.views.keys.createKeyTitle')" :subtitle="t('common.app.views.keys.createKeySubtitle')" tone="warning" />
      </template>
      <el-form label-width="auto" :disabled="creating">
        <el-form-item :label="t('common.app.views.keys.keyName')" :error="createNameError">
          <el-input v-model="createForm.name" maxlength="100" show-word-limit :placeholder="t('common.app.views.keys.enterKeyName')" @input="createNameError = ''" />
        </el-form-item>
        <el-divider content-position="left" class="section-divider">{{ t('common.app.views.keys.permSection') }}</el-divider>
        <el-form-item :label="t('common.app.views.keys.mcpFeature')">
          <el-switch v-model="createForm.mcp_enabled" />
          <span class="switch-hint">{{ t('common.app.views.keys.mcpFeatureHint') }}</span>
        </el-form-item>
        <el-form-item :label="t('common.app.views.keys.readOnlyMode')">
          <el-tooltip :disabled="isAdmin" :content="t('common.app.views.keys.readOnlyOnlyTip')" placement="top">
            <el-switch v-model="createForm.read_only" :disabled="!isAdmin" />
          </el-tooltip>
          <span class="switch-hint">{{ t('common.app.views.keys.readOnlyHint') }}</span>
        </el-form-item>
        <div v-if="createForm.read_only" class="info-note-bar readonly-alert"><span class="info-note-desc">{{ isAdmin ? t('common.app.views.keys.readOnlyNote') : t('common.app.views.keys.readOnlyOnlyTip') }}</span></div>
        <el-divider content-position="left" class="section-divider">{{ t('common.app.views.keys.expirySourceSection') }}</el-divider>
        <el-form-item :label="t('common.app.views.keys.expiresAt')" :error="createExpiresError">
          <el-date-picker
            v-model="createForm.expiresAt"
            type="datetime"
            clearable
            format="YYYY-MM-DD HH:mm:ss"
            :disabled-date="disablePastDate"
            :placeholder="t('common.app.views.keys.expiresPlaceholder')"
            style="width: 100%"
            @change="createExpiresError = ''"
          />
        </el-form-item>
        <el-form-item :label="t('common.app.views.keys.ipWhitelist')" :error="createWhitelistError">
          <el-input
            v-model="createForm.whitelistText"
            type="textarea"
            :rows="5"
            resize="vertical"
            :placeholder="t('common.app.views.keys.whitelistPlaceholder')"
            @input="createWhitelistError = ''"
          />
        </el-form-item>
        <div class="info-note-bar"><span class="info-note-desc">{{ t('common.app.views.keys.whitelistNote') }}</span></div>
      </el-form>
      <template #footer>
        <el-button :disabled="creating" @click="createDialogVisible = false">{{ t('common.app.views.keys.cancel') }}</el-button>
        <el-button type="primary" :loading="creating" @click="createKey">{{ t('common.app.views.keys.createBtn') }}</el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="featureDialogVisible"
      class="dialog-body-inset"
      width="min(620px, 92vw)"
      :close-on-click-modal="false"
      :close-on-press-escape="!featureSaving"
      :show-close="!featureSaving"
      top="6vh"
      @closed="resetFeatureForm"
    >
      <template #header>
        <DialogHeader :icon="Setting" :title="t('common.app.views.keys.featureConfig')" :subtitle="t('common.app.views.keys.featureTargetSubtitle', { name: featureTarget?.name || '' })" />
      </template>
      <el-form label-width="auto" :disabled="featureSaving">
        <el-divider content-position="left" class="section-divider">{{ t('common.app.views.keys.permSection') }}</el-divider>
        <el-form-item :label="t('common.app.views.keys.mcpFeature')">
          <el-switch v-model="featureForm.mcp_enabled" />
          <span class="switch-hint">{{ t('common.app.views.keys.mcpFeatureHint') }}</span>
        </el-form-item>
        <el-form-item :label="t('common.app.views.keys.readOnlyMode')">
          <el-tooltip :disabled="isAdmin" :content="t('common.app.views.keys.readOnlyOnlyTip')" placement="top">
            <el-switch v-model="featureForm.read_only" :disabled="!isAdmin" />
          </el-tooltip>
          <span class="switch-hint">{{ t('common.app.views.keys.readOnlyHint') }}</span>
        </el-form-item>
        <div v-if="featureForm.read_only" class="info-note-bar readonly-alert"><span class="info-note-desc">{{ isAdmin ? t('common.app.views.keys.readOnlyNote') : t('common.app.views.keys.readOnlyOnlyTip') }}</span></div>
        <el-divider content-position="left" class="section-divider">{{ t('common.app.views.keys.sourceRestrictSection') }}</el-divider>
        <el-form-item :label="t('common.app.views.keys.ipWhitelist')" :error="featureWhitelistError">
          <el-input
            v-model="featureForm.whitelistText"
            type="textarea"
            :rows="5"
            resize="vertical"
            :placeholder="t('common.app.views.keys.whitelistPlaceholder')"
            @input="featureWhitelistError = ''"
          />
        </el-form-item>
        <div class="info-note-bar"><span class="info-note-desc">{{ t('common.app.views.keys.whitelistNote') }}</span></div>
      </el-form>
      <template #footer>
        <el-button :disabled="featureSaving" @click="featureDialogVisible = false">{{ t('common.app.views.keys.cancel') }}</el-button>
        <el-button type="primary" :loading="featureSaving" @click="saveFeatures">{{ t('common.app.views.keys.save') }}</el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="createdKeyVisible"
      class="dialog-body-inset"
      width="min(560px, 92vw)"
      :close-on-click-modal="false"
      :before-close="closeCreatedKey"
      @closed="createdKey = ''"
    >
      <template #header>
        <DialogHeader :icon="CircleCheckFilled" :title="t('common.app.views.keys.createdTitle')" :subtitle="t('common.app.views.keys.createdSubtitle')" tone="success" />
      </template>
      <div class="info-note-bar"><span class="info-note-desc">{{ t('common.app.views.keys.createdNote') }}</span></div>
      <div class="dialog-panel created-key-box">
        <code class="created-key-text">{{ createdKey }}</code>
        <el-button type="primary" @click="copyCreatedKey">
          <el-icon><CopyDocument /></el-icon>
          {{ t('common.app.views.keys.copyKey') }}
        </el-button>
      </div>
      <template #footer>
        <el-button type="primary" @click="createdKeyVisible = false">{{ t('common.app.views.keys.savedAck') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted } from 'vue'
import { request, mfaAwareSuccess } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import { formatDate, formatDateShort } from '@/utils/date'
import { parseWhitelist, serializeWhitelist } from '@/utils/apiKeyWhitelist'
import { copyText } from '@/utils/copy'
import { createOneTimeSecretCloseGuard } from '@/utils/oneTimeSecretGuard'
import { saveBlob } from '@/utils/download'
import { ElMessageBox, ElMessage } from 'element-plus'
import { CircleCheckFilled, Connection, CopyDocument, Delete, Document, Key, Plus, Setting, SetUp, SwitchButton, VideoPlay } from '@element-plus/icons-vue'
import type { APIKey, APIResponse, CreateAPIKeyInput, MCPToolSpec, UpdateAPIKeyInput } from '@/types'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()
import DialogHeader from '@/components/DialogHeader.vue'
import DialogSectionHeader from '@/components/DialogSectionHeader.vue'

interface CreateAPIKeyResponse {
  readonly data?: {
    readonly id: number
    readonly key: string
    readonly message: string
  }
}

const authStore = useAuthStore()
// 从节点判定走 store 单源；节点模式未知仍按既有契约 fail-closed。
// 主节点非 admin 可管理本人密钥，因此不能复用全站 non-admin 只读门。
const nodeWriteBlocked = computed(() => authStore.isSlaveNode || authStore.readOnlyReason === 'unknown')
const nodeWriteBlockedReason = computed(() => authStore.isSlaveNode ? t('common.app.views.keys.slaveReadOnly') : t('common.app.views.keys.nodeUnknownReadOnly'))
const isAdmin = computed(() => authStore.user?.role === 'admin')

const keys = ref<readonly APIKey[]>([])
const loading = ref(false)
// 加载失败不得呈现为「暂无 API 密钥」——显性错误态 + 重试
const loadError = ref(false)
const creating = ref(false)
const createDialogVisible = ref(false)
const createNameError = ref('')
const createWhitelistError = ref('')
const createExpiresError = ref('')
const createForm = ref({ name: '', mcp_enabled: false, read_only: true, whitelistText: '', expiresAt: null as Date | null })
const featureDialogVisible = ref(false)
const featureSaving = ref(false)
const featureTarget = ref<APIKey | null>(null)
const featureWhitelistError = ref('')
const featureForm = ref({ mcp_enabled: false, read_only: false, whitelistText: '' })
const togglePendingId = ref<number | null>(null)
const deletingIds = ref(new Set<number>())
const createdKey = ref('')
const createdKeyVisible = ref(false)
/** 明文密钥仅此一次下发（库内只存哈希）：ESC / 右上角 X 关闭前必须确认已保存，
 *  否则误触即永久丢失、只能删除重建（一次性凭据守卫单源——与集群注册令牌、
 *  MFA 恢复码同实现）。 */
const closeCreatedKey = createOneTimeSecretCloseGuard({
  message: t('common.app.views.keys.closeGuardMessage'),
  title: t('common.app.views.keys.closeGuardTitle'),
})
const mcpDocsVisible = ref(false)
const mcpTools = ref<MCPToolSpec[]>([])
const mcpToolsLoading = ref(false)
const mcpToolsLoaded = ref(false)
const mcpToolsError = ref('')
const mcpServiceURL = new URL('/api/v1/mcp', window.location.origin).toString()
const mcpConfigJSON = computed(() => JSON.stringify({
  mcpServers: {
    'lazy-balancer': {
      transport: 'streamable_http',
      url: mcpServiceURL,
      headers: { 'X-API-Key': '<YOUR_API_KEY>' },
    },
  },
}, null, 2))
const copyMCPConfig = async (): Promise<void> => {
  if (await copyText(mcpConfigJSON.value)) {
    ElMessage.success(t('common.app.views.keys.mcpConfigCopied'))
    return
  }
  ElMessage.error(t('common.app.views.keys.copyConfigFailed'))
}
const formatSchema = (schema: Record<string, unknown>): string => JSON.stringify(schema, null, 2)
const mcpPlaybookDownloading = ref(false)
const downloadMCPPlaybook = async (): Promise<void> => {
  if (mcpPlaybookDownloading.value) return
  mcpPlaybookDownloading.value = true
  try {
    const blob = await request.get<Blob>('/mcp/ops-playbook', { responseType: 'blob' })
    saveBlob(blob, 'lazy-balancer-mcp-ops-playbook.md')
  } catch (error: unknown) {
    // 全局拦截器已弹 toast（blob 错误体会被解析出后端 message），这里仅记录
    console.error('Failed to download MCP playbook:', error)
  } finally {
    mcpPlaybookDownloading.value = false
  }
}
let keysRequestSeq = 0

const fetchKeys = async () => {
  const requestSeq = ++keysRequestSeq
  loading.value = true
  try {
    const res = await request.get<APIResponse<readonly APIKey[]>>('/users/me/api-keys')
    if (requestSeq === keysRequestSeq) {
      keys.value = res.data || []
      loadError.value = false
    }
  } catch (error: unknown) {
    // Error toast is already shown by the global axios interceptor; swallow here
    // so fire-and-forget refresh calls don't surface as unhandled rejections.
    console.error('Failed to fetch keys:', error)
    if (requestSeq === keysRequestSeq) loadError.value = true
  } finally {
    if (requestSeq === keysRequestSeq) loading.value = false
  }
}

// 白名单解析/归一/序列化/逐行 CIDR 校验收敛到 utils/apiKeyWhitelist 单源（可 node 行为测试）。

const whitelistEntries = (value: readonly string[]): string[] => value.filter(Boolean)

const whitelistSummary = (value: readonly string[]): string => {
  const entries = whitelistEntries(value)
  const preview = entries.slice(0, 3).join('、')
  return t('common.app.views.keys.whitelistSummary', { count: entries.length, preview, more: entries.length > 3 ? t('common.app.views.keys.summaryMore') : '' })
}

const openCreateDialog = (): void => {
  if (nodeWriteBlocked.value || creating.value) return
  resetCreateForm()
  createDialogVisible.value = true
}

const resetCreateForm = (): void => {
  createForm.value = { name: '', mcp_enabled: false, read_only: !isAdmin.value, whitelistText: '', expiresAt: null }
  createNameError.value = ''
  createWhitelistError.value = ''
  createExpiresError.value = ''
}

const keyExpired = (key: APIKey): boolean => {
  if (!key.expires_at) return false
  const expiresAt = new Date(key.expires_at).getTime()
  return Number.isFinite(expiresAt) && expiresAt < Date.now()
}

const disablePastDate = (date: Date): boolean => {
  const today = new Date()
  today.setHours(0, 0, 0, 0)
  return date.getTime() < today.getTime()
}

async function createKey() {
  if (nodeWriteBlocked.value || creating.value) return
  const name = createForm.value.name.trim()
  if (!name) {
    createNameError.value = t('common.app.views.keys.enterKeyName')
    return
  }
  const whitelist = serializeWhitelist(createForm.value.whitelistText)
  if (whitelist.error) {
    createWhitelistError.value = whitelist.error
    return
  }
  // 日期面板仅按天禁用过去日期，仍可选到当天早于现在的时刻；
  // 该值必被后端 400（apikeys.go「过期时间不能早于当前时间」）——提交前同文案拦截。
  if (createForm.value.expiresAt && createForm.value.expiresAt.getTime() < Date.now()) {
    createExpiresError.value = t('common.app.views.keys.expiresPastError')
    return
  }

  creating.value = true
  try {
    try {
      await ElMessageBox.confirm(t('common.app.views.keys.createConfirmMsg', { name }), t('common.app.views.keys.createKeyTitle'), {
        type: 'warning', confirmButtonText: t('common.app.views.keys.confirmCreate'), cancelButtonText: t('common.app.views.keys.cancel'),
      })
    } catch { return }
    const payload: CreateAPIKeyInput = {
      name,
      mcp_enabled: createForm.value.mcp_enabled,
      read_only: isAdmin.value ? createForm.value.read_only : true,
      mcp_ip_whitelist: whitelist.value,
      expires_at: createForm.value.expiresAt ? createForm.value.expiresAt.toISOString() : undefined,
    }
    const res = await request.post<CreateAPIKeyResponse>('/users/me/api-keys', payload)
    // 一次性明文是本次创建的唯一产出：响应缺 key（契约漂移/网关改写）时不得
    // 先报成功再关框——密钥已入库（列表会多一条），明文却永久不可得，用户只能
    // 删除重建。缺 key 即显性报错、保持创建框并刷新列表，把违约形态摆到眼前。
    if (!res.data?.key) {
      ElMessage.error(t('common.app.views.keys.createNoKeyError'))
      await fetchKeys()
      return
    }
    mfaAwareSuccess(t('common.app.views.keys.createSuccess'))
    createdKey.value = res.data.key
    createdKeyVisible.value = true
    createDialogVisible.value = false
    await fetchKeys()
  } catch (error: unknown) {
    // Error toast is already shown by the global axios interceptor.
    console.error('Failed to create API key:', error)
  } finally {
    creating.value = false
  }
}

const openFeatureDialog = (key: APIKey): void => {
  if (nodeWriteBlocked.value || featureSaving.value) return
  featureTarget.value = key
  featureForm.value = {
    mcp_enabled: key.mcp_enabled,
    read_only: isAdmin.value ? key.read_only : true,
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
  if (nodeWriteBlocked.value || featureSaving.value || !featureTarget.value) return
  const whitelist = serializeWhitelist(featureForm.value.whitelistText)
  if (whitelist.error) {
    featureWhitelistError.value = whitelist.error
    return
  }
  featureSaving.value = true
  try {
    try {
      await ElMessageBox.confirm(t('common.app.views.keys.featureSaveConfirmMsg', { name: featureTarget.value.name }), t('common.app.views.keys.featureSaveTitle'), {
        type: 'warning', confirmButtonText: t('common.app.views.keys.confirmSave'), cancelButtonText: t('common.app.views.keys.cancel'),
      })
    } catch { return }
    const payload: UpdateAPIKeyInput = {
      mcp_enabled: featureForm.value.mcp_enabled,
      read_only: isAdmin.value ? featureForm.value.read_only : true,
      mcp_ip_whitelist: whitelist.value,
    }
    await request.patch(`/users/me/api-keys/${featureTarget.value.id}`, payload)
    mfaAwareSuccess(t('common.app.views.keys.featureSaveSuccess'))
    featureDialogVisible.value = false
    await fetchKeys()
  } catch (error: unknown) {
    // Error toast is already shown by the global axios interceptor.
    console.error('Failed to save API key features:', error)
  } finally {
    featureSaving.value = false
  }
}

const deleteKey = async (id: number) => {
  if (nodeWriteBlocked.value || togglePendingId.value === id || deletingIds.value.has(id)) return
  deletingIds.value.add(id)
  try {
    await ElMessageBox.confirm(t('common.app.views.keys.deleteConfirmMsg'), t('common.app.views.keys.deleteTitle'), { type: 'warning', confirmButtonText: t('common.app.views.keys.confirmDelete'), cancelButtonText: t('common.app.views.keys.cancel') })
    await request.delete(`/users/me/api-keys/${id}`)
    mfaAwareSuccess(t('common.app.views.keys.deleteSuccess'))
    await fetchKeys()
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    console.error('Failed to delete API key:', error)
  } finally {
    deletingIds.value.delete(id)
  }
}

const toggleKey = async (key: APIKey) => {
  if (nodeWriteBlocked.value || togglePendingId.value !== null || deletingIds.value.has(key.id)) return
  const isEnabled = !key.is_enabled

  // 占位先于确认（同 TaskMonitor/ClusterSettings 范式）：确认框悬挂期也是「操作在途」，
  // 此时没有门，连点会叠出第二个确认框并重复写。
  togglePendingId.value = key.id
  try {
    if (!isEnabled) {
      try {
        await ElMessageBox.confirm(t('common.app.views.keys.disableConfirmMsg', { name: key.name }), t('common.app.views.keys.disableTitle'), {
          type: 'warning',
          confirmButtonText: t('common.app.views.keys.confirmDisable'),
          cancelButtonText: t('common.app.views.keys.cancel'),
        })
      } catch {
        return
      }
    }
    const payload: UpdateAPIKeyInput = { is_enabled: isEnabled }
    await request.patch(`/users/me/api-keys/${key.id}`, payload)
    mfaAwareSuccess(isEnabled ? t('common.app.views.keys.enableSuccess') : t('common.app.views.keys.disableSuccess'))
    await fetchKeys()
  } catch (error: unknown) {
    // Error toast is already shown by the global axios interceptor.
    console.error('Failed to toggle API key:', error)
  } finally {
    togglePendingId.value = null
  }
}

const copyCreatedKey = async () => {
  if (await copyText(createdKey.value)) {
    ElMessage.success(t('common.app.views.keys.keyCopied'))
    return
  }
  ElMessage.error(t('common.app.views.keys.copyKeyFailed'))
}

const fetchMCPTools = async (): Promise<void> => {
  if (mcpToolsLoading.value || mcpToolsLoaded.value) return
  mcpToolsLoading.value = true
  mcpToolsError.value = ''
  try {
    const response = await request.get<APIResponse<readonly MCPToolSpec[]>>('/mcp/tools')
    mcpTools.value = [...(response.data ?? [])].sort((left, right) => {
      const categoryOrder = Number(right.read_only) - Number(left.read_only)
      return categoryOrder || left.name.localeCompare(right.name)
    })
    mcpToolsLoaded.value = true
  } catch (error: unknown) {
    if (error instanceof Error) {
      mcpToolsError.value = t('common.app.views.keys.toolListLoadFailed', { reason: error.message })
      return
    }
    // 非 Error 异常同样置错误态——否则落入「暂无工具」误态。
    mcpToolsError.value = t('common.app.views.keys.toolListLoadFailed', { reason: String(error) || t('common.app.views.keys.unknownError') })
    console.error('Failed to fetch MCP tools:', error)
  } finally {
    mcpToolsLoading.value = false
  }
}

const copyMCPServiceURL = async (): Promise<void> => {
  if (await copyText(mcpServiceURL)) {
    ElMessage.success(t('common.app.views.keys.mcpUrlCopied'))
    return
  }
  ElMessage.error(t('common.app.views.keys.copyUrlFailed'))
}

onMounted(() => {
  fetchKeys()
})
</script>

<style scoped>
.section-divider { margin: 24px 0 20px; }
.section-divider :deep(.el-divider__text) { font-size: 14px; color: var(--text-secondary, #6b7280); font-weight: 600; }
.switch-hint { margin-left: 10px; font-size: 12px; color: var(--text-secondary, #6b7280); }
.header-actions { display: flex; gap: 8px; }
.header-actions :deep(a.el-button) { text-decoration: none; }
.header-actions :deep(.el-button .el-icon) { margin-right: 4px; }

.key-col { margin-bottom: 20px; }

.key-card-disabled { opacity: 0.72; }

.key-title-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.key-name { min-width: 0; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.feature-tags { display: flex; flex-wrap: wrap; gap: 6px; }

.key-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 16px; }
.key-actions :deep(.el-icon) { margin-right: 4px; }

.readonly-alert { margin: -2px 0 18px; }

.mcp-agent-guide { margin-bottom: 20px; }
.mcp-guide-text { color: var(--el-text-color-regular); font-size: 13px; line-height: 1.6; }
.mcp-guide-pre, .mcp-schema-pre { background: #f6f8fa; border-radius: 0; padding: 12px; font-family: 'SF Mono', Menlo, monospace; font-size: 12px; line-height: 1.55; overflow-x: auto; white-space: pre; }
.mcp-schema-pre { max-height: 320px; overflow-y: auto; }
.mcp-config-json { margin-top: 12px; }
.mcp-config-json :deep(textarea) { font-family: 'SF Mono', Menlo, monospace; font-size: 12px; }
.mcp-config-toolbar { display: flex; justify-content: flex-end; margin-top: 8px; }
.mcp-tool-expand { padding: 4px 12px 10px; }
.mcp-tool-usage { font-size: 13px; line-height: 1.6; margin-bottom: 8px; }
.mcp-expand-label { font-weight: 600; }
.mcp-table-scroll-hint { display: none; }
.mcp-tools-table { min-height: 120px; overflow-x: auto; }
.mcp-tools-table :deep(.el-table) { min-width: 800px; }
.mcp-tool-description { line-height: 1.5; white-space: normal; }
:deep(.mcp-docs-dialog .el-dialog__body) { max-height: calc(100dvh - 200px); overflow-y: auto; }

.created-key-box { display: flex; align-items: center; gap: 12px; margin-top: 20px; }

.created-key-text { flex: 1; min-width: 0; color: #111827; font-family: 'SF Mono', monospace; font-size: 12px; word-break: break-all; }

.empty-card { padding: 20px; }
.empty-card :deep(.el-empty__bottom) { margin-top: 16px; }

@media (max-width: 767px) {
  .page-header { align-items: flex-start; flex-direction: column; gap: 12px; }
  .header-actions { width: 100%; flex-wrap: wrap; }
  .key-actions { flex-wrap: wrap; }
}

@media (max-width: 1023px) {
  .mcp-table-scroll-hint { display: block; margin: -4px 0 8px; }
}
</style>
