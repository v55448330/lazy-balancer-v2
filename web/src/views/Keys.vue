<template>
  <div class="page">
    <div class="page-header">
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
        <el-button @click="mcpDocsVisible = true">
          <el-icon><Connection /></el-icon>
          MCP 文档
        </el-button>
        <el-tooltip :disabled="!nodeWriteBlocked" :content="nodeWriteBlockedReason">
          <div>
            <el-button type="primary" :disabled="nodeWriteBlocked || creating" @click="openCreateDialog">
              <el-icon><Plus /></el-icon>
              创建密钥
            </el-button>
          </div>
        </el-tooltip>
      </div>
    </div>

    <el-alert v-if="loadError" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
      <template #title>
        <div class="polling-error-title">
          <span>API 密钥加载失败：密钥列表为空不代表没有密钥</span>
          <el-button link type="danger" @click="fetchKeys">立即重试</el-button>
        </div>
      </template>
    </el-alert>

    <el-row v-loading="loading" :gutter="20">
      <el-col v-for="key in keys" :key="key.id" :span="8" class="key-col">
        <el-card class="key-card" shadow="hover" :class="{ 'key-card-disabled': !key.is_enabled }">
          <template #header>
            <div class="key-title-row">
              <span class="key-name">{{ key.name }}</span>
              <el-tag v-if="keyExpired(key)" type="danger" size="small">已过期</el-tag>
              <el-tag v-else :type="key.is_enabled ? 'success' : 'info'" size="small">
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
                <el-tooltip v-if="whitelistEntries(key.mcp_ip_whitelist).length" :content="whitelistSummary(key.mcp_ip_whitelist)" placement="top">
                  <el-tag type="warning" size="small" effect="plain">IP 白名单</el-tag>
                </el-tooltip>
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
                  功能配置
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
                  {{ key.is_enabled ? '禁用' : '启用' }}
                </el-button>
              </div>
            </el-tooltip>
            <el-tooltip :disabled="!nodeWriteBlocked" :content="nodeWriteBlockedReason">
              <div>
                <el-button size="small" type="danger" :loading="deletingIds.has(key.id)" :disabled="nodeWriteBlocked || togglePendingId === key.id || deletingIds.has(key.id)" @click="deleteKey(key.id)">
                  <el-icon><Delete /></el-icon>
                  删除
                </el-button>
              </div>
            </el-tooltip>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-card v-if="!loading && keys.length === 0 && !loadError" class="empty-card">
      <el-empty description="暂无 API 密钥" :image-size="80" />
    </el-card>

    <el-dialog
      v-model="mcpDocsVisible"
      class="mcp-docs-dialog dialog-body-inset"
      width="min(1000px, 96vw)"
      top="5vh"
      @opened="fetchMCPTools"
    >
      <template #header>
        <DialogHeader :icon="SetUp" title="MCP 接入文档" subtitle="服务地址与接入配置，供 AI 客户端（Claude / Cursor 等）连接" />
      </template>
      <section class="dialog-panel mcp-connection-panel">
        <DialogSectionHeader title="接入配置" description="Streamable HTTP 服务地址与客户端 JSON" />
      <el-form label-position="top">
        <el-form-item label="MCP 服务地址（Streamable HTTP）">
          <el-input :model-value="mcpServiceURL" readonly>
            <template #append>
              <el-button aria-label="复制 MCP 服务地址" @click="copyMCPServiceURL">
                <el-icon><CopyDocument /></el-icon>
                复制
              </el-button>
            </template>
          </el-input>
        </el-form-item>
        <el-form-item label="MCP 客户端配置 JSON（粘贴到客户端，替换 <YOUR_API_KEY> 为密钥全文）">
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
                复制配置
              </el-button>
            </div>
            <div class="mcp-config-hints" style="margin-top: 6px">
              如客户端报证书错误，处置方式见下方「AI Agent 接入指南」自签证书段。密钥需保持 MCP 开启，只读 Key 仅暴露只读工具。
            </div>
          </div>
        </el-form-item>
      </el-form>
      </section>

      <div class="info-note-bar"><span class="info-note-desc">请求需通过 X-API-Key 头携带 API Key（兼容 Authorization: Bearer lb_sk_... 形式），且该 Key 必须开启 MCP 功能。read_only Key 仅能看到只读工具；配置 IP 白名单后，请求来源还必须命中白名单。</span></div>

      <el-collapse class="mcp-agent-guide">
        <el-collapse-item title="AI Agent 接入指南（协议流程 / 自签证书 / 错误码）" name="agent-guide">
          <div class="mcp-guide-block">
            <section class="dialog-panel">
              <DialogSectionHeader title="协议流程" :description="`Streamable HTTP · JSON-RPC 2.0 · POST ${mcpServiceURL}`" />
            <pre class="mcp-guide-pre">1) 初始化
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"your-agent","version":"1.0"}}}

2) 获取工具清单
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}

3) 调用工具（示例：获取指标总览）
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_metrics_overview","arguments":{}}}</pre>
            </section>
            <section class="dialog-panel">
              <DialogSectionHeader title="自签证书" description="可选配置" />
            <div class="mcp-guide-text">如客户端报证书错误，在启动环境加 <code>NODE_TLS_REJECT_UNAUTHORIZED=0</code>，或将面板证书加入系统信任。</div>
            </section>
            <section class="dialog-panel">
              <DialogSectionHeader title="常见错误" />
            <div class="mcp-guide-text">401：密钥无效或缺失 / JWT 无效；403：MCP 未开启 / 只读 Key 调用写工具或 export_config、get_caddy_config / 非管理员属主调用 validate_import、preview_config / 来源 IP 不在白名单；参数错误：校验在 REST 侧执行，以 IsError + 具体 message 文本返回（协议层不做 input_schema 校验，无 -32602）——读 message 修正后重试。</div>
            </section>
            <section class="dialog-panel">
              <DialogSectionHeader title="权限范围（scope）" />
            <div class="mcp-guide-text">只读 Key 可调用 GET 查询类工具（export_config 与 get_caddy_config 除外——前者导出含用户/密钥哈希，后者原始 Caddy 配置可能含内联私钥，对只读 Key 恒 403 且 tools/list 不展示）及 3 个读探测 POST 工具（parse_certificate / validate_import / preview_config）；其中 parse_certificate 对非管理员开放，validate_import 与 preview_config 要求 Key 属主为管理员（非管理员调用恒 403 且 tools/list 不展示）。证书配置测试与 CA 提供商测试会写入真实 DNS 记录/凭据，属写语义，只读 Key 不可用。其余写工具（POST/PUT/DELETE）需非只读 Key 且 Key 属主为管理员，仅在主节点可用（从节点一律 403——集群端点 promote_cluster / pull_sync / set_cluster_mode / forget_cluster_pins 除外，在从节点本身可用）。写操作校验后即时生效，失败自动回滚，无需手动 reload。完整口径以 <code>lazy-balancer://docs/ops-playbook</code> 资源为准。</div>
            </section>
            <section class="dialog-panel">
              <DialogSectionHeader title="常用流程" />
            <pre class="mcp-guide-pre">新建 HTTP 代理：create_rule（protocol=http + domain + listen_port + upstreams）
  → 需要免费证书再 issue_certificate 传 caddy_id
新建 TCP 代理：create_rule（protocol=tcp + listen_port + upstreams，不填 domain）
  → 后端需真实客户端 IP 加 tcp_proxy_protocol=true
排查流量异常：get_upstream_health → get_metrics_dashboard → list_audit_logs
快速看全局指标：get_metrics_overview（轻量）
  dashboard 为全量聚合、数据量大，非必要不用</pre>
            </section>
            <section class="dialog-panel">
              <DialogSectionHeader title="完整操作手册（MCP 资源）" />
            <div class="mcp-guide-text">Agent 连上后可通过 <code>resources/read</code> 读取 <code>lazy-balancer://docs/ops-playbook</code> 获取完整操作手册（接入/scope/工作流/排障/纪律/性能建议），无需访问代码仓库。</div>
            <el-button size="small" :loading="mcpPlaybookDownloading" @click="downloadMCPPlaybook">下载手册正文（markdown）</el-button>
            </section>
          </div>
        </el-collapse-item>
        <el-collapse-item title="工具清单" name="tools-list">
          <div class="mcp-table-scroll-hint">左右滑动表格可查看方法、REST 路径和类型</div>
          <div v-loading="mcpToolsLoading" class="mcp-tools-table">
            <div v-if="mcpToolsError" class="info-note-bar">
              <span class="info-note-desc">{{ mcpToolsError }}</span>
              <span class="info-note-sub"><el-button size="small" @click="fetchMCPTools">重新加载</el-button></span>
            </div>
            <div v-else class="dialog-panel dialog-panel--flush">
            <el-table :data="mcpTools" stripe max-height="38vh" empty-text="暂无工具">
              <el-table-column type="expand">
                <template #default="scope">
                  <div class="mcp-tool-expand">
                    <div v-if="scope.row.usage" class="mcp-tool-usage"><span class="mcp-expand-label">使用场景：</span>{{ scope.row.usage }}</div>
                    <template v-if="scope.row.input_schema">
                      <div class="mcp-expand-label">参数契约（input_schema）：</div>
                      <pre class="mcp-schema-pre">{{ formatSchema(scope.row.input_schema) }}</pre>
                    </template>
                    <div v-else class="mcp-tool-usage"><span class="mcp-expand-label">参数：</span>无（空对象调用）</div>
                  </div>
                </template>
              </el-table-column>
              <el-table-column prop="name" label="名称" min-width="180" />
              <el-table-column label="详细描述" min-width="260">
                <template #default="scope">
                  <span class="mcp-tool-description">{{ scope.row.description }}</span>
                </template>
              </el-table-column>
              <el-table-column label="方法与 REST 路径" min-width="260">
                <template #default="scope">
                  <code>{{ scope.row.method }} {{ scope.row.path }}</code>
                </template>
              </el-table-column>
              <el-table-column label="类型" width="90" align="center">
                <template #default="scope">
                  <el-tag :type="scope.row.read_only ? 'success' : 'warning'" size="small">
                    {{ scope.row.read_only ? '只读' : '写' }}
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
        <DialogHeader :icon="Key" title="创建 API 密钥" subtitle="lb_sk_ 前缀凭证，创建后仅显示一次" tone="warning" />
      </template>
      <el-form label-width="110px" :disabled="creating">
        <el-form-item label="密钥名称" :error="createNameError">
          <el-input v-model="createForm.name" maxlength="100" show-word-limit placeholder="请输入密钥名称" @input="createNameError = ''" />
        </el-form-item>
        <el-divider content-position="left" class="section-divider">权限</el-divider>
        <el-form-item label="MCP 功能">
          <el-switch v-model="createForm.mcp_enabled" />
          <span class="switch-hint">允许该密钥调用 MCP 工具接口</span>
        </el-form-item>
        <el-form-item label="只读模式">
          <el-tooltip :disabled="isAdmin" content="普通用户密钥仅支持只读权限" placement="top">
            <el-switch v-model="createForm.read_only" :disabled="!isAdmin" />
          </el-tooltip>
          <span class="switch-hint">开启后所有写操作被拒绝</span>
        </el-form-item>
        <div v-if="createForm.read_only" class="info-note-bar readonly-alert"><span class="info-note-desc">{{ isAdmin ? '只读模式开启后，该密钥的所有写操作都将被拒绝（包括 MCP 写操作）。' : '普通用户密钥仅支持只读权限' }}</span></div>
        <el-divider content-position="left" class="section-divider">有效期与来源限制</el-divider>
        <el-form-item label="过期时间" :error="createExpiresError">
          <el-date-picker
            v-model="createForm.expiresAt"
            type="datetime"
            clearable
            format="YYYY-MM-DD HH:mm:ss"
            :disabled-date="disablePastDate"
            placeholder="留空表示永不过期"
            style="width: 100%"
            @change="createExpiresError = ''"
          />
        </el-form-item>
        <el-form-item label="IP 白名单" :error="createWhitelistError">
          <el-input
            v-model="createForm.whitelistText"
            type="textarea"
            :rows="5"
            resize="vertical"
            placeholder="一行一个 CIDR，例如：10.0.0.0/8 或 192.168.1.10\n留空表示不限制来源 IP"
            @input="createWhitelistError = ''"
          />
        </el-form-item>
        <div class="info-note-bar"><span class="info-note-desc">IP 白名单约束该密钥的全部 REST 与 MCP 调用。</span></div>
      </el-form>
      <template #footer>
        <el-button :disabled="creating" @click="createDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="creating" @click="createKey">创建</el-button>
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
        <DialogHeader :icon="Setting" title="功能配置" :subtitle="`目标密钥：${featureTarget?.name || ''}`" />
      </template>
      <el-form label-width="110px" :disabled="featureSaving">
        <el-divider content-position="left" class="section-divider">权限</el-divider>
        <el-form-item label="MCP 功能">
          <el-switch v-model="featureForm.mcp_enabled" />
          <span class="switch-hint">允许该密钥调用 MCP 工具接口</span>
        </el-form-item>
        <el-form-item label="只读模式">
          <el-tooltip :disabled="isAdmin" content="普通用户密钥仅支持只读权限" placement="top">
            <el-switch v-model="featureForm.read_only" :disabled="!isAdmin" />
          </el-tooltip>
          <span class="switch-hint">开启后所有写操作被拒绝</span>
        </el-form-item>
        <div v-if="featureForm.read_only" class="info-note-bar readonly-alert"><span class="info-note-desc">{{ isAdmin ? '只读模式开启后，该密钥的所有写操作都将被拒绝（包括 MCP 写操作）。' : '普通用户密钥仅支持只读权限' }}</span></div>
        <el-divider content-position="left" class="section-divider">来源限制</el-divider>
        <el-form-item label="IP 白名单" :error="featureWhitelistError">
          <el-input
            v-model="featureForm.whitelistText"
            type="textarea"
            :rows="5"
            resize="vertical"
            placeholder="一行一个 CIDR，例如：10.0.0.0/8 或 192.168.1.10\n留空表示不限制来源 IP"
            @input="featureWhitelistError = ''"
          />
        </el-form-item>
        <div class="info-note-bar"><span class="info-note-desc">IP 白名单约束该密钥的全部 REST 与 MCP 调用。</span></div>
      </el-form>
      <template #footer>
        <el-button :disabled="featureSaving" @click="featureDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="featureSaving" @click="saveFeatures">保存</el-button>
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
        <DialogHeader :icon="CircleCheckFilled" title="API 密钥已创建" subtitle="仅显示一次，请立即复制并妥善保存" tone="success" />
      </template>
      <div class="info-note-bar"><span class="info-note-desc">此密钥仅显示一次，请立即复制并妥善保存。</span></div>
      <div class="dialog-panel created-key-box">
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
import { request, mfaAwareSuccess } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import { formatDate, formatDateShort } from '@/utils/date'
import { serializeWhitelist } from '@/utils/apiKeyWhitelist'
import { parseWhitelist } from '@/utils/apiKeyWhitelist'
import { copyText } from '@/utils/copy'
import { createOneTimeSecretCloseGuard } from '@/utils/oneTimeSecretGuard'
import { ElMessageBox, ElMessage } from 'element-plus'
import { CircleCheckFilled, Connection, CopyDocument, Delete, Document, Key, Plus, Setting, SetUp, SwitchButton, VideoPlay } from '@element-plus/icons-vue'
import type { APIKey, APIResponse, CreateAPIKeyInput, MCPToolSpec, UpdateAPIKeyInput } from '@/types'
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
const nodeWriteBlockedReason = computed(() => authStore.isSlaveNode ? '从节点只读，请在主节点操作' : '节点信息加载中，暂以只读模式呈现')
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
  message: '密钥仅此一次显示，关闭后将无法再次查看。确认已保存？',
  title: '保存密钥',
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
    ElMessage.success('MCP 配置已复制')
    return
  }
  ElMessage.error('复制失败，请手动复制配置')
}
const formatSchema = (schema: Record<string, unknown>): string => JSON.stringify(schema, null, 2)
const mcpPlaybookDownloading = ref(false)
const downloadMCPPlaybook = async (): Promise<void> => {
  if (mcpPlaybookDownloading.value) return
  mcpPlaybookDownloading.value = true
  try {
    const blob = await request.get<Blob>('/mcp/ops-playbook', { responseType: 'blob' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'lazy-balancer-mcp-ops-playbook.md'
    link.click()
    // Safari 下立即回收 objectURL 会截断下载文件，延迟 1s 再释放（与 BasicSettings 导出一致）
    setTimeout(() => URL.revokeObjectURL(url), 1000)
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

const whitelistEntries = (value: readonly string[]): string[] => parseWhitelist(value).split('\n').filter(Boolean)

const whitelistSummary = (value: readonly string[]): string => {
  const entries = whitelistEntries(value)
  const preview = entries.slice(0, 3).join('、')
  return `${entries.length} 条：${preview}${entries.length > 3 ? ' 等' : ''}`
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
    createNameError.value = '请输入密钥名称'
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
    createExpiresError.value = '过期时间不能早于当前时间'
    return
  }

  creating.value = true
  try {
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
      ElMessage.error('响应异常：密钥未返回，请在列表中删除该条目后重建')
      await fetchKeys()
      return
    }
    mfaAwareSuccess('密钥创建成功')
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
    const payload: UpdateAPIKeyInput = {
      mcp_enabled: featureForm.value.mcp_enabled,
      read_only: isAdmin.value ? featureForm.value.read_only : true,
      mcp_ip_whitelist: whitelist.value,
    }
    await request.patch(`/users/me/api-keys/${featureTarget.value.id}`, payload)
    mfaAwareSuccess('功能配置已更新')
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
    await ElMessageBox.confirm('将删除这个 API 密钥。删除后无法恢复，使用该密钥的调用会立即失效。', '删除 API 密钥', { type: 'warning', confirmButtonText: '确认删除', cancelButtonText: '取消' })
    await request.delete(`/users/me/api-keys/${id}`)
    mfaAwareSuccess('删除成功')
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
        await ElMessageBox.confirm(`确定要禁用 API 密钥“${key.name}”吗？禁用后该密钥将无法访问接口。`, '禁用确认', {
          type: 'warning',
          confirmButtonText: '确认禁用',
          cancelButtonText: '取消',
        })
      } catch {
        return
      }
    }
    const payload: UpdateAPIKeyInput = { is_enabled: isEnabled }
    await request.patch(`/users/me/api-keys/${key.id}`, payload)
    mfaAwareSuccess(isEnabled ? '密钥已启用' : '密钥已禁用')
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
    ElMessage.success('密钥已复制')
    return
  }
  ElMessage.error('复制失败，请手动复制密钥')
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
      mcpToolsError.value = `工具清单加载失败：${error.message}`
      return
    }
    // 非 Error 异常同样置错误态——否则落入「暂无工具」误态。
    mcpToolsError.value = `工具清单加载失败：${String(error) || '未知错误'}`
    console.error('Failed to fetch MCP tools:', error)
  } finally {
    mcpToolsLoading.value = false
  }
}

const copyMCPServiceURL = async (): Promise<void> => {
  if (await copyText(mcpServiceURL)) {
    ElMessage.success('MCP 服务地址已复制')
    return
  }
  ElMessage.error('复制失败，请手动复制 MCP 服务地址')
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
.mcp-config-hints { margin-top: 10px; color: var(--el-text-color-secondary); font-size: 12px; line-height: 1.8; }
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
  .mcp-table-scroll-hint { display: block; margin: -4px 0 8px; color: var(--el-text-color-secondary); font-size: 12px; }
}
</style>
