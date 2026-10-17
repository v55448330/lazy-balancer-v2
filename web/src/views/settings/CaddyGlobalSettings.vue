<template>
  <el-card class="settings-card">
    <template #header>
      <div class="card-header">
        <div class="card-title">
          <el-icon><Setting /></el-icon>
          <span>Caddy 全局配置</span>
        </div>
      </div>
    </template>

    <el-form :model="settings" label-width="140px" class="caddy-form">
      <el-divider content-position="left">运行日志</el-divider>
      <el-form-item label="日志级别">
        <el-select v-model="settings.caddy_log_level" :disabled="isReadOnly" style="width: 140px">
          <el-option label="debug" value="debug" />
          <el-option label="info" value="info" />
          <el-option label="warn" value="warn" />
          <el-option label="error" value="error" />
        </el-select>
        <span class="form-tip-inline">建议 info；debug 日志量大</span>
      </el-form-item>
      <el-form-item label="日志大小">
        <el-input-number v-model="settings.caddy_log_size_mb" :disabled="isReadOnly" :min="100" :max="10240" controls-position="right" class="number-input" />
        <span class="form-tip-inline tip-nowrap">MB，超限归档保留 5 份</span>
      </el-form-item>
      <el-form-item label="运行日志">
        <el-button size="small" :icon="View" @click="openLogDialog">查看日志</el-button>
        <span class="form-tip-inline">查看 Caddy 运行时、TLS、HTTP 服务器与反向代理日志</span>
      </el-form-item>

      <el-divider content-position="left">请求与超时</el-divider>
      <el-form-item label="请求体大小">
        <el-input-number v-model="settings.request_body_max_size_mb" :disabled="isReadOnly" :min="1" :max="4096" controls-position="right" class="number-input" />
        <span class="form-tip-inline tip-nowrap">MB，请求体上限；默认 128，必须为 1-4096（0 不再表示默认）</span>
      </el-form-item>
      <el-form-item label="读取超时">
        <el-input-number v-model="settings.http_read_timeout" :disabled="isReadOnly" :min="1" :max="86400" controls-position="right" class="number-input" />
        <span class="form-tip-inline tip-nowrap">秒，读请求超时；必须为 1-86400（0 不再表示无超时）</span>
      </el-form-item>
      <el-form-item label="写入超时">
        <el-input-number v-model="settings.http_write_timeout" :disabled="isReadOnly" :min="1" :max="86400" controls-position="right" class="number-input" />
        <span class="form-tip-inline">秒，写响应超时；必须为 1-86400（0 不再表示无超时）</span>
      </el-form-item>
      <el-form-item label="空闲超时">
        <el-input-number v-model="settings.http_idle_timeout" :disabled="isReadOnly" :min="1" :max="86400" controls-position="right" class="number-input" />
        <span class="form-tip-inline">秒，Keep-Alive 空闲超时；必须为 1-86400（0 不再表示默认）</span>
      </el-form-item>
      <el-form-item label="上游 Keepalive">
        <el-input-number v-model="settings.upstream_keepalive_timeout" :disabled="isReadOnly" :min="0" :max="86400" controls-position="right" class="number-input" />
        <span class="form-tip-inline">秒，上游空闲保持；0 = 默认 2 分钟</span>
      </el-form-item>

      <el-divider content-position="left">代理超时</el-divider>
      <ProxyTimeoutFields :value="settings" inherit-label="Caddy 默认" :disabled="isReadOnly" show-suggested @update="updateProxyTimeout" />

      <el-divider content-position="left">响应头</el-divider>
      <el-form-item label="Server Tokens">
        <el-switch v-model="settings.server_tokens_hidden" :disabled="isReadOnly" active-text="开启" inactive-text="关闭" />
        <span class="form-tip-inline">隐藏响应 Server 头，减少指纹暴露</span>
      </el-form-item>

      <el-divider content-position="left">安全防护</el-divider>
      <el-form-item label="受信代理">
        <div class="trusted-toggle">
          <el-switch v-model="settings.trusted_proxy_enabled" :disabled="isReadOnly" active-text="开启" inactive-text="关闭" />
          <div class="form-tip-line">CDN/前置代理回源时开启，按真实客户端 IP 判定名单/地域/限流</div>
        </div>
      </el-form-item>
      <template v-if="settings.trusted_proxy_enabled">
        <el-form-item label="受信网段">
          <div class="trusted-inline-row">
            <el-select
              v-model="trustedRanges"
              multiple
              filterable
              allow-create
              default-first-option
              :disabled="isReadOnly"
              placeholder="粘贴该 CDN 回源网段（CIDR），以官方公布为准"
              class="trusted-field"
            />
            <el-button
              v-if="!isReadOnly"
              link
              type="primary"
              class="trusted-save-list-btn"
              :disabled="trustedRanges.length === 0"
              @click="openSaveListDialog"
            >存为列表</el-button>
          </div>
          <div class="form-tip-line">仅这些网段发来的请求头会被采信；未配对网段时所有头一律被忽略（最小 /8 与 /96）。{{ trustedPresetRangesDoc }}</div>
        </el-form-item>
        <el-form-item label="引用地址列表">
          <el-select
            v-model="trustedRangeRefs"
            multiple
            filterable
            :disabled="isReadOnly"
            placeholder="选择要引用的 IP 地址列表"
            class="trusted-field"
          >
            <el-option v-for="l in customIpLists" :key="l.id" :label="`${l.name}（${l.entry_count} 条）`" :value="l.id" />
          </el-select>
          <div class="form-tip-line">引用「规则集 → IP 地址列表」中的可复用列表，条目与上方内联网段合并生效（合计 {{ trustedRangesTotalCount }} 条，上限 2000）</div>
        </el-form-item>
        <el-form-item label="请求头">
          <el-select
            v-model="trustedHeaders"
            multiple
            filterable
            allow-create
            default-first-option
            :disabled="isReadOnly"
            placeholder="留空 = 仅 X-Forwarded-For"
            class="trusted-field"
          />
          <div class="form-tip-line">按顺序优先取：把该 CDN 保证覆盖的权威头放最前。{{ trustedPresetNote }}</div>
        </el-form-item>
        <el-form-item label="预设填充">
          <el-select
            v-model="trustedPresetKey"
            :disabled="isReadOnly"
            placeholder="按 CDN 填充请求头"
            clearable
            class="trusted-preset-field"
            @change="applyTrustedPreset"
          >
            <el-option v-for="preset in CDN_PRESETS" :key="preset.label" :label="preset.label" :value="preset.label" />
          </el-select>
          <div class="form-tip-line">按所选 CDN 一键填充上方「请求头」推荐值；仅辅助输入，不影响已填内容以外的配置</div>
        </el-form-item>
        <el-form-item label="严格模式">
          <el-switch v-model="settings.trusted_proxy_strict" :disabled="isReadOnly" active-text="开启" inactive-text="关闭" />
          <el-tooltip content="关闭后按最左值取 IP，可被伪造，不建议关闭" placement="top">
            <span class="form-tip-inline">严格取「最右可信」值；关闭仅用于特殊代理链</span>
          </el-tooltip>
        </el-form-item>
      </template>

      <el-divider content-position="left">访问日志</el-divider>
      <el-form-item label="自定义格式">
        <el-switch v-model="settings.access_log_json" :disabled="isReadOnly" active-text="自定义 JSON" inactive-text="Caddy JSON" />
        <div class="form-tip-line">开启后使用 filter 编码器按自定义格式输出；关闭时输出 Caddy 原生完整 JSON</div>
      </el-form-item>
      <el-form-item v-if="settings.access_log_json" label="日志格式">
        <div class="format-field">
          <el-input
            v-model="settings.access_log_format"
            type="textarea"
            :rows="8"
            :disabled="isReadOnly"
            placeholder="每行一个字段映射，格式: caddy字段路径 -> 自定义名称，或 caddy字段路径 -> delete"
          />
          <el-button text type="primary" size="small" :disabled="isReadOnly" @click="settings.access_log_format = DEFAULT_ACCESS_LOG_FORMAT">还原默认格式</el-button>
          <div class="form-tip-line format-tip">
            每行一条规则：字段重命名 <code>request&gt;remote_ip -&gt; src</code> 或删除字段 <code>request&gt;headers -&gt; delete</code>。
            可用字段：<code>request&gt;remote_ip</code> <code>request&gt;client_ip</code> <code>request&gt;method</code> <code>request&gt;host</code> <code>request&gt;uri</code> <code>request&gt;proto</code> <code>request&gt;headers&gt;User-Agent</code> <code>status</code> <code>size</code> <code>duration</code> <code>bytes_read</code> <code>user_id</code> <code>ts</code> <code>resp_headers</code> <code>request&gt;tls</code>。
            Caddy 日志文档：<a href="https://caddyserver.com/docs/json/apps/http/servers/logs/" target="_blank" rel="noopener noreferrer">官方字段说明</a>
          </div>
        </div>
      </el-form-item>
      <div class="form-actions">
        <el-button type="primary" :loading="saving" :disabled="isReadOnly" @click="handleSave">保存</el-button>
        <el-button type="warning" :loading="reloading" :disabled="isReadOnly || reloading" @click="handleReloadCaddy">重载 Caddy</el-button>
      </div>
    </el-form>
  </el-card>

  <el-dialog
    v-model="logDialogVisible"
    width="min(1100px, 94vw)"
    top="5vh"
    class="log-dialog"
    destroy-on-close
    @opened="onLogDialogOpened"
    @close="onLogDialogClosed"
  >
    <template #header>
      <DialogHeader :icon="Tickets" title="Caddy 日志" subtitle="运行时 / TLS / HTTP 服务器 / 反向代理四通道实时日志" />
    </template>
    <el-tabs v-model="activeLogTab" @tab-change="onLogTabChange">
      <el-tab-pane label="运行时" name="runtime" />
      <el-tab-pane label="TLS" name="tls" />
      <el-tab-pane label="HTTP 服务器" name="server" />
      <el-tab-pane label="反向代理" name="proxy" />
    </el-tabs>
    <div class="log-toolbar">
      <el-switch v-model="autoRefresh" active-text="自动刷新" />
      <el-button type="primary" :loading="logLoading" size="small" @click="refreshLogs">
        <el-icon><RefreshRight /></el-icon>刷新
      </el-button>
    </div>
    <div ref="logContainerRef" class="log-viewer" v-html="logHtml" />
    <template #footer>
      <div style="display: flex; align-items: center;">
        <LogStorageBar :key="activeLogTab" :log-key="caddyTabLogKey" style="margin-right: auto" />
        <el-button @click="logDialogVisible = false">关闭</el-button>
      </div>
    </template>
  </el-dialog>

  <el-dialog
    v-model="saveListDialogVisible"
    width="min(480px, 92vw)"
    append-to-body
    :close-on-click-modal="false"
    :close-on-press-escape="!savingList"
    :show-close="!savingList"
  >
    <template #header>
      <DialogHeader :icon="Tickets" title="存为地址列表" subtitle="内联网段转为可复用的共享 IP 列表" />
    </template>
    <el-form label-width="80px" @submit.prevent>
      <el-form-item label="来源">
        <span>当前内联网段（{{ trustedRanges.length }} 条）</span>
      </el-form-item>
      <el-form-item label="列表名称" required>
        <el-input v-model="saveListForm.name" placeholder="列表名称" maxlength="50" show-word-limit />
      </el-form-item>
      <el-form-item label="分类">
        <el-select v-model="saveListForm.category" allow-create filterable default-first-option placeholder="选择或输入分类" style="width: 100%">
          <el-option v-for="c in IP_LIST_CATEGORIES" :key="c" :label="c" :value="c" />
        </el-select>
      </el-form-item>
    </el-form>
    <template #footer>
      <el-button @click="saveListDialogVisible = false" :disabled="savingList">取消</el-button>
      <el-button type="primary" :loading="savingList" @click="confirmSaveAsList">创建并引用</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { RefreshRight, Setting, Tickets, View } from '@element-plus/icons-vue'
import { useAuthStore } from '@/stores/auth'
import { ansiToHtml } from '@/utils/ansi'
import { request, mfaAwareSuccess } from '@/utils/api'
import { CDN_PRESETS, DEFAULT_ACCESS_LOG_FORMAT } from '@/utils/caddyDefaults'
import { IP_LIST_CATEGORIES } from '@/utils/securityStages'
import type { APIResponse, ProxyTimeoutConfig } from '@/types'
import ProxyTimeoutFields from '@/components/rules/ProxyTimeoutFields.vue'

type CaddySettingsConfig = ProxyTimeoutConfig & {
  caddy_log_level: string
  caddy_log_size_mb: number
  request_body_max_size_mb: number
  http_read_timeout: number
  http_write_timeout: number
  http_idle_timeout: number
  upstream_keepalive_timeout: number
  server_tokens_hidden: boolean
  access_log_json: boolean
  access_log_format: string
  // v2.3.x 受信代理（CDN 真实 IP）；range_refs 为引用列表 id 的 JSON 数组文本
  trusted_proxy_enabled: boolean
  trusted_proxy_ranges: string
  trusted_proxy_range_refs: string
  trusted_proxy_headers: string
  trusted_proxy_strict: boolean
}

type ConfigPreviewResponse = {
  readonly data?: {
    readonly changed: boolean
    readonly section: string
    readonly changes: readonly string[]
  }
}

// 与后端 internal/handlers/config_changes.go 的 caddy 键集合保持一致的唯一来源；
// 新增 caddy 全局键时只需在此常量与卡片表单各加一处，payload 自动覆盖。
const CADDY_CONFIG_KEYS = [
  'caddy_log_level',
  'caddy_log_size_mb',
  'request_body_max_size_mb',
  'http_read_timeout',
  'http_write_timeout',
  'http_idle_timeout',
  'upstream_keepalive_timeout',
  'server_tokens_hidden',
  'access_log_json',
  'access_log_format',
  'trusted_proxy_enabled',
  'trusted_proxy_ranges',
  'trusted_proxy_range_refs',
  'trusted_proxy_headers',
  'trusted_proxy_strict',
  'proxy_dial_timeout',
  'proxy_response_header_timeout',
  'proxy_read_timeout',
  'proxy_write_timeout',
  'proxy_stream_timeout',
  'proxy_flush_interval',
  'proxy_stream_close_delay',
] as const satisfies readonly (keyof CaddySettingsConfig)[]

type CaddyLogsResponse = {
  readonly data?: { readonly content?: string }
}

const settings = defineModel<CaddySettingsConfig>('settings', { required: true })
const emit = defineEmits<{ (event: 'save'): void }>()
const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.readOnlyReason !== null)
const saving = ref(false)

// —— 受信代理（CDN 真实 IP，v2.3.x）：settings 携 JSON 文本，表单用数组代理 ——
const trustedRanges = ref<string[]>([])
const trustedHeaders = ref<string[]>([])
// 引用地址列表（2026-10-12）：id 数组 ↔ trusted_proxy_range_refs JSON 文本
const trustedRangeRefs = ref<number[]>([])
const trustedPresetKey = ref('')
const trustedPresetNote = computed(() => CDN_PRESETS.find(p => p.label === trustedPresetKey.value)?.note || '')
const trustedPresetRangesDoc = computed(() => {
  const doc = CDN_PRESETS.find(p => p.label === trustedPresetKey.value)?.rangesDoc
  return doc ? `官方网段：${doc}` : ''
})

const parseTrustedList = (raw: string): string[] => {
  try {
    const parsed: unknown = JSON.parse(raw || '[]')
    return Array.isArray(parsed) ? parsed.filter((v): v is string => typeof v === 'string') : []
  } catch {
    return []
  }
}

const parseTrustedRefIds = (raw: string): number[] => {
  try {
    const parsed: unknown = JSON.parse(raw || '[]')
    return Array.isArray(parsed) ? parsed.filter((v): v is number => typeof v === 'number' && Number.isInteger(v)) : []
  } catch {
    return []
  }
}

// settings（外部回填/加载）→ 表单数组
watch(() => [settings.value.trusted_proxy_ranges, settings.value.trusted_proxy_headers, settings.value.trusted_proxy_range_refs], ([ranges, headers, refs]) => {
  trustedRanges.value = parseTrustedList(ranges)
  trustedHeaders.value = parseTrustedList(headers)
  trustedRangeRefs.value = parseTrustedRefIds(refs)
}, { immediate: true })
// 表单数组 → settings（保存载荷经 CADDY_CONFIG_KEYS 拾取 JSON 文本）
watch(trustedRanges, (list) => { settings.value.trusted_proxy_ranges = JSON.stringify(list) })
watch(trustedHeaders, (list) => { settings.value.trusted_proxy_headers = JSON.stringify(list) })
watch(trustedRangeRefs, (ids) => { settings.value.trusted_proxy_range_refs = JSON.stringify(ids) })

const applyTrustedPreset = (label: string): void => {
  const preset = CDN_PRESETS.find(p => p.label === label)
  if (!preset) return
  trustedHeaders.value = [...preset.headers]
}

// —— 引用地址列表选项（与策略侧引用选择器同数据源；仅非内置名单） ——
interface TrustedIpListOption { id: number; name: string; entry_count: number; system?: boolean }
const ipLists = ref<TrustedIpListOption[]>([])
const customIpLists = computed(() => ipLists.value.filter((l) => !l.system))
const fetchIpLists = async (): Promise<void> => {
  try {
    const res = await request.get<APIResponse<TrustedIpListOption[]>>('/security/ip-lists', { silent: true })
    ipLists.value = res.data || []
  } catch {
    // 静默失败：选择器退化为空列表，空警告按内联口径显示
    ipLists.value = []
  }
}
onMounted(() => { void fetchIpLists() })

// 空警告与合计：引用侧条数按选项缓存 entry_count 汇总（与后端展开上限同口径）
const referencedEntryCount = computed(() => trustedRangeRefs.value.reduce((sum, id) => sum + (ipLists.value.find((l) => l.id === id)?.entry_count ?? 0), 0))
const trustedRangesTotalCount = computed(() => trustedRanges.value.length + referencedEntryCount.value)

// —— 存为列表：内联网段一键建名单并转为引用（镜像策略侧「提取为列表」） ——
const saveListDialogVisible = ref(false)
const saveListForm = ref({ name: '受信代理网段', category: 'CDN 节点' })
const savingList = ref(false)
const openSaveListDialog = (): void => {
  saveListForm.value = { name: '受信代理网段', category: 'CDN 节点' }
  saveListDialogVisible.value = true
}
const confirmSaveAsList = async (): Promise<void> => {
  if (savingList.value) return
  const name = saveListForm.value.name.trim()
  if (!name) { ElMessage.warning('请输入列表名称'); return }
  if (name.length > 50) { ElMessage.warning('列表名称不能超过 50 字符'); return }
  if (saveListForm.value.category.length > 32) { ElMessage.warning('分类不能超过 32 字符'); return }
  const sourceEntries = trustedRanges.value.map((value) => value.trim()).filter((value) => value !== '')
  if (sourceEntries.length === 0) { ElMessage.warning('内联网段为空，无需存为列表'); return }
  savingList.value = true
  try {
    const res = await request.post<APIResponse<{ id: number }>>('/security/ip-lists', {
      name,
      description: '',
      category: saveListForm.value.category.trim(),
      // entries 与其余名单字段同口径：JSON 数组文本（后端 Entries 为 string）
      entries: JSON.stringify(sourceEntries.map((value) => ({ value, remark: '受信代理网段' }))),
    })
    const newId = res.data?.id
    if (!newId) throw new Error('创建列表响应缺少 id')
    // 交换语义：新建列表 → 并入 refs → 清空内联（合并生效集不变）；
    // 配置不在此保存——用户点「保存」才提交（PUT /config 落库并重载）
    trustedRangeRefs.value = [...new Set([...trustedRangeRefs.value, newId])]
    trustedRanges.value = []
    saveListDialogVisible.value = false
    // 刷新选项缓存：选择器与「合计 N 条」立即反映新列表
    await fetchIpLists()
    mfaAwareSuccess(`已创建列表「${name}」并转为引用，内联网段已清空（语义不变），保存配置后生效`)
  } catch (error: unknown) {
    // 409 重名 / 400 条目非法已由全局拦截器 toast，这里仅记录避免 unhandled rejection
    console.error('Failed to save trusted ranges as IP list:', error)
  } finally { savingList.value = false }
}
const reloading = ref(false)
const logDialogVisible = ref(false)
const logContent = ref('')
// 分通道统计:tab 切换时 LogStorageBar 随之切到对应通道的独立统计
const caddyTabLogKey = computed(() => ({
  runtime: 'caddy_runtime',
  tls: 'caddy_tls',
  server: 'caddy_server',
  proxy: 'caddy_proxy',
} as Record<string, string>)[activeLogTab.value] ?? 'caddy_runtime')

const activeLogTab = ref('runtime')
const logHtml = computed(() => ansiToHtml(logContent.value))
const logLoading = ref(false)
const autoRefresh = ref(true)
const logContainerRef = ref<HTMLElement | null>(null)
let logPollTimer: ReturnType<typeof setInterval> | null = null
let logRequestSeq = 0

const updateProxyTimeout = (field: keyof ProxyTimeoutConfig, value: number): void => {
  settings.value[field] = value
}

const handleSave = async (): Promise<void> => {
  if (isReadOnly.value || saving.value) return
  saving.value = true
  try {
    // 显式白名单：settings 是与 BasicSettings 共享的同一对象，全量展开会把
    // 兄弟卡片未保存的编辑（basic 键）连带提交；只发 caddy 键（R39 I-1）
    const payload = {
      ...Object.fromEntries(CADDY_CONFIG_KEYS.map((key) => [key, settings.value[key]] as const)),
      source: 'caddy',
    }
    const preview = await request.post<ConfigPreviewResponse>('/config/preview', payload)
    const changed = preview.data?.changed ?? false
    if (changed) {
      const changes = preview.data?.changes?.length ? preview.data.changes.join('；') : '检测到配置变更'
      await ElMessageBox.confirm(changes, `确认保存${preview.data?.section || 'Caddy 配置'}？`, {
        confirmButtonText: '确认', cancelButtonText: '取消', type: 'warning',
      })
    }
    const saved = await request.put('/config', payload)
    // 诚实提示（v2.3.2 用户反馈）：无变化时不得谎报「保存成功」
    if (!changed || saved?.message?.startsWith('配置无变化')) {
      ElMessage.info('配置无变化')
    } else {
      mfaAwareSuccess('保存成功')
    }
    emit('save')
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    // Error toast is already shown by the global axios interceptor.
    console.error('Failed to save Caddy global settings:', error)
  } finally {
    saving.value = false
  }
}

const handleReloadCaddy = async (): Promise<void> => {
  if (isReadOnly.value || reloading.value) return
  try {
    await ElMessageBox.confirm('此操作将重新加载 Caddy 配置，是否继续？', '确认重载', {
      confirmButtonText: '确认', cancelButtonText: '取消', type: 'warning',
    })
  } catch (error: unknown) {
    // MessageBox 仅以 'cancel'/'close' 字符串 reject（取消语义）；其余值仅记录，不再向上抛。
    if (error === 'cancel' || error === 'close') return
    console.error('Unexpected MessageBox rejection:', error)
  }
  if (reloading.value) return
  reloading.value = true
  try {
    await request.post('/config/reload')
    mfaAwareSuccess('Caddy 配置已重载')
  } catch (error: unknown) {
    console.error('Failed to reload Caddy:', error)
  } finally {
    reloading.value = false
  }
}

const stopLogPolling = (): void => {
  if (!logPollTimer) return
  clearInterval(logPollTimer)
  logPollTimer = null
}

const refreshLogs = async (): Promise<void> => {
  // 后台标签页暂停轮询：定时器空转跳过，回到可见后的下一个 tick 立即补拉
  if (document.hidden) return
  const targetTab = activeLogTab.value
  const requestSeq = ++logRequestSeq
  logLoading.value = true
  try {
    const response = await request.get<CaddyLogsResponse>('/caddy/logs', { params: { type: targetTab }, silent: true })
    if (requestSeq !== logRequestSeq || !logDialogVisible.value || activeLogTab.value !== targetTab) return
    logContent.value = response.data?.content || ''
    await nextTick()
    const container = logContainerRef.value
    if (container) container.scrollTop = container.scrollHeight
  } catch (error: unknown) {
    console.error('Failed to fetch caddy logs:', error)
  } finally {
    if (requestSeq === logRequestSeq) logLoading.value = false
  }
}

const startLogPolling = (): void => {
  stopLogPolling()
  if (autoRefresh.value) logPollTimer = setInterval(() => { if (!logLoading.value) void refreshLogs() }, 2000)
}

const openLogDialog = (): void => { logDialogVisible.value = true }
const onLogDialogOpened = (): void => { logRequestSeq++; void refreshLogs(); startLogPolling() }
const onLogDialogClosed = (): void => { logRequestSeq++; logLoading.value = false; stopLogPolling(); logContent.value = '' }
const onLogTabChange = (): void => { logRequestSeq++; logLoading.value = false; logContent.value = ''; void refreshLogs() }

watch(autoRefresh, (enabled) => {
  if (!logDialogVisible.value) return
  if (enabled) startLogPolling()
  else stopLogPolling()
})

onUnmounted(stopLogPolling)
</script>

<style scoped>
.card-header { display: flex; justify-content: space-between; align-items: center; gap: 16px; }
.card-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: var(--text-primary); }
.caddy-form { width: 100%; }
.number-input { width: 120px; }
.trusted-field { width: 100%; max-width: 560px; }
/* 内联网段行：选择器 + 「存为列表」链接钮（镜像策略侧 acl-inline-row 形态） */
.trusted-inline-row { display: flex; align-items: flex-start; gap: 8px; width: 100%; max-width: 560px; }
.trusted-inline-row .trusted-field { flex: 1; max-width: none; }
.trusted-save-list-btn { flex-shrink: 0; margin-top: 4px; }
.trusted-preset-field { width: 260px; }
.trusted-toggle { display: flex; flex-direction: column; align-items: flex-start; }
/* 单行描述(2026-09-19 图片报障):只加 nowrap,不做溢出裁切(窄屏容忍伸出) */
.tip-nowrap { white-space: nowrap; }
.format-field { width: 100%; min-width: 0; }
/* U9-68-P5-1：tip-inline/tip-block 旧式 el-text 已全量归一全局 form-tip-inline/
   form-tip-line（main.css 唯一事实源，scoped 重复定义删除）；format-tip 仅保留
   链接/行高补充样式 */
.format-tip { line-height: 1.5; }
.format-tip a { color: var(--primary); text-decoration: none; }
.format-tip a:hover { text-decoration: underline; }
.form-actions { display: flex; justify-content: flex-end; gap: 12px; margin-top: 20px; padding-top: 16px; border-top: 1px solid var(--border); }
.log-toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.log-viewer { height: 55vh; min-height: 320px; max-height: 700px; overflow: auto; padding: 12px 16px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; font-size: 13px; line-height: 1.7; background: #0f172a; color: #e2e8f0; border: 1px solid #1e293b; border-radius: var(--radius-sm); white-space: pre-wrap; }

@media (max-width: 767px) {
  .card-header { align-items: flex-start; }
}
</style>
