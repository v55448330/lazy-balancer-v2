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

    <el-form :model="settings" label-width="140px" class="caddy-form" :disabled="formFrozen">
      <el-divider content-position="left">运行日志</el-divider>
      <el-form-item label="日志级别">
        <el-select v-model="settings.caddy_log_level" :disabled="formFrozen" style="width: 140px">
          <el-option label="debug" value="debug" />
          <el-option label="info" value="info" />
          <el-option label="warn" value="warn" />
          <el-option label="error" value="error" />
        </el-select>
        <span class="form-tip-inline">建议 info；debug 日志量大</span>
      </el-form-item>
      <el-form-item label="日志大小">
        <el-input-number v-model="settings.caddy_log_size_mb" :disabled="formFrozen" :min="100" :max="10240" controls-position="right" class="number-input" />
        <span class="form-tip-inline tip-nowrap">MB，超限归档保留 5 份</span>
      </el-form-item>
      <el-form-item label="运行日志">
        <el-button size="small" :icon="View" @click="openLogDialog">查看日志</el-button>
        <span class="form-tip-inline">查看 Caddy 运行时、TLS、HTTP 服务器与反向代理日志</span>
      </el-form-item>

      <el-divider content-position="left">请求与超时</el-divider>
      <el-form-item label="请求体大小">
        <el-input-number v-model="settings.request_body_max_size_mb" :disabled="formFrozen" :min="1" :max="1024" controls-position="right" class="number-input" />
        <span class="form-tip-inline tip-nowrap">MB，请求体上限；默认 128，必须为 1-1024（0 不再表示默认）</span>
      </el-form-item>
      <el-form-item label="读取超时">
        <el-input-number v-model="settings.http_read_timeout" :disabled="formFrozen" :min="1" controls-position="right" class="number-input" />
        <span class="form-tip-inline tip-nowrap">秒，读请求超时；必须 ≥1（0 不再表示无超时），常用 60</span>
      </el-form-item>
      <el-form-item label="写入超时">
        <el-input-number v-model="settings.http_write_timeout" :disabled="formFrozen" :min="1" controls-position="right" class="number-input" />
        <span class="form-tip-inline">秒，写响应超时；必须 ≥1（0 不再表示无超时），常用 60</span>
      </el-form-item>
      <el-form-item label="空闲超时">
        <el-input-number v-model="settings.http_idle_timeout" :disabled="formFrozen" :min="1" controls-position="right" class="number-input" />
        <span class="form-tip-inline">秒，Keep-Alive 空闲超时；必须 ≥1（0 不再表示默认），常用 120</span>
      </el-form-item>
      <el-form-item label="上游 Keepalive">
        <el-input-number v-model="settings.upstream_keepalive_timeout" :disabled="formFrozen" :min="0" controls-position="right" class="number-input" />
        <span class="form-tip-inline">秒，上游空闲保持；0 = 默认 2 分钟</span>
      </el-form-item>

      <el-divider content-position="left">代理超时</el-divider>
      <ProxyTimeoutFields :value="settings" inherit-label="Caddy 默认" :disabled="formFrozen" show-suggested @update="updateProxyTimeout" />

      <el-divider content-position="left">响应头</el-divider>
      <el-form-item label="Server Tokens">
        <el-switch v-model="settings.server_tokens_hidden" :disabled="formFrozen" active-text="开启" inactive-text="关闭" />
        <span class="form-tip-inline">隐藏响应 Server 头，减少指纹暴露</span>
      </el-form-item>

      <el-divider content-position="left">安全防护</el-divider>
      <el-form-item label="受信代理">
        <div class="trusted-toggle">
          <el-switch v-model="settings.trusted_proxy_enabled" :disabled="formFrozen" active-text="开启" inactive-text="关闭" />
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
              :disabled="formFrozen"
              placeholder="粘贴该 CDN 回源网段（CIDR），以官方公布为准"
              class="trusted-field"
            />
            <el-button
              v-if="!isReadOnly"
              link
              type="primary"
              class="trusted-save-list-btn"
              :disabled="formFrozen || trustedRanges.length === 0"
              @click="openSaveListDialog"
            >存为列表</el-button>
          </div>
          <div v-if="trustedRangesError" class="form-tip-line trusted-ranges-error">{{ trustedRangesError }}</div>
          <div class="form-tip-line">仅这些网段发来的请求头会被采信；未配对网段时所有头一律被忽略（最小 /8 与 /29）。{{ trustedPresetRangesDoc }}</div>
        </el-form-item>
        <div v-if="ipListsLoadError" class="info-note-bar">
          <span class="info-note-desc">IP 地址列表加载失败：「引用地址列表」下拉为空≠未配置，下方「合计 N 条」也未计入已引用列表的条目</span>
          <el-button size="small" type="primary" plain :loading="ipListsLoading" @click="fetchIpLists">重新加载</el-button>
        </div>
        <el-form-item label="引用地址列表">
          <el-select
            v-model="trustedRangeRefs"
            multiple
            filterable
            :disabled="formFrozen"
            placeholder="选择要引用的 IP 地址列表"
            class="trusted-field"
          >
            <el-option v-for="l in customIpLists" :key="l.id" :label="`${l.name}（${l.entry_count} 条）`" :value="l.id" />
          </el-select>
          <div v-if="trustedTotalError" class="form-tip-line trusted-ranges-error">{{ trustedTotalError }}</div>
          <div v-else-if="trustedTotalWarning" class="form-tip-line">{{ trustedTotalWarning }}</div>
          <div v-if="refListEntriesRetryIds.length" class="info-note-bar">
            <span class="info-note-desc">{{ refListEntriesRetryIds.length }} 个引用列表的条目未加载成功，「合计」条数按名单记录数估算（重叠网段未去重）；若名单已被删除，保存会被拒绝；服务端以去重后结果为准</span>
            <el-button size="small" type="primary" plain @click="retryRefListEntries">重新加载名单条目</el-button>
          </div>
          <div class="form-tip-line">引用「规则集 → IP 地址列表」中的可复用列表，条目与上方内联网段合并生效（合计 {{ trustedRangesTotalCount }} 条，上限 {{ TRUSTED_PROXY_MAX_TOTAL_ENTRIES }}）</div>
        </el-form-item>
        <el-form-item label="请求头">
          <el-select
            v-model="trustedHeaders"
            multiple
            filterable
            allow-create
            default-first-option
            :disabled="formFrozen"
            placeholder="留空 = 仅 X-Forwarded-For"
            class="trusted-field"
          />
          <div v-if="trustedHeadersError" class="form-tip-line trusted-ranges-error">{{ trustedHeadersError }}</div>
          <div class="form-tip-line">按顺序优先取：把该 CDN 保证覆盖的权威头放最前。{{ trustedPresetNote }}</div>
        </el-form-item>
        <el-form-item label="预设填充">
          <el-select
            v-model="trustedPresetKey"
            :disabled="formFrozen"
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
          <el-switch v-model="settings.trusted_proxy_strict" :disabled="formFrozen" active-text="开启" inactive-text="关闭" />
          <el-tooltip content="关闭后按最左值取 IP，可被伪造，不建议关闭" placement="top">
            <span class="form-tip-inline">严格取「最右可信」值；关闭仅用于特殊代理链</span>
          </el-tooltip>
        </el-form-item>
      </template>

      <!-- 关闭态：隐藏字段仍参与后端写侧校验（与开关无关），非法存量值
           必须可见且给出可修复路径——否则用户看不到控件也无法定位。 -->
      <el-form-item v-else-if="trustedProxyDisabledStaleError" label="受信代理">
        <div class="form-tip-line trusted-ranges-error">{{ trustedProxyDisabledStaleError }}</div>
        <div class="form-tip-line">受信代理已关闭，但存量配置仍会被写侧校验：请临时开启「受信代理」修正上述条目后再关闭，否则保存会被拒绝。</div>
      </el-form-item>

      <el-divider content-position="left">访问日志</el-divider>
      <el-form-item label="自定义格式">
        <el-switch v-model="settings.access_log_json" :disabled="formFrozen" active-text="自定义 JSON" inactive-text="Caddy JSON" />
        <div class="form-tip-line">开启后使用 filter 编码器按自定义格式输出；关闭时输出 Caddy 原生 JSON（X-API-Key 请求头始终脱敏）。关闭后保存会清空已配置的自定义字段映射</div>
      </el-form-item>
      <el-form-item v-if="settings.access_log_json" label="日志格式">
        <div class="format-field">
          <el-input
            v-model="settings.access_log_format"
            type="textarea"
            :rows="8"
            maxlength="16384"
            show-word-limit
            :disabled="formFrozen"
            placeholder="每行一个字段映射，格式: caddy字段路径 -> 自定义名称，或 caddy字段路径 -> delete"
          />
          <el-button text type="primary" size="small" :disabled="formFrozen" @click="settings.access_log_format = DEFAULT_ACCESS_LOG_FORMAT">还原默认格式</el-button>
          <div class="form-tip-line format-tip">
            <!-- 上限与后端写侧门同源（internal/handlers/caddy.go：16KiB / 200 行，
                 按 UTF-8 字节计）——超限保存会被拒绝，先在此告知而不是让用户试错 -->
            <div>最多 200 行、16 KiB（后端按 UTF-8 字节计）；超限保存会被拒绝。</div>
            每行一条规则：字段重命名 <code>request&gt;remote_ip -&gt; src</code> 或删除字段 <code>request&gt;headers -&gt; delete</code>。
            无论格式如何，<code>request&gt;headers&gt;X-API-Key</code> 恒被删除（面板 API Key 不落日志）。
            可用字段：<code>request&gt;remote_ip</code> <code>request&gt;client_ip</code> <code>request&gt;method</code> <code>request&gt;host</code> <code>request&gt;uri</code> <code>request&gt;proto</code> <code>request&gt;headers&gt;User-Agent</code> <code>status</code> <code>size</code> <code>duration</code> <code>bytes_read</code> <code>user_id</code> <code>ts</code> <code>resp_headers</code> <code>request&gt;tls</code>。
            Caddy 日志文档：<a href="https://caddyserver.com/docs/json/apps/http/servers/logs/" target="_blank" rel="noopener noreferrer">官方字段说明</a>
          </div>
        </div>
      </el-form-item>
      <div class="form-actions">
        <el-button type="primary" :loading="saving" :disabled="isReadOnly || !props.configLoaded" @click="handleSave">保存</el-button>
        <el-button type="warning" :loading="reloading" :disabled="formFrozen || reloading" @click="handleReloadCaddy">重载 Caddy</el-button>
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
    <el-form label-width="80px" @submit.prevent :disabled="savingList">
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
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { RefreshRight, Setting, Tickets, View } from '@element-plus/icons-vue'
import { useAuthStore } from '@/stores/auth'
import { useLogTailPolling } from '@/composables/useLogTailPolling'
import { ansiToHtml } from '@/utils/ansi'
import { request, mfaAwareSuccess } from '@/utils/api'
import { CDN_PRESETS, DEFAULT_ACCESS_LOG_FORMAT } from '@/utils/caddyDefaults'
import { buildCaddyConfigPayload } from '@/utils/caddyConfigPayload'
import { TRUSTED_PROXY_MAX_TOTAL_ENTRIES, trustedProxyExpansion, trustedProxyHeadersError, trustedProxyRangesError, trustedProxyTotalError, trustedProxyTotalWarning } from '@/utils/trustedProxyRanges'
import type { TrustedProxyReferencedEntries } from '@/utils/trustedProxyRanges'
import { IP_LIST_CATEGORIES, parseIPList, parseRefIds } from '@/utils/securityStages'
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
// 父级 /config 加载完成前禁止保存：表单此刻仍是默认值——与 BasicSettings 同门
// （同族缺口：设置类表单均需此门）。
const props = defineProps<{ configLoaded: boolean }>()
const emit = defineEmits<{ (event: 'save'): void }>()
const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.readOnlyReason !== null)
const saving = ref(false)
// 保存中冻结整卡表单：Caddy 应用可达数秒，成功由父级回填整卡——在途编辑会被
// 静默覆盖（口径与 BasicSettings/策略向导一致）。
const formFrozen = computed(() => isReadOnly.value || saving.value)

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

// JSON 数组文本解析统一走 utils/securityStages（parseIPList/parseRefIds 单源，
// 原文件内 parseTrustedList/parseTrustedRefIds 与其逐字重复）。

// settings（外部回填/加载）→ 表单数组
watch(() => [settings.value.trusted_proxy_ranges, settings.value.trusted_proxy_headers, settings.value.trusted_proxy_range_refs], ([ranges, headers, refs]) => {
  trustedRanges.value = parseIPList(ranges)
  trustedHeaders.value = parseIPList(headers)
  trustedRangeRefs.value = parseRefIds(refs)
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
// 辅助端点失败必须显性化且可重试（与 Rules 页辅助数据横幅同口径）：下拉变空
// 不等于未配置，且已引用列表的条目数会按 0 汇总——静默会让用户误判引用丢失。
const ipListsLoadError = ref(false)
const ipListsLoading = ref(false)
const customIpLists = computed(() => ipLists.value.filter((l) => !l.system))
const fetchIpLists = async (): Promise<void> => {
  ipListsLoading.value = true
  try {
    const res = await request.get<APIResponse<TrustedIpListOption[]>>('/security/ip-lists', { silent: true })
    ipLists.value = res.data || []
    ipListsLoadError.value = false
    // 名单目录刷新成功 → 条目缓存一并失效（名单可能已被他处编辑）
    invalidateRefListEntries()
  } catch {
    ipLists.value = []
    ipListsLoadError.value = true
  } finally {
    ipListsLoading.value = false
  }
}
onMounted(() => { void fetchIpLists() })

// 引用名单条目缓存：总量门与后端同口径（规范化前缀并集），只拿 entry_count
// 无法识别「同一网段既内联又列在名单里」的重叠，会误拒实际展开规模未超限的
// 合法配置。条目按 id 惰性拉取一次（null=拉取失败/未返回，总量门退回条数估算）。
interface TrustedIpListDetail { id: number; entries?: { value: string }[] }
const refListEntries = ref<Record<number, string[] | null>>({})
// 拉取失败的引用 id：失败不写缓存键（下次 watch 触发可重试），但必须让用户
// 看到「合计 N 条」里有哪几个列表是按条数估算的，并提供一键重试——否则某份
// 名单条目接口瞬时失败后，本页再无重拉入口，只能改选引用或刷新整页。
const refListEntriesFailed = ref<Record<number, boolean>>({})
// 拉取在途集合（占位 null 之外的独立标记：失败后可随下次选择重试）
const refListEntriesLoading = new Set<number>()
// 会话内缓存失效：名单可能在别处被编辑/删除，重新拉取名单目录成功时
// 一并清空条目缓存并重排当前引用（否则「合计」用旧条目直到整页刷新）。
const invalidateRefListEntries = (): void => {
  refListEntries.value = {}
  refListEntriesFailed.value = {}
  refEntryQueue.length = 0
  for (const id of trustedRangeRefs.value) scheduleRefListEntries(id)
}
const fetchRefListEntries = async (id: number): Promise<void> => {
  if (id in refListEntries.value || refListEntriesLoading.has(id)) return
  refListEntriesLoading.add(id)
  try {
    const res = await request.get<APIResponse<TrustedIpListDetail>>(`/security/ip-lists/${id}`, { silent: true })
    refListEntries.value = {
      ...refListEntries.value,
      [id]: (res.data?.entries ?? []).map((entry) => String(entry.value ?? '')).filter((value) => value.trim() !== ''),
    }
    if (refListEntriesFailed.value[id]) {
      const next = { ...refListEntriesFailed.value }
      delete next[id]
      refListEntriesFailed.value = next
    }
  } catch {
    // 失败保持未知：总量门降级为提示且不硬拦（估算无法去重），保存由后端兜底
    refListEntriesFailed.value = { ...refListEntriesFailed.value, [id]: true }
  } finally {
    refListEntriesLoading.delete(id)
  }
}
// 引用条目无上限并行 fan-out 会在进入设置页时同时打 N 个详情请求
// （每份最多数千条），限并发 2 并去重排队。
const REF_ENTRY_FETCH_CONCURRENCY = 2
const refEntryQueue: number[] = []
let refEntryActive = 0
const drainRefEntryQueue = (): void => {
  while (refEntryActive < REF_ENTRY_FETCH_CONCURRENCY && refEntryQueue.length > 0) {
    const id = refEntryQueue.shift() as number
    if (id in refListEntries.value || refListEntriesLoading.has(id)) continue
    refEntryActive++
    void fetchRefListEntries(id).finally(() => {
      refEntryActive--
      drainRefEntryQueue()
    })
  }
}
const scheduleRefListEntries = (id: number): void => {
  if (id in refListEntries.value || refListEntriesLoading.has(id) || refEntryQueue.includes(id)) return
  refEntryQueue.push(id)
  drainRefEntryQueue()
}
watch(trustedRangeRefs, (ids) => {
  for (const id of ids) scheduleRefListEntries(id)
}, { immediate: true })

/** 条目未加载成功的引用 id（用于提示与重试入口）。 */
const refListEntriesRetryIds = computed(() => trustedRangeRefs.value.filter((id) => refListEntriesFailed.value[id]))
const retryRefListEntries = (): void => {
  const ids = refListEntriesRetryIds.value
  for (const id of ids) {
    const next = { ...refListEntriesFailed.value }
    delete next[id]
    refListEntriesFailed.value = next
  }
  for (const id of ids) scheduleRefListEntries(id)
}

const referencedLists = computed<TrustedProxyReferencedEntries[]>(() => trustedRangeRefs.value.map((id) => ({
  values: refListEntries.value[id] ?? null,
  entryCount: ipLists.value.find((l) => l.id === id)?.entry_count ?? 0,
})))
const trustedExpansion = computed(() => trustedProxyExpansion(trustedRanges.value, referencedLists.value))
// 合计展示与判据同源：并集（重叠网段只计一次），而非把内联条数与名单条数相加
const trustedRangesTotalCount = computed(() => trustedExpansion.value.union)
// 行内校验：非法/过宽条目进入表单即标红（判据单源 utils/trustedProxyRanges，
// 与后端 services.TrustedProxy* / normalizeTrustedProxyRanges 对表）——
// 原实现只在预览/PUT 时被整组拒绝，用户只拿到一次 toast 且无法定位是哪一条。
const trustedRangesError = computed(() => trustedProxyRangesError(trustedRanges.value))
// 请求头与总量同源判据：条数 ≤8 / 字符集（后端去重前判定）与「内联 ∪ 引用展开」
// ≤2000（后端去重前缀并集口径）——未知条目按条数估算，只在已知超限时拦。
const trustedHeadersError = computed(() => trustedProxyHeadersError(trustedHeaders.value))
const trustedTotalError = computed(() => trustedProxyTotalError(trustedRanges.value, referencedLists.value))
// 非阻断提示：估算合计越限但无法证明真实并集超限（含未加载条目时重叠无法去重）
// ——不拦保存，由后端按去重后的网段集合兜底判定。
const trustedTotalWarning = computed(() => trustedProxyTotalWarning(trustedRanges.value, referencedLists.value))
// 关闭态存量非法值：开关关闭不影响后端写侧校验，错误必须显性可见
const trustedProxyDisabledStaleError = computed(() =>
  settings.value.trusted_proxy_enabled
    ? ''
    : [trustedRangesError.value, trustedHeadersError.value, trustedTotalError.value].filter(Boolean).join('；'))

// —— 存为列表：内联网段一键建名单并转为引用（镜像策略侧「提取为列表」） ——
const saveListDialogVisible = ref(false)
const saveListForm = ref({ name: '受信代理网段', category: 'CDN 节点' })
const savingList = ref(false)
const openSaveListDialog = (): void => {
  saveListForm.value = { name: '受信代理网段', category: 'CDN 节点' }
  saveListDialogVisible.value = true
}
const confirmSaveAsList = async (): Promise<void> => {
  // 创建名单是写操作——弹框打开期间角色/节点模式变化时函数级拦截。
  if (isReadOnly.value || savingList.value) return
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
const autoRefresh = ref(true)
const logContainerRef = ref<HTMLElement | null>(null)

// 日志尾轮询收敛 useLogTailPolling 单源（补上原缺的后台标签页暂停；
// tab 切换/关闭的迟到响应守卫由 composable 序号 + fetch 内目标校验双层保证）。
const logTail = useLogTailPolling({
  interval: 2000,
  content: logContent,
  container: logContainerRef,
  isActive: () => logDialogVisible.value,
  fetch: async () => {
    const targetTab = activeLogTab.value
    const response = await request.get<CaddyLogsResponse>('/caddy/logs', { params: { type: targetTab }, silent: true })
    if (!logDialogVisible.value || activeLogTab.value !== targetTab) return null
    return response.data?.content || ''
  },
  onError: (error) => { console.error('Failed to fetch caddy logs:', error) },
})
const logLoading = logTail.loading
const refreshLogs = async (): Promise<void> => logTail.refresh()

const updateProxyTimeout = (field: keyof ProxyTimeoutConfig, value: number): void => {
  settings.value[field] = value
}

const handleSave = async (): Promise<void> => {
  // 配置未加载完成时表单为默认值——保存即整体覆盖真实配置
  if (!props.configLoaded) {
    ElMessage.warning('配置尚未加载完成，暂不能保存')
    return
  }
  if (isReadOnly.value || saving.value) return
  // 关闭态同样被后端写侧校验（开关不影响 validateTrustedProxyFields）：
  // 提示中给出「临时开启后修正」的修复路径，而不是让用户对着隐藏字段无计可施。
  const trustedGateMessage = (error: string): string =>
    settings.value.trusted_proxy_enabled ? error : `${error}（受信代理已关闭：请临时开启后修正）`
  // 非法/过宽网段在表单内即拦下（后端 PUT/preview 同样拒绝，但不点名具体条目）
  if (trustedRangesError.value) {
    ElMessage.warning(trustedGateMessage(trustedRangesError.value))
    return
  }
  // 请求头（条数/字符集）与「内联 + 引用展开」总量同源同门
  if (trustedHeadersError.value) {
    ElMessage.warning(trustedGateMessage(trustedHeadersError.value))
    return
  }
  if (trustedTotalError.value) {
    ElMessage.warning(trustedGateMessage(trustedTotalError.value))
    return
  }
  // 估算合计越限但无法证明真实并集超限（引用条目未加载，重叠未去重）：
  // 提示后继续保存，判定以后端去重后的集合为准——前端不得以估算否掉合法配置。
  if (trustedTotalWarning.value) ElMessage.warning(trustedTotalWarning.value)
  saving.value = true
  try {
    // 显式白名单：settings 是与 BasicSettings 共享的同一对象，全量展开会把
    // 兄弟卡片未保存的编辑（basic 键）连带提交；只发 caddy 键。
    // 载荷组装单源：关闭自定义 JSON 时剔除格式键（后端跨字段门会以 400 拒绝
    // 「json=false + 非空格式」，而清空入口又随开关隐藏）。
    const { payload: caddyPayload, accessLogFormatCleared } = buildCaddyConfigPayload(settings.value, CADDY_CONFIG_KEYS)
    const payload = { ...caddyPayload, source: 'caddy' }
    const preview = await request.post<ConfigPreviewResponse>('/config/preview', payload)
    const changed = preview.data?.changed ?? false
    if (changed) {
      const changes = preview.data?.changes?.length ? preview.data.changes.join('；') : '检测到配置变更'
      // 清空语义必须在确认框显性告知（载荷已剔除该键，用户此后无处可查）
      const clearedNote = accessLogFormatCleared ? '；已关闭自定义 JSON：库中自定义字段映射将被清空（该格式不生效）' : ''
      await ElMessageBox.confirm(`${changes}${clearedNote}`, `确认保存${preview.data?.section || 'Caddy 配置'}？`, {
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
    // 确认门在任何 reject 形态下都必须中止——原实现对非 cancel/close
    // 异常仅 console 后继续执行 /config/reload（与 ClusterSettings.confirmAction
    // / FreeCertificates 的 return 口径不一致）。
    if (error !== 'cancel' && error !== 'close') console.error('Unexpected MessageBox rejection:', error)
    return
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

const openLogDialog = (): void => { logDialogVisible.value = true }
const onLogDialogOpened = (): void => {
  if (autoRefresh.value) logTail.start()
  else void logTail.refresh()
}
const onLogDialogClosed = (): void => { logTail.stop(); logContent.value = '' }
const onLogTabChange = (): void => { logTail.invalidate(); logContent.value = ''; void logTail.refresh() }

watch(autoRefresh, (enabled) => {
  if (!logDialogVisible.value) return
  if (enabled) logTail.start()
  else logTail.stop()
})

onUnmounted(() => logTail.stop())
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
/* 行内校验提示：复用全局 form-tip-line 排版，仅追加危险色（不重定义全局类） */
.trusted-ranges-error { color: var(--el-color-danger, #f56c6c); }
.trusted-toggle { display: flex; flex-direction: column; align-items: flex-start; }
/* 单行描述(2026-09-19 图片报障):只加 nowrap,不做溢出裁切(窄屏容忍伸出) */
.tip-nowrap { white-space: nowrap; }
.format-field { width: 100%; min-width: 0; }
/* tip-inline/tip-block 旧式 el-text 已全量归一全局 form-tip-inline/
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
