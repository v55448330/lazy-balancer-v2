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
        <el-select v-model="settings.caddy_log_level" :disabled="isReadOnly" class="compact-select">
          <el-option label="debug" value="debug" />
          <el-option label="info" value="info" />
          <el-option label="warn" value="warn" />
          <el-option label="error" value="error" />
        </el-select>
        <el-text type="info" size="small" class="tip-inline">生产环境建议 info；debug 会产生大量日志</el-text>
      </el-form-item>
      <el-form-item label="日志大小">
        <el-input-number v-model="settings.caddy_log_size_mb" :disabled="isReadOnly" :min="100" :max="10240" controls-position="right" class="number-input" />
        <el-text type="info" size="small" class="tip-inline">MB，单个文件达到此大小后自动滚动归档，保留 5 个历史文件；建议 100</el-text>
      </el-form-item>
      <el-form-item label="运行日志">
        <el-button size="small" :icon="View" @click="openLogDialog">查看日志</el-button>
        <el-text type="info" size="small" class="tip-inline">查看 Caddy 运行时、TLS、HTTP 服务器与反向代理日志</el-text>
      </el-form-item>

      <el-divider content-position="left">请求与超时</el-divider>
      <el-form-item label="请求体大小">
        <el-input-number v-model="settings.request_body_max_size_mb" :disabled="isReadOnly" :min="0" controls-position="right" class="number-input" />
        <el-text type="info" size="small" class="tip-inline">MB，限制单个请求体最大体积；0 = 不限制。常规建议 0，需防护大文件上传可设为 100</el-text>
      </el-form-item>
      <el-form-item label="读取超时">
        <el-input-number v-model="settings.http_read_timeout" :disabled="isReadOnly" :min="0" controls-position="right" class="number-input" />
        <el-text type="info" size="small" class="tip-inline">秒，等待客户端发送请求体的最长时间；0 = Caddy 默认（无超时）。常规建议 60</el-text>
      </el-form-item>
      <el-form-item label="写入超时">
        <el-input-number v-model="settings.http_write_timeout" :disabled="isReadOnly" :min="0" controls-position="right" class="number-input" />
        <el-text type="info" size="small" class="tip-inline">秒，向客户端写入响应的最长时间；0 = Caddy 默认（无超时）。常规建议 60</el-text>
      </el-form-item>
      <el-form-item label="空闲超时">
        <el-input-number v-model="settings.http_idle_timeout" :disabled="isReadOnly" :min="0" controls-position="right" class="number-input" />
        <el-text type="info" size="small" class="tip-inline">秒，客户端到 Caddy 的 Keep-Alive 连接空闲多久后关闭；0 = Caddy 默认。常规建议 120</el-text>
      </el-form-item>
      <el-form-item label="上游 Keepalive">
        <el-input-number v-model="settings.upstream_keepalive_timeout" :disabled="isReadOnly" :min="0" controls-position="right" class="number-input" />
        <el-text type="info" size="small" class="tip-inline">秒，Caddy 到后端服务器的长连接空闲多久后关闭；0 = Caddy 默认。常规建议 60</el-text>
      </el-form-item>

      <el-divider content-position="left">响应头</el-divider>
      <el-form-item label="Server Tokens">
        <el-switch v-model="settings.server_tokens_hidden" :disabled="isReadOnly" active-text="开启" inactive-text="关闭" />
        <el-text type="info" size="small" class="tip-inline">开启后在响应头中隐藏 Server 字段，减少服务器指纹暴露</el-text>
      </el-form-item>

      <el-divider content-position="left">访问日志</el-divider>
      <el-form-item label="自定义格式">
        <el-switch v-model="settings.access_log_json" :disabled="isReadOnly" active-text="自定义 JSON" inactive-text="Caddy JSON" />
        <el-text type="info" size="small" class="tip-inline">开启后使用 filter 编码器按自定义格式输出；关闭时输出 Caddy 原生完整 JSON</el-text>
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
          <el-button text type="primary" size="small" :disabled="isReadOnly" @click="settings.access_log_format = defaultLogFormat">还原默认格式</el-button>
          <el-text type="info" size="small" class="format-tip">
            每行一条规则：字段重命名 <code>request&gt;remote_ip -&gt; src</code> 或删除字段 <code>request&gt;headers -&gt; delete</code>。
            可用字段：<code>request&gt;remote_ip</code> <code>request&gt;client_ip</code> <code>request&gt;method</code> <code>request&gt;host</code> <code>request&gt;uri</code> <code>request&gt;proto</code> <code>request&gt;headers&gt;User-Agent</code> <code>status</code> <code>size</code> <code>duration</code> <code>bytes_read</code> <code>user_id</code> <code>ts</code> <code>resp_headers</code> <code>request&gt;tls</code>。
            Caddy 日志文档：<a href="https://caddyserver.com/docs/json/apps/http/servers/logs/" target="_blank" rel="noopener noreferrer">官方字段说明</a>
          </el-text>
        </div>
      </el-form-item>
      <div class="form-actions">
        <el-button type="primary" :loading="saving" :disabled="isReadOnly" @click="handleSave">保存</el-button>
        <el-button type="warning" :disabled="isReadOnly" @click="handleReloadCaddy">重载 Caddy</el-button>
      </div>
    </el-form>
  </el-card>

  <el-dialog
    v-model="logDialogVisible"
    title="Caddy 日志"
    width="70%"
    :style="{ maxWidth: '70vw' }"
    class="log-dialog"
    destroy-on-close
    @opened="onLogDialogOpened"
    @closed="onLogDialogClosed"
  >
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
    <template #footer><el-button @click="logDialogVisible = false">关闭</el-button></template>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, nextTick, onUnmounted, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { RefreshRight, Setting, View } from '@element-plus/icons-vue'
import { useAuthStore } from '@/stores/auth'
import { ansiToHtml } from '@/utils/ansi'
import { request } from '@/utils/api'

type CaddySettingsConfig = {
  caddy_log_path: string
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
}

type ConfigPreviewResponse = {
  readonly data?: {
    readonly changed: boolean
    readonly section: string
    readonly changes: readonly string[]
  }
}

type CaddyLogsResponse = {
  readonly data?: { readonly content?: string }
}

const defaultLogFormat = 'resp_headers -> delete\nrequest>tls -> delete\nrequest>remote_port -> delete\nlevel -> delete\nlogger -> delete\nmsg -> delete\nrequest>remote_ip -> src\nrequest>client_ip -> src_ip\nrequest>method -> http_method\nrequest>host -> server\nrequest>uri -> uri_path\nrequest>proto -> protocol\nuser_id -> user\nts -> time_local\nsize -> bytes_out\nbytes_read -> bytes_in\nduration -> request_time'

const settings = defineModel<CaddySettingsConfig>('settings', { required: true })
const emit = defineEmits<{ (event: 'save'): void }>()
const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.readOnlyReason !== null)
const saving = ref(false)
const logDialogVisible = ref(false)
const logContent = ref('')
const activeLogTab = ref('runtime')
const logHtml = computed(() => ansiToHtml(logContent.value))
const logLoading = ref(false)
const autoRefresh = ref(true)
const logContainerRef = ref<HTMLElement | null>(null)
let logPollTimer: ReturnType<typeof setInterval> | null = null

const handleSave = async (): Promise<void> => {
  if (isReadOnly.value || saving.value) return
  saving.value = true
  try {
    const payload = { ...settings.value, source: 'caddy' }
    const preview = await request.post<ConfigPreviewResponse>('/config/preview', payload)
    if (preview.data?.changed) {
      const changes = preview.data.changes.length > 0 ? preview.data.changes.join('；') : '检测到配置变更'
      await ElMessageBox.confirm(changes, `确认保存${preview.data.section || 'Caddy 配置'}？`, {
        confirmButtonText: '确认', cancelButtonText: '取消', type: 'warning',
      })
    }
    await request.put('/config', payload)
    ElMessage.success('保存成功')
    emit('save')
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    if (error instanceof Error) {
      ElMessage.error(`保存失败：${error.message || '配置验证未通过'}`)
      return
    }
    throw error
  } finally {
    saving.value = false
  }
}

const handleReloadCaddy = async (): Promise<void> => {
  if (isReadOnly.value) return
  try {
    await ElMessageBox.confirm('此操作将重新加载 Caddy 配置，是否继续？', '确认重载', {
      confirmButtonText: '确认', cancelButtonText: '取消', type: 'warning',
    })
    await request.post('/config/reload')
    ElMessage.success('Caddy 配置已重载')
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    if (error instanceof Error) {
      console.error('Failed to reload Caddy:', error)
      return
    }
    throw error
  }
}

const stopLogPolling = (): void => {
  if (!logPollTimer) return
  clearInterval(logPollTimer)
  logPollTimer = null
}

const refreshLogs = async (): Promise<void> => {
  logLoading.value = true
  try {
    const response = await request.get<CaddyLogsResponse>('/caddy/logs', { params: { type: activeLogTab.value } })
    logContent.value = response.data?.content || ''
    await nextTick()
    const container = logContainerRef.value
    if (container) container.scrollTop = container.scrollHeight
  } catch (error: unknown) {
    if (error instanceof Error) {
      console.error('Failed to fetch caddy logs:', error)
      return
    }
    throw error
  } finally {
    logLoading.value = false
  }
}

const startLogPolling = (): void => {
  stopLogPolling()
  if (autoRefresh.value) logPollTimer = setInterval(() => { if (!logLoading.value) void refreshLogs() }, 2000)
}

const openLogDialog = (): void => { logDialogVisible.value = true }
const onLogDialogOpened = (): void => { void refreshLogs(); startLogPolling() }
const onLogDialogClosed = (): void => { stopLogPolling(); logContent.value = '' }
const onLogTabChange = (): void => { logContent.value = ''; void refreshLogs() }

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
.compact-select { width: 240px; max-width: 100%; }
.number-input { width: 120px; }
.tip-inline { margin-left: 8px; line-height: 1.5; }
.format-field { width: 100%; min-width: 0; }
.format-tip { display: block; margin-top: 4px; line-height: 1.5; white-space: normal; }
.format-tip a { color: var(--primary); text-decoration: none; }
.format-tip a:hover { text-decoration: underline; }
.form-actions { display: flex; justify-content: flex-end; gap: 12px; margin-top: 20px; padding-top: 16px; border-top: 1px solid var(--border); }
.log-toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.log-viewer { height: 65vh; min-height: 400px; max-height: 800px; overflow: auto; padding: 12px 16px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; font-size: 13px; line-height: 1.7; background: #0f172a; color: #e2e8f0; border: 1px solid #1e293b; border-radius: var(--radius-sm); white-space: pre-wrap; }

@media (max-width: 767px) {
  .card-header { align-items: flex-start; }
  .tip-inline { flex-basis: 100%; margin-top: 4px; margin-left: 0; }
}
</style>
