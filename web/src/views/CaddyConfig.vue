<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Cpu /></el-icon>
          全局配置
        </h2>
        <p class="page-desc">管理 Caddy 配置和全局设置</p>
      </div>
    </div>

    <el-row :gutter="20">
      <el-col :span="24" class="mb-5">
        <el-card class="settings-card">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon><Setting /></el-icon>
                <span>Caddy 全局配置</span>
              </div>
            </div>
          </template>
          <el-form :model="caddySettings" label-width="180px" class="caddy-form">
            <el-divider content-position="left">运行日志</el-divider>
            <el-form-item label="日志级别">
              <el-select v-model="caddySettings.caddy_log_level" style="width: 120px;">
                <el-option label="debug" value="debug" />
                <el-option label="info" value="info" />
                <el-option label="warn" value="warn" />
                <el-option label="error" value="error" />
              </el-select>
              <span class="caddy-form-tip">生产环境建议 info；debug 会产生大量日志</span>
              <el-button type="primary" :icon="View" @click="openLogDialog" style="margin-left: auto;">查看日志</el-button>
            </el-form-item>
            <el-form-item label="日志大小">
              <el-input-number v-model="caddySettings.caddy_log_size_mb" :min="0" controls-position="right" style="width: 120px;" />
              <span class="caddy-form-tip">MB，单个文件达到此大小后自动滚动归档，保留 5 个历史文件；建议 100</span>
            </el-form-item>

            <el-divider content-position="left">请求与超时</el-divider>
            <el-form-item label="请求体大小">
              <el-input-number v-model="caddySettings.request_body_max_size_mb" :min="0" controls-position="right" style="width: 120px;" />
              <span class="caddy-form-tip">MB，限制单个请求体最大体积；0 = 不限制。常规建议 0，需防护大文件上传可设为 100</span>
            </el-form-item>
            <el-form-item label="读取超时">
              <el-input-number v-model="caddySettings.http_read_timeout" :min="0" controls-position="right" style="width: 120px;" />
              <span class="caddy-form-tip">秒，等待客户端发送请求体的最长时间；0 = Caddy 默认（无超时）。常规建议 60</span>
            </el-form-item>
            <el-form-item label="写入超时">
              <el-input-number v-model="caddySettings.http_write_timeout" :min="0" controls-position="right" style="width: 120px;" />
              <span class="caddy-form-tip">秒，向客户端写入响应的最长时间；0 = Caddy 默认（无超时）。常规建议 60</span>
            </el-form-item>
            <el-form-item label="空闲超时">
              <el-input-number v-model="caddySettings.http_idle_timeout" :min="0" controls-position="right" style="width: 120px;" />
              <span class="caddy-form-tip">秒，客户端到 Caddy 的 Keep-Alive 连接空闲多久后关闭；0 = Caddy 默认。常规建议 120</span>
            </el-form-item>
            <el-form-item label="上游 Keepalive">
              <el-input-number v-model="caddySettings.upstream_keepalive_timeout" :min="0" controls-position="right" style="width: 120px;" />
              <span class="caddy-form-tip">秒，Caddy 到后端服务器的长连接空闲多久后关闭；0 = Caddy 默认。常规建议 60</span>
            </el-form-item>

            <el-divider content-position="left">响应头</el-divider>
            <el-form-item label="Server Tokens">
              <el-switch v-model="caddySettings.server_tokens_hidden" active-text="开启" inactive-text="关闭" />
              <span class="caddy-form-tip">开启后在响应头中隐藏 Server 字段，减少服务器指纹暴露</span>
            </el-form-item>

            <el-divider content-position="left">访问日志</el-divider>
            <el-form-item label="自定义格式">
              <el-switch v-model="caddySettings.access_log_json" active-text="自定义 JSON" inactive-text="Caddy JSON" />
              <span class="caddy-form-tip">开启后使用 filter 编码器按自定义格式输出；关闭时输出 Caddy 原生完整 JSON</span>
            </el-form-item>
            <el-form-item label="日志格式" v-if="caddySettings.access_log_json">
              <el-input
                v-model="caddySettings.access_log_format"
                type="textarea"
                :rows="8"
                style="width: 100%"
                placeholder='每行一个字段映射，格式: caddy字段路径 -> 自定义名称，或 caddy字段路径 -> delete'
              />
              <div>
                <el-button text type="primary" size="small" @click="caddySettings.access_log_format = defaultLogFormat">还原默认格式</el-button>
              </div>
              <div class="caddy-form-tip">
                每行一条规则：字段重命名 <code>request>remote_ip -&gt; src</code> 或删除字段 <code>request>headers -&gt; delete</code>。
                可用字段：<code>request>remote_ip</code> <code>request>client_ip</code> <code>request>method</code> <code>request>host</code> <code>request>uri</code> <code>request>proto</code> <code>request>headers>User-Agent</code> <code>status</code> <code>size</code> <code>duration</code> <code>bytes_read</code> <code>user_id</code> <code>ts</code> <code>resp_headers</code> <code>request>tls</code>。
                Caddy 日志文档：<a href="https://caddyserver.com/docs/json/apps/http/servers/logs/" target="_blank">官方字段说明</a>
              </div>
            </el-form-item>
            <div class="form-actions">
              <el-button type="primary" :loading="saving" @click="handleSave">保存</el-button>
              <el-button type="warning" @click="handleReloadCaddy">重载 Caddy</el-button>
            </div>
          </el-form>
        </el-card>
      </el-col>

      <el-col :span="24">
        <el-collapse v-model="activeCollapse" @change="onCollapseChange">
          <el-collapse-item name="json-preview" title="Caddy 配置预览 (JSON)">
            <div class="config-toolbar">
              <el-button size="small" :loading="loading" :disabled="!isJsonExpanded" @click="refreshConfig">
                <el-icon><RefreshRight /></el-icon>刷新
              </el-button>
            </div>
            <div v-loading="loading" class="config-preview">
              <VueJsonPretty v-if="caddyConfigData" :data="caddyConfigData" :collapsed="false" show-length copyable :show-line="false" />
              <pre v-else>{{ '点击展开以加载配置' }}</pre>
            </div>
          </el-collapse-item>
        </el-collapse>
      </el-col>
  </el-row>

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
    <div
      ref="logContainerRef"
      class="log-viewer"
      v-html="logHtml"
    />
    <template #footer>
      <el-button @click="logDialogVisible = false">关闭</el-button>
    </template>
  </el-dialog>
</div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch, nextTick } from 'vue'
import { request } from '@/utils/api'
import { Cpu, RefreshRight, Setting, View } from '@element-plus/icons-vue'
import VueJsonPretty from 'vue-json-pretty'
import 'vue-json-pretty/lib/styles.css'
import { ElMessage, ElMessageBox } from 'element-plus'
import { ansiToHtml } from '@/utils/ansi'

const caddyConfigData = ref<any>(null)
const loading = ref(false)

const defaultLogFormat = 'request>headers -> delete\nresp_headers -> delete\nrequest>tls -> delete\nrequest>remote_port -> delete\nlevel -> delete\nlogger -> delete\nmsg -> delete\nrequest>remote_ip -> src\nrequest>client_ip -> src_ip\nrequest>method -> http_method\nrequest>host -> server\nrequest>uri -> uri_path\nrequest>proto -> protocol\nuser_id -> user\nts -> time_local\nsize -> bytes_out\nbytes_read -> bytes_in\nduration -> request_time'

const caddySettings = ref({
  caddy_log_path: '/app/logs/caddy.log',
  caddy_log_level: 'info',
  caddy_log_size_mb: 100,
  request_body_max_size_mb: 0,
  http_read_timeout: 60,
  http_write_timeout: 60,
  http_idle_timeout: 120,
  upstream_keepalive_timeout: 60,
  server_tokens_hidden: false,
  access_log_json: true,
  access_log_format: defaultLogFormat,
})

const saving = ref(false)
const activeCollapse = ref<string[]>([])

const logDialogVisible = ref(false)
const logContent = ref('')
const activeLogTab = ref('runtime')
const logHtml = computed(() => ansiToHtml(logContent.value))
const logLoading = ref(false)
const autoRefresh = ref(true)
const logContainerRef = ref<HTMLElement | null>(null)
let logPollTimer: ReturnType<typeof setInterval> | null = null

const fetchCaddyConfig = async () => {
  loading.value = true
  try {
    const res = await request.get('/caddy/config')
    if (res.data) {
      caddyConfigData.value = res.data
    }
  } catch (e: any) {
    caddyConfigData.value = null
  } finally {
    loading.value = false
  }
}

const fetchGlobalConfig = async () => {
  try {
    const res = await request.get('/config')
    if (res.data) {
      caddySettings.value = {
        caddy_log_path: res.data.caddy_log_path || '/app/logs/caddy.log',
        caddy_log_level: res.data.caddy_log_level || 'info',
        caddy_log_size_mb: res.data.caddy_log_size_mb ?? 100,
        request_body_max_size_mb: res.data.request_body_max_size_mb ?? 0,
        http_read_timeout: res.data.http_read_timeout ?? 60,
        http_write_timeout: res.data.http_write_timeout ?? 60,
        http_idle_timeout: res.data.http_idle_timeout ?? 120,
        upstream_keepalive_timeout: res.data.upstream_keepalive_timeout ?? 60,
        server_tokens_hidden: res.data.server_tokens_hidden ?? false,
        access_log_json: res.data.access_log_json ?? true,
        access_log_format: res.data.access_log_format || defaultLogFormat,
      }
    }
  } catch (e: any) {
    console.error('Failed to fetch global config:', e)
  }
}

const handleSave = async () => {
  try {
    await ElMessageBox.confirm('确认保存并重载 Caddy 配置？', '确认保存', {
      confirmButtonText: '确认',
      cancelButtonText: '取消',
      type: 'warning',
    })
  } catch {
    return
  }
  saving.value = true
  try {
    await request.put('/config', caddySettings.value)
    ElMessage.success('保存成功')
  } catch (e: any) {
    ElMessage.error('保存失败：' + (e?.response?.data?.message || e?.message || '配置验证未通过'))
  } finally {
    saving.value = false
  }
}

const handleReloadCaddy = async () => {
  try {
    await ElMessageBox.confirm('此操作将重新加载 Caddy 配置，是否继续？', '确认重载', {
      confirmButtonText: '确认',
      cancelButtonText: '取消',
      type: 'warning',
    })
    await request.post('/config/reload')
    ElMessage.success('Caddy 配置已重载')
  } catch (error: any) {
    if (error !== 'cancel') {
      console.error('Failed to reload Caddy:', error)
    }
  }
}

const isJsonExpanded = computed(() => activeCollapse.value.includes('json-preview'))

const onCollapseChange = (val: string[]) => {
  if (val.includes('json-preview') && !caddyConfigData.value) {
    fetchCaddyConfig()
  }
}

const refreshConfig = () => {
  fetchCaddyConfig()
}

const openLogDialog = () => {
  logDialogVisible.value = true
}

const onLogDialogOpened = () => {
  refreshLogs()
  startLogPolling()
}

const onLogDialogClosed = () => {
  stopLogPolling()
  logContent.value = ''
}

const startLogPolling = () => {
  stopLogPolling()
  if (autoRefresh.value) {
    logPollTimer = setInterval(refreshLogs, 2000)
  }
}

const stopLogPolling = () => {
  if (logPollTimer) {
    clearInterval(logPollTimer)
    logPollTimer = null
  }
}

const refreshLogs = async () => {
  logLoading.value = true
  try {
    const res: any = await request.get('/caddy/logs', { params: { type: activeLogTab.value } })
    logContent.value = res.data?.content || ''
    nextTick(scrollToBottom)
  } catch (e: any) {
    console.error('Failed to fetch caddy logs:', e)
  } finally {
    logLoading.value = false
  }
}

const onLogTabChange = () => {
  logContent.value = ''
  refreshLogs()
}

const scrollToBottom = () => {
  const el = logContainerRef.value
  if (el) {
    el.scrollTop = el.scrollHeight
  }
}

watch(autoRefresh, (val) => {
  if (!logDialogVisible.value) return
  if (val) {
    startLogPolling()
  } else {
    stopLogPolling()
  }
})

onMounted(() => {
  fetchGlobalConfig()
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

.card-header {
  display: flex;
  justify-content: space-between;
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

.config-toolbar {
  display: flex;
  justify-content: flex-end;
  margin-bottom: 12px;
}

.caddy-form {
  width: 100%;
  padding: 0 64px;
  box-sizing: border-box;
}

.caddy-form .el-input-number :deep(.el-input__inner) {
  text-align: left;
}

.caddy-form .el-input :deep(.el-input__inner) {
  text-align: left;
}

.caddy-form .el-select :deep(.el-input__inner) {
  text-align: left;
}

.caddy-form-tip {
  margin-left: 8px;
  font-size: 12px;
  color: #6b7280;
  vertical-align: middle;
}

.log-path-row {
  display: flex;
  gap: 12px;
  align-items: center;
  width: 100%;
}

.log-path-row .el-input {
  flex: 1;
}

.log-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.log-viewer {
  height: 65vh;
  min-height: 400px;
  max-height: 800px;
  overflow: auto;
  padding: 12px 16px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  font-size: 13px;
  line-height: 1.7;
  background: #0f172a;
  color: #e2e8f0;
  border: 1px solid #1e293b;
  border-radius: 4px;
  white-space: pre-wrap;
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 20px;
  padding-top: 16px;
  border-top: 1px solid var(--border);
}

.config-preview {
  background: #1e293b;
  border-radius: 6px;
  padding: 14px;
  max-height: 600px;
  overflow: auto;
}

:deep(.vjs-tree) {
  background: transparent;
  font-family: 'SF Mono', 'Monaco', 'Menlo', 'Consolas', monospace;
  font-size: 13px;
  line-height: 1.6;
  color: #e4e4e7;
}

:deep(.vjs-indent) {
  border-left: none !important;
}

:deep(.vjs-key) {
  color: #7dd3fc !important;
}

:deep(.vjs-value-string) {
  color: #86efac !important;
}

:deep(.vjs-value-number) {
  color: #fbbf24 !important;
}

:deep(.vjs-value-boolean) {
  color: #f472b6 !important;
}

:deep(.vjs-value-null),
:deep(.vjs-value-undefined) {
  color: #a78bfa !important;
  font-style: italic;
}

:deep(.vjs-tree-node:hover),
:deep(.vjs-tree-node.is-highlight),
:deep(.vjs-tree-node.dark:hover),
:deep(.vjs-tree-node.dark.is-highlight),
:deep(.vjs-tree-node .vjs-tree-node-actions) {
  background-color: rgba(59, 130, 246, 0.22) !important;
}

:deep(.vjs-tree-node:hover .vjs-key),
:deep(.vjs-tree-node:hover .vjs-value-string),
:deep(.vjs-tree-node:hover .vjs-value-number),
:deep(.vjs-tree-node:hover .vjs-value-boolean),
:deep(.vjs-tree-node:hover .vjs-value-null),
:deep(.vjs-tree-node:hover .vjs-value-undefined),
:deep(.vjs-tree-node:hover .vjs-tree-brackets),
:deep(.vjs-tree-node.is-highlight .vjs-key),
:deep(.vjs-tree-node.is-highlight .vjs-value-string),
:deep(.vjs-tree-node.is-highlight .vjs-value-number),
:deep(.vjs-tree-node.is-highlight .vjs-value-boolean),
:deep(.vjs-tree-node.is-highlight .vjs-value-null),
:deep(.vjs-tree-node.is-highlight .vjs-value-undefined),
:deep(.vjs-tree-node.is-highlight .vjs-tree-brackets) {
  color: #ffffff !important;
}

:deep(.vjs-tree-node .vjs-tree-node-actions) {
  background-color: rgba(59, 130, 246, 0.22) !important;
}

:deep(.vjs-tree-brackets:hover) {
  color: #ffffff !important;
}

:deep(.el-collapse) {
  background: var(--bg-primary);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  overflow: hidden;
}

:deep(.el-collapse-item__header) {
  padding: 14px 16px;
  font-size: 14px;
  font-weight: 600;
  color: var(--text-primary);
  background: var(--bg-primary);
}

:deep(.el-collapse-item__content) {
  padding: 0 16px 16px;
  background: var(--bg-primary);
}

:deep(.el-collapse-item__wrap) {
  background: var(--bg-primary);
}
</style>
