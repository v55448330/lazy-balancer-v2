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
          <el-form :model="caddySettings" label-width="240px" class="caddy-form">
            <el-form-item label="日志路径">
              <div class="log-path-row">
                <el-input v-model="caddySettings.caddy_log_path" readonly placeholder="/app/logs/caddy.log" />
                <el-button type="primary" :icon="View" @click="openLogDialog">查看</el-button>
              </div>
            </el-form-item>
            <el-form-item label="日志级别">
              <el-select v-model="caddySettings.caddy_log_level" class="caddy-input">
                <el-option label="debug" value="debug" />
                <el-option label="info" value="info" />
                <el-option label="warn" value="warn" />
                <el-option label="error" value="error" />
              </el-select>
            </el-form-item>
            <el-form-item label="日志大小 (MB)">
              <el-input-number v-model="caddySettings.caddy_log_size_mb" :min="0" controls-position="right" class="caddy-input" />
            </el-form-item>
            <el-form-item label="请求体最大大小 (MB)">
              <el-input-number v-model="caddySettings.request_body_max_size_mb" :min="0" controls-position="right" class="caddy-input" />
            </el-form-item>
            <el-form-item label="HTTP 读取超时 (秒)">
              <el-input-number v-model="caddySettings.http_read_timeout" :min="0" controls-position="right" class="caddy-input" />
            </el-form-item>
            <el-form-item label="HTTP 写入超时 (秒)">
              <el-input-number v-model="caddySettings.http_write_timeout" :min="0" controls-position="right" class="caddy-input" />
            </el-form-item>
            <el-form-item label="HTTP 空闲超时 (秒)">
              <el-input-number v-model="caddySettings.http_idle_timeout" :min="0" controls-position="right" class="caddy-input" />
            </el-form-item>
            <el-form-item label="上游 Keepalive 超时 (秒)">
              <el-input-number v-model="caddySettings.upstream_keepalive_timeout" :min="0" controls-position="right" class="caddy-input" />
            </el-form-item>
            <el-form-item label="隐藏 Server Tokens">
              <el-switch v-model="caddySettings.server_tokens_hidden" active-text="开启" inactive-text="关闭" />
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
    title="Caddy 运行日志"
    width="900px"
    destroy-on-close
    @opened="onLogDialogOpened"
    @closed="onLogDialogClosed"
  >
    <div class="log-toolbar">
      <el-switch v-model="autoRefresh" active-text="自动刷新" />
      <el-button type="primary" :loading="logLoading" size="small" @click="refreshLogs">
        <el-icon><RefreshRight /></el-icon>刷新
      </el-button>
    </div>
    <el-input
      v-model="logContent"
      type="textarea"
      :readonly="true"
      :rows="20"
      class="log-textarea"
      placeholder="暂无日志"
    />
    <template #footer>
      <el-button @click="logDialogVisible = false">关闭</el-button>
    </template>
  </el-dialog>
</div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { request } from '@/utils/api'
import { Cpu, RefreshRight, Setting, View } from '@element-plus/icons-vue'
import VueJsonPretty from 'vue-json-pretty'
import 'vue-json-pretty/lib/styles.css'
import { ElMessage, ElMessageBox } from 'element-plus'

const caddyConfigData = ref<any>(null)
const loading = ref(false)

const caddySettings = ref({
  caddy_log_path: '/app/logs/caddy.log',
  caddy_log_level: 'info',
  caddy_log_size_mb: 100,
  request_body_max_size_mb: 0,
  http_read_timeout: 0,
  http_write_timeout: 0,
  http_idle_timeout: 0,
  upstream_keepalive_timeout: 0,
  server_tokens_hidden: false,
})

const saving = ref(false)
const activeCollapse = ref<string[]>([])

const logDialogVisible = ref(false)
const logContent = ref('')
const logLoading = ref(false)
const autoRefresh = ref(true)
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
        http_read_timeout: res.data.http_read_timeout ?? 0,
        http_write_timeout: res.data.http_write_timeout ?? 0,
        http_idle_timeout: res.data.http_idle_timeout ?? 0,
        upstream_keepalive_timeout: res.data.upstream_keepalive_timeout ?? 0,
        server_tokens_hidden: res.data.server_tokens_hidden ?? false,
      }
    }
  } catch (e: any) {
    console.error('Failed to fetch global config:', e)
  }
}

const handleSave = async () => {
  saving.value = true
  try {
    await request.put('/config', caddySettings.value)
    ElMessage.success('保存成功')
  } catch (e: any) {
    ElMessage.error('保存失败')
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
    const res: any = await request.get('/caddy/logs')
    logContent.value = res.data?.content || ''
  } catch (e: any) {
    console.error('Failed to fetch caddy logs:', e)
  } finally {
    logLoading.value = false
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
  padding-left: 24px;
  padding-right: 24px;
  box-sizing: border-box;
}

.caddy-form .caddy-input {
  width: 100%;
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

.log-textarea :deep(.el-textarea__inner) {
  height: 500px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  font-size: 13px;
  line-height: 1.7;
  background: #0f172a;
  color: #e2e8f0;
  border: 1px solid #1e293b;
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
