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
      <el-col :span="24">
        <el-card class="config-card">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon><Document /></el-icon>
                <span>Caddy 配置预览 (JSON)</span>
              </div>
              <div class="card-actions">
                <el-button size="small" @click="refreshConfig" :loading="loading">
                  <el-icon><RefreshRight /></el-icon>刷新
                </el-button>
              </div>
            </div>
          </template>
          <div v-loading="loading" class="config-preview">
            <VueJsonPretty v-if="caddyConfigData" :data="caddyConfigData" :collapsed="false" show-length copyable :show-line="false" />
            <pre v-else>{{ '正在加载...' }}</pre>
          </div>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { request } from '@/utils/api'
import { Cpu, Document, RefreshRight } from '@element-plus/icons-vue'
import VueJsonPretty from 'vue-json-pretty'
import 'vue-json-pretty/lib/styles.css'

const caddyConfigData = ref<any>(null)
const loading = ref(false)

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

const refreshConfig = () => {
  fetchCaddyConfig()
}

onMounted(() => {
  fetchCaddyConfig()
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

.card-actions {
  display: flex;
  gap: 8px;
  align-items: center;
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
</style>
