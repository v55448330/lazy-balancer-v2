<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Cpu /></el-icon>
          配置预览
        </h2>
        <p class="page-desc">查看从数据库渲染并应用到 Caddy 的完整配置</p>
      </div>
    </div>

    <el-card class="config-card">
      <template #header>
        <div class="card-header">
          <div class="card-title">
            <el-icon><Document /></el-icon>
            <span>Caddy 配置预览 (JSON)</span>
          </div>
          <el-button size="small" :loading="loading" @click="fetchCaddyConfig">
            <el-icon><RefreshRight /></el-icon>刷新
          </el-button>
        </div>
      </template>
      <div v-loading="loading" class="config-preview">
        <VueJsonPretty v-if="caddyConfigData" :data="caddyConfigData" :collapsed="false" show-length copyable :show-line="false" />
        <el-empty v-else description="暂无配置" :image-size="64" />
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref, shallowRef } from 'vue'
import { Cpu, Document, RefreshRight } from '@element-plus/icons-vue'
import VueJsonPretty from 'vue-json-pretty'
import 'vue-json-pretty/lib/styles.css'
import { request } from '@/utils/api'

type JsonPrimitive = string | number | boolean | null
type JsonValue = JsonPrimitive | { readonly [key: string]: JsonValue } | JsonValue[]
type CaddyConfigResponse = { readonly data?: JsonValue }

const caddyConfigData = shallowRef<JsonValue | null>(null)
const loading = ref(false)

const fetchCaddyConfig = async (): Promise<void> => {
  loading.value = true
  try {
    const response = await request.get<CaddyConfigResponse>('/caddy/config')
    caddyConfigData.value = response.data ?? null
  } catch (error: unknown) {
    caddyConfigData.value = null
    if (error instanceof Error) {
      console.error('Failed to fetch Caddy config:', error)
      return
    }
    throw error
  } finally {
    loading.value = false
  }
}

onMounted(() => void fetchCaddyConfig())
</script>

<style scoped>
.card-header { display: flex; justify-content: space-between; align-items: center; gap: 16px; }
.card-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: var(--text-primary); }
.config-preview { min-height: 160px; max-height: 720px; overflow: auto; padding: 14px; border-radius: var(--radius-md); background: #1e293b; }

:deep(.vjs-tree) { background: transparent; font-family: 'SF Mono', 'Monaco', 'Menlo', 'Consolas', monospace; font-size: 13px; line-height: 1.6; color: #e4e4e7; }
:deep(.vjs-indent) { border-left: none !important; }
:deep(.vjs-key) { color: #7dd3fc !important; }
:deep(.vjs-value-string) { color: #86efac !important; }
:deep(.vjs-value-number) { color: #fbbf24 !important; }
:deep(.vjs-value-boolean) { color: #f472b6 !important; }
:deep(.vjs-value-null),
:deep(.vjs-value-undefined) { color: #a78bfa !important; font-style: italic; }
:deep(.vjs-tree-node:hover),
:deep(.vjs-tree-node.is-highlight),
:deep(.vjs-tree-node.dark:hover),
:deep(.vjs-tree-node.dark.is-highlight),
:deep(.vjs-tree-node .vjs-tree-node-actions) { background-color: rgba(59, 130, 246, 0.22) !important; }
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
:deep(.vjs-tree-node.is-highlight .vjs-tree-brackets),
:deep(.vjs-tree-brackets:hover) { color: #ffffff !important; }
</style>
