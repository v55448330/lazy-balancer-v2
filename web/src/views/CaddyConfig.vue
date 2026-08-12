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
        <SyntaxHighlight v-if="caddyConfigData" :content="jsonText" language="json" />
        <el-empty v-else description="暂无配置" :image-size="64" />
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, shallowRef } from 'vue'
import { Cpu, Document, RefreshRight } from '@element-plus/icons-vue'
import SyntaxHighlight from '@/components/SyntaxHighlight.vue'
import { request } from '@/utils/api'

type JsonPrimitive = string | number | boolean | null
type JsonValue = JsonPrimitive | { readonly [key: string]: JsonValue } | JsonValue[]
type CaddyConfigResponse = { readonly data?: JsonValue }

const caddyConfigData = shallowRef<JsonValue | null>(null)
const loading = ref(false)
const jsonText = computed(() => JSON.stringify(caddyConfigData.value, null, 2))

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

</style>
