<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Cpu /></el-icon>
          {{ t('common.app.views.caddyCfg.pageTitle') }}
        </h2>
        <p class="page-desc">{{ t('common.app.views.caddyCfg.pageDesc') }}</p>
      </div>
    </div>

    <!-- /caddy/config 仅 admin 组（middleware.go admin.GET("/caddy/config")），
         页面此前对全体登录用户可见、非管理员每次进入必得 403（横幅 + toast 双通道，
         无权限语义）。按角色渲染空态且不发请求——深链 #/caddy 同样被覆盖。从节点
         admin 的 GET 仍放行（readonly.go 只拦写），故不按 slave 收口。 -->
    <el-empty
      v-if="!canViewConfig"
      :description="permissionEmptyText"
      :image-size="64"
    />

    <template v-else>
      <el-alert
        v-if="fetchError"
        type="error"
        :closable="false"
        show-icon
        class="config-error-alert"
        :title="t('common.app.views.caddyCfg.loadFailedTitle')"
        :description="fetchError"
      />

      <el-card class="config-card">
        <template #header>
          <div class="card-header">
            <div class="card-title">
              <el-icon><Document /></el-icon>
              <span>{{ t('common.app.views.caddyCfg.cardTitle') }}</span>
            </div>
            <el-button size="small" :loading="loading" @click="fetchCaddyConfig">
              <el-icon><RefreshRight /></el-icon>{{ t('common.app.views.caddyCfg.refreshBtn') }}
            </el-button>
          </div>
        </template>
        <div v-loading="loading" class="config-preview">
          <SyntaxHighlight v-if="caddyConfigData" :content="jsonText" language="json" />
          <!-- 首拉失败且无数据时，空态不得误导读作「暂无配置」——错误横幅已
               在上方展示，此处改「加载失败」（有数据时保留最后渲染）。-->
          <el-empty v-else :description="fetchError ? t('common.app.views.caddyCfg.loadFailed') : t('common.app.views.caddyCfg.emptyConfig')" :image-size="64" />
        </div>
      </el-card>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, shallowRef, watch } from 'vue'
import { Cpu, Document, RefreshRight } from '@element-plus/icons-vue'
import SyntaxHighlight from '@/components/SyntaxHighlight.vue'
import { request } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

type JsonPrimitive = string | number | boolean | null
type JsonValue = JsonPrimitive | { readonly [key: string]: JsonValue } | JsonValue[]
type CaddyConfigResponse = { readonly data?: JsonValue }

const authStore = useAuthStore()
// 权限态收口——只有 admin 能读 /caddy/config（服务端另有纵深 403）。
// user 尚未拉到（null）时给「读取权限中」而非「无权限」，避免 admin 首屏误判。
const canViewConfig = computed(() => authStore.user?.role === 'admin')
const permissionEmptyText = computed(() => authStore.user === null ? t('common.app.views.caddyCfg.readingPermissions') : t('common.app.views.caddyCfg.adminOnlyHint'))

const caddyConfigData = shallowRef<JsonValue | null>(null)
const loading = ref(false)
const fetchError = ref<string | null>(null)
const jsonText = computed(() => JSON.stringify(caddyConfigData.value, null, 2))

const fetchCaddyConfig = async (): Promise<void> => {
  loading.value = true
  try {
    const response = await request.get<CaddyConfigResponse>('/caddy/config')
    caddyConfigData.value = response.data ?? null
    fetchError.value = null
  } catch (error: unknown) {
    // 拉取失败保留最后一份已渲染配置（全局拦截器已 toast），仅置页面级错误状态
    fetchError.value = error instanceof Error ? error.message : t('common.app.views.caddyCfg.loadFailedTitle')
    console.error('Failed to fetch Caddy config:', error)
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  if (canViewConfig.value) void fetchCaddyConfig()
})
// /users/me 若首拉失败（user=null）→ 角色补齐后自动补拉，无需用户手动刷新。
watch(canViewConfig, (allowed) => {
  if (allowed && caddyConfigData.value === null && fetchError.value === null && !loading.value) void fetchCaddyConfig()
})
</script>

<style scoped>
.config-error-alert { margin-bottom: 16px; }
.card-header { display: flex; justify-content: space-between; align-items: center; gap: 16px; }
.card-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: var(--text-primary); }
/* 滚动唯一归 SyntaxHighlight 内层（70vh 自滚）——外层不得叠加 max-height+
   overflow（双垂直滚动条根因，本页是唯一未传 height 的
   消费方）；外层只保留深色底框与最小高度。 */
.config-preview { min-height: 160px; overflow: visible; padding: 14px; border-radius: var(--radius-md); background: #1e293b; }

</style>
