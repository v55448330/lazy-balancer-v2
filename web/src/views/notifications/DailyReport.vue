<template>
  <el-card shadow="never" v-loading="loading">
    <template #header>
      <div class="card-header-row">
        <span class="card-title">{{ t('app.notification.daily.title') }}</span>
        <div v-if="isAdmin" class="daily-header-actions">
          <el-tooltip :content="t('app.notification.daily.triggerHint')">
            <el-button size="small" :loading="triggering" @click="triggerDaily">
              {{ t('app.notification.daily.trigger') }}
            </el-button>
          </el-tooltip>
        </div>
      </div>
    </template>

    <el-empty v-if="loadError" :description="t('app.notification.daily.loadFailed')" :image-size="80" />
    <el-row v-else :gutter="20">
      <el-col :xs="24" :lg="12">
        <div class="section-head">{{ t('app.notification.daily.configTitle') }}</div>
        <el-form :label-width="$flw('120px')" :disabled="saving">
          <el-form-item :label="t('app.notification.daily.enabled')">
            <el-switch v-model="form.enabled" />
            <span class="switch-hint">{{ t('app.notification.daily.enabledHint') }}</span>
          </el-form-item>
          <el-form-item :label="t('app.notification.daily.sendTime')">
            <el-time-select v-model="form.sendTime" start="00:00" step="00:30" end="23:30" class="daily-time" />
            <span class="switch-hint">{{ t('app.notification.daily.sendTimeHint') }}</span>
          </el-form-item>
          <el-form-item :label="t('app.notification.daily.items')">
            <el-checkbox-group v-model="form.items" class="daily-items">
              <el-checkbox v-for="it in itemOptions" :key="it.id" :value="it.id" :label="it.id">
                {{ it.label }}
              </el-checkbox>
            </el-checkbox-group>
          </el-form-item>
          <el-form-item :label="t('app.notification.daily.format')">
        <span class="switch-hint">{{ t('app.notification.daily.formatNowInChannel') }}</span>
      </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="saving" :disabled="!canSave" @click="saveDaily">
              {{ t('app.notification.daily.save') }}
            </el-button>
          </el-form-item>
        </el-form>
      </el-col>
      <el-col :xs="24" :lg="12">
        <div class="section-head">{{ t('app.notification.daily.preview') }}</div>
        <div class="daily-preview-bar">
          <el-select v-model="previewFormat" class="daily-format">
            <el-option v-for="f in FORMAT_OPTIONS" :key="f.value" :value="f.value" :label="f.label" />
          </el-select>
          <el-button size="small" :loading="previewing" @click="previewDaily">{{ t('app.notification.daily.previewRun') }}</el-button>
        </div>
        <pre v-if="previewContent" class="daily-preview">{{ previewContent }}</pre>
        <el-empty v-else-if="!previewing" :description="t('app.notification.daily.previewEmpty')" :image-size="60" />
      </el-col>
    </el-row>

    <!-- 投递目标透明化：日报发送给谁→通过什么通道 -->
    <div v-if="dailyTargets.length" class="daily-targets">
      <div class="section-head">{{ t('app.notification.daily.targetsTitle') }}</div>
      <div v-for="tgt in dailyTargets" :key="tgt.username" class="daily-target-row">
        <el-icon class="target-user-icon"><User /></el-icon>
        <span class="target-username">{{ tgt.username }}</span>
        <span class="target-arrow">→</span>
        <el-tag v-for="ch in tgt.channels" :key="ch.type + ch.name" size="small" effect="plain">
          {{ ch.name }}（{{ ch.type }}）
        </el-tag>
        <span v-if="!tgt.channels.length" class="target-none">{{ t('app.notification.daily.noChannels') }}</span>
      </div>
    </div>
  </el-card>
</template>

<script setup lang="ts">
import { computed, ref, watch, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { User } from '@element-plus/icons-vue'


import { request, mfaAwareSuccess } from '@/utils/api'

const dailyTargets = ref<{ username: string; channels: { type: string; name: string }[] }[]>([])
const fetchDailyTargets = async (): Promise<void> => {
  try {
    const res = await request.get<{ code: number; data?: { targets: typeof dailyTargets.value } }>('/notification/daily/targets', { silent: true })
    dailyTargets.value = res.data?.targets ?? []
  } catch {
    dailyTargets.value = []
  }
}

import { useAuthStore } from '@/stores/auth'

const { t } = useI18n()
const authStore = useAuthStore()
const isAdmin = computed(() => authStore.user?.role === 'admin')

interface DailyConfigResponse {
  enabled: boolean
  send_time: string
  items: string[]
  formats: Record<string, string>
}

interface DailyGetResponse {
  code: number
  data?: {
    config: DailyConfigResponse
    items: string[]
    labels: Record<string, string>
  }
}

const loading = ref(false)
const loadError = ref(false)
const saving = ref(false)
const triggering = ref(false)
const previewing = ref(false)
const previewFormat = ref('markdown')
const previewLoadedOnce = ref(false)
const previewDaily = async (): Promise<void> => {
  if (previewing.value) return
  previewing.value = true
  try {
    const res = await request.post<{ code: number; data?: { content: string } }>('/notification/daily/preview', {
      items: form.value.items,
      format: previewFormat.value,
    })
    previewContent.value = res.data?.content ?? ''
    previewLoadedOnce.value = true
  } catch (error: unknown) {
    console.error('Failed to preview daily:', error)
  } finally {
    previewing.value = false
  }
}
// 配置变化即自动刷新预览（常驻右侧，不再按按钮生成）
watch([() => form.value.items, () => form.value.formats, previewFormat], () => {
  if (!previewLoadedOnce.value || previewing.value) return
  void previewDaily()
}, { deep: true })
// 预览格式默认跟随投递格式（用户仍可临时切换其它格式对比渲染效果）
const previewContent = ref('')
const itemOptions = ref<{ id: string; label: string }[]>([])

// 按用户配置的投递格式渲染（text/markdown/html/json 白名单与后端一一对应）
const FORMAT_OPTIONS = [
  { value: 'text', label: 'Text' },
  { value: 'markdown', label: 'Markdown' },
  { value: 'html', label: 'HTML' },
  { value: 'json', label: 'JSON' },
] as const

const form = ref<{ enabled: boolean; sendTime: string; items: string[]; formats: Record<string, string> }>({
  enabled: false,
  sendTime: '09:00',
  items: [],
  formats: {},
})


const canSave = computed(() => /^([01]\d|2[0-3]):[0-5]\d$/.test(form.value.sendTime) && form.value.items.length > 0)

const fetchDaily = async (): Promise<void> => {
  loading.value = true
  try {
    const res = await request.get<DailyGetResponse>('/notification/daily')
    const data = res.data
    const cfg = data?.config
    form.value = {
      enabled: cfg?.enabled ?? false,
      sendTime: cfg?.send_time ?? '09:00',
      items: cfg?.items ?? data?.items ?? [],
      formats: { ...(cfg?.formats ?? {}) },
    }
    itemOptions.value = (data?.items ?? []).map((id) => ({ id, label: data?.labels?.[id] ?? id }))
    loadError.value = false
  } catch (error: unknown) {
    console.error('Failed to fetch daily config:', error)
    loadError.value = true
  } finally {
    loading.value = false
  }
}

const saveDaily = async (): Promise<void> => {
  if (saving.value) return
  saving.value = true
  try {
    await request.put('/notification/daily', {
      enabled: form.value.enabled,
      send_time: form.value.sendTime,
      items: form.value.items,
      formats: form.value.formats,
    })
    mfaAwareSuccess(t('app.notification.daily.saved'))
  } catch (error: unknown) {
    console.error('Failed to save daily config:', error)
  } finally {
    saving.value = false
  }
}


const triggerDaily = async (): Promise<void> => {
  if (triggering.value) return
  triggering.value = true
  try {
    await request.post('/notification/daily/trigger', {})
    mfaAwareSuccess(t('app.notification.daily.triggered'))
  } catch (error: unknown) {
    console.error('Failed to trigger daily:', error)
  } finally {
    triggering.value = false
  }
}

onMounted(() => {
  void fetchDailyTargets()
  void fetchDaily()
  void fetchDailyTargets()
})
</script>

<style scoped>
.card-header-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.card-title { font-weight: 600; }
.daily-header-actions { display: flex; gap: 8px; }
.daily-items { display: flex; flex-wrap: wrap; gap: 4px 16px; }
.daily-time { width: 120px; }
.daily-format { width: 140px; }
.daily-preview-bar { display: flex; gap: 8px; align-items: center; }
.daily-preview {
  width: 100%;
  max-height: 320px;
  overflow: auto;
  margin: 8px 0 0;
  padding: 10px;
  font-size: 12px;
  line-height: 1.6;
  background: var(--el-fill-color-light);
  border-radius: 6px;
  white-space: pre-wrap;
  word-break: break-word;
}
.daily-format-map { margin-top: 6px; }
.daily-format-rows { display: flex; flex-direction: column; gap: 8px; }
.daily-format-row { display: flex; align-items: center; gap: 12px; }
.daily-format-channel { flex: none; width: 88px; font-size: 13px; text-align: right; }
.daily-format-row .daily-format { width: 220px; }
.daily-format-note { margin-top: 8px; font-size: 12px; color: var(--text-secondary, #6b7280); }
.switch-hint { margin-left: 10px; font-size: 12px; color: var(--text-secondary, #6b7280); }
.daily-targets { margin-top: 16px; padding-top: 14px; border-top: 1px solid var(--el-border-color-lighter); }
.section-head { font-weight: 600; font-size: 14px; margin-bottom: 10px; }
.daily-target-row { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; flex-wrap: wrap; }
.target-user-icon { color: var(--el-color-primary); }
.target-username { font-weight: 600; font-size: 13px; }
.target-arrow { color: var(--text-secondary, #6b7280); }
.target-none { font-size: 12px; color: var(--text-secondary, #6b7280); font-style: italic; }
</style>
