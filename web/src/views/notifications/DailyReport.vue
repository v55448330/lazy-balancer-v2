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
    <el-form v-else :label-width="$flw('130px')" :disabled="saving">
      <el-form-item :label="t('app.notification.daily.enabled')">
        <el-switch v-model="form.enabled" />
        <span class="switch-hint">{{ t('app.notification.daily.enabledHint') }}</span>
      </el-form-item>
      <el-form-item :label="t('app.notification.daily.sendTime')">
        <el-time-select
          v-model="form.sendTime"
          :start="'00:00'"
          :step="'00:30'"
          :end="'23:30'"
          class="daily-time"
        />
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
        <el-select v-model="form.format" class="daily-format">
          <el-option v-for="f in FORMAT_OPTIONS" :key="f.value" :value="f.value" :label="f.label" />
        </el-select>
        <span class="switch-hint">{{ t('app.notification.daily.formatHint') }}</span>
        <div class="info-note-bar daily-format-map">
          <span class="info-note-desc">{{ t('app.notification.daily.formatChannelMap') }}</span>
        </div>
      </el-form-item>
      <el-form-item :label="t('app.notification.daily.preview')">
        <div class="daily-preview-bar">
          <el-select v-model="previewFormat" class="daily-format">
            <el-option v-for="f in FORMAT_OPTIONS" :key="f.value" :value="f.value" :label="f.label" />
          </el-select>
          <el-button :loading="previewing" @click="previewDaily">{{ t('app.notification.daily.previewRun') }}</el-button>
        </div>
        <pre v-if="previewContent" class="daily-preview">{{ previewContent }}</pre>
      </el-form-item>
      <el-form-item>
        <el-button type="primary" :loading="saving" :disabled="!canSave" @click="saveDaily">
          {{ t('app.notification.daily.save') }}
        </el-button>
      </el-form-item>
    </el-form>
  </el-card>
</template>

<script setup lang="ts">
import { computed, ref, watch, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { request, mfaAwareSuccess } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'

const { t } = useI18n()
const authStore = useAuthStore()
const isAdmin = computed(() => authStore.user?.role === 'admin')

interface DailyConfigResponse {
  enabled: boolean
  send_time: string
  items: string[]
  format: string
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
// 预览格式默认跟随投递格式（用户仍可临时切换其它格式对比渲染效果）
watch(() => form.value.format, (v) => { previewFormat.value = v })
const previewContent = ref('')
const itemOptions = ref<{ id: string; label: string }[]>([])

// 按用户配置的投递格式渲染（text/markdown/html/json 白名单与后端一一对应）
const FORMAT_OPTIONS = [
  { value: 'text', label: 'Text' },
  { value: 'markdown', label: 'Markdown' },
  { value: 'html', label: 'HTML' },
  { value: 'json', label: 'JSON' },
] as const

const form = ref<{ enabled: boolean; sendTime: string; items: string[]; format: string }>({
  enabled: false,
  sendTime: '09:00',
  items: [],
  format: 'markdown',
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
      format: cfg?.format ?? 'markdown',
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
      format: form.value.format,
    })
    mfaAwareSuccess(t('app.notification.daily.saved'))
  } catch (error: unknown) {
    console.error('Failed to save daily config:', error)
  } finally {
    saving.value = false
  }
}

const previewDaily = async (): Promise<void> => {
  if (previewing.value) return
  previewing.value = true
  try {
    const res = await request.post<{ code: number; data?: { content: string } }>('/notification/daily/preview', {
      items: form.value.items,
      format: previewFormat.value,
    })
    previewContent.value = res.data?.content ?? ''
  } catch (error: unknown) {
    console.error('Failed to preview daily:', error)
  } finally {
    previewing.value = false
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
  void fetchDaily()
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
.switch-hint { margin-left: 10px; font-size: 12px; color: var(--text-secondary, #6b7280); }
</style>
