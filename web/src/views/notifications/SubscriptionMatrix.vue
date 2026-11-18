<template>
  <div>
    <!-- 每日日报已拆独立页签（通知日报）：订阅矩阵只承载事件订阅面 -->

    <el-card shadow="never">
      <template #header>
        <div class="card-header-row">
          <span>{{ t('app.notification.tabs.subs') }}</span>
          <el-button type="primary" :loading="subsSaving" :disabled="catalogLoading" @click="saveSubs">
            {{ t('app.notification.subs.save') }}
          </el-button>
        </div>
      </template>

      <el-alert v-if="catalogError" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
        <template #title>
          <div class="polling-error-title">
            <span>{{ t('app.notification.subs.catalogLoadFailed') }}</span>
            <el-button link type="danger" @click="fetchMatrix">{{ t('common.app.views.audit.retryNow') }}</el-button>
          </div>
        </template>
      </el-alert>

      <div class="info-note-bar subs-hint">
        <span class="info-note-desc">{{ t('app.notification.subs.levelHint') }}</span>
      </div>

      <el-table
        v-loading="catalogLoading"
        :data="groupedRows"
        row-key="key"
        :tree-props="{ children: 'children' }"
        default-expand-all
        :empty-text="t('app.notification.subs.emptyText')"
      >
        <el-table-column :label="t('app.notification.deliveries.colEvent')" min-width="260">
          <template #default="scope">
            <span :class="{ 'group-row-title': isGroupRow(scope.row) }">
              <el-icon v-if="isGroupRow(scope.row)" class="group-row-icon"><Folder /></el-icon>
              {{ scope.row.title }}
            </span>
          </template>
        </el-table-column>
        <el-table-column :label="t('app.notification.deliveries.colLevel')" width="110" align="center">
          <template #default="scope">
            <el-tag v-if="!isGroupRow(scope.row)" :type="levelTagType(scope.row.level)" size="small">
              {{ t(`app.notification.subs.levels.${scope.row.level}`) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="t('app.notification.subs.levelMin')" width="150" align="center">
          <template #default="scope">
            <el-select
              v-if="!isGroupRow(scope.row) && matrix[scope.row.id]?.subscribed"
              :model-value="matrix[scope.row.id]?.min_level"
              size="small"
              :disabled="subsSaving"
              @update:model-value="(val: string | number | boolean) => setMinLevel(scope.row.id, val as NotificationLevel)"
            >
              <el-option
                v-for="lv in LEVELS"
                :key="lv"
                :value="lv"
                :label="t(`app.notification.subs.levels.${lv}`)"
              />
            </el-select>
          </template>
        </el-table-column>
        <el-table-column :label="t('app.notification.subs.subscribe')" width="110" align="center">
          <template #default="scope">
            <el-switch
              v-if="!isGroupRow(scope.row)"
              :model-value="matrix[scope.row.id]?.subscribed === true"
              :disabled="subsSaving"
              @update:model-value="(val: string | number | boolean) => toggleEvent(scope.row.id, val === true)"
            />
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { Folder } from '@element-plus/icons-vue'
import { request, mfaAwareSuccess } from '@/utils/api'
import type {
  CatalogEvent,
  NotificationCatalogResponse,
  NotificationLevel,
  NotificationSubsPayload,
  NotificationSubsResponse,
} from '@/types/notifications.ts'

const { t } = useI18n()

const LEVELS: readonly NotificationLevel[] = ['info', 'warn', 'critical']

interface MatrixState {
  subscribed: boolean
  min_level: NotificationLevel | ''
}

interface GroupRow {
  key: string
  title: string
  children: CatalogEvent[]
}

const events = ref<CatalogEvent[]>([])
const catalogLoading = ref(false)
const catalogError = ref(false)
const subsSaving = ref(false)
/** event_type → 订阅态（含未订阅事件的显式 off；保存时全量提交）。 */
const matrix = ref<Record<string, MatrixState>>({})
let matrixRequestSeq = 0

const groupedRows = computed<GroupRow[]>(() => {
  // group 为服务端下发的分组显示串（认证/安全/…），直接作行标题渲染
  const byGroup = new Map<string, CatalogEvent[]>()
  for (const evt of events.value) {
    const list = byGroup.get(evt.group) ?? []
    list.push(evt)
    byGroup.set(evt.group, list)
  }
  return [...byGroup.entries()].map(([group, children]) => ({
    key: `group:${group}`,
    title: group,
    children,
  }))
})

const isGroupRow = (row: unknown): boolean =>
  typeof row === 'object' && row !== null && Array.isArray((row as GroupRow).children)

const levelTagType = (level: NotificationLevel): 'info' | 'warning' | 'danger' => {
  switch (level) {
    case 'info': return 'info'
    case 'warn': return 'warning'
    case 'critical': return 'danger'
  }
}

const toggleEvent = (eventType: string, on: boolean): void => {
  const current = matrix.value[eventType]
  const evt = events.value.find((e) => e.id === eventType)
  const fallbackLevel: NotificationLevel = evt?.level ?? 'info'
  matrix.value = {
    ...matrix.value,
    [eventType]: {
      subscribed: on,
      min_level: on ? (current?.min_level || fallbackLevel) : '',
    },
  }
}

const setMinLevel = (eventType: string, level: NotificationLevel): void => {
  matrix.value = {
    ...matrix.value,
    [eventType]: { subscribed: true, min_level: level },
  }
}

const fetchMatrix = async (): Promise<void> => {
  const seq = ++matrixRequestSeq
  catalogLoading.value = true
  try {
    const [catalogRes, subsRes] = await Promise.all([
      request.get<NotificationCatalogResponse>('/notification/catalog'),
      request.get<NotificationSubsResponse>('/notification/subscriptions'),
    ])
    if (seq !== matrixRequestSeq) return
    events.value = catalogRes.data?.events ?? []
    const subRows = new Map((subsRes.data?.subscriptions ?? []).map((row) => [row.event_type, row]))
    const state: Record<string, MatrixState> = {}
    for (const evt of events.value) {
      const row = subRows.get(evt.id)
      if (row) {
        state[evt.id] = { subscribed: row.subscribed, min_level: row.min_level }
      } else {
        // 无显式订阅行：目录默认态（default_subscribed=true 时级别下限取事件级别）
        state[evt.id] = { subscribed: evt.default_subscribed, min_level: evt.default_subscribed ? evt.level : '' }
      }
    }
    matrix.value = state
    catalogError.value = false
  } catch (error: unknown) {
    console.error('Failed to fetch subscription matrix:', error)
    if (seq === matrixRequestSeq) catalogError.value = true
  } finally {
    if (seq === matrixRequestSeq) catalogLoading.value = false
  }
}

const saveSubs = async (): Promise<void> => {
  if (subsSaving.value) return
  subsSaving.value = true
  try {
    // 契约：PUT {items:[{event_type,min_level}]}，min_level 空=删行回默认。
    // 全量提交目录内全部事件（订阅→级别，未订阅→空串显式删行），不依赖
    // 「缺席项」的隐式语义。
    const payload: NotificationSubsPayload = {
      items: events.value.map((evt) => {
        const state = matrix.value[evt.id]
        return { event_type: evt.id, min_level: state?.subscribed ? (state.min_level || evt.level) : '' }
      }),
    }
    await request.put('/notification/subscriptions', payload)
    mfaAwareSuccess(t('app.notification.subs.saved'))
    await fetchMatrix()
  } catch (error: unknown) {
    console.error('Failed to save subscriptions:', error)
  } finally {
    subsSaving.value = false
  }
}

onMounted(() => {
  void fetchMatrix()
})

defineExpose({ fetchMatrix })
</script>

<style scoped>
.card-header-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.subs-hint { margin-bottom: 8px; }
.group-row-title { font-weight: 600; display: inline-flex; align-items: center; gap: 6px; }
.group-row-icon { flex: none; }
</style>
