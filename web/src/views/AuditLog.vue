<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Document /></el-icon>
          操作日志
        </h2>
        <p class="page-desc">记录系统中所有写操作和配置变更</p>
      </div>
    </div>

    <!-- 家族口径——列表失败必须显性化（「暂无操作日志」不得
         同时代表空库与故障），并给重试入口。 -->
    <el-alert v-if="loadError" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
      <template #title>
        <div class="polling-error-title">
          <span>操作日志加载失败：列表为空不代表没有日志</span>
          <el-button link type="danger" @click="fetchLogs">立即重试</el-button>
        </div>
      </template>
    </el-alert>

    <el-card>
      <div class="filter-bar">
        <el-date-picker
          v-model="filters.timeRange"
          name="audit-time-range"
          type="datetimerange"
          range-separator="至"
          start-placeholder="开始时间"
          end-placeholder="结束时间"
          format="YYYY-MM-DD HH:mm:ss"
          value-format="YYYY-MM-DD HH:mm:ss"
          :default-time="[new Date(2000, 0, 1, 0, 0, 0), new Date(2000, 0, 1, 23, 59, 59)]"
          class="audit-filter-date-range"
        />
        <el-select v-model="filters.username" :placeholder="optionsIncomplete ? '操作人（选项加载失败）' : '操作人'" clearable filterable style="width: 130px">
          <el-option v-for="o in usernameOptions" :key="o" :label="o" :value="o" />
        </el-select>
        <el-select v-model="filters.action" :placeholder="optionsIncomplete ? '操作（选项加载失败）' : '操作'" clearable filterable style="width: 120px">
          <el-option v-for="o in actionOptions" :key="o" :label="o" :value="o" />
        </el-select>
        <el-select v-model="filters.resource" :placeholder="optionsIncomplete ? '对象（选项加载失败）' : '对象'" clearable filterable allow-create style="width: 150px">
          <el-option v-for="o in resourceOptions" :key="o" :label="o" :value="o" />
        </el-select>
        <el-input v-model="filters.ip" placeholder="IP" clearable style="width: 120px" @keyup.enter="applyFilters" />
        <el-input v-model="filters.keyword" placeholder="详情关键词" clearable style="width: 160px" @keyup.enter="applyFilters" />
        <div class="filter-actions">
          <el-button type="primary" @click="applyFilters">筛选</el-button>
          <el-button @click="resetFilters">重置</el-button>
        </div>
        <!-- 消费后端 partial=true（部分下拉）与整体失败——下拉缺项必须可见，
             且不得与「真空库」混淆。 -->
        <el-text v-if="optionsIncomplete" type="warning" size="small">
          筛选选项未完整加载，下拉列表可能缺项
          <el-button link type="warning" size="small" @click="fetchOptions">重试</el-button>
        </el-text>
      </div>
      <el-table :data="logs" v-loading="loading" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="" :tooltip-options="{ popperClass: 'log-overflow-popper' }">
        <template #empty>
          <el-empty :description="loadError ? '日志加载失败' : '暂无操作日志'" :image-size="60" />
        </template>
        <el-table-column prop="created_at" label="时间" width="190" :formatter="(row: AuditLogEntry) => formatDate(row.created_at)" />
        <el-table-column label="操作人" width="200">
          <template #default="{ row }">
            <el-tooltip v-if="row.display_name && row.display_name !== row.username" :content="`${row.display_name}（${row.username}）`" placement="top">
              <span class="operator-cell">{{ row.display_name }}<span class="operator-email">（{{ row.username }}）</span></span>
            </el-tooltip>
            <span v-else class="operator-cell">{{ row.username || '-' }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="action" label="操作" width="90">
          <template #default="{ row }">
            <el-tag :type="actionTagType(row.action)" size="small">{{ row.action }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="resource" label="对象" width="160" />
        <el-table-column prop="detail" label="详情" show-overflow-tooltip />
        <el-table-column prop="ip_address" label="IP" width="160" show-overflow-tooltip />
      </el-table>

      <div style="margin-top: 16px; display: flex; align-items: center; flex-wrap: wrap; row-gap: 8px;">
        <LogStorageBar log-key="audit" style="margin-right: auto" />
        <!-- 后端 total 走 5 秒进程内缓存并以 total_stale 披露来源——陈旧计数
             必须可见，避免列表条数与总数短暂不一致时无任何提示。 -->
        <el-text v-if="totalStale" type="info" size="small" style="margin-right: 12px">
          统计总数来自缓存，可能滞后数秒
        </el-text>
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="pageSize"
          :total="total"
          :page-sizes="[20, 50, 100]"
          layout="total, sizes, prev, pager, next"
          @size-change="onPageSizeChange"
          @current-change="onCurrentPageChange"
        />
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted } from 'vue'
import { request } from '@/utils/api'
import { formatDate } from '@/utils/date'
import { Document } from '@element-plus/icons-vue'
import LogStorageBar from '@/components/LogStorageBar.vue'

import { buildAuditLogParams } from '@/utils/auditLogFilters'
import { actionTagType } from '@/utils/auditActionTone'

interface AuditLogEntry {
  id: number
  username?: string | null
  display_name?: string | null
  action: string
  resource: string
  detail: string
  ip_address: string
  created_at: string
}

const logs = ref<AuditLogEntry[]>([])
const loading = ref(false)
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)
// 后端 total 5 秒缓存命中时下发 total_stale=true——列表条数与总数短暂不一致
// 必须有可见提示（不静默）。
const totalStale = ref(false)
let requestSeq = 0
let lastLogsRequestKey = ''

const filters = ref({
  timeRange: null as [string, string] | null,
  username: '',
  action: '',
  resource: '',
  ip: '',
  keyword: '',
})

const usernameOptions = ref<string[]>([])
const actionOptions = ref<string[]>([])
const resourceOptions = ref<string[]>([])
// 列表请求失败与「确实没有日志」必须可区分。
const loadError = ref(false)
// 后端在任一 option 查询失败时下发 partial=true（auditlog.go）——原实现
// 只映射三列、把「部分下拉」渲染成「下拉为空」。optionsError 覆盖请求整体失败。
const optionsPartial = ref(false)
const optionsError = ref(false)
const optionsIncomplete = computed(() => optionsPartial.value || optionsError.value)

const fetchOptions = async () => {
  try {
    const res = await request.get<{ data?: { partial?: boolean; usernames?: { value: string }[]; actions?: { value: string }[]; resources?: { value: string }[] } }>('/audit-logs/options')
    const d = res.data
    usernameOptions.value = (d?.usernames || []).map((o) => o.value)
    actionOptions.value = (d?.actions || []).map((o) => o.value)
    resourceOptions.value = (d?.resources || []).map((o) => o.value)
    optionsPartial.value = d?.partial === true
    optionsError.value = false
  } catch (e) {
    console.error('Failed to fetch audit log options:', e)
    optionsError.value = true
  }
}

const buildParams = () => buildAuditLogParams(filters.value, page.value, pageSize.value)

const applyFilters = () => {
  page.value = 1
  fetchLogs()
}

// EP 的页大小变化在页码越界时会自行写入一次页码并发 current-change；
// 同参请求键去重，保证页大小切换只发一条 GET。
const logsRequestKey = (): string => `${page.value}\u0000${pageSize.value}`

const onPageSizeChange = (): void => {
  page.value = 1
  if (logsRequestKey() === lastLogsRequestKey) return
  fetchLogs()
}

const onCurrentPageChange = (): void => {
  if (logsRequestKey() === lastLogsRequestKey) return
  fetchLogs()
}

const resetFilters = () => {
  filters.value = { timeRange: null, username: '', action: '', resource: '', ip: '', keyword: '' }
  page.value = 1
  fetchLogs()
}

// 动作词色调 = 例外表 + 关键词派生 + 未命中告警（单源 utils/auditActionTone）。
// 原全表约 150 条字面量——后端词表新增动作静默落灰色 info，漂移无信号。
// fetchLogs 等其余逻辑不感知色调细节。
const fetchLogs = async () => {
  const targetPage = page.value
  const targetPageSize = pageSize.value
  lastLogsRequestKey = logsRequestKey()
  const currentRequestSeq = ++requestSeq
  loading.value = true
  try {
    const res = await request.get<{ data?: { list?: AuditLogEntry[]; total?: number; total_stale?: boolean } }>('/audit-logs', { params: buildParams() })
    if (currentRequestSeq !== requestSeq || page.value !== targetPage || pageSize.value !== targetPageSize) return
    // 总数收缩（保留期清理/他处删改）后夹紧当前页：否则停留在越界页会
    // 看到「暂无操作日志」而分页器页码超界，必须手动回退。
    const nextTotal = res.data?.total || 0
    const maxPage = Math.max(1, Math.ceil(nextTotal / targetPageSize))
    if (targetPage > maxPage) {
      // 夹紧后显式重取：el-pagination 只在其内部写入页码时发 current-change
      //（外部 v-model 赋值不触发），故不会产生同参数的第二条请求。
      page.value = maxPage
      void fetchLogs()
      return
    }
    logs.value = res.data?.list || []
    total.value = nextTotal
    totalStale.value = res.data?.total_stale === true
    loadError.value = false
  } catch (e) {
    console.error('Failed to fetch audit logs:', e)
    // 仅最新请求可置错误态（陈旧请求的失败不得覆盖新结果）。
    if (currentRequestSeq === requestSeq) loadError.value = true
  } finally {
    if (currentRequestSeq === requestSeq) loading.value = false
  }
}

onMounted(() => {
  fetchLogs()
  fetchOptions()
})
</script>

<style scoped>
.operator-cell {
  display: inline-block;
  max-width: 100%;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  vertical-align: bottom;
}
.operator-email { font-size: 11.5px; color: var(--el-text-color-secondary); }

.filter-bar { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; align-items: center; }
/* .polling-error-alert 已收敛 main.css（三处 scoped 逐字重复删除） */
.filter-actions { display: flex; gap: 0; margin-left: 8px; }
.filter-actions .el-button + .el-button { margin-left: 8px; }

/* 日期范围选择器宽度：类名落在子组件根元素上，scoped 的 data-v 会随
   inheritAttrs 一并落到根节点，故仍用 :global 以免依赖该细节。 */
:global(.audit-filter-date-range.el-date-editor) {
  --el-date-editor-width: 360px;
  width: 360px;
  flex: 0 0 auto;
}

/* tooltip 弹层被 teleport 到 body，scoped 选择器无法命中 */
:global(.log-overflow-popper) { max-width: 420px; word-break: break-all; }
:global(.log-overflow-popper .el-tooltip__popper) { max-width: 420px; }
</style>
