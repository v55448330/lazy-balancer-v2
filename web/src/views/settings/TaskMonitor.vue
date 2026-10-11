<template>
  <div class="tm-root">
    <!-- KPI 概览（四卡） -->
    <el-row :gutter="20" class="tm-kpis">
      <el-col :xs="12" :md="6">
        <el-card class="tm-kpi">
          <div class="tm-kpi-num">{{ tasks.length }}</div>
          <div class="tm-kpi-label">任务族</div>
        </el-card>
      </el-col>
      <el-col :xs="12" :md="6">
        <el-card class="tm-kpi">
          <div class="tm-kpi-num tm-kpi-run">{{ runningCount }}</div>
          <div class="tm-kpi-label">运行中</div>
        </el-card>
      </el-col>
      <el-col :xs="12" :md="6">
        <el-card class="tm-kpi">
          <div class="tm-kpi-num">{{ total24h }}</div>
          <div class="tm-kpi-label">24h 执行</div>
        </el-card>
      </el-col>
      <el-col :xs="12" :md="6">
        <el-card class="tm-kpi">
          <div class="tm-kpi-num" :class="{ 'tm-kpi-bad': fail24h > 0 }">{{ fail24h }}</div>
          <div class="tm-kpi-label">24h 失败 <el-icon v-if="readOnly" class="tm-kpi-lock"><Lock /></el-icon></div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 图表行：状态分布 + 24h 执行 -->
    <el-row :gutter="20">
      <el-col :xs="24" :md="8">
        <el-card>
          <template #header>
            <div class="card-header">
              <div class="card-title"><el-icon class="title-icon"><PieChartIcon /></el-icon><span>任务状态分布</span></div>
            </div>
          </template>
          <v-chart v-if="loaded" :option="statusPieOption" autoresize class="tm-chart" />
          <div v-else class="tm-chart tm-skeleton"></div>
        </el-card>
      </el-col>
      <el-col :xs="24" :md="16">
        <el-card>
          <template #header>
            <div class="card-header">
              <div class="card-title"><el-icon class="title-icon"><DataLine /></el-icon><span>近 24 小时执行（成功 / 失败）</span></div>
              <el-button :icon="Refresh" circle size="small" :loading="refreshing" @click="refreshNow" title="立即刷新" />
            </div>
          </template>
          <v-chart v-if="loaded" :option="statsBarOption" autoresize class="tm-chart" />
          <div v-else class="tm-chart tm-skeleton"></div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 证书队列横幅（实时——非任务） -->
    <el-card class="tm-cq-banner">
      <div class="tm-cq-banner-inner">
        <div class="tm-cq-banner-title"><el-icon class="title-icon"><Lock /></el-icon><span>ACME 证书任务队列</span></div>
        <div class="tm-cq-banner-stats">
          <span class="tm-cq-chip">排队 <b>{{ certQueue.queued }}</b></span>
          <span class="tm-cq-chip">进行中 <b class="tm-c-run">{{ certQueue.running }}</b></span>
          <span class="tm-cq-chip">等 CA <b class="tm-c-wait">{{ certQueue.waiting }}</b></span>
        </div>
        <div class="tm-cq-banner-live">
          <template v-if="certQueue.jobs.length">
            <span v-for="j in certQueue.jobs.slice(0, 4)" :key="j.id" class="tm-cq-domain-chip">
              {{ j.domain }}<i :class="'tm-cq-dot tm-cq-dot--' + j.status" />
            </span>
            <span v-if="certQueue.total > 4" class="tm-cq-more">+{{ certQueue.total - 4 }}</span>
          </template>
          <span v-else class="tm-cq-idle">空闲——临期证书由「证书续期扫描」自动入队</span>
        </div>
        <el-tag :type="certQueue.running > 0 ? 'primary' : 'success'" size="small" effect="plain">
          {{ certQueue.running > 0 ? '签发进行中' : '空闲' }}
        </el-tag>
      </div>
    </el-card>

    <!-- 任务列表 -->
    <el-card>
      <template #header>
        <div class="card-header">
          <div class="card-title"><el-icon class="title-icon"><List /></el-icon><span>全部任务</span>
            <span class="tm-count">{{ tasks.length }}</span>
          </div>
          <el-radio-group v-model="kindFilter" size="small">
            <el-radio-button value="all">全部</el-radio-button>
            <el-radio-button value="scheduled">定时</el-radio-button>
            <el-radio-button value="daemon">常驻</el-radio-button>
            <el-radio-button value="periodic">循环</el-radio-button>
            <el-radio-button value="oneshot">触发</el-radio-button>
                      </el-radio-group>
        </div>
      </template>
      <el-table :data="pagedTasks" v-loading="!loaded" size="default" row-key="id" class="tm-nowrap-table">
        <el-table-column label="任务" min-width="128" show-overflow-tooltip>
          <template #default="{ row }">
            <el-tooltip :disabled="!row.description" placement="top" :offset="8" :show-after="150" :show-arrow="false" popper-class="tm-name-tip">
              <template #content>
                <div class="tm-tip-title">{{ row.name }}</div>
                <div v-if="row.cadence" class="tm-tip-cadence">节奏：{{ row.cadence }}</div>
                <div class="tm-tip-desc">{{ row.description }}</div>
              </template>
              <div class="tm-task-name">{{ row.name }}</div>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="分类" width="92" :filters="categoryFilters" :filter-method="filterCategory">
          <template #default="{ row }">
            <el-tag size="small" effect="plain" :type="categoryTagType(row.category)">{{ row.category }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="类型" width="72">
          <template #default="{ row }">
            <el-tag size="small" :type="kindTag(row.kind)" effect="plain" :class="kindTagClass(row.kind)">{{ kindLabel(row.kind) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="88">
          <template #default="{ row }">
            <span class="tm-status" :data-status="row.status"><span class="tm-dot"></span>{{ statusLabel(row.status) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="调度" width="92">
          <template #default="{ row }">
            <!-- v2.0 调度开关统一：定时=暂停/恢复排程、循环=暂停/恢复循环、
                 常驻=启停自管理循环——绑定 loop_on 走 /toggle（后端按 Kind 路由） -->
            <el-switch v-if="row.kind !== 'oneshot'" :model-value="row.loop_on" :disabled="!canOperate" @change="(v: string | number | boolean) => onToggle(row, !!v)" />
            <!-- 触发类（含 cert-job 动态行）：统一显示禁用开关保持页面一致性——
                 仅手动/代码触发执行（2026-10-01 用户裁定；cert-job 特例已消除） -->
            <el-tooltip v-else content="触发类任务不可调度——仅手动/代码触发执行" placement="top" :offset="8" :show-after="150" :show-arrow="false">
              <el-switch :model-value="false" disabled />
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="执行时间" width="180">
          <template #default="{ row }">
            <el-tooltip :disabled="!row.last_run" placement="top" :offset="8" :show-after="150" :show-arrow="false">
              <template #content>
                <div class="tm-tip-title">最近执行</div>
                <div>{{ fmtTime(row.last_run?.started_at) || '—' }}<template v-if="row.last_run?.duration_ms > 0">（耗时 {{ fmtDuration(row.last_run.duration_ms) }}）</template></div>
                <div class="tm-tip-sep"></div>
                <div class="tm-tip-title">完成时间</div>
                <div>{{ row.status === 'running' ? '进行中' : fmtTime(row.last_run?.finished_at) || '—' }}</div>
              </template>
              <!-- 执行时间列=最近执行时刻（全类型统一，含常驻——其执行记录=boot 行）；
                   不再显示「常驻 · 启动于」文案（2026-10-03 用户裁定） -->
              <span v-if="row.last_run?.started_at">{{ fmtTime(row.last_run.started_at) }}</span>
              <span v-else class="tm-dim">—</span>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="下次执行" width="180">
          <template #default="{ row }">
            <span v-if="row.next_run_at && row.loop_on && row.kind !== 'daemon'">{{ row.next_run_at }}</span>
            <span v-else class="tm-dim">—</span>
          </template>
        </el-table-column>
        <el-table-column width="104">
          <template #header>
            <el-tooltip content="近 24 小时成功 / 失败次数（完整统计见详情）" placement="top" :show-arrow="false">
              <span>成功/失败 ⓘ</span>
            </el-tooltip>
          </template>
          <template #default="{ row }">
            <span class="tm-ok">{{ row.success_24h }}</span> / <span :class="{ 'tm-bad': row.fail_24h > 0 }">{{ row.fail_24h }}</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="225" fixed="right">
          <template #default="{ row }">
            <el-button
              v-if="row.triggerable"
              link type="primary" size="small" :disabled="!canOperate || row.status === 'running'"
              @click="onTrigger(row)"
            >立即执行</el-button>
            <el-button
              v-if="row.cancellable && row.status === 'running'"
              link type="danger" size="small" :disabled="!canOperate"
              @click="onCancel(row)"
            >取消</el-button>
            <!-- 常驻行启停已由调度列开关承担（loop_on 同源，U5-P4-6e）——操作列改「重启」 -->
            <el-button
              v-if="row.controllable"
              link type="warning" size="small"
              :disabled="!canOperate"
              @click="onRestart(row)"
            >重启</el-button>
            <el-button link type="info" size="small" @click="openLogs(row)">日志</el-button>
            <el-button link type="info" size="small" @click="openDetail(row)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div class="tm-pagination">
        <el-pagination
          v-model:current-page="page"
          :page-size="pageSize"
          :page-sizes="[10, 20, 50]"
          :total="filteredTasks.length"
          layout="total, sizes, prev, pager, next"
          @size-change="(s: number) => pageSize = s"
        />
      </div>
    </el-card>

    <!-- 任务详情 -->
    <el-dialog v-model="detailVisible" width="640px" top="8vh">
      <template #header>
        <DialogHeader
          :icon="detailIcon" :title="detailTask?.name || ''"
          :subtitle="detailTask ? `${detailTask.category} · ${kindLabel(detailTask.kind)} · ${statusLabel(detailTask.status)}` : ''"
          :tone="detailTone"
        />
      </template>
      <div v-if="detailTask" class="tm-detail">
        <div v-if="detailTask.description" class="tm-detail-desc">{{ detailTask.description }}</div>
        <el-descriptions :column="2" border size="small" class="tm-detail-descs">
          <el-descriptions-item label="运行节奏">{{ detailTask.cadence || '—' }}</el-descriptions-item>
          <el-descriptions-item label="调度开关">
            <!-- v2.0 统一口径：非触发类显示 loop_on 态（定时/循环=排程暂停、常驻=运行/停止） -->
            <el-tag v-if="detailTask.kind !== 'oneshot'" size="small" :type="detailTask.loop_on ? 'success' : 'warning'" effect="plain">{{ detailTask.loop_on ? '开启' : '已暂停' }}</el-tag>
            <el-tooltip v-else content="触发类任务不可调度——仅手动/代码触发执行" placement="top" :offset="8" :show-after="150" :show-arrow="false">
              <el-tag size="small" type="info" effect="plain">不可调度</el-tag>
            </el-tooltip>
          </el-descriptions-item>
          <el-descriptions-item label="下次执行">{{ detailTask.next_run_at || '—' }}</el-descriptions-item>
          <el-descriptions-item label="24h 成功 / 失败">
            <span class="tm-ok">{{ detailTask.success_24h }}</span> / <span :class="{ 'tm-bad': detailTask.fail_24h > 0 }">{{ detailTask.fail_24h }}</span>
          </el-descriptions-item>
          <el-descriptions-item v-if="detailTask.kind === 'daemon'" label="启动时间">{{ fmtTime(detailTask.started_at) || '—' }}</el-descriptions-item>
          <el-descriptions-item v-if="detailTask.last_run" label="开始时间">{{ fmtTime(detailTask.last_run.started_at) || '—' }}</el-descriptions-item>
          <el-descriptions-item v-if="detailTask.last_run" label="完成时间">{{ detailTask.status === 'running' ? '进行中' : fmtTime(detailTask.last_run.finished_at) || '—' }}</el-descriptions-item>
          <el-descriptions-item v-if="detailTask.last_run" label="耗时">{{ fmtDuration(detailTask.last_run.duration_ms) }}</el-descriptions-item>
          <el-descriptions-item v-if="detailTask.last_run" label="触发 / 结果">{{ triggerLabel(detailTask.last_run.trigger) }} · {{ detailTask.last_run.operator || '系统' }} · <el-tag size="small" :type="resultTagType(detailTask.last_run.result)">{{ statusResultLabel(detailTask.last_run.result) }}</el-tag></el-descriptions-item>
        </el-descriptions>
        <div v-if="detailTask.last_run?.message" class="tm-detail-msg">{{ detailTask.last_run.message }}</div>
        <template v-if="history.length">
          <div class="tm-detail-section">{{ historyTitle }}</div>
          <el-table :data="history" size="small" max-height="240" class="tm-nowrap-table">
            <el-table-column prop="started_at" label="开始" width="160">
              <template #default="{ row }">{{ fmtTime(row.started_at) }}</template>
            </el-table-column>
            <el-table-column prop="duration_ms" label="耗时" width="78">
              <template #default="{ row }">{{ fmtDuration(row.duration_ms) }}</template>
            </el-table-column>
            <el-table-column prop="trigger" label="触发" width="72">
              <template #default="{ row }">{{ triggerLabel(row.trigger) }}</template>
            </el-table-column>
            <el-table-column label="操作者" width="90">
              <!-- operator 为空=自动/排程/启动等系统触发（后端 auto/startup/legacy 恒空） -->
              <template #default="{ row }">{{ row.operator || '系统' }}</template>
            </el-table-column>
            <el-table-column prop="status" label="结果" width="88">
              <template #default="{ row }">
                <el-tag size="small" :type="resultTagType(row.status)">{{ statusResultLabel(row.status) }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="message" label="信息" min-width="140" show-overflow-tooltip />
          </el-table>
        </template>
      </div>
    </el-dialog>

    <!-- 任务日志弹框（与证书日志同款：暗色终端流） -->
    <el-dialog v-model="logsVisible" width="min(1100px, 94vw)" top="5vh" destroy-on-close @closed="closeLogs">
      <template #header>
        <DialogHeader :icon="Timer" :title="`任务日志 · ${logsTask?.name || ''}`" subtitle="统一任务引擎文本日志（实时刷新）" />
      </template>
      <!-- 日志存储统计栏（cert-job 行同 CertJobs 页 key=certjob，其余任务族 key=tasks；后端未含该键时组件自隐） -->
      <div class="tm-log-stats">
        <LogStorageBar :log-key="logsTask && isCertJobRow(logsTask.id) ? 'certjob' : 'tasks'" style="margin-right: auto" />
      </div>
      <div v-if="logsTask?.log_size_bytes != null" style="font-size:12px;color:#6b7280;margin-bottom:6px">
            本文件 {{ (logsTask.log_size_bytes / 1024).toFixed(1) }} KB
          </div>
          <div ref="logContainerRef" class="tm-log-container">
        <pre v-if="logsText" class="tm-log-content">{{ logsText }}</pre>
        <el-empty v-else description="暂无日志" :image-size="60" />
      </div>
      <template #footer>
        <div style="display: flex; align-items: center;">
          <span style="font-size: 12px; color: #9aa0b5; margin-right: auto;">每 5 秒自动刷新</span>
          <el-button @click="logsVisible = false">关闭</el-button>
        </div>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, nextTick } from 'vue'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { PieChart, BarChart } from 'echarts/charts'
import { GridComponent, TooltipComponent, LegendComponent } from 'echarts/components'
import type { EChartsOption } from 'echarts'
import VChart from 'vue-echarts'
import { ElMessage, ElMessageBox } from 'element-plus'
import { formatDate } from '@/utils/date'
import { Refresh, PieChart as PieChartIcon, DataLine, List, Monitor, Lock, Box, Timer } from '@element-plus/icons-vue'
import { request } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import { usePollingTask } from '@/composables/usePollingTask'
import { statusColor } from '@/utils/chartTheme'
import { certJobStatusLabel, type CertJobStatus } from '@/utils/certJobStatus'
import DialogHeader from '@/components/DialogHeader.vue'
import LogStorageBar from '@/components/LogStorageBar.vue'
import type { APIResponse } from '@/types'

use([CanvasRenderer, PieChart, BarChart, GridComponent, TooltipComponent, LegendComponent])

interface TaskRunInfo { started_at: string; finished_at: string; duration_ms: number; trigger: string; operator?: string; result: string; message?: string }
interface TaskInfo {
  id: string; name: string; description?: string; cadence?: string; category: string
  kind: 'scheduled' | 'daemon' | 'periodic' | 'oneshot'
  status: string; cancellable: boolean; controllable?: boolean; triggerable?: boolean
  last_run?: TaskRunInfo; next_run_at?: string; runs_24h: number; success_24h: number; fail_24h: number
  loop_on?: boolean; started_at?: string; log_size_bytes?: number // 常驻族：循环启停态（调度列开关绑定值）/ 引擎启动时刻
}
interface RunRecord {
  id: number; task_id: string; family: string; trigger: string; operator?: string; status: string
  started_at: string; finished_at: string; duration_ms: number
  // TASK-L7（第 69 轮）：stage/entry_count 恒零死列已随后端删除——不再声明。
  message?: string
}

const authStore = useAuthStore()
const isAdmin = computed(() => authStore.user?.role === 'admin')
const tasks = ref<TaskInfo[]>([])
const loaded = ref(false)
const refreshing = ref(false)
// L1-2（第 65 轮）：只读判定统一走全局 fail-closed 契约（authStore.
// readOnlyReason===null=可写；曾本地 isSlave fetch-open 且不随角色切换刷新，
// 违反 F49-10——全站 14 页唯一偏离者）
const readOnly = computed(() => authStore.readOnlyReason !== null)
const canOperate = computed(() => isAdmin.value && !readOnly.value)

const fetchTasks = async () => {
  const res = await request.get<APIResponse<{ tasks: TaskInfo[] }>>('/system/tasks', { silent: true })
  tasks.value = res.data?.tasks || []
  loaded.value = true
}
const refreshNow = async () => {
  refreshing.value = true
  try { await Promise.all([fetchTasks(), fetchCertQueue()]) } finally { refreshing.value = false }
}
onMounted(() => {
  void polling.run() // 首跑立即（start() 只设定时器；证书队列横幅已入轮询闭包随首跑）
  polling.start()
})
onUnmounted(() => polling.stop())

const polling = usePollingTask(async () => {
  // U5-P3-4：证书队列横幅与任务列表同频 10s（曾只在 mounted/手动刷新拉取，横幅最长陈旧一个会话）
  await Promise.all([fetchTasks(), fetchCertQueue()])
}, {
  interval: 10000,
  onError: (e) => console.error('task monitor poll failed:', e),
})
// ===== 证书队列状态（独立卡——非任务族） =====
interface CertJobRow { id: number; domain: string; status: string; updated_at?: string | null; ca_provider_name?: string }
// FE-D3（第 69 轮）：certQueue.loaded 死字段删除（写字段零消费方）。
const certQueue = ref<{ queued: number; running: number; waiting: number; total: number; jobs: CertJobRow[] }>({
  queued: 0, running: 0, waiting: 0, total: 0, jobs: [],
})
const fetchCertQueue = async () => {
  try {
    const res = await request.get<APIResponse<{ list: CertJobRow[]; total: number }>>('/certificates/jobs', { params: { page: 1, page_size: 50 }, silent: true })
    // 实时队列 = 非终态（签发执行状态/结果在任务列表 cert-job 行）
    const live = (res.data?.list || []).filter(j => !['issued', 'failed', 'disabled'].includes(j.status))
    const count = (pred: (j: CertJobRow) => boolean) => live.filter(pred).length
    certQueue.value = {
      total: live.length,
      queued: count(j => ['queued', 'pending'].includes(j.status)),
      running: live.length - count(j => ['queued', 'pending'].includes(j.status)),
      waiting: count(j => j.status === 'waiting_ca'),
      jobs: live.slice(0, 6),
    }
  } catch { /* 静默：独立卡数据下一轮轮询自愈 */ }
}

// ===== 概览统计 =====
const runningCount = computed(() => tasks.value.filter(t => t.status === 'running').length)
const total24h = computed(() => tasks.value.reduce((s, t) => s + (t.runs_24h || 0), 0))
const fail24h = computed(() => tasks.value.reduce((s, t) => s + (t.fail_24h || 0), 0))

// ===== 筛选 + 分页 =====
const kindFilter = ref('all')
const filteredTasks = computed(() => {
  const list = kindFilter.value === 'all' ? tasks.value : tasks.value.filter(t => t.kind === kindFilter.value)
  // 默认按分类排序（安全防护→证书→备份→集群→系统→触发），类内稳定
  return [...list].sort((a, b) => (categoryOrder[a.category] ?? 9) - (categoryOrder[b.category] ?? 9))
})
const page = ref(1)
const pageSize = ref(20)
const pagedTasks = computed(() => filteredTasks.value.slice((page.value - 1) * pageSize.value, page.value * pageSize.value))
const categoryFilters = computed(() => [...new Set(tasks.value.map(t => t.category))].map(c => ({ text: c, value: c })))
const filterCategory = (value: string, row: TaskInfo) => row.category === value

// ===== 图表（引擎真数据） =====
const statusPieOption = computed<EChartsOption>((): EChartsOption => {
  const counts = new Map<string, number>()
  for (const t of tasks.value) counts.set(t.status, (counts.get(t.status) || 0) + 1)
  return {
    tooltip: { trigger: 'item' },
    legend: { bottom: 0, type: 'scroll' },
    series: [{
      type: 'pie',
      radius: ['50%', '72%'],
      center: ['50%', '44%'],
      itemStyle: { borderRadius: 4, borderColor: '#fff', borderWidth: 2 },
      label: { show: false },
      data: [...counts.entries()].map(([k, v]) => ({
        name: statusLabel(k), value: v, itemStyle: { color: statusColor[k] || '#4f8cff' },
      })),
    }],
  }
})
const statsBarOption = computed<EChartsOption>((): EChartsOption => {
  const rows = tasks.value.filter(t => (t.success_24h || t.fail_24h) > 0).slice(0, 10)
  return {
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    legend: { top: 0, itemGap: 24 },
    grid: { left: 8, right: 12, top: 36, bottom: 8, containLabel: true },
    xAxis: { type: 'category', data: rows.map(t => t.name.replace(/（.*）/, '')), axisLabel: { interval: 0, width: 72, overflow: 'truncate' } },
    yAxis: { type: 'value', minInterval: 1 },
    series: [
      { name: '成功', type: 'bar', data: rows.map(t => t.success_24h), itemStyle: { color: '#34d399', borderRadius: [4, 4, 0, 0] }, barMaxWidth: 14 },
      { name: '失败', type: 'bar', data: rows.map(t => t.fail_24h), itemStyle: { color: '#f87171', borderRadius: [4, 4, 0, 0] }, barMaxWidth: 14 },
    ],
  }
})

// ===== 操作 =====
const onTrigger = async (row: TaskInfo) => {
  try {
    await ElMessageBox.confirm(`立即执行「${row.name}」？`, '手动触发', { type: 'info', confirmButtonText: '执行' })
  } catch { return }
  const res = await request.post<APIResponse>(`/system/tasks/${row.id}/trigger`)
  ElMessage.success(res.message || '已触发')
  fetchTasks()
}
const onToggle = async (row: TaskInfo, enabled: boolean) => {
  // 常驻族停止前确认（功能中断影响大——如安全事件采集停摆）
  if (!enabled && row.kind === 'daemon') {
    try {
      await ElMessageBox.confirm(`确认停止「${row.name}」？停止后相关功能将中断，可随时重新启动。`, '常驻任务控制', { type: 'warning', confirmButtonText: '停止' })
    } catch { return }
  }
  const res = await request.post<APIResponse>(`/system/tasks/${row.id}/toggle`, { enabled })
  ElMessage.success(res.message || '已更新')
  fetchTasks()
}
const onCancel = async (row: TaskInfo) => {
  try {
    await ElMessageBox.confirm(`取消运行中的「${row.name}」？下载阶段将中断，已完成部分保留。`, '手动取消', { type: 'warning', confirmButtonText: '取消任务' })
  } catch { return }
  const res = await request.post<APIResponse>(`/system/tasks/${row.id}/cancel`)
  ElMessage.success(res.message || '已发出取消信号')
  fetchTasks()
}
// U5-P4-6e：常驻行操作列「重启」（control restart——启停已由调度列开关承担）
const onRestart = async (row: TaskInfo) => {
  try {
    await ElMessageBox.confirm(`确认重启「${row.name}」？重启期间相关功能将短暂中断。`, '常驻任务控制', { type: 'warning', confirmButtonText: '重启' })
  } catch { return }
  const res = await request.post<APIResponse>(`/system/tasks/${row.id}/control`, { action: 'restart' })
  ElMessage.success(res.message || '已重启')
  fetchTasks()
}

// ===== 详情 =====
const detailVisible = ref(false)
const detailTask = ref<TaskInfo | null>(null)
const history = ref<RunRecord[]>([])
const detailIcon = computed(() => (detailTask.value?.category === '证书' ? Lock : detailTask.value?.category === '备份' ? Box : Monitor))
const detailTone = computed((): 'primary' | 'success' | 'warning' | 'danger' | undefined => {
  const st = detailTask.value?.status
  if (st === 'failed') return 'danger'
  if (st === 'running') return 'primary'
  if (st === 'stopped' || st === 'disabled') return 'warning'
  return undefined
})
const isCertJobRow = (id: string): boolean => id.startsWith('cert-job:')
// cert-job 动态行无引擎运行历史——历史区域接 cert_jobs 数据源（每规则+域名
// 单行在册，展示该签发任务当前记录）
const historyTitle = computed(() =>
  detailTask.value && isCertJobRow(detailTask.value.id) ? '签发任务记录（cert_jobs）' : `运行历史（最近 ${history.value.length} 次）`)
// cert-job 详情数据源（GET /certificates/jobs/:id——与 CertJobs 页同源字段）
interface CertJobDetail { id: number; rule_id: string; domain: string; status: string; message: string; created_at?: string; updated_at?: string | null }
const fetchCertJobHistory = async (jobId: number): Promise<RunRecord[]> => {
  const res = await request.get<APIResponse<CertJobDetail>>(`/certificates/jobs/${jobId}`, { silent: true })
  const j = res.data
  if (!j) return []
  const start = j.created_at ? Date.parse(j.created_at) : NaN
  const end = j.updated_at ? Date.parse(j.updated_at) : NaN
  return [{
    id: j.id, task_id: `cert-job:${j.id}`, family: 'cert-job', trigger: 'queue', status: j.status,
    started_at: j.created_at || '', finished_at: j.updated_at || '',
    duration_ms: !isNaN(start) && !isNaN(end) && end > start ? end - start : 0,
    message: j.message || undefined,
  }]
}
const openDetail = async (row: TaskInfo) => {
  detailTask.value = row
  detailVisible.value = true
  history.value = []
  try {
    if (isCertJobRow(row.id)) {
      history.value = await fetchCertJobHistory(Number(row.id.slice(9)))
      return
    }
    const res = await request.get<APIResponse<{ runs: RunRecord[] }>>(`/system/tasks/${row.id}/history`, { silent: true })
    history.value = res.data?.runs || []
  } catch { /* 无历史族静默 */ }
}

// ===== 日志抽屉（content 纯文本解析） =====
const logsVisible = ref(false)
const logsText = ref('')
const logsTask = ref<TaskInfo | null>(null)
const logContainerRef = ref<HTMLElement | null>(null)
let logsTimer: ReturnType<typeof setInterval> | null = null
const taskLogEndpoint = (id: string): string =>
  id.startsWith('cert-job:') ? `/certificates/jobs/${id.slice(9)}/logs` : `/system/tasks/${id}/logs`
const openLogs = async (row: TaskInfo) => {
  logsTask.value = row
  logsVisible.value = true
  await refreshLogs()
  logsTimer = setInterval(refreshLogs, 5000)
}
const refreshLogs = async () => {
  if (!logsTask.value) return
  try {
    const res = await request.get<APIResponse<{ content: string }>>(taskLogEndpoint(logsTask.value.id), { silent: true })
    logsText.value = (res.data?.content || '').trim()
    await nextTick(() => {
      if (logContainerRef.value) logContainerRef.value.scrollTop = logContainerRef.value.scrollHeight
    })
  } catch { /* 静默 */ }
}
const closeLogs = () => {
  if (logsTimer) { clearInterval(logsTimer); logsTimer = null }
}
onUnmounted(closeLogs)



// ===== 文案 =====
// 状态五态统一（R63 设计重构）：引擎族只呈现 running/idle/failed/stopped/disabled；
// cert-job 行的 queued 等队列态经 certJobStatusLabel 回退链显示
const statusLabels: Record<string, string> = {
  running: '运行中', idle: '空闲', failed: '失败', stopped: '已停止', disabled: '已暂停',
}
const statusLabel = (s: string) => statusLabels[s] || certJobStatusLabel(s as CertJobStatus)
// v2.0 四类型：定时(蓝)/常驻(绿)/循环(青)/触发(橙)
const kindLabels: Record<string, string> = { scheduled: '定时', daemon: '常驻', periodic: '循环', oneshot: '触发' }
const kindLabel = (k: string) => kindLabels[k] || k
const kindTag = (k: string): 'primary' | 'success' | 'info' | 'warning' =>
  k === 'scheduled' ? 'primary' : k === 'daemon' ? 'success' : k === 'periodic' ? 'info' : 'warning'
const kindTagClass = (k: string) => (k === 'periodic' ? 'tm-tag-periodic' : '')
const categoryOrder: Record<string, number> = { '安全防护': 0, '证书': 1, '备份': 2, '集群': 3, '系统': 4, '触发': 5 }
const categoryTagType = (c: string): 'primary' | 'success' | 'warning' | 'info' =>
  c === '安全防护' ? 'primary' : c === '证书' ? 'success' : c === '备份' ? 'warning' : c === '触发' ? 'info' : 'info'
const triggerLabels: Record<string, string> = { manual: '手动', auto: '自动', schedule: '排程', queue: '队列', 'slave-sync': '从节点同步', startup: '启动' }
const triggerLabel = (t: string) => triggerLabels[t] || t || '—'
// 结果串双源：引擎 task_runs 结果（success/failed/…/skipped）+ cert-job 动态行
// 的 cert_jobs 状态机（issued/validating/…）——前者未命中时回退 certJobStatusLabel
const statusResultLabel = (r: string): string =>
  ({ success: '成功', failed: '失败', cancelled: '已取消', interrupted: '中断', running: '运行中', skipped: '已跳过' }[r] ?? certJobStatusLabel(r as CertJobStatus))
const resultTagType = (r: string): 'success' | 'danger' | 'info' | 'warning' =>
  r === 'success' || r === 'issued' ? 'success' : r === 'failed' ? 'danger' : r === 'cancelled' ? 'warning' : 'info'

// FE-U5（第 69 轮）：委托 formatDate（配置时区单源）——此前 new Date 浏览器本地
// 时区格式化，与全站口径分叉；非法串回退 formatDate 的 string-fallback 透传。
const fmtTime = (s?: string) => formatDate(s)
const fmtDuration = (ms?: number) => {
  if (!ms || ms <= 0) return '—'
  if (ms < 1000) return `${ms}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.floor(ms / 60000)}m${Math.round((ms % 60000) / 1000)}s`
}
</script>

<style scoped>
.tm-root { display: flex; flex-direction: column; gap: 20px; max-width: 1500px; margin: 0 auto; width: 100%; }
.card-header { display: flex; justify-content: space-between; align-items: center; }
.card-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: #111827; }
.title-icon { font-size: 16px; color: #3b82f6; }

/* KPI 四卡 */
.tm-kpis { margin-bottom: 0; }
.tm-kpi { text-align: center; }
.tm-kpi :deep(.el-card__body) { padding: 18px 12px; }
.tm-kpi-num { font-size: 30px; font-weight: 800; color: #111827; line-height: 1.1; }
.tm-kpi-run { color: #3b82f6; }
.tm-kpi-bad { color: #f87171; }
.tm-kpi-label { font-size: 12.5px; color: #6b7280; margin-top: 6px; display: flex; align-items: center; justify-content: center; gap: 4px; }
.tm-kpi-lock { font-size: 12px; color: #b45309; }

/* 队列横幅 */
.tm-cq-banner :deep(.el-card__body) { padding: 12px 20px; }
.tm-cq-banner-inner { display: flex; align-items: center; gap: 16px; }
.tm-cq-banner-title { display: flex; align-items: center; gap: 6px; font-size: 14px; font-weight: 600; color: #111827; white-space: nowrap; }
.tm-cq-banner-stats { display: flex; gap: 12px; }
.tm-cq-chip { font-size: 12.5px; color: #6b7280; white-space: nowrap; }
.tm-cq-chip b { font-weight: 700; color: #111827; margin-left: 2px; }
.tm-c-run { color: #4f8cff !important; } .tm-c-wait { color: #38e1ff !important; }
.tm-cq-banner-live { flex: 1; min-width: 0; display: flex; align-items: center; gap: 8px; overflow: hidden; }
.tm-cq-domain-chip { font-size: 12px; color: #374151; background: #f3f4f6; border-radius: 999px; padding: 3px 10px; white-space: nowrap; display: inline-flex; align-items: center; gap: 5px; }
.tm-cq-dot { width: 6px; height: 6px; border-radius: 50%; background: #4f8cff; }
.tm-cq-dot--queued, .tm-cq-dot--pending { background: #fbbf24; }
.tm-cq-dot--waiting_ca { background: #38e1ff; }
.tm-cq-idle { font-size: 12.5px; color: #9aa0b5; }
.tm-cq-more { font-size: 12px; color: #9aa0b5; text-align: center; padding-top: 4px; }

.tm-chart { height: 230px; width: 100%; }
.tm-skeleton { background: linear-gradient(90deg, rgba(0,0,0,.03) 25%, rgba(0,0,0,.06) 50%, rgba(0,0,0,.03) 75%); background-size: 200% 100%; animation: tm-shimmer 1.2s infinite; border-radius: 8px; }
@keyframes tm-shimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }
.tm-count { font-size: 12px; color: #6b7280; font-weight: 400; background: #f3f4f6; border-radius: 999px; padding: 1px 8px; }

/* 表格 */
:deep(.tm-nowrap-table .cell) { white-space: nowrap; }
.tm-task-name { font-weight: 500; }
.tm-status { display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px; }
.tm-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--tm-c, #9aa0b5); box-shadow: 0 0 6px var(--tm-c, transparent); }
.tm-status[data-status="running"] { --tm-c: #4f8cff; }
.tm-status[data-status="failed"] { --tm-c: #f87171; }
.tm-status[data-status="stopped"], .tm-status[data-status="disabled"] { --tm-c: #62687f; }
.tm-status[data-status="idle"] { --tm-c: #9aa0b5; }
.tm-tag-periodic {
  --el-tag-bg-color: rgba(0, 168, 168, 0.1);
  --el-tag-border-color: rgba(0, 168, 168, 0.35);
  --el-tag-text-color: #009393;
}
.tm-tag-periodic.el-tag--dark,
.tm-tag-periodic.el-tag--plain {
  background-color: var(--el-tag-bg-color);
  border-color: var(--el-tag-border-color);
  color: var(--el-tag-text-color);
}
.tm-dim { color: var(--el-text-color-placeholder); }
.tm-ok { color: #34d399; font-weight: 600; }
.tm-bad { color: #f87171; font-weight: 600; }
.tm-pagination { display: flex; justify-content: flex-end; margin-top: 12px; }

/* tooltip 提示 */
:global(.tm-name-tip) { max-width: 380px; }
.tm-tip-title { font-weight: 600; margin-bottom: 4px; }
.tm-tip-cadence { font-size: 12px; opacity: .85; margin-bottom: 2px; }
.tm-tip-desc { font-size: 12px; line-height: 1.6; }
.tm-tip-sep { height: 6px; }

/* 详情 */
.tm-detail { display: flex; flex-direction: column; gap: 14px; }
.tm-detail-desc { font-size: 13px; color: var(--el-text-color-regular); line-height: 1.7; background: var(--el-fill-color-lighter); border-radius: 8px; padding: 10px 14px; }
.tm-detail-descs :deep(.el-descriptions__label) { white-space: nowrap; }
.tm-detail-descs :deep(.el-descriptions__content .el-tag) { vertical-align: middle; margin-left: 4px; }
.tm-detail-msg { font-size: 12.5px; color: var(--el-text-color-secondary); }
.tm-detail-section { font-size: 13px; font-weight: 600; color: var(--el-text-color-primary); margin-top: 4px; padding-top: 12px; border-top: 1px solid var(--el-border-color-lighter); }

/* 日志 */
.tm-log-stats { display: flex; align-items: center; margin-bottom: 10px; }
.tm-log-container { max-height: 60vh; overflow: auto; background: #0f172a; border-radius: 8px; padding: 16px; border: 1px solid #1e293b; }
.tm-log-content { margin: 0; color: #e2e8f0; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; font-size: 12px; line-height: 1.7; white-space: pre-wrap; }
</style>

