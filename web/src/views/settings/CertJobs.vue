<template>
  <el-alert v-if="jobsPollingError.errorMessage.value" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
    <template #title>
      <div class="polling-error-title">
        <span>证书任务加载失败：{{ jobsPollingError.errorMessage.value }}</span>
        <el-button link type="danger" :loading="loading" @click="retryJobsPolling">立即重试</el-button>
      </div>
    </template>
    <div class="polling-error-meta">{{ jobsPollingErrorDescription }}</div>
  </el-alert>
  <!-- 需人工横幅（2026-10-30 裁定）：仅本页存在「需人工」行（failed 且无 CA 冷却
       且失败次数达上限）时出现；× 按「行 id+updated_at」指纹记 localStorage
       （单源 utils/certJobStatus），新增/变化的需人工行重新出现。 -->
  <el-alert v-if="manualBannerRows.length > 0" type="warning" show-icon class="manual-banner" @close="dismissManualBanner">
    <template #title>
      <div class="polling-error-title">
        <span>本页 {{ manualBannerRows.length }} 条证书任务自动重试已达上限，需人工处理</span>
        <el-button link type="warning" @click="showManualOnly">查看</el-button>
      </div>
    </template>
  </el-alert>
  <!-- 查看后的筛选态：仅显示本页命中的需人工行（服务端分页不动），可清除 -->
  <div v-if="manualFilterActive" class="info-note-bar">
    <span class="info-note-desc">已筛选：需人工任务（本页 {{ manualRows.length }} 条，自动重试已达上限）</span>
    <el-button link type="primary" @click="manualFilterActive = false">清除筛选</el-button>
  </div>
  <!-- 宽度观测容器：容器变窄时按优先级隐藏低价值列（见 utils/certJobColumns）。
       收敛下限 619px（不可让位列合计）；更窄时切 overflow-x:auto——「日志/重签」
       操作列可达性优先于无滚动条目标（overflow:hidden 会把操作列硬裁到不可见）。 -->
  <div ref="tableWrapRef" class="cert-jobs-wrap" :class="{ 'cert-jobs-wrap--scroll': tableBelowMinWidth }">
  <el-table
    v-if="loading || jobs.length > 0"
    :data="filteredJobs"
    row-key="id"
    size="small"
    v-loading="loading"
    class="cert-jobs-table"
    :fit="true"
  >
    <el-table-column v-if="visibleColumns.has('rule_id')" prop="rule_id" label="规则 ID" min-width="116" show-overflow-tooltip />
    <el-table-column prop="domain" label="域名" min-width="210">
      <template #default="{ row }">
        <!-- 多域名规则可能超长：单元格内尽量显示，hover 看完整域名。
             规则 ID 列让位后并入副行，信息不丢失 -->
        <el-tooltip :content="row.domain">
          <span class="cell-text">{{ row.domain }}</span>
        </el-tooltip>
        <span v-if="!visibleColumns.has('rule_id')" class="cell-sub">#{{ row.rule_id }}</span>
      </template>
    </el-table-column>
    <el-table-column prop="status" label="状态" width="84" align="center">
      <template #default="{ row }">
        <!-- hover=派生口径（2026-10-30 裁定：旧证书/失败次数/下次重试，实现单源
             utils/certJobStatus）；CA 原文（message）只在「日志」对话框呈现，
             不再挂状态标签。在途行回落在途说明（stage 文本）。 -->
        <el-tooltip :disabled="!statusHover(row as CertJob)" :content="statusHover(row as CertJob)">
          <span><el-tag :type="statusType(row.status)" size="small">{{ rowStatusLabel(row as CertJob) }}</el-tag></span>
        </el-tooltip>
      </template>
    </el-table-column>
    <el-table-column v-if="visibleColumns.has('issuer')" label="颁发者" min-width="84" show-overflow-tooltip>
      <template #default="{ row }">
        <span :class="row.issuer ? 'cell-text' : 'cell-empty'">{{ row.issuer || '-' }}</span>
      </template>
    </el-table-column>
    <el-table-column label="证书有效期" min-width="155">
      <template #default="{ row }">
        <!-- 过期时间与剩余天数合并一列：列内只留日期，精确时间（配置时区）进 tooltip。
             过期证书不渲染裸负数——色弱/黑白场景下「-1 天」无文字语义。
             门用后端派生的 not_after（expires_at 缺失时按 PEM 解析）：只判
             expires_at 会让导入/集群回插的 NULL 有效期行显示「-」，而规则页
             同一证书显示「剩 N 天」。 -->
        <el-tooltip v-if="row.status === 'issued' && effectiveNotAfter(row as CertJobListItem)" :content="formatDate(effectiveNotAfter(row as CertJobListItem))">
          <span :class="['cert-days', row.certificate_status]">{{ formatDateShort(effectiveNotAfter(row as CertJobListItem)) }} · {{ row.certificate_status === 'expired' ? `已过期 ${Math.abs(row.days_remaining)} 天` : `剩 ${row.days_remaining} 天` }}</span>
        </el-tooltip>
        <span v-else class="cell-empty">-</span>
      </template>
    </el-table-column>
    <el-table-column v-if="visibleColumns.has('renewal')" label="自动重签时间" min-width="150">
      <template #default="{ row }">
        <!-- 收敛提示：配置窗口超出寿命可执行区间时按「到期前 7 天」续签，
             列值不能被读成「配置的 88 天」 -->
        <el-tooltip :disabled="!renewalConverged" :content="renewalConvergedNote">
          <span v-if="row.status === 'issued' && renewalAt(row as CertJobListItem)" class="cell-text">{{ formatDate(renewalAt(row as CertJobListItem)) }}</span>
          <span v-else class="cell-empty">-</span>
        </el-tooltip>
      </template>
    </el-table-column>
    <el-table-column v-if="visibleColumns.has('updated')" label="更新时间" min-width="150">
      <template #default="{ row }">
        <span v-if="formatDate(row.updated_at)" class="cell-text">{{ formatDate(row.updated_at) }}</span>
        <span v-else class="cell-empty">-</span>
      </template>
    </el-table-column>
    <el-table-column label="重试次数" width="80" align="center">
      <template #default="{ row }">
        <!-- 仅终态失败显示 N（= renewal_attempts，上限=续签重试次数配置）；
             在途/成功/禁用显示 -。冷却列让位时，等待 CA 的冷却值并入本格 tooltip -->
        <el-tooltip :disabled="visibleColumns.has('cooling') || !coolingHint(row as CertJob)" :content="coolingHint(row as CertJob)">
          <span v-if="attemptsCell(row as CertJob)" class="cell-text">{{ attemptsCell(row as CertJob) }}</span>
          <span v-else class="cell-empty">-</span>
        </el-tooltip>
      </template>
    </el-table-column>
    <el-table-column v-if="visibleColumns.has('cooling')" label="冷却时间" min-width="90" show-overflow-tooltip>
      <template #default="{ row }">
        <!-- waiting_ca=剩余倒计时；终态失败=「档位 · 时刻」（computeBackoff 同规则
             推导，429 实际间隔更短时显示实际间隔，单源 certJobCooldownCell） -->
        <span v-if="coolingCell(row as CertJob)" class="cell-text">{{ coolingCell(row as CertJob) }}</span>
        <span v-else class="cell-empty">-</span>
      </template>
    </el-table-column>
    <el-table-column label="操作" width="90" align="center">
      <template #default="{ row }">
        <el-button link type="primary" size="small" @click="viewLogs(row as CertJobListItem)">日志</el-button>
        <el-tooltip :disabled="!retryDisabledReason(row as CertJobListItem)" :content="retryDisabledReason(row as CertJobListItem)">
          <span>
            <el-button link type="primary" size="small" :loading="retryingJobIds.has(row.id)" :disabled="isReadOnly || !canRetry(row as CertJobListItem) || retryingJobIds.has(row.id)" @click="retryJob(row as CertJobListItem)">重签</el-button>
          </span>
        </el-tooltip>
      </template>
    </el-table-column>
  </el-table>
  </div>
  <!-- 首拉失败且无数据时改「加载失败」，与顶部错误横幅口径一致，避免误
       导作「暂无签发任务」（有数据时保留最后列表，此空态不渲染）。-->
  <el-empty v-if="!loading && jobs.length === 0" :description="jobsPollingError.errorMessage.value ? '加载失败' : '暂无签发任务'" :image-size="60" />
  <div v-if="jobs.length > 0 || currentPage > 1" class="cert-jobs-pagination">
    <el-pagination
      v-model:current-page="currentPage"
      v-model:page-size="pageSize"
      :page-sizes="[10, 20, 50, 100]"
      :total="total"
      layout="total, sizes, prev, pager, next"
      @current-change="jobsPolling.run"
      @size-change="onPageSizeChange"
    />
  </div>

  <el-dialog
    v-model="logDialogVisible"
    width="min(1100px, 94vw)"
    top="5vh"
    class="cert-log-dialog"
    destroy-on-close
    @opened="onLogDialogOpened"
    @closed="onLogDialogClosed"
  >
    <template #header>
      <DialogHeader :icon="Timer" :title="`证书日志 - ${currentJob?.domain || ''}`" subtitle="ACME 签发任务实时日志" />
    </template>
    <div ref="logContainerRef" class="dialog-panel log-container">
      <pre v-if="logHtml" class="log-content" v-html="logHtml" />
      <el-empty v-else description="暂无日志" :image-size="60" />
    </div>
    <template #footer>
      <div style="display: flex; align-items: center; gap: 10px;">
        <LogStorageBar v-if="currentJob" :key="currentJob.rule_id" log-key="certjob" :caddy-id="String(currentJob.rule_id)" style="margin-right: auto" />
        <div class="log-auto-refresh" title="关闭后停止自动拉取，可使用「刷新」按钮手动更新">
          <span>自动刷新</span>
          <el-switch v-model="logAutoRefresh" size="small" />
        </div>
        <el-button @click="logDialogVisible = false">关闭</el-button>
        <el-button type="primary" :loading="logLoading" @click="refreshLogs">刷新</el-button>
      </div>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed, watch } from 'vue'
import { Timer } from '@element-plus/icons-vue'
import DialogHeader from '@/components/DialogHeader.vue'
import { request, mfaAwareSuccess } from '@/utils/api'
import { useLogTailPolling } from '@/composables/useLogTailPolling'
import LogStorageBar from '@/components/LogStorageBar.vue'
import { formatDate, formatDateShort } from '@/utils/date'
import { CERT_JOB_COLUMNS_MIN_WIDTH, pickVisibleCertJobColumns } from '@/utils/certJobColumns'
import { escapeHtml } from '@/utils/escape'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useAuthStore } from '@/stores/auth'
import type { APIResponse, CertJobsPage, CertJobListItem } from '@/types'
import { certJobStatusTone, certJobRetryReady, certJobManualNeeded, certJobRowStatusLabel, certJobStatusHover, certJobCooldownCell, certManualBannerFingerprint, loadCertManualBannerDismissed, saveCertManualBannerDismissed, CERT_JOB_RENEWAL_ATTEMPTS_FALLBACK } from '@/utils/certJobStatus'
import type { CertJobStatus } from '@/utils/certJobStatus'
import { certJobEffectiveNotAfter, certJobRenewalAt, certRenewalWindowConverged, certRenewalWindowDays } from '@/utils/certJobExpiry'
import { usePollingTask } from '@/composables/usePollingTask'
import { usePollingErrorState } from '@/composables/usePollingErrorState'

// 视图类型收敛 types/index.ts 的 CertJobListItem（后端 certJobListItem 投影单源）。
type CertJob = CertJobListItem

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.readOnlyReason !== null)
let disposed = false
// （过度修复审查 REMOVE：jobsRequestSeq 已删——入口 loading 门 + disposed
// 析取使其作为裁决条件永不为真，且全部调用经 jobsPolling drain 串行。）

// 表格容器宽度 → 可见列集合（贪心让位，见 utils/certJobColumns）。
// 初始 Infinity = 未测量：先按全列渲染，ResizeObserver 给出真实宽度后收敛。
const tableWrapRef = ref<HTMLDivElement | null>(null)
const tableWrapWidth = ref(Number.POSITIVE_INFINITY)
const visibleColumns = computed(() => pickVisibleCertJobColumns(tableWrapWidth.value))
// 最小集（619px）之下表格必然溢出：overflow:hidden 会把「操作」列裁到不可达，
// 切横向滚动兜底（可达性优先）。
const tableBelowMinWidth = computed(() => tableWrapWidth.value < CERT_JOB_COLUMNS_MIN_WIDTH)
let tableWrapObserver: ResizeObserver | null = null

const coolingHint = (row: CertJob): string => {
  if (row.status !== 'waiting_ca' || !row.ca_available_after) return ''
  return `冷却：${formatCoolingTime(row.ca_available_after)}`
}

// ── 续签语境派生口径（2026-10-30 裁定，单源 utils/certJobStatus）─────────

// 续签重试上限（hover「上限 M」/需人工判定/横幅门）。auth store 的 /config 投影
// 只携带 cert_renewal_days（投影面不含 cert_renewal_attempts），这里一次性拉取
// （非轮询；任意登录用户可读，失败保持兜底值=db.DefaultCertRenewalAttempts 同值）。
const renewalAttemptsCap = ref(CERT_JOB_RENEWAL_ATTEMPTS_FALLBACK)

// 配置时区 HH:mm（冷却列「时刻」与 hover「下次自动重试」共用）：ca_available_after
// 是 RFC3339/UTC 族，走 formatDate 换算配置时区后截取时分。
const clockHHmm = (iso: string): string => {
  const full = formatDate(iso)
  const matched = /(\d{2}:\d{2}):\d{2}$/.exec(full)
  return matched ? matched[1] : ''
}

// 状态标签：failed 细分（需人工/续签失败/失败），其余沿用全表（≤4 字约束）。
const rowStatusLabel = (row: CertJob): string => certJobRowStatusLabel(row, renewalAttemptsCap.value)

// 状态 hover：四态走派生单源；其余在途行回落在途说明（message 为 stage 文本，
// CA 原文只随 failed 形态出现，已被派生口径替代）。
const statusHover = (row: CertJob): string =>
  certJobStatusHover(row, renewalAttemptsCap.value, Date.now(), clockHHmm) || row.message || ''

// 重试次数列：仅终态失败显示 N（renewal_attempts omitempty 缺失时按无数据显示 -）。
const attemptsCell = (row: CertJob): string =>
  row.status === 'failed' && typeof row.renewal_attempts === 'number' ? String(row.renewal_attempts) : ''

// 冷却时间列：waiting_ca=剩余倒计时（既有文案）；终态失败=档位·时刻（computeBackoff
// 同规则，429 实际间隔更短时显示实际间隔）；其余 -。
const coolingCell = (row: CertJob): string => {
  if (row.status === 'waiting_ca' && row.ca_available_after) return formatCoolingTime(row.ca_available_after)
  if (row.status === 'failed') return certJobCooldownCell(row, clockHHmm)
  return ''
}

const jobs = ref<CertJob[]>([])
const loading = ref(false)
// cert_renewal_days 改读 authStore.fetchConfig 消费面（曾挂载整取
// GET /config 单键）——store ref 响应式，挂载早于 fetchConfig 完成也能随后收敛。
const certRenewalDays = computed(() => authStore.certRenewalDays)
const currentPage = ref(1)
const pageSize = ref(20)
const total = ref(0)
const retryingJobIds = ref(new Set<number>())

// ── 需人工横幅（可关闭）+ 筛选 ─────────────────────────────
let dismissedManualFingerprints = loadCertManualBannerDismissed()
const manualFilterActive = ref(false)

const manualRows = computed(() => jobs.value.filter((row) => certJobManualNeeded(row, renewalAttemptsCap.value)))
// 横幅只列未被关闭指纹命中的行：同一行 updated_at 再变化（新一轮失败）→ 新指纹重现。
const manualBannerRows = computed(() =>
  manualRows.value.filter((row) => !dismissedManualFingerprints.has(certManualBannerFingerprint(row))))
// 「查看」= 本页需人工行筛选（服务端分页不动；命中集为空自动退出筛选态）。
const filteredJobs = computed(() => (manualFilterActive.value ? manualRows.value : jobs.value))

watch(manualRows, (rows) => {
  if (manualFilterActive.value && rows.length === 0) manualFilterActive.value = false
})

const showManualOnly = (): void => {
  manualFilterActive.value = true
}

const dismissManualBanner = (): void => {
  dismissedManualFingerprints = new Set([
    ...dismissedManualFingerprints,
    ...manualBannerRows.value.map((row) => certManualBannerFingerprint(row)),
  ])
  saveCertManualBannerDismissed(dismissedManualFingerprints)
}

const logDialogVisible = ref(false)
const logContent = ref('')
const currentJob = ref<CertJob | null>(null)
let lastLogErrorToastAt = 0
let logDialogController: AbortController | null = null
const logContainerRef = ref<HTMLDivElement | null>(null)

const logHtml = computed(() => {
  if (!logContent.value) return ''
  return escapeHtml(logContent.value)
    .replace(/\[INFO\]/g, '<span style="color:#3b82f6">$&</span>')
    .replace(/\[WARN\]/g, '<span style="color:#eab308">$&</span>')
    .replace(/\[ERROR\]/g, '<span style="color:#ef4444">$&</span>')
    .replace(/\[DEBUG\]/g, '<span style="color:#a855f7">$&</span>')
})

// 日志尾轮询收敛 useLogTailPolling 单源（后台标签页暂停/单飞/会话
// 序号作废/滚底统一）；30s 节流错误 toast保留在 onError。
const logTail = useLogTailPolling({
  interval: 3000,
  content: logContent,
  container: logContainerRef,
  isActive: () => !disposed && logDialogVisible.value && currentJob.value !== null,
  fetch: async () => {
    const job = currentJob.value
    if (!job) return null
    const res = await request.get<APIResponse<{ content: string }>>(`/certificates/jobs/${job.id}/logs`, { signal: logDialogController?.signal, silent: true })
    if (disposed || currentJob.value?.id !== job.id) return null
    return res.data?.content || ''
  },
  onError: (error) => {
    if (disposed) return
    console.error('Failed to fetch cert job logs:', error)
    // toast 节流（对齐 usePollingErrorState 的 30s 语义）——弹窗内
    // 3s 轮询持续失败时不再每 tick 叠加一条「获取日志失败」刷屏。
    const now = Date.now()
    if (now - lastLogErrorToastAt > 30_000) {
      lastLogErrorToastAt = now
      ElMessage.error('获取日志失败')
    }
  },
})
const logLoading = logTail.loading

const statusType = (status: CertJobStatus) => certJobStatusTone(status)

const canRetry = (row: CertJob): boolean =>
  certJobRetryReady(row.retry_cooldown_seconds)

const retryDisabledReason = (row: CertJob): string => {
  if (isReadOnly.value) return authStore.readOnlyMessage
  if (row.status === 'disabled') return '已禁用的任务无法重签'
  if (canRetry(row)) return ''
  // 冷却秒数为 null 时「等待 0 分钟」是自相矛盾的文案——不可重试且无冷却
  // 信息（契约漂移形态）给无行动指引的中性文案。
  if (row.retry_cooldown_seconds === null || row.retry_cooldown_seconds === undefined) return '当前状态暂不可重签'
  return `当前状态需等待 ${Math.ceil(row.retry_cooldown_seconds / 60)} 分钟后重签`
}

// 证书真实到期时刻：后端派生 not_after 优先（库值 expires_at 缺失时按 PEM
// 解析），expires_at 仅作旧版响应回退。两列（有效期/自动重签时间）共用本口径，
// 避免同一行一个显示天数、另一个显示「-」（实现单源 utils/certJobExpiry）。
const effectiveNotAfter = (row: CertJob): string => certJobEffectiveNotAfter(row)

// 自动重签时间 = 证书到期前「实际生效窗口」天；返回 ISO 原值，列内紧凑格式
// 与 tooltip 完整格式各自取用，不在 helper 里预先格式化（避免双口径）。
const renewalAt = (row: CertJob): string => certJobRenewalAt(row, certRenewalDays.value)

// 配置窗口超出寿命可执行区间（84–88 天）时后端按「到期前 7 天」续签——列值
// 必须与设置页说明、扫描实际行为同口径，收敛事实显性提示而非静默改写。
const renewalConverged = computed(() => certRenewalWindowConverged(certRenewalDays.value))
const renewalConvergedNote = computed(() =>
  `配置的自动续签天数（${certRenewalDays.value} 天）超出证书寿命可执行窗口，实际按到期前 ${certRenewalWindowDays(certRenewalDays.value)} 天续签`)

const formatCoolingTime = (iso: string): string => {
  // 畸形/缺失时间返回空串（与 utils/certJobExpiry 同族口径）：不做防御会渲染
  // 「NaN小时NaN分钟后」。后端 ca_available_after 为 RFC3339 或 null，正常链路
  // 不触发，此处仅防御带外/旧版响应。
  const t = Date.parse(iso)
  if (!Number.isFinite(t)) return ''
  const diff = t - Date.now()
  if (diff <= 0) return '可重试'
  const hours = Math.floor(diff / (1000 * 60 * 60))
  const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60))
  return `${hours}小时${minutes}分钟后`
}

const fetchJobs = async (roundSignal?: AbortSignal) => {
  if (disposed || loading.value) return
  loading.value = true
  try {
    const jobsRes = await request.get<APIResponse<CertJobsPage<CertJob>>>('/certificates/jobs', {
      params: { page: currentPage.value, page_size: pageSize.value },
      signal: roundSignal ?? jobsPolling.signal,
      silent: true,
    })
    if (disposed) return
    if (!jobsRes.data) throw new TypeError('证书任务分页响应缺少 data')
    jobs.value = [...jobsRes.data.list]
    total.value = jobsRes.data.total
    const lastPage = Math.max(1, Math.ceil(total.value / pageSize.value))
    if (currentPage.value > lastPage) {
      currentPage.value = lastPage
      queueMicrotask(() => void jobsPolling.run())
    }
  } finally {
    if (!disposed) loading.value = false
  }
}

const onPageSizeChange = (): void => {
  currentPage.value = 1
  void jobsPolling.run()
}

const retryJob = async (row: CertJob) => {
  if (isReadOnly.value || !canRetry(row) || retryingJobIds.value.has(row.id)) return
  const isWaitingCA = row.status === 'waiting_ca'
  const message = isWaitingCA
    ? '任务当前处于"等待 CA"状态（可能仍在频率冷却中）。确定要立即重新签发吗？如果使用同一 CA 且冷却未到，可能再次被拒绝。'
    : `确定要对域名 ${row.domain} 重新签发证书吗？`
  retryingJobIds.value = new Set(retryingJobIds.value).add(row.id)
  try {
    try {
      await ElMessageBox.confirm(message, '重签确认', { type: isWaitingCA ? 'warning' : 'info' })
    } catch {
      return
    }
    if (disposed) return
    // 上方确认对话框已是显式用户确认；force=true 让服务端越过 waiting_ca
    // 的 CA 冷却门（未确认的直接调用会被 429 拒绝并提示剩余冷却时长）。
    await request.post(`/certificates/jobs/${row.id}/retry?force=true`, undefined, { signal: jobsPolling.signal })
    if (disposed) return
    mfaAwareSuccess('重新签发已触发')
    // run() 恰逢在途轮询时只把 pending 合并进当前 drain——若撞上 drain 已退出
    // 而 inFlight 未清的微任务窗口，pending 会搁浅到下一个 5s 定时 tick，「已触发」toast
    // 后列表迟迟不更新。第一次 await 等在途排空（drainPromise 的 finally 先于本 continuation
    // 清掉 inFlight），第二次 run 必然新起 drain，强制一次 POST 之后的新鲜抓取。
    await jobsPolling.run()
    await jobsPolling.run()
  } catch (error: unknown) {
    // Error toast is already shown by the global axios interceptor.
    if (!disposed) console.error('Failed to retry cert job:', error)
  } finally {
    if (!disposed) {
      const nextRetryingIds = new Set(retryingJobIds.value)
      nextRetryingIds.delete(row.id)
      retryingJobIds.value = nextRetryingIds
    }
  }
}

const viewLogs = async (row: CertJob) => {
  logDialogController?.abort()
  logDialogController = new AbortController()
  logTail.invalidate()
  currentJob.value = row
  logDialogVisible.value = true
}

// 先同步装定时器再触发首拉（logTail.start 内部即此序）——原 await 后才
// startLogPolling，首拉慢于关闭时 @closed 已清 timer，随后续体又装上 3s 轮询
// （关闭后持续请求日志端点）。
const logAutoRefresh = ref(true)

watch(logAutoRefresh, (on) => {
  if (on) logTail.start()
  else logTail.stop()
})

const onLogDialogOpened = (): void => {
  if (logAutoRefresh.value) logTail.start()
  else logTail.refresh()
}

const onLogDialogClosed = () => {
  logTail.stop()
  logDialogController?.abort()
  logDialogController = null
  currentJob.value = null
  logContent.value = ''
}

const refreshLogs = async (): Promise<void> => logTail.refresh()

const jobsPollingError = usePollingErrorState()
const jobsPollingErrorDescription = computed(() => {
  const lastError = formatDate(jobsPollingError.lastErrorAt.value)
  const retryAt = formatDate(jobsPollingError.retryAt.value)
  return retryAt
    ? `最后错误：${lastError}；契约响应异常，自动重试已退避至 ${retryAt}`
    : `最后错误：${lastError}`
})
const jobsPolling = usePollingTask(async (task) => {
  if (!jobsPollingError.canRun()) return
  await fetchJobs(task.signal)
  jobsPollingError.clear()
}, {
  interval: 5000,
  onError: (error) => {
    console.error('Failed to poll certificate jobs:', error)
    jobsPollingError.recordError(error)
  },
})

const retryJobsPolling = async (): Promise<void> => {
  jobsPollingError.resetBackoff()
  await jobsPolling.run()
}

onMounted(() => {
  void jobsPolling.run()
  jobsPolling.start()
  // 续签重试上限（cert_renewal_attempts）：一次性 /config 拉取，失败保持兜底值
  // CERT_JOB_RENEWAL_ATTEMPTS_FALLBACK（db.DefaultCertRenewalAttempts 同值）。
  request.get<APIResponse<{ cert_renewal_attempts?: number }>>('/config', { silent: true, signal: jobsPolling.signal })
    .then((res) => {
      const attempts = res.data?.cert_renewal_attempts
      if (typeof attempts === 'number' && attempts > 0) renewalAttemptsCap.value = attempts
    })
    .catch(() => { /* 读取失败保持兜底上限 */ })
  // 容器宽度观测：驱动列让位（避免任何宽度下出现水平滚动条）
  const wrap = tableWrapRef.value
  if (!wrap) return
  // 无 ResizeObserver 时无法测量：按 0 处理以切横向滚动，保证右侧操作列可达
  // （初始 Infinity 会让全列保留且不切 --scroll，overflow:hidden 裁掉操作列）。
  if (typeof ResizeObserver === 'undefined') {
    tableWrapWidth.value = 0
    return
  }
  tableWrapObserver = new ResizeObserver((entries) => {
    const width = entries[0]?.contentRect?.width ?? 0
    tableWrapWidth.value = width > 0 ? width : 0
  })
  tableWrapObserver.observe(wrap)
})

onUnmounted(() => {
  disposed = true
  logTail.stop()
  logDialogController?.abort()
  logDialogController = null
  tableWrapObserver?.disconnect()
  tableWrapObserver = null
})
</script>

<style scoped>
.log-container {
  max-height: 520px;
  overflow: auto;
  background: #0f172a;
  border-radius: 0;
  padding: 12px;
  border: 1px solid #1e293b;
}
.log-content {
  margin: 0;
  color: #e2e8f0;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  font-size: 12px;
  line-height: 1.7;
  white-space: pre-wrap;
}

.cell-text {
  line-height: 1;
}
.cell-empty {
  color: #9ca3af;
  line-height: 1;
}
.cert-days {
  line-height: 1;
  font-weight: 500;
}
.cert-days.valid {
  color: #10b981;
}
.cert-days.expiring {
  color: #f59e0b;
}
.cert-days.expired {
  color: #ef4444;
}
.cert-jobs-wrap {
  /* 表格自身按列宽自适应；宽于最小集时容器裁掉任何溢出，杜绝页面级/卡片级横向滚动 */
  overflow: hidden;
}
.cert-jobs-wrap--scroll {
  /* 窄于最小集（619px）：列让位已耗尽，恢复横向滚动保住操作列可达 */
  overflow-x: auto;
}
.cert-jobs-table {
  width: 100%;
}
.cell-sub {
  display: block;
  margin-top: 2px;
  font-size: 11px;
  line-height: 1.2;
  color: #9ca3af;
}
.cert-jobs-pagination { display: flex; justify-content: flex-end; margin-top: 16px; }
/* .polling-error-alert 已收敛 main.css（三处 scoped 逐字重复删除） */
/* .polling-error-title/.polling-error-meta 已收敛 main.css*/
.cert-jobs-table :deep(.el-table__cell) {
  vertical-align: middle;
}
.cert-jobs-table :deep(.el-table__cell .cell) {
  text-align: left;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.cert-jobs-table :deep(.el-table__cell.is-center .cell) {
  text-align: center;
}
.cert-jobs-table :deep(.el-button + .el-button) {
  margin-left: 6px;
}

.log-auto-refresh {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--text-secondary, #909399);
  white-space: nowrap;
}
</style>
