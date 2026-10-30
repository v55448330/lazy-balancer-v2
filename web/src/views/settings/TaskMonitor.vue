<template>
  <div class="tm-root">
    <!-- 轮询失败横幅（照 CertJobs 形态；行内件样式复用 main.css
         .polling-error-*/.error-banner，家族收敛第 4 点） -->
    <el-alert v-if="pollingError.errorMessage.value" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
      <template #title>
        <div class="polling-error-title">
          <span>任务监控加载失败：{{ pollingError.errorMessage.value }}</span>
          <el-button link type="danger" :loading="refreshing" @click="retryPolling">立即重试</el-button>
        </div>
      </template>
      <div class="polling-error-meta">{{ pollingErrorDescription }}</div>
    </el-alert>
    <!-- KPI 概览（四卡） -->
    <el-row :gutter="20" class="tm-kpis">
      <el-col :xs="12" :md="6">
        <el-card class="tm-kpi">
          <div class="tm-kpi-num">{{ taskFamilyCount }}</div>
          <div class="tm-kpi-label" title="仅统计引擎任务族，不含证书签发工作项（cert-job 动态行）">任务族</div>
        </el-card>
      </el-col>
      <el-col :xs="12" :md="6">
        <el-card class="tm-kpi">
          <div class="tm-kpi-num tm-kpi-run">{{ runningCount }}</div>
          <div class="tm-kpi-label" title="在途工作项：含证书签发工作项（排队/等待 CA 均计为运行中），可能大于任务族数">运行中</div>
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
          <div class="tm-kpi-label">24h 失败</div>
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
              <!-- 口径显性化：本图是「列表全部任务行」的分布，与只数引擎族的 KPI
                   不同源（cert-job 动态行最多 100 条会主导占比）。 -->
              <span class="form-tip-inline">口径：全部任务行（含证书工作项，上限 100）</span>
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
              <el-button :icon="Refresh" circle size="small" :loading="refreshing" @click="() => refreshNow()" title="立即刷新" />
            </div>
          </template>
          <!-- 数据就位后再挂载（vue-echarts 8 增量规划对「空 option 挂载→数据后到达」
               的 series/legend 合并不稳——实证轴渲染而序列/图例缺失；挂载即完整
               option 与独立 echarts 实证一致） -->
          <div v-if="seriesStale && series24h.length" class="chart-stale-hint">采集失败：展示上次结果</div>
          <v-chart v-if="loaded && series24h.length" :option="statsBarOption" :update-options="{ notMerge: true }" autoresize class="tm-chart" />
          <el-empty v-else-if="loaded && !series24h.length" description="该时间范围内暂无数据" :image-size="60" />
          <div v-else class="tm-chart tm-skeleton"></div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 证书队列横幅（实时——非任务） -->
    <el-card class="tm-cq-banner">
      <div class="tm-cq-banner-inner">
        <div class="tm-cq-banner-title"><el-icon class="title-icon"><Lock /></el-icon><span>ACME 证书任务队列</span></div>
        <div v-if="certQueueError" class="tm-cq-banner-stats">
          <span class="tm-cq-chip">排队 <b>—</b></span>
          <span class="tm-cq-chip">进行中 <b>—</b></span>
          <span class="tm-cq-chip">等 CA <b>—</b></span>
        </div>
        <div v-else class="tm-cq-banner-stats">
          <span class="tm-cq-chip">排队 <b>{{ certQueue.truncated ? '≥' : '' }}{{ certQueue.queued }}</b></span>
          <span class="tm-cq-chip">进行中 <b class="tm-c-run">{{ certQueue.truncated ? '≥' : '' }}{{ certQueue.running }}</b></span>
          <span class="tm-cq-chip">等 CA <b class="tm-c-wait">{{ certQueue.truncated ? '≥' : '' }}{{ certQueue.waiting }}</b></span>
        </div>
        <div class="tm-cq-banner-live">
          <span v-if="certQueueError" class="tm-cq-idle">证书队列状态加载失败（下一轮轮询自动重试）</span>
          <!-- 正文空态改按聚合存活计数判定（原只看首页存活行——
               首页均为终态而聚合计数非空时会谎报「空闲」）。 -->
          <template v-else-if="certQueueHasLive(certQueue)">
            <span v-for="j in certQueue.jobs.slice(0, CERT_QUEUE_VISIBLE_JOBS)" :key="j.id" class="tm-cq-domain-chip">
              {{ j.domain }}<i :class="'tm-cq-dot tm-cq-dot--' + j.status" />
            </span>
            <span v-if="certQueueMoreCount(certQueue) > 0" class="tm-cq-more">+{{ certQueueMoreCount(certQueue) }}</span>
          </template>
          <span v-else class="tm-cq-idle">空闲——临期证书由「证书续期扫描」自动入队</span>
        </div>
        <!-- 标签判据与聚合计数同口径——排队/等 CA 亦为「非空闲」。-->
        <el-tag :type="certQueueError ? 'danger' : certQueueIsBusy(certQueue) ? 'primary' : 'success'" size="small" effect="plain">
          {{ certQueueError ? '加载失败' : certQueueIsBusy(certQueue) ? '队列非空' : '空闲' }}
        </el-tag>
      </div>
    </el-card>

    <!-- 任务列表 -->
    <div v-if="certJobsTruncated" class="info-note-bar"><span class="info-note-desc">证书任务行仅显示最近 100 条（更老的签发记录请在证书任务页按规则查看）</span></div>

    <el-card>
      <template #header>
        <div class="card-header">
          <div class="card-title"><el-icon class="title-icon"><List /></el-icon><span>全部任务</span>
            <span class="tm-count">{{ filteredTasks.length }}</span>
          </div>
          <div class="tm-filter-group">
            <el-select v-model="categoryFilter" size="small" clearable placeholder="全部分类" class="tm-category-filter" @change="page = 1">
              <el-option label="全部分类" value="all" />
              <el-option v-for="c in categoryOptions" :key="c" :label="c" :value="c" />
            </el-select>
            <el-radio-group v-model="kindFilter" size="small">
              <el-radio-button value="all">全部</el-radio-button>
              <el-radio-button value="scheduled">定时</el-radio-button>
              <el-radio-button value="daemon">常驻</el-radio-button>
              <el-radio-button value="periodic">循环</el-radio-button>
              <el-radio-button value="oneshot">触发</el-radio-button>
            </el-radio-group>
          </div>
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
        <el-table-column label="分类" width="92">
          <template #default="{ row }">
            <el-tag size="small" effect="plain" :type="categoryTagType(row.category)">{{ row.category }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="类型" width="72">
          <template #default="{ row }">
            <el-tag size="small" :type="kindTag(row.kind)" effect="plain" :class="kindTagClass(row.kind)">{{ kindLabel(row.kind) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="96">
          <template #default="{ row }">
            <!-- 状态列词表=引擎执行语义三态（空闲/运行中/失败，2026-10-22 用户
                 裁定）：证书业务生命周期态（已签发/限流中…）不进状态列，
                 由任务名称下的业务文本承载。 -->
            <span class="tm-status" :data-status="row.status"><span class="tm-dot"></span>{{ statusLabel(row.status) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="调度" width="92">
          <template #default="{ row }">
            <!-- v2.0 调度开关统一：定时/循环=停止/恢复调度、
                 常驻=启停自管理循环——绑定 loop_on 走 /toggle（后端按 Kind 路由）。
                 方案 A（2026-10-12）：开关只看 loop_on（TaskMeta.Enabled 字段已删除）——
                 业务关时调度态由业务页开关停调度承载（business_driven 行开关只读），
                 状态列不再用 disabled 表达 -->
            <!-- cert-waiting-ca 默认调度关闭、续期扫描入队
                 唤醒——开关上加 tooltip 说明自动唤醒语义（页内既有 tooltip 范式） -->
            <!-- 角色不适用（从节点上的 master-only 族）：调度开关在本节点
                 不可用——显性标注原因，避免把「永不投递」误读为开关故障 -->
            <el-tooltip v-if="row.role_applicable === false" content="仅主节点生效：从节点不调度此任务，调度开关仅在主节点可用" placement="top" :offset="8" :show-after="150" :show-arrow="false">
              <el-tag size="small" type="info" effect="plain">仅主节点</el-tag>
            </el-tooltip>
            <el-tooltip v-else-if="row.id === 'cert-waiting-ca'" :content="scheduleStoppedTip(row as TaskInfo) || '有证书任务入队时自动唤醒'" placement="top" :offset="8" :show-after="150" :show-arrow="false">
              <el-switch :model-value="!!row.loop_on" :disabled="!canOperate" @change="(v: string | number | boolean) => onToggle(row as TaskInfo, !!v)" />
            </el-tooltip>
            <el-tooltip v-else-if="row.kind !== 'oneshot'" :content="scheduleStoppedTip(row as TaskInfo) || (isBusinessDrivenTask(row as TaskInfo) ? '由对应业务页自动更新控制' : '停止/恢复调度')" placement="top" :offset="8" :show-after="150" :show-arrow="false">
              <!-- 引擎自行停调（连续失败未推进排程槽）：业务驱动任务的开关在本页
                   只读，恢复入口在业务页——用警示标签替代不可用开关，避免「关着的
                   开关」被读成用户主动停止；非业务驱动任务保留开关（打开即恢复）。 -->
              <el-tag v-if="row.schedule_stopped_reason && isBusinessDrivenTask(row as TaskInfo)" size="small" type="danger" effect="plain">已停调</el-tag>
              <el-switch v-else :model-value="!!row.loop_on" :disabled="!canOperate || isBusinessDrivenTask(row as TaskInfo)" @change="(v: string | number | boolean) => onToggle(row as TaskInfo, !!v)" />
            </el-tooltip>
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
            <span v-if="row.next_run_at && row.loop_on && row.kind !== 'daemon' && row.role_applicable !== false">{{ row.next_run_at }}</span>
            <span v-else class="tm-dim">—</span>
          </template>
        </el-table-column>
        <el-table-column width="104">
          <template #header>
            <el-tooltip content="近 24 小时成功 / 失败次数；历史明细最多 50 条（见详情）" placement="top" :show-arrow="false">
              <span>成功/失败 ⓘ</span>
            </el-tooltip>
          </template>
          <template #default="{ row }">
            <span class="tm-ok">{{ row.success_24h }}</span> / <span :class="{ 'tm-bad': row.fail_24h > 0 }">{{ row.fail_24h }}</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="250" fixed="right" class-name="tm-op-cell">
          <template #default="{ row }">
            <el-tooltip v-if="row.triggerable" :disabled="!runCooldownReason(row as TaskInfo)" :content="runCooldownReason(row as TaskInfo)">
              <span class="tm-op-trigger">
                <el-button
                  link type="primary" size="small"
                  :disabled="!canOperate || taskActionPendingId !== null || row.status === 'running' || Boolean(runCooldownReason(row as TaskInfo))"
                  @click="onTrigger(row as TaskInfo)"
                >运行</el-button>
              </span>
            </el-tooltip>
            <el-button
              v-if="row.cancellable && row.status === 'running'"
              link type="danger" size="small" :disabled="!canOperate || taskActionPendingId !== null"
              @click="onCancel(row as TaskInfo)"
            >取消</el-button>
            <!-- 常驻行启停已由调度列开关承担（loop_on 同源）——操作列改「重启」-->
            <el-button
              v-if="row.controllable"
              link type="primary" size="small"
              :disabled="!canOperate || taskActionPendingId !== null"
              @click="onRestart(row as TaskInfo)"
            >重启</el-button>
            <el-button link type="info" size="small" @click="openLogs(row as TaskInfo)">日志</el-button>
            <el-button link type="info" size="small" @click="openDetail(row as TaskInfo)">详情</el-button>
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
          @size-change="(s: number) => { pageSize = s; page = 1 }"
        />
      </div>
    </el-card>

    <!-- 任务详情 -->
    <!-- 同类弹框均 min(…,92vw)——固定 720px 在窄屏横向溢出。-->
    <el-dialog v-model="detailVisible" width="min(720px, 92vw)" top="8vh">
      <template #header>
        <DialogHeader
          :icon="detailIcon" :title="detailTask?.name || ''"
          :subtitle="detailTask ? `${detailTask.category} · ${kindLabel(detailTask.kind)} · ${statusLabel(detailTask.status)}` : ''"
          :tone="detailTone"
        />
      </template>
      <div v-if="detailTask" class="tm-detail">
        <section class="dialog-panel">
          <DialogSectionHeader title="任务信息" :description="detailTask.description" />
        <el-descriptions :column="2" border size="small" class="tm-detail-descs">
          <el-descriptions-item label="运行节奏">{{ detailTask.cadence || '—' }}</el-descriptions-item>
          <el-descriptions-item label="角色适用性">
            <el-tag v-if="detailTask.role_applicable === false" size="small" type="info" effect="plain">仅主节点运行（本节点不调度）</el-tag>
            <el-tag v-else size="small" type="success" effect="plain">本节点可运行</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="调度开关">
            <el-tooltip content="引擎调度投递开关（列表「调度」列同源）" placement="top" :offset="8" :show-after="150" :show-arrow="false">
              <el-tag v-if="detailTask.role_applicable === false" size="small" type="info" effect="plain">仅主节点生效</el-tag>
              <el-tag v-else-if="detailTask.kind !== 'oneshot'" size="small" :type="detailTask.loop_on ? 'success' : 'warning'" effect="plain">{{ detailTask.loop_on ? '开启' : '关闭' }}</el-tag>
              <el-tag v-else size="small" type="info" effect="plain">不可调度</el-tag>
            </el-tooltip>
          </el-descriptions-item>
          <el-descriptions-item v-if="detailTask.schedule_stopped_reason" label="停调原因">
            <span class="tm-bad">{{ scheduleStoppedTip(detailTask) }}</span>
          </el-descriptions-item>
          <!-- 与列表「下次执行」列同门（loop_on 且非常驻且角色适用）——停用
               任务的排程槽是陈旧预约值，详情无条件显示会与列表「—」口径分叉 -->
          <el-descriptions-item label="下次执行">{{ (detailTask.next_run_at && detailTask.loop_on && detailTask.kind !== 'daemon' && detailTask.role_applicable !== false) ? detailTask.next_run_at : '—' }}</el-descriptions-item>
          <el-descriptions-item label="24h 成功 / 失败">
            <span class="tm-ok">{{ detailTask.success_24h }}</span> / <span :class="{ 'tm-bad': detailTask.fail_24h > 0 }">{{ detailTask.fail_24h }}</span>
          </el-descriptions-item>
          <el-descriptions-item v-if="detailTask.kind === 'daemon'" label="启动时间">{{ fmtTime(detailTask.started_at) || '—' }}</el-descriptions-item>
          <el-descriptions-item v-if="detailTask.last_run" label="开始时间">{{ fmtTime(detailTask.last_run.started_at) || '—' }}</el-descriptions-item>
          <el-descriptions-item v-if="detailTask.last_run" label="完成时间">{{ detailTask.status === 'running' ? '进行中' : fmtTime(detailTask.last_run.finished_at) || '—' }}</el-descriptions-item>
          <el-descriptions-item v-if="detailTask.last_run" label="耗时">{{ fmtDuration(detailTask.last_run.duration_ms) }}</el-descriptions-item>
          <el-descriptions-item v-if="detailTask.last_run" label="触发 / 结果"><span class="tm-inline-flex">{{ triggerLabel(detailTask.last_run.trigger) }} · {{ detailTask.last_run.operator || '系统' }} · <el-tag size="small" :type="resultTagType(detailTask.last_run.result)">{{ statusResultLabel(detailTask.last_run.result) }}</el-tag></span></el-descriptions-item>
        </el-descriptions>
        </section>
        <div v-if="detailTask.last_run?.message" class="dialog-panel tm-detail-msg">{{ detailTask.last_run.message }}</div>
        <!-- 历史加载失败显性化（原静默呈现为空表，与「无记录」不可区分）-->
        <el-alert v-if="detailHistoryError" type="error" :closable="false" show-icon title="运行历史加载失败，请关闭后重新打开" style="margin-bottom: 12px" />
        <section v-if="history.length" class="tm-history-section">
          <DialogSectionHeader :title="historyTitle" />
          <div class="dialog-panel dialog-panel--flush">
            <el-table :data="history" size="small" max-height="240" class="tm-nowrap-table">
              <el-table-column prop="started_at" label="开始" width="152">
                <template #default="{ row }">{{ fmtTime(row.started_at) }}</template>
              </el-table-column>
              <el-table-column prop="duration_ms" label="耗时" width="78">
                <template #default="{ row }">{{ fmtDuration(row.duration_ms) }}</template>
              </el-table-column>
              <el-table-column prop="trigger" label="触发" width="72">
                <template #default="{ row }">{{ triggerLabel(row.trigger) }}</template>
              </el-table-column>
              <el-table-column label="操作者" width="120" show-overflow-tooltip>
                <!-- operator 为空=自动/排程/启动等系统触发（后端 auto/startup/legacy 恒空） -->
                <template #default="{ row }">{{ row.operator || '系统' }}</template>
              </el-table-column>
              <el-table-column prop="status" label="结果" width="88">
                <template #default="{ row }">
                  <el-tag size="small" :type="resultTagType(row.status)">{{ statusResultLabel(row.status) }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column prop="message" label="信息" min-width="120" show-overflow-tooltip />
            </el-table>
          </div>
        </section>
      </div>
    </el-dialog>

    <!-- 任务日志弹框（与证书日志同款：暗色终端流） -->
    <el-dialog v-model="logsVisible" width="min(1100px, 94vw)" top="5vh" destroy-on-close @closed="closeLogs">
      <template #header>
        <DialogHeader :icon="Timer" :title="`任务日志 · ${logsTask?.name || ''}`" subtitle="统一任务引擎文本日志（实时刷新）" />
      </template>
      <!-- 日志存储统计栏：task:<id> 逐任务真实文件（含 cert-job 动态行）；后端未含该键时组件自隐 -->
      <div class="tm-log-stats">
        <LogStorageBar :log-key="logsTaskStorageKey" style="margin-right: auto" />
      </div>
          <div ref="logContainerRef" class="dialog-panel tm-log-container">
        <pre v-if="logsText" class="tm-log-content">{{ logsText }}</pre>
        <el-empty v-else description="暂无日志" :image-size="60" />
      </div>
      <template #footer>
        <div style="display: flex; align-items: center;">
          <span v-if="logsLoadError" style="font-size: 12px; color: var(--el-color-danger); margin-right: 12px;">日志加载失败，自动重试中</span>
          <span style="font-size: 12px; color: #9aa0b5; margin-right: auto;">每 5 秒自动刷新</span>
          <el-button @click="logsVisible = false">关闭</el-button>
        </div>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import '@/utils/echarts' // 统一注册（含 LineChart——直刷本页不再依赖先到 Dashboard）
import type { EChartsOption } from 'echarts'
import VChart from 'vue-echarts'
import axios from 'axios'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Refresh, PieChart as PieChartIcon, DataLine, List, Monitor, Lock, Box, Timer } from '@element-plus/icons-vue'
import { request, mfaAwareSuccess } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import { usePollingTask } from '@/composables/usePollingTask'
import { useLogTailPolling } from '@/composables/useLogTailPolling'
import { formatDate } from '@/utils/date'
import { usePollingErrorState } from '@/composables/usePollingErrorState'
import { useClampedPagination } from '@/composables/useClampedPagination'
import { createLatestReadSession } from '@/utils/viewAsyncState'
import { hasOwn } from '@/utils/hasOwn'
import { statusColor } from '@/utils/chartTheme'
import { certJobRetryReady } from '@/utils/certJobStatus'
import { CERT_QUEUE_VISIBLE_JOBS, certQueueHasLive, certQueueIsBusy, certQueueMoreCount } from '@/utils/certQueue'
import DialogHeader from '@/components/DialogHeader.vue'
import DialogSectionHeader from '@/components/DialogSectionHeader.vue'
import LogStorageBar from '@/components/LogStorageBar.vue'
import type { APIResponse } from '@/types'


interface TaskRunInfo { started_at: string; finished_at: string; duration_ms: number; trigger: string; operator?: string; result: string; message?: string }
interface TaskInfo {
  id: string; name: string; description?: string; cadence?: string; category: string
  kind: 'scheduled' | 'daemon' | 'periodic' | 'oneshot'
  status: string; cancellable: boolean; controllable?: boolean; triggerable?: boolean
  last_run?: TaskRunInfo; next_run_at?: string; runs_24h: number; success_24h: number; fail_24h: number
  loop_on?: boolean; started_at?: string; business_driven?: boolean // 常驻族：循环启停态/引擎启动时刻
  schedule_stopped_reason?: string // 引擎自行停调来源（fail-streak=自动轮连续失败未推进排程槽）
  role_applicable?: boolean // 本节点角色是否允许该任务运行（false=仅主节点，从节点视图标注）
  retry_cooldown_seconds?: number | null // 证书行剩余重试冷却（秒，0=可运行；null=永久不可重试；其它行为 0）
}
interface RunRecord {
  id: number; task_id: string; family: string; trigger: string; operator?: string; status: string
  started_at: string; finished_at: string; duration_ms: number
  // stage/entry_count 恒零死列已随后端删除——不再声明。
  message?: string
}

// 24h 分小时桶（GET /system/tasks/stats-24h-series；配置时区墙面小时，后端已对齐）
interface TaskHourlyStat { hour: string; success: number; failed: number }

const authStore = useAuthStore()
const isAdmin = computed(() => authStore.user?.role === 'admin')
const tasks = ref<TaskInfo[]>([])
const certJobsTruncated = ref(false)
const loaded = ref(false)
const series24h = ref<TaskHourlyStat[]>([])
const seriesStale = ref(false)
const refreshing = ref(false)
// 只读判定统一走全局 fail-closed 契约（authStore.
// readOnlyReason===null=可写；曾本地 isSlave fetch-open 且不随角色切换刷新，
// 违反 ——全站 14 页唯一偏离者）
const readOnly = computed(() => authStore.readOnlyReason !== null)
const canOperate = computed(() => isAdmin.value && !readOnly.value)

// 200 但缺 data 是契约违约，不得静默渲染成「0 任务 / 空图表」——与
// CertJobs.vue 同口径抛 TypeError，才能进入 usePollingErrorState 的契约退避与
// 错误横幅（原 `res.data?.tasks || []` 把违约伪装成合法空集）。
const fetchTasks = async (signal?: AbortSignal) => {
  const res = await request.get<APIResponse<{ tasks: TaskInfo[]; cert_jobs_truncated?: boolean }>>('/system/tasks', { silent: true, signal })
  if (!res.data) throw new TypeError('任务列表响应缺少 data')
  return { data: res.data }
}
const fetchSeries = async (signal?: AbortSignal) => {
  const res = await request.get<APIResponse<{ series: TaskHourlyStat[] }>>('/system/tasks/stats-24h-series', { silent: true, signal })
  if (!res.data) throw new TypeError('任务统计响应缺少 data')
  return { data: res.data }
}
// 手动刷新与 10s 轮询共用最新读取会话：后发轮次推进世代，旧快照（含任务、序列、
// 队列）即使晚到也不得覆盖新快照。刷新整体结束（成功或失败）即撤掉首屏骨架。
interface TaskRefreshSnapshot {
  cancelled: boolean
  taskResult: PromiseSettledResult<{ data: { tasks: TaskInfo[]; cert_jobs_truncated?: boolean } }>
  seriesResult: PromiseSettledResult<{ data: { series: TaskHourlyStat[] } }>
  queueResult: PromiseSettledResult<CertQueueRead>
}
const refreshReadSession = createLatestReadSession()
const refreshNow = async (roundSignal?: AbortSignal): Promise<void> => {
  refreshing.value = true
  await refreshReadSession.run<TaskRefreshSnapshot>(async (ownSignal) => {
    const signal = roundSignal ?? ownSignal
    const [taskResult, seriesResult, queueResult] = await Promise.allSettled([
      fetchTasks(signal),
      fetchSeries(signal),
      fetchCertQueue(signal),
    ])
    return { cancelled: signal.aborted, taskResult, seriesResult, queueResult }
  }, {
    onStart: () => { refreshing.value = true },
    onSuccess: ({ cancelled, taskResult, seriesResult, queueResult }) => {
      // pause/stop 取消的一轮不是在途失败，也不得清掉既有错误或陈旧标记。
      if (cancelled) return
      let firstError: unknown
      let failed = false
      if (taskResult.status === 'fulfilled') {
        const res = taskResult.value
        tasks.value = res.data.tasks || []
        // 审计项：cert-job 动态行上限 100——后端回传截断标记，页面显性提示，
        // 避免把「只有这些任务」误读成全量（更老的记录请在证书任务页按规则查看）。
        certJobsTruncated.value = !!res.data.cert_jobs_truncated
      } else if (!axios.isCancel(taskResult.reason)) {
        failed = true
        firstError = taskResult.reason
      }
      if (seriesResult.status === 'fulfilled') {
        series24h.value = seriesResult.value.data.series || []
        seriesStale.value = false
      } else if (!axios.isCancel(seriesResult.reason)) {
        // 序列失败保留上一轮柱图，但必须显式标陈旧；首次失败由下方空态承接。
        seriesStale.value = true
        if (!failed) {
          failed = true
          firstError = seriesResult.reason
        }
      }
      if (queueResult.status === 'fulfilled') {
        certQueueError.value = queueResult.value.failed
        if (queueResult.value.snapshot) certQueue.value = queueResult.value.snapshot
      } else if (!axios.isCancel(queueResult.reason)) {
        certQueueError.value = true
        // 契约违约（缺 data）与其余两份请求同语义进入退避；普通失败只影响横幅。
        if (queueResult.reason instanceof TypeError && !failed) {
          failed = true
          firstError = queueResult.reason
        }
      }
      if (failed) pollingError.recordError(firstError)
      else pollingError.clear()
    },
    onError: (error: unknown) => pollingError.recordError(error),
    onFinally: () => {
      loaded.value = true
      refreshing.value = false
    },
  })
}
onMounted(() => {
  void polling.run() // 首跑立即（start() 只设定时器；证书队列横幅已入轮询闭包随首跑）
  polling.start()
})
onUnmounted(() => {
  refreshReadSession.invalidate()
  polling.stop()
})

// 轮询失败可见化（此前只落 console）。契约性失败（TypeError）退避
// 期间轮询闭包经 canRun 门跳过；横幅「立即重试」重置退避立即拉取。
const pollingError = usePollingErrorState()
const pollingErrorDescription = computed(() => {
  const lastError = formatDate(pollingError.lastErrorAt.value)
  const retryAt = formatDate(pollingError.retryAt.value)
  return retryAt
    ? `最后错误：${lastError}；契约响应异常，自动重试已退避至 ${retryAt}`
    : `最后错误：${lastError}`
})
const polling = usePollingTask(async ({ signal }) => {
  // 证书队列横幅与任务列表同频 10s（曾只在 mounted/手动刷新拉取，横幅最长陈旧一个会话）
  if (!pollingError.canRun()) return
  // 消费每轮 abort signal——pause/stop（含组件卸载）可取消在途请求；
  // 与手动刷新共用最新读取会话，后发轮次覆盖前一轮快照。
  await refreshNow(signal)
}, {
  interval: 10000,
  onError: (e) => {
    console.error('task monitor poll failed:', e)
    pollingError.recordError(e)
  },
})
const retryPolling = async (): Promise<void> => {
  pollingError.resetBackoff()
  // 重试按钮此前从不置 refreshing，点击后零反馈（勾着号/看不到在跑）
  refreshing.value = true
  try {
    await polling.run()
  } finally {
    refreshing.value = false
  }
}
// ===== 证书队列状态（独立卡——非任务族） =====
interface CertJobRow { id: number; domain: string; status: string; updated_at?: string | null; ca_provider_name?: string }
interface CertQueueState { queued: number; running: number; waiting: number; total: number; jobs: CertJobRow[]; truncated: boolean }
interface CertQueueRead { snapshot: CertQueueState | null; failed: boolean }
// certQueue.loaded 死字段删除（写字段零消费方）。
const certQueue = ref<CertQueueState>({
  queued: 0, running: 0, waiting: 0, total: 0, jobs: [], truncated: false,
})
// 队列加载失败不得呈现为「全 0 / 空闲」——显式错误态（下一轮轮询自愈）
const certQueueError = ref(false)
// 列表只用于横幅列 4 个域名 chip——page_size=6 即够（原 200，每 10s
// 让后端逐行截取 cert_pem/解析 issuer/算到期状态后丢弃）。计数仍以
// status_counts 聚合为真源；该字段缺席时才退回「首页可见行推导 + total 超页
// 声明 ≥」。
const CERT_QUEUE_PAGE_SIZE = 6
// 接入轮询 AbortSignal——pause/stop（含组件卸载）可取消在途请求，
// 与 fetchTasks/fetchSeries 同口径（补齐 :409 注释承诺）。
const fetchCertQueue = async (signal?: AbortSignal): Promise<CertQueueRead> => {
  try {
    const res = await request.get<APIResponse<{ list: CertJobRow[]; total: number; status_counts?: Record<string, number> }>>('/certificates/jobs', { params: { page: 1, page_size: CERT_QUEUE_PAGE_SIZE }, silent: true, signal })
    // 缺 data 为契约违约（同 fetchTasks/fetchSeries），下面向上抛。
    if (!res.data) throw new TypeError('证书队列响应缺少 data')
    const list = res.data.list || []
    const counts = res.data?.status_counts
    const statusCount = (statuses: string[]): number => statuses.reduce((sum, s) => sum + (counts?.[s] || 0), 0)
    let liveCount: number
    let queued: number
    let waiting: number
    if (counts) {
      const terminal = statusCount(['issued', 'failed', 'disabled'])
      liveCount = Object.values(counts).reduce((sum, n) => sum + n, 0) - terminal
      queued = statusCount(['queued', 'pending'])
      waiting = statusCount(['waiting_ca'])
    } else {
      const live = list.filter(j => !['issued', 'failed', 'disabled'].includes(j.status))
      liveCount = live.length
      queued = live.filter(j => ['queued', 'pending'].includes(j.status)).length
      waiting = live.filter(j => j.status === 'waiting_ca').length
    }
    const liveJobs = list.filter(j => !['issued', 'failed', 'disabled'].includes(j.status))
    return {
      snapshot: {
        total: liveCount,
        // status_counts 为空时才依赖首页下界；有聚合计数则完整。
        truncated: !counts && (res.data?.total ?? 0) > list.length,
        queued,
        running: Math.max(0, liveCount - queued - waiting),
        waiting,
        jobs: liveJobs.slice(0, CERT_QUEUE_PAGE_SIZE),
      },
      failed: false,
    }
  } catch (error: unknown) {
    // 契约违约（缺 data）与其余两份请求同语义——向上抛，交由读取会话
    // 记录并进入 TypeError 退避；普通网络/5xx 只影响横幅（下一轮自愈）。
    if (error instanceof TypeError) throw error
    return { snapshot: null, failed: !axios.isCancel(error) }
  }
}

// ===== 概览统计 =====
// 任务族只数引擎族：cert-job 动态行是逐张证书的签发工作项（上限 100），
// 计入会让计数随签发记录在 ~30 → ~130 之间漂移（同排 24h 计数已排除它们）。
const taskFamilyCount = computed(() => tasks.value.filter(t => !isCertJobRow(t.id)).length)
// 运行中=当前在途工作项：cert-job 的 queued/pending/waiting_ca 也是在途工作
// （后端将非终态一律映射 running），与引擎族同列可比，故不排除。
const runningCount = computed(() => tasks.value.filter(t => t.status === 'running').length)
// 24h KPI 只聚合引擎族执行行——cert-job 行的 runs_24h/fail_24h 语义是
// 「工作项终态事件」（每行 ≤1），与引擎族「执行轮次」混加会把两种口径
// 并成一个数（高频引擎任务淹没证书计数，反之亦然）。
const total24h = computed(() => tasks.value.reduce((s, t) => s + (isCertJobRow(t.id) ? 0 : (t.runs_24h || 0)), 0))
const fail24h = computed(() => tasks.value.reduce((s, t) => s + (isCertJobRow(t.id) ? 0 : (t.fail_24h || 0)), 0))

// ===== 筛选 + 分页 =====
const kindFilter = ref('all')
// 分类筛选原为 el-table 列级 filter（作用在 pagedTasks 切片上=
// 只过滤当前页），现提升到 filteredTasks 参与计数/分页。
const categoryFilter = ref('all')
const categoryOptions = computed(() => [...new Set(tasks.value.map(t => t.category))].sort())
const filteredTasks = computed(() => {
  const list = tasks.value
    .filter(t => kindFilter.value === 'all' || t.kind === kindFilter.value)
    .filter(t => categoryFilter.value === 'all' || !categoryFilter.value || t.category === categoryFilter.value)
  // 默认按分类排序（安全防护→证书→备份→集群→系统），类内稳定
  return [...list].sort((a, b) =>
    (hasOwn(categoryOrder, a.category) ? categoryOrder[a.category] : 9)
    - (hasOwn(categoryOrder, b.category) ? categoryOrder[b.category] : 9))
})
const page = ref(1)
const pageSize = ref(20)
// 页码夹紧单源（useClampedPagination）——任务列表收缩（cert-job 动态行
// 完成消失）或增大 pageSize 后自动回夹，不再停留在空页。原 slice 无夹紧，仅筛选
// 变化复位。
const { pagedItems: pagedTasks } = useClampedPagination(filteredTasks, page, pageSize)
// 筛选条件变化回第 1 页（避免高页码 + 收窄结果落在空页）
watch([kindFilter, categoryFilter], () => { page.value = 1 })

// ===== 图表（引擎真数据） =====
// 口径（有意保留「全部任务行」）：本图回答「列表里各状态各有多少」，故与表格同集，
// 与只数引擎族的 KPI 不同源——cert-job 动态行（上限 100）会主导占比，卡片头已
// 显式标注该口径；若改为引擎族分布须同时标注，避免两处对同一事实呈现强弱相反。
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
        name: statusLabel(k), value: v, itemStyle: { color: hasOwn(statusColor, k) ? statusColor[k] : '#4f8cff' },
      })),
    }],
  }
})
// 近 24 小时执行（成功/失败）——24h 分小时桶堆叠面积时间序列（2026-10-11
// 用户裁定方案 A）：任务名柱状图被手动证书任务高频执行压扁其他任务；时间
// 序列既消除频次压制，又新增「何时跑/何时挂」的分布信息。数据源
// GET /system/tasks/stats-24h-series（配置时区墙面小时，24 桶升序零填）。
const statsBarOption = computed<EChartsOption>((): EChartsOption => {
  const buckets = series24h.value
  return {
    animation: false,
    tooltip: { trigger: 'axis' },
    legend: { top: 0, itemGap: 24 },
    grid: { left: 8, right: 12, top: 36, bottom: 8, containLabel: true },
    xAxis: { type: 'category', boundaryGap: false, data: buckets.map(b => b.hour.slice(11, 16)), axisLabel: { interval: 3 } },
    yAxis: { type: 'value', minInterval: 1 },
    series: [
      { name: '成功', type: 'line', stack: 'runs', smooth: true, symbol: 'none', areaStyle: { opacity: 0.35 }, data: buckets.map(b => b.success), itemStyle: { color: '#34d399' }, lineStyle: { color: '#34d399' } },
      { name: '失败', type: 'line', stack: 'runs', smooth: true, symbol: 'none', areaStyle: { opacity: 0.35 }, data: buckets.map(b => b.failed), itemStyle: { color: '#f87171' }, lineStyle: { color: '#f87171' } },
    ],
  }
})

// ===== 操作 =====
// 请求调用原在 confirm 的 try 之外 → 失败产生 unhandled
// rejection；且无重入守卫（快速双击叠加多个确认框/重复请求）。统一范式：
// pending 守卫 → confirm → try/catch 包住请求 → finally 释放。
const taskActionPendingId = ref<string | null>(null)

interface TaskActionOptions {
  /** 可选确认框（占位在其之前完成——快速双击只出现一个框）。 */
  confirm?: { message: string; title: string; type?: 'warning' | 'info'; confirmButtonText: string }
  request: () => Promise<APIResponse>
  successFallback: string
  failureLabel: string
  /** 失败后回读服务端真实状态（开关类操作用）。 */
  refreshOnError?: boolean
}

/**
 * 任务操作统一执行器：占位守卫 → 确认 → 请求 → 记录失败
 * → 释放占位。原实现把 request 放在 confirm 的 try 之外（失败 unhandled
 * rejection）且无重入守卫（双击叠加确认框/重复请求）。
 */
async function runTaskAction(row: TaskInfo, options: TaskActionOptions): Promise<void> {
  if (taskActionPendingId.value !== null) return
  // 函数级纵深守卫：按钮 :disabled 只是入口层，角色/只读态可能在页面停留期间
  // 变化（另标签降权、整机切从节点）——此处再守一道，避免重渲染窗口内的点击
  // 绕过入口直发写请求（后端仍会 403，但用户只会看到莫名其妙的报错）。
  if (!canOperate.value) return
  taskActionPendingId.value = row.id
  try {
    if (options.confirm) {
      try {
        await ElMessageBox.confirm(options.confirm.message, options.confirm.title, {
          type: options.confirm.type ?? 'warning',
          confirmButtonText: options.confirm.confirmButtonText,
        })
      } catch {
        return // 用户取消：不请求
      }
    }
    const res = await options.request()
    mfaAwareSuccess(res.message || options.successFallback)
    void refreshNow().catch(() => {})
  } catch (error: unknown) {
    // 全局拦截器已 toast；仅记录，避免 unhandled rejection
    console.error(`${options.failureLabel} failed`, error)
    if (options.refreshOnError) void refreshNow().catch(() => {})
  } finally {
    if (taskActionPendingId.value === row.id) taskActionPendingId.value = null
  }
}

const runCooldownReason = (row: TaskInfo): string => {
  // null 是契约里的第三种状态（永久不可重试），不得先 `?? 0` 归成「可运行」。
  if (row.retry_cooldown_seconds === null) return '该任务永久不可重试'
  const seconds = Number(row.retry_cooldown_seconds ?? 0)
  if (!Number.isFinite(seconds)) return ''
  // 判据与证书任务页同源（utils/certJobStatus）：后端下发「此刻剩余秒」，0 即可运行。
  if (certJobRetryReady(seconds)) return ''
  return `冷却中，约 ${Math.ceil(seconds / 60)} 分钟后可运行`
}

const onTrigger = (row: TaskInfo): Promise<void> => runTaskAction(row, {
  confirm: { message: `立即执行「${row.name}」？`, title: '手动触发', type: 'info', confirmButtonText: '执行' },
  request: () => request.post<APIResponse>(`/system/tasks/${row.id}/trigger`),
  successFallback: '已触发',
  failureLabel: 'trigger task',
})

const onToggle = async (row: TaskInfo, enabled: boolean): Promise<void> => {
  if (isBusinessDrivenTask(row)) {
    ElMessage.warning('该任务由对应业务页自动更新控制，请在业务页修改')
    return
  }
  // 常驻族停止前确认（功能中断影响大——如安全事件采集停摆）
  const needConfirm = !enabled && row.kind === 'daemon'
  await runTaskAction(row, {
    confirm: needConfirm
      ? { message: `确认停止「${row.name}」？停止后相关功能将中断，可随时重新启动。`, title: '常驻任务控制', confirmButtonText: '停止' }
      : undefined,
    request: () => request.post<APIResponse>(`/system/tasks/${row.id}/toggle`, { enabled }),
    successFallback: '已更新',
    failureLabel: 'toggle task',
    refreshOnError: true,
  })
}

const onCancel = (row: TaskInfo): Promise<void> => runTaskAction(row, {
  confirm: { message: `取消运行中的「${row.name}」？下载阶段将中断，已完成部分保留。`, title: '手动取消', confirmButtonText: '取消任务' },
  request: () => request.post<APIResponse>(`/system/tasks/${row.id}/cancel`),
  successFallback: '已发出取消信号',
  failureLabel: 'cancel task',
})

// 常驻行操作列「重启」（control restart——启停已由调度列开关承担）
const onRestart = (row: TaskInfo): Promise<void> => runTaskAction(row, {
  confirm: { message: `确认重启「${row.name}」？重启期间相关功能将短暂中断。`, title: '常驻任务控制', confirmButtonText: '重启' },
  request: () => request.post<APIResponse>(`/system/tasks/${row.id}/control`, { action: 'restart' }),
  successFallback: '已重启',
  failureLabel: 'restart task',
})

// ===== 详情 =====
const detailVisible = ref(false)
// 详情按 id 从最新 tasks 派生（此前持有打开时的行快照——轮询每轮整体替换
// tasks 后，状态/24h 计数/下次执行在弹框内永远不再更新）。行从列表消失（cert-job
// 完成退役）时退回打开时的行，避免正文瞬间清空。
const detailTaskId = ref<string | null>(null)
const detailSeed = ref<TaskInfo | null>(null)
const detailTask = computed<TaskInfo | null>(() => {
  const id = detailTaskId.value
  if (!id) return null
  return tasks.value.find(t => t.id === id) ?? detailSeed.value
})
const history = ref<RunRecord[]>([])
const detailIcon = computed(() => (detailTask.value?.category === '证书' ? Lock : detailTask.value?.category === '备份' ? Box : Monitor))
const detailTone = computed((): 'primary' | 'success' | 'warning' | 'danger' | undefined => {
  const st = detailTask.value?.status
  if (st === 'failed') return 'danger'
  if (st === 'running') return 'primary'
  return undefined
})
const isCertJobRow = (id: string): boolean => id.startsWith('cert-job:')
// cert-job 动态行无引擎运行历史——历史区域接 cert_jobs 数据源（每规则+域名
// 单行在册，展示该签发任务当前记录）
const historyTitle = computed(() =>
  detailTask.value && isCertJobRow(detailTask.value.id) ? '签发任务记录（cert_jobs）' : `运行历史（最近 ${history.value.length} 次）`)
// cert-job 动态行历史与引擎族同端点（GET /system/tasks/:id/history 的
// cert-job 分支直接返回 RunRecord 形状，时间已按配置时区转换）——
// 前端不再自建映射（字段推导/时区转换双实现漂移面收敛到后端单源）。
let detailSeq = 0
// 详情历史加载失败显性化（原静默 catch 呈现为空「运行历史」，与
// 无记录不可区分）
const detailHistoryError = ref(false)
const openDetail = async (row: TaskInfo) => {
  const seq = ++detailSeq
  detailTaskId.value = row.id
  detailSeed.value = row
  detailVisible.value = true
  history.value = []
  detailHistoryError.value = false
  try {
    const res = await request.get<APIResponse<{ runs: RunRecord[] }>>(`/system/tasks/${row.id}/history`, { silent: true })
    if (seq === detailSeq) history.value = res.data?.runs || []
  } catch {
    if (seq === detailSeq) detailHistoryError.value = true
  }
}

// ===== 日志抽屉（content 纯文本解析） =====
const logsVisible = ref(false)
const logsText = ref('')
const logsTask = ref<TaskInfo | null>(null)
const logsTaskStorageKey = computed(() => logsTask.value ? `task:${logsTask.value.id}` : 'tasks')
const logContainerRef = ref<HTMLElement | null>(null)
// 日志加载失败显性化（原静默）；轮询收敛
// useLogTailPolling 单源——补上本页原缺的后台标签页暂停。
const logsLoadError = ref(false)
const taskLogEndpoint = (id: string): string =>
  id.startsWith('cert-job:') ? `/certificates/jobs/${id.slice(9)}/logs` : `/system/tasks/${id}/logs`
const logsTail = useLogTailPolling({
  interval: 5000,
  content: logsText,
  container: logContainerRef,
  isActive: () => logsVisible.value && logsTask.value !== null,
  fetch: async () => {
    const task = logsTask.value
    if (!task) return null
    const res = await request.get<APIResponse<{ content: string }>>(taskLogEndpoint(task.id), { silent: true })
    // 先确认仍是同一任务，再清错误态：切任务后迟到的成功不得清掉新任务的失败提示。
    if (logsTask.value?.id !== task.id) return null
    if (!res.data) throw new TypeError('任务日志响应缺少 data')
    logsLoadError.value = false
    return res.data.content.trim()
  },
  onError: () => { logsLoadError.value = true },
})
const openLogs = (row: TaskInfo): void => {
  // 先清空上一任务内容并同步装定时器（start 内部即此序）——不再清空
  // 残留，也不会出现「首拉未完成就关闭 → await 后续体又装 interval」的关闭后
  // 永久轮询。
  logsTask.value = row
  logsVisible.value = true
  logsText.value = ''
  logsLoadError.value = false
  logsTail.start()
}
const closeLogs = (): void => {
  logsTail.stop()
  logsTask.value = null
  logsText.value = ''
}
onUnmounted(closeLogs)



// ===== 文案 =====
// 状态列方案 A（2026-10-12 用户裁定）：只承载执行语义——running/idle/failed
// 三态（cert-job 动态行同口径：退役/终态成功归 idle，证书业务生命周期态
// 由业务文本承载，不进状态列）。
// stopped/disabled 已从引擎族状态产出退役（调度语义归开关列 loop_on&&enabled）。
const statusLabels: Record<string, string> = {
  running: '运行中', idle: '空闲', failed: '失败',
}
// 状态列兜底只回显原值——禁止把 cert_jobs 业务生命周期态（issued/waiting_ca…）
// 经证书标签兜底渲染进状态列（2026-10-22 用户裁定三态词表）。
const statusLabel = (s: string) => hasOwn(statusLabels, s) ? statusLabels[s] : s
// v2.0 四类型：定时(蓝)/常驻(绿)/循环(青)/触发(橙)
const kindLabels: Record<string, string> = { scheduled: '定时', daemon: '常驻', periodic: '循环', oneshot: '触发' }
const kindLabel = (k: string) => hasOwn(kindLabels, k) ? kindLabels[k] : k
const kindTag = (k: string): 'primary' | 'success' | 'info' | 'warning' =>
  k === 'scheduled' ? 'primary' : k === 'daemon' ? 'success' : k === 'periodic' ? 'info' : 'warning'
const kindTagClass = (k: string) => (k === 'periodic' ? 'tm-tag-periodic' : '')
const isBusinessDrivenTask = (row: TaskInfo) => !!row.business_driven
// 引擎自行停调的恢复入口与用户主动停止不同：业务驱动任务的调度开关在本页
// 只读（后端 400），须到业务页重新保存「自动更新」（setter 会重新对齐调度），
// 或重启进程；其余任务直接打开本页开关即恢复。空串=非引擎停调。
const scheduleStoppedTip = (row: TaskInfo) => {
  if (!row.schedule_stopped_reason) return ''
  if (row.schedule_stopped_reason !== 'fail-streak') {
    return '引擎已停止该任务自动调度：请先修复失败原因，再重新开启调度，或重启进程恢复'
  }
  const head = '引擎已停止自动调度（自动轮连续失败且排程槽未推进）'
  return isBusinessDrivenTask(row)
    ? `${head}：请先修复失败原因，再到对应业务页重新保存「自动更新」开关，或重启进程恢复`
    : `${head}：请先修复失败原因，再打开本页调度开关恢复，或重启进程恢复`
}
const categoryOrder: Record<string, number> = { '安全防护': 0, '证书': 1, '备份': 2, '集群': 3, '系统': 4 }
const categoryTagType = (c: string): 'primary' | 'success' | 'warning' | 'info' =>
  c === '安全防护' ? 'primary' : c === '证书' ? 'success' : c === '备份' ? 'warning' : 'info'
// caddy-restart（Caddy 崩溃自愈 watcher 通道）此前裸显
// 英文 token——补中文标签，未列触发值仍回退原文。
const triggerLabels: Record<string, string> = { manual: '手动', auto: '自动', schedule: '排程', queue: '队列', startup: '启动', 'caddy-restart': 'Caddy重启' }
const triggerLabel = (t: string) => (hasOwn(triggerLabels, t) ? triggerLabels[t] : t) || '—'
// 结果词表=引擎 task_runs 结果域自有映射（running/success/failed/cancelled/
// skipped/interrupted，与 GET /system/tasks/:id/history 的 status 枚举同源）；
// 未知值显性回显「未知」——不借用 cert_jobs 状态机词表（issued/waiting_ca 等
// 属证书业务域，进了结果列只会域错位误导；cert-job 动态行的业务状态由任务
// 名称/详情的业务文本承载）。
const resultLabels: Record<string, string> = { success: '成功', failed: '失败', cancelled: '已取消', interrupted: '中断', running: '运行中', skipped: '已跳过' }
const statusResultLabel = (r: string): string =>
  hasOwn(resultLabels, r) ? resultLabels[r]! : '未知'
const resultTagType = (r: string): 'success' | 'danger' | 'info' | 'warning' =>
  r === 'success' ? 'success' : r === 'failed' ? 'danger' : r === 'cancelled' ? 'warning' : 'info'

// 时间显示（时区基本原则 2026-10-11 用户重申）：task_runs 由引擎按**配置时区**
// 写入无时区字符串（engineNowStr=CurrentLocation）——原样渲染即配置时区，禁止
// 再作任何时区换算。曾委托 formatDate（其把无时区串强制按 UTC 解析再转
// 配置时区），任务时间全部被 +8h 偏移（22:12→次日 06:12 实证）；formatDate 其余
// 消费方（audit/cert_jobs/nodes 等 UTC 存储族）不受影响、保持原样。
// 两族的边界与禁止面同时写在 utils/date.ts 的 formatDate 文档里（新增调用点先读那里）。
const fmtTime = (s?: string) => {
  if (!s) return ''
  return s.replace('T', ' ').replace(/\.\d+/g, '').replace(/Z$/, '')
}
const fmtDuration = (ms?: number) => {
  if (!ms || ms <= 0) return '—'
  if (ms < 1000) return `${ms}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.floor(ms / 60000)}m${Math.round((ms % 60000) / 1000)}s`
}
</script>

<style scoped>
.tm-root { display: flex; flex-direction: column; gap: 20px; max-width: 1500px; margin: 0 auto; width: 100%; }
.card-header { display: flex; justify-content: space-between; align-items: center; gap: 10px; }
.tm-category-filter { width: 150px; }
.tm-filter-group { display: flex; align-items: center; gap: 10px; margin-left: auto; }
.card-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: #111827; }
/* 卡片/横幅标题图标 16px——不得写裸 .title-icon（会压小全局 20px 页头图标，
   与 page-desc 缩进错位，同类事故见 SecurityOverview）；限定到本页容器内。 */
.card-title .title-icon, .tm-cq-banner-title .title-icon { font-size: 16px; color: #3b82f6; }

/* KPI 四卡 */
.tm-kpis { margin-bottom: 0; }
.tm-kpi { text-align: center; }
.tm-kpi :deep(.el-card__body) { padding: 18px 12px; }
.tm-kpi-num { font-size: 30px; font-weight: 800; color: #111827; line-height: 1.1; }
.tm-kpi-run { color: #3b82f6; }
.tm-kpi-bad { color: #f87171; }
.tm-kpi-label { font-size: 12.5px; color: #6b7280; margin-top: 6px; }

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
/* 操作列：单一 flex 行，禁用按钮 tooltip 的包裹节点不得是块级元素（否则“运行”独占一行）。
   gap 统一承担间距；显式清零 el-button 相邻 margin-left——tooltip 包裹 span 会打断
   Element Plus 的相邻按钮 margin 规则，导致“运行”与“重启”行间距不一致。 */
:deep(.tm-nowrap-table .tm-op-cell .cell) { display: flex; flex-wrap: nowrap; align-items: center; gap: 12px; }
:deep(.tm-nowrap-table .tm-op-cell .el-button) { margin-left: 0; }
.tm-op-trigger { display: inline-flex; align-items: center; }
.tm-task-name { font-weight: 500; }
.tm-status { display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px; }
.tm-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--tm-c, #9aa0b5); box-shadow: 0 0 6px var(--tm-c, transparent); }
.tm-status[data-status="running"] { --tm-c: #4f8cff; }
.tm-status[data-status="failed"] { --tm-c: #f87171; }
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
.tm-detail { display: flex; flex-direction: column; gap: 12px; }
.tm-detail > .dialog-panel + .dialog-panel { margin-top: 0; }
.tm-detail-descs :deep(.el-descriptions__label) { white-space: nowrap; }
.tm-detail-descs :deep(.el-descriptions__content .el-tag) { vertical-align: middle; margin-left: 4px; }
.tm-inline-flex { display: inline-flex; align-items: center; gap: 2px; }
.tm-detail-msg { font-size: 12.5px; color: var(--el-text-color-secondary); }

/* 日志 */
.tm-log-stats { display: flex; align-items: center; margin-bottom: 10px; }
.tm-log-container { max-height: 60vh; overflow: auto; background: #0f172a; border-radius: 0; padding: 12px; border: 1px solid #1e293b; }
.tm-log-content { margin: 0; color: #e2e8f0; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; font-size: 12px; line-height: 1.7; white-space: pre-wrap; }
</style>

