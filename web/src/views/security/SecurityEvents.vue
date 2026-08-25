<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Warning /></el-icon>
          事件日志
        </h2>
        <p class="page-desc">查看 WAF 拦截和检测的安全事件记录</p>
      </div>
      <el-button :icon="Refresh" @click="fetchEvents">刷新</el-button>
    </div>

    <el-card>
      <div class="table-toolbar">
        <el-date-picker
          v-model="filters.timeRange"
          type="datetimerange"
          range-separator="至"
          start-placeholder="开始时间"
          end-placeholder="结束时间"
          format="YYYY-MM-DD HH:mm:ss"
          value-format="YYYY-MM-DD HH:mm:ss"
          :default-time="[new Date(2000, 0, 1, 0, 0, 0), new Date(2000, 0, 1, 23, 59, 59)]"
          class="filter-date-range"
        />
        <el-select v-model="filters.action" placeholder="动作" clearable style="width: 120px">
          <el-option label="拦截" value="blocked" />
          <el-option label="检测" value="logged" />
        </el-select>
        <!-- R72 十九次（用户需求）：规则 ID 筛选替换为三列（负载规则/触发规则/策略）
             服务端筛选（rule_name/rule_triggered/policy_name LIKE）。 -->
        <el-input v-model="filters.rule_name" placeholder="负载规则" clearable style="width: 140px" @keyup.enter="applyFilters" />
        <!-- R72 二十次：触发规则改下拉+可输入——选项即表格显示的 family 标签（后端
             映射为 ID 前缀匹配）；也可直接输入 CRS 规则 ID（如 942100）或消息关键词。 -->
        <el-select v-model="filters.rule_triggered" placeholder="触发规则" clearable filterable allow-create style="width: 140px">
          <el-option label="IP 访问控制" value="IP 访问控制" />
          <el-option label="请求阻断评估" value="请求阻断评估" />
          <el-option label="协议异常" value="协议异常" />
          <el-option label="协议攻击" value="协议攻击" />
          <el-option label="自定义规则" value="自定义规则" />
        </el-select>
        <el-input v-model="filters.policy_name" placeholder="策略" clearable style="width: 120px" @keyup.enter="applyFilters" />
        <el-input v-model="filters.ip" placeholder="IP 地址" clearable style="width: 150px" @keyup.enter="applyFilters" />
        <el-input v-model="filters.uri" placeholder="URI" clearable style="width: 160px" @keyup.enter="applyFilters" />
        <div class="filter-actions">
          <el-button type="primary" @click="applyFilters">筛选</el-button>
          <el-button @click="resetFilters">重置</el-button>
        </div>
      </div>

      <el-table :data="events" v-loading="loading" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="">
        <template #empty><el-empty description="暂无安全事件" :image-size="60" /></template>
        <el-table-column prop="event_time" label="时间" width="170" :formatter="(row: SecurityEvent) => formatDate(row.event_time)" />
        <el-table-column label="动作" width="90" align="center">
          <template #default="{ row }">
            <el-tag :type="row.action === 'blocked' ? 'danger' : 'warning'" size="small" effect="light">{{ row.action === 'blocked' ? '拦截' : '检测' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="规则" min-width="140">
          <template #default="{ row }">
            <el-link v-if="row.rule_name || row.rule_caddy_id" type="primary" @click="goToRule(row)">{{ row.rule_name || row.rule_caddy_id || '—' }}</el-link>
            <span v-else>—</span>
          </template>
        </el-table-column>
        <el-table-column label="触发规则" min-width="120">
          <template #default="{ row }">
            <el-tooltip v-if="showTriggeredMsg(row)" :content="row.rule_msg" placement="top" :show-after="200">
              <span class="cell-tip">{{ triggeredLabel(row) }}</span>
            </el-tooltip>
            <span v-else>{{ triggeredLabel(row) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="策略" min-width="140">
          <template #default="{ row }">
            <el-link v-if="row.policy_name || row.policy_id > 0" type="primary" @click="goToPolicy(row)">{{ row.policy_name || row.policy_id }}</el-link>
            <span v-else>—</span>
          </template>
        </el-table-column>
        <el-table-column prop="client_ip" label="客户端 IP" width="140" />
        <el-table-column prop="method" label="方法" width="70" align="center" />
        <el-table-column prop="uri" label="URI" min-width="220" show-overflow-tooltip />
      </el-table>

      <div style="margin-top: 16px; display: flex; align-items: center;">
        <LogStorageBar log-key="security_events" style="margin-right: auto" />
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="pageSize"
          :total="total"
          :page-sizes="[20, 50, 100]"
          layout="total, sizes, prev, pager, next"
          @size-change="handleSizeChange"
          @current-change="fetchEvents"
        />
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { Refresh, Warning } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { request } from '@/utils/api'
import LogStorageBar from '@/components/LogStorageBar.vue'
import { formatDate } from '@/utils/date'
import type { APIResponse } from '@/types'

interface SecurityEvent { id: number; event_time: string; rule_caddy_id: string; rule_name: string; policy_id: number; policy_name: string; client_ip: string; method: string; uri: string; event_type: string; rule_triggered: string; rule_msg: string; action: string; anomaly_score: number }

// 触发规则 family 映射：'2'/'3'/'4'/'5' 为 IP 访问控制拦截，949 为异常评分评估拦截，920/921 为协议异常/攻击，其余为 CRS 规则 ID
const triggeredLabel = (row: SecurityEvent): string => {
  const t = row.rule_triggered
  if (!t) return '—'
  if (t === '2' || t === '3' || t === '4' || t === '5') return 'IP 访问控制'
  if (/^949/.test(t)) return '请求阻断评估'
  if (/^920/.test(t)) return '协议异常'
  if (/^921/.test(t)) return '协议攻击'
  if (/^1\d{4}$/.test(t)) return '自定义规则'
  return t
}
const showTriggeredMsg = (row: SecurityEvent): boolean => {
  const t = row.rule_triggered
  return !!t && t !== '2' && t !== '3' && t !== '4' && t !== '5' && !/^949/.test(t) && !!row.rule_msg
}

const loading = ref(false)
const events = ref<SecurityEvent[]>([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)
const filters = ref({ action: '', ip: '', uri: '', rule_name: '', rule_triggered: '', policy_name: '', rule_caddy_id: '', timeRange: null as [string, string] | null })

const applyFilters = () => {
  // 时间区间校验：开始晚于结束时提示并清除该筛选（后端同样兜底 400）。
  // value-format 为 YYYY-MM-DD HH:mm:ss，字符串比较即时间先后比较。
  const range = filters.value.timeRange
  if (range?.[0] && range?.[1] && range[0] > range[1]) {
    ElMessage.warning('开始时间不能晚于结束时间')
    filters.value.timeRange = null
  }
  page.value = 1
  fetchEvents()
}

const resetFilters = () => {
  filters.value = { action: '', ip: '', uri: '', rule_name: '', rule_triggered: '', policy_name: '', rule_caddy_id: '', timeRange: null }
  page.value = 1
  fetchEvents()
}

const handleSizeChange = () => { page.value = 1; fetchEvents() }

const goToRule = (row: SecurityEvent) => { localStorage.setItem('rules-search', row.rule_caddy_id); window.open('/?page=rules', '_blank') }
const goToPolicy = (row: SecurityEvent) => {
  if (row.policy_id > 0) {
    localStorage.setItem('security-policies-focus-id', String(row.policy_id))
  } else if (row.policy_name) {
    localStorage.setItem('security-policies-search', row.policy_name)
  } else {
    return
  }
  window.open('/?page=security-policies', '_blank')
}

let fetchEventsSeq = 0
const fetchEvents = async () => {
  // 乱序响应守卫：只有最新一次请求的响应才允许写入列表，避免旧响应覆盖新页
  const requestSeq = ++fetchEventsSeq
  loading.value = true
  try {
    const p = new URLSearchParams({ page: String(page.value), page_size: String(pageSize.value) })
    if (filters.value.action) p.set('action', filters.value.action)
    if (filters.value.ip) p.set('ip', filters.value.ip)
    if (filters.value.rule_caddy_id) p.set('rule_caddy_id', filters.value.rule_caddy_id)
    if (filters.value.rule_name) p.set('rule_name', filters.value.rule_name)
    if (filters.value.rule_triggered) p.set('rule_triggered', filters.value.rule_triggered)
    if (filters.value.policy_name) p.set('policy_name', filters.value.policy_name)
    if (filters.value.uri) p.set('uri', filters.value.uri)
    if (filters.value.timeRange?.[0]) p.set('start_time', filters.value.timeRange[0])
    if (filters.value.timeRange?.[1]) p.set('end_time', filters.value.timeRange[1])
    const res = await request.get<APIResponse<{ events: SecurityEvent[]; total: number }>>(`/security/events?${p}`)
    if (requestSeq !== fetchEventsSeq) return
    events.value = res.data?.events || []
    total.value = res.data?.total || 0
  } catch {
    // R68 D-N5：瞬态失败保留末次成功数据（对齐 AuditLog 口径）——此前清空列表
    // 却保留陈旧 total，空态文案「暂无安全事件」在排障窗口内误导为「无攻击」。
    // 全局拦截器已弹失败 toast。
  } finally {
    if (requestSeq === fetchEventsSeq) loading.value = false
  }
}
onMounted(fetchEvents)
</script>

<style scoped>
.table-toolbar { display: flex; flex-wrap: wrap; gap: 8px; justify-content: flex-start; margin-bottom: 16px; align-items: center; }
.filter-actions { display: flex; gap: 0; margin-left: 8px; }
.filter-actions .el-button + .el-button { margin-left: 8px; }
.cell-tip { cursor: help; border-bottom: 1px dashed #c0c4cc; }
</style>

<style>
.filter-date-range.el-date-editor {
  --el-date-editor-width: 360px;
  width: 360px;
  flex: 0 0 auto;
}
</style>
