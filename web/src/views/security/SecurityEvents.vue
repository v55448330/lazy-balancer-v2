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
        <el-select v-model="filters.action" placeholder="动作" clearable style="width: 140px" @change="fetchEvents">
          <el-option label="全部" value="" />
          <el-option label="拦截" value="blocked" />
          <el-option label="检测" value="logged" />
        </el-select>
        <el-input v-model="filters.ip" placeholder="IP 地址" clearable style="width: 200px" @clear="fetchEvents" @keyup.enter="fetchEvents" />
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

      <div style="margin-top: 16px; display: flex; justify-content: flex-end;">
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
import { request } from '@/utils/api'
import { formatDate } from '@/utils/date'

interface APIResponse<T> { code: number; message: string; data: T }
interface SecurityEvent { id: number; event_time: string; rule_caddy_id: string; rule_name: string; policy_id: number; policy_name: string; client_ip: string; method: string; uri: string; event_type: string; rule_triggered: string; rule_msg: string; action: string; anomaly_score: number }

// 触发规则 family 映射：'2'/'3'/'4' 为 IP 访问控制拦截，'949110' 为异常评分评估拦截，其余为 CRS 规则 ID
const triggeredLabel = (row: SecurityEvent): string => {
  const t = row.rule_triggered
  if (!t) return '—'
  if (t === '2' || t === '3' || t === '4') return 'IP 访问控制'
  if (t === '949110') return '评估拦截'
  if (/^1\d{4}$/.test(t)) return '自定义规则'
  return t
}
const showTriggeredMsg = (row: SecurityEvent): boolean => {
  const t = row.rule_triggered
  return !!t && t !== '2' && t !== '3' && t !== '4' && t !== '949110' && !!row.rule_msg
}

const loading = ref(false)
const events = ref<SecurityEvent[]>([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)
const filters = ref({ action: '', ip: '' })

const handleSizeChange = () => { page.value = 1; fetchEvents() }

const goToRule = (row: SecurityEvent) => { localStorage.setItem('rules-search', row.rule_caddy_id); window.open('/?page=rules', '_blank') }
const goToPolicy = (row: SecurityEvent) => { localStorage.setItem('security-policies-search', row.policy_name); window.open('/?page=security-policies', '_blank') }

const fetchEvents = async () => {
  loading.value = true
  try { const p = new URLSearchParams({ page: String(page.value), page_size: String(pageSize.value) }); if (filters.value.action) p.set('action', filters.value.action); if (filters.value.ip) p.set('ip', filters.value.ip); const res = await request.get<APIResponse<{ events: SecurityEvent[]; total: number }>>(`/security/events?${p}`); events.value = res.data?.events || []; total.value = res.data?.total || 0 } catch { events.value = [] } finally { loading.value = false }
}
onMounted(fetchEvents)
</script>

<style scoped>
.table-toolbar { display: flex; gap: 12px; justify-content: flex-end; margin-bottom: 16px; }
.cell-tip { cursor: help; border-bottom: 1px dashed #c0c4cc; }
</style>
