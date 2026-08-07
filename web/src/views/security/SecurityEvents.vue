<template>
  <div class="p-6">
    <h2 class="text-xl font-semibold text-gray-800 mb-4">事件日志</h2>

    <div class="flex gap-3 mb-4">
      <el-select v-model="filters.action" placeholder="动作" clearable style="width: 120px" @change="fetchEvents">
        <el-option label="全部" value="" />
        <el-option label="拦截" value="blocked" />
        <el-option label="检测" value="logged" />
      </el-select>
      <el-input v-model="filters.ip" placeholder="IP 地址" clearable style="width: 160px" @clear="fetchEvents" @keyup.enter="fetchEvents" />
      <el-button :icon="Refresh" @click="fetchEvents">刷新</el-button>
    </div>

    <el-table :data="events" v-loading="loading" stripe>
      <el-table-column prop="event_time" label="时间" width="160" />
      <el-table-column label="动作" width="80">
        <template #default="{ row }">
          <el-tag :type="row.action === 'blocked' ? 'danger' : 'warning'" size="small">
            {{ row.action === 'blocked' ? '拦截' : '检测' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="rule_triggered" label="规则" width="120" />
      <el-table-column prop="rule_msg" label="描述" min-width="180" show-overflow-tooltip />
      <el-table-column prop="client_ip" label="客户端 IP" width="130" />
      <el-table-column prop="method" label="方法" width="70" />
      <el-table-column prop="uri" label="URI" min-width="200" show-overflow-tooltip />
    </el-table>

    <div class="flex justify-center mt-4">
      <el-pagination
        v-model:current-page="page"
        :page-size="pageSize"
        :total="total"
        layout="prev, pager, next, total"
        @current-change="fetchEvents"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { Refresh } from '@element-plus/icons-vue'
import { request } from '@/utils/api'

interface APIResponse<T> { code: number; message: string; data: T }
interface SecurityEvent {
  id: number; event_time: string; rule_caddy_id: string; policy_id: number
  client_ip: string; method: string; uri: string; event_type: string
  rule_triggered: string; rule_msg: string; action: string; anomaly_score: number
}

const loading = ref(false)
const events = ref<SecurityEvent[]>([])
const page = ref(1)
const pageSize = 20
const total = ref(0)
const filters = ref({ action: '', ip: '' })

const fetchEvents = async () => {
  loading.value = true
  try {
    const params = new URLSearchParams({ page: String(page.value), page_size: String(pageSize) })
    if (filters.value.action) params.set('action', filters.value.action)
    if (filters.value.ip) params.set('ip', filters.value.ip)
    const res = await request.get<APIResponse<{ events: SecurityEvent[]; total: number }>>(`/security/events?${params}`)
    events.value = res.data?.events || []
    total.value = res.data?.total || 0
  } catch { events.value = [] } finally { loading.value = false }
}

onMounted(fetchEvents)
</script>
