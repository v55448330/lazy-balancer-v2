<template>
  <div class="p-6">
    <div class="flex items-center justify-between mb-4">
      <h2 class="text-xl font-semibold text-gray-800">安全策略</h2>
      <el-button v-if="!isReadOnly" type="primary" :icon="Plus" @click="openDialog()">新建策略</el-button>
    </div>

    <el-table :data="policies" v-loading="loading" stripe>
      <el-table-column prop="name" label="策略名称" min-width="120" />
      <el-table-column label="模式" width="100">
        <template #default="{ row }">
          <el-tag v-if="row.mode === 'blocking'" type="danger" size="small">拦截</el-tag>
          <el-tag v-else-if="row.mode === 'detection'" type="warning" size="small">检测</el-tag>
          <el-tag v-else type="info" size="small">关闭</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="rule_count" label="关联规则" width="90" align="center" />
      <el-table-column label="防护能力" min-width="200">
        <template #default="{ row }">
          <el-tag v-if="row.has_waf" size="small" class="mr-1">WAF</el-tag>
          <el-tag v-if="row.has_ip_control" size="small" type="success" class="mr-1">IP</el-tag>
          <el-tag v-if="row.has_rate_limit" size="small" type="warning">限流</el-tag>
          <span v-if="!row.has_waf && !row.has_ip_control && !row.has_rate_limit" class="text-gray-400">—</span>
        </template>
      </el-table-column>
      <el-table-column label="状态" width="80" align="center">
        <template #default="{ row }">
          <el-tag :type="row.enabled ? 'success' : 'info'" size="small">{{ row.enabled ? '启用' : '禁用' }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column v-if="!isReadOnly" label="操作" width="150" fixed="right">
        <template #default="{ row }">
          <el-button size="small" @click="openDialog(row)">编辑</el-button>
          <el-button size="small" type="danger" @click="handleDelete(row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog v-model="dialogVisible" :title="editingId ? '编辑策略' : '新建策略'" width="700px" @close="resetForm">
      <el-form :model="form" label-width="100px">
        <el-form-item label="名称" required>
          <el-input v-model="form.name" placeholder="策略名称" />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="form.description" placeholder="策略描述" />
        </el-form-item>
        <el-form-item label="WAF 模式">
          <el-radio-group v-model="form.mode">
            <el-radio value="off">关闭</el-radio>
            <el-radio value="detection">检测（仅记录）</el-radio>
            <el-radio value="blocking">拦截（阻断请求）</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="异常阈值" v-if="form.mode !== 'off'">
          <el-input-number v-model="form.anomaly_threshold" :min="1" :max="100" />
          <span class="ml-2 text-sm text-gray-500">越低越严格，CRS 默认 5</span>
        </el-form-item>

        <el-divider content-position="left">IP 访问控制</el-divider>
        <el-form-item label="白名单">
          <el-select v-model="ipWhitelist" multiple filterable allow-create default-first-option
            placeholder="输入 IP/CIDR 后回车" style="width: 100%" />
        </el-form-item>
        <el-form-item label="黑名单">
          <el-select v-model="ipBlacklist" multiple filterable allow-create default-first-option
            placeholder="输入 IP/CIDR 后回车" style="width: 100%" />
        </el-form-item>

        <el-divider content-position="left">限流</el-divider>
        <el-form-item label="启用限流">
          <el-switch v-model="form.rate_limit_enabled" />
        </el-form-item>
        <template v-if="form.rate_limit_enabled">
          <el-form-item label="每秒请求">
            <el-input-number v-model="form.rate_limit_rps" :min="1" />
            <span class="ml-2 text-sm text-gray-500">req/s</span>
          </el-form-item>
          <el-form-item label="突发大小">
            <el-input-number v-model="form.rate_limit_burst" :min="0" />
          </el-form-item>
        </template>

        <el-divider content-position="left">关联规则</el-divider>
        <el-form-item label="已关联">
          <el-select v-model="boundRules" multiple filterable placeholder="选择要关联的负载均衡规则" style="width: 100%">
            <el-option v-for="r in allRules" :key="r.caddy_id" :label="`${r.name} (${r.domain}:${r.listen_port})`" :value="r.caddy_id" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="handleSave">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { Plus } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { request } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'

interface APIResponse<T> { code: number; message: string; data: T }
interface PolicySummary {
  id: number; name: string; mode: string; enabled: boolean; rule_count: number
  has_waf: boolean; has_ip_control: boolean; has_rate_limit: boolean
}
interface PolicyDetail {
  id: number; name: string; description: string; mode: string; anomaly_threshold: number
  ip_whitelist: string; ip_blacklist: string; rate_limit_enabled: boolean
  rate_limit_rps: number; rate_limit_burst: number; crs_rule_groups: string
  custom_rules: string; enabled: boolean
}
interface Rule { caddy_id: string; name: string; domain: string; listen_port: number }

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.user?.role !== 'admin')

const loading = ref(false)
const saving = ref(false)
const policies = ref<PolicySummary[]>([])
const allRules = ref<Rule[]>([])
const dialogVisible = ref(false)
const editingId = ref<number | null>(null)
const ipWhitelist = ref<string[]>([])
const ipBlacklist = ref<string[]>([])
const boundRules = ref<string[]>([])

const form = ref({
  name: '', description: '', mode: 'off', anomaly_threshold: 5,
  rate_limit_enabled: false, rate_limit_rps: 100, rate_limit_burst: 50,
})

const fetchData = async () => {
  loading.value = true
  try {
    const [polRes, ruleRes] = await Promise.all([
      request.get<APIResponse<PolicySummary[]>>('/security/policies'),
      request.get<APIResponse<Rule[]>>('/rules'),
    ])
    policies.value = polRes.data || []
    allRules.value = ruleRes.data || []
  } catch { ElMessage.error('加载数据失败') } finally { loading.value = false }
}

const openDialog = async (row?: PolicySummary) => {
  editingId.value = row?.id ?? null
  if (row) {
    try {
      const res = await request.get<APIResponse<{ policy: PolicyDetail; bindings: string[] }>>(`/security/policies/${row.id}`)
      const detail = res.data.policy
      form.value = {
        name: detail.name, description: detail.description, mode: detail.mode,
        anomaly_threshold: detail.anomaly_threshold, rate_limit_enabled: detail.rate_limit_enabled,
        rate_limit_rps: detail.rate_limit_rps, rate_limit_burst: detail.rate_limit_burst,
      }
      ipWhitelist.value = JSON.parse(detail.ip_whitelist || '[]')
      ipBlacklist.value = JSON.parse(detail.ip_blacklist || '[]')
      boundRules.value = res.data.bindings || []
    } catch { ElMessage.error('加载策略详情失败') }
  } else {
    resetForm()
  }
  dialogVisible.value = true
}

const resetForm = () => {
  form.value = { name: '', description: '', mode: 'off', anomaly_threshold: 5, rate_limit_enabled: false, rate_limit_rps: 100, rate_limit_burst: 50 }
  ipWhitelist.value = []
  ipBlacklist.value = []
  boundRules.value = []
  editingId.value = null
}

const handleSave = async () => {
  if (!form.value.name.trim()) { ElMessage.warning('请输入策略名称'); return }
  saving.value = true
  try {
    const payload = { ...form.value, ip_whitelist: JSON.stringify(ipWhitelist.value), ip_blacklist: JSON.stringify(ipBlacklist.value) }
    if (editingId.value) {
      await request.put(`/security/policies/${editingId.value}`, payload)
    } else {
      const res = await request.post<APIResponse<{ id: number }>>('/security/policies', payload)
      editingId.value = res.data.id
    }
    for (const caddyId of boundRules.value) {
      await request.post(`/security/policies/${editingId.value}/bind`, { rule_caddy_id: caddyId })
    }
    ElMessage.success('保存成功')
    dialogVisible.value = false
    fetchData()
  } catch { ElMessage.error('保存失败') } finally { saving.value = false }
}

const handleDelete = (row: PolicySummary) => {
  ElMessageBox.confirm(`确定删除策略"${row.name}"？`, '确认', { type: 'warning' })
    .then(async () => {
      await request.delete(`/security/policies/${row.id}`)
      ElMessage.success('已删除')
      fetchData()
    }).catch(() => {})
}

onMounted(fetchData)
</script>
