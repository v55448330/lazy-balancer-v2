<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Lock /></el-icon>
          安全策略
        </h2>
        <p class="page-desc">管理 WAF 防火墙、IP 访问控制和限流策略</p>
      </div>
      <el-button v-if="!isReadOnly" type="primary" :disabled="loading" @click="openDialog()">
        <el-icon><Plus /></el-icon>
        新建策略
      </el-button>
    </div>

    <el-card>
      <el-table :data="policies" v-loading="loading" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="">
        <template #empty>
          <el-empty description="暂无安全策略" :image-size="60" />
        </template>
        <el-table-column prop="name" label="策略名称" min-width="140">
          <template #default="{ row }">
            <el-link type="primary" @click="openDialog(row)">{{ row.name }}</el-link>
          </template>
        </el-table-column>
        <el-table-column label="模式" width="100" align="center">
          <template #default="{ row }">
            <el-tag v-if="row.mode === 'blocking'" type="danger" size="small" effect="light">拦截</el-tag>
            <el-tag v-else-if="row.mode === 'detection'" type="warning" size="small" effect="light">检测</el-tag>
            <el-tag v-else type="info" size="small" effect="plain">关闭</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="rule_count" label="关联规则" width="100" align="center" />
        <el-table-column label="防护能力" min-width="220">
          <template #default="{ row }">
            <el-tag v-if="row.has_waf" size="small" effect="plain" class="mr-1">WAF</el-tag>
            <el-tag v-if="row.has_ip_control" size="small" type="success" effect="plain" class="mr-1">IP 控制</el-tag>
            <el-tag v-if="row.has_rate_limit" size="small" type="warning" effect="plain">限流</el-tag>
            <span v-if="!row.has_waf && !row.has_ip_control && !row.has_rate_limit" class="text-secondary">—</span>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="90" align="center">
          <template #default="{ row }">
            <el-tag :type="row.enabled ? 'success' : 'info'" size="small" effect="light">{{ row.enabled ? '启用' : '禁用' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column v-if="!isReadOnly" label="操作" width="160" fixed="right">
          <template #default="{ row }">
            <el-button size="small" link type="primary" @click="openDialog(row)">编辑</el-button>
            <el-button size="small" link type="danger" @click="handleDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="dialogVisible" :title="editingId ? '编辑策略' : '新建策略'" width="760px">
      <el-form :model="form" label-width="100px" label-position="right">
        <el-form-item label="名称" required>
          <el-input v-model="form.name" placeholder="策略名称" />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="form.description" placeholder="策略描述" />
        </el-form-item>

        <el-divider content-position="left">WAF 防火墙</el-divider>
        <el-form-item label="WAF 模式">
          <el-radio-group v-model="form.mode">
            <el-radio value="off">关闭</el-radio>
            <el-radio value="detection">检测（仅记录）</el-radio>
            <el-radio value="blocking">拦截（阻断请求）</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="form.mode !== 'off'" label="异常阈值">
          <el-input-number v-model="form.anomaly_threshold" :min="1" :max="100" />
          <span class="ml-2 text-secondary">越低越严格，CRS 默认 5</span>
        </el-form-item>

        <el-divider content-position="left">IP 访问控制</el-divider>
        <el-form-item label="启用">
          <el-switch v-model="form.ip_acl_enabled" />
        </el-form-item>
        <template v-if="form.ip_acl_enabled">
          <el-form-item label="控制模式">
            <el-radio-group v-model="form.ip_acl_mode">
              <el-radio value="allow">白名单（仅允许列表中的 IP）</el-radio>
              <el-radio value="deny">黑名单（拒绝列表中的 IP）</el-radio>
            </el-radio-group>
          </el-form-item>
          <el-form-item :label="form.ip_acl_mode === 'allow' ? '允许 IP' : '拒绝 IP'">
            <el-select v-model="ipACLList" multiple filterable allow-create default-first-option placeholder="输入 IP/CIDR 后回车" style="width: 100%" />
            <div class="text-secondary">{{ form.ip_acl_mode === 'allow' ? '列表中的 IP 将被允许，其他 IP 一律拒绝' : '列表中的 IP 将被拒绝，其他 IP 一律允许' }}</div>
          </el-form-item>
        </template>

        <el-divider content-position="left">限流</el-divider>
        <el-form-item label="启用">
          <el-switch v-model="form.rate_limit_enabled" />
        </el-form-item>
        <template v-if="form.rate_limit_enabled">
          <el-form-item label="每秒请求">
            <el-input-number v-model="form.rate_limit_rps" :min="1" style="width: 180px" />
            <el-text class="ml-2 text-secondary">次/秒</el-text>
          </el-form-item>
          <el-form-item label="突发大小">
            <el-input-number v-model="form.rate_limit_burst" :min="0" style="width: 180px" />
            <el-text class="ml-2 text-secondary">次，超过突发量后按限流速率为发送返回 429</el-text>
          </el-form-item>
        </template>

        <el-divider content-position="left">CRS 规则排除</el-divider>
        <el-form-item label="排除规则">
          <el-select v-model="crsExcludedRules" multiple filterable placeholder="搜索并选择要排除的规则" style="width: 100%">
            <el-option-group label="OWASP CRS 规则">
              <el-option v-for="rule in crsRuleOptions" :key="rule.filename" :label="`${rule.filename} (${rule.category})`" :value="rule.filename" />
            </el-option-group>
            <el-option-group label="自定义规则" v-if="customRuleOptions.length > 0">
              <el-option v-for="rule in customRuleOptions" :key="rule.name" :label="rule.name" :value="rule.name" />
            </el-option-group>
          </el-select>
          <div class="text-secondary">排除的规则不会被检测或拦截</div>
        </el-form-item>

        <el-divider content-position="left">自定义规则选择</el-divider>
        <el-form-item label="已选规则">
          <el-select v-model="selectedCustomRules" multiple filterable placeholder="选择要包含的自定义规则" style="width: 100%">
            <el-option v-for="rule in allCustomRules" :key="rule.id" :label="rule.name" :value="rule.id" />
          </el-select>
          <div class="text-secondary">自定义规则在"规则集"页面创建，此处仅选择使用哪些</div>
        </el-form-item>

        <el-divider content-position="left">拦截页面</el-divider>
        <el-form-item label="拦截页面">
          <el-select v-model="form.block_page_id" placeholder="选择拦截页面" style="width: 100%">
            <el-option label="默认页面" :value="0" />
            <el-option v-for="p in blockPages" :key="p.id" :label="p.name" :value="p.id" />
          </el-select>
          <div v-if="blockPages.length === 0" class="text-secondary mt-1">
            暂无拦截页面，<el-link type="primary" @click="goBlockPages">去创建</el-link>
          </div>
        </el-form-item>

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
import { Plus, Lock } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { request } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'

interface APIResponse<T> { code: number; message: string; data: T }
interface PolicySummary { id: number; name: string; mode: string; enabled: boolean; rule_count: number; has_waf: boolean; has_ip_control: boolean; has_rate_limit: boolean }
interface PolicyDetail { id: number; name: string; description: string; mode: string; anomaly_threshold: number; ip_acl_mode: string; ip_acl_list: string; ip_acl_enabled: boolean; ip_whitelist: string; ip_blacklist: string; rate_limit_enabled: boolean; rate_limit_rps: number; rate_limit_burst: number; crs_rule_groups: string; crs_excluded_rules: string; custom_rules: string; block_page_id: number; enabled: boolean }
interface Rule { caddy_id: string; name: string; domain: string; listen_port: number }
interface CRSRuleOption { filename: string; category: string }
interface BlockPage { id: number; name: string }

const blockPages = ref<BlockPage[]>([])

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.user?.role !== 'admin')

const crsRuleOptions = ref<CRSRuleOption[]>([])
const customRuleOptions = ref<Array<{ name: string }>>([])
const loading = ref(false)
const saving = ref(false)
const policies = ref<PolicySummary[]>([])
const allRules = ref<Rule[]>([])
const dialogVisible = ref(false)
const editingId = ref<number | null>(null)
const ipACLList = ref<string[]>([])
const crsExcludedRules = ref<string[]>([])
const boundRules = ref<string[]>([])

const form = ref({ name: '', description: '', mode: 'off', anomaly_threshold: 5, ip_acl_enabled: false, ip_acl_mode: 'allow', rate_limit_enabled: false, rate_limit_rps: 100, rate_limit_burst: 50, block_page_id: 0 })
const selectedCustomRules = ref<number[]>([])
const allCustomRules = ref<Array<{ id: number; name: string }>>([])

const fetchData = async () => {
  loading.value = true
  try {
    const [polRes, ruleRes, crsRes, bpRes, crRes] = await Promise.all([
      request.get<APIResponse<PolicySummary[]>>('/security/policies'),
      request.get<APIResponse<Rule[]>>('/rules'),
      request.get<APIResponse<{ rules: CRSRuleOption[] }>>('/security/crs/rules?page_size=100'),
      request.get<APIResponse<BlockPage[]>>('/security/block-pages'),
      request.get<APIResponse<Array<{ id: number; name: string }>>>('/security/custom-rules'),
    ])
    policies.value = polRes.data || []
    allRules.value = ruleRes.data || []
    crsRuleOptions.value = crsRes.data?.rules || []
    blockPages.value = bpRes.data || []
    allCustomRules.value = crRes.data || []
  } catch { ElMessage.error('加载数据失败') } finally { loading.value = false }
}

async function openDialog(row?: PolicySummary) {
  editingId.value = row?.id ?? null
  if (row) {
    try {
      const res = await request.get<APIResponse<{ policy: PolicyDetail; bindings: string[] }>>(`/security/policies/${row.id}`)
      const d = res.data.policy
      form.value = { name: d.name, description: d.description, mode: d.mode, anomaly_threshold: d.anomaly_threshold, ip_acl_enabled: d.ip_acl_enabled, ip_acl_mode: d.ip_acl_mode || 'allow', rate_limit_enabled: d.rate_limit_enabled, rate_limit_rps: d.rate_limit_rps, rate_limit_burst: d.rate_limit_burst, block_page_id: d.block_page_id || 0 }
      ipACLList.value = JSON.parse(d.ip_acl_list || '[]')
      crsExcludedRules.value = JSON.parse(d.crs_excluded_rules || '[]')
      selectedCustomRules.value = JSON.parse(d.custom_rules || '[]').map((r: any) => typeof r === 'number' ? r : r.id || 0).filter((id: number) => id > 0)
      boundRules.value = res.data.bindings || []
    } catch { ElMessage.error('加载策略详情失败') }
  } else { resetForm() }
  dialogVisible.value = true
}

const resetForm = () => {
  form.value = { name: '', description: '', mode: 'off', anomaly_threshold: 5, ip_acl_enabled: false, ip_acl_mode: 'allow', rate_limit_enabled: false, rate_limit_rps: 100, rate_limit_burst: 50, block_page_id: 0 }
  ipACLList.value = []; crsExcludedRules.value = []; selectedCustomRules.value = []; boundRules.value = []; editingId.value = null
}

const handleSave = async () => {
  if (!form.value.name.trim()) { ElMessage.warning('请输入策略名称'); return }
  saving.value = true
  try {
    const payload = { ...form.value, ip_acl_list: JSON.stringify(ipACLList.value), crs_excluded_rules: JSON.stringify(crsExcludedRules.value), custom_rules: JSON.stringify(selectedCustomRules.value) }
    if (editingId.value) {
      await request.put(`/security/policies/${editingId.value}`, payload)
    } else {
      const res = await request.post<APIResponse<{ id: number }>>('/security/policies', payload)
      editingId.value = res.data.id
    }
    for (const caddyId of boundRules.value) { await request.post(`/security/policies/${editingId.value}/bind`, { rule_caddy_id: caddyId }) }
    ElMessage.success('保存成功'); dialogVisible.value = false; fetchData()
  } catch { ElMessage.error('保存失败') } finally { saving.value = false }
}

function handleDelete(row: PolicySummary) {
  ElMessageBox.confirm(`确定删除策略"${row.name}"？`, '确认', { type: 'warning' })
    .then(async () => { await request.delete(`/security/policies/${row.id}`); ElMessage.success('已删除'); fetchData() }).catch(() => {})
}

const goBlockPages = () => { useAuthStore().setCurrentPage('security-block-pages') }

onMounted(fetchData)
</script>

<style scoped>
.custom-rule-row { display: flex; gap: 6px; margin-bottom: 6px; align-items: center; flex-wrap: wrap; }
</style>
