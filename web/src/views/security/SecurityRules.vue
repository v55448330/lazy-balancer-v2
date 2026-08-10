<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Notebook /></el-icon>
          规则集
        </h2>
        <p class="page-desc">浏览 OWASP CRS 规则和管理自定义规则</p>
      </div>
    </div>

    <el-card class="mb-5">
      <template #header>
        <div class="flex items-center justify-between w-full">
          <div class="flex items-center gap-3">
            <span class="font-medium">OWASP CRS</span>
            <el-tag type="success" size="small" effect="light">{{ crsInfo.version || '—' }}</el-tag>
            <el-tag v-if="crsInfo.is_latest" type="info" size="small" effect="plain">已最新</el-tag>
          </div>
        </div>
      </template>
      <el-descriptions :column="3" border>
        <el-descriptions-item label="版本">{{ crsInfo.version || '—' }}</el-descriptions-item>
        <el-descriptions-item label="规则文件数">{{ total }}</el-descriptions-item>
        <el-descriptions-item label="更新时间">{{ crsInfo.updated_at || '—' }}</el-descriptions-item>
        <el-descriptions-item label="自动更新">
          <el-switch v-model="crsInfo.auto_update" :disabled="isReadOnly" @change="toggleAutoUpdate" />
        </el-descriptions-item>
        <el-descriptions-item label="更新状态">{{ crsInfo.update_status || '—' }}</el-descriptions-item>
      </el-descriptions>
    </el-card>

    <el-card>
      <el-tabs v-model="activeTab">
        <el-tab-pane label="CRS 规则浏览" name="rules">
          <div class="table-toolbar">
            <el-input v-model="searchQuery" placeholder="搜索规则文件名或分类" clearable :prefix-icon="Search" class="search-input" @clear="fetchRules" @keyup.enter="fetchRules" />
          </div>
          <el-table :data="rules" v-loading="loadingRules" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="" @row-click="openRuleContent" style="cursor: pointer">
            <template #empty><el-empty description="暂无规则文件" :image-size="60" /></template>
            <el-table-column prop="filename" label="文件名" min-width="320" show-overflow-tooltip />
            <el-table-column prop="category" label="分类" width="160">
              <template #default="{ row }"><el-tag size="small" effect="plain" type="info">{{ row.category }}</el-tag></template>
            </el-table-column>
            <el-table-column label="大小" width="100" align="right">
              <template #default="{ row }">{{ formatSize(row.size) }}</template>
            </el-table-column>
            <el-table-column label="" width="80" align="center">
              <template #default><el-button link type="primary" size="small">查看</el-button></template>
            </el-table-column>
          </el-table>
          <div class="flex justify-center mt-4">
          <div class="rules-pagination">
            <el-pagination v-model:current-page="page" :page-size="pageSize" :total="total" layout="total, sizes, prev, pager, next" @current-change="fetchRules" />
          </div>
          </div>
        </el-tab-pane>
        <el-tab-pane label="CRS 配置" name="setup">
          <el-card v-loading="loadingSetup">
            <template #header><div class="flex items-center justify-between"><span class="font-medium">crs-setup.conf</span><el-button link type="primary" size="small" @click="fetchSetup">刷新</el-button></div></template>
            <el-input type="textarea" :model-value="setupContent" readonly :rows="25" style="font-family: monospace; font-size: 12px" />
          </el-card>
        </el-tab-pane>
        <el-tab-pane label="自定义规则" name="custom">
            <div class="table-toolbar">
              <el-button v-if="!isReadOnly" type="primary" :icon="Plus" @click="openRuleDialog()">新建规则</el-button>
            </div>
            <el-table :data="customRules" v-loading="loadingCustom" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="">
            <template #empty><el-empty description="暂无自定义规则" :image-size="60" /></template>
            <el-table-column prop="name" label="规则名称" min-width="150">
              <template #default="{ row }">
                <el-link v-if="!isReadOnly" type="primary" @click="openRuleDialog(row)">{{ row.name }}</el-link>
                <span v-else>{{ row.name }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="description" label="描述" min-width="200" show-overflow-tooltip />
            <el-table-column label="条件" min-width="250">
              <template #default="{ row }">
                <el-tag v-for="(cond, i) in row.conditions" :key="i" size="small" effect="plain" class="mr-1">{{ cond.target }} {{ cond.operator }} {{ cond.pattern }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="动作" width="80" align="center">
              <template #default="{ row }">
                <el-tag :type="row.action === 'block' ? 'danger' : 'warning'" size="small" effect="light">{{ row.action === 'block' ? '拦截' : '记录' }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="状态" width="80" align="center">
              <template #default="{ row }">
                <el-tag :type="row.enabled ? 'success' : 'info'" size="small" effect="light">{{ row.enabled ? '启用' : '禁用' }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column v-if="!isReadOnly" label="操作" width="140" fixed="right">
              <template #default="{ row }">
                <el-button size="small" link type="primary" @click="openRuleDialog(row)">编辑</el-button>
                <el-button size="small" link type="danger" @click="deleteCustomRule(row)">删除</el-button>
            </template>
            </el-table-column>
          </el-table>
          <div class="rules-pagination">
            <el-pagination v-model:current-page="customPage" :page-size="customPageSize" :total="customRules.length" layout="total, sizes, prev, pager, next" />
          </div>
        </el-tab-pane>
      </el-tabs>
    </el-card>

    <el-dialog v-model="contentDialogVisible" :title="currentFilename" width="900px" top="5vh">
      <div v-loading="loadingContent"><pre class="crs-content">{{ currentContent }}</pre></div>
    </el-dialog>

    <el-dialog v-model="ruleDialogVisible" :title="editingRuleId ? '编辑自定义规则' : '新建自定义规则'" width="760px">
      <el-form :model="ruleForm" label-width="80px" label-position="right">
        <el-form-item label="名称" required>
          <el-input v-model="ruleForm.name" placeholder="规则名称" />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="ruleForm.description" placeholder="规则描述" />
        </el-form-item>
        <el-form-item label="条件">
          <div style="width: 100%">
            <div v-for="(cond, idx) in ruleForm.conditions" :key="idx" class="rule-condition-row">
              <el-select v-model="cond.target" style="width: 110px" size="small">
                <el-option label="URI" value="uri" />
                <el-option label="参数" value="args" />
                <el-option label="请求体" value="body" />
                <el-option label="请求头" value="headers" />
                <el-option label="User-Agent" value="user_agent" />
              </el-select>
              <el-select v-model="cond.operator" style="width: 100px" size="small">
                <el-option label="包含" value="contains" />
                <el-option label="正则" value="regex" />
                <el-option label="精确" value="equals" />
                <el-option label="前缀" value="starts_with" />
              </el-select>
              <el-input v-model="cond.pattern" :placeholder="cond.operator === 'regex' ? '如 /admin/.* 或 /api/v[0-9]+/' : '匹配值'" style="flex: 1" size="small" :class="{ 'is-error': cond.operator === 'regex' && !isValidRegex(cond.pattern) }" />
              <el-icon v-if="cond.operator === 'regex' && !isValidRegex(cond.pattern)" class="regex-error-icon"><WarningFilled /></el-icon>
              <el-button link type="danger" size="small" @click="ruleForm.conditions.splice(idx, 1)">删除</el-button>
            </div>
            <el-button size="small" type="primary" plain @click="ruleForm.conditions.push({ target: 'uri', operator: 'contains', pattern: '' })">
              + 添加条件
            </el-button>
          </div>
        </el-form-item>
        <el-form-item label="动作">
          <el-radio-group v-model="ruleForm.action">
            <el-radio value="block">拦截</el-radio>
            <el-radio value="log">仅记录</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="ruleForm.action === 'block'" label="状态码">
          <el-input-number v-model="ruleForm.status_code" :min="400" :max="599" style="width: 200px" />
          <div class="text-secondary">拦截时返回给客户端的 HTTP 状态码，常用 403 Forbidden</div>
        </el-form-item>
        <el-form-item label="异常分值">
          <el-input-number v-model="ruleForm.score" :min="1" :max="100" style="width: 200px" />
          <div class="text-secondary">匹配此规则时增加的异常分数，达到策略阈值后触发拦截，常用 5（默认级别）</div>
        </el-form-item>
        <el-form-item label="启用">
          <el-switch v-model="ruleForm.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="ruleDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="savingRule" @click="saveCustomRule">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { Search, Notebook, Plus, WarningFilled } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { request } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'

interface APIResponse<T> { code: number; message: string; data: T }
interface CRSRuleFile { filename: string; category: string; size: number }
interface CustomRuleCondition { target: string; operator: string; pattern: string }
interface CustomRule { id: number; name: string; description: string; conditions: CustomRuleCondition[]; action: string; score: number; status_code: number; enabled: boolean }

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.user?.role !== 'admin')

const crsInfo = ref({ version: '', server_version: '', auto_update: true, last_checked: '', updated_at: '', rule_count: 0, is_latest: false, update_status: '' })
const activeTab = ref('rules')
const loadingRules = ref(false)
const rules = ref<CRSRuleFile[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = 50
const searchQuery = ref('')
const loadingSetup = ref(false)
const setupContent = ref('')
const contentDialogVisible = ref(false)
const loadingContent = ref(false)
const currentFilename = ref('')
const currentContent = ref('')

const customRules = ref<CustomRule[]>([])
const customPage = ref(1)
const customPageSize = ref(10)
const loadingCustom = ref(false)
const ruleDialogVisible = ref(false)
const editingRuleId = ref<number | null>(null)
const savingRule = ref(false)
const ruleForm = ref({ name: '', description: '', conditions: [] as CustomRuleCondition[], action: 'block', score: 5, status_code: 403, enabled: true })

const isValidRegex = (pattern: string): boolean => {
  if (!pattern) return true
  try { new RegExp(pattern); return true } catch { return false }
}

const fetchCRS = async () => { try { const res = await request.get<APIResponse<typeof crsInfo.value>>('/security/crs'); if (res.data) crsInfo.value = res.data } catch {} }
const fetchRules = async () => {
  loadingRules.value = true
  try { const p = new URLSearchParams({ page: String(page.value), page_size: String(pageSize) }); if (searchQuery.value) p.set('search', searchQuery.value); const res = await request.get<APIResponse<{ rules: CRSRuleFile[]; total: number }>>(`/security/crs/rules?${p}`); rules.value = res.data?.rules || []; total.value = res.data?.total || 0 } catch { rules.value = [] } finally { loadingRules.value = false }
}
const fetchSetup = async () => { loadingSetup.value = true; try { const res = await request.get<APIResponse<{ content: string }>>('/security/crs/setup'); setupContent.value = res.data?.content || '# 文件不存在' } catch { setupContent.value = '# 加载失败' } finally { loadingSetup.value = false } }
const fetchCustomRules = async () => { loadingCustom.value = true; try { const res = await request.get<APIResponse<CustomRule[]>>('/security/custom-rules'); customRules.value = res.data || [] } catch { customRules.value = [] } finally { loadingCustom.value = false } }

const openRuleContent = async (row: CRSRuleFile) => { currentFilename.value = row.filename; contentDialogVisible.value = true; loadingContent.value = true; currentContent.value = ''; try { const res = await request.get<APIResponse<{ content: string; size: number }>>(`/security/crs/rules/${encodeURIComponent(row.filename)}`); currentContent.value = res.data?.content || '(空文件)' } catch { currentContent.value = '加载失败' } finally { loadingContent.value = false } }
const toggleAutoUpdate = async (val: boolean) => { try { await request.put('/security/crs/auto-update', { auto_update: val }); ElMessage.success('已更新') } catch { ElMessage.error('更新失败') } }

const openRuleDialog = (row?: CustomRule) => {
  editingRuleId.value = row?.id ?? null
  if (row) {
    ruleForm.value = { name: row.name, description: row.description, conditions: [...row.conditions], action: row.action, score: row.score, status_code: row.status_code, enabled: row.enabled }
  } else {
    ruleForm.value = { name: '', description: '', conditions: [{ target: 'uri', operator: 'contains', pattern: '' }], action: 'block', score: 5, status_code: 403, enabled: true }
  }
  ruleDialogVisible.value = true
}

const saveCustomRule = async () => {
  if (!ruleForm.value.name.trim()) { ElMessage.warning('请输入规则名称'); return }
  savingRule.value = true
  try {
    if (editingRuleId.value) {
      await request.put(`/security/custom-rules/${editingRuleId.value}`, ruleForm.value)
    } else {
      await request.post('/security/custom-rules', ruleForm.value)
    }
    ElMessage.success('保存成功'); ruleDialogVisible.value = false; fetchCustomRules()
  } catch { ElMessage.error('保存失败') } finally { savingRule.value = false }
}

const deleteCustomRule = (row: CustomRule) => {
  ElMessageBox.confirm(`确定删除规则"${row.name}"？`, '确认', { type: 'warning' })
    .then(async () => { await request.delete(`/security/custom-rules/${row.id}`); ElMessage.success('已删除'); fetchCustomRules() }).catch(() => {})
}

const formatSize = (b: number) => b < 1024 ? `${b} B` : b < 1048576 ? `${(b/1024).toFixed(1)} KB` : `${(b/1048576).toFixed(1)} MB`

onMounted(() => { fetchCRS(); fetchRules(); fetchSetup(); fetchCustomRules() })
</script>

<style scoped>
.crs-content { max-height: 70vh; overflow: auto; background: #f8f9fa; padding: 16px; border-radius: 6px; font-family: 'Courier New', monospace; font-size: 13px; line-height: 1.5; white-space: pre-wrap; word-break: break-all; }
.rule-condition-row { display: flex; gap: 6px; margin-bottom: 6px; align-items: center; flex-wrap: wrap; }
.table-toolbar { display: flex; justify-content: flex-end; margin-bottom: 16px; }
.search-input { width: 280px; }
.rules-pagination { display: flex; justify-content: flex-end; margin-top: 16px; }
</style>
