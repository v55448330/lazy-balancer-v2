<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Notebook /></el-icon>
          规则集
        </h2>
        <p class="page-desc">浏览 OWASP CRS 规则文件和配置</p>
      </div>
    </div>

    <el-card class="mb-4">
      <template #header>
        <div class="flex items-center justify-between">
          <span class="font-medium">OWASP CRS</span>
          <el-tag type="success" size="small" effect="light">{{ crsInfo.version || '—' }}</el-tag>
        </div>
      </template>
      <el-descriptions :column="3" border>
        <el-descriptions-item label="版本">{{ crsInfo.version || '—' }}</el-descriptions-item>
        <el-descriptions-item label="规则文件数">{{ total }}</el-descriptions-item>
        <el-descriptions-item label="自动更新">
          <el-switch v-model="crsInfo.auto_update" :disabled="isReadOnly" @change="toggleAutoUpdate" />
        </el-descriptions-item>
      </el-descriptions>
    </el-card>

    <el-tabs v-model="activeTab">
      <el-tab-pane label="CRS 规则浏览" name="rules">
        <div class="flex gap-3 mb-4">
          <el-input v-model="searchQuery" placeholder="搜索规则文件名或分类" clearable style="width: 280px" @clear="fetchRules" @keyup.enter="fetchRules">
            <template #prefix><el-icon><Search /></el-icon></template>
          </el-input>
          <el-button type="primary" plain :icon="Search" @click="fetchRules">搜索</el-button>
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
          <el-pagination v-model:current-page="page" :page-size="pageSize" :total="total" layout="prev, pager, next, total" @current-change="fetchRules" />
        </div>
      </el-tab-pane>
      <el-tab-pane label="CRS 配置" name="setup">
        <el-card v-loading="loadingSetup">
          <template #header><div class="flex items-center justify-between"><span class="font-medium">crs-setup.conf</span><el-button link type="primary" size="small" @click="fetchSetup">刷新</el-button></div></template>
          <el-input type="textarea" :model-value="setupContent" readonly :rows="25" style="font-family: monospace; font-size: 12px" />
        </el-card>
      </el-tab-pane>
    </el-tabs>

    <el-dialog v-model="contentDialogVisible" :title="currentFilename" width="900px" top="5vh">
      <div v-loading="loadingContent"><pre class="crs-content">{{ currentContent }}</pre></div>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { Search, Notebook } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { request } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'

interface APIResponse<T> { code: number; message: string; data: T }
interface CRSRuleFile { filename: string; category: string; size: number }

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.user?.role !== 'admin')
const crsInfo = ref({ version: '', auto_update: true, last_checked: '', rule_count: 0 })
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

const fetchCRS = async () => { try { const res = await request.get<APIResponse<typeof crsInfo.value>>('/security/crs'); if (res.data) crsInfo.value = res.data } catch {} }
const fetchRules = async () => {
  loadingRules.value = true
  try { const p = new URLSearchParams({ page: String(page.value), page_size: String(pageSize) }); if (searchQuery.value) p.set('search', searchQuery.value); const res = await request.get<APIResponse<{ rules: CRSRuleFile[]; total: number }>>(`/security/crs/rules?${p}`); rules.value = res.data?.rules || []; total.value = res.data?.total || 0 } catch { rules.value = [] } finally { loadingRules.value = false }
}
const fetchSetup = async () => { loadingSetup.value = true; try { const res = await request.get<APIResponse<{ content: string }>>('/security/crs/setup'); setupContent.value = res.data?.content || '# 文件不存在' } catch { setupContent.value = '# 加载失败' } finally { loadingSetup.value = false } }
const openRuleContent = async (row: CRSRuleFile) => { currentFilename.value = row.filename; contentDialogVisible.value = true; loadingContent.value = true; currentContent.value = ''; try { const res = await request.get<APIResponse<{ content: string; size: number }>>(`/security/crs/rules/${encodeURIComponent(row.filename)}`); currentContent.value = res.data?.content || '(空文件)' } catch { currentContent.value = '加载失败' } finally { loadingContent.value = false } }
const toggleAutoUpdate = async (val: boolean) => { try { await request.put('/security/crs/auto-update', { auto_update: val }); ElMessage.success('已更新') } catch { ElMessage.error('更新失败') } }
const formatSize = (b: number) => b < 1024 ? `${b} B` : b < 1048576 ? `${(b/1024).toFixed(1)} KB` : `${(b/1048576).toFixed(1)} MB`
onMounted(() => { fetchCRS(); fetchRules(); fetchSetup() })
</script>

<style scoped>
.crs-content { max-height: 70vh; overflow: auto; background: #f8f9fa; padding: 16px; border-radius: 6px; font-family: 'Courier New', monospace; font-size: 13px; line-height: 1.5; white-space: pre-wrap; word-break: break-all; }
</style>
