<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Document /></el-icon>
          拦截页面
        </h2>
        <p class="page-desc">管理 WAF 拦截时返回给客户端的自定义页面</p>
      </div>
      <el-button v-if="!isReadOnly" type="primary" :disabled="loading" @click="openDialog()">
        <el-icon><Plus /></el-icon>
        新建页面
      </el-button>
    </div>

    <el-card class="list-card">
      <el-table :data="pagedPages" v-loading="loading" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="">
        <template #empty>
          <el-empty description="暂无拦截页面" :image-size="60" />
        </template>
        <el-table-column prop="name" label="页面名称" min-width="180">
          <template #default="{ row }">
            <el-link type="primary" @click="previewPage(row)">{{ row.name }}</el-link>
            <el-tag v-if="row.is_default || row.is_builtin" size="small" type="info" effect="plain" style="margin-left: 8px">内置</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="内容类型" width="110" align="center">
          <template #default="{ row }">
            <el-tag size="small" :type="contentTypeTagType(row.content_type)" effect="plain">{{ contentTypeLabel(row.content_type) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="规则引用" width="90" align="center">
          <template #default="{ row }">
            <el-tooltip :disabled="!row.rule_ref_count" content="引用本页的负载均衡规则数（启用策略绑定 ∪ 规则级阶段覆盖）" placement="top">
              <span>{{ row.rule_ref_count ?? 0 }}</span>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column prop="description" label="描述" min-width="180" show-overflow-tooltip />
        <el-table-column label="更新时间" width="170" align="center">
          <template #default="{ row }">{{ formatDate(row.updated_at) || '-' }}</template>
        </el-table-column>
        <el-table-column label="更新者" width="100" align="center">
          <template #default="{ row }">{{ getUpdaterName(row.updated_by) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="200" fixed="right">
          <template #default="{ row }">
            <el-button size="small" link type="primary" @click="previewPage(row)">预览</el-button>
            <el-button size="small" link :type="row.is_default || row.is_builtin || isReadOnly ? 'info' : 'primary'" @click="openDialog(row)">{{ row.is_default || row.is_builtin || isReadOnly ? '查看' : '编辑' }}</el-button>
            <el-button size="small" link type="danger" :disabled="row.is_default || row.is_builtin || isReadOnly" @click="handleDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
      <!-- 与其他表格页同款分页器（2026-09-25 用户裁定）：总数/页大小/翻页 -->
      <el-pagination
        v-model:current-page="page"
        v-model:page-size="pageSize"
        :page-sizes="[10, 20, 50]"
        :total="pages.length"
        layout="total, sizes, prev, pager, next"
        @size-change="page = 1"
      />
    </el-card>

    <el-dialog v-model="dialogVisible" width="min(960px, 94vw)" top="3vh" class="dialog-body-inset">
      <template #header>
        <div class="dialog-header">
          <div class="dialog-header__icon dialog-header__icon--warning"><el-icon :size="18"><Document /></el-icon></div>
          <div class="dialog-header__text">
            <div class="dialog-header__title">{{ dialogTitle }}</div>
            <div class="dialog-header__subtitle">命中拦截规则时返回给客户端的响应页面，支持自定义内容类型</div>
          </div>
        </div>
      </template>
      <el-form :model="form" label-width="80px" label-position="right" class="block-page-form">
        <el-form-item label="名称" required>
          <el-input v-model="form.name" placeholder="页面名称" :readonly="isReadOnly || currentPage?.is_default || currentPage?.is_builtin" />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="form.description" placeholder="页面描述" :readonly="isReadOnly || currentPage?.is_default || currentPage?.is_builtin" />
        </el-form-item>
        <el-form-item label="内容类型">
          <el-select v-model="form.content_type" style="width: 320px" :disabled="isReadOnly || currentPage?.is_default || currentPage?.is_builtin">
            <el-option v-for="opt in CONTENT_TYPE_OPTIONS" :key="opt.value" :value="opt.value" :label="opt.label" />
          </el-select>
          <span class="form-tip-inline">拦截响应的 Content-Type（均 UTF-8 编码）</span>
        </el-form-item>
        <el-form-item label="内容" class="content-form-item">
          <div class="block-content-editor" style="width: 100%">
            <SyntaxHighlight v-if="isReadOnly || currentPage?.is_default || currentPage?.is_builtin" :content="form.content" language="markup" height="520px" />
            <CodeEditor v-else v-model="form.content" language="markup" height="520px" placeholder="HTML 内容，支持内联 CSS 样式" />
          </div>
          <div class="form-tip-line">
            {{ (currentPage?.is_default || currentPage?.is_builtin) ? '内置页面内容只读，仅可查看' : '拦截时返回给客户端的 HTML 页面，支持内联 CSS 样式' }}
          </div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button v-if="!currentPage?.is_default && !currentPage?.is_builtin && !isReadOnly" type="primary" :loading="saving" @click="handleSave">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="previewVisible" title="拦截页面预览" width="min(960px, 94vw)" top="3vh" @close="previewContent = ''">
      <iframe v-if="previewVisible && previewContent" :srcdoc="previewContent" sandbox="" :key="previewKey" style="width: 100%; aspect-ratio: 16/9; border: 1px solid #e4e7ed; border-radius: 6px; background: #fff; display: block" />
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { Plus, Document } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { request } from '@/utils/api'
import { showSaveResult } from '@/utils/saveResult'
import { useAuthStore } from '@/stores/auth'
import { formatDate } from '@/utils/date'
import SyntaxHighlight from '@/components/SyntaxHighlight.vue'
import CodeEditor from '@/components/CodeEditor.vue'
import type { APIResponse, UserListItem } from '@/types'
interface BlockPage { id: number; name: string; description: string; content: string; content_type?: string; rule_ref_count?: number; is_default: boolean; is_builtin?: boolean; updated_at: string; updated_by: number }

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.readOnlyReason !== null)

const loading = ref(false)

const page = ref(1)
const pageSize = ref(10)
// 客户端分页（与 Rules/SecurityRules 同款：页大小变更回第一页；删除后夹紧页码）
const pagedPages = computed(() => {
  const maxPage = Math.max(1, Math.ceil(pages.value.length / pageSize.value))
  if (page.value > maxPage) page.value = maxPage
  const start = (page.value - 1) * pageSize.value
  return pages.value.slice(start, start + pageSize.value)
})
const saving = ref(false)
const users = ref<UserListItem[]>([])
const pages = ref<BlockPage[]>([])
const dialogVisible = ref(false)
const previewVisible = ref(false)
const previewContent = ref('')
const previewKey = ref(0)
const editingId = ref<number | null>(null)
const currentPage = ref<BlockPage | null>(null)

const dialogTitle = computed(() => {
  if (!editingId.value) return '新建拦截页面'
  // R72 二十九次 M6：只读用户打开非默认页也应显示「查看」（此前编辑态误导）。
  return currentPage.value?.is_default || isReadOnly.value ? '查看拦截页面' : '编辑拦截页面'
})

const form = ref({ name: '', description: '', content: '', content_type: 'text/html; charset=utf-8' })

// 可选内容类型（与后端 models.BlockPageContentTypes 白名单同口径）
const CONTENT_TYPE_OPTIONS = [
  { value: 'text/html; charset=utf-8', label: 'HTML 页面（text/html）' },
  { value: 'application/json; charset=utf-8', label: 'JSON（application/json）' },
  { value: 'application/xml; charset=utf-8', label: 'XML（application/xml）' },
  { value: 'text/plain; charset=utf-8', label: '纯文本（text/plain）' },
] as const
const contentTypeLabel = (ct?: string): string => {
  if (!ct) return 'HTML'
  if (ct.includes('json')) return 'JSON'
  if (ct.includes('xml')) return 'XML'
  if (ct.includes('plain')) return 'TXT'
  return 'HTML'
}
const contentTypeTagType = (ct?: string): 'primary' | 'success' | 'warning' | 'info' => {
  if (!ct || ct.includes('html')) return 'primary'
  if (ct.includes('json')) return 'success'
  if (ct.includes('xml')) return 'warning'
  return 'info'
}

const fetchData = async () => {
  loading.value = true
  try {
    const [pagesRes, usersRes] = await Promise.all([
      request.get<APIResponse<BlockPage[]>>('/security/block-pages'),
      request.get<APIResponse<UserListItem[]>>('/users'),
    ])
    pages.value = pagesRes.data || []
    users.value = usersRes.data || []
  } catch (error: unknown) {
    // 全局拦截器已弹 toast，这里仅记录避免 unhandled rejection
    console.error('Failed to load block pages data:', error)
  } finally { loading.value = false }
}

const getUpdaterName = (userId?: number) => {
  if (!userId || userId === 0) return '-'
  const user = users.value.find(u => u.id === userId)
  return user?.display_name || user?.username || '-'
}

const openDialog = (row?: BlockPage) => {
  editingId.value = row?.id ?? null
  currentPage.value = row ?? null
  if (row) {
      form.value = { name: row.name, description: row.description, content: row.content, content_type: row.content_type || 'text/html; charset=utf-8' }
  } else {
      form.value = { name: '', description: '', content: '', content_type: 'text/html; charset=utf-8' }
  }
  dialogVisible.value = true
}
const handleSave = async () => {
  if (!form.value.name.trim()) { ElMessage.warning('请输入页面名称'); return }
  saving.value = true
  try {
    const res = editingId.value
      ? await request.put(`/security/block-pages/${editingId.value}`, form.value)
      : await request.post('/security/block-pages', form.value)
    showSaveResult(res, '保存成功')
    dialogVisible.value = false
    await fetchData()
  } catch { /* 具体错误已由全局 axios 拦截器统一展示 */ } finally { saving.value = false }
}

const handleDelete = (row: BlockPage) => {
  ElMessageBox.confirm(`确定删除拦截页面"${row.name}"？`, '确认', { type: 'warning' })
    .then(async () => { const del = await request.delete(`/security/block-pages/${row.id}`); showSaveResult(del, '已删除'); fetchData() }).catch(() => {})
}

const previewPage = (row: BlockPage) => {
  previewContent.value = row.content || '<p style="color: #999; padding: 20px; text-align: center">(空内容)</p>'
  previewKey.value++
  previewVisible.value = true
}

onMounted(fetchData)
</script>

<style scoped>
/* ── 通用弹框头部 ── */
/* 少数据时卡片不塌陷（2026-09-25 用户裁定）：至少与空表格占位同高；上界天然受页面高度约束 */
.list-card :deep(.el-card__body) { min-height: 360px; }
.dialog-header { display: flex; align-items: flex-start; gap: 12px; }
.dialog-header__icon {
  flex-shrink: 0; width: 36px; height: 36px; border-radius: 8px;
  background: #ecf5ff; color: #409eff;
  display: flex; align-items: center; justify-content: center;
}
.dialog-header__icon--warning { background: #fdf6ec; color: #e6a23c; }
.dialog-header__title { font-size: 16px; font-weight: 600; color: var(--text-primary, #111827); line-height: 1.4; }
.dialog-header__subtitle { font-size: 12px; color: var(--text-secondary, #6b7280); margin-top: 2px; }

.block-content-editor { border: 1px solid #e4e7ed; border-radius: 6px; overflow: hidden; }
.block-page-form .content-form-item .el-form-item__content { flex: 1; max-width: 100%; }

</style>
