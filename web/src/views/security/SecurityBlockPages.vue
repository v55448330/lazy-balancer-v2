<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Document /></el-icon>
          拦截页面
        </h2>
        <p class="page-desc">管理各阶段拦截（IP 访问控制 / 限流 / WAF）返回给客户端的自定义页面</p>
      </div>
      <el-button v-if="!isReadOnly" type="primary" :disabled="loading" @click="openDialog()">
        <el-icon><Plus /></el-icon>
        新建页面
      </el-button>
    </div>

    <el-alert v-if="loadError" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
      <template #title>
        <div class="polling-error-title">
          <span>拦截页面加载失败：列表为空不代表没有页面</span>
          <el-button link type="danger" :loading="loading" @click="fetchData">立即重试</el-button>
        </div>
      </template>
    </el-alert>

    <el-card class="list-card">
      <el-table :data="pagedPages" v-loading="loading" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="">
        <template #empty>
          <el-empty v-if="!loadError" description="暂无拦截页面" :image-size="60" />
          <span v-else class="text-secondary">加载失败</span>
        </template>
        <el-table-column prop="name" label="页面名称" min-width="180">
          <template #default="{ row }">
            <AccessibleLink type="primary" @click="previewPage(row)">{{ row.name }}</AccessibleLink>
            <el-tag v-if="row.is_default || row.is_builtin" size="small" type="info" effect="plain" style="margin-left: 8px">内置</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="内容类型" width="105" align="center">
          <template #default="{ row }">
            <el-tag size="small" :type="contentTypeTagType(row.content_type)" effect="plain">{{ contentTypeLabel(row.content_type) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="大小" width="90" align="center">
          <template #default="{ row }">
            <el-tooltip content="拦截响应体字节数——评估拦截面传输压力（出站流量 ≈ 每秒拦截次数 × 页面大小，64KB 上限）" placement="top">
              <span>{{ contentSizes.get(row.id) }}</span>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column prop="description" label="描述" min-width="180" show-overflow-tooltip />
        <el-table-column label="规则引用" width="90" align="center">
          <template #default="{ row }">
            <el-tooltip :disabled="!row.rule_ref_count" content="引用本页的负载均衡规则数（启用策略绑定 ∪ 规则级阶段覆盖）" placement="top">
              <span>{{ row.rule_ref_count ?? 0 }}</span>
            </el-tooltip>
          </template>
        </el-table-column>
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
            <el-button size="small" link type="danger" :loading="deletingId === row.id" :disabled="row.is_default || row.is_builtin || isReadOnly || deletingId !== null" @click="handleDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
      <!-- 与其他表格页同款分页器（2026-09-25 用户裁定）：右对齐 + 16px 上距，同
           Rules/SecurityRules 的 .rules-pagination 范式 -->
      <div class="rules-pagination">
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="pageSize"
          :page-sizes="[10, 20, 50]"
          :total="pages.length"
          layout="total, sizes, prev, pager, next"
          @size-change="page = 1"
        />
      </div>
    </el-card>

    <el-dialog v-model="dialogVisible" width="min(960px, 94vw)" top="3vh" class="dialog-body-inset" :close-on-click-modal="false" :close-on-press-escape="!saving" :show-close="!saving">
      <template #header>
        <DialogHeader :icon="Document" :title="dialogTitle" tone="warning"
          subtitle="命中拦截规则时返回给客户端的响应页面，支持自定义内容类型" />
      </template>
      <el-form :model="form" label-width="80px" label-position="right" class="block-page-form" :disabled="saving">
        <el-form-item label="名称" required>
          <el-input v-model="form.name" placeholder="页面名称" :maxlength="SECURITY_NAME_MAX_RUNES" show-word-limit :readonly="isReadOnly || currentPage?.is_default || currentPage?.is_builtin || saving" />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="form.description" placeholder="页面描述" :maxlength="SECURITY_DESCRIPTION_MAX_RUNES" show-word-limit :readonly="isReadOnly || currentPage?.is_default || currentPage?.is_builtin || saving" />
        </el-form-item>
        <el-form-item label="内容类型">
          <el-select v-model="form.content_type" style="width: 320px" :disabled="isReadOnly || currentPage?.is_default || currentPage?.is_builtin || saving">
            <el-option v-for="opt in CONTENT_TYPE_OPTIONS" :key="opt.value" :value="opt.value" :label="opt.label" />
          </el-select>
          <span class="form-tip-inline">拦截响应的 Content-Type（均 UTF-8 编码）</span>
        </el-form-item>
        <el-form-item label="内容" class="content-form-item">
          <div class="block-content-editor" style="width: 100%">
            <SyntaxHighlight v-if="isReadOnly || currentPage?.is_default || currentPage?.is_builtin" :content="form.content" language="markup" height="520px" />
            <CodeEditor v-else v-model="form.content" language="markup" height="520px" aria-label="拦截页面内容" placeholder="响应内容（HTML 类型支持内联 CSS）" :readonly="saving" />
          </div>
          <div class="form-tip-line">
            {{ (currentPage?.is_default || currentPage?.is_builtin) ? '内置页面内容只读，仅可查看' : '拦截时返回给客户端的响应内容（HTML 类型支持内联 CSS）' }}
          </div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button :disabled="saving" @click="dialogVisible = false">取消</el-button>
        <el-button v-if="!currentPage?.is_default && !currentPage?.is_builtin && !isReadOnly" type="primary" :loading="saving" :disabled="saving" @click="handleSave">保存</el-button>
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
import { formatBytes } from '@/utils/formatBytes'
import { useClampedPagination } from '@/composables/useClampedPagination'
import { showSaveResult } from '@/utils/saveResult'
import { escapeHtml } from '@/utils/escape'
import { useAuthStore } from '@/stores/auth'
import { formatDate } from '@/utils/date'
import { updaterName } from '@/utils/updaterName'
import { SECURITY_DESCRIPTION_MAX_RUNES, SECURITY_NAME_MAX_RUNES } from '@/utils/securityLimits'
import SyntaxHighlight from '@/components/SyntaxHighlight.vue'
import CodeEditor from '@/components/CodeEditor.vue'
import DialogHeader from '@/components/DialogHeader.vue'
import AccessibleLink from '@/components/common/AccessibleLink.vue'
import type { APIResponse, UserListItem } from '@/types'
interface BlockPage { id: number; name: string; description: string; content: string; content_type?: string; rule_ref_count?: number; is_default: boolean; is_builtin?: boolean; updated_at: string; updated_by: number }

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.readOnlyReason !== null)

const loading = ref(false)

const page = ref(1)
const pageSize = ref(10)

const saving = ref(false)
const users = ref<UserListItem[]>([])
const pages = ref<BlockPage[]>([])
// 拦截页加载失败不得显示「暂无拦截页面」（与真实空列表不可区分）
const loadError = ref(false)
// 分页夹紧+切片：useClampedPagination 单一范式（取代 computed
// 内副作用赋值反模式）
const { pagedItems: pagedPages } = useClampedPagination(pages, page, pageSize)
const dialogVisible = ref(false)
const previewVisible = ref(false)
const previewContent = ref('')
const previewKey = ref(0)
const editingId = ref<number | null>(null)
const currentPage = ref<BlockPage | null>(null)

const dialogTitle = computed(() => {
  if (!editingId.value) return '新建拦截页面'
  // 只读用户打开非默认页也应显示「查看」（此前编辑态误导）。
  return currentPage.value?.is_default || currentPage.value?.is_builtin || isReadOnly.value ? '查看拦截页面' : '编辑拦截页面'
})


// 内容大小（响应体 UTF-8 字节数）：仅在页面列表变化时逐条计算一次，
// 避免每次表格渲染都为每行创建 Blob/重新编码；格式化走 formatBytes 单一事实源。
const contentSizes = computed(() => {
  const encoder = new TextEncoder()
  return new Map(pages.value.map((page) => [page.id, formatBytes(encoder.encode(page.content).byteLength)]))
})
const form = ref({ name: '', description: '', content: '', content_type: 'text/html; charset=utf-8' })

// 后端 validateBlockPagePayload 的内容上限（64<<10 字节），前端仅做同源前置门。
const BLOCK_PAGE_CONTENT_MAX_BYTES = 64 << 10

// 可选内容类型（与后端 models.BlockPageContentTypeWhitelist 白名单同口径）
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
    // 用户列表失败不得连带丢弃已成功的拦截页——Promise.all 下
    // 任一 reject 即整页空态「暂无拦截页面」，与真实数据状态不符。
    const [pagesRes, usersRes] = await Promise.allSettled([
      request.get<APIResponse<BlockPage[]>>('/security/block-pages'),
      request.get<APIResponse<UserListItem[]>>('/users'),
    ])
    if (pagesRes.status === 'fulfilled') {
      pages.value = pagesRes.value.data || []
      loadError.value = false
    }
    if (usersRes.status === 'fulfilled') users.value = usersRes.value.data || []
    // 全局拦截器已弹 toast，这里仅记录（用户列失败时更新者显示 '-'）
    if (pagesRes.status === 'rejected') {
      console.error('Failed to load block pages:', pagesRes.reason)
      loadError.value = true
    }
    if (usersRes.status === 'rejected') console.error('Failed to load block page users:', usersRes.reason)
  } finally { loading.value = false }
}

// 更新者显示名走 utils/updaterName 单源
const getUpdaterName = (userId?: number) => updaterName(users.value, userId)

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
  // 与后端 validateBlockPagePayload 同源的前置门：内容非空 + ≤64KB（UTF-8 字节）。
  // 此前只判名称，超限内容过确认后由后端 400 拒绝，错误文案不落到字段。
  if (!form.value.content.trim()) { ElMessage.warning('请输入页面内容'); return }
  const contentBytes = new TextEncoder().encode(form.value.content).byteLength
  if (contentBytes > BLOCK_PAGE_CONTENT_MAX_BYTES) {
    ElMessage.warning(`页面内容 ${formatBytes(contentBytes)} 超出 64KB 上限，请精简后保存`)
    return
  }
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

// 删除重入守卫（双击叠两个确认框 → 两次 DELETE，第二次 404 误报失败）——
// 与 SecurityPolicies.deletingPolicyId 同款范式。
const deletingId = ref<number | null>(null)
const handleDelete = (row: BlockPage) => {
  if (deletingId.value !== null) return
  deletingId.value = row.id
  ElMessageBox.confirm(`确定删除拦截页面"${row.name}"？`, '确认', { type: 'warning' })
    .then(async () => { const del = await request.delete(`/security/block-pages/${row.id}`); showSaveResult(del, '已删除'); fetchData() })
    .catch(() => { /* 用户取消或请求失败（全局拦截器已 toast）——列表保持不变 */ })
    .finally(() => { deletingId.value = null })
}

const previewPage = (row: BlockPage) => {
  // 非 HTML 类型按源码展示——srcdoc 恒按 text/html 解析，
  // JSON/XML/纯文本直接塞入会被吞标签/压成无格式文本流，与真实响应不一致
  const content = row.content || ''
  const isHtml = !row.content_type || row.content_type.startsWith('text/html')
  previewContent.value = !content
    ? '<p style="color: #999; padding: 20px; text-align: center">(空内容)</p>'
    : isHtml
      ? content
      : `<pre style="white-space: pre-wrap; word-break: break-all; margin: 0; padding: 12px; font: 13px/1.6 ui-monospace, SFMono-Regular, Menlo, monospace">${escapeHtml(content)}</pre>`
  previewKey.value++
  previewVisible.value = true
}

onMounted(fetchData)
</script>

<style scoped>
.block-content-editor { border: 1px solid #e4e7ed; border-radius: 6px; overflow: hidden; }

/* .rules-pagination 已收敛 styles/main.css（四处逐字重复单源化） */

</style>
