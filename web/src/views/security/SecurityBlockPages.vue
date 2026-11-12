<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Document /></el-icon>
          {{ t('app.security.blockPages.page.title') }}
        </h2>
        <p class="page-desc">{{ t('app.security.blockPages.page.desc') }}</p>
      </div>
      <el-button v-if="!isReadOnly" type="primary" :disabled="loading" @click="openDialog()">
        <el-icon><Plus /></el-icon>
        {{ t('app.security.blockPages.page.newPage') }}
      </el-button>
    </div>

    <el-alert v-if="loadError" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
      <template #title>
        <div class="polling-error-title">
          <span>{{ pages.length > 0 ? t('app.security.blockPages.alert.loadFailedStale') : t('app.security.blockPages.alert.loadFailedEmpty') }}</span>
          <el-button link type="danger" :loading="loading" @click="fetchData">{{ t('app.security.blockPages.alert.retryNow') }}</el-button>
        </div>
      </template>
    </el-alert>

    <el-card class="list-card">
      <el-table :data="pagedPages" v-loading="loading" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="">
        <template #empty>
          <el-empty v-if="!loadError" :description="t('app.security.blockPages.table.empty')" :image-size="60" />
          <span v-else class="text-secondary">{{ t('app.security.blockPages.table.loadFailed') }}</span>
        </template>
        <el-table-column prop="name" :label="t('app.security.blockPages.table.colName')" min-width="180">
          <template #default="{ row }">
            <AccessibleLink type="primary" @click="previewPage(row as BlockPage)">{{ pageName(row as BlockPage) }}</AccessibleLink>
            <el-tag v-if="row.is_default || row.is_builtin" size="small" type="info" effect="plain" style="margin-left: 8px">{{ t('app.security.blockPages.table.builtin') }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="t('app.security.blockPages.table.contentType')" width="105" align="center">
          <template #default="{ row }">
            <el-tag size="small" :type="contentTypeTagType(row.content_type)" effect="plain">{{ contentTypeLabel(row.content_type) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="t('app.security.blockPages.table.size')" width="90" align="center">
          <template #default="{ row }">
            <el-tooltip :content="t('app.security.blockPages.table.sizeTip')" placement="top">
              <span>{{ contentSizes.get(row.id) }}</span>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column :label="t('app.security.blockPages.table.description')" min-width="180" show-overflow-tooltip>
          <template #default="{ row }">{{ pageDesc(row as BlockPage) }}</template>
        </el-table-column>
        <el-table-column :label="t('app.security.blockPages.table.ruleRefs')" width="120" align="center">
          <template #default="{ row }">
            <el-tooltip :disabled="!row.rule_ref_count" :content="t('app.security.blockPages.table.ruleRefsTip')" placement="top">
              <span>{{ row.rule_ref_count ?? 0 }}</span>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column :label="t('app.security.blockPages.table.updatedAt')" width="170" align="center">
          <template #default="{ row }">{{ formatDate(row.updated_at) || '-' }}</template>
        </el-table-column>
        <el-table-column :label="t('app.security.blockPages.table.updatedBy')" width="100" align="center">
          <template #default="{ row }">{{ getUpdaterName(row.updated_by) }}</template>
        </el-table-column>
        <el-table-column :label="t('app.security.blockPages.table.actions')" width="200" fixed="right">
          <template #default="{ row }">
            <el-button size="small" link type="primary" @click="previewPage(row as BlockPage)">{{ t('app.security.blockPages.rowActions.preview') }}</el-button>
            <el-button size="small" link :type="row.is_default || row.is_builtin || isReadOnly ? 'info' : 'primary'" @click="openDialog(row as BlockPage)">{{ row.is_default || row.is_builtin || isReadOnly ? t('app.security.blockPages.rowActions.view') : t('app.security.blockPages.rowActions.edit') }}</el-button>
            <el-button size="small" link type="danger" :loading="deletingId === row.id" :disabled="row.is_default || row.is_builtin || isReadOnly || deletingId !== null" @click="handleDelete(row as BlockPage)">{{ t('app.security.blockPages.rowActions.delete') }}</el-button>
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

    <el-dialog v-model="dialogVisible" width="min(1080px, 96vw)" top="2vh" class="dialog-body-inset block-page-dialog" :close-on-click-modal="false" :close-on-press-escape="!saving" :show-close="!saving">
      <template #header>
        <DialogHeader :icon="Document" :title="dialogTitle" tone="warning"
          :subtitle="t('app.security.blockPages.dialog.subtitle')" />
      </template>
      <el-form :model="form" :label-width="$flw('80px')" label-position="right" class="block-page-form block-page-form--scroll" :disabled="saving">
        <el-form-item :label="t('app.security.blockPages.dialog.labelName')" required>
          <el-input v-model="form.name" :placeholder="t('app.security.blockPages.dialog.placeholderName')" :maxlength="SECURITY_NAME_MAX_RUNES" show-word-limit :readonly="isReadOnly || currentPage?.is_default || currentPage?.is_builtin || saving" />
        </el-form-item>
        <el-form-item :label="t('app.security.blockPages.table.description')">
          <el-input v-model="form.description" :placeholder="t('app.security.blockPages.dialog.placeholderDesc')" :maxlength="SECURITY_DESCRIPTION_MAX_RUNES" show-word-limit :readonly="isReadOnly || currentPage?.is_default || currentPage?.is_builtin || saving" />
        </el-form-item>
        <el-form-item :label="t('app.security.blockPages.dialog.labelContent')" class="content-form-item" for="block-content-static">
          <input type="text" id="block-content-static" aria-hidden="true" tabindex="-1" autocomplete="off" style="display:none">
          <el-tabs v-model="bodyTab" class="block-page-body-tabs">
            <el-tab-pane :label="t('app.security.blockPages.dialog.tabHtml')" name="html">
              <div v-if="!isReadOnly && !currentPage?.is_default && !currentPage?.is_builtin" class="block-widget-bar">
                <el-button size="small" :disabled="saving" @click="insertHumanWidget">{{ t('app.security.blockPages.dialog.insertHumanWidget') }}</el-button>
                <el-button size="small" :disabled="saving" @click="insertJsWidget">{{ t('app.security.blockPages.dialog.insertJsWidget') }}</el-button>
                <span class="form-tip-inline">{{ t('app.security.blockPages.dialog.humanWidgetTip') }}</span>
                <span class="form-tip-inline">{{ t('app.security.blockPages.dialog.jsWidgetTip') }}</span>
              </div>
              <div class="block-content-editor" style="width: 100%">
                <SyntaxHighlight v-if="isReadOnly || currentPage?.is_default || currentPage?.is_builtin" :content="form.content" language="markup" height="320px" />
                <CodeEditor v-else v-model="form.content" language="markup" height="320px" :aria-label="t('app.security.blockPages.dialog.editorAria')" :placeholder="t('app.security.blockPages.dialog.placeholderContent')" :readonly="saving" />
              </div>
              <div class="form-tip-line">
                {{ (currentPage?.is_default || currentPage?.is_builtin) ? t('app.security.blockPages.dialog.contentTipReadonly') : t('app.security.blockPages.dialog.contentTipEditable') }}
              </div>
            </el-tab-pane>
            <el-tab-pane :label="t('app.security.blockPages.dialog.labelJson')" name="json">
              <div class="block-content-editor" style="width: 100%">
                <SyntaxHighlight v-if="isReadOnly || currentPage?.is_default || currentPage?.is_builtin" :content="resolvedJson(form.json_content, form.content)" language="json" height="220px" />
                <CodeEditor v-else v-model="form.json_content" language="json" height="220px" :aria-label="t('app.security.blockPages.dialog.labelJson')" :placeholder="resolvedJson('', form.content)" :readonly="saving" />
              </div>
              <div class="form-tip-line">{{ t('app.security.blockPages.dialog.jsonTip') }}</div>
            </el-tab-pane>
          </el-tabs>
        </el-form-item>

      </el-form>
      <template #footer>
        <el-button :disabled="saving" @click="dialogVisible = false">{{ t('app.security.blockPages.dialog.cancel') }}</el-button>
        <el-button v-if="!currentPage?.is_default && !currentPage?.is_builtin && !isReadOnly" type="primary" :loading="saving" :disabled="saving" @click="handleSave">{{ t('app.security.blockPages.dialog.save') }}</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="previewVisible" width="min(960px, 94vw)" top="3vh" @close="previewContent = ''">
      <template #header>
        <DialogHeader :icon="Document" :title="t('app.security.blockPages.preview.title')" :subtitle="t('app.security.blockPages.preview.subtitle')" />
      </template>
      <DialogSectionHeader :title="t('app.security.blockPages.preview.effectTitle')" />
      <el-tabs v-model="previewTab" class="block-page-preview-tabs">
        <el-tab-pane :label="t('app.security.blockPages.preview.tabHtml')" name="html">
          <div class="dialog-panel dialog-panel--flush">
            <iframe v-if="previewVisible && previewContent" :srcdoc="previewContent" sandbox="" :key="previewKey" style="width: 100%; aspect-ratio: 16/9; border: 0; background: #fff; display: block" />
          </div>
        </el-tab-pane>
        <el-tab-pane :label="t('app.security.blockPages.preview.tabJson')" name="json">
          <div class="dialog-panel dialog-panel--flush">
            <SyntaxHighlight :content="previewJson" language="json" height="220px" />
          </div>
        </el-tab-pane>
      </el-tabs>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { Plus, Document } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { request } from '@/utils/api'
import { formatBytes } from '@/utils/formatBytes'
import { useClampedPagination } from '@/composables/useClampedPagination'
import { showSaveResult } from '@/utils/saveResult'
import { escapeHtml } from '@/utils/escape'
import { useAuthStore } from '@/stores/auth'
import { formatDate } from '@/utils/date'
import { builtinBlockPageLabel, type BlockPageLike } from '@/utils/builtinBlockPages'
import { updaterName } from '@/utils/updaterName'
import { SECURITY_DESCRIPTION_MAX_RUNES, SECURITY_NAME_MAX_RUNES } from '@/utils/securityLimits'
import SyntaxHighlight from '@/components/SyntaxHighlight.vue'
import CodeEditor from '@/components/CodeEditor.vue'
import DialogHeader from '@/components/DialogHeader.vue'
import DialogSectionHeader from '@/components/DialogSectionHeader.vue'
import AccessibleLink from '@/components/common/AccessibleLink.vue'
import type { APIResponse, UserListItem } from '@/types'

// 验证组件占位符插入（重复插入检测——同页只一个组件实例；滑块/JS 各自独立检测）
const insertHumanWidget = (): void => {
  if (form.value.content.includes('{{human_verify_widget}}')) return
  form.value.content = form.value.content.trimEnd() + '\n{{human_verify_widget}}\n'
}

const insertJsWidget = (): void => {
  if (form.value.content.includes('{{human_js_widget}}')) return
  form.value.content = form.value.content.trimEnd() + '\n{{human_js_widget}}\n'
}

const { t } = useI18n()

// 内置页名称/描述按 id 多语言显示（自定义页回退库内原文）
const pageName = (page: BlockPage | BlockPageLike): string => builtinBlockPageLabel(page, 'name', t)
const pageDesc = (page: BlockPage | BlockPageLike): string => builtinBlockPageLabel(page, 'desc', t)
interface BlockPage { id: number; name: string; description: string; content: string; json_content?: string; content_type?: string; rule_ref_count?: number; is_default: boolean; is_builtin?: boolean; updated_at: string; updated_by: number }

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
const previewJson = ref('')
const previewTab = ref<'html' | 'json'>('html')
const previewKey = ref(0)
const editingId = ref<number | null>(null)
const currentPage = ref<BlockPage | null>(null)

const dialogTitle = computed(() => {
  if (!editingId.value) return t('app.security.blockPages.dialog.createTitle')
  // 只读用户打开非默认页也应显示「查看」（此前编辑态误导）。
  return currentPage.value?.is_default || currentPage.value?.is_builtin || isReadOnly.value ? t('app.security.blockPages.dialog.viewTitle') : t('app.security.blockPages.dialog.editTitle')
})


// 内容大小（响应体 UTF-8 字节数）：仅在页面列表变化时逐条计算一次，
// 避免每次表格渲染都为每行创建 Blob/重新编码；格式化走 formatBytes 单一事实源。
const contentSizes = computed(() => {
  const encoder = new TextEncoder()
  return new Map(pages.value.map((page) => [page.id, formatBytes(encoder.encode(page.content).byteLength)]))
})
const form = ref({ name: '', description: '', content: '', json_content: '', content_type: 'text/html; charset=utf-8' })
// 响应模式：dual=HTML+JSON 双档（推荐）；single=兼容旧版单一内容类型。
const bodyTab = ref<'html' | 'json'>('html')

// 后端 validateBlockPagePayload 的内容上限（64<<10 字节），前端仅做同源前置门。
const BLOCK_PAGE_CONTENT_MAX_BYTES = 64 << 10

// 可选内容类型（与后端 models.BlockPageContentTypeWhitelist 白名单同口径）

// 单档模式只列机器可读的旧版类型（HTML 走双档，不在单档内重复出现）。
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
  form.value = row
    ? { name: row.name, description: row.description, content: row.content, json_content: row.json_content ?? '', content_type: 'text/html; charset=utf-8' }
    : { name: '', description: '', content: '', json_content: '', content_type: 'text/html; charset=utf-8' }
  // 拦截页恒为双档（HTML + JSON）；实际返回哪种由安全策略的「拦截响应」决定。
  bodyTab.value = 'html'
  dialogVisible.value = true
}
const handleSave = async () => {
  if (!form.value.name.trim()) { ElMessage.warning(t('app.security.blockPages.messages.nameRequired')); return }
  // 与后端 validateBlockPagePayload 同源的前置门：内容非空 + ≤64KB（UTF-8 字节）。
  // 此前只判名称，超限内容过确认后由后端 400 拒绝，错误文案不落到字段。
  if (!form.value.content.trim()) { ElMessage.warning(t('app.security.blockPages.messages.contentRequired')); return }
  const contentBytes = new TextEncoder().encode(form.value.content).byteLength
  if (contentBytes > BLOCK_PAGE_CONTENT_MAX_BYTES) {
    ElMessage.warning(t('app.security.blockPages.messages.contentTooLarge', { size: formatBytes(contentBytes) }))
    return
  }
  // API 变体（json_content）：非空必须是合法 JSON 且 ≤64KB——非法 JSON 会在
  // 运行时直接发给 API 客户端（解析失败/静默掉错），必须在保存前拦住。
  if (form.value.json_content.trim()) {
    const jsonBytes = new TextEncoder().encode(form.value.json_content).byteLength
    if (jsonBytes > BLOCK_PAGE_CONTENT_MAX_BYTES) {
      ElMessage.warning(t('app.security.blockPages.messages.jsonTooLarge', { size: formatBytes(jsonBytes) }))
      return
    }
    try { JSON.parse(form.value.json_content) } catch {
      ElMessage.warning(t('app.security.blockPages.messages.jsonInvalid'))
      return
    }
  }
  // 提交口径：页面恒为双档，content_type 固定 text/html（JSON 走 json_content）；
  // 旧版单档类型不再写回（用户裁定：兼容旧版单一内容不需要）。
  const payload = {
    ...form.value,
    content_type: 'text/html; charset=utf-8',
  }
  saving.value = true
  try {
    const res = editingId.value
      ? await request.put(`/security/block-pages/${editingId.value}`, payload)
      : await request.post('/security/block-pages', payload)
    showSaveResult(res, t('app.security.blockPages.messages.saved'))
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
  ElMessageBox.confirm(t('app.security.blockPages.deleteConfirm.text', { name: row.name }), t('app.security.blockPages.deleteConfirm.title'), { type: 'warning', confirmButtonText: t('app.security.blockPages.deleteConfirm.confirm'), cancelButtonText: t('app.security.blockPages.dialog.cancel') })
    .then(async () => { const del = await request.delete(`/security/block-pages/${row.id}`); showSaveResult(del, t('app.security.blockPages.messages.deleted')); fetchData() })
    .catch(() => { /* 用户取消或请求失败（全局拦截器已 toast）——列表保持不变 */ })
    .finally(() => { deletingId.value = null })
}

// 未配置 JSON 时的默认响应体：从 HTML <title> 派生消息（与后端
// defaultBlockPageJSONMessage 同口径），且不含 code——状态码由 HTTP status 表达。
const resolvedJson = (json: string, html: string): string => {
  const trimmed = (json || '').trim()
  if (trimmed) return trimmed
  const match = (html || '').match(/<title[^>]*>([\s\S]*?)<\/title>/i)
  const title = (match?.[1] || '').replace(/<[^>]*>/g, '').trim()
  return JSON.stringify({ message: title || 'Request blocked' }, null, 2)
}

const previewPage = (row: BlockPage) => {
  // 非 HTML 类型按源码展示——srcdoc 恒按 text/html 解析，
  // JSON/XML/纯文本直接塞入会被吞标签/压成无格式文本流，与真实响应不一致
  const content = row.content || ''
  const isHtml = !row.content_type || row.content_type.startsWith('text/html')
  previewContent.value = !content
    ? '<p style="color: #999; padding: 20px; text-align: center">' + t('app.security.blockPages.preview.emptyContent') + '</p>'
    : isHtml
      ? content
      : `<pre style="white-space: pre-wrap; word-break: break-all; margin: 0; padding: 12px; font: 13px/1.6 ui-monospace, SFMono-Regular, Menlo, monospace">${escapeHtml(content)}</pre>`
  // API 变体预览：页面未配置时展示引擎将生成的最小 JSON（与真实回退一致）。
  previewJson.value = resolvedJson(row.json_content || '', content)
  previewTab.value = 'html'
  previewKey.value++
  previewVisible.value = true
}

onMounted(fetchData)
</script>

<style scoped>
.block-content-editor { border: 1px solid #e4e7ed; overflow: hidden; }

/* 弹框高度约束（2026-11-12 用户反馈：原弹框超出屏幕）：
   表单区内滚，编辑器随标签页切换按需占用高度；弹框自身不超出视口。 */
.block-page-form--scroll { max-height: calc(90vh - 150px); overflow-y: auto; padding-right: 6px; }
.block-page-body-tabs { width: 100%; }
.block-page-dialog :deep(.el-dialog__body) { max-height: calc(96vh - 120px); overflow: hidden; }

/* .rules-pagination 已收敛 styles/main.css（四处逐字重复单源化） */

</style>
