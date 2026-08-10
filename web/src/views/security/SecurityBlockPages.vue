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

    <el-card>
      <el-table :data="pages" v-loading="loading" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="">
        <template #empty>
          <el-empty description="暂无拦截页面" :image-size="60" />
        </template>
        <el-table-column prop="name" label="页面名称" min-width="180">
          <template #default="{ row }">
            <el-link type="primary" @click="previewPage(row)">{{ row.name }}</el-link>
          </template>
        </el-table-column>
        <el-table-column prop="description" label="描述" min-width="200" show-overflow-tooltip />
        <el-table-column label="更新时间" width="170" align="center">
          <template #default="{ row }">{{ formatDate(row.updated_at) || '-' }}</template>
        </el-table-column>
        <el-table-column label="更新者" width="100" align="center">
          <template #default="{ row }">{{ getUpdaterName(row.updated_by) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="200" fixed="right">
          <template #default="{ row }">
            <el-button size="small" link type="primary" @click="previewPage(row)">预览</el-button>
            <el-button size="small" link :type="row.is_default ? 'info' : 'primary'" @click="openDialog(row)">{{ row.is_default ? '查看' : '编辑' }}</el-button>
            <el-button size="small" link type="danger" :disabled="row.is_default" @click="handleDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="dialogVisible" :title="editingId ? (currentPage?.is_default ? '查看默认拦截页面' : '编辑拦截页面') : '新建拦截页面'" width="960px" top="3vh">
      <el-form :model="form" label-width="80px" label-position="right" class="block-page-form">
        <el-form-item label="名称" required>
          <el-input v-model="form.name" placeholder="页面名称" :readonly="currentPage?.is_default" />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="form.description" placeholder="页面描述" :readonly="currentPage?.is_default" />
        </el-form-item>
        <el-form-item label="内容" class="content-form-item">
          <div class="block-content-editor" style="width: 100%">
            <el-input v-model="form.content" type="textarea" :rows="25" placeholder="HTML 内容，支持 CSS 样式" class="vjs-textarea" style="font-family: 'SF Mono', 'Monaco', 'Menlo', 'Consolas', monospace; font-size: 13px; line-height: 1.6; color: #e4e4e7; background: #1e293b; width: 100%" :readonly="currentPage?.is_default" v-html="currentPage?.is_default ? highlightHtml(form.content) : undefined" />
          </div>
          <div class="form-tip-inline" style="display: block; margin-top: 4px; margin-left: 0;">
            {{ currentPage?.is_default ? '默认页面内容只读，仅可查看' : '拦截时返回给客户端的 HTML 页面，支持内联 CSS 样式' }}
          </div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button v-if="!currentPage?.is_default" type="primary" :loading="saving" @click="handleSave">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="previewVisible" title="拦截页面预览" width="min(960px, 94vw)" top="3vh">
      <div v-html="previewContent" style="border: 1px solid #e4e7ed; border-radius: 6px; overflow: hidden; aspect-ratio: 16/9; display: flex; align-items: center; justify-content: center; background: #f9fafb" />
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { Plus, Document } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { request } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import { formatDate } from '@/utils/date'
import type { UserListItem } from '@/types'

interface APIResponse<T> { code: number; message: string; data: T }
interface BlockPage { id: number; name: string; description: string; content: string; is_default: boolean; created_at: string; updated_at: string; updated_by: number }

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.user?.role !== 'admin')

const loading = ref(false)
const saving = ref(false)
const users = ref<UserListItem[]>([])
const pages = ref<BlockPage[]>([])
const dialogVisible = ref(false)
const previewVisible = ref(false)
const previewContent = ref('')
const editingId = ref<number | null>(null)
const currentPage = ref<BlockPage | null>(null)

const form = ref({ name: '', description: '', content: '' })

const fetchData = async () => {
  loading.value = true
  try {
    const [pagesRes, usersRes] = await Promise.all([
      request.get<APIResponse<BlockPage[]>>('/security/block-pages'),
      request.get<APIResponse<UserListItem[]>>('/users'),
    ])
    pages.value = pagesRes.data || []
    users.value = usersRes.data || []
  } catch { ElMessage.error('加载数据失败') } finally { loading.value = false }
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
    form.value = { name: row.name, description: row.description, content: row.content }
  } else {
    form.value = { name: '', description: '', content: '' }
  }
  dialogVisible.value = true
}
const handleSave = async () => {
  if (!form.value.name.trim()) { ElMessage.warning('请输入页面名称'); return }
  saving.value = true
  try {
    if (editingId.value) {
      await request.put(`/security/block-pages/${editingId.value}`, form.value)
    } else {
      await request.post('/security/block-pages', form.value)
    }
    ElMessage.success('保存成功')
    dialogVisible.value = false
    fetchData()
  } catch { ElMessage.error('保存失败') } finally { saving.value = false }
}

const handleDelete = (row: BlockPage) => {
  ElMessageBox.confirm(`确定删除拦截页面"${row.name}"？`, '确认', { type: 'warning' })
    .then(async () => { await request.delete(`/security/block-pages/${row.id}`); ElMessage.success('已删除'); fetchData() }).catch(() => {})
}

const previewPage = (row: BlockPage) => {
  previewContent.value = row.content || '<p style="color: #999; padding: 20px; text-align: center">(空内容)</p>'
  previewVisible.value = true
}

const highlightHtml = (text: string): string => {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/&lt;\/?(html|head|body|title|meta|style|div|h1|h2|h3|h4|h5|h6|p|span|a|img|br|hr|table|tr|td|th|ul|ol|li|form|input|button|textarea|select|option|label|fieldset|legend|section|article|aside|header|footer|nav|main|figure|figcaption|blockquote|pre|code|em|strong|b|i|u|s|del|ins|mark|small|sub|sup|abbr|cite|q|dfn|kbd|samp|var|time|address|data|details|summary|dialog|menu|menuitem|object|embed|iframe|video|audio|source|track|canvas|svg|path|circle|rect|line|polyline|polygon|ellipse|g|text|tspan|defs|marker|pattern|mask|clipPath|linearGradient|radialGradient|stop|use|symbol|image|filter|feGaussianBlur|feColorMatrix|feOffset|feMerge|feMergeNode|feComposite|feBlend|feFlood|feComponentTransfer|feFuncA|feFuncR|feFuncG|feFuncB|feDisplacementMap|feDropShadow|feTurbulence|feTile|feImage|feMorphology|feConvolveMatrix|feSpecularLighting|feDistantLight|fePointLight|feSpotLight|feSpecularColor|feSpecularConstant|feSpecularExponent|feDiffuseLighting|feDiffuseConstant|feSurfaceScale|feLightingColor|feSpotLight|fePointLight|feDistantLight)\b/g, '<span class="hl-tag">&lt;$1</span>')
    .replace(/\b(class|id|style|href|src|alt|title|width|height|color|background|font-family|font-size|font-weight|text-align|text-decoration|margin|padding|border|border-radius|display|flex|align-items|justify-content|position|top|left|right|bottom|z-index|opacity|visibility|overflow|cursor|transition|transform|animation|box-shadow|text-shadow|letter-spacing|line-height|white-space|word-break|vertical-align|float|clear|content|quotes|counter-reset|counter-increment|list-style|outline|resize|user-select|pointer-events|clip-path|filter|backdrop-filter|mix-blend-mode|isolation|aspect-ratio|object-fit|object-position|perspective|backface-visibility|transform-style|transform-origin|will-change|touch-action|appearance|column-count|column-gap|column-rule|column-width|break-inside|break-before|break-after|grid-template-columns|grid-template-rows|grid-template-areas|grid-auto-flow|grid-auto-columns|grid-auto-rows|grid-column|grid-row|grid-area|grid-column-start|grid-column-end|grid-row-start|grid-row-end|justify-self|align-self|place-items|place-content|place-self|order|flex-direction|flex-wrap|flex-flow|flex-grow|flex-shrink|flex-basis|gap|row-gap|column-gap|inset|inset-block|inset-inline|inset-block-start|inset-block-end|inset-inline-start|inset-inline-end|scroll-behavior|scroll-snap-type|scroll-snap-align|scroll-margin|scroll-padding|overscroll-behavior|scrollbar-width|scrollbar-color|scrollbar-gutter|touch-action|user-select|pointer-events|caret-color|accent-color|color-scheme|forced-color-adjust|print-color-adjust|color-adjust|image-rendering|image-resolution|image-orientation|writing-mode|text-orientation|text-combine-upright|text-decoration-line|text-decoration-color|text-decoration-style|text-decoration-thickness|text-underline-offset|text-underline-position|text-emphasis|text-emphasis-color|text-emphasis-style|text-emphasis-position|text-indent|text-transform|text-rendering|text-size-adjust|font-feature-settings|font-variation-settings|font-kerning|font-variant|font-variant-caps|font-variant-east-asian|font-variant-ligatures|font-variant-numeric|font-variant-position|font-stretch|font-optical-sizing|font-palette|font-synthesis|font-language-override|font-size-adjust|font-display|font-loading-api|unicode-bidi|direction|dominant-baseline|alignment-baseline|baseline-shift|glyph-orientation-horizontal|glyph-orientation-vertical|text-anchor|paint-order|marker-start|marker-mid|marker-end|stroke|stroke-width|stroke-linecap|stroke-linejoin|stroke-miterlimit|stroke-dasharray|stroke-dashoffset|stroke-opacity|fill|fill-opacity|fill-rule|clip-rule|color-interpolation|color-interpolation-filters|lighting-color|flood-color|flood-opacity|stop-color|stop-opacity|vector-effect|visibility|pointer-events|cursor|shape-rendering|text-rendering|image-rendering|color-rendering|color-profile|rendering-intent|enable-background|accumulate|additive|calculationMode|keySplines|keyTimes|keyPoints|rotate|from|to|by|values|begin|dur|end|min|max|restart|repeatCount|repeatDur|fill|begin|end|min|max|restart|repeatCount|repeatDur|fill|accumulate|additive|calculationMode|keySplines|keyTimes|keyPoints|rotate|from|to|by|values)\s*=/g, '<span class="hl-attr">$1</span>=')
    .replace(/"([^"]*)"/g, '<span class="hl-value">"$1"</span>')
    .replace(/'([^']*)'/g, "<span class=\"hl-value\">'$1'</span>")
    .replace(/\/\*[\s\S]*?\*\//g, '<span class="hl-comment">$&</span>')
    .replace(/<!--[\s\S]*?-->/g, '<span class="hl-comment">$&</span>')
    .replace(/\b(html|head|body|title|meta|style|div|h1|h2|h3|h4|h5|h6|p|span|a|img|br|hr|table|tr|td|th|ul|ol|li|form|input|button|textarea|select|option|label|fieldset|legend|section|article|aside|header|footer|nav|main|figure|figcaption|blockquote|pre|code|em|strong|b|i|u|s|del|ins|mark|small|sub|sup|abbr|cite|q|dfn|kbd|samp|var|time|address|data|details|summary|dialog|menu|menuitem|object|embed|iframe|video|audio|source|track|canvas|svg|path|circle|rect|line|polyline|polygon|ellipse|g|text|tspan|defs|marker|pattern|mask|clipPath|linearGradient|radialGradient|stop|use|symbol|image|filter|feGaussianBlur|feColorMatrix|feOffset|feMerge|feMergeNode|feComposite|feBlend|feFlood|feComponentTransfer|feFuncA|feFuncR|feFuncG|feFuncB|feDisplacementMap|feDropShadow|feTurbulence|feTile|feImage|feMorphology|feConvolveMatrix|feSpecularLighting|feDistantLight|fePointLight|feSpotLight|feSpecularColor|feSpecularConstant|feSpecularExponent|feDiffuseLighting|feDiffuseConstant|feSurfaceScale|feLightingColor|feSpotLight|fePointLight|feDistantLight)\b(?!\s*[=<>])/g, '<span class="hl-tag">$1</span>')
    .replace(/\b(color|background|font-family|font-size|font-weight|text-align|text-decoration|margin|padding|border|border-radius|display|flex|align-items|justify-content|position|top|left|right|bottom|z-index|opacity|visibility|overflow|cursor|transition|transform|animation|box-shadow|text-shadow|letter-spacing|line-height|white-space|word-break|vertical-align|float|clear|content|quotes|counter-reset|counter-increment|list-style|outline|resize|user-select|pointer-events|clip-path|filter|backdrop-filter|mix-blend-mode|isolation|aspect-ratio|object-fit|object-position|perspective|backface-visibility|transform-style|transform-origin|will-change|touch-action|appearance|column-count|column-gap|column-rule|column-width|break-inside|break-before|break-after|grid-template-columns|grid-template-rows|grid-template-areas|grid-auto-flow|grid-auto-columns|grid-auto-rows|grid-column|grid-row|grid-area|grid-column-start|grid-column-end|grid-row-start|grid-row-end|justify-self|align-self|place-items|place-content|place-self|order|flex-direction|flex-wrap|flex-flow|flex-grow|flex-shrink|flex-basis|gap|row-gap|column-gap|inset|inset-block|inset-inline|inset-block-start|inset-block-end|inset-inline-start|inset-inline-end|scroll-behavior|scroll-snap-type|scroll-snap-align|scroll-margin|scroll-padding|overscroll-behavior|scrollbar-width|scrollbar-color|scrollbar-gutter|touch-action|user-select|pointer-events|caret-color|accent-color|color-scheme|forced-color-adjust|print-color-adjust|color-adjust|image-rendering|image-resolution|image-orientation|writing-mode|text-orientation|text-combine-upright|text-decoration-line|text-decoration-color|text-decoration-style|text-decoration-thickness|text-underline-offset|text-underline-position|text-emphasis|text-emphasis-color|text-emphasis-style|text-emphasis-position|text-indent|text-transform|text-rendering|text-size-adjust|font-feature-settings|font-variation-settings|font-kerning|font-variant|font-variant-caps|font-variant-east-asian|font-variant-ligatures|font-variant-numeric|font-variant-position|font-stretch|font-optical-sizing|font-palette|font-synthesis|font-language-override|font-size-adjust|font-display|font-loading-api|unicode-bidi|direction|dominant-baseline|alignment-baseline|baseline-shift|glyph-orientation-horizontal|glyph-orientation-vertical|text-anchor|paint-order|marker-start|marker-mid|marker-end|stroke|stroke-width|stroke-linecap|stroke-linejoin|stroke-miterlimit|stroke-dasharray|stroke-dashoffset|stroke-opacity|fill|fill-opacity|fill-rule|clip-rule|color-interpolation|color-interpolation-filters|lighting-color|flood-color|flood-opacity|stop-color|stop-opacity|vector-effect|visibility|pointer-events|cursor|shape-rendering|text-rendering|image-rendering|color-rendering|color-profile|rendering-intent|enable-background)\s*:/g, '<span class="hl-attr">$1</span>:')
}

onMounted(fetchData)
</script>

<style scoped>
.block-content-editor { border: 1px solid #e4e7ed; border-radius: 6px; overflow: hidden; }
.vjs-textarea { border-radius: 6px; }
.vjs-textarea :deep(.el-textarea__inner) { background: #1e293b; color: #e4e4e7; border: none; }
.vjs-textarea :deep(.el-textarea__inner):focus { background: #1e293b; color: #e4e4e7; border: none; box-shadow: none; }
.hl-tag { color: #7dd3fc; }
.hl-attr { color: #f472b6; }
.hl-value { color: #86efac; }
.hl-comment { color: #64748b; font-style: italic; }
.block-page-form .content-form-item .el-form-item__content { flex: 1; max-width: 100%; }
.form-tip-inline { font-size: 12px; color: #9ca3af; margin-left: 8px; vertical-align: middle; line-height: 1; }
.block-page-form .form-tip-inline { display: block; margin-top: 4px; margin-left: 0; }
</style>
