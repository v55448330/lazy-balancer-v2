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
            <el-button size="small" link :type="row.is_default ? 'info' : 'primary'" @click="openDialog(row)">{{ row.is_default ? '查看' : '编辑' }}</el-button>
            <el-button size="small" link type="danger" :disabled="row.is_default" @click="handleDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="dialogVisible" :title="dialogTitle" width="960px" top="3vh">
      <el-form :model="form" label-width="80px" label-position="right" class="block-page-form">
        <el-form-item label="名称" required>
          <el-input v-model="form.name" placeholder="页面名称" :readonly="currentPage?.is_default" />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="form.description" placeholder="页面描述" :readonly="currentPage?.is_default" />
        </el-form-item>
        <el-form-item label="内容" class="content-form-item">
          <div class="block-content-editor" style="width: 100%">
            <SyntaxHighlight v-if="currentPage?.is_default" :content="form.content" language="markup" height="520px" />
            <CodeEditor v-else v-model="form.content" language="markup" height="520px" placeholder="HTML 内容，支持内联 CSS 样式" />
          </div>
          <div class="form-tip-line">
            {{ currentPage?.is_default ? '默认页面内容只读，仅可查看' : '拦截时返回给客户端的 HTML 页面，支持内联 CSS 样式' }}
          </div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button v-if="!currentPage?.is_default" type="primary" :loading="saving" @click="handleSave">保存</el-button>
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
import type { UserListItem } from '@/types'

interface APIResponse<T> { code: number; message: string; data: T }
interface BlockPage { id: number; name: string; description: string; content: string; is_default: boolean; updated_at: string; updated_by: number }

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.readOnlyReason !== null)

const loading = ref(false)
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
  return currentPage.value?.is_default ? '查看拦截页面' : '编辑拦截页面'
})

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
    const res = editingId.value
      ? await request.put(`/security/block-pages/${editingId.value}`, form.value)
      : await request.post('/security/block-pages', form.value)
    showSaveResult(res, '保存成功')
    dialogVisible.value = false
    await fetchData()
  } catch { ElMessage.error('保存失败') } finally { saving.value = false }
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
.block-content-editor { border: 1px solid #e4e7ed; border-radius: 6px; overflow: hidden; }
.block-page-form .content-form-item .el-form-item__content { flex: 1; max-width: 100%; }
</style>
