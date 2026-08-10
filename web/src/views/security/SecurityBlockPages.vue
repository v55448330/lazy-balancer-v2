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
            <el-link :type="row.is_default ? 'info' : 'primary'" @click="previewPage(row)">{{ row.name }}{{ row.is_default ? ' (默认)' : '' }}</el-link>
          </template>
        </el-table-column>
        <el-table-column prop="description" label="描述" min-width="280" show-overflow-tooltip />
        <el-table-column label="默认" width="90" align="center">
          <template #default="{ row }">
            <el-tag v-if="row.is_default" type="success" size="small" effect="light">默认</el-tag>
            <span v-else class="text-secondary">—</span>
          </template>
        </el-table-column>
        <el-table-column v-if="!isReadOnly" label="操作" width="200" fixed="right">
          <template #default="{ row }">
            <el-button size="small" link type="primary" @click="previewPage(row)">预览</el-button>
            <el-button size="small" link :type="row.is_default ? 'info' : 'primary'" @click="openDialog(row)">编辑</el-button>
            <el-button v-if="!row.is_default" size="small" link type="danger" @click="handleDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="dialogVisible" :title="editingId ? (currentPage?.is_default ? '编辑默认拦截页面' : '编辑拦截页面') : '新建拦截页面'" width="860px" top="5vh">
      <el-form :model="form" label-width="80px" label-position="right">
        <el-form-item label="名称" required>
          <el-input v-model="form.name" placeholder="页面名称" />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="form.description" placeholder="页面描述" />
        </el-form-item>
        <el-form-item label="内容">
          <div class="block-content-editor">
            <el-input v-model="form.content" type="textarea" :rows="25" placeholder="HTML 内容，支持 CSS 样式" class="vjs-textarea" style="font-family: 'SF Mono', 'Monaco', 'Menlo', 'Consolas', monospace; font-size: 13px; line-height: 1.6; color: #e4e4e7; background: #1e1e2e" :readonly="currentPage?.is_default" />
          </div>
          <div class="text-secondary mt-1">
            {{ currentPage?.is_default ? '默认页面内容只读，可修改名称和描述' : '拦截时返回给客户端的 HTML 页面，支持内联 CSS 样式' }}
          </div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="handleSave">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="previewVisible" title="拦截页面预览" width="800px" top="5vh">
      <div v-html="previewContent" style="border: 1px solid #e4e7ed; border-radius: 6px; overflow: hidden" />
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { Plus, Document } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { request } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'

interface APIResponse<T> { code: number; message: string; data: T }
interface BlockPage { id: number; name: string; description: string; content: string; is_default: boolean }

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.user?.role !== 'admin')

const loading = ref(false)
const saving = ref(false)
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
    const res = await request.get<APIResponse<BlockPage[]>>('/security/block-pages')
    pages.value = res.data || []
  } catch { ElMessage.error('加载数据失败') } finally { loading.value = false }
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

onMounted(fetchData)
</script>

<style scoped>
.block-content-editor { border: 1px solid #e4e7ed; border-radius: 6px; overflow: hidden; }
.vjs-textarea { border-radius: 6px; }
</style>
