<template>
  <div class="page" :class="{ 'hide-header': hideHeader }">
    <div v-if="!hideHeader" class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Key /></el-icon>
          API 密钥
        </h2>
        <p class="page-desc">管理 API 访问密钥，用于程序化访问</p>
      </div>
      <el-button type="primary" @click="createKey">
        <el-icon><Plus /></el-icon>
        创建密钥
      </el-button>
    </div>

    <div v-else class="toolbar">
      <el-button type="primary" @click="createKey">
        <el-icon><Plus /></el-icon>
        创建密钥
      </el-button>
    </div>

    <el-row :gutter="20">
      <el-col v-for="key in keys" :key="key.id" :span="8" class="key-col">
        <el-card class="key-card">
          <div class="key-header">
            <div class="key-icon">
              <el-icon><Key /></el-icon>
            </div>
            <div class="key-info">
              <div class="key-name">{{ key.name }}</div>
              <div class="key-date">创建于 {{ formatDateShort(key.created_at) || '-' }}</div>
            </div>
          </div>
          <el-divider />
          <div class="key-value">
            <span v-if="!key.showKey" class="key-masked">••••••••••••••••</span>
            <span v-else class="key-text">{{ key.key }}</span>
          </div>
          <div class="key-actions">
            <el-button size="small" @click="key.showKey = !key.showKey">
              <el-icon><View v-if="!key.showKey" /><Hide v-else /></el-icon>
              {{ key.showKey ? '隐藏' : '显示' }}
            </el-button>
            <el-button size="small" type="danger" @click="deleteKey(key.id)">
              <el-icon><Delete /></el-icon>
            </el-button>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-card v-if="keys.length === 0" class="empty-card">
      <el-empty description="暂无 API 密钥" :image-size="80">
        <el-button type="primary" @click="createKey">创建第一个密钥</el-button>
      </el-empty>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { request } from '@/utils/api'
import { formatDateShort } from '@/utils/date'
import { ElMessageBox, ElMessage } from 'element-plus'
import { Key, Plus, View, Hide, Delete } from '@element-plus/icons-vue'

defineProps<{
  hideHeader?: boolean
}>()

defineExpose({
  createKey,
})

const keys = ref<any[]>([])

const fetchKeys = async () => {
  const res = await request.get('/keys')
  keys.value = (res.data || []).map((k: any) => ({ ...k, showKey: false }))
}

async function createKey() {
  const { value: name } = await ElMessageBox.prompt('请输入密钥名称', '创建 API 密钥', {
    confirmButtonText: '创建',
    cancelButtonText: '取消',
  })
  if (!name) return

  const res = await request.post('/keys', { name })
  ElMessage.success('密钥创建成功')
  if (res.data?.key) {
    ElMessageBox.alert(`密钥: ${res.data.key}`, '请妥善保存', { confirmButtonText: '确定' })
  }
  fetchKeys()
}

const deleteKey = async (id: number) => {
  await ElMessageBox.confirm('确定要删除这个 API 密钥吗？删除后无法恢复。', '警告', { type: 'warning' })
  await request.delete(`/keys/${id}`)
  ElMessage.success('删除成功')
  fetchKeys()
}

onMounted(() => {
  fetchKeys()
})
</script>

<style scoped>
.page { max-width: 1500px; margin: 0 auto; }

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.toolbar {
  display: flex;
  justify-content: flex-end;
  margin-bottom: 20px;
}

.hide-header .page-header,
.hide-header .toolbar { display: none; }

.header-left { flex: 1; }

.page-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 18px;
  font-weight: 600;
  color: #111827;
  margin: 0;
}

.title-icon { color: #3b82f6; font-size: 20px; }

.page-desc {
  font-size: 13px;
  color: #6b7280;
  margin: 4px 0 0 28px;
}

.key-col { margin-bottom: 20px; }

.key-card { }

.key-header { display: flex; align-items: center; gap: 12px; }

.key-icon {
  width: 40px;
  height: 40px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #fef3c7;
  color: #d97706;
  font-size: 18px;
}

.key-info { flex: 1; }

.key-name { font-weight: 600; color: #111827; font-size: 14px; margin-bottom: 2px; }
.key-date { font-size: 12px; color: #9ca3af; }

.key-value {
  background: #f9fafb;
  padding: 12px;
  border-radius: 6px;
  margin: 12px 0;
  text-align: center;
}

.key-masked { color: #9ca3af; font-family: monospace; }
.key-text { color: #111827; font-family: 'SF Mono', monospace; font-size: 12px; word-break: break-all; }

.key-actions { display: flex; justify-content: flex-end; gap: 8px; }

.empty-card { padding: 20px; }
</style>
