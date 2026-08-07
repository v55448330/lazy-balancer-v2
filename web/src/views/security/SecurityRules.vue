<template>
  <div class="p-6">
    <h2 class="text-xl font-semibold text-gray-800 mb-4">规则集</h2>

    <el-card class="mb-4">
      <template #header><span class="font-medium">OWASP CRS</span></template>
      <el-descriptions :column="2" border>
        <el-descriptions-item label="版本">{{ crsInfo.version || '—' }}</el-descriptions-item>
        <el-descriptions-item label="规则数">{{ crsInfo.rule_count || 0 }} 条</el-descriptions-item>
        <el-descriptions-item label="自动更新">
          <el-switch v-model="crsInfo.auto_update" :disabled="isReadOnly" @change="toggleAutoUpdate" />
        </el-descriptions-item>
        <el-descriptions-item label="最后检查">{{ crsInfo.last_checked || '—' }}</el-descriptions-item>
      </el-descriptions>
    </el-card>

    <el-alert type="info" :closable="false" class="mb-4">
      CRS 规则随 Docker 镜像版本发布，当前版本内置 v4.14.0。自动更新功能将在后续版本中支持。
    </el-alert>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { request } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'

interface APIResponse<T> { code: number; message: string; data: T }

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.user?.role !== 'admin')

const crsInfo = ref({ version: '', auto_update: true, last_checked: '', rule_count: 0 })

const fetchCRS = async () => {
  try {
    const res = await request.get<APIResponse<typeof crsInfo.value>>('/security/crs')
    if (res.data) crsInfo.value = res.data
  } catch { /* silent */ }
}

const toggleAutoUpdate = async (val: boolean) => {
  try {
    await request.put('/security/crs/auto-update', { auto_update: val })
    ElMessage.success('已更新')
  } catch { ElMessage.error('更新失败') }
}

onMounted(fetchCRS)
</script>
