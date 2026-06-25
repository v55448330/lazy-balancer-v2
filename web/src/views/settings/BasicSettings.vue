<template>
  <el-row :gutter="20">
    <el-col :span="12">
      <el-card class="settings-card">
        <template #header>
          <div class="card-header">
            <div class="card-title">
              <el-icon><Setting /></el-icon>
              <span>基础设置</span>
            </div>
          </div>
        </template>
        <el-form :model="settings" label-width="120px" class="settings-form">
          <el-form-item label="日志级别">
            <el-select v-model="settings.log_level" style="width: 100%">
              <el-option label="Debug" value="debug" />
              <el-option label="Info" value="info" />
              <el-option label="Warning" value="warn" />
              <el-option label="Error" value="error" />
            </el-select>
            <div class="form-tip">控制日志详细程度</div>
          </el-form-item>
          <el-form-item label="访问日志">
            <el-switch v-model="settings.access_log_enabled" />
            <div class="form-tip">记录所有 HTTP 请求到日志</div>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="saving" @click="handleSave">
              <el-icon><Check /></el-icon>
              <span class="btn-text">保存</span>
            </el-button>
          </el-form-item>
        </el-form>
      </el-card>
    </el-col>

    <el-col :span="12">
      <el-card class="info-card">
        <template #header>
          <div class="card-header">
            <div class="card-title">
              <el-icon><InfoFilled /></el-icon>
              <span>系统信息</span>
            </div>
          </div>
        </template>
        <div class="info-list">
          <div class="info-item">
            <span class="info-label">版本</span>
            <el-tag type="info" size="small">2.0.0</el-tag>
          </div>
          <div class="info-item">
            <span class="info-label">运行模式</span>
            <el-tag :type="authStore.nodeMode === 'master' ? 'success' : 'warning'" size="small">
              {{ authStore.nodeMode === 'master' ? '主节点' : '从节点' }}
            </el-tag>
          </div>
        </div>
      </el-card>

      <el-card class="action-card" style="margin-top: 20px;">
        <template #header>
          <div class="card-header">
            <div class="card-title danger">
              <el-icon><WarningFilled /></el-icon>
              <span>危险操作</span>
            </div>
          </div>
        </template>
        <div class="danger-actions">
          <el-button type="warning" @click="handleReloadCaddy">
            <el-icon><RefreshRight /></el-icon>
            <span class="btn-text">重载 Caddy</span>
          </el-button>
        </div>
      </el-card>
    </el-col>
  </el-row>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { ElMessage, ElMessageBox } from 'element-plus'
import { request } from '@/utils/api'
import { Setting, InfoFilled, WarningFilled, RefreshRight, Check } from '@element-plus/icons-vue'

const authStore = useAuthStore()

const settings = defineModel<any>('settings', { required: true })
const emit = defineEmits<{
  (e: 'save'): void
}>()

const saving = ref(false)

const handleSave = async () => {
  saving.value = true
  try {
    await request.put('/config', {
      log_level: settings.value.log_level,
      access_log_enabled: settings.value.access_log_enabled,
    })
    ElMessage.success('保存成功')
    emit('save')
  } catch (error) {
    console.error('Failed to save basic settings:', error)
  } finally {
    saving.value = false
  }
}

const handleReloadCaddy = async () => {
  try {
    await ElMessageBox.confirm(
      '此操作将重新加载 Caddy 配置，是否继续？',
      '确认重载',
      {
        confirmButtonText: '确认',
        cancelButtonText: '取消',
        type: 'warning',
      }
    )
    await request.post('/config/reload')
    ElMessage.success('Caddy 配置已重载')
  } catch (error) {
    if (error !== 'cancel') {
      console.error('Failed to reload Caddy:', error)
    }
  }
}
</script>

<style scoped>
.card-header { display: flex; align-items: center; }
.card-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 14px;
  font-weight: 600;
  color: #111827;
}
.card-title.danger { color: #dc2626; }
.settings-form { padding: 4px 0; }
.form-tip {
  font-size: 12px;
  color: #9ca3af;
  margin-top: 4px;
}
.info-list { padding: 4px 0; }
.info-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 0;
  border-bottom: 1px solid #f3f4f6;
}
.info-item:last-child { border-bottom: none; }
.info-label { color: #6b7280; font-size: 13px; }
.danger-actions { display: flex; gap: 12px; }
.btn-text { margin-left: 4px; }
</style>
