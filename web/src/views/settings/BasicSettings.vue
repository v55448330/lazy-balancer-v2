<template>
  <div>
    <el-alert v-if="isReadOnly" :title="authStore.readOnlyMessage" type="info" :closable="false" show-icon class="readonly-alert" />
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
        <el-form :model="settings" label-width="120px" class="settings-form" :disabled="isReadOnly">
          <el-form-item label="日志级别">
            <el-select v-model="settings.log_level" style="width: 100%">
              <el-option label="Debug" value="debug" />
              <el-option label="Info" value="info" />
              <el-option label="Warning" value="warn" />
              <el-option label="Error" value="error" />
            </el-select>
            <div class="form-tip">控制 Lazy Balancer 自身日志详细程度</div>
          </el-form-item>
          <el-form-item label="访问日志">
            <el-switch v-model="settings.access_log_enabled" />
            <div class="form-tip">记录所有 HTTP 请求到日志</div>
          </el-form-item>
          <el-form-item label="证书日志大小">
            <el-input-number v-model="settings.cert_job_log_size_mb" :min="1" :max="1024" controls-position="right" style="width: 120px;" />
            <span class="form-tip-inline">MB，单个证书签发日志文件达到该大小后滚动</span>
          </el-form-item>
          <el-form-item label="日志保留">
            <el-input-number v-model="settings.audit_retention_months" :min="1" :max="12" controls-position="right" style="width: 120px;" />
            <span class="form-tip-inline">个月，操作日志保留时间，超期自动清理（最短 1 个月）</span>
          </el-form-item>
          <el-form-item label="登录过期">
            <el-input-number v-model="settings.jwt_expire_minutes" :min="5" :max="1440" controls-position="right" style="width: 120px;" />
            <span class="form-tip-inline">分钟，登录令牌有效期，默认 20 分钟</span>
          </el-form-item>
          <el-form-item label="时区">
            <el-select v-model="settings.timezone" filterable style="width: 100%">
              <el-option label="Asia/Shanghai (UTC+8)" value="Asia/Shanghai" />
              <el-option label="Asia/Hong_Kong (UTC+8)" value="Asia/Hong_Kong" />
              <el-option label="Asia/Tokyo (UTC+9)" value="Asia/Tokyo" />
              <el-option label="Asia/Singapore (UTC+8)" value="Asia/Singapore" />
              <el-option label="Asia/Seoul (UTC+9)" value="Asia/Seoul" />
              <el-option label="Asia/Bangkok (UTC+7)" value="Asia/Bangkok" />
              <el-option label="Asia/Kolkata (UTC+5:30)" value="Asia/Kolkata" />
              <el-option label="Asia/Dubai (UTC+4)" value="Asia/Dubai" />
              <el-option label="Europe/London (UTC+0)" value="Europe/London" />
              <el-option label="Europe/Paris (UTC+1)" value="Europe/Paris" />
              <el-option label="Europe/Berlin (UTC+1)" value="Europe/Berlin" />
              <el-option label="Europe/Moscow (UTC+3)" value="Europe/Moscow" />
              <el-option label="America/New_York (UTC-5)" value="America/New_York" />
              <el-option label="America/Chicago (UTC-6)" value="America/Chicago" />
              <el-option label="America/Denver (UTC-7)" value="America/Denver" />
              <el-option label="America/Los_Angeles (UTC-8)" value="America/Los_Angeles" />
              <el-option label="America/Sao_Paulo (UTC-3)" value="America/Sao_Paulo" />
              <el-option label="Australia/Sydney (UTC+10)" value="Australia/Sydney" />
              <el-option label="UTC" value="UTC" />
            </el-select>
            <div class="form-tip">影响所有日志时间戳和证书时间；修改后需重启容器生效</div>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="saving" :disabled="isReadOnly" @click="handleSave">
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

    </el-col>
  </el-row>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { ElMessage, ElMessageBox } from 'element-plus'
import { request } from '@/utils/api'
import { Setting, InfoFilled, Check } from '@element-plus/icons-vue'

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.readOnlyReason !== null)

interface BasicSettingsConfig {
  log_level: string
  access_log_enabled: boolean
  cert_job_log_size_mb: number
  audit_retention_months: number
  jwt_expire_minutes: number
  timezone: string
}

interface ConfigPreviewResponse {
  data?: {
    changed: boolean
    section: string
    changes: string[]
  }
}

const settings = defineModel<BasicSettingsConfig>('settings', { required: true })
const emit = defineEmits<{
  (e: 'save'): void
}>()

const saving = ref(false)

const handleSave = async () => {
  if (isReadOnly.value) return
  if (saving.value) return
  saving.value = true
  try {
    const payload = {
      log_level: settings.value.log_level,
      access_log_enabled: settings.value.access_log_enabled,
      cert_job_log_size_mb: settings.value.cert_job_log_size_mb,
      audit_retention_months: settings.value.audit_retention_months,
      jwt_expire_minutes: settings.value.jwt_expire_minutes,
      timezone: settings.value.timezone,
      source: 'basic',
    }
    const preview = await request.post<ConfigPreviewResponse>('/config/preview', payload)
    if (preview.data?.changed) {
      const changes = preview.data.changes.length > 0 ? preview.data.changes.join('；') : '检测到配置变更'
      await ElMessageBox.confirm(changes, `确认保存${preview.data.section || '基础设置'}？`, {
        confirmButtonText: '确认',
        cancelButtonText: '取消',
        type: 'warning',
      })
    }
    await request.put('/config', payload)
    ElMessage.success('保存成功')
    emit('save')
  } catch (error) {
    console.error('Failed to save basic settings:', error)
  } finally {
    saving.value = false
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
.settings-form { padding: 4px 0; }
.form-tip {
  font-size: 12px;
  color: #9ca3af;
  margin-top: 4px;
}
.form-tip-inline {
  font-size: 12px;
  color: #9ca3af;
  margin-left: 8px;
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
.btn-text { margin-left: 4px; }
.readonly-alert { margin-bottom: 20px; }
</style>
