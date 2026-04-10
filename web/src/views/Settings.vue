<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Setting /></el-icon>
          系统设置
        </h2>
        <p class="page-desc">配置系统参数、证书提供者和行为选项</p>
      </div>
    </div>

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
          </el-form>
        </el-card>

        <el-card class="settings-card" style="margin-top: 20px;">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon><Connection /></el-icon>
                <span>集群设置</span>
              </div>
            </div>
          </template>
          <el-form :model="settings" label-width="120px" class="settings-form">
            <el-form-item label="节点模式">
              <el-radio-group v-model="settings.is_master" :disabled="!isAdmin">
                <el-radio :true-value="true" :false-value="false">主节点</el-radio>
                <el-radio :true-value="false" :false-value="true">从节点</el-radio>
              </el-radio-group>
              <div class="form-tip">主节点管理负载均衡规则，从节点同步配置</div>
            </el-form-item>
            <el-form-item label="主节点地址" v-if="!settings.is_master">
              <el-input v-model="settings.master_url" placeholder="http://192.168.1.1:8000" />
              <div class="form-tip">从节点需要连接到主节点</div>
            </el-form-item>
            <el-form-item label="同步间隔">
              <el-input-number v-model="settings.sync_interval" :min="10" :max="3600" />
              <div class="form-tip">从节点同步配置的间隔（秒）</div>
            </el-form-item>
          </el-form>
        </el-card>
      </el-col>

      <el-col :span="12">
        <el-card class="settings-card">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon><Lock /></el-icon>
                <span>免费证书配置</span>
              </div>
              <el-button v-if="authStore.nodeMode === 'master'" size="small" type="primary" @click="openCertConfigDialog()">
                <el-icon><Plus /></el-icon>添加
              </el-button>
            </div>
          </template>
          <el-table :data="certConfigs" size="small" v-if="certConfigs.length > 0">
            <el-table-column prop="name" label="名称" />
            <el-table-column prop="acme_email" label="ACME 邮箱" />
            <el-table-column prop="enabled" label="状态" width="60" align="center">
              <template #default="{ row }">
                <el-tag :type="row.enabled ? 'success' : 'info'" size="small">{{ row.enabled ? '启用' : '禁用' }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column v-if="authStore.nodeMode === 'master'" label="操作" width="80" align="center">
              <template #default="{ row }">
                <el-button type="primary" link size="small" @click="openCertConfigDialog(row)">编辑</el-button>
                <el-button type="danger" link size="small" @click="deleteCertConfig(row)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
          <el-empty v-else description="暂无证书配置" :image-size="60" />
        </el-card>

        <el-card class="info-card" style="margin-top: 20px;">
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
            <el-button type="warning" size="small" @click="handleReloadCaddy">
              <el-icon><RefreshRight /></el-icon>重载 Caddy
            </el-button>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <div class="save-bar">
      <el-button type="primary" size="large" @click="handleSave" :loading="saving">
        <el-icon><Check /></el-icon>保存设置
      </el-button>
    </div>

    <el-dialog v-model="certConfigDialogVisible" :title="editingCertConfigId ? '编辑证书配置' : '添加证书配置'" width="500">
      <el-form :model="certConfigForm" label-width="100px">
        <el-form-item label="配置名称" required>
          <el-input v-model="certConfigForm.name" placeholder="例如：我的证书配置" />
        </el-form-item>
        <el-form-item label="ACME 邮箱" required>
          <el-input v-model="certConfigForm.acme_email" placeholder="your@email.com" />
          <div class="form-tip">用于 Let's Encrypt 证书申请和到期通知</div>
        </el-form-item>
        <el-form-item label="DNS 提供商">
          <el-input value="DNSPod (腾讯云)" disabled />
        </el-form-item>
        <el-form-item label="DNSPod ID">
          <el-input v-model="certConfigForm.dns_id" placeholder="DNSPod API ID" />
        </el-form-item>
        <el-form-item label="DNSPod Key">
          <el-input v-model="certConfigForm.dns_key" placeholder="DNSPod API Token" type="password" show-password />
        </el-form-item>
        <el-form-item label="启用">
          <el-switch v-model="certConfigForm.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="certConfigDialogVisible = false">取消</el-button>
        <el-button type="primary" @click="saveCertConfig">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { request } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Setting, Connection, Lock, InfoFilled, WarningFilled, RefreshRight, Check, Plus } from '@element-plus/icons-vue'

interface CertConfig {
  id?: number
  name: string
  acme_email: string
  dns_provider: string
  dns_id: string
  dns_key: string
  enabled: boolean
}

const authStore = useAuthStore()

const saving = ref(false)
const isAdmin = computed(() => authStore.user?.role === 'admin')

const settings = ref({
  dns_provider: 'dnspod',
  dns_credentials: '',
  letsencrypt_email: '',
  log_level: 'info',
  access_log_enabled: true,
  is_master: true,
  master_url: '',
  sync_interval: 60,
})

const certConfigs = ref<CertConfig[]>([])
const certConfigDialogVisible = ref(false)
const certConfigForm = ref<CertConfig>({
  name: '',
  acme_email: '',
  dns_provider: 'dnspod',
  dns_id: '',
  dns_key: '',
  enabled: true,
})
const editingCertConfigId = ref<number | null>(null)

const fetchSettings = async () => {
  try {
    const res = await request.get('/config')
    if (res.data) {
      settings.value = {
        dns_provider: res.data.dns_provider || 'dnspod',
        dns_credentials: res.data.dns_credentials || '',
        letsencrypt_email: res.data.letsencrypt_email || '',
        log_level: res.data.log_level || 'info',
        access_log_enabled: res.data.access_log_enabled ?? true,
        is_master: res.data.is_master ?? true,
        master_url: res.data.master_url || '',
        sync_interval: res.data.sync_interval || 60,
      }
    }
  } catch (error) {
    console.error('Failed to fetch settings:', error)
  }
}

const handleSave = async () => {
  saving.value = true
  try {
    await request.put('/config', {
      dns_provider: settings.value.dns_provider,
      dns_credentials: settings.value.dns_credentials,
      letsencrypt_email: settings.value.letsencrypt_email,
      log_level: settings.value.log_level,
      access_log_enabled: settings.value.access_log_enabled,
      is_master: settings.value.is_master,
      master_url: settings.value.master_url,
      sync_interval: settings.value.sync_interval,
    })
    ElMessage.success('保存成功')
  } catch (error) {
    console.error('Failed to save settings:', error)
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

const fetchCertConfigs = async () => {
  try {
    const res = await request.get('/certificate-configs')
    certConfigs.value = res.data || []
  } catch (error) {
    console.error('Failed to fetch cert configs:', error)
  }
}

const openCertConfigDialog = (config?: CertConfig) => {
  if (config) {
    editingCertConfigId.value = config.id || null
    certConfigForm.value = { ...config }
  } else {
    editingCertConfigId.value = null
    certConfigForm.value = {
      name: '',
      acme_email: '',
      dns_provider: 'dnspod',
      dns_id: '',
      dns_key: '',
      enabled: true,
    }
  }
  certConfigDialogVisible.value = true
}

const saveCertConfig = async () => {
  if (!certConfigForm.value.name || !certConfigForm.value.acme_email) {
    ElMessage.warning('请填写配置名称和 ACME 邮箱')
    return
  }
  try {
    if (editingCertConfigId.value) {
      await request.put(`/certificate-configs/${editingCertConfigId.value}`, certConfigForm.value)
      ElMessage.success('配置已更新')
    } else {
      await request.post('/certificate-configs', certConfigForm.value)
      ElMessage.success('配置已创建')
    }
    certConfigDialogVisible.value = false
    fetchCertConfigs()
  } catch (error) {
    console.error('Failed to save cert config:', error)
  }
}

const deleteCertConfig = async (config: CertConfig) => {
  try {
    await ElMessageBox.confirm(`确定要删除配置 "${config.name}" 吗？`, '删除确认', { type: 'warning' })
    await request.delete(`/certificate-configs/${config.id}`)
    ElMessage.success('配置已删除')
    fetchCertConfigs()
  } catch (error) {
    if (error !== 'cancel') {
      console.error('Failed to delete cert config:', error)
    }
  }
}

onMounted(() => {
  fetchSettings()
  fetchCertConfigs()
})
</script>

<style scoped>
.page { max-width: 1200px; margin: 0 auto; }

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

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

.card-header {
  display: flex;
  align-items: center;
}

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
.info-value { color: #111827; font-size: 13px; }

.danger-actions { display: flex; gap: 12px; }

.save-bar {
  margin-top: 24px;
  padding-top: 20px;
  border-top: 1px solid #e5e7eb;
  display: flex;
  justify-content: flex-end;
}
</style>