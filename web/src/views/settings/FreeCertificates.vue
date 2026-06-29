<template>
  <div>
    <el-card class="settings-card">
      <template #header>
        <div class="card-header">
          <span>ACME 全局设置</span>
        </div>
      </template>
      <el-form :model="global" label-width="140px">
        <el-form-item label="ACME 邮箱">
          <el-input v-model="global.acme_email" placeholder="your@email.com" />
        </el-form-item>
        <el-form-item label="过期提醒天数">
          <el-input-number v-model="global.cert_expiry_days" :min="1" :max="90" />
        </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="saving" @click="handleSave">
              <el-icon><Check /></el-icon>
              <span class="btn-text">保存</span>
            </el-button>
          </el-form-item>
      </el-form>
    </el-card>

    <el-card class="settings-card" style="margin-top: 20px">
      <template #header>
        <div class="card-header">
          <span>DNS 提供商配置</span>
          <el-button v-if="authStore.nodeMode === 'master'" type="primary" @click="openConfigDialog()">
            <el-icon><Plus /></el-icon>
            <span class="btn-text">添加</span>
          </el-button>
        </div>
      </template>
      <el-table v-if="configs.length > 0" :data="configs" size="small">
        <el-table-column prop="name" label="名称" />
        <el-table-column prop="dns_provider" label="提供商" />
        <el-table-column prop="enabled" label="状态" width="80" align="center">
          <template #default="{ row }">
            <el-tag :type="row.enabled ? 'success' : 'info'" size="small">{{ row.enabled ? '启用' : '禁用' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column v-if="authStore.nodeMode === 'master'" label="操作" width="180" align="center">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click="testConfig(row)">测试</el-button>
            <el-button link type="primary" size="small" @click="openConfigDialog(row)">编辑</el-button>
            <el-button link type="danger" size="small" @click="deleteConfig(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
      <el-empty v-else description="暂无 DNS 提供商配置" :image-size="60" />
    </el-card>

    <el-card class="settings-card" style="margin-top: 20px">
      <template #header>
        <span>签发任务</span>
      </template>
      <CertJobs />
    </el-card>

    <el-dialog v-model="dialogVisible" :title="editingId ? '编辑证书配置' : '添加证书配置'" width="520">
      <el-form :model="form" label-width="120px">
        <el-form-item label="配置名称" required>
          <el-input v-model="form.name" placeholder="例如：我的证书配置" />
        </el-form-item>
        <el-form-item label="DNS 提供商" required>
          <el-select v-model="form.dns_provider" style="width: 100%" @change="onProviderChange">
            <el-option v-for="p in providers" :key="p.code" :label="p.name" :value="p.code" />
          </el-select>
        </el-form-item>
        <template v-if="selectedProvider">
          <el-form-item v-for="field in selectedProvider.credential_fields" :key="field.name" :label="field.label">
            <el-input
              v-model="form.dns_credentials[field.name]"
              :type="field.type === 'password' ? 'password' : 'text'"
              :placeholder="field.placeholder || ''"
              show-password
            />
          </el-form-item>
        </template>
        <el-form-item label="启用">
          <el-switch v-model="form.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveConfig">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { request } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Check } from '@element-plus/icons-vue'
import CertJobs from './CertJobs.vue'

interface CredentialField {
  name: string
  label: string
  type: string
  required: boolean
  placeholder?: string
}

interface DNSProvider {
  code: string
  name: string
  credential_fields: CredentialField[]
}

interface CertConfig {
  id?: number
  name: string
  dns_provider: string
  enabled: boolean
}

const authStore = useAuthStore()

const global = defineModel<any>('global', { required: true })
const emit = defineEmits<{
  (e: 'save', payload?: any): void
}>()

const saving = ref(false)
const configs = ref<CertConfig[]>([])
const providers = ref<DNSProvider[]>([])
const dialogVisible = ref(false)
const editingId = ref<number | null>(null)
const form = ref<{
  name: string
  dns_provider: string
  dns_credentials: Record<string, string>
  enabled: boolean
}>({
  name: '',
  dns_provider: 'dnspod',
  dns_credentials: {},
  enabled: true,
})

const selectedProvider = computed(() => providers.value.find(p => p.code === form.value.dns_provider))

const fetchConfigs = async () => {
  try {
    const res = await request.get('/certificate-configs')
    configs.value = res.data || []
  } catch (error) {
    console.error('Failed to fetch cert configs:', error)
  }
}

const fetchProviders = async () => {
  try {
    const res = await request.get('/dns-providers')
    providers.value = res.data || []
  } catch (error) {
    console.error('Failed to fetch DNS providers:', error)
  }
}

const onProviderChange = () => {
  form.value.dns_credentials = {}
}

const openConfigDialog = (config?: CertConfig) => {
  if (config) {
    editingId.value = config.id || null
    form.value = {
      name: config.name,
      dns_provider: config.dns_provider,
      dns_credentials: {},
      enabled: config.enabled,
    }
  } else {
    editingId.value = null
    form.value = {
      name: '',
      dns_provider: providers.value[0]?.code || 'dnspod',
      dns_credentials: {},
      enabled: true,
    }
  }
  dialogVisible.value = true
}

const saveConfig = async () => {
  if (!form.value.name || !form.value.dns_provider) {
    ElMessage.warning('请填写配置名称和 DNS 提供商')
    return
  }
  try {
    if (editingId.value) {
      await request.put(`/certificate-configs/${editingId.value}`, form.value)
      ElMessage.success('配置已更新')
    } else {
      await request.post('/certificate-configs', form.value)
      ElMessage.success('配置已创建')
    }
    dialogVisible.value = false
    fetchConfigs()
  } catch (error) {
    console.error('Failed to save cert config:', error)
  }
}

const deleteConfig = async (config: CertConfig) => {
  try {
    await ElMessageBox.confirm(`确定要删除配置 "${config.name}" 吗？`, '删除确认', { type: 'warning' })
    await request.delete(`/certificate-configs/${config.id}`)
    ElMessage.success('配置已删除')
    fetchConfigs()
  } catch (error) {
    if (error !== 'cancel') {
      console.error('Failed to delete cert config:', error)
    }
  }
}

const testConfig = async (config: CertConfig) => {
  try {
    const res = await request.post(`/certificate-configs/${config.id}/test`)
    ElMessage.success(res.message || '凭证有效')
  } catch (error) {
    console.error('Failed to test cert config:', error)
  }
}

const handleSave = async () => {
  saving.value = true
  try {
    await emit('save', {
      acme_email: global.value.acme_email,
      cert_expiry_days: global.value.cert_expiry_days,
    })
  } finally {
    saving.value = false
  }
}

onMounted(() => {
  fetchConfigs()
  fetchProviders()
})
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.btn-text { margin-left: 4px; }
</style>
