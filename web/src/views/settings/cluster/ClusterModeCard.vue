<template>
  <el-card class="settings-card">
    <template #header>
      <div class="card-header">
        <div class="card-title">
          <el-icon><Connection /></el-icon>
          <span>节点模式设置</span>
        </div>
      </div>
    </template>

    <el-form :model="form" label-width="120px" class="settings-form" :disabled="readOnly">
      <el-form-item label="节点模式">
        <el-radio-group v-model="selectedMode" :disabled="loading || readOnly" @change="handleModeChange">
          <el-radio value="master">主节点</el-radio>
          <el-radio value="slave">从节点</el-radio>
        </el-radio-group>
        <div class="form-tip-line">主节点管理权威配置，从节点定期同步主节点数据</div>
      </el-form-item>

      <el-form-item label="同步间隔">
        <div class="interval-row">
          <el-input-number v-model="syncInterval" :min="10" :max="3600" :disabled="intervalDisabled" />
          <span class="interval-unit">秒</span>
          <el-button v-if="!isSlave" :loading="intervalSaving" :disabled="intervalDisabled || syncInterval === status?.sync_interval" @click="saveSyncInterval">保存</el-button>
        </div>
        <div class="form-tip-line">{{ isSlave ? '由主节点同步下发，从节点不可修改' : '从节点拉取同步与上报状态的周期（10–3600 秒）' }}</div>
      </el-form-item>

    </el-form>

    <el-dialog
      v-model="registrationOpen"
      title="注册为从节点"
      width="520px"
      :close-on-click-modal="false"
      append-to-body
    >
      <el-alert
        title="切换后本地数据将被主节点全覆盖"
        type="error"
        :closable="false"
        show-icon
        class="registration-alert"
      />
      <el-alert
        v-if="usesPlainHttp"
        title="证书私钥将经明文 HTTP 传输，建议使用 HTTPS"
        type="warning"
        :closable="false"
        show-icon
        class="registration-alert"
      />
      <el-form ref="dialogFormRef" :model="form" :rules="rules" label-width="100px" :disabled="readOnly">
        <el-form-item label="主节点地址" prop="master_url">
          <el-input v-model="form.master_url" placeholder="https://master.example.com:8000" />
          <div class="form-tip-line">填写可从当前节点访问的主节点管理地址</div>
        </el-form-item>
        <el-form-item label="注册令牌" prop="register_token">
          <el-input v-model="form.register_token" type="password" show-password placeholder="请输入一次性注册令牌" />
        </el-form-item>
        <el-form-item label="节点名称" prop="node_name">
          <el-input v-model="form.node_name" placeholder="选填，例如：上海从节点" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button :disabled="loading || readOnly" @click="closeRegistration">取消</el-button>
        <el-button type="primary" :loading="loading" :disabled="readOnly" @click="submitRegistration">注册并切换为从节点</el-button>
      </template>
    </el-dialog>
  </el-card>
</template>

<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import type { FormInstance, FormRules } from 'element-plus'
import { Connection } from '@element-plus/icons-vue'
import type { ClusterNodeMode, ClusterRegistrationInput, ClusterStatus } from '@/types'

interface RegistrationForm {
  master_url: string
  register_token: string
  node_name: string
}

const props = defineProps<{
  readonly status: ClusterStatus | null
  readonly loading: boolean
  readonly registrationRequest: number
  readonly readOnly: boolean
  readonly intervalSaving: boolean
}>()

const emit = defineEmits<{
  (event: 'register', payload: ClusterRegistrationInput): void
  (event: 'promote'): void
  (event: 'update-interval', value: number): void
}>()

const dialogFormRef = ref<FormInstance>()
const selectedMode = ref<ClusterNodeMode>('master')
const registrationOpen = ref(false)
const syncInterval = ref(60)
const form = reactive<RegistrationForm>({ master_url: '', register_token: '', node_name: '' })

const validateMasterUrl = (_rule: unknown, value: string, callback: (error?: Error) => void): void => {
  if (!value.trim()) {
    callback(new Error('请输入主节点地址'))
    return
  }
  try {
    const parsed = new URL(value.trim())
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      callback(new Error('主节点地址必须使用 HTTP 或 HTTPS'))
      return
    }
    callback()
  } catch (error: unknown) {
    if (error instanceof TypeError) {
      callback(new Error('主节点地址格式不正确'))
      return
    }
    throw error
  }
}

const rules: FormRules<RegistrationForm> = {
  master_url: [{ required: true, validator: validateMasterUrl, trigger: 'blur' }],
  register_token: [{ required: true, message: '请输入注册令牌', trigger: 'blur' }],
}

const usesPlainHttp = computed(() => form.master_url.trim().toLowerCase().startsWith('http://'))
const isSlave = computed(() => props.status?.node_mode === 'slave')
const intervalDisabled = computed(() => props.readOnly || props.intervalSaving || isSlave.value)

watch(
  () => props.status,
  (status, oldStatus) => {
    if (!status) return
    if (registrationOpen.value) return
    selectedMode.value = status.node_mode
    if (!oldStatus || syncInterval.value === oldStatus.sync_interval) {
      syncInterval.value = status.sync_interval
    }
    if (!form.master_url) form.master_url = status.master_url
    if (status.node_mode === 'master') registrationOpen.value = false
  },
  { immediate: true },
)

watch(
  () => props.registrationRequest,
  () => {
    if (props.status?.node_mode !== 'slave') return
    selectedMode.value = 'slave'
    registrationOpen.value = true
  },
)

const handleModeChange = (value: string | number | boolean): void => {
  if (props.readOnly || props.loading) return
  if (value === 'slave') {
    registrationOpen.value = true
    return
  }
  if (value === 'master' && props.status?.node_mode === 'slave') {
    selectedMode.value = 'slave'
    emit('promote')
  }
}

const closeRegistration = (): void => {
  registrationOpen.value = false
  selectedMode.value = props.status?.node_mode ?? 'master'
}

const saveSyncInterval = (): void => {
  if (props.readOnly) return
  emit('update-interval', syncInterval.value)
}

const submitRegistration = async (): Promise<void> => {
  if (props.readOnly) return
  if (!dialogFormRef.value) return
  const valid = await dialogFormRef.value.validate().catch(() => false)
  if (!valid) return
  const nodeName = form.node_name.trim()
  emit('register', {
    master_url: form.master_url.trim(),
    register_token: form.register_token.trim(),
    ...(nodeName ? { node_name: nodeName } : {}),
  })
}
</script>

<style scoped>
.card-header { display: flex; align-items: center; }
.card-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: var(--text-primary); }
.settings-form { max-width: 760px; padding: 4px 0; }
.registration-alert { margin-bottom: 16px; }
.interval-row { display: flex; align-items: center; gap: 8px; }
.interval-unit { color: var(--text-secondary); font-size: 13px; }

@media (max-width: 768px) {
  .settings-form :deep(.el-form-item) { display: block; }
  .settings-form :deep(.el-form-item__label) { justify-content: flex-start; }
}
</style>
