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
      <!-- 原生表单行（2026-10-11 用户裁定：对齐统一走 el-form-item，弃自管标签行；
           Firefox label-for 控制台告警为 EP 上游已知形态，非用户可见） -->
      <el-form-item label="节点模式">
        <el-radio-group v-model="selectedMode" :disabled="loading || readOnly || !status" aria-label="节点模式" @change="handleModeChange">
          <el-radio value="master">主节点</el-radio>
          <el-radio value="slave">从节点</el-radio>
        </el-radio-group>
        <div class="form-tip-line">主节点管理权威配置，从节点定期同步主节点数据</div>
      </el-form-item>

      <el-form-item label="同步间隔">
        <div class="interval-row">
          <el-input-number v-model="syncInterval" :min="10" :max="86400" :disabled="intervalDisabled" />
          <!-- 单位后缀归一全局 form-tip-inline（原自管.interval-unit
               与全局类仅色差/字号差）；行内 gap 已提供间距，左侧外边距置零 -->
          <span class="form-tip-inline" style="margin-left: 0">秒</span>
          <el-button v-if="!isSlave" :loading="intervalSaving" :disabled="intervalDisabled || !syncIntervalValid || syncInterval === status?.sync_interval" @click="saveSyncInterval">保存</el-button>
        </div>
        <div class="form-tip-line">
          <span v-if="!syncIntervalValid">请输入 10–86400 之间的同步间隔（清空后无法保存）</span>
          <span v-else>{{ isSlave ? '由主节点同步下发，从节点不可修改' : '从节点拉取同步与上报状态的周期（10–86400 秒）' }}</span>
        </div>
      </el-form-item>

    </el-form>

    <el-dialog
      v-model="registrationOpen"
      width="min(560px, 92vw)"
      top="5vh"
      :close-on-click-modal="false"
      :close-on-press-escape="!loading"
      :show-close="!loading"
      append-to-body
      destroy-on-close
    >
      <template #header>
        <DialogHeader :icon="Connection" title="注册为从节点" subtitle="连接主节点，本节点将定期同步主节点数据" tone="warning" />
      </template>
      <div class="registration-warnings">
        <el-alert type="error" :closable="false" show-icon>
          切换后本地数据将被主节点全覆盖，本地已有的差异化配置将丢失
        </el-alert>
        <el-alert v-if="usesPlainHttp" type="warning" :closable="false" show-icon>
          主节点地址为 HTTP，证书私钥等敏感数据将明文传输，建议启用 HTTPS
        </el-alert>
      </div>
      <el-form ref="dialogFormRef" :model="form" :rules="rules" label-width="100px" :disabled="readOnly" style="margin-top: 16px">
        <el-form-item label="主节点地址" prop="master_url">
          <el-input v-model="form.master_url" placeholder="https://master.example.com:8000" />
          <div class="form-tip-line">填写可从当前节点访问的主节点管理地址</div>
        </el-form-item>
        <el-form-item label="注册令牌" prop="register_token">
          <el-input v-model="form.register_token" type="password" show-password placeholder="请输入一次性注册令牌" />
          <div class="form-tip-line">在主节点「集群管理」页面生成</div>
        </el-form-item>
        <el-form-item label="节点名称" prop="node_name">
          <el-input v-model="form.node_name" placeholder="选填，例如：上海从节点" maxlength="100" show-word-limit />
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
import DialogHeader from '@/components/DialogHeader.vue'
import type { ClusterNodeMode, ClusterRegistrationInput, ClusterStatus } from '@/types'
import { shouldCloseRegistrationDialog } from '@/utils/clusterRegistration'
import { validateClusterUrl } from '@/utils/clusterUrl'

interface RegistrationForm {
  master_url: string
  register_token: string
  node_name: string
}

const props = defineProps<{
  readonly status: ClusterStatus | null
  readonly loading: boolean
  readonly registrationRequest: number
  /** 父级注册请求成功计数（成功后清空一次性令牌；取消/失败保留）。*/
  readonly registrationSucceeded: number
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
let registrationOriginMode: ClusterNodeMode | null = null
const syncInterval = ref<number | null | undefined>(60)
const form = reactive<RegistrationForm>({ master_url: '', register_token: '', node_name: '' })

// 与节点访问地址共用 utils/clusterUrl——原实现只校验 scheme，带凭证/
// query/fragment 的地址会通过前端校验、提交时被后端同一规则拒绝（晚失败）。
const validateMasterUrl = (_rule: unknown, value: string, callback: (error?: Error) => void): void => {
  const error = validateClusterUrl(value, { label: '主节点地址', emptyMessage: '请输入主节点地址' })
  if (error) {
    callback(new Error(error))
    return
  }
  callback()
}

const rules: FormRules<RegistrationForm> = {
  master_url: [{ required: true, validator: validateMasterUrl, trigger: 'blur' }],
  register_token: [{ required: true, message: '请输入注册令牌', trigger: 'blur' }],
}

const usesPlainHttp = computed(() => form.master_url.trim().toLowerCase().startsWith('http://'))
const isSlave = computed(() => props.status?.node_mode === 'slave')
// status 未就绪（首拉在途/契约失败）时写控件 fail-closed：否则
// syncInterval 初值 60 ≠ status?.sync_interval(undefined) 恒真，保存按钮可点
// 会以前端默认值覆盖真实配置（与 BasicSettings 的 configLoaded 门同口径）。
const intervalDisabled = computed(() => props.readOnly || props.intervalSaving || isSlave.value || !props.status)

// el-input-number 清空后把 v-model 回写成 null/undefined：空值不是「未提供」的
// 有效输入——后端把缺失的 sync_interval 当成保持现值并回 200，界面会提示
// 「同步间隔已更新」而实际未改。保存按钮与提交门一并按此判据拒绝。
const syncIntervalValid = computed(
  () => typeof syncInterval.value === 'number' && Number.isFinite(syncInterval.value),
)

watch(
  () => props.status,
  (status, oldStatus) => {
    if (!status) return
    // 仅首次注册的 master→slave 跃迁自动关闭；slave→slave 轮询属于重新注册，
    // 不得关闭弹框或清空一次性令牌。
    if (shouldCloseRegistrationDialog(registrationOpen.value, registrationOriginMode, status.node_mode)) {
      registrationOpen.value = false
      return
    }
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
    registrationOriginMode = props.status?.node_mode ?? null
    registrationOpen.value = true
  },
)

// 注册请求被主节点受理（父级二次确认后的 POST 成功）→ 令牌已消耗，清空；
// 取消确认/入口守卫早退/请求失败都保留输入。
watch(() => props.registrationSucceeded, () => { form.register_token = '' })

// 注册令牌为一次性凭据：注册流程结束（提交/取消/成功关闭）后不回填，避免下次打开残留旧令牌
watch(registrationOpen, (open) => {
  if (!open) {
    registrationOriginMode = null
    form.register_token = ''
    // X/ESC 直闭不走 closeRegistration——复位对齐实际节点模式，否则
    // 主节点表单错显「从节点」（曾等 status 轮询 ≤15s 才自愈）
    selectedMode.value = props.status?.node_mode ?? 'master'
  }
})

const handleModeChange = (value: string | number | boolean | undefined): void => {
  if (props.readOnly || props.loading || !props.status) return
  if (value === 'slave') {
    registrationOriginMode = props.status?.node_mode ?? null
    registrationOpen.value = true
    return
  }
  if (value === 'master' && props.status?.node_mode === 'slave') {
    selectedMode.value = 'slave'
    emit('promote')
  }
}

const closeRegistration = (): void => {
  // 关闭路径统一收口 watch(registrationOpen)：令牌清空 + selectedMode 复位
  registrationOpen.value = false
}

const saveSyncInterval = (): void => {
  if (props.readOnly || !props.status) return
  const value = syncInterval.value
  if (!syncIntervalValid.value || typeof value !== 'number') return
  emit('update-interval', value)
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
  // 不在此清空令牌——emit 之后父级的二次确认/入口守卫才可能发生，
  // 取消确认或守卫早退都会让已粘贴的一次性令牌白白丢失。弹框关闭
  //（成功/取消/X）统一由 watch(registrationOpen) 清空。
}
</script>

<style scoped>
.registration-warnings :deep(.el-alert__icon) {
  font-size: 14px;
}
.registration-warnings {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.card-header { display: flex; align-items: center; }
.card-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: var(--text-primary); }
/* el-form-item 内的原生弹性行：输入框、单位与帮助图标水平对齐；
 * 标签宽度/对齐统一由 Element Plus 表单项负责。 */
.interval-row { display: flex; align-items: center; gap: 8px; }

@media (max-width: 768px) {
  .settings-form :deep(.el-form-item) { display: block; }
  .settings-form :deep(.el-form-item__label) { justify-content: flex-start; }
}
</style>
