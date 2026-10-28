import { ref } from 'vue'

// 设置页本地暂存态单源（模块级单例）。
//
// 基础设置卡在页内切换设置分页时会被卸载（Settings.vue 按 activeTab 挂载
// BasicSettings+CaddyGlobalSettings），组件内 ref 的暂存内容随之复位——与同卡
// 直绑 settings（父级共享模型）的字段行为不一致：管理员粘贴 GitHub 令牌、
// 调整安全事件保留/行数上限、上传并暂存管理面板证书后去看一眼别的分页，回来
// 全部还原，而界面明示「已暂存」。需要「提交前只存在于本地」的状态（一次性
// 令牌输入、dirty 标记、证书暂存）提升到本模块，随「设置」逻辑页面存活；
// 离开系统设置（Settings.vue 卸载）时由 resetSettingsDraft() 复位。
//
// 可直接落父级 settings 的字段（大屏视觉模式/流量采样/保留与行数编辑值）在
// BasicSettings 内改为写回共享模型，不在此重复持有。

export interface AdminTlsCertInfo {
  domain: string
  issuer: string
  not_after: string
  days_left: number
}

interface AdminTlsSelection {
  enabled: boolean
  mode: string
}

interface StagedAdminTlsCert {
  certFile: File
  keyFile: File
  certInfo: AdminTlsCertInfo
}

const githubTokenInput = ref('')
// 清除标记（用户裁定三态语义：nil=保持/空串=清除/非空=覆盖）
const githubTokenClearPending = ref(false)
// 安全事件保留/行数上限 dirty：只在用户实际编辑过时提交对应键（未编辑省略，
// 后端保持现值——库值 0=自动 不被展示归一值物化）。
const securityEventsRetentionDirty = ref(false)
const securityEventsRowCapDirty = ref(false)
// 管理面板 HTTPS：saved/hasCert/certError 是服务端派生缓存（唯一真相仍在
// /admin-tls 读路径，挂载即刷新），与暂存的开关/证书同置一处，使切页后
// 「已暂存」提示、损坏横幅与确认门继续成立。
const adminTls = ref<AdminTlsSelection>({ enabled: false, mode: 'selfsigned' })
const adminTlsSaved = ref<AdminTlsSelection>({ enabled: false, mode: 'selfsigned' })
const adminTlsHasCert = ref(false)
const adminTlsCertError = ref('')
// 后端降级读标记（/admin-tls 的 config_unavailable）：DB 故障/迁移窗口下读路径
// 以 200 返回「未启用/自签名」的降级值，不是真实状态——必须显性提示「显示的
// 开关不可信」，不得让界面以「已关闭」静默呈现。
const adminTlsUnavailable = ref(false)
const stagedAdminTlsCert = ref<StagedAdminTlsCert | null>(null)

let draftIdentity: number | null = null
const resetSettingsDraft = (): void => {
  draftIdentity = null
  githubTokenInput.value = ''
  githubTokenClearPending.value = false
  securityEventsRetentionDirty.value = false
  securityEventsRowCapDirty.value = false
  adminTls.value = { enabled: false, mode: 'selfsigned' }
  adminTlsSaved.value = { enabled: false, mode: 'selfsigned' }
  adminTlsHasCert.value = false
  adminTlsCertError.value = ''
  adminTlsUnavailable.value = false
  stagedAdminTlsCert.value = null
}

export const useSettingsDraft = () => ({
  githubTokenInput,
  githubTokenClearPending,
  securityEventsRetentionDirty,
  securityEventsRowCapDirty,
  adminTls,
  adminTlsSaved,
  adminTlsHasCert,
  adminTlsCertError,
  adminTlsUnavailable,
  stagedAdminTlsCert,
})

/** 身份变化时清空草稿；首次挂载只记录身份，不清空页内暂存。 */
export const syncSettingsDraftIdentity = (userId: number | null): void => {
  if (draftIdentity !== null && userId !== null && userId !== draftIdentity) {
    resetSettingsDraft()
  }
  draftIdentity = userId
}

export { resetSettingsDraft }
