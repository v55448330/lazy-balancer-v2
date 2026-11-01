import { computed, ref } from 'vue'
import { appVersion } from '@/utils/branding'
import { fetchRemoteVersions, isNewer, pickLatestChannel, type RemoteVersionEntry } from '@/utils/versionCheck'

/**
 * 面板「检查更新」单一状态源：进入基础设置页时检查一次官网版本目录（零轮询，
 * 调用方在 onMounted 触发），与当前运行版本（branding 的 APP_VERSION）比较后
 * 落定稳定版/测试版更新条目。拉取失败/超时由 versionCheck 就地吞并（静默跳过，
 * 零打扰），条目保持空、入口不渲染。
 *
 * 渠道口径（与任务契约一致）：
 * - 稳定版条目仅在 latest stable 比当前运行版本新时落定；
 * - 测试版条目仅在 latest beta 比当前运行版本新时落定——同版本号下 beta 是
 *   预发布（v2.4.0-beta 相对 v2.4.0 不是新版本），beta 用户会收到后续转正提示。
 */
export function useUpdateCheck() {
  const stableUpdate = ref<RemoteVersionEntry | null>(null)
  const betaUpdate = ref<RemoteVersionEntry | null>(null)
  const dialogVisible = ref(false)
  /** 弹框当前 tab（'stable' | 'beta'；string 化以贴合 el-tabs 的 modelValue 形状）。 */
  const activeTab = ref('stable')

  const hasUpdate = computed(() => stableUpdate.value !== null || betaUpdate.value !== null)
  /** 入口徽标展示的版本号：稳定版更新优先，其次测试版；无更新为空串。 */
  const badgeVersion = computed(() => stableUpdate.value?.version ?? betaUpdate.value?.version ?? '')

  /** 拉取远端目录并落定两个更新条目；失败静默（versionCheck 内部吞错返回 null）。 */
  const check = async (): Promise<void> => {
    const versions = await fetchRemoteVersions()
    if (versions === null) return
    const current = appVersion.value
    const stable = pickLatestChannel(versions, 'stable')
    const beta = pickLatestChannel(versions, 'beta')
    stableUpdate.value = stable !== null && isNewer(stable.version, current) ? stable : null
    betaUpdate.value = beta !== null && isNewer(beta.version, current) ? beta : null
  }

  /** 打开弹框并落在有更新内容的 tab（无更新时入口本不渲染，这里防御性短路）。 */
  const openDialog = (): void => {
    if (!hasUpdate.value) return
    activeTab.value = stableUpdate.value !== null ? 'stable' : 'beta'
    dialogVisible.value = true
  }

  return { stableUpdate, betaUpdate, hasUpdate, badgeVersion, dialogVisible, activeTab, check, openDialog }
}
