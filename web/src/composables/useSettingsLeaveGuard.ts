import { ElMessageBox } from 'element-plus'
import type { PageId } from '@/utils/pageIds'
import { tSafe as t } from '../i18n/tSafe.ts'
import { discardSettingsDraft, hasDirtySettingsForm, resetSettingsDraft } from './useSettingsDraft.ts'
import { settingsTabOfPage } from '@/utils/settingsPages'

// 离开设置页的统一守卫：侧栏切页（AppLayout.goPage）与设置页内直接切页的入口
// 共用。设置域有未保存改动时，切到任何其它页面（含设置内的其它分页）都要确认；
// 点击当前所在页不弹。确认「放弃并离开」= 丢弃全部未保存改动；「留在本页」
// 返回 false，调用方不得切页。全站非路由驱动，页面切换入口都必须经过这里。
export const confirmLeavingSettingsPage = async (page: PageId, currentPage: PageId): Promise<boolean> => {
  if (page === currentPage) return true
  if (!hasDirtySettingsForm()) return true
  try {
    await ElMessageBox.confirm(
      t('common.app.views.layout.unsavedLeaveMessage'),
      t('common.app.views.layout.unsavedLeaveTitle'),
      {
        type: 'warning',
        confirmButtonText: t('common.app.views.layout.unsavedLeaveConfirm'),
        cancelButtonText: t('common.app.views.layout.unsavedLeaveStay'),
      },
    )
  } catch {
    return false
  }
  // 设置内切页：Settings.vue 不卸载，共享模型里的编辑值必须回填为服务端值；
  // 离开设置域：组件即将卸载，只需清登记（不为即将销毁的模型多发一次请求）。
  if (settingsTabOfPage(page)) discardSettingsDraft()
  else resetSettingsDraft()
  return true
}
