// 侧栏布局状态与折叠态账户入口的单源口径。
//
// 窄屏（≤768px）强制折叠只是默认态：折叠入口是真实可聚焦、带 aria-expanded/
// aria-controls 的控件，点击/回车/空格必须有可观察效果——旧实现只翻转宽屏
// collapsed，窄屏下入口完全无效且读屏恒听「已折叠」。窄屏展开走浮层（不挤压
// 内容区），由遮罩点击或再次触发入口收起。
//
// 折叠态用户区只剩图标条时仍必须可发现：给出可见标识（用户名首字）与无障碍
// 名称，否则「退出登录」在窄屏上没有可宣布的入口。

interface SidebarLayoutState {
  /** 视口是否 ≤768px */
  narrow: boolean
  /** 宽屏下用户显式折叠 */
  userCollapsed: boolean
  /** 窄屏下用户显式展开（覆盖媒体查询） */
  narrowExpanded: boolean
}

/** 侧栏是否处于折叠态：窄屏默认折叠，显式展开时覆盖。 */
export const sidebarCollapsed = (state: SidebarLayoutState): boolean =>
  state.narrow ? !state.narrowExpanded : state.userCollapsed

/** 折叠入口触发后的下一状态（只翻转当前视口相关的那一维）。 */
export const toggleSidebarState = (state: SidebarLayoutState): SidebarLayoutState =>
  state.narrow
    ? { ...state, narrowExpanded: !state.narrowExpanded }
    : { ...state, userCollapsed: !state.userCollapsed }

/** 侧栏宽度（展开 220px / 折叠 64px）。 */
export const sidebarWidth = (collapsed: boolean): string => (collapsed ? '64px' : '220px')

/** 窄屏展开是否走浮层（不挤压内容区，需遮罩承接点击）。 */
export const sidebarOverlay = (state: { narrow: boolean; collapsed: boolean }): boolean =>
  state.narrow && !state.collapsed

/** 折叠态账户入口的无障碍名称（折叠后无可见文本，读屏必须可宣布）。 */
export const accountTriggerLabel = (name: string): string => `账户菜单：${name.trim() || '当前用户'}`

/** 折叠态可见标识：用户名首字（缺省「用」）。 */
export const accountInitial = (name: string): string => Array.from(name.trim())[0] ?? '用'
