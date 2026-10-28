// 请求体可见性判据与空态文案单源。
//
// 服务端在返回安全事件前会调用 maskSecurityEventRequestContextIfNeeded：非管理员
// 会话与只读 API Key 一律把 request_body 整体置空（敏感请求头值置 ••••••）。
// 线上契约里没有「body 已被掩码」的布尔位，于是前端看到的空串既可能是「从未记录」
// 也可能是「已记录但无权查看」——旧文案把两者压成「无请求体记录」，与同弹框请求头
// 区（值掩码、可眼睛图标切换）给出相反结论，误导排障。
//
// 判据只覆盖面板侧会话（管理员角色）；只读 API Key 不走本视图，故不在此建模。

/** 当前会话是否能读到请求体原文（服务端掩码条件是角色 admin 且非只读 Key）。 */
export const viewerCanReadRequestBody = (role: string | null | undefined): boolean => role === 'admin'

/** 请求体空态文案：对无权读者必须披露「可能是掩码，不能据此判断未记录」。 */
export const requestBodyEmptyNotice = (adminViewer: boolean): string =>
  adminViewer
    ? '无请求体记录'
    : '无请求体记录（当前账号看不到请求体正文：服务端对非管理员会掩码该字段，不能据此判断该事件未记录请求体；需要时请用管理员账号查看）'
