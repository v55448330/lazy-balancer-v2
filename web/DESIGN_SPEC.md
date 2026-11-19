# 前端组件设计规范（lazy-balancer-v2 面板）

**建立：** 2026-11-19（用户裁定：从安全总览/仪表盘/任务监控提取标准，后续所有前端组件变动必须遵循）
**适用范围：** web/src 全部页面与组件。新页面/新组件 MUST 先对照本规范；既有页面改动时顺带对齐。
**机械守卫：** tests/designGuard.spec.ts（全仓设计守卫）、tests/notificationsCenter.spec.ts、apiAccessRename.spec.ts、exportSurface.spec.ts、notificationKeyCoverage.spec.ts、settingsConfirmationGuards.spec.ts、formFreeze.spec.ts 及布局类钉测（npm test 必跑，违规即红）。

## 1. 形状语言
- 全站直角：`--el-border-radius-base/small/round: 0`（main.css）。卡片/按钮/输入/弹框/标签一律直角。
- 例外白名单：stat-icon 8px、stat-item 8px、通道类型图标 10px、饼图扇区 4px（语义图形，非容器）。

## 2. 卡片（el-card）
- **阴影**：不写 shadow 属性（默认 always）或显式 `shadow="always"`；`shadow="never"` 禁止（用户裁定）。
  全站统一 computed = `0 0 12px rgba(0,0,0,0.12)`（Element Plus 默认，无 override）。
- **边框色**：`--el-card-border-color: #ebeef5`（安全总览定案值）。新页面 scoped 必须带
  `.el-card { --el-card-border-color: #ebeef5; }`；禁止沿用默认 #e4e7ed（偏深，与安全总览不一致）。
- **卡头**：`card-header`（flex space-between，flex-wrap，row-gap 8px）+ `card-title`（图标+14px/600/#111827）+ `title-icon`（16px，主色 #3b82f6；图表卡 #f59e0b，分布卡 #8b5cf6）。
- **卡头右侧**：操作/筛选放 `card-header-actions`（flex gap 12px）。
- **禁止**：卡片嵌套卡片（list-card 套自带卡组件）；空态用 el-empty 直接放卡内，不再包 empty-card。
- **表格卡**：`el-card.list-card` + 卡头标题；表格 `stripe` + `:header-cell-style="{ background: '#f9fafb' }"`。
- **图表卡**：`chart-card`，body 定高（240-280px）+ padding 16px；容器 `.chart-container` 定高，v-chart autoresize。

## 3. 统计项（stat-item，Dashboard 单源）
```css
.stat-item { display:flex; align-items:center; gap:14px; padding:16px; background:#f9fafb; border-radius:8px; }
.stat-icon { width:40px; height:40px; border-radius:8px; display:flex; align-items:center; justify-content:center; font-size:18px; }
.stat-blue{background:#eff6ff;color:#3b82f6} .stat-purple{background:#f5f3ff;color:#8b5cf6}
.stat-green{background:#ecfdf5;color:#10b981} .stat-orange{background:#fff7ed;color:#f59e0b} .stat-red{background:#fef2f2;color:#ef4444}
.stat-value { font-size:20px; font-weight:600; color:#111827; line-height:1.2; }
.stat-label { font-size:12px; color:#6b7280; margin-top:2px; }
```
- 布局：el-row :gutter=16 + el-col 响应式（xs=12 sm=8/6 md=4/6）。统计项入卡，不裸奔。

## 4. 图表（ECharts，utils/chartBase.ts 单源）
- 注册：`import '@/utils/echarts'`（全站单点副作用注册）+ `VChart from 'vue-echarts'`。
- 构建：MUST 经 `axisChartBase / pieChartBase / lineSeries / barSeries / chartColors`；禁止手搓 div bar、禁止各持一套轴色值。
- 视觉基线：tooltip 白底 95%/灰边 #e5e7eb/12px #374151；类目轴轴线 #e5e7eb、标签 10px #9ca3af；数值轴无轴线、分隔线 #f3f4f6；折线 smooth/2px/10% 面积；饼环形 45%-68%、白描边 2px、扇区圆角 4px；legend 11px #6b7280（轴图底部或顶部 itemGap 24，饼图底部 scroll）。
- 空态：数据为空渲染 el-empty（image-size 60），不渲染空坐标系。
- 语义色：成功 #10b981、失败 #ef4444、主序列 #3b82f6、次序列 #8b5cf6、警示 #f59e0b。

## 5. 页头与页签
- 页头：page-header（page-title 带图标 + page-desc）。**全局操作按钮必须归属其功能页签**，
  不放全局页头（例：创建密钥属于「密钥管理」tab，不属于 API 接入页头）。
- 页签名：跨页面同语义同名（「概览」不叫「接入概览」）。
- 同族功能对称：API 与 MCP 同为对外接入，开关/统计/明细/会话（或调用记录）必须成对设计；
  一方独有的能力要么补齐要么都不做。
- 单 tab 无实质内容时合并入相邻页签（保留功能，去掉空壳 tab）。

## 6. 表格
- stripe + 表头底色 #f9fafb + 操作列 `size=small link type=primary`（或小型 plain 按钮组）。
- 列内控件紧凑：级别/枚举选择用 el-select（宽 ≤120px），禁止 radio-button 组在窄列竖排堆叠。
- 列头文案必须是名词性标题（「事件」不是「个事件」）；列内容与列名语义一致（级别列不放预览按钮）。
- 事件/枚举展示 MUST 用用户可读标题（catalog title），禁止裸事件键（cert.expiry_warning 类）。
- 空态：el-empty 卡内直出；加载失败显性 error-banner + 重试，不得伪装「暂无数据」。

## 7. 弹框（el-dialog）
- class="dialog-body-inset" + DialogHeader（icon/title/subtitle/tone）。
- 宽度按内容：简单表单 min(560px,94vw)；多区块编辑器 min(760-860px,94vw)；top 6-8vh。
- footer：取消（默认按钮）+ 保存（primary，loading）。文案走词条，禁止硬编码。
- 代码编辑：CodeEditor（Prism 高亮叠层）——JSON 用 language=json，HTML 用 language=markup；
  只读展示用 SyntaxHighlight。HTML 类模板必须提供渲染预览（iframe sandbox srcdoc）。
- 确认删除：ElMessageBox.confirm，禁止 window.confirm。

## 8. 表单与控件
- 数字输入：el-input-number（全站 28px 高/13px/左对齐，main.css 统一），禁止 el-input v-model.number 手搓。
- 输入+动作：并排 flex（input + 独立按钮），不用 append slot 塞测试按钮（视觉挤压）。
- 说明文字：`.form-hint`（12px #6b7280 margin-top 4px）；每个非常规控件必须有 hint。
- 表单最大宽 640px（creds-form 范式），输入宽 ≤420px。
- 密码行：input + 状态 tag flex 对齐。

## 9. 词条（i18n）
- 全部可见文案走 t()；zh 母本 en 同位（叶子键集一致，spec 钉）。
- 值含 @ 用 {'@'} 转义；含 {{x}} 用 {'{{x}}'} 转义（vue-i18n linked-message 语法）。
- 死键随组件删除同步清理；新键先有消费方（导出面守卫同口径）。
- 标题描述必须指明主体（「API 最近调用」不是「最近调用」）；同族区块空态文案风格一致。

## 10. 按钮一致性
- 同一卡头/同一行的同族按钮形态必须一致（同为 link 或同为 small default）。
- 外链按钮 `tag="a"` 必须 `text-decoration:none`（.header-actions :deep(a.el-button) 范式），
  禁止一个有下划线一个没有。
- code 展示值必须完整可见（word-break:break-all + 换行），禁止省略号截断关键端点/URL。

## 11. 反馈
- 写操作成功：mfaAwareSuccess（MFA 感知）；失败：ElMessage.error 或 error-banner。
- 测试类操作：成功/失败都必须有明示反馈，禁止静默 catch。
- 轮询：setInterval 必须配对清理（关闭/卸载/成功三路径），禁止泄漏。

## 12. 验收
- 交付前：npm test 全绿 + vue-tsc 0 + build ✓ + dist 特征 grep + 容器 chunk hash 一致 + 浏览器 DOM/console 实测。
- 视觉验收以浏览器 computed style 为准（阴影/边框/圆角逐项对比参考页），不凭代码推理。

## 13. 增补裁定（2026-11-19 第三轮）
- **tab 内卡片阴影**：`el-tabs__content` 默认 overflow:hidden 裁剪四周阴影——
  tab 页 scoped 必须 `:deep(.el-tabs__content){overflow:visible}` + `.el-tab-pane{padding:6px;margin:-6px}`。
- **行内按钮高度**：与输入框并排的按钮一律 `size="small"`（24px 对 28px 输入框，
  视觉齐平）；default 尺寸（32px）禁止出现在输入行内。
- **表单提示**：统一 `info-note-bar`（虚线浅底），禁止自管红字/裸 div 提示；
  条件提示必须有常驻占位槽（min-height）保证卡片等高。
- **表格操作列**：文字按钮（`size=small link`），禁止 plain/filled 按钮组；
  状态独立列（不混名称列）；审计维度（更新时间/更新人）随表呈现。
- **模板编辑归属**：消息正文模板归通知规则（每通道模板）；通道编辑只保留
  传输配置（请求方式/请求头/消息类型/日报格式）。
- **空选语义**：通道选择全不选=不投递（'[]' 落库），不是「全部」；缺省才是全部。
- **双协议对称**：API/MCP 的开关、只读、统计、明细必须成对设计；Key 级与全局级同构。
- **投递记录**：恒全量（不区分用户视角），用户/通道维度经行内列呈现；禁止裸事件键。
- **每日摘要**：定时摘要与事件规则形态不同，独立卡片交互，不混事件表格。

## 14. 增补裁定（2026-11-19 第四轮，designGuard 机器化）
- **表头左对齐**：表格列头一律左对齐（设计标准）；通知/密钥面禁 `align="center"/"right"`（designGuard 钉）。其余页面逐步对齐。
- **图表直角**：概览及所有图表柱/饼 `borderRadius:0`、图例 `icon:'rect'`（直角语言延伸到数据图形容器；饼扇区白描边保留）。
- **操作确认**：测试/保存/启用/禁用/删除等状态变更或外发操作必须 `ElMessageBox.confirm`（取消不执行）；开关启停取消需回滚。
- **创建人显示名**：列表创建人/属主优先 display_name，回退 username/#id；更新人同口径入详情。
- **列表列取舍**：创建时间不重要入详情；更新时间/过期时间/最后使用保留在列表；列宽按内容优化避免省略号/换行。
- **详情完整**：密钥详情必含 IP 白名单（空=不限制来源）。
- **webhook 请求头**：下拉预设（Authorization/X-API-Key/Content-Type/Accept/User-Agent）+可创建 X-* 自定义+值输入，网格对齐；禁裸 input 名。
- **机器人传输配置**：QQ/微信消息形态由官方协议固定，通道编辑不提供消息类型/传输配置；日报格式对机器人固定，弹框仅决定高亮/预览样式。
- **模板弹框统一**：日报每通道模板编辑复用事件规则同一弹框（全类型可编辑）；日报基本配置=投递时间/包含项目/目标通道（三态），label 与控件垂直对齐。
- **命名统一**：bot 绑定输入统一「接收者」，placeholder 区分 openid/wxid；webhook 地址 label「URL」。
- **设计守卫豁免**：shadow="never"/v-model.number 仅限登记 legacy（PathRulesEditor 内嵌面板/百分号输入），条目失效即红；新增违规无法交付。