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

## 15. 增补裁定（2026-11-20 第五轮，状态标签与日报署名）
- **状态指示统一标签**：表格内过期/永不过期/即将过期/有效/从未使用等状态 MUST 用
  `el-tag size="small" effect="plain"`，颜色区分语义（success=有效/永不过期、warning=即将过期/只读、
  danger=已过期/失败、info=从未使用/关闭）。时间文本用 `.cell-time{color:#6b7280;font-size:13px}`，
  与标签同格用 `.cell-tags{display:inline-flex;gap:6px;flex-wrap:wrap}`。
- **过期标签归属**：已过期/即将过期标签放「过期时间」列（日期+标签），状态列仅保留启用开关。
- **日报统计补全**：每日摘要含 请求/放行/观察/独立IP/拦截/攻击TOP规则/TOP攻击源/自动封禁/证书/集群
  十项（DailyItemIDs 单源），分节 全局概览/安全风险/证书/集群；缺失值显「无」不省略行。
- **消息署名**：机器人文本/邮件/日报统一附加品牌+时间署名（`{{brand}}`/`{{time}}` 变量，
  BrandName() 单源）；QQ 用 markdown 表格、微信纯文本、邮件内联样式 HTML、webhook JSON。
## 16. 增补裁定（2026-11-20 第六轮，表单描述/分区标题/弹框与预览/多选/表格）
- **表单描述 MUST 用标准类**（main.css 单源，禁组件内重定义）：
  - 同行简短后缀 → `form-tip-inline`；控件下方块级说明 → `form-tip-line`。
  - 禁止自写 `.xxx-hint` 覆写或 `el-text` 包裹；`form-hint` 为遗留类，新代码不得再用。
- **分区标题 MUST 用 `DialogSectionHeader`**：标题前带彩色竖条（primary/danger/success/warning tone）；
  事件弹框的级别分区标题同样用竖条（严重=红/警告=橙/信息=蓝）。禁止纯文本裸标题。
- **弹框高度**：弹框体 MUST `max-height: calc(100vh - 240~300px); overflow-y:auto`，footer 不贴屏/不超屏；
  用全局类选择器（append-to-body 下 scoped `:deep` 不可靠）。
- **预览区**：
  - 上半正文即源码，预览区只渲染（HTML=iframe、Markdown=渲染 HTML、文本/JSON=占位符替换样例后的纯文本）；
    禁止提供「渲染/源码」切换。
  - 预览容器固定高度（统一 `height:360px; max-height:46vh`；日报预览 `.daily-preview-body` 四格式同高）。
  - 禁横向滚动条（容器 `overflow-x:hidden`，iframe 100% 宽）。
- **多选控件**：bordered el-checkbox 组自适应换行（无固定 max-width）；**隐藏勾选对号**（`.el-checkbox__inner{display:none}`），
  仅以边框/选中态表达；禁用通道 disabled 且已选自动移除并提示。
- **选择浮层**：popover 宽度=触发器 `offsetWidth`（点击时测量）；placement 底部优先，底部不足翻到上方，
  `preventOverflow altAxis:false` 不横向位移；高度超限内部滚动。
- **卡头操作**：保存/取消放卡片 header，保存为 `size=small type=primary`，取消为 `size=small`；
  顺序在用户选择器左侧；表格行内不再放保存/取消。
- **表格填满**：末列/主内容列用 `min-width` 吸收剩余宽度，禁止右侧大片空白；列宽按内容设定。
- **时间显示**：统一 `formatDate`（面板时区设置），禁裸 UTC 字符串。
- **协议固定**：QQ 日报=Markdown（表格）、微信=纯文本；iLink 会话上下文有时效，失效时卡片提示「会话待刷新」+重绑入口。
- **更新人/更新时间**：列表体现最近更新用户（display_name 优先）与更新时间；订阅表 updated_at/updated_by 单源。

## 17. 如何避免新改动违反规范（执行机制）
1. 开始任何前端改动前：读本规范 §1-16；对照参考页（Dashboard/SecurityPolicies/通道编辑弹框）实际实现，不凭记忆。
2. 复用标准类/组件：`form-tip-inline/line`、`DialogSectionHeader`、`el-card.list-card`、`formatDate`；
   禁止在 scoped CSS 重新定义标准类或新造近似类。
3. 机械门禁（npm test 必跑，违规即红）：
   - `tests/designGuard.spec.ts` — 通知面设计标准守卫（描述类/DialogSectionHeader/弹框体高度/预览固定高度/多选隐藏对号/表格填宽）。
   - `tests/notificationsCenter.spec.ts` — 交互契约（卡头保存、事件分区、浮层宽度/定位、语言切换、消息模板列删除等）。
   - `tests/ansiHtml.spec.ts` — 所有 v-html 面登记。
   - `tests/layoutAlignment.spec.ts` — 输入框同高契约（32px 双壳/禁 :deep 锚组件根）与工具栏居中。
   - `tests/channelEdit.spec.ts` — target_masked 编辑不回写/占位提示/编辑体省略 target（§19-2）。
   - `tests/channelHealth.spec.ts` — 复合健康态顺序：未验证早于验证失败（§19-3 同族判定口径）。
   - `tests/deliveryLog.spec.ts` — 同通道多尝试只保留最新结果行（§19-5）。
   - `tests/mdPreview.spec.ts` — fenced code 内 `---` 不隔断 + 日报摘要跨栈夹具（§19-1/4 前端侧）。
   - `tests/channelStyleConfig.spec.ts` — 日报渲染模式跨键/不 trim 与后端同口径（§19-6）。
   - `tests/securityLibraries.spec.ts` — 自动更新开关失败回滚完整行（§19-7）。
   - `tests/frontendEdgeGuards.spec.ts` — TaskMonitor hasOwn / IP 查询提示 / 删除负下标（§19-8）。
   - §18 条款对应守卫：v-html scoped 直写拦截、同选择器单声明（行首锚定）、通道就绪 channelSendable 单源。
4. 新增标准时：先加规范条款 + 机械断言，再改实现；无守卫的新约定视为未落地。
5. 交付前视觉核验：浏览器 computed style/DOM 对照参考页（阴影/边框/直角/间距/高度），不凭代码推理。

## 18. 增补裁定（2026-11-22 第七轮，scoped 深选择器/同行输入框同高/预览收敛/通道就绪门）
1. **:deep 锚定必须用原生元素**：Element 组件根（el-time-picker/el-select 等）只透传 class、
   **不带 scoped data-v 属性**——挂在 `.xxx[data-v]` 上的 `:deep()` 规则永不匹配（通知预览与定时更新
   行多轮修复空转的共同根因）。组件内部元素的 scoped 覆写一律锚定**本组件模板里的原生容器**
   （如 `.schedule-editor__controls`）再向下 `:deep(.el-input__wrapper)`。
2. **v-html 后代样式必须 `:deep()`**：marked/prism 等注入的子元素不带组件 data-v，scoped 直写
   （`.容器 子元素`）永不匹配；守卫见 `notificationsCenter.spec.ts`（v-html 面禁 scoped 直写）。
3. **同行输入框严格同高**：同一行两个及以上输入控件，可见边框高度必须相等（用户裁定「不接受
   一高一低」）。对齐基准=全局输入壳规则 `.el-input.el-input:not(--large) .el-input__wrapper`
   （28px，特异性 (0,4,0)）与多选框自然高度（单行标签 32px）；覆写须 (0,4,0)+ 后源注入
   （`.组件根 .行容器 :deep(.el-input__wrapper)` 形态，参照 RuleLibScheduleEditor 终版）。
   验收=浏览器实测 `heightDelta=0 / centerDelta=0`，代码推理不算。
4. **预览收敛在编辑弹框内**：消息模板的预览（自定义模板实时渲染 + 内置模板端点渲染）统一在
   「编辑消息模板」弹框的预览区；不得另设独立预览弹框（已下线日报预览弹框）。预览格式跟随
   弹框格式行的当前选择（`tplFormats`），不按通道类型猜。
5. **通道就绪门**：微信会话失效（`session_ready=false`，会话待刷新）后：选择面禁用+失效原因
   tooltip+已选自动取消（显示层 prune）；保存侧剔除（`sanitizeRuleChannelIDs`）；派发侧跳过并留
   可见原因（不触网）。直到重新绑定且会话就绪。picker 数据源必须透传 `session_ready` 字段
   （曾因映射丢字段整体失效）。
6. **同选择器单声明 + 行首锚定**：同一选择器只允许一条声明（后值静默覆盖前值=不可维护）；
   守卫统计用行首锚定（`^选择器 {`），后代作用域窄覆写（`.A .B {`）合法不算重复。

## 19. 增补裁定（2026-11-22 第八轮，脱敏编辑/健康态/投递收敛/日报口径）
1. **HTML 模板占位符转义纪律**：占位符值进入 HTML 上下文（`body_format=html` 的通道
   正文模板、事件邮件卡片、日报 HTML 模块）必须先 `html.EscapeString` 再拼接——模板
   字面量由用户声明结构，变量内容（正文/标题/IP/UA/规则名/品牌/日期）一律视为不可信
   输入；非 HTML 格式（text/markdown/json）不得进入 HTML 上下文，`{{body}}` 在邮件
   主题模板中保留字面量（防整篇正文顶进主题）。守卫：`internal/notify/
   notify_semantics_hardening_test.go`（转义面）、`internal/notify/sender_email_test.go`
   （Content-Type 跟随渲染格式）。
2. **target_masked 编辑不回写**：通道列表 DTO 带 `target_masked`（true=后端已脱敏非属主
   target）。编辑弹框必须置空目标输入框并给「已脱敏，重新输入完整目标」占位提示
   （`targetMaskedPlaceholder`）；未重新输入时 PUT 体不得包含 `target`（后端保留原值），
   输入后才按通道类型 target JSON 键提交。脱敏串展示不得二次切片。守卫：
   `tests/channelEdit.spec.ts`。
3. **通道选择=last_test_ok 且 sanitize 剔除已知失败**：规则/日报的通道选择面只允许
   `enabled && last_test_ok===true && !(wx_clawbot && session_ready===false)`（`channelSendable`
   单源）；已选通道失效时显示层 `pruneChannelIds` 自动取消，保存侧 `sanitizeRuleChannelIDs`
   以服务端就绪事实剔除（含已知测试失败），派发侧跳过并留可见原因（不触网）。守卫：
   `tests/notificationsCenter.spec.ts`。
4. **日报摘要键=SlaveNodeLabel**：日报节点摘要（`nodes_summary`）与集群节点日报统计的归属键
   必须使用 `notify.SlaveNodeLabel(name, ip, port)` 同形串（「从节点 name(ip:port)」，无
   ip/port 退化为「从节点 name」）；前端 `dailyMultiValueMd` 与后端 `mdMultiValueTable`
   共用跨栈夹具逐字对齐。守卫：`tests/mdPreview.spec.ts`（`fixtures/daily-multivalue-md.json`）
   + `internal/notify/daily_template_mode_test.go`。
5. **投递流水同通道只保留最新结果行**：一次投递的每次尝试都会追加同 `channel_id` 的
   `notification_delivery_channels` 行；展示层按 `channel_id` 收敛（有 id 取最大 id，
   无 id 依赖接口 `ORDER BY nc.id` 的后出现者），否则展开列表重复、成功/失败计数被
   历史重试放大。守卫：`tests/deliveryLog.spec.ts`。
6. **日报渲染模式与后端同口径**：`effectiveDailyMode` = 显式 `daily_mode` 优先；缺省
   时 `payload_template`/`body_template`/`content_template` **任一非空串**即 template
   （不按通道类型挑键、不 trim——后端判据 `Key == ""`）。守卫：
   `tests/channelStyleConfig.spec.ts`。
7. **规则库自动更新开关失败回滚用完整行**：回滚值必须取完整 `LibRow` 的 `autoUpdate`
   （`restoreLibRow` 单源）；合成半行/未加载行的非布尔值回落 `false`，禁止把
   `undefined` 写进展示态。守卫：`tests/securityLibraries.spec.ts`。
8. **展示层查表/只读提示/删除下标防御**：任意字符串键查普通对象前必须 `hasOwn`
   （原型链键不得渲染为函数）；只读操作（IP 名单查询）成功提示走 `ElMessage.success`，
   不消费 MFA 宽限提示；按分页映射删除前必须拒绝负下标（`splice(-1)` 误删末条）。守卫：
   `tests/frontendEdgeGuards.spec.ts`。

## 20. 增补裁定（2026-11-24 第九轮，保存/删除的后果清单与证书告警分流）
1. **删除确认必须列级联清单**：删除类操作（负载规则/安全策略/用户/证书任务等）的
   `ElMessageBox.confirm` 必须列出「一并移除的关联对象」（名称或数量），不得只有一句
   「确定删除吗」——用户必须能看见这次删除会带走什么。清单形态固定为
   `h('ul', { class: 'confirm-scope-list' }, items.map(...))`，首行保留既有确认文案；
   `.confirm-scope-list` / `.confirm-scope-lead` 为全局单源类（main.css，紧邻
   `.el-message-box` 样式块），组件内禁止另写列表样式。清单条目必须对应后端真实级联
   （如规则删除：上游/路径规则/策略绑定/证书任务/历史指标），不得凭猜测新增条目。
2. **保存响应 warnings 以同一清单形态披露**：保存接口返回的 `data.warnings`（握手失败
   类证书问题、可用性变化）必须在 `ElMessageBox.alert` 中以 `.confirm-scope-list` 逐条
   展示，用户确认后才消失；创建与更新同口径（创建同样携带证书材料）。
3. **证书警告响应面分流**：域名不匹配/链不完整 → 保存响应 `warnings`（面板弹框披露）；
   过期/未生效 → 只进审计与证书列表标记（可轮换状态），不得在每次保存时重复弹框。
   守卫：`internal/handlers/rules_cert_warning_response_test.go`、
   `tests/designGuard.spec.ts`（.confirm-scope-list 单源 + 规则删除确认含清单）。

## 21. 增补裁定（2026-11-24 第十轮，用户实测追加的界面口径）
1. **说明文字内的行内链接随正文字号**：`.info-note-bar` / `.form-tip-line` / `.form-tip-inline`
   内的 `el-link`（含 `AccessibleLink`）`font-size: inherit` 并基线对齐，不得比所在说明
   文字大一号（全局规则在 main.css，组件内不得另写）。
2. **证书有效期文案单源**：带符号的剩余天数不得上屏——过期显示「已过期 N 天」（danger），
   当天到期显示「今天到期」，否则「N 天后」（≤30 天 warning）。规则向导的预览行与 TLS
   步骤提示框共用 `certExpiryText`；提示框固定三段（结论 / 证书事实：域名、过期时间 /
   警告列表），过期时间只出现一次；预览行的证书类型、域名标签、过期时间同一行对齐。
3. **从节点 / 只读页面整体只读**：含写操作的表单用 `el-form :disabled`（输入框、开关、
   按钮一并禁用），不得只禁用保存按钮；纯筛选类控件（搜索、视图过滤）除外。
4. **规则选择器次行提示的对齐与间距**：「未绑定策略 / 本策略排第 x 位」这类次行提示，左
   边缘与上一行协议标签的左边缘对齐（缩进 22px = 复选框 14px + 标签内边距 8px），无已绑
   策略时与标题行之间留出间距；首个 chips 的文字列与协议标签文字列同列。两个规则选择器
   （策略页「选择关联规则」与「绑定规则」弹框）同口径。
5. **请求速率口径**：CC 阈值的每个渲染点都写「N 次/秒（{sec} 秒内 > N×W 次）」，窗口内
   总数一律经 `ccWindowBudget` 计算，不得再写成「N 次 / W 秒」；默认值不变。
   守卫：`tests/designGuard.spec.ts`（第 1–4 条）、`tests/ccRateWording.spec.ts`（第 5 条）。

## 22. 增补裁定（2026-11-24 第十二轮，状态语义 / 级联清单 / 深链值域）
1. **列表状态列 = 实际生效态**：策略「启用」但未关联任何规则时不得只显示「启用」——必须
   显示复合态「启用 · 未关联规则」（warning 色）。判定与标签色/文案单源
   （`utils/securityPolicyList.ts` 的 `policyListStatus` + `POLICY_LIST_STATUS_TAG`），
   组件内不得自写 `enabled ? 'success' : 'info'`。守卫：`tests/designGuard.spec.ts`。
2. **删除策略的级联清单须含绑定解除**：§20-1 的延伸——除后端真实级联对象外，
   「同时解除与 N 条规则的绑定」必须进清单（规则名可逐条列出；名称不可得时只报数量，
   不得省略整段）。0 绑定时保持原一句确认。
3. **跨页深链参数消费端必须过值域**：解析走单源（`utils/deepLink.ts`），枚举型参数只认
   白名单取值（如 `eventsAction` 四值、`eventsAutoban` 仅 `config`），非法值丢弃；消费后
   `history.replaceState` 清除 query，刷新不得重复触发。守卫：`tests/designGuard.spec.ts`。

## 23. 增补裁定（2026-11-24 第十三轮，操作前预览 / 失败可见 / 未保存守卫 / 本地化）
1. **覆盖型操作提交前必须有预览**：导入 / 还原这类整份覆盖配置的操作，确认框必须先
   展示「跨版本告警 + 将被置为禁用的规则清单 + 其余告警」（数据来自只读预览接口，
   如 `GET /auto-backup/:id/preview`），形态沿用 `.confirm-scope-lead` / `.confirm-scope-list`；
   预览获取失败**不阻断**——以一行原因披露，仍允许继续。
2. **轮询类查看器的失败必须可见**：日志 / 事件流等自动刷新面的 `onError` 必须置位
   页面错误态（文案 + 重试入口，当前内容保留并注明），禁止只 `console.error`。
   分钟级同步写请求（`timeout: 0`）断连时必须提示「可能仍在后台执行」并给出审计入口。
3. **设置页未保存守卫**：改过且未保存时，离开设置域（侧栏切页）弹确认，刷新被
   `beforeunload` 拦截；切设置内分页不触发。脏态以「当前表单 vs 最近一次保存/加载
   快照」判定，登记走 `useSettingsDraft` 单例（非组件树内也能读到）。
4. **后端下发的展示名不得直出模板**：任务名、日志存储项名等由后端返回的中文字段，
   模板必须经 `utils` 词条映射（按稳定 key）渲染；日志类接口的本地化提示由前端按
   标志（如 `truncated`）渲染，不得混进 `content` 正文。
5. **可配置跳转不缓存**（前后端共同口径）：由用户配置控制的 301 / 302（HTTP→HTTPS
   跳转、路径规则跳转、面板入口跳转）必须带 `Cache-Control: no-store`，否则修改或
   关闭跳转后浏览器仍沿用缓存的旧跳转。请求已是 HTTPS（`X-Forwarded-Proto: https`）
   时不得再跳到同一 https 地址（无限跳转），改为 400 + 说明。守卫：
   `internal/services/caddy_https_redirect_loop_test.go`、
   `caddygeoip/https_redirect_loop_test.go`。
