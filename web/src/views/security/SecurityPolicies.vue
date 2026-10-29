<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Lock /></el-icon>
          安全策略
        </h2>
        <p class="page-desc">管理 WAF 防火墙、IP 访问控制和限流策略</p>
      </div>
      <el-button v-if="!isReadOnly" type="primary" :disabled="loading" @click="openDialog()">
        <el-icon><Plus /></el-icon>
        新建策略
      </el-button>
    </div>

    <!-- 主数据失败与「确实没有策略」必须可区分——保留旧表 + 重试入口
         （同族页 SecurityRules/SecurityBlockPages 同款 error-banner 范式） -->
    <el-alert v-if="policiesLoadError" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
      <template #title>
        <div class="polling-error-title">
          <span>安全策略加载失败：列表为空/停留旧值不代表策略被清空</span>
          <el-button link type="danger" :loading="loading" @click="fetchData">立即重试</el-button>
        </div>
      </template>
    </el-alert>

    <!-- 辅助端点部分失败：计数/冲突告警会降级，必须可见点名（同族页 error-banner 范式） -->
    <el-alert v-if="auxLoadFailures.length > 0" type="warning" :closable="false" show-icon class="polling-error-alert">
      <template #title>
        <div class="polling-error-title">
          <span>部分辅助数据加载失败（{{ auxLoadFailures.join('、') }}）：策略计数与冲突告警可能不完整</span>
          <el-button link type="warning" :loading="loading" @click="fetchData">重新加载</el-button>
        </div>
      </template>
    </el-alert>

    <el-card class="list-card">
      <el-tabs v-model="activeTypeTab" class="policy-type-tabs">
        <el-tab-pane v-for="tab in policyTypeTabs" :key="tab.type" :label="`${tab.label}（${tab.count}）`" :name="tab.type" />
      </el-tabs>
      <div class="table-toolbar">
        <el-input v-model="policySearch" placeholder="搜索策略名称" clearable :prefix-icon="Search" style="width: 240px" />
      </div>
      <el-table :data="pagedPolicies" v-loading="loading" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="">
        <template #empty>
          <el-empty v-if="!policiesLoadError" description="暂无安全策略" :image-size="60" />
          <span v-else class="text-secondary">加载失败，请点击上方「立即重试」</span>
        </template>
        <el-table-column prop="name" label="策略名称" min-width="200">
          <template #default="{ row }">
            <AccessibleLink type="primary" @click="openDialog(row as PolicySummary)">{{ row.name }}</AccessibleLink>
          </template>
        </el-table-column>
        <el-table-column label="关联规则" width="100" align="center">
          <template #default="{ row }">
            <!-- 关联规则 drill-down 必须键盘可达：hover-only tooltip 里的 div 既开不了
                 也点不到，而 role="button" 的 span 没有任何激活行为=假按钮。改用
                 el-dropdown（click 触发 + 菜单内 roving focus + Esc 关闭）：reference 是
                 真按钮，Enter/Space 打开后焦点进入菜单，可逐条跳到规则。 -->
            <el-dropdown
              v-if="policyBoundRules(row.id).length > 0"
              trigger="click"
              placement="bottom-start"
              popper-class="policy-rules-popper"
              :popper-options="popperViewportSafe"
              @command="openRuleInNewTab"
            >
              <button type="button" class="policy-rule-count" :aria-label="`关联规则 ${row.rule_count} 条，查看并跳转规则`">{{ row.rule_count }}</button>
              <template #dropdown>
                <el-dropdown-menu>
                  <el-dropdown-item v-for="rule in policyBoundRules(row.id)" :key="rule.caddy_id" :command="rule.caddy_id">
                    {{ rule.name }} ({{ rule.caddy_id }})
                  </el-dropdown-item>
                </el-dropdown-menu>
              </template>
            </el-dropdown>
            <template v-else>{{ row.rule_count }}</template>
          </template>
        </el-table-column>
        <!-- 内容摘要列（按类型一行摘要） -->
        <el-table-column label="内容摘要" min-width="324">
          <template #default="{ row }">
            <div class="policy-summary-cell">
              <span class="policy-summary-text" :title="policySummaryLine(row as PolicySummary)">{{ policySummaryLine(row as PolicySummary) }}</span>
            </div>
          </template>
        </el-table-column>
        <!-- 24h 触发列（trigger_24h 后端字段）：近 24h 归因该策略的 blocked+logged 事件数，
             每条策略恒显示（0=灰色 info 标签，与 >0 danger 标签同构）；列宽 92=表头四字+cell padding 单行容纳；
             历史（用户反馈）92→108（大数字标签留白不足），差额从内容摘要 min-width 340→324 划出。
             disable-transitions：el-tag 内置 <Transition name="el-zoom-in-center" appear>，切阶段 tab 时
             行重建会重播缩放淡入，居中缩放令标签左缘从中心外起步再回位（视觉上「数字先右偏再归位」）。 -->
        <el-table-column label="24h 触发" width="108" align="center">
          <template #default="{ row }">
            <el-tag v-if="(row.trigger_24h ?? 0) > 0" disable-transitions size="small" type="danger" effect="plain" class="policy-trigger-tag">{{ row.trigger_24h }}</el-tag>
            <el-tag v-else disable-transitions size="small" type="info" effect="plain" class="policy-trigger-tag">0</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="90" align="center">
          <template #default="{ row }">
            <el-tag :type="row.enabled ? 'success' : 'info'" disable-transitions size="small" effect="light">{{ row.enabled ? '启用' : '禁用' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="更新时间" width="170" align="center">
          <template #default="{ row }">{{ formatDate(row.updated_at) || '-' }}</template>
        </el-table-column>
        <el-table-column label="更新者" width="100" align="center">
          <template #default="{ row }">{{ getUpdaterName(row.updated_by) }}</template>
        </el-table-column>
        <el-table-column v-if="!isReadOnly" label="操作" width="168" fixed="right">
          <template #default="{ row }">
            <el-button size="small" link type="primary" @click="openDialog(row as PolicySummary)">{{ policyTypeOf(row as PolicySummary) === 'mixed' ? '查看' : '编辑' }}</el-button>
            <el-button v-if="policyTypeOf(row as PolicySummary) !== 'mixed'" size="small" link type="primary" :disabled="securityBindingsLoading || securityBindingsFailed || bindRulesOpening" :title="securityBindingsLoading ? '规则绑定数据加载中' : securityBindingsFailed ? '规则绑定数据加载失败，请先重新加载' : ''" @click="openBindRulesDialog(row as PolicySummary)">绑定规则</el-button>
            <el-button v-if="policyTypeOf(row as PolicySummary) === 'mixed'" size="small" link type="warning" @click="openMigrateDialog(row as PolicySummary)">更新迁移</el-button>
            <el-button size="small" link type="danger" @click="handleDelete(row as PolicySummary)">删除</el-button>
          </template>
        </el-table-column>

      </el-table>
      <!-- 与其他表格页同款分页器（2026-09-25 用户裁定）：右对齐 + 16px 上距 -->
      <div class="rules-pagination">
        <el-pagination
          v-model:current-page="policyPage"
          v-model:page-size="policyPageSize"
          :page-sizes="[10, 20, 50]"
          :total="filteredPolicies.length"
          layout="total, sizes, prev, pager, next"
          @size-change="policyPage = 1"
        />
      </div>
    </el-card>
    <!-- 混合策略更新迁移预演：确认前展示将创建的子策略/重映射范围/上限风险 -->
    <el-dialog v-model="migrateVisible" class="dialog-body-inset" width="min(560px, 94vw)" top="10vh" :close-on-click-modal="false" :close-on-press-escape="!migrateSaving" :show-close="!migrateSaving">
      <template #header>
        <DialogHeader :icon="WarningFilled" title="更新迁移预演"
          :subtitle="`混合策略「${migratePolicy?.name}」将按阶段迁移为单职子策略（兼容组不再支持新建）`" />
      </template>
      <div v-if="migratePolicy" class="migrate-preview">
        <div class="migrate-preview-section">
          <DialogSectionHeader :title="`将创建 ${migrateChildTypes.length} 条子策略`" tone="warning" />
          <div class="dialog-panel">
            <div class="migrate-preview-tags">
              <!-- 四阶段恒出（2026-09-21 用户裁定：与查看弹框/流程弹框同口径）——
                   空阶段灰态标注「未启用 · 不生成」，不再整段缺席 -->
              <el-tag v-for="type in (['stage0', 'stage1', 'stage2', 'stage3'] as const)" :key="type" size="small" effect="plain" :type="migrateChildTypes.includes(type) ? 'primary' : 'info'">
                {{ migrateChildTypes.includes(type) ? `${migratePolicy.name}（${POLICY_TYPE_SHORT_LABELS[type]}）` : `${POLICY_TYPE_SHORT_LABELS[type]} · 未启用（不生成）` }}
              </el-tag>
            </div>
          </div>
        </div>
        <div class="migrate-preview-section">
          <DialogSectionHeader title="将重映射绑定" description="原策略的绑定整体改挂到子策略" tone="warning" />
          <div class="dialog-panel">
            <template v-if="migrateBoundRules.length > 0">
              <div v-for="rule in migrateBoundRules" :key="rule.caddy_id" class="migrate-preview-rule">
                <span class="migrate-preview-rule-name">{{ rule.name }}</span>
                <span class="migrate-preview-rule-meta">{{ rule.domain || '-' }}:{{ rule.listen_port }}</span>
                <el-tag v-if="migrateStage2SkipRisk.some((r) => r.caddy_id === rule.caddy_id)" size="small" type="warning" effect="plain">将跳过（已有 stage2）</el-tag>
              </div>
            </template>
            <div v-else class="migrate-preview-empty">当前无规则绑定本策略</div>
          </div>
        </div>
        <div v-if="migrateStage2SkipRisk.length > 0" class="info-note-bar"><span class="info-note-desc">限流唯一风险：{{ migrateStage2SkipRisk.map((r) => r.name).join('、') }} 已绑定其他限流策略——拆分将产出阶段 2 子策略，这些规则会跳过重映射（每条规则最多一条限流策略），保持原绑定</span></div>
        <div v-if="migrateCapRisk.length > 0" class="info-note-bar"><span class="info-note-desc">上限风险：{{ migrateCapRisk.map((r) => r.name).join('、') }} 迁移后将超过每条规则 {{ MAX_POLICIES_PER_RULE }} 条绑定上限——这些规则保持原绑定并进入跳过清单</span></div>
        <div class="info-note-bar"><span class="info-note-desc">全部规则重映射成功后原策略将被删除；存在被跳过的规则时原策略保留（因仍在使用）</span></div>
      </div>
      <template #footer>
        <el-button :disabled="migrateSaving" @click="cancelMigrate">取消</el-button>
        <el-button type="warning" :loading="migrateSaving" :disabled="migrateSaving" @click="submitMigrate">确认更新迁移</el-button>
      </template>
    </el-dialog>

    <!-- 混合策略只读查看：按阶段分组展示全部内容，零可编辑字段，底部唯一操作=更新迁移 -->
    <el-dialog v-model="viewPolicyVisible" width="min(760px, 94vw)" top="6vh">
      <template #header>
        <DialogHeader :icon="Lock" :title="viewPolicyDetail?.name || viewPolicyRow?.name || ''"
          subtitle="混合策略（兼容旧版）· 只读查看——经「更新迁移」拆分为单职策略后可编辑" />
      </template>
      <div v-loading="viewPolicyLoading" class="view-policy-body">
        <template v-if="viewPolicyDetail">
          <div v-for="section in viewPolicySections" :key="section.title" class="view-policy-section">
            <DialogSectionHeader :title="section.title" />
            <div class="dialog-panel">
              <div v-for="row in section.rows" :key="row.label" class="view-policy-row">
                <span class="view-policy-label">{{ row.label }}</span>
                <span class="view-policy-value" :title="row.value">{{ row.value }}</span>
              </div>
            </div>
          </div>
          <div class="view-policy-section">
            <DialogSectionHeader :title="`关联规则（${viewPolicyBoundRuleRows.length}）`" />
            <div class="dialog-panel">
              <template v-if="viewPolicyBoundRuleRows.length > 0">
                <div v-for="rule in viewPolicyBoundRuleRows" :key="rule.caddyId" class="view-policy-row">
                  <span class="view-policy-label">{{ rule.name }}</span>
                  <span class="view-policy-value">{{ rule.domain || '-' }}:{{ rule.listenPort }}</span>
                </div>
              </template>
              <div v-else class="view-policy-empty">未关联规则</div>
            </div>
          </div>
        </template>
      </div>
      <template #footer>
        <el-button @click="viewPolicyVisible = false">关闭</el-button>
        <el-button v-if="!isReadOnly" type="warning" @click="openMigrateFromView">更新迁移</el-button>
      </template>
    </el-dialog>
    <el-dialog v-model="dialogVisible" class="dialog-body-inset" width="min(950px, 94vw)" top="5vh" :close-on-click-modal="false" :before-close="beforeWizardClose" @close="resetWizard">
      <template #header>
        <DialogHeader :icon="Lock" :title="editingId ? (isReadOnly ? '查看策略' : '编辑策略') : '新建策略'"
          :subtitle="EDITOR_SUBTITLES[editorPolicyType]" tone="primary" />
      </template>
      <el-steps :active="visualStepIndex" finish-status="success" align-center class="wizard-steps" :class="{ 'is-clickable': stepsClickable && !saving }">
        <el-step
          v-for="step in visibleSteps"
          :key="step"
          :title="WIZARD_STEP_META[step].title"
          :icon="WIZARD_STEP_META[step].icon"
          @click="jumpToStep(step)"
        />
      </el-steps>

      <div class="wizard-content">
        <!-- Step 0: 基础信息 -->
        <div v-show="currentStep === WIZARD_STEP.BASIC" class="step-content">
          <el-form :model="form" label-width="100px" :disabled="formFrozen">
            <!-- 策略类型：新建时选择（决定步骤条与表单裁剪）；编辑时固定展示。
                 与 el-form-item label 完全同构（用户裁定）；radio 不用 el-radio-group
                 包组——组容器 DIV 会被 EP 注册为表单输入 id 触发 Firefox label-for 告警，
                 改为同 model-value 的独立 radio 纵向列表（首行与输入框基线对齐） -->
            <el-form-item v-if="editingId === null" label="策略类型" required>
              <div class="policy-type-radio-list" role="radiogroup" aria-label="策略类型">
                <el-radio
                  v-for="opt in POLICY_TYPE_CREATE_OPTIONS"
                  :key="opt.value"
                  :model-value="createPolicyType"
                  :value="opt.value"
                  @update:model-value="createPolicyType = opt.value"
                >{{ opt.label }}</el-radio>
              </div>
            </el-form-item>
            <el-form-item v-else label="策略类型">
              <el-tag :type="editorPolicyType === 'mixed' ? 'warning' : 'primary'" effect="plain">{{ POLICY_TYPE_LABELS[editorPolicyType] }}</el-tag>
            </el-form-item>
            <el-form-item label="名称" required>
              <el-input v-model="form.name" placeholder="策略名称" :maxlength="SECURITY_NAME_MAX_RUNES" show-word-limit />
            </el-form-item>
            <el-form-item label="描述">
              <el-input v-model="form.description" placeholder="策略描述" :maxlength="SECURITY_DESCRIPTION_MAX_RUNES" show-word-limit />
            </el-form-item>
            <el-form-item label="启用状态">
              <el-switch v-model="form.enabled" />
              <span class="form-tip-inline">禁用后该策略对所有关联规则停止生效</span>
            </el-form-item>
          </el-form>
        </div>
        <!-- Step: 阶段 0 · 信任名单（stage0 编辑器表单：信任名单内联+引用 + 保留检测记录开关） -->
        <div v-show="currentStep === WIZARD_STEP.TRUST" class="step-content">
          <div class="stage-projection-bar">
            <span class="stage-projection-desc">本策略将在关联规则的信任名单阶段生效——信任 IP 命中后跳过全部后续安全阶段</span>
            <div class="stage-projection-rules">
              <span v-if="boundRules.length === 0" class="stage-projection-empty">尚未关联规则</span>
              <span v-else class="stage-projection-empty">将应用于 {{ boundRules.length }} 条已关联规则</span>
            </div>
          </div>
          <el-form :model="form" label-width="100px" :disabled="formFrozen">
            <el-form-item label="信任 IP">
              <div class="acl-inline-row">
                <el-select v-model="ipWhitelist" multiple filterable allow-create default-first-option placeholder="输入 IP/CIDR 后回车" class="acl-inline-select" />
                <el-button v-if="!isReadOnly" link type="primary" class="acl-extract-btn" :disabled="ipWhitelist.length === 0" @click="openExtractDialog('trust')">提取为列表</el-button>
              </div>
              <div class="form-tip-line">名单内 IP 跳过全部后续安全阶段（IP 访问控制 / 限流 / WAF）；内联与引用列表合并生效</div>
            </el-form-item>
            <el-form-item label="引用地址列表">
              <el-select v-model="ipWhitelistRefs" multiple filterable placeholder="选择要引用的 IP 地址列表" style="width: 100%">
                <!-- 内置威胁名单仅可用于 IP ACL 黑名单（2026-09-24 用户裁定），信任名单不可引用 -->
                <el-option-group v-if="customIpLists.length > 0" label="自定义列表">
                  <el-option v-for="l in customIpLists" :key="l.id" :label="`${l.name}（${l.entry_count} 条）`" :value="l.id" />
                </el-option-group>
              </el-select>
              <div v-if="showWhitelistRefHint" class="form-tip-line">{{ whitelistRefHint }}</div>
            </el-form-item>
            <el-form-item label="保留检测记录">
              <el-switch v-model="form.trust_detection" />
              <span class="form-tip-inline">{{ form.trust_detection ? '开启：信任 IP 仍过后续检测流程，事件动作记为检测' : '关闭（默认）：信任 IP 直通上游，不产生任何安全事件' }}</span>
            </el-form-item>
            <!-- 信任名单区地址级冲突实时警告（本区条目：信任 IP × 他策略黑名单）：
                 el-form 直接子级（2026-10-03 模板归一），缩进由
                 提示条在表单项内自然对齐控件列（EP label-width 布局，零 CSS 覆盖） -->
            <el-form-item v-if="whitelistSectionAlert"><div class="info-note-bar"><span class="info-note-desc">{{ whitelistSectionAlert }}</span></div>
            </el-form-item>
          </el-form>
        </div>

        <!-- Step 1: WAF 规则 -->
        <div v-show="currentStep === WIZARD_STEP.WAF_RULES" class="step-content">
          <!-- 投影条：左=生效说明句、右=关联规则覆盖状态。历史改为摘要口径（原逐规则
               清单在关联规则多时撑破弹框：右段 flex:0 0 auto 按 max-content 定尺挤压左段
               成单字竖排，见 SecurityPolicies 弹框实测）；逐规则覆盖状态与编辑在「关联规则」步骤 -->
          <div class="stage-projection-bar">
            <span class="stage-projection-desc">本策略将在关联规则的 WAF 阶段生效</span>
            <div class="stage-projection-rules">
              <span v-if="boundRules.length === 0" class="stage-projection-empty">尚未关联规则</span>
              <span v-else class="stage-projection-empty">将应用于 {{ boundRules.length }} 条已关联规则</span>
            </div>
          </div>
          <el-form :model="form" label-width="100px" :disabled="formFrozen">
            <!-- 原生表单行（2026-10-11 用户裁定：对齐统一走 el-form-item；Firefox
                 label-for 控制台告警为 EP 上游已知形态，非用户可见） -->
            <el-form-item label="WAF 模式">
              <el-radio-group v-model="form.mode" class="mode-radio-group" aria-label="WAF 模式">
                <!-- 2026-09-09 四态化:off=CRS 与自定义均不生效;custom_only=仅自定义生效;
                     detection=CRS 只记录;blocking=CRS 阻断。每项标签+描述单行不换行。 -->
                <el-radio value="off">关闭（全不生效）</el-radio>
                <el-radio value="custom_only">仅自定义规则（CRS 不生效）</el-radio>
                <el-radio value="detection">检测（CRS 只记录）</el-radio>
                <el-radio value="blocking">拦截（CRS 阻断）</el-radio>
              </el-radio-group>
              <div class="form-tip-line">关闭 = CRS 与自定义规则均不生效；IP 访问控制与地域拦截按各自开关独立生效。</div>
              <div class="form-tip-line">自定义规则在检测/拦截/仅自定义模式下按规则内动作执行；计分动作在 CRS 开启时由异常阈值统一裁决（检测计分、拦截按阈值）。</div>
            </el-form-item>
            <div v-if="form.mode === 'off'" class="waf-off-hint">当前 WAF 已关闭：CRS 与自定义规则均不生效，以下 CRS 配置不可用</div>
            <div v-else-if="form.mode === 'custom_only'" class="waf-off-hint">仅自定义模式：CRS 不生效，以下 CRS 配置不可用</div>
            <el-form-item label="异常阈值">
              <el-select v-model="form.anomaly_threshold" :disabled="crsFieldsOff || isReadOnly" style="width: 140px">
                <el-option v-if="[1, 3].includes(form.anomaly_threshold)" :value="1" label="严格（阈值 1 · 存量档）" disabled />
                <el-option v-if="form.anomaly_threshold === 3" :value="3" label="严格（阈值 3 · 存量档）" disabled />
                <el-option :value="5" label="标准（阈值 5）" />
                <el-option :value="10" label="宽松（阈值 10）" />
                <el-option :value="15" label="很宽松（阈值 15）" />
                <el-option :value="20" label="极宽松（阈值 20）" />
              </el-select>
              <div class="form-tip-line">阈值以异常分为单位：CRS 严重规则每条 +5（错误 +4、警告 +3），自定义「计分」规则按其分值累加。</div>
              <div class="form-tip-line">累计达到阈值拦截；低于阈值的命中不拦截，但记录为检测事件（计入安全总览「今日检测」）。</div>
            </el-form-item>
            <el-form-item label="CRS 规则组">
              <!-- 懒加载级联多选：一级规则组节点（剔 01/49/59），展开组时才生成该组
                   规则叶（剔 901/949/959，label「ID — 描述」+ 副行「文件 · 分类」仿
                   旧版两行样式）；checkStrictly 允许组 + 单规则混选，值↔路径由
                   crsGroupCascaderValue 双向桥接（组→[组号]、规则→[组号, 规则ID]），
                   写回取路径末段保持存储契约（两位组号 ∪ 6 位规则 ID）不变；陈旧规则
                   ID/遗留文件名无法映射路径，以 ghost 标签兜底展示可单独删除；:key
                   在索引就绪后重挂载，避免在途期间展开组缓存空叶。 -->
              <el-cascader
                :key="crsIndexLoaded ? 'ready' : 'pending'"
                v-model="crsGroupCascaderValue"
                :props="crsGroupCascaderProps"
                :disabled="crsFieldsOff"
                filterable
                collapse-tags
                collapse-tags-tooltip
                :show-all-levels="false"
                popper-class="crs-rule-popper"
                placeholder="留空加载全部 CRS 规则"
                style="width: 100%"
              >
                <template #default="{ data }">
                  <div v-if="data.isRule" class="crs-rule-option" :title="`${data.value} — ${data.fullLabel}`">
                    <div class="crs-rule-option-label">{{ data.label }}</div>
                    <div class="crs-rule-option-meta">{{ data.file }} · {{ data.category }}</div>
                  </div>
                  <span v-else>{{ data.label }}</span>
                </template>
              </el-cascader>
              <!-- ghost 标签：CRS 更新后消失的规则 ID / 遗留文件名形态（级联无法映射
                   路径），可读展示（「942100 —（当前 CRS 已无此规则）」式）且可删除 -->
              <div v-if="crsGroupGhostTags.length > 0" class="crs-ghost-tags">
                <el-tag
                  v-for="opt in crsGroupGhostTags"
                  :key="opt.value"
                  size="small"
                  type="info"
                  effect="plain"
                  :closable="!crsFieldsOff && !isReadOnly"
                  :disable-transitions="true"
                  :title="opt.title"
                  @close="removeCrsGroupValue(opt.value)"
                >{{ opt.label }}</el-tag>
              </div>
              <div class="form-tip-line">选择后仅加载所选规则组，留空加载全部 CRS 规则</div>
              <div class="form-tip-line">初始化（901）与拦截评估（949/959）为系统基础规则，随策略自动加载；通用误报豁免（999）在选择全部规则时自动包含</div>
            </el-form-item>
            <!-- 跨策略 CRS 规则组重复实时警告（随当前选择重算）：el-form 直接子级
                 提示条在表单项内自然对齐控件列（EP label-width 布局，零 CSS 覆盖） -->
            <el-form-item v-if="wafStepCrsAlert"><div class="info-note-bar"><span class="info-note-desc">{{ wafStepCrsAlert }}</span></div>
            </el-form-item>
            <el-form-item v-if="hasResponsePhaseGroupWithoutCheck"><div class="info-note-bar"><span class="info-note-desc">已选含响应阶段的规则组（955 Webshell 等），但未开启「检查响应体」——这些组不会加载生效，请开启「检查响应体」或移除响应阶段组</span></div>
            </el-form-item>
            <el-form-item label="检查响应体">
              <el-switch v-model="form.waf_check_response" :disabled="crsFieldsOff || isReadOnly" />
              <div class="form-tip-line">开启后 WAF 读取并检查上游响应内容（响应泄露类规则需要）；关闭可显著降低内存与 CPU 开销，大多数部署只需检查请求</div>
            </el-form-item>
            <el-form-item label="记录请求体">
              <el-switch v-model="form.log_request_body" :disabled="isReadOnly || form.mode === 'off'" />
              <div class="form-tip-line">仅 CRS/自定义规则命中事件记录请求体；当前模式关闭时不记录</div>
            </el-form-item>
            <el-form-item v-if="form.log_request_body"><div class="info-note-bar"><span class="info-note-desc">开启后命中规则事件的请求体将明文记录到事件库（单条上限 64KB），可能包含密码等敏感信息，请仅在排障期间开启</span></div>
            </el-form-item>
            <el-form-item label="排除规则">
              <!-- 表格行编辑器：目标（与规则组同款混合下拉）× 作用域（全部 IP/指定 IP/地址
                   列表）× 条件控件（ip → 标签输入 + isValidCidr 即时拒绝；list → 引用
                   /security/ip-lists 列表）× 删除。上限 50 行；旧字符串数组存储读取时已
                   归一为 scope:all 行，保存统一写对象数组。
                    布局：空态不渲染表格——单行紧凑引导（说明 + 添加按钮）避免挤占弹框
                    高度；有条目才渲染表格，条目多时容器 max-height 260px 内部滚动（表头
                    sticky 固定），不再撑高弹框。每条排除单行呈现（目标 × 作用域 × 条件
                    合并列）：行内控件统一 small（24px）同高 + 单元格顶部对齐；cascader
                    弹性占满剩余宽（min 280px）、radios 自然紧凑、条件控件内联于 radios
                    之后（all 灰字短提示 / ip 标签输入 min 220 max 360 / list 紧凑选择），
                    行高 ~32-40px（原双行 60px+）；合并列 min-width 560 + 删除列 60 低于
                    弹框内容宽 → 1080px 全宽不换行、无横向滚动；条目数徽标随工具行。 -->
              <!-- 2026-09-19 用户裁定:空态按钮在首行(与「排除规则」标题同一
                   水平线、内容列左对齐),描述文字居其下 -->
              <div v-if="crsExcludedRows.length === 0" class="exclusion-empty">
                <el-button size="small" type="primary" plain :disabled="crsFieldsOff || isReadOnly" @click="addExcludedRule">添加排除规则</el-button>
                <span class="exclusion-empty-tip">未添加排除规则——排除的目标规则/规则组不会被检测或拦截；作用域限定排除仅对所选来源 IP 或地址列表生效</span>
              </div>
              <template v-else>
                <el-table :data="crsExcludedRows" size="small" class="exclusion-table" :max-height="260">
                  <!-- 单行合并列：目标规则 × 作用域 × 条件，一条排除规则一行呈现——
                       左起：目标 cascader（弹性占满剩余，min 280px）+ ghost 内联标签 +
                       冲突警告图标（tooltip 悬浮）→ 作用域 radios（自然宽）→ 条件控件
                       内联随 radios 之后，条件区为恒定槽位（见下方 CSS——三态同
                       flex 规格，切换作用域不改变剩余空间分配，cascader 宽度与
                       radios 位置恒定不抖动），行高 ~32-40px；1080px 弹框全宽下
                       不换行，窄于该宽度时 flex-wrap 优雅折行且首行对齐不乱；ghost /
                       冲突图标出现只挤压 cascader 宽度，不改行结构 -->
                  <el-table-column label="目标规则 × 作用域 × 条件" min-width="560">
                    <template #default="{ row }">
                      <div class="exclusion-row-cell">
                        <!-- 懒加载级联单选（与规则组同一懒加载实现，排除口径：剔 01 组
                             /901 ID，保留 49/59/80）：每行一个 cascader（上限 50 行），
                             面板展开才挂载菜单、展开组才生成该组规则叶；checkStrictly
                             组或单条规则皆可作为 target。已存值能映射路径（组→[组号]、
                             规则→[组号, 规则ID]）则级联回填显示解析标签；不能映射
                             （遗留文件名/陈旧 ID/被剔口径值）由右侧 ghost 标签兜底，
                             可清除（×）或直接改选覆盖。key 在索引就绪后重挂载，避免
                             在途期间展开组缓存空叶。 -->
                        <el-cascader
                          :key="crsIndexLoaded ? 'ready' : 'pending'"
                          :model-value="exclusionTargetPath(row.target)"
                          :props="crsExclusionCascaderProps"
                          size="small"
                          filterable
                          clearable
                          :show-all-levels="false"
                          :disabled="crsFieldsOff || isReadOnly"
                          popper-class="crs-rule-popper"
                          placeholder="选择规则组 / 单条规则"
                          class="exclusion-target-select"
                          @update:model-value="(value: CascaderValue | null | undefined) => onExclusionTargetChange(row as CrsExcludedRow, value)"
                        >
                          <template #default="{ data }">
                            <div v-if="data.isRule" class="crs-rule-option" :title="`${data.value} — ${data.fullLabel}`">
                              <div class="crs-rule-option-label">{{ data.label }}</div>
                              <div class="crs-rule-option-meta">{{ data.file }} · {{ data.category }}</div>
                            </div>
                            <span v-else>{{ data.label }}</span>
                          </template>
                        </el-cascader>
                        <el-tag
                          v-if="exclusionRowGhostLabel(row.target) !== ''"
                          size="small"
                          type="info"
                          effect="plain"
                          class="exclusion-target-ghost"
                          :title="row.target"
                          :closable="!crsFieldsOff && !isReadOnly"
                          :disable-transitions="true"
                          @close="row.target = ''"
                        >{{ exclusionRowGhostLabel(row.target) }}</el-tag>
                        <!-- 行级矛盾提示：目标同时出现在规则组正选与排除清单（单条 ID 矛盾 /
                             整组冗余），排除恒优先——提示而非阻断。行内警告图标 +
                             tooltip 悬浮展示全文，不占布局流 -->
                        <el-tooltip
                          v-if="exclusionRowConflict(row as CrsExcludedRow)"
                          :content="exclusionRowConflict(row as CrsExcludedRow)"
                          placement="top"
                          :show-after="200"
                        >
                          <el-icon class="exclusion-conflict-icon"><WarningFilled /></el-icon>
                        </el-tooltip>
                        <el-radio-group v-model="row.scope" size="small" class="exclusion-scope-radios" :disabled="crsFieldsOff || isReadOnly" @change="onScopeChange(row as CrsExcludedRow)">
                          <el-radio value="all">全部 IP</el-radio>
                          <el-radio value="ip">指定 IP</el-radio>
                          <el-radio value="list">地址列表</el-radio>
                        </el-radio-group>
                        <!-- 条件控件内联于 radios 之后：all → 灰字短提示（自然宽、不预留
                             布局空间）/ ip → 标签输入（min 220 max 360）/ list → 列表
                             多选（紧凑宽）；切换只影响 radios 之后的空位，radios 与
                             cascader 位置不抖动 -->
                        <el-select
                          v-if="row.scope === 'ip'"
                          v-model="row.ips"
                          size="small"
                          multiple
                          filterable
                          allow-create
                          default-first-option
                          :disabled="crsFieldsOff || isReadOnly"
                          placeholder="输入 IP/CIDR 后回车"
                          class="exclusion-scope-control-ip"
                          @change="(value: string[]) => onExclusionIpsChange(row as CrsExcludedRow, value)"
                        />
                        <el-select
                          v-else-if="row.scope === 'list'"
                          v-model="row.listRefs"
                          size="small"
                          multiple
                          filterable
                          :disabled="crsFieldsOff || isReadOnly"
                          placeholder="选择 IP 地址列表"
                          class="exclusion-scope-control-list"
                        >
                          <el-option-group v-if="customIpLists.length > 0" label="自定义列表">
                  <el-option v-for="l in customIpLists" :key="l.id" :label="`${l.name}（${l.entry_count} 条）`" :value="l.id" />
                </el-option-group>
                        </el-select>
                        <span v-else class="exclusion-scope-all">对所有 IP 生效</span>
                      </div>
                    </template>
                  </el-table-column>
                  <el-table-column label="" width="60" align="center">
                    <template #default="{ $index }">
                      <el-button link type="danger" size="small" :disabled="crsFieldsOff || isReadOnly" @click="removeExcludedRule($index)">删除</el-button>
                    </template>
                  </el-table-column>
                </el-table>
                <div class="exclusion-toolbar">
                  <el-button size="small" type="primary" plain :disabled="crsFieldsOff || isReadOnly || crsExcludedRows.length >= CRS_EXCLUDED_MAX_ROWS" @click="addExcludedRule">添加排除规则</el-button>
                  <el-tag size="small" type="info" effect="plain" class="exclusion-count">{{ crsExcludedRows.length }}/{{ CRS_EXCLUDED_MAX_ROWS }}</el-tag>
                </div>
                <div class="form-tip-line">排除的目标规则/规则组不会被检测或拦截；作用域限定排除仅对所选来源 IP 或地址列表生效</div>
              </template>
            </el-form-item>
            <el-form-item v-if="blockingEvalExclusionAlert"><div class="info-note-bar"><span class="info-note-desc">排除评估规则（949/959）将使拦截模式的评分阈值拦截失效</span></div>
            </el-form-item>
            <el-form-item label="自定义规则">
              <el-select v-model="selectedCustomRules" :disabled="form.mode === 'off'" multiple filterable placeholder="选择要包含的自定义规则" style="width: 100%">
                <el-option v-for="rule in allCustomRules" :key="rule.id" :label="rule.name" :value="rule.id" />
              </el-select>
              <div class="form-tip-line">自定义规则在"规则集"页面创建，<AccessibleLink type="primary" @click="goToCustomRulesPage">去创建/编辑</AccessibleLink></div>
            </el-form-item>
          </el-form>
        </div>
        <!-- Step 2: IP 访问控制 -->
        <div v-show="currentStep === WIZARD_STEP.IP_ACL" class="step-content">
          <div class="stage-projection-bar">
            <span class="stage-projection-desc">本策略将在关联规则的 IP 访问控制/地域拦截阶段生效</span>
            <div class="stage-projection-rules">
              <span v-if="boundRules.length === 0" class="stage-projection-empty">尚未关联规则</span>
              <span v-else class="stage-projection-empty">将应用于 {{ boundRules.length }} 条已关联规则</span>
            </div>
          </div>
          <el-divider content-position="left" class="acl-divider">访问控制</el-divider>
          <el-form :model="form" label-width="100px" :disabled="formFrozen">
            <el-form-item label="启用">
              <el-switch v-model="form.ip_acl_enabled" />
            </el-form-item>
            <template v-if="form.ip_acl_enabled">
              <el-form-item label="控制模式">
                <el-radio-group v-model="form.ip_acl_mode" aria-label="IP 访问控制模式">
                  <el-radio value="deny">黑名单（拒绝列表中的 IP，其他正常检测）</el-radio>
                  <el-radio value="allow">白名单（仅允许列表中的 IP，其他一律拒绝）</el-radio>
                  <!-- 历史 绕过 策略仅作展示，不再提供新选 -->
                  <el-radio v-if="form.ip_acl_mode === '绕过'" value="绕过">免检测（列表中的 IP 跳过全部安全检测）</el-radio>
                </el-radio-group>
              </el-form-item>
              <el-form-item :label="aclListLabel">
                <div class="acl-inline-row">
                  <el-select v-model="ipACLList" multiple filterable allow-create default-first-option placeholder="输入 IP/CIDR 后回车" class="acl-inline-select" />
                  <el-button v-if="!isReadOnly" link type="primary" class="acl-extract-btn" :disabled="ipACLList.length === 0" @click="openExtractDialog('acl')">提取为列表</el-button>
                </div>
                <div class="form-tip-line">{{ aclListTip }}</div>
              </el-form-item>
              <el-form-item label="引用地址列表">
                <el-select v-model="ipACLListRefs" multiple filterable placeholder="选择要引用的 IP 地址列表" style="width: 100%">
                  <el-option-group v-if="form.ip_acl_mode === 'deny' && builtinIpLists.length > 0" label="内置威胁名单">
                  <el-option v-for="l in builtinIpLists" :key="l.id" :label="`${l.name}（${l.entry_count} 条）`" :value="l.id" />
                </el-option-group>
                <el-option-group v-if="customIpLists.length > 0" label="自定义列表">
                  <el-option v-for="l in customIpLists" :key="l.id" :label="`${l.name}（${l.entry_count} 条）`" :value="l.id" />
                </el-option-group>
                </el-select>
                <div v-if="showAclRefHint" class="form-tip-line">{{ aclRefHint }}</div>
                <div class="form-tip-line">引用「规则集 → IP 地址列表」中的可复用列表，条目与上方内联名单合并生效</div>
              </el-form-item>
              <!-- 访问控制区地址级冲突实时警告（本区条目：ACL 列表 + 黑名单）：
                   el-form 直接子级（2026-10-03 模板归一），缩进由
                   提示条在表单项内自然对齐控件列（EP label-width 布局，零 CSS 覆盖） -->
              <el-form-item v-if="aclSectionAlert"><div class="info-note-bar"><span class="info-note-desc">{{ aclSectionAlert }}</span></div>
              </el-form-item>
            </template>
          </el-form>
          <el-divider content-position="left" class="acl-divider">区域控制</el-divider>
          <el-form :model="form" label-width="100px" :disabled="formFrozen">
            <el-form-item label="启用">
              <!-- 开关即生效状态：关闭提交 geoip_mode='off'（后端零发射），名单
                   保留不清单（重开即复用）；从 off 重开时控制模式回落 deny。 -->
              <el-switch v-model="form.geoip_enabled" @change="onGeoipEnabledChange" />
            </el-form-item>
            <template v-if="form.geoip_enabled">
              <!-- （裁决）：披露 IPv6/不可解析客户端语义——
                   fail-closed 设计下它们按「海外」处理。 -->
              <el-form-item><div class="info-note-bar"><span class="info-note-desc">地域规则仅对 IPv4 生效：IPv6 与不可解析客户端按「海外」处理（拦截模式勾选海外时将被拦截；仅允许模式只勾选省份时将被拦截）。IP 库未安装时地域规则不可启用。</span></div>
              </el-form-item>
              <el-form-item label="控制模式">
                <el-radio-group v-model="form.geoip_mode" aria-label="地域控制模式">
                  <el-radio value="deny">拦截所选区域（其他放行）</el-radio>
                  <el-radio value="allow">仅允许所选区域（其他拦截）</el-radio>
                </el-radio-group>
              </el-form-item>
              <el-form-item label="区域选择">
                <!-- （用户裁决）：区域精确到市——省级联选择；只选省 =
                     整省生效（存量语义），展开选市 = 省+市联合匹配（省/市 形态）。
                     v2.3.7 修正：独立「海外」一级叶子取消——「海外国家」父节点
                     可勾选，勾选 = 全部海外（解析失败/IPv6 兜底哨兵 ∪ 全部
                     已解析国名）；展开按国家粒度勾选，标签中文、提交英文国名。 -->
                <el-cascader
                  v-model="geoipCountries"
                  :options="regionCascaderOptions"
                  :props="{ multiple: true, checkStrictly: true, emitPath: false }"
                  filterable
                  clearable
                  placeholder="选择区域（省 / 省-市 / 海外国家）"
                  style="width: 100%"
                />
                <div class="form-tip-line">基于 IP2Region 离线库判断访客所在区域，与 CIDR 规则同时生效；只选省份 = 整省生效</div>
                <!-- 加载失败显性化+重试；已保存的地域值保留不清空-->
                <div v-if="regionsError" class="form-tip-line">
                  <el-text type="danger" size="small">地域数据加载失败，已保存的地域配置仍保留。</el-text>
                  <AccessibleLink type="primary" size="small" @click="fetchRegions">重试</AccessibleLink>
                </div>
              </el-form-item>
              <!-- v2.3.8 爬虫豁免（方案 B）：已验证搜索引擎/AI 爬虫跳过地域拦截。
                   验证=UA+PTR 双跳（360=官方 IP 段），伪装 UA 独立记「爬虫伪装」事件。 -->
              <el-form-item label="爬虫豁免">
                <el-switch v-model="form.geoip_crawler_exempt" />
                <template v-if="form.geoip_crawler_exempt">
                  <el-checkbox-group v-model="form.geoip_crawler_engines" style="margin-left: 12px">
                    <el-checkbox v-for="e in crawlerEngineOptions" :key="e.id" :value="e.id">{{ e.name }}</el-checkbox>
                  </el-checkbox-group>
                  <div class="form-tip-line">勾选的引擎经反向 DNS/官方 IP 段验证为真实爬虫后豁免地域拦截（IP 名单/WAF/限流仍全量生效）；伪装爬虫 UA 的请求会被拒绝并记录攻击事件。360 无反查支持按官方 IP 段验证；标注「观察级」的引擎按厂商域名验证</div>
                  <!-- 空选=全部引擎（后端空集语义），必须显性说明——否则
                       用户以为「全不选=不豁免」，实际是全豁免 -->
                  <div v-if="form.geoip_crawler_engines.length === 0" class="form-tip-line">
                    <el-text type="warning" size="small">未勾选任何引擎：等于豁免全部引擎（此形态不可保存，请至少勾选一个或关闭爬虫豁免）</el-text>
                  </div>
                </template>
              </el-form-item>
            </template>
          </el-form>
        </div>
        <!-- Step 3: 限流 -->
        <div v-show="currentStep === WIZARD_STEP.RATE_LIMIT" class="step-content">
          <div class="stage-projection-bar">
            <span class="stage-projection-desc">本策略将在关联规则的限流阶段生效——限流拦截恒为 429（便于指标单独计量）；拦截页在下一步配置，缺省时跟随同规则其他策略的页面</span>
            <div class="stage-projection-rules">
              <span class="stage-projection-empty">{{ boundRules.length > 0 ? `将应用于 ${boundRules.length} 条已关联规则` : '尚未关联规则' }}</span>
            </div>
          </div>
          <el-form :model="form" label-width="100px" :disabled="formFrozen">
            <el-form-item label="启用">
              <el-switch v-model="form.rate_limit_enabled" />
            </el-form-item>
            <template v-if="form.rate_limit_enabled">
              <el-form-item label="速率上限">
                <el-input-number v-model="form.rate_limit_rps" :min="1" :max="1_000_000_000" style="width: 120px" />
              </el-form-item>
              <el-form-item label="突发余量">
                <el-input-number v-model="form.rate_limit_burst" :min="0" :max="1_000_000_000" style="width: 120px" />
                <span class="form-tip-inline">次，短时允许超出速率上限的额外请求数</span>
              </el-form-item>
            </template>
          </el-form>
        </div>

        <!-- Step 4: 关联规则 -->
        <div v-show="currentStep === WIZARD_STEP.BINDINGS" class="step-content">
          <el-form :model="form" label-width="100px" :disabled="formFrozen">
            <el-form-item label="已关联">
              <div class="rule-bind-field">
                <div class="rule-picker-trigger" role="button" tabindex="0" :class="{ 'is-locked': isReadOnly }" @click="!isReadOnly && openRulePicker()" @keydown.enter.prevent="activateOnce($event, () => !isReadOnly && openRulePicker())" @keydown.space.prevent="activateOnce($event, () => !isReadOnly && openRulePicker())">
                  <span :class="{ 'rule-picker-placeholder': boundRules.length === 0 }">{{ boundRules.length > 0 ? `已选 ${boundRules.length} 条` : '选择要关联的负载均衡规则' }}</span>
                  <el-icon class="rule-picker-arrow"><ArrowDown /></el-icon>
                </div>
                <div v-if="boundRuleRows.length > 0" class="bound-rule-list">
                  <div v-for="row in boundRuleRows" :key="row.caddyId" class="bound-rule-row">
                    <div class="bound-rule-head">
                      <span class="bound-rule-name">{{ row.name }}</span>
                      <span class="bound-rule-meta">{{ row.domain || '-' }}:{{ row.listenPort }}</span>
                      <el-button v-if="!isReadOnly" size="small" link type="danger" class="bound-rule-remove" @click="removeBoundRule(row.caddyId)">移除</el-button>
                    </div>
                    <!-- v2.2.0 多策略绑定：完整绑定链（policy_id ASC，1-based 序号）+ 本策略落点；
                         拦截页面仅首个「启用且配置了拦截页」的策略生效。每条规则的拦截页面生效状态
                         统一展示在下方「拦截页面」配置项说明区。 -->
                    <div class="bound-rule-chain">
                      <span
                        v-for="(entry, idx) in row.chain"
                        :key="entry.policyId ?? 'self'"
                        class="binding-order-chip"
                        :class="{ 'is-self': entry.isSelf, 'is-disabled': !entry.enabled, 'is-trust': isStage0ChainEntry(entry) }"
                      >{{ chainChipText(entry, idx) }}</span>
                    </div>
                    <div v-if="row.showPerfTip" class="info-note-bar"><span class="info-note-desc">该规则将绑定 {{ row.mergedCount }} 条策略：每条策略都会叠加一层处理链（WAF/ACL/限流），超过 3 条可能影响转发性能</span></div>
                    <div v-for="hint in row.hints" :key="hint" class="info-note-bar"><span class="info-note-desc">{{ hint }}</span></div>
                    <div
                      v-for="hint in row.infoHints"
                      :key="hint"
                      class="info-note-bar"
                    ><span class="info-note-desc">{{ hint }}</span></div>
                    <!-- 行内编辑该规则的阶段拦截页覆盖（规则级 4 字段收口到策略侧）：历史
                         用户裁定 A 改为向导内延迟生效——改选只暂存，随向导「保存」收尾按
                         4 字段分组调 POST /rules/batch-block-pages（单事务一次渲染；单次
                         rule_ids ≤500 分片；skipped 规则保持待重试）。旧语义「变更即 PUT」
                         已废弃：会绕过向导保存、不进配置预览、文案误导。 -->
                    <div v-if="!isReadOnly && editableOverrideStages.length > 0" class="stage-override-editors">
                      <div v-for="stage in editableOverrideStages" :key="stage" class="stage-override-line">
                        <span class="stage-override-label">阶段 {{ stage }} 拦截页覆盖</span>
                        <el-select
                          size="small"
                          :model-value="overrideEditOf(row.caddyId)[stage === 1 ? 'stage1_id' : 'stage3_id']"
                          :disabled="stageOverrideSaving[row.caddyId]"
                          class="stage-override-page-select"
                          @update:model-value="onStageOverrideChange(row.caddyId, stage, 'id', Number($event))"
                        >
                          <el-option :value="0" label="跟随策略" />
                          <el-option v-for="p in blockPages" :key="p.id" :value="p.id" :label="p.name" />
                        </el-select>
                        <el-select
                          size="small"
                          :model-value="overrideEditOf(row.caddyId)[stage === 1 ? 'stage1_status' : 'stage3_status']"
                          :disabled="overrideEditOf(row.caddyId)[stage === 1 ? 'stage1_id' : 'stage3_id'] <= 0 || stageOverrideSaving[row.caddyId]"
                          class="stage-override-status-select"
                          @update:model-value="onStageOverrideChange(row.caddyId, stage, 'status', Number($event))"
                        >
                          <el-option :value="0" label="默认（403）" />
                          <!-- 与策略表单返回状态码同集单源（securityStages.STAGE_BLOCK_STATUS_OPTIONS） -->
                          <el-option v-for="opt in STAGE_BLOCK_STATUS_OPTIONS" :key="opt.value" :value="opt.value" :label="opt.label" />
                        </el-select>
                        <el-tag
                          v-if="overrideEditOf(row.caddyId)[stage === 1 ? 'stage1_id' : 'stage3_id'] > 0"
                          :type="stageOverrideSkipped[row.caddyId] ? 'danger' : pendingStageOverride(row.caddyId, stage) ? 'primary' : 'warning'"
                          size="small"
                          effect="plain"
                          disable-transitions
                          :title="stageOverrideSkipped[row.caddyId] ? `未写入（${stageOverrideSkipped[row.caddyId]}）` : undefined"
                        >{{ stageOverrideSkipped[row.caddyId] ? '未写入' : stageOverrideFailed[row.caddyId] ? '待重试' : pendingStageOverride(row.caddyId, stage) ? '待保存' : '已覆盖' }}</el-tag>
                        <el-icon v-if="stageOverrideSaving[row.caddyId]" class="is-loading stage-override-saving"><Loading /></el-icon>
                      </div>
                    </div>
                  </div>
                </div>
                <div class="form-tip-line">策略将应用到所选负载均衡规则的入站流量；同一规则绑定多条策略时按阶段 0→3 顺序、同阶段内按策略 ID 升序依次评估</div>
                <div v-if="editableOverrideStages.length > 0 && !isReadOnly" class="form-tip-line">「阶段 N 拦截页覆盖」是规则级字段（存于规则，非本策略）：改选后随本向导「保存」一并写入；未保存前不影响规则现状</div>
              </div>
            </el-form-item>
          </el-form>
        </div>

        <!-- Step: 拦截页（阶段 1/2/3 策略可配；阶段 2 状态码恒 429——步内隐藏状态码项） -->
        <div v-show="currentStep === WIZARD_STEP.BLOCK_PAGE" class="step-content">
          <div class="stage-projection-bar">
            <span class="stage-projection-desc">规则可配阶段 1/3 页覆盖；未覆盖时按触发策略显示（阶段 1 预检合并拦截、阶段 2 限流 429 由绑定链首位有页策略显示）</span>
            <div class="stage-projection-rules">
              <span v-if="boundRules.length === 0" class="stage-projection-empty">尚未关联规则</span>
              <span v-else class="stage-projection-empty">将应用于 {{ boundRules.length }} 条已关联规则</span>
            </div>
          </div>
          <el-form :model="form" label-width="100px" :disabled="formFrozen">
            <el-form-item label="拦截页面">
              <el-select v-model="form.block_page_id" placeholder="选择拦截页面" style="width: 100%">
                <el-option :value="0" :label="editorPolicyType === 'stage2' ? '不使用自定义页面（429 空响应体）' : '不使用自定义页面（Caddy 默认 403）'" />
                <el-option v-for="p in blockPages" :key="p.id" :label="p.name" :value="p.id" />
              </el-select>
              <div v-if="form.block_page_id === 0" class="form-tip-line">{{ editorPolicyType === 'stage2' ? '不配置拦截页：429 返回空响应体（可选内置「限流拦截页面」）' : '不配置拦截页；规则无阶段页覆盖且同规则无其他策略页时，拦截返回 Caddy 默认 403' }}</div>
              <div v-else class="form-tip-line">拦截时返回给客户端的自定义页面，在"拦截页面"页面管理，<AccessibleLink type="primary" @click="goToBlockPagesPage">去创建/编辑</AccessibleLink></div>
              <!-- 拦截页归因分层口径：规则可配阶段页覆盖；未覆盖时按触发策略显示。
                   逐阶段按后端渲染事实判定（阶段 1/2 取绑定链首个有页策略，
                   阶段 3 逐策略合成码；规则级覆盖压过策略页），不再恒渲染绿色「生效中」。 -->
              <div v-if="boundRuleRows.length > 0" class="block-page-rule-annotations">
                <div v-for="row in boundRuleRows" :key="row.caddyId" class="block-page-rule-annotation">
                  <span class="block-page-rule-annotation-name">{{ row.name }}</span>
                  <span v-for="note in row.blockPageNotes" :key="`${note.kind}:${note.text}`" class="block-page-rule-annotation-status" :class="`is-${note.kind}`">{{ note.text }}</span>
                </div>
              </div>
            </el-form-item>
            <el-form-item v-if="editorPolicyType !== 'stage2'" label="返回状态码">
              <el-select v-model="form.block_status_code" style="width: 200px" :disabled="form.block_page_id === 0">
                <el-option v-for="opt in STAGE_BLOCK_STATUS_OPTIONS" :key="opt.value" :value="opt.value" :label="opt.label" />
              </el-select>
              <span class="form-tip-inline">{{ form.block_page_id === 0 ? '未选择自定义页面时状态码不生效，拦截固定返回 Caddy 默认 403；请先选择页面' : 'WAF、IP ACL 拦截使用此状态码；限流拦截恒为 429（便于指标单独计量）' }}</span>
            </el-form-item>
            <el-form-item v-else label="返回状态码">
              <el-tag type="warning" size="small" effect="plain">429 Too Many Requests</el-tag>
              <span class="form-tip-inline">限流拦截恒为 429（便于指标单独计量），不可修改</span>
            </el-form-item>
          </el-form>
        </div>

        <!-- Step: 配置预览（三阶段投影·策略视角——与规则侧流程抽屉共用 buildStageModel 投影） -->
        <div v-show="currentStep === WIZARD_STEP.PREVIEW" class="step-content">
          <div class="preview-meta">
            <span class="preview-meta-name">{{ form.name || '-' }}</span>
            <el-tag :type="editorPolicyType === 'mixed' ? 'warning' : 'primary'" size="small" effect="plain">{{ POLICY_TYPE_LABELS[editorPolicyType] }}</el-tag>
            <el-tag :type="form.enabled ? 'success' : 'info'" size="small" effect="light">{{ form.enabled ? '启用' : '禁用' }}</el-tag>
            <span v-if="form.description" class="preview-meta-desc" :title="form.description">{{ form.description }}</span>
          </div>
          <div class="preview-pipeline">
            <section
              v-for="stage in previewVisibleStages"
              :key="stage.stage"
              class="preview-stage-card"
              :class="{ 'is-disabled': !stage.enabled }"
            >
              <DialogSectionHeader :title="stage.title" />
              <div class="dialog-panel">
                <div v-if="!stage.enabled" class="preview-stage-empty">未启用</div>
                <template v-if="stage.enabled">
                  <div v-for="group in stage.groups" :key="group.key" class="preview-policy-rows">
                    <div v-for="row in group.rows" :key="row.label" class="preview-row">
                      <span class="preview-row-label">{{ row.label }}</span>
                      <span class="preview-row-detail" :title="row.detail">{{ row.detail }}</span>
                    </div>
                  </div>
                </template>
                <div v-if="stage.enabled && stage.footnote" class="preview-stage-footnote">{{ stage.footnote }}</div>
              </div>
            </section>
          </div>
          <!-- 影响范围与阶段页覆盖：与上方阶段卡片同构（标题 + 键值行 + 脚注）。 -->
          <section class="preview-stage-card preview-bindings-card">
            <DialogSectionHeader title="适用规则" :description="boundRules.length > 0 ? `${boundRules.length} 条已关联` : '未关联'" />
            <div class="dialog-panel">
              <div class="preview-policy-rows">
                <div class="preview-row">
                  <span class="preview-row-label">生效范围</span>
                  <span class="preview-row-detail">{{ boundRules.length > 0 ? `本策略将应用于 ${boundRules.length} 条已关联规则` : '保存后可在「关联规则」步骤绑定，或在规则行点「安全」绑定' }}</span>
                </div>
                <div class="preview-row">
                  <span class="preview-row-label">阶段页覆盖</span>
                  <span class="preview-row-detail">逐规则状态与编辑在「关联规则」步骤</span>
                </div>
                <div v-if="pendingOverrideRules.length > 0" class="preview-row">
                  <span class="preview-row-label">本次保存</span>
                  <span class="preview-row-detail">写入 {{ pendingOverrideRules.length }} 条规则的阶段拦截页覆盖</span>
                </div>
              </div>
              <div v-if="pendingOverrideRules.length > 0" class="preview-stage-footnote">覆盖属规则级字段，随本向导保存生效</div>
            </div>
          </section>
        </div>
      </div>

      <template #footer>
        <div class="wizard-footer">
          <el-button v-if="hasPreviousStep" :disabled="saving" @click="prevStep">
            <el-icon><ArrowLeft /></el-icon>上一步
          </el-button>
          <el-button v-if="hasNextStep" type="primary" :disabled="saving" @click="nextStep">
            下一步<el-icon><ArrowRight /></el-icon>
          </el-button>
          <el-button v-if="currentStep === WIZARD_STEP.PREVIEW" type="primary" :disabled="isReadOnly" :loading="saving" @click="handleSave">
            <span>保存策略</span><el-icon style="margin-left: 6px;"><Check /></el-icon>
          </el-button>
        </div>
      </template>
    </el-dialog>

    <!-- 关联规则选择器 -->
    <el-dialog v-model="rulePickerVisible" class="dialog-body-inset" width="min(640px, 90vw)" append-to-body>
      <template #header>
        <DialogHeader :icon="Connection" title="选择关联规则" />
      </template>
      <el-input v-model="pickerSearch" placeholder="搜索规则名 / 域名 / 规则 ID" clearable :prefix-icon="Search" class="rule-picker-search" />
      <DialogSectionHeader title="可选规则" />
      <div class="dialog-panel">
        <div class="rule-picker-header">
          <el-checkbox
            :model-value="pickerSelectAllChecked"
            :indeterminate="pickerSelectAllIndeterminate"
            :disabled="pickerSelectableRules.length === 0"
            @change="handlePickerSelectAll"
          >全选</el-checkbox>
          <span class="rule-picker-header-meta">筛选 {{ pickerFilteredRules.length }} 条</span>
        </div>
        <div class="rule-picker-list">
          <el-checkbox-group v-model="pickerSelected">
            <div v-for="rule in pickerPagedRules" :key="rule.caddy_id" class="rule-picker-item">
              <el-checkbox :value="rule.caddy_id" :disabled="pickerMeta(rule.caddy_id).blockReason !== ''">
                <span class="rule-picker-name">{{ rule.name }}</span>
                <span class="rule-picker-meta">{{ rule.domain || '-' }}:{{ rule.listen_port }}</span>
              </el-checkbox>
              <!-- 每条候选规则展示当前绑定链（policy_id ASC，1-based）与本策略落点；
                   后端必然拒绝的形态（绑定条数上限 / 阶段 2 限流唯一门）在选择阶段
                   禁用并逐条说明原因——冲突在整批提交时会让本片全部失败。 -->
              <div class="rule-binding-preview">
                <span v-if="pickerMeta(rule.caddy_id).blockReason" class="rule-binding-limit">{{ pickerMeta(rule.caddy_id).blockReason }}</span>
                <template v-else>
                  <span
                    v-for="(entry, idx) in pickerMeta(rule.caddy_id).chain"
                    :key="entry.policyId ?? 'self'"
                    class="binding-order-chip"
                    :class="{ 'is-self': entry.isSelf, 'is-disabled': !entry.enabled, 'is-trust': isStage0ChainEntry(entry) }"
                  >{{ chainChipText(entry, idx) }}</span>
                  <!-- 阶段 0 排位语义：信任 IP 在任何策略判定前直达上游/进入检测，与绑定顺序无关 -->
                  <span v-if="editorPolicyType === 'stage0'" class="rule-binding-landing rule-binding-landing--trust">阶段 0·拦截判定前优先生效</span>
                  <span v-else class="rule-binding-landing">本策略排第 {{ pickerMeta(rule.caddy_id).selfPos }} 位</span>
                </template>
              </div>
            </div>
          </el-checkbox-group>
          <el-empty v-if="pickerPagedRules.length === 0" description="没有匹配的规则" :image-size="60" />
        </div>
      </div>
      <el-pagination
        v-model:current-page="pickerPage"
        :page-size="PICKER_PAGE_SIZE"
        :total="pickerFilteredRules.length"
        layout="total, prev, pager, next"
        small
        class="rule-picker-pagination"
      />
      <template #footer>
        <div class="picker-footer">
          <span class="picker-count">已选 {{ pickerSelected.length }} 条</span>
          <div class="picker-footer-buttons">
            <el-button :disabled="pickerSelected.length === 0" @click="pickerSelected = []">清空</el-button>
            <el-button @click="rulePickerVisible = false">取消</el-button>
            <el-button type="primary" @click="confirmRulePicker">确定</el-button>
          </div>
        </div>
      </template>
    </el-dialog>

    <el-dialog v-model="extractDialogVisible" class="dialog-body-inset" width="min(480px, 92vw)" append-to-body :close-on-click-modal="false" :close-on-press-escape="!extracting" :show-close="!extracting">
      <template #header>
        <DialogHeader :icon="Document" title="提取为地址列表" subtitle="将内联 IP 转为可复用名单并关联到当前策略" />
      </template>
      <div class="info-note-bar"><span class="info-note-desc">将创建列表并清空内联条目，引用后语义不变</span></div>
      <el-form label-width="80px" @submit.prevent>
        <el-form-item label="来源">
          <span class="extract-source">{{ extractSide === 'acl' ? aclListLabel : '信任 IP' }}（内联 {{ extractSourceEntries.length }} 条）</span>
        </el-form-item>
        <el-form-item label="列表名称" required>
          <el-input v-model="extractForm.name" placeholder="列表名称" maxlength="50" show-word-limit />
        </el-form-item>
        <el-form-item label="分类">
          <el-select v-model="extractForm.category" allow-create filterable default-first-option placeholder="选择或输入分类" style="width: 100%">
            <el-option v-for="c in IP_LIST_CATEGORIES" :key="c" :label="c" :value="c" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="extractDialogVisible = false" :disabled="extracting">取消</el-button>
        <el-button type="primary" :loading="extracting" @click="confirmExtract">创建并引用</el-button>
      </template>
    </el-dialog>

    <!-- 行级「绑定规则」：不经编辑器直接重置该策略绑定集（与规则页「安全」弹框共享同一组件） -->
    <SecurityBindingEditor
      v-model="bindRulesVisible"
      mode="policy"
      :policy-id="bindRulesPolicy?.id ?? null"
      :policy-name="bindRulesPolicy?.name"
      :policies="policies"
      :bindings="securityBindings"
      :rules="allRules"
      :block-pages="blockPages"
      @saved="onBindRulesSaved"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed, watch } from 'vue'
import { Plus, Lock, InfoFilled, Connection, Odometer, Link, Check, ArrowLeft, ArrowRight, ArrowDown, Search, WarningFilled, Document, Loading } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import type { CascaderOption, CascaderProps, CascaderValue, LazyLoad } from 'element-plus'
import { request, ApiRequestError, mfaAwareSuccess } from '@/utils/api'
import { showSaveResult } from '@/utils/saveResult'
import { CADDY_APPLY_FAILED_MARKER, mergeBulkResults, policySaveResultMessage, stageOverrideDraftPending } from '@/utils/bulkApplyResult'
import { isValidCidr } from '@/utils/ipAddress'
import { popperViewportSafe } from '@/utils/popper'
import { formatDate } from '@/utils/date'
import { useAuthStore } from '@/stores/auth'
import { useCrsRuleIndex, issueCrsIndexSession, crsRuleLabelView, parseCrsExcludedRules, CRS_EXCLUDED_MAX_ROWS } from '@/composables/useCrsRuleIndex'
import { useClampedPagination } from '@/composables/useClampedPagination'
import type { CrsExcludedRow, CrsRuleOptionView } from '@/composables/useCrsRuleIndex'
import type { APIResponse, UserListItem } from '@/types'
import SecurityBindingEditor from '@/components/SecurityBindingEditor.vue'
import DialogHeader from '@/components/DialogHeader.vue'
import DialogSectionHeader from '@/components/DialogSectionHeader.vue'
import AccessibleLink from '@/components/common/AccessibleLink.vue'
import { POLICY_TYPE_LABELS, POLICY_TYPE_SHORT_LABELS, STAGE_BLOCK_STATUS_OPTIONS, addressAllowDenyConflictText, blockPageMissing, blockPageStageCanIntercept, buildStageModel, chunkForBulk, customRuleCanBlockInMode, entriesIntersect, ensureSharedEntries, formatAclModeDetail, hasGeoIPControl, hasIPACLControl, hasOtherStage2Binding, hasStage3Features, hasTrustEntries, inferPolicyType, mergeIpEntryCount, mergeIpEntryValues, parseCrsFilename, parseIPList, parseRefIds, parseUnknownIds, parseUnknownStrings, pickDefaultPolicyTab, sharedEntriesCache, subscribeSharedEntriesCache, trustHitMode, wafModeLabel, IP_LIST_CATEGORIES, MAX_POLICIES_PER_RULE, SECURITY_BULK_LIMITS, resolveBlockPageAttribution, type BlockPageAttribution, type BlockPageStage } from '@/utils/securityStages'
import type { RuleStageModel, SecurityPolicyType, SecurityStagePolicy, SecurityStageCustomRule, CrsRuleFileOption } from '@/utils/securityStages'
import { fetchAllCrsRuleFiles } from '@/utils/crsRuleFiles'
import { updaterName } from '@/utils/updaterName'
import { hasOwn } from '@/utils/hasOwn'
import { SECURITY_DESCRIPTION_MAX_RUNES, SECURITY_NAME_MAX_RUNES } from '@/utils/securityLimits'
import { CRS_HIDDEN_GROUP_CODES, CRS_INFRA_GROUP_CODES, isInfraRuleId, isInitRuleId, normalizeCrsGroups } from '@/utils/crsGroups'
import { DEEP_LINK_PARAMS, pageUrl } from '@/utils/deepLink'
import { buildPolicyPayload, crawlerExemptionNeedsEngines, trustEnabledForPolicyType } from '@/utils/policyPayload'
import { activateOnce } from '@/utils/keyboardActivate'

interface PolicyDetail { id: number; name: string; description: string; mode: string; anomaly_threshold: number; ip_acl_mode: string; ip_acl_list: string; ip_acl_enabled: boolean; ip_whitelist: string; ip_whitelist_enabled?: boolean; ip_blacklist?: string; ip_acl_list_refs?: string; ip_whitelist_refs?: string; rate_limit_enabled: boolean; rate_limit_rps: number; rate_limit_burst: number; crs_rule_groups: string; crs_excluded_rules: string; custom_rules: string; block_page_id: number; block_status_code: number; enabled: boolean; updated_at: string; geoip_mode?: string; geoip_countries?: string; geoip_crawler_exempt?: boolean; geoip_crawler_engines?: string; waf_check_response?: boolean; log_request_body?: boolean; trust_detection?: boolean }
// 规则行携带阶段拦截页覆盖 4 字段（关联规则行内编辑与生效投影同源）
interface Rule { caddy_id: string; name: string; domain: string; listen_port: number; protocol: string; block_page_stage1_id?: number; block_page_stage1_status?: number; block_page_stage3_id?: number; block_page_stage3_status?: number }
// v2.2.0 多策略绑定：/security/bindings 的值从单 BindingInfo 改为数组（policy_id ASC）
interface BindingInfo { policy_id: number; name: string; mode: string; enabled: boolean; rate_limit_enabled: boolean; block_page_id?: number; block_status_code?: number }
// GET /security/rules/:caddy_id/policy 直接序列化 models.SecurityPolicy——json.RawMessage
// 字段以原生 JSON（数组）出现，与策略详情接口的字符串形态不同，按 unknown 接收再解析。
interface RuleBoundPolicy { id: number; name: string; mode: string; enabled: boolean; ip_acl_enabled: boolean; ip_acl_mode: string; crs_rule_groups: unknown; custom_rules: unknown; block_page_id: number }
interface CustomRuleRef { id: number; action: string }
interface ChainEntry { policyId: number | null; name: string; enabled: boolean; isSelf: boolean; blockPageId?: number; blockStatusCode?: number }
interface BlockPageNote { kind: 'active' | 'disabled' | 'warning' | 'info'; text: string }
interface BoundRuleRow { caddyId: string; name: string; domain: string; listenPort: number; chain: ChainEntry[]; blockPageNotes: BlockPageNote[]; mergedCount: number; showPerfTip: boolean; hints: string[]; infoHints: string[] }
interface BlockPage { id: number; name: string; content?: string }

const blockPages = ref<BlockPage[]>([])

interface PolicySummary { id: number; name: string; mode: string; enabled: boolean; rule_count: number; has_waf: boolean; has_ip_control: boolean; has_rate_limit: boolean; has_custom_rules: boolean; anomaly_threshold: number; ip_acl_mode: string; ip_acl_list: string; ip_whitelist: string; ip_whitelist_enabled?: boolean; ip_blacklist: string; ip_acl_list_refs?: string; ip_whitelist_refs?: string; rate_limit_rps: number; rate_limit_burst: number; crs_excluded_count: number; custom_rules_count: number; custom_rules_ref_count?: number; ip_acl_enabled: boolean; updated_by: number; updated_at: string; crs_rule_groups?: string | string[]; has_geoip?: boolean; geoip_countries?: string; geoip_mode?: string; policy_type?: string; trust_detection?: boolean; trigger_24h?: number }




interface RegionTree {
  provinces: string[]
  cities: Record<string, string[]>
  countries?: string[]
  // 海外国家英文→中文映射（regions API 并行字段，单源 geoipnames.CountryNamesCN）；
  // 缺失（旧后端/请求失败）时子节点回退英文标签。
  country_names_cn?: Record<string, string>
}
const regionTree = ref<RegionTree>({ provinces: [], cities: {} })
// 级联选项：各省为父节点（选父 = 整省），省内城市为子节点（省/市 联合匹配）；
// 独立「海外」一级叶子不再展示（v2.3.7 修正）——「海外国家」为分组父节点且
// 可勾选（checkStrictly）：勾选父节点提交「海外」= 全部海外语义（解析失败/
// IPv6 兜底哨兵 ∪ 全部已解析国名，与发射端 geoipLocOperator 的海外条目展开
// 语义一致）；子节点按国家粒度选择，提交英文国名（匹配键形态不变，标签用
// 中文）。选择值仍为扁平字符串数组，下游（geoip_countries 提交/回显）零改动。
const regionCascaderOptions = computed(() => {
  type RegionNode = { value: string; label: string; children?: Array<{ value: string; label: string }> }
  const options: Array<RegionNode> = []
  for (const prov of regionTree.value.provinces) {
    // 「海外」哨兵不再作独立一级叶子——提交值由「海外国家」父节点承载
    if (prov === '海外') continue
    const cities = regionTree.value.cities[prov] || []
    if (cities.length === 0) {
      options.push({ value: prov, label: prov })
      continue
    }
    options.push({
      value: prov,
      label: prov,
      children: cities.map((city) => ({ value: `${prov}/${city}`, label: city })),
    })
  }
  const overseas = regionTree.value.countries || []
  if (regionTree.value.provinces.length > 0 || overseas.length > 0) {
    const zhNames = regionTree.value.country_names_cn || {}
    options.push({
      value: '海外',
      label: '海外国家',
      children:
        overseas.length > 0
          ? // X5：按展示标签（中文简称，未命中回退英文）排序——
            // 后端 Countries 为英文字典序，中文标签直显时乱序；提交值不变。
            overseas
              .map((country) => ({ value: country, label: zhNames[country] || country }))
              .sort((a, b) => a.label.localeCompare(b.label, 'zh-Hans-CN'))
          : undefined,
    })
  }
  return options
})

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.readOnlyReason !== null)

const users = ref<UserListItem[]>([])
// 更新者显示名走 utils/updaterName 单源
const getUpdaterName = (userId?: number) => updaterName(users.value, userId)

const crsRuleOptions = ref<CrsRuleFileOption[]>([])
// CRS 规则索引（约 832 条，id/msg/file/category）：规则组/排除目标级联的规则叶与
// 预览 hover 明细共用；对话框打开时取一次（同会话缓存，openSeq 过期守卫见 useCrsRuleIndex）
const { loaded: crsIndexLoaded, byId: crsIndexById, options: crsIndexOptions, ensureForDialog: ensureCrsRuleIndex } = useCrsRuleIndex()
// —— 排除规则行编辑器（存储形态：对象数组 [{target,scope,ips,listRefs}]，旧字符串数组
//     读取时由 parseCrsExcludedRules 归一为 scope:all 行）——
const crsExcludedRows = ref<CrsExcludedRow[]>([])

const loading = ref(false)
const saving = ref(false)
// 保存中冻结表单与步骤导航：payload 跨多个 await 组装，在途时的编辑会让
// 「是否生效」取决于编辑落在哪个 await 之后，成功提示也不披露被丢弃的字段。
const formFrozen = computed(() => isReadOnly.value || saving.value)
const policies = ref<PolicySummary[]>([])
// 主列表拉取失败必须可辨识（否则「加载失败」与「确实没有策略」同形，
// 用户会误以为策略被清空）。失败保留旧数据，仅置错误态供横幅+重试。
const policiesLoadError = ref(false)
// 辅助端点部分失败（规则/CRS/拦截页/自定义规则/绑定/用户/地址列表）：
// 计数与冲突告警会静默降级——必须可见点名，不能只 console.warn。
const auxLoadFailures = ref<string[]>([])
// 拦截页列表是否至少成功落地过一次——未落地时不得做「页面已删除/
// 内容为空」的空页预告（bpRes 部分失败会让所有启用策略显示假警告）。
const blockPagesLoaded = ref(false)
const policySearch = ref('')

// ── 列表按类型分组（阶段 1/2/3 + 混合兼容组）：policy_type 缺省时按内容推断（inferPolicyType
// 与后端兜底同形状） ──
const activeTypeTab = ref<SecurityPolicyType>('stage1')
const policyTypeOf = (row: PolicySummary): SecurityPolicyType => inferPolicyType(row)
// 策略 id → 阶段类型（绑定选择器/提交门的 stage2 唯一性判据用）：与列表分组同一
// 推断口径（inferPolicyType 优先 policy_type 列，缺省按内容推断）。
const policyTypeById = computed<ReadonlyMap<number, SecurityPolicyType>>(() => {
  const map = new Map<number, SecurityPolicyType>()
  for (const p of policies.value) map.set(p.id, policyTypeOf(p))
  return map
})
// 各类型条数（tab 标签 + 默认/回落 tab 选择共用一个计数源）
const policyTypeCounts = computed<Record<SecurityPolicyType, number>>(() => {
  const counts: Record<SecurityPolicyType, number> = { stage0: 0, stage1: 0, stage2: 0, stage3: 0, mixed: 0 }
  for (const p of policies.value) counts[policyTypeOf(p)]++
  return counts
})
// 「混合策略（兼容旧版）」tab 条件可见：仅当存在 mixed 策略（导入或存量）时显示；
// 混合组清空（如更新迁移完成）后当前 tab 回落到第一个非空类型
const policyTypeTabs = computed(() => {
  const counts = policyTypeCounts.value
  // 阶段编号体系：阶段 0 · 信任名单 → 阶段 1 → 阶段 2 → 阶段 3（混合兼容组条件可见）
  const tabs = (['stage0', 'stage1', 'stage2', 'stage3'] as const).map((type) => ({
    type: type as SecurityPolicyType,
    label: POLICY_TYPE_LABELS[type],
    count: counts[type],
  }))
  if (counts.mixed > 0) tabs.push({ type: 'mixed', label: POLICY_TYPE_LABELS.mixed, count: counts.mixed })
  return tabs
})

// tab 消失（混合组迁移/删除清空）时回落到第一个非空类型——硬编码阶段 1 会让
// 「子策略都在别的 tab」的站点停在空表。
watch(policyTypeTabs, (tabs) => {
  if (!tabs.some((tab) => tab.type === activeTypeTab.value)) {
    activeTypeTab.value = pickDefaultPolicyTab(policyTypeCounts.value)
  }
})

// 行内阶段页编辑收敛到当前策略类型对应阶段（任务 D）：stage1→阶段 1、stage3→阶段 3；
// stage2 无覆盖页编辑；mixed 走只读查看弹框不进编辑器（恒空兜底）
const editableOverrideStages = computed<readonly (1 | 3)[]>(() => {
  if (editorPolicyType.value === 'stage1') return [1]
  if (editorPolicyType.value === 'stage3') return [3]
  return []
})

const filteredPolicies = computed(() => {
  const typed = policies.value.filter((p) => policyTypeOf(p) === activeTypeTab.value)
  const query = policySearch.value.trim().toLowerCase()
  if (!query) return typed
  return typed.filter((p) => (p.name || '').toLowerCase().includes(query))
})

// 客户端分页（与其他表格页同款）：tab/搜索变更回首页；删除后夹紧页码
const policyPage = ref(1)
const policyPageSize = ref(10)
watch([activeTypeTab, policySearch], () => { policyPage.value = 1 })
// 分页夹紧+切片：useClampedPagination 单一范式（取代 computed
// 内副作用赋值反模式）
const { pagedItems: pagedPolicies } = useClampedPagination(filteredPolicies, policyPage, policyPageSize)

// 三阶段启用 chips 谓词：阶段 1=IP 访问控制||地域拦截、阶段 2=限流、
// 阶段 3=与后端 models.PolicyTypeFeatures 的 G3 逐字对齐（mode 三态 ∪ custom_rules
// 引用非空，见 utils/securityStages.hasStage3Features）。判定必须用引用数
// （custom_rules_ref_count，含禁用条目）；custom_rules_count 只数启用规则，
// 「mode=off 且引用规则全部禁用」的边界会少标一条子策略。
const stage3ChipOn = (row: PolicySummary): boolean => {
  return hasStage3Features(row.mode, row.custom_rules_ref_count ?? row.custom_rules_count)
}


// ── 阶段页覆盖：投影条与预览步自历史起只出摘要（「将应用于 N 条已关联规则」），
// 逐规则的覆盖状态与编辑入口在「关联规则」步骤（stageOverrideSeed/overrideEditOf 等） ──

// 内容摘要列（按类型一行摘要）：stage0=信任条数+模式、stage1=模式+ACL+GeoIP、
// stage2=限流值、stage3=WAF 模式+自定义+CRS 组、mixed=混合（任务 2）

// 阶段 0 排位语义（浏览器实证修正）：阶段 0 不在评估链内，绑定链上的 stage0 条目
// 不显示序数——本策略/其他 stage0 策略统一标注「阶段 0·拦截判定前优先生效」；
// stage1/2/3/mixed 保持「N.名称」序数（评估序 policy_id ASC）
const isStage0ChainEntry = (entry: ChainEntry): boolean => {
  if (entry.isSelf) return editorPolicyType.value === 'stage0'
  const policy = policies.value.find((p) => p.id === entry.policyId)
  return policy ? policyTypeOf(policy) === 'stage0' : false
}
// WAF 模式展示词单源已上移 utils/securityStages（wafModeLabel/WAF_MODE_TEXT）——列表摘要、
// 只读详情分段、触发详情策略行、流程投影四处同词（此前文件内两份 + 跨文件一份
// 措辞互斥：拦截/阻断、仅自定义/仅自定义规则）。
const chainChipText = (entry: ChainEntry, index: number): string => {
  const name = entry.isSelf ? '本策略' : entry.name
  if (isStage0ChainEntry(entry)) return `${name} · 阶段 0·拦截判定前优先生效`
  return `${index + 1}.${name}`
}
const policySummaryLine = (row: PolicySummary): string => {
  const type = policyTypeOf(row)
  if (type === 'stage0') {
    const count = mergeIpEntryCount(ipLists.value, parseIPList(row.ip_whitelist), parseRefIds(row.ip_whitelist_refs))
    return `信任 ${count} 条 · ${trustHitMode(row.policy_type, row.trust_detection) === 'detection' ? '保留检测记录' : '直通上游'}`
  }
  if (type === 'stage2') {
    return row.has_rate_limit ? `${row.rate_limit_rps} 次/秒 · 突发 ${row.rate_limit_burst}` : '未启用'
  }
  if (type === 'stage3') {
    // 组数口径与编辑器写回同源（normalizeCrsGroups）：历史文件名前缀、重复值、
    // 系统基础组（01/49/59）都不该让「N 组」虚增——否则同一策略在编辑器里是
    // 2 组、在列表摘要里是 4 组，用户无从判断哪份是生效配置。
    const crsCount = normalizeCrsGroups(parseUnknownStrings(row.crs_rule_groups)).length
    // WAF 全关=CRS 与自定义规则均不生效（共享 buildStage3Rows 同门）——不得把
    // 保留的自定义条数说成生效中。
    if (row.mode === 'off') return 'WAF 关闭'
    const parts = [`WAF ${wafModeLabel(row.mode)}`, `自定义 ${row.custom_rules_count} 条`]
    if (row.mode === 'blocking' || row.mode === 'detection') parts.push(crsCount > 0 ? `CRS 组 ${crsCount}` : 'CRS 全部')
    return parts.join(' · ')
  }
  if (type === 'stage1') {
    const geoCount = geoipRegionCount(row)
    // 与锁摘要/详情弹框共用共享投影器口径
    // ① ACL 关闭但遗留独立黑名单仍在拦截时不得显示「未启用 ACL」；
    // ② 地域关闭但保留区域时如实标注「已关闭（保留 N 区域）」。
    // 内容门 hasIPACLControl 只决定「是否有渲染产物」，
    // 列表摘要展示必须与后端 SecurityPolicyHasIPControl（ip_acl_enabled 开启即
    // true）对齐——显式开启 ACL 但名单为空时显示模式与 0 条，而不是「未启用」。
    const aclPart = row.ip_acl_enabled === true || hasIPACLControl(row) ? formatAclModeDetail(ipLists.value, row) : '未启用 ACL'
    const geoPart = hasGeoIPControl(row)
      ? `GeoIP ${geoCount} 区域`
      : geoCount > 0 ? `GeoIP 已关闭（保留 ${geoCount} 区域）` : 'GeoIP 未启用'
    return `${aclPart} · ${geoPart}`
  }
  return '混合 · 阶段 1/2/3 组合'
}

// ── 关联规则行内阶段页编辑（规则级 4 字段收口到策略侧；历史起向导内延迟生效：
// 改选暂存 → 向导保存收尾 POST /rules/batch-block-pages（单事务一次渲染、按
// 4 字段分组、单次 rule_ids ≤500 分片；被跳过的规则记原因并保持待重试） ──
interface StageOverrideEdit { stage1_id: number; stage1_status: number; stage3_id: number; stage3_status: number }
const stageOverrideEdits = ref<Record<string, StageOverrideEdit>>({})
const stageOverrideSaving = ref<Record<string, boolean>>({})
// 上次保存失败待重试：失败不得回写 seed（待提交项消失=与「重新
// 点击保存可重试」承诺矛盾），改记失败标记并在行内显示「待重试」。
const stageOverrideFailed = ref<Record<string, boolean>>({})
// 批量端点会跳过 TCP/不存在的规则（200 + skipped 列表）——被跳过的规则
// 不得回写「已覆盖」，需逐条记住原因并保持待提交（下次保存重试）。
const stageOverrideSkipped = ref<Record<string, string>>({})

const stageOverrideSeed = (caddyId: string): StageOverrideEdit => {
  const rule = allRules.value.find((r) => r.caddy_id === caddyId)
  return {
    stage1_id: rule?.block_page_stage1_id ?? 0,
    stage1_status: rule?.block_page_stage1_status ?? 0,
    stage3_id: rule?.block_page_stage3_id ?? 0,
    stage3_status: rule?.block_page_stage3_status ?? 0,
  }
}

// 该规则该阶段的覆盖是否为本次会话暂存（未保存）——供「待保存/已覆盖」标签与
// 覆盖编辑器状态区分（seed=库值，edit=暂存值）。
const pendingStageOverride = (caddyId: string, stage: 1 | 3): boolean => {
  const edit = overrideEditOf(caddyId)
  const seed = stageOverrideSeed(caddyId)
  return stage === 1
    ? edit.stage1_id !== seed.stage1_id || edit.stage1_status !== seed.stage1_status
    : edit.stage3_id !== seed.stage3_id || edit.stage3_status !== seed.stage3_status
}

const overrideEditOf = (caddyId: string): StageOverrideEdit =>
  stageOverrideEdits.value[caddyId] ?? stageOverrideSeed(caddyId)
const onStageOverrideChange = (caddyId: string, stage: 1 | 3, field: 'id' | 'status', value: number): void => {
  const edit = { ...overrideEditOf(caddyId) }
  if (field === 'id') {
    if (stage === 1) edit.stage1_id = value
    else edit.stage3_id = value
    // 跟随策略（页=0）时状态码归 0（后端归一语义）
    if (value <= 0) {
      if (stage === 1) edit.stage1_status = 0
      else edit.stage3_status = 0
    }
  } else if (stage === 1) edit.stage1_status = value
  else edit.stage3_status = value
  stageOverrideEdits.value = { ...stageOverrideEdits.value, [caddyId]: edit }
  // 用户重新选择即清除「未写入」标记（原因来自上一次写入，已不适用）
  if (stageOverrideSkipped.value[caddyId]) {
    const nextSkipped = { ...stageOverrideSkipped.value }
    delete nextSkipped[caddyId]
    stageOverrideSkipped.value = nextSkipped
  }
  // 改回原值后两阶段均无待提交项 → 清除「待重试」：失败标记只对
  // 待提交项有意义，滞留会误导「仍有未重试的写入」。
  if (stageOverrideFailed.value[caddyId]
    && !pendingStageOverride(caddyId, 1) && !pendingStageOverride(caddyId, 3)) {
    const nextFailed = { ...stageOverrideFailed.value }
    delete nextFailed[caddyId]
    stageOverrideFailed.value = nextFailed
  }
  // 历史（用户裁定 A）：只暂存，不再即时 PUT——规则级覆盖随向导「保存」
  // 统一提交（handleSave 收尾走批量端点 batch-block-pages），与向导其余步骤的延迟语义一致。
}

// ── 混合策略一键更新迁移（用户裁定）：预演（子策略/重映射/上限风险）→ POST split → 汇总 ──
interface MigratePolicyResult {
  created: Array<{ id: number; name: string; policy_type: string }>
  remapped: number
  skipped: Array<{ rule_id: string; reason: string }>
  deleted_original: boolean
}
const migrateVisible = ref(false)
const migrateSaving = ref(false)
// 迁移弹框会话序号：关闭/换目标即失效——在途 split 响应不得关掉新打开的弹框
// （split 本身不可逆，取消只关闭预演，不撤回已发出的请求）。
let migrateSessionSeq = 0
const migratePolicy = ref<PolicySummary | null>(null)

// 预演子策略类型 = 特征组探测（与 inferPolicyType 同形状的阶段能力谓词；后端按同口径实际生成）
const migrateChildTypes = computed<SecurityPolicyType[]>(() => {
  const p = migratePolicy.value
  if (!p) return []
  const types: SecurityPolicyType[] = []
  // 含信任名单 → 产出「原名（阶段 0）」子策略（后端 trust_detection 恒 1=保留检测，行为保持）
  if (hasTrustEntries(p)) types.push('stage0')
  // 改用 securityStages 单一事实源（ACL 启用 ∧ 内联∪引用
  // 非空，或遗留黑名单非空——与后端 PolicyTypeFeatures 同口径）——旧本地谓词
  // 要求内联条目非空且 migrate 路径不拉条目值，仅靠引用列表的混合策略预演
  // 会漏报阶段 1。
  if (hasIPACLControl(p) || hasGeoIPControl(p)) types.push('stage1')
  if (p.has_rate_limit) types.push('stage2')
  if (stage3ChipOn(p)) types.push('stage3')
  return types
})

const migrateBoundRules = computed(() => (migratePolicy.value ? policyBoundRules(migratePolicy.value.id) : []))

// 上限风险：规则当前绑定数 - 1（原策略被替换）+ 子策略数 > MAX_POLICIES_PER_RULE → 该规则保持原绑定进 skipped
const migrateCapRisk = computed(() =>
  migrateBoundRules.value.filter((rule) =>
    (securityBindings.value[rule.caddy_id] || []).length - 1 + migrateChildTypes.value.length > MAX_POLICIES_PER_RULE))

// 限流唯一门风险：拆分产出 stage2 子策略时，规则现存的其他绑定若已含 stage2
// → 后端逐条 skipped（每条规则最多一条限流策略；与 SplitSecurityPolicy 的
// otherStage2 门同口径）。摘要缺该策略类型时回退 binding 的 rate_limit_enabled。
const migrateStage2SkipRisk = computed(() => {
  const policyId = migratePolicy.value?.id
  if (policyId === undefined || !migrateChildTypes.value.includes('stage2')) return []
  const boundIsOtherStage2 = (b: BindingInfo): boolean => {
    const type = policies.value.find((p) => p.id === b.policy_id)?.policy_type
    return type ? type === 'stage2' : b.rate_limit_enabled
  }
  return migrateBoundRules.value.filter((rule) =>
    (securityBindings.value[rule.caddy_id] || []).some((b) => b.policy_id !== policyId && boundIsOtherStage2(b)))
})

const openMigrateDialog = (row: PolicySummary): void => {
  if (isReadOnly.value) return
  migrateSessionSeq++
  migratePolicy.value = row
  migrateVisible.value = true
}

const cancelMigrate = (): void => {
  if (migrateSaving.value) return
  migrateSessionSeq++
  migrateVisible.value = false
}

const submitMigrate = async (): Promise<void> => {
  if (isReadOnly.value || migrateSaving.value) return
  const policy = migratePolicy.value
  if (!policy) return
  const sessionSeq = migrateSessionSeq
  migrateSaving.value = true
  try {
    const res = await request.post<APIResponse<MigratePolicyResult>>(`/security/policies/${policy.id}/split`)
    if (sessionSeq !== migrateSessionSeq) return
    const data = res.data
    const parts: string[] = []
    if (data && data.created.length > 0) parts.push(`已创建 ${data.created.length} 条子策略（${data.created.map((c) => c.name).join('、')}）`)
    if (data && data.remapped > 0) parts.push(`重映射 ${data.remapped} 条规则绑定`)
    if (data && !data.deleted_original) parts.push('原策略因仍在使用未删除')
    mfaAwareSuccess(parts.length > 0 ? parts.join('；') : '更新迁移完成')
    // 退化 200+后缀（Caddy 应用失败但 DB 已提交）须持续警告可见——
    // 有后缀才弹，无后缀不重复 toast（同下方保存主链路 FE1 口径）
    if (res.message?.includes(CADDY_APPLY_FAILED_MARKER)) showSaveResult(res, '')
    if (data && data.skipped.length > 0) {
      ElMessage.warning(`${data.skipped.length} 条规则跳过：${data.skipped.map((s) => s.reason).join('；')}`)
    }
    migrateVisible.value = false
    await fetchData()
    // 迁移后切到第一个子策略的类型 tab：混合组消失后回落谓词会选「第一个非空」，
    // 但子策略类型顺序与创建结果一致，直接跟随可避免落到不相关的非空 tab。
    const createdType = data?.created.find((c) => c.policy_type === 'stage0' || c.policy_type === 'stage1' || c.policy_type === 'stage2' || c.policy_type === 'stage3')?.policy_type
    if (createdType) activeTypeTab.value = createdType as SecurityPolicyType
  } catch (error: unknown) {
    // 错误提示已由全局拦截器展示
    console.error('migrate policy failed', error)
  } finally {
    migrateSaving.value = false
  }
}

// ── 混合策略只读查看（决策：mixed 不再可编辑，唯一操作 = 更新迁移） ──
const viewPolicyVisible = ref(false)
const viewPolicyLoading = ref(false)
const viewPolicyRow = ref<PolicySummary | null>(null)
const viewPolicyDetail = ref<PolicyDetail | null>(null)
const viewPolicyBindings = ref<string[]>([])

const openViewDialog = async (row: PolicySummary, openSeq: number): Promise<void> => {
  viewPolicyRow.value = row
  viewPolicyVisible.value = true
  viewPolicyLoading.value = true
  viewPolicyDetail.value = null
  viewPolicyBindings.value = []
  try {
    const res = await request.get<APIResponse<{ policy: PolicyDetail; bindings: string[] }>>(`/security/policies/${row.id}`)
    if (openSeq !== policyDialogOpenSeq) return
    viewPolicyDetail.value = res.data?.policy ?? null
    viewPolicyBindings.value = res.data?.bindings ?? []
    // 查看弹框分段计数改 mergeIpEntryCount 纯计数口径（
    // 此前打开查看弹框会拉取引用名单全量条目，USTC 单源 ~460KB）
  } catch (error: unknown) {
    if (openSeq !== policyDialogOpenSeq) return
    console.error('view policy failed', error)
    viewPolicyVisible.value = false
  } finally {
    if (openSeq === policyDialogOpenSeq) viewPolicyLoading.value = false
  }
}

// 只读查看的分段内容：详情接口为字符串形态（ip_* 列表/geo* 为 JSON 文本），计数用合并口径
interface ViewPolicySection { title: string; rows: Array<{ label: string; value: string }> }
const viewPolicySections = computed<ViewPolicySection[]>(() => {
  const d = viewPolicyDetail.value
  if (!d) return []
  const trustCount = mergeIpEntryCount(ipLists.value, parseIPList(d.ip_whitelist), parseRefIds(d.ip_whitelist_refs))
  const geoCount = parseIPList(d.geoip_countries).length
  // 与编辑器/列表摘要同一计数口径（归一后长度）：库值为字符串 JSON，原样计数
  // 会把历史文件名前缀、重复值、系统基础组算成用户选择，详情与编辑器互相矛盾。
  const crsGroupCount = normalizeCrsGroups(parseIPList(d.crs_rule_groups)).length
  const excludedCount = parseCrsExcludedRules(d.crs_excluded_rules).length
  const customCount = parseCustomRuleIds(d.custom_rules).length
  const stage3Rows: Array<{ label: string; value: string }> = [{ label: 'WAF 模式', value: wafModeLabel(d.mode) }]
  if (d.mode === 'blocking' || d.mode === 'detection') {
    stage3Rows.push({ label: '异常阈值', value: String(d.anomaly_threshold) })
    stage3Rows.push({ label: 'CRS 规则组', value: crsGroupCount === 0 ? '全部（默认）' : `${crsGroupCount} 组` })
    stage3Rows.push({ label: '排除规则', value: `${excludedCount} 条` })
  }
  if (d.mode !== 'off') {
    stage3Rows.push({ label: '自定义规则', value: `${customCount} 条` })
    stage3Rows.push({ label: '检查响应体', value: d.waf_check_response ? '启用' : '关闭' })
    stage3Rows.push({ label: '记录请求体', value: d.log_request_body ? '启用' : '关闭' })
  }
  const page = d.block_page_id > 0 ? blockPages.value.find((p) => p.id === d.block_page_id) : undefined
  // 地域模式词表键（off 已在上游分支排除；未知/空模式显性说明，不得代填 deny）
  const geoipMode = d.geoip_mode ?? 'off'
  return [
    {
      title: '基础信息',
      rows: [
        { label: '名称', value: d.name },
        { label: '描述', value: d.description || '-' },
        { label: '类型', value: POLICY_TYPE_LABELS.mixed },
        { label: '启用状态', value: d.enabled ? '启用' : '禁用' },
      ],
    },
    // 阶段 0 段恒出（与流程弹框同口径 2026-09-21：无信任名单也显「未启用」，
    // 缺环节比灰态更误导）；有名单时显条目数与模式，开关关闭标注（未启用）
    {
      title: '阶段 0 · 信任名单',
      rows: trustCount === 0
        ? [{ label: '信任名单', value: '未启用' }]
        : [
            { label: '信任名单', value: `${trustCount} 条${d.ip_whitelist_enabled === false ? '（未启用）' : ''}` },
            { label: '模式', value: trustHitMode('mixed', d.trust_detection) === 'detection' ? '保留检测记录（事件动作=检测）' : '直通上游（不产生安全事件）' },
          ],
    },
    {
      title: '阶段 1 · IP 访问控制',
      rows: [
        // 与列表摘要同口径——ip_acl_enabled 开启即展示模式（即使名单为空），
        // 内容门只用于阶段能力/类型推断
        { label: '访问控制', value: d.ip_acl_enabled === true || hasIPACLControl(d) ? formatAclModeDetail(ipLists.value, d) : '未启用' },
        // 信任名单只归阶段 0 段（2026-09-21 用户裁定：独立阶段 0，阶段 1 不再重复展示）
        { label: '地域拦截', value: (d.geoip_mode ?? 'off') !== 'off'
          ? `${hasOwn(GEOIP_MODE_LABELS, geoipMode) ? GEOIP_MODE_LABELS[geoipMode] : geoipMode || '未配置模式'} · ${geoCount} 区域`
          : (geoCount > 0 ? `已关闭（保留 ${geoCount} 区域）` : '未启用') },
      ],
    },
    {
      title: '阶段 2 · 限流',
      rows: [{ label: '速率限制', value: d.rate_limit_enabled ? `${d.rate_limit_rps} 次/秒 · 突发 ${d.rate_limit_burst} 次 · 拦截恒 429` : '未启用' }],
    },
    { title: '阶段 3 · WAF', rows: stage3Rows },
    {
      title: '拦截页',
      rows: [
        { label: '拦截页面', value: d.block_page_id > 0
          ? `${page?.name ?? `页面 #${d.block_page_id}`}（状态码 ${d.block_status_code || 403}）`
          : d.rate_limit_enabled
            ? '不使用自定义页面：限流 429 返回空响应体（阶段 1/3 拦截回落 Caddy 默认 403）'
            : '不使用自定义页面（Caddy 默认 403）' },
        { label: '归因口径', value: '阶段 3 按触发策略显示；阶段 1 预检合并拦截与阶段 2 限流 429 由绑定链首位有页策略显示；规则级阶段 1/3 覆盖优先' },
      ],
    },
  ]
})

const viewPolicyBoundRuleRows = computed(() => viewPolicyBindings.value.map((caddyId) => {
  const rule = allRules.value.find((r) => r.caddy_id === caddyId)
  return { caddyId, name: rule?.name || caddyId, domain: rule?.domain || '', listenPort: rule?.listen_port ?? 0 }
}))

// 只读查看底部唯一操作：更新迁移（关查看框 → 开迁移预演）
const openMigrateFromView = (): void => {
  const row = viewPolicyRow.value
  if (!row) return
  viewPolicyVisible.value = false
  openMigrateDialog(row)
}

/** 成功回写：规则行（生效投影/覆盖徽标同源）+ 清失败标记；不整表刷新打断编辑节奏。 */
const applyStageOverrideSuccess = (caddyId: string, edit: StageOverrideEdit): void => {
  const rule = allRules.value.find((r) => r.caddy_id === caddyId)
  if (rule) {
    rule.block_page_stage1_id = edit.stage1_id
    rule.block_page_stage1_status = edit.stage1_id > 0 ? edit.stage1_status : 0
    rule.block_page_stage3_id = edit.stage3_id
    rule.block_page_stage3_status = edit.stage3_id > 0 ? edit.stage3_status : 0
  }
  if (stageOverrideFailed.value[caddyId]) {
    const next = { ...stageOverrideFailed.value }
    delete next[caddyId]
    stageOverrideFailed.value = next
  }
  if (stageOverrideSkipped.value[caddyId]) {
    const nextSkipped = { ...stageOverrideSkipped.value }
    delete nextSkipped[caddyId]
    stageOverrideSkipped.value = nextSkipped
  }
}

// ── 行级「绑定规则」（不经编辑器；与规则页「安全」弹框共享 SecurityBindingEditor） ──
const bindRulesVisible = ref(false)
const bindRulesPolicy = ref<PolicySummary | null>(null)
// 数据就绪门（与 Rules.vue 的 securityBindingsLoading/Error 同源）：编辑器语义是
// 「整集替换/全量重置」，以加载中/失败时的旧快照或空快照打开，会按错误的 delta
// 提交——界面提示更新成功，实际未被看到的既有绑定仍保留。
const securityBindingsLoading = ref(true)
const securityBindingsFailed = ref(false)
const bindRulesOpening = ref(false)

const refreshBindingsSnapshot = async (): Promise<boolean> => {
  securityBindingsLoading.value = true
  try {
    const res = await request.get<APIResponse<Record<string, BindingInfo[]>>>('/security/bindings')
    securityBindings.value = res.data || {}
    securityBindingsFailed.value = false
    return true
  } catch {
    securityBindingsFailed.value = true
    return false
  } finally { securityBindingsLoading.value = false }
}

const openBindRulesDialog = async (row: PolicySummary): Promise<void> => {
  if (securityBindingsLoading.value || securityBindingsFailed.value || bindRulesOpening.value) {
    ElMessage.warning(securityBindingsLoading.value ? '规则绑定数据加载中，请稍后再试' : '规则绑定数据加载失败，请先点击上方「重新加载」')
    return
  }
  bindRulesOpening.value = true
  try {
    // 打开前重取一次快照（保存是全量替换，旧快照的 delta 不等于当前真实绑定集）
    if (!(await refreshBindingsSnapshot())) {
      ElMessage.error('规则绑定数据刷新失败，已取消打开；请稍后重试')
      return
    }
    bindRulesPolicy.value = row
    bindRulesVisible.value = true
  } finally { bindRulesOpening.value = false }
}
const onBindRulesSaved = (): void => { void fetchData() }
const allRules = ref<Rule[]>([])
const securityBindings = ref<Record<string, BindingInfo[]>>({})
const dialogVisible = ref(false)
const editingId = ref<number | null>(null)
const ipACLList = ref<string[]>([])
const ipWhitelist = ref<string[]>([])
const ipWhitelistEnabled = ref(false)
// —— 可复用 IP 地址列表引用（refs）：与内联名单位列存储（ID 数组），保存时序列化
// 为 JSON 数组文本（ip_acl_list_refs / ip_whitelist_refs）；生效口径 = 内联 ∪ 引用条目。
const ipACLListRefs = ref<number[]>([])
const ipWhitelistRefs = ref<number[]>([])
// 引用列表载荷：页面加载/向导打开时刷新，供引用选择器 / 合计条数 / 冲突比较共用。
// v2.3.2 弹框性能重构后续：列表载荷不再内联 entries（大名单 460KB/行）——
// 条目值按需经 GET /security/ip-lists/:id 拉取，落跨组件共享缓存（见下）；
// 仅需条数的口径（列表页摘要/向导 hint）一律走 entry_count，不背条目。
interface IPListRefOption { id: number; name: string; entry_count: number; system?: boolean; entries?: Array<{ value: string; remark: string }> }
const ipLists = ref<IPListRefOption[]>([])
// 引用选择器分组（2026-09-24 用户裁定）：内置威胁名单恒置顶，与自定义列表
// 分两组展示（el-option-group 自带分隔线+组标题）
const builtinIpLists = computed(() => ipLists.value.filter((l) => l.system))
const customIpLists = computed(() => ipLists.value.filter((l) => !l.system))
// 引用名单条目：复用 utils/securityStages 的跨组件共享缓存（代际守卫 + 在途
// 去重，IPLocationAction / TriggerDetailDialog 同源）。模块缓存是普通对象，
// 视图侧以本地镜像 + 订阅保持响应式；写动作经 invalidate 清空后镜像即时刷新。
const ipListEntries = ref<Record<number, string[]>>({ ...sharedEntriesCache })
const unregisterIpListEntries = subscribeSharedEntriesCache(() => {
  ipListEntries.value = { ...sharedEntriesCache }
})
onUnmounted(unregisterIpListEntries)

// 按需补齐引用名单条目（只对未缓存 id 发请求；代际守卫保证写动作后在途响应
// 不会把失效前的旧条目回填）。镜像只在缓存确有新增时重建：命中原缓存仍重建会
// 让全部依赖 ipListEntries 的 computed（跨策略名单并集/Set、本策略合并计数）
// 在每次名单增删时全量重算——万级名单 × N 条启用策略的代价落在下拉增删上。
const ensureIpListEntries = async (ids: number[]): Promise<void> => {
  const cachedBefore = Object.keys(sharedEntriesCache).length
  await ensureSharedEntries(ids, async (id) => {
    const res = await request.get<APIResponse<{ id: number; entries?: Array<{ value: string }> }>>(`/security/ip-lists/${id}`)
    return (res.data?.entries || []).map((e) => e.value.trim()).filter((v) => v !== '')
  })
  if (Object.keys(sharedEntriesCache).length !== cachedBefore) ipListEntries.value = { ...sharedEntriesCache }
}

const fetchIpLists = async (seq?: number): Promise<void> => {
  try {
    const res = await request.get<APIResponse<IPListRefOption[]>>('/security/ip-lists')
    // 带序列号调用（openDialog）时丢弃过期返回——对话框快速关闭重开后，
    // 旧会话的在途响应不得覆盖新会话已刷新的引用列表缓存
    if (seq !== undefined && seq !== policyDialogOpenSeq) return
    ipLists.value = res.data || []
  } catch { /* 静默失败：引用选择器退化为空列表，冲突比较回退内联口径 */ }
}
// 合并内联 + 引用列表条目（按精确字符串去重，与 v1 匹配口径一致）；缓存中缺失的
// 引用列表跳过（防御性回退为仅内联）。内核统一在 utils/securityStages
// mergeIpEntryValues，本处仅适配共享条目缓存数据源成形。
const mergeIpEntries = (inline: string[], refs: number[]): string[] =>
  mergeIpEntryValues(inline, refs.map((id) => ipListEntries.value[id] ?? []))
// 条数-only 合并口径（列表页摘要用，不拉条目值）：内联去重数 + Σ引用名单
// entry_count。与 mergeIpEntries 的去重合计可能略有出入（内联与引用重叠时），
// 仅作列表页一行摘要展示；精确合计以向导内（条目已加载）为准。
// 本地 mergedIpEntryCount 与 utils/securityStages 共享
// mergeIpEntryCount 逐字重复——删除本地实现，调用点直连共享函数。
// 引用侧合计条数（各列表条目数之和，不去重——去重后的合计在 hint 的「合计」中给出）
const selectedRefEntryCount = (refs: number[]): number => refs.reduce((sum, id) => sum + (ipLists.value.find((l) => l.id === id)?.entry_count ?? 0), 0)
const aclMergedCount = computed(() => mergeIpEntries(ipACLList.value, ipACLListRefs.value).length)
// 保存校验用纯计数口径（不依赖按步惰性拉取的条目值——编辑态跳步
// 直达预览时 mergeIpEntries 会漏未加载列表致假性「名单为空」阻断保存）
const aclSaveCount = computed(() => mergeIpEntryCount(ipLists.value, ipACLList.value, ipACLListRefs.value))
const aclRefHint = computed(() => `内联 ${ipACLList.value.length} 条 + 引用列表 ${selectedRefEntryCount(ipACLListRefs.value)} 条（合计 ${aclMergedCount.value} 条）`)
const showAclRefHint = computed(() => ipACLList.value.length > 0 || ipACLListRefs.value.length > 0)
const whitelistMergedCount = computed(() => mergeIpEntries(ipWhitelist.value, ipWhitelistRefs.value).length)
const whitelistSaveCount = computed(() => mergeIpEntryCount(ipLists.value, ipWhitelist.value, ipWhitelistRefs.value))
const whitelistRefHint = computed(() => `内联 ${ipWhitelist.value.length} 条 + 引用列表 ${selectedRefEntryCount(ipWhitelistRefs.value)} 条（合计 ${whitelistMergedCount.value} 条）`)
const showWhitelistRefHint = computed(() => ipWhitelist.value.length > 0 || ipWhitelistRefs.value.length > 0)
// 本策略既有 ip_blacklist（仅用于跨策略冲突比较；本对话框不编辑该字段，
// 保存时由后端指针语义自动保留原值）
const ipBlacklistSelf = ref<string[]>([])
const geoipCountries = ref<string[]>([])
const crsRuleGroups = ref<string[]>([])
const boundRules = ref<string[]>([])

// 绑定集/规则快照变化时回填编辑态（在飞行中的行跳过，避免覆盖用户刚选的值）。
// 位置约束：immediate watch 在 setup 期即执行，必须晚于 boundRules/allRules 声明（TDZ）
//
// 稀疏持有（不再物化 seed）：只保留用户已暂存的编辑——读路径 overrideEditOf
// 已做 `?? seed` 回退。原实现把库值 seed 物化进 edits，而物化时 allRules 可能
// 仍是上一次快照（openDialog 先落地 bindings、/rules 异步后至）；新快照到达后
// 旧库值被钉成「待保存」假标记，点击保存会把旧覆盖值写回服务器，静默回退
// 他处会话/API 的变更。
watch([boundRules, allRules], () => {
  const next: Record<string, StageOverrideEdit> = {}
  for (const cid of boundRules.value) {
    const existing = stageOverrideEdits.value[cid]
    if (existing) next[cid] = existing
  }
  stageOverrideEdits.value = next
}, { immediate: true })

// 本次向导会话内、与库值不同的阶段拦截页覆盖（随向导「保存」一并提交）。
// seed 来自 allRules（库值），edit 为用户暂存值；两者相异即待提交项。
const pendingOverrideRules = computed<Array<{ caddyId: string; edit: StageOverrideEdit }>>(() =>
  boundRules.value
    .map((caddyId) => ({ caddyId, edit: overrideEditOf(caddyId), seed: stageOverrideSeed(caddyId) }))
    .filter(({ edit, seed }) =>
      edit.stage1_id !== seed.stage1_id || edit.stage1_status !== seed.stage1_status
      || edit.stage3_id !== seed.stage3_id || edit.stage3_status !== seed.stage3_status)
    .map(({ caddyId, edit }) => ({ caddyId, edit })))
const originalBoundRules = ref<string[]>([])
// 策略对话框打开序列号——丢弃在途详情 GET 的过期返回。
let policyDialogOpenSeq = 0

// 步骤条按阶段序重排（实体单职化）：基础信息 → 阶段 1 → 阶段 2 → 阶段 3 → 拦截页 → 关联规则 → 预览；
// 可见性按策略类型裁剪（visibleSteps），无该阶段的步骤不出现
const WIZARD_STEP = {
  BASIC: 0,
  TRUST: 1,
  IP_ACL: 2,
  RATE_LIMIT: 3,
  WAF_RULES: 4,
  BLOCK_PAGE: 5,
  BINDINGS: 6,
  PREVIEW: 7,
} as const
type WizardStep = (typeof WIZARD_STEP)[keyof typeof WIZARD_STEP]
const WIZARD_STEP_META: Record<WizardStep, { title: string; icon: typeof InfoFilled }> = {
  [WIZARD_STEP.BASIC]: { title: '基础信息', icon: InfoFilled },
  [WIZARD_STEP.TRUST]: { title: '阶段 0 · 信任名单', icon: Connection },
  [WIZARD_STEP.IP_ACL]: { title: '阶段 1 · IP 访问控制', icon: Connection },
  [WIZARD_STEP.RATE_LIMIT]: { title: '阶段 2 · 限流', icon: Odometer },
  [WIZARD_STEP.WAF_RULES]: { title: '阶段 3 · WAF 规则', icon: Lock },
  [WIZARD_STEP.BLOCK_PAGE]: { title: '拦截页', icon: Document },
  [WIZARD_STEP.BINDINGS]: { title: '关联规则', icon: Link },
  [WIZARD_STEP.PREVIEW]: { title: '配置预览', icon: Check },
}
const currentStep = ref<WizardStep>(WIZARD_STEP.BASIC)
// 条目值惰性拉取：进入 IP/信任编辑、拦截页、关联规则或配置预览时补齐缺失
// 条目——后三步同样消费引用条目：拦截页的「该阶段是否会产生拦截」能力门按
// 合并条目数判定（编辑态可点步骤条直接跳转），关联规则/预览的冲突链与预览
// 亦同。漏掉拦截页会让引用型 ACL 在该步被误判为「不会产生该阶段拦截」。
watch([currentStep, ipACLList, ipWhitelist, ipACLListRefs, ipWhitelistRefs], ([step]) => {
  if (step !== WIZARD_STEP.IP_ACL && step !== WIZARD_STEP.TRUST
    && step !== WIZARD_STEP.BLOCK_PAGE && step !== WIZARD_STEP.BINDINGS
    && step !== WIZARD_STEP.PREVIEW) return
  const hasContent = ipACLList.value.length > 0 || ipWhitelist.value.length > 0 ||
    ipBlacklistSelf.value.length > 0 || ipACLListRefs.value.length > 0 || ipWhitelistRefs.value.length > 0
  if (!hasContent) return
  const ids = [...ipACLListRefs.value, ...ipWhitelistRefs.value]
  // 只补本策略 + 共绑 peer 的引用名单（原实现汇总全部策略——含 stage2/3 与
  // 被禁用策略，会把内置威胁大库（单源数百 KB × 若干）整批下载）。无共绑时
  // 冲突警告的「若绑定同一规则」兜底路径按 inline 口径降级（引用条目缺失时
  // mergeIpEntries 跳过该 id），不再为此全量预取。
  const coIds = coBoundPeerIds.value
  for (const p of policies.value) {
    if (!coIds.has(p.id)) continue
    ids.push(...parseRefIds(p.ip_acl_list_refs), ...parseRefIds(p.ip_whitelist_refs))
  }
  void ensureIpListEntries(ids)
})

// 新建类型纵向列表选项（任务 C：与 el-form-item 同构的独立 radio 列表）
const POLICY_TYPE_CREATE_OPTIONS: ReadonlyArray<{ value: 'stage0' | 'stage1' | 'stage2' | 'stage3'; label: string }> = [
  { value: 'stage0', label: '阶段 0 · 信任名单（信任名单直接转发上游；可选保留检测记录）' },
  { value: 'stage1', label: '阶段 1 · IP 访问控制（IP 名单 / 地域拦截 / 拦截页）' },
  { value: 'stage2', label: '阶段 2 · 限流（速率上限，拦截恒 429）' },
  { value: 'stage3', label: '阶段 3 · WAF（模式 / CRS / 自定义规则 / 拦截页）' },
]
// ── 策略类型（实体单职化）：新建先选类型；编辑态类型由行推断/后端 policy_type 携带 ──
const createPolicyType = ref<'stage0' | 'stage1' | 'stage2' | 'stage3'>('stage0')
const editingPolicyType = ref<SecurityPolicyType | null>(null)
const editorPolicyType = computed<SecurityPolicyType>(() =>
  editingId.value === null ? createPolicyType.value : (editingPolicyType.value ?? 'mixed'))

// 信任名单在编辑器内的生效口径（与保存载荷 trustEnabledForPolicyType 同源）：
// 阶段 0 恒启用——新建阶段 0 时 ipWhitelistEnabled 初值 false 且向导没有开关控件，
// 告警/预览若各自读开关会把恒启用的信任条目判成零生效（跨策略冲突静默）。
const trustEnabledInEditor = computed(() => trustEnabledForPolicyType(editorPolicyType.value, ipWhitelistEnabled.value))

// 弹框副标题按策略类型描述；mixed/缺省保持兼容组总述文案
const EDITOR_SUBTITLES: Record<SecurityPolicyType, string> = {
  stage0: '配置信任名单条目与直通/保留检测模式',
  stage1: '配置 IP 访问控制、地域拦截与拦截页',
  stage2: '配置速率限制（恒 429）',
  stage3: '配置 WAF 模式、CRS 规则组、自定义规则与拦截页',
  mixed: '配置 WAF 检测规则、IP 访问控制、限流与规则关联',
}

const typeAllowsStage = (stage: 0 | 1 | 2 | 3): boolean =>
  editorPolicyType.value === 'mixed' || editorPolicyType.value === `stage${stage}`

const visibleSteps = computed<readonly WizardStep[]>(() => {
  const steps: WizardStep[] = [WIZARD_STEP.BASIC]
  if (typeAllowsStage(0)) steps.push(WIZARD_STEP.TRUST)
  if (typeAllowsStage(1)) steps.push(WIZARD_STEP.IP_ACL)
  if (typeAllowsStage(2)) steps.push(WIZARD_STEP.RATE_LIMIT)
  if (typeAllowsStage(3)) steps.push(WIZARD_STEP.WAF_RULES)
  // 阶段 0（直通/记录不拦截）无拦截页步骤；阶段 2 可配页（2026-09-25 用户裁定，
  // 状态码恒 429 不可改——步内状态码项按类型隐藏）
  if (editorPolicyType.value !== 'stage0') steps.push(WIZARD_STEP.BLOCK_PAGE)
  steps.push(WIZARD_STEP.BINDINGS, WIZARD_STEP.PREVIEW)
  return steps
})

const visualStepIndex = computed(() => {
  const index = visibleSteps.value.indexOf(currentStep.value)
  return index >= 0 ? index : 0
})

// 类型切换（新建态）后当前步可能被裁剪——回落到基础信息
watch(visibleSteps, (steps) => {
  if (!steps.includes(currentStep.value)) currentStep.value = WIZARD_STEP.BASIC
})

const rulePickerVisible = ref(false)
const pickerSearch = ref('')
const pickerPage = ref(1)
const pickerSelected = ref<string[]>([])
const PICKER_PAGE_SIZE = 20
const defaultForm = () => ({ name: '', description: '', enabled: true, mode: 'off', anomaly_threshold: 5, ip_acl_enabled: false, ip_acl_mode: 'allow', rate_limit_enabled: false, rate_limit_rps: 100, rate_limit_burst: 50, block_page_id: 1, block_status_code: 403, geoip_enabled: false, geoip_mode: 'deny', geoip_crawler_exempt: false, geoip_crawler_engines: ['googlebot', 'bingbot', 'baiduspider'], waf_check_response: false, log_request_body: false, trust_detection: false })

const form = ref(defaultForm())
// v2.3.8 爬虫豁免引擎注册表（geoipnames 单源镜像；ID 稳定——后端白名单校验）
const crawlerEngineOptions = [
  { id: 'googlebot', name: 'Google' },
  { id: 'bingbot', name: 'Bing' },
  { id: 'baiduspider', name: '百度' },
  { id: 'sogouspider', name: '搜狗' },
  { id: 'so360spider', name: '360' },
  { id: 'yisouspider', name: '神马' },
  { id: 'petalbot', name: '华为 PetalBot（观察级）' },
  { id: 'duckduckbot', name: 'DuckDuckGo' },
  { id: 'yandexbot', name: 'Yandex' },
  { id: 'gptbot', name: 'OpenAI（GPTBot 等）' },
  { id: 'deepseekbot', name: 'DeepSeek（观察级）' },
  { id: 'claudebot', name: 'Anthropic Claude' },
  { id: 'perplexitybot', name: 'Perplexity' },
  { id: 'kimisearchbot', name: 'Kimi（观察级）' },
  { id: 'bytespider', name: '字节 Bytespider' },
]
const selectedCustomRules = ref<number[]>([])
// action/enabled/conditions 供冲突检测与按 Coraza 相位判定真实拦截能力
const allCustomRules = ref<SecurityStageCustomRule[]>([])

// 返回是否加载成功——聚焦流程需区分
// 「列表加载失败」与「策略确已删除」，否则瞬时失败会被误报为「已被删除」。
const fetchData = async (): Promise<boolean> => {
  loading.value = true
  // 行级「绑定规则」的就绪门：主数据/辅助数据都在本次 allSettled 里，门随整体结束释放
  securityBindingsLoading.value = true
  try {
    // allSettled 替代 all——策略主数据失败才整体报错，
    // 辅助数据（规则/CRS 选项/拦截页/绑定/用户）部分失败保留已有数据，
    // 避免「保存策略后任一辅助端点失败 → 整个列表不刷新」的 stale 状态。
    const [polRes, ruleRes, crsRes, bpRes, crRes, bindRes, userRes, ipListRes] = await Promise.allSettled([
      request.get<APIResponse<PolicySummary[]>>('/security/policies'),
      request.get<APIResponse<Rule[]>>('/rules'),
      fetchAllCrsRuleFiles(),
      request.get<APIResponse<BlockPage[]>>('/security/block-pages'),
      request.get<APIResponse<SecurityStageCustomRule[]>>('/security/custom-rules'),
      request.get<APIResponse<Record<string, BindingInfo[]>>>('/security/bindings'),
      request.get<APIResponse<UserListItem[]>>('/users'),
      // IP 地址列表缓存：列表页「IP 控制」能力判定/提示与冲突比较需要引用条目合并口径
      request.get<APIResponse<IPListRefOption[]>>('/security/ip-lists'),
    ])
    if (polRes.status === 'rejected') {
      console.error('Failed to load policies data:', polRes.reason)
      // 错误态显性化——保留旧数据（若有），横幅+重试由模板渲染
      policiesLoadError.value = true
      auxLoadFailures.value = []
      return false
    }
    policies.value = polRes.value.data || []
    policiesLoadError.value = false
    const failures: string[] = []
    if (ruleRes.status === 'fulfilled') allRules.value = ruleRes.value.data || []
    else failures.push('规则列表')
    if (crsRes.status === 'fulfilled') crsRuleOptions.value = crsRes.value || []
    else failures.push('CRS 规则选项')
    if (bpRes.status === 'fulfilled') { blockPages.value = bpRes.value.data || []; blockPagesLoaded.value = true }
    else failures.push('拦截页面')
    if (crRes.status === 'fulfilled') allCustomRules.value = crRes.value.data || []
    else failures.push('自定义规则')
    if (bindRes.status === 'fulfilled') { securityBindings.value = bindRes.value.data || {}; securityBindingsFailed.value = false }
    else { failures.push('规则绑定'); securityBindingsFailed.value = true }
    if (userRes.status === 'fulfilled') users.value = userRes.value.data || []
    else failures.push('用户列表')
    if (ipListRes.status === 'fulfilled') ipLists.value = ipListRes.value.data || []
    else failures.push('IP 地址列表')
    auxLoadFailures.value = failures
    if (failures.length > 0) console.warn('部分辅助数据加载失败：', failures.join('、'))
    return true
  } catch (error: unknown) {
    console.error('Failed to load policies data:', error)
    policiesLoadError.value = true
    return false
  } finally {
    loading.value = false
    securityBindingsLoading.value = false
  }
}

// JSON 数组文本解析走 utils/securityStages（单源）：文本 JSON.parse 后委托
// parseUnknownIds 的对象/数字双形态守卫（收敛——原与本模块
// parseUnknownIds 同构两份，存在漂移风险）。
const parseCustomRuleIds = (raw: string | undefined): number[] => {
  if (!raw) return []
  try {
    return parseUnknownIds(JSON.parse(raw))
  } catch { return [] }
}

// CRS 规则组/基础设施 ID 的取值口径全部收敛在 utils/crsGroups（后端 Include 以
// 两位组代码为键；可识别形态归一、不可识别形态原样保留，见该模块文件头）。

// crsOptionCode 从 CRS 文件名提取展示组码（REQUEST-942-*.conf → "942"）——
// 解析单源 utils/securityStages.parseCrsFilename；非 CRS 文件名原样返回。
const crsOptionCode = (filename: string): string => {
  const info = parseCrsFilename(filename)
  return info ? `9${info.code}` : filename
}

// crsOptionPhase（用户反馈）：CRS 规则文件分请求/响应两个阶段——REQUEST-*
// 为请求阶段（请求行/头/参数/体），RESPONSE-* 为响应阶段（响应体）。选项
// 必须区分阶段，否则「942 · SQL 注入」与「955 · Webshell」无法看出分别作用
// 于请求还是响应。命名取 CRS 官方 phase 术语的最简中文：请求 / 响应
//（REQUEST 规则查的不只是请求体，叫「请求体」不准确）。
const crsOptionPhase = (filename: string): string => parseCrsFilename(filename)?.phase ?? '请求'

// 规则组/排除目标级联的已知值全集（两位组号 ∪ 索引规则 ID）——命中即无需 ghost 兜底
const crsKnownTargetValues = computed<Set<string>>(() =>
  new Set([...crsGroupOptions.value.map((o) => o.value), ...crsIndexOptions.value.map((o) => o.id)]))

// ghost 兜底：已选/已存值不在已知值集（CRS 更新后消失的规则 ID/组码、旧字符串数组
// 遗留的文件名/区间形态）时派生可读标签，避免控件回退显示裸值。级联无法映射路径
// 的值（多选侧 ghost 标签 / 排除行 ghost 文本）共用此语义。
interface CrsGhostOption { value: string; label: string; title: string }
const crsGhostOptionFor = (value: string): CrsGhostOption | null => {
  const v = value.trim()
  if (v === '' || crsKnownTargetValues.value.has(v)) return null
  if (parseCrsFilename(v)) {
    const fileRule = crsRuleOptions.value.find((r) => r.filename === v)
    const label = fileRule
      ? `文件 · ${crsOptionPhase(v)} · ${crsOptionCode(v)} · ${fileRule.category}`
      : `文件 · ${crsOptionPhase(v)} · ${crsOptionCode(v)}`
    return { value: v, label, title: v }
  }
  if (/^\d{6}$/.test(v)) {
    // 陈旧判定仅在索引成功加载后生效——加载失败/在途时不得把规则 ID 误标为已移除
    if (!crsIndexLoaded.value) return null
    return { value: v, label: `${v} —（当前 CRS 已无此规则）`, title: v }
  }
  if (/^\d{2}$/.test(v)) {
    // 两数字组码组：旧版 CRS 遗留的失效组码（如 10/12，当前 CRS 4.x 已无对应文件）。
    // 守卫：规则文件列表未加载/失败（该列表恒 27 组，空=未就绪）时不标记，防误报。
    if (crsRuleOptions.value.length === 0) return null
    if (CRS_HIDDEN_GROUP_CODES.includes(v)) {
      const label = `${v} · 通用误报豁免（选择全部规则时自动包含）`
      return { value: v, label, title: label }
    }
    const label = `${v} —（当前 CRS 已无此规则组，可删除）`
    return { value: v, label, title: label }
  }
  return { value: v, label: v, title: v }
}
// 规则组多选框的 ghost 标签（按当前选中值派生）：级联无法映射路径的值以此呈现，可删除
const crsGroupGhostTags = computed<CrsGhostOption[]>(() =>
  crsRuleGroups.value.map(crsGhostOptionFor).filter((o): o is CrsGhostOption => o !== null))

const removeCrsGroupValue = (value: string): void => {
  crsRuleGroups.value = crsRuleGroups.value.filter((v) => v !== value)
}

// crsResponsePhaseGroupCodes：响应阶段 CRS 类别两位代码
//（950-956/980）——这些组仅在「检查响应体」开启时才被后端 Include
//（security.go:169-177），否则静默 no-op。用于给选中响应组但开关关闭的用户
// 一个针对性提示。959 响应评估为系统基础组（随响应检查开启由后端强制加载，
// 不再出现在可选组中），不在此列。
const crsResponsePhaseGroupCodes = ['50', '51', '52', '53', '54', '55', '56', '80']
const hasResponsePhaseGroupWithoutCheck = computed(
  () => (form.value.mode === 'blocking' || form.value.mode === 'detection') && !form.value.waf_check_response && crsRuleGroups.value.some((g) => crsResponsePhaseGroupCodes.includes(g)),
)

// 拦截评估规则（949 请求阻断评估 / 959 响应评估）排除判定：拦截模式下这两组负责
// 按异常阈值执行阻断，排除后阈值拦截失效。目标形态覆盖两位组号 49/59、949xxx/959xxx
// 六位规则 ID、REQUEST-949-*/-* 文件名，以及与 949000-949999 /
// 959000-959999 相交的区间遗留形态。
const isEvalGroupExclusionTarget = (target: string): boolean => {
  const t = target.trim()
  if (t === '') return false
  if (/^\d{2}$/.test(t)) return t === '49' || t === '59'
  if (/^\d{6}$/.test(t)) return t.startsWith('949') || t.startsWith('959')
  const fileInfo = parseCrsFilename(t)
  if (fileInfo && (fileInfo.code === '49' || fileInfo.code === '59')) return true
  const rangeMatch = /^(\d{6})\s*[-:]\s*(\d{6})$/.exec(t)
  if (rangeMatch) {
    const lo = Number(rangeMatch[1])
    const hi = Number(rangeMatch[2])
    return (lo <= 949999 && hi >= 949000) || (lo <= 959999 && hi >= 959000)
  }
  return false
}
// 仅 scope=all 的 949/959 排除使阈值拦截全局失效；scoped 排除只影响命中来源
// IP，不配「全局失效」的无条件告警（审计口径）。
const blockingEvalExclusionAlert = computed(
  () => form.value.mode === 'blocking' && crsExcludedRows.value.some((row) => row.scope === 'all' && isEvalGroupExclusionTarget(row.target)),
)
const crsGroupOptions = computed(() => {
  const seen = new Map<string, string>()
  for (const rule of crsRuleOptions.value) {
    const info = parseCrsFilename(rule.filename)
    const code = info?.code
    // 系统基础组（01/49/59）不提供选择——后端强制加载；99 通用误报豁免非检测
    // 组（全部规则时自动包含），同样不提供选项（v2.3.x 用户裁定）
    if (!code || seen.has(code) || CRS_INFRA_GROUP_CODES.includes(code) || CRS_HIDDEN_GROUP_CODES.includes(code)) continue
    seen.set(code, `${crsOptionPhase(rule.filename)} · 9${code} · ${rule.category}`)
  }
  return [...seen.entries()].map(([value, label]) => ({ value, label }))
})

// 排除选择器的组选项：仅剔 "01"（后端硬拒，提供即必现 400）与 "99"（非检测组，
// 误报豁免不应被排除）；49/59 保留可选（检测模式排除评估规则是合法调优，拦截模式
// 下另有 blockingEvalExclusionAlert 警告）
const crsExclusionGroupOptions = computed(() => {
  const seen = new Map<string, string>()
  for (const rule of crsRuleOptions.value) {
    const info = parseCrsFilename(rule.filename)
    const code = info?.code
    if (!code || seen.has(code) || code === '01' || CRS_HIDDEN_GROUP_CODES.includes(code)) continue
    seen.set(code, `${crsOptionPhase(rule.filename)} · 9${code} · ${rule.category}`)
  }
  return [...seen.entries()].map(([value, label]) => ({ value, label }))
})

// 两个 CRS 选择器（规则组多选 / 排除目标每行单选）共用同一懒加载级联实现：一级
// 返回组节点（label 沿用「请求 · 942 · SQL 注入」），展开组时才从已缓存索引按
// 文件名两位组号切出该组规则叶（相位与组号一一对应：REQUEST/RESPONSE 前缀决定）。
// 懒的是组件挂载不是数据获取——索引仍由 useCrsRuleIndex 一次性拉回（约 832 条），
// 叶节点数组仅在组展开时生成，832 条全集不随任何 cascader 挂载渲染（排除行上限
// 50 行）。两侧差异仅剔除口径：'group' 剔基础设施 ID（901/949/959，写入面同语义
// 剥离，提供选项=选了保存后消失）；'exclusion' 仅剔 901（后端硬拒，提供即必现
// 400）——949/959 保留可选（检测模式排除评估是合法调优，拦截模式另有
// blockingEvalExclusionAlert）。组节点剔除口径由 crsGroupOptions（剔 01/49/59）/
// crsExclusionGroupOptions（剔 01）各自保证。
type CrsCascaderSide = 'group' | 'exclusion'

// 级联节点数据：组节点（leaf:false）+ 规则叶（leaf:true，isRule/file/category/
// fullLabel 供默认插槽按旧版 crs-rule-option 两行样式渲染）
interface CrsCascaderOption extends CascaderOption {
  value: string
  label: string
  isRule?: boolean
  file?: string
  category?: string
  fullLabel?: string
}

// 从 CRS 文件名提取两位组号（REQUEST-942-*.conf → "42"）——解析单源 parseCrsFilename
const crsGroupCodeOfFile = (file: string): string => parseCrsFilename(file)?.code ?? ''

const crsCascaderLazyLoad = (side: CrsCascaderSide): LazyLoad => (node, resolve) => {
  // 一级：组节点（常渲染可浏览，剔除口径按侧）
  if (node.level === 0) {
    const groups = side === 'group' ? crsGroupOptions.value : crsExclusionGroupOptions.value
    resolve(groups.map((g): CrsCascaderOption => ({ value: g.value, label: g.label, leaf: false })))
    return
  }
  // 二级：展开组时才生成该组规则叶（索引已按 id 升序；剔除口径按侧）
  const code = typeof node.value === 'string' ? node.value : ''
  const rules: CrsRuleOptionView[] = crsIndexOptions.value.filter((r) =>
    crsGroupCodeOfFile(r.file) === code && (side === 'group' ? !isInfraRuleId(r.id) : !isInitRuleId(r.id)))
  resolve(rules.map((r): CrsCascaderOption => ({
    value: r.id,
    label: `${r.id} — ${r.label}`,
    leaf: true,
    isRule: true,
    file: r.file,
    category: r.category,
    fullLabel: r.fullLabel,
  })))
}

const crsGroupCascaderProps: CascaderProps = {
  lazy: true,
  multiple: true,
  checkStrictly: true,
  lazyLoad: crsCascaderLazyLoad('group'),
}

const crsExclusionCascaderProps: CascaderProps = {
  lazy: true,
  checkStrictly: true,
  lazyLoad: crsCascaderLazyLoad('exclusion'),
}

// 存储值 → 级联路径：两位组号 → [组号]（组须在对应侧可选组列表内）；6 位规则 ID
// → [组号, 规则ID]（组号由索引条目文件名解析，且该组节点存在）。无法映射（陈旧
// ID/遗留文件名/索引未就绪/被剔除口径的值）返回 null——多选侧交 ghost 标签、单选
// 侧交 ghost 文本兜底，均不进入级联值，写回时原样保留（存储契约不变）。
const crsValueToPath = (value: string, side: CrsCascaderSide): string[] | null => {
  const v = value.trim()
  if (v === '') return null
  const groups = side === 'group' ? crsGroupOptions.value : crsExclusionGroupOptions.value
  if (/^\d{2}$/.test(v)) return groups.some((g) => g.value === v) ? [v] : null
  if (/^\d{6}$/.test(v)) {
    const entry = crsIndexById.value.get(v)
    if (!entry) return null
    const code = crsGroupCodeOfFile(entry.file)
    if (code === '' || !groups.some((g) => g.value === code)) return null
    return [code, v]
  }
  return null
}

// crs_rule_groups ↔ 级联路径双向桥接：读侧把可映射存储值翻译为路径数组；写侧把
// 路径压平回存储值（取路径末段：组→组号、规则→规则 ID），无法映射的值原样保留
const crsGroupCascaderValue = computed<string[][]>({
  get: () => {
    const paths: string[][] = []
    for (const raw of crsRuleGroups.value) {
      const path = crsValueToPath(raw, 'group')
      if (path) paths.push(path)
    }
    return paths
  },
  set: (paths) => {
    const selected = paths.map((p) => p[p.length - 1]).filter((v) => v !== '')
    const ghosts = crsRuleGroups.value.filter((v) => crsValueToPath(v, 'group') === null)
    crsRuleGroups.value = [...new Set([...selected, ...ghosts])]
  },
})

// 排除行单选级联回填：已存 target 能映射路径则显示路径解析标签，否则留空交 ghost 文本
const exclusionTargetPath = (target: string): string[] => crsValueToPath(target, 'exclusion') ?? []

// 单选 + checkStrictly（emitPath 默认 true）：值为路径数组，取末段（组号或规则 ID）写入 target
// el-cascader 的 update:model-value 载荷含 null（清空），与 undefined 同义
const onExclusionTargetChange = (row: CrsExcludedRow, value: CascaderValue | null | undefined): void => {
  if (!Array.isArray(value) || value.length === 0) { row.target = ''; return }
  const leaf = value[value.length - 1]
  row.target = typeof leaf === 'string' ? leaf : ''
}

// ================= 排除规则行编辑器 =================
const addExcludedRule = (): void => {
  if (crsExcludedRows.value.length >= CRS_EXCLUDED_MAX_ROWS) return
  crsExcludedRows.value.push({ target: '', scope: 'all', ips: [], listRefs: [] })
}

const removeExcludedRule = (idx: number): void => {
  crsExcludedRows.value.splice(idx, 1)
}

// 指定 IP 标签输入即时校验：非法条目立即拒绝（toast + 回滚为仅合法条目），
// 与 ACL 内联名单位同一 isValidCidr 口径（后端 400 为最终裁决，此处前置拦截）
const onExclusionIpsChange = (row: CrsExcludedRow, value: string[]): void => {
  const invalid = value.find((entry) => !isValidCidr(entry))
  if (invalid !== undefined) {
    ElMessage.error(`IP/CIDR 条目格式不正确：${invalid}`)
    row.ips = value.filter((entry) => isValidCidr(entry))
    return
  }
  row.ips = value
}

// 行级矛盾提示：目标同时出现在规则组正选与排除清单——排除恒优先。
// - 单条规则 ID 两边都选 → 矛盾（正选加载、排除又不加载）；
// - 整组排除且该组同时在规则组正选 → 冗余（整组都不加载，正选形同虚设）。
// 仅做提示不阻断：组合「正选组 + 排除组内单条」是正常用法，不在此列。
const exclusionRowConflict = (row: CrsExcludedRow): string => {
  const target = row.target.trim()
  if (target === '' || form.value.mode !== 'blocking' && form.value.mode !== 'detection') return ''
  if (!crsRuleGroups.value.includes(target)) return ''
  return /^\d{2}$/.test(target) ? '冗余：排除优先生效' : '与规则组选择矛盾（排除优先）'
}

// 提交口径：全空行（无目标且无条件）静默丢弃，其余按 target+scope+ips+listRefs 去重
// 作用域切换清残留——否则 scope=all 残留 ips 保存 400，
// scope=list 残留 ips 被静默并入匹配集（语义漂移且 UI 不可见）。
const onScopeChange = (row: CrsExcludedRow): void => {
  if (row.scope === 'all') { row.ips = []; row.listRefs = [] }
  else if (row.scope === 'ip') { row.listRefs = [] }
  else if (row.scope === 'list') { row.ips = [] }
}

const serializedExcludedRules = computed<CrsExcludedRow[]>(() => {
  const seen = new Set<string>()
  const out: CrsExcludedRow[] = []
  for (const row of crsExcludedRows.value) {
    const target = row.target.trim()
    if (target === '' && row.ips.length === 0 && row.listRefs.length === 0) continue
    const key = `${target}\u0000${row.scope}\u0000${row.ips.join(',')}\u0000${row.listRefs.join(',')}`
    if (seen.has(key)) continue
    seen.add(key)
    // 序列化按 scope 剥离非当前作用域的残留——
      // 带外数据（scope=all 但 ips 非空）会 400 卡保存。
      out.push({ target, scope: row.scope,
        ips: row.scope === 'ip' ? [...row.ips] : [],
        listRefs: row.scope === 'list' ? [...row.listRefs] : [] })
  }
  return out
})

// 行是否为待校验的有效配置行（非全空行即需通过校验）
const isFilledExclusionRow = (row: CrsExcludedRow): boolean =>
  row.target.trim() !== '' || row.ips.length > 0 || row.listRefs.length > 0

// 保存/跨步闸门：非空行必须目标齐备，scope=ip 需至少一个 IP，scope=list 需至少一个列表
const validateExcludedRules = (): boolean => {
  for (let i = 0; i < crsExcludedRows.value.length; i++) {
    const row = crsExcludedRows.value[i]
    if (!row || !isFilledExclusionRow(row)) continue
    if (row.target.trim() === '') {
      ElMessage.error(`第 ${i + 1} 条排除规则未选择目标`)
      return false
    }
    if (row.scope === 'ip' && row.ips.length === 0) {
      ElMessage.error(`第 ${i + 1} 条排除规则（指定 IP）未填写 IP`)
      return false
    }
    if (row.scope === 'list' && row.listRefs.length === 0) {
      ElMessage.error(`第 ${i + 1} 条排除规则（地址列表）未选择列表`)
      return false
    }
  }
  return true
}

// 预览目标 label：两位组号 → 组选项 label；6 位 ID → 索引「ID — 描述」（截断版）；
// 旧文件名/未知值 → 解析化文件形态或原值
const exclusionTargetLabel = (target: string): string => {
  if (/^\d{2}$/.test(target)) return crsGroupOptions.value.find((o) => o.value === target)?.label ?? `规则组 ${target}`
  const entry = crsIndexById.value.get(target)
  if (entry) return `${target} — ${crsRuleLabelView(entry).label}`
  if (parseCrsFilename(target)) return `文件 · ${crsOptionPhase(target)} · ${crsOptionCode(target)}`
  return target
}

// 排除行 ghost 文本：target 无法映射级联路径（遗留文件名/陈旧 ID/被剔除口径的值如
// 901xxx）时的可读兜底——优先 crsGhostOptionFor（陈旧/遗留语义，含「（当前 CRS 已无
// 此规则）」），已知值回退 exclusionTargetLabel（「ID — 描述」/组 label）；返回空串
// 表示无需 ghost（空 target 或可映射路径）。
const exclusionRowGhostLabel = (target: string): string => {
  const v = target.trim()
  if (v === '' || crsValueToPath(v, 'exclusion') !== null) return ''
  return crsGhostOptionFor(v)?.label ?? exclusionTargetLabel(v)
}



// CRS 配置面禁用门(2026-09-09 四态化):off=全关、custom_only=仅自定义,两者 CRS 均不生效
const crsFieldsOff = computed(() => form.value.mode === 'off' || form.value.mode === 'custom_only')


// 内置威胁名单仅可用于黑名单模式（2026-09-24 用户裁定，与后端
// validateBuiltinThreatListRefs 同口径）：模式切到白名单/免检测时，
// 已选的内置名单引用自动剥离并提示（否则保存将被后端 400 拒绝）
watch(() => form.value.ip_acl_mode, (mode) => {
  if (mode === 'deny') return
  const builtinIds = new Set(builtinIpLists.value.map((l) => l.id))
  const kept = ipACLListRefs.value.filter((id) => !builtinIds.has(id))
  if (kept.length !== ipACLListRefs.value.length) {
    ipACLListRefs.value = kept
    ElMessage.warning('内置威胁名单仅可用于黑名单模式，已从引用中移除')
  }
})

const ACL_LIST_LABELS: Record<string, string> = { deny: '拒绝 IP', allow: '允许 IP', 绕过: '免检测 IP' }
// 词表查表统一过 hasOwn：库值可能命中原型键（constructor/toString/__proto__，
// 只能由带外改库产生），裸下标会把 Object.prototype 上的函数当标签渲染。
const aclListLabel = computed(() => (hasOwn(ACL_LIST_LABELS, form.value.ip_acl_mode)
  ? ACL_LIST_LABELS[form.value.ip_acl_mode]
  : 'IP 列表'))

const GEOIP_MODE_LABELS: Record<string, string> = { deny: '拦截所选区域', allow: '仅允许所选区域' }
// 从 off 态重开开关时控制模式回落 deny（off 只是关闭哨兵，radio 无此项）。
const onGeoipEnabledChange = (enabled: string | number | boolean) => {
  if (enabled && form.value.geoip_mode === 'off') form.value.geoip_mode = 'deny'
}

const ACL_MODE_TIPS: Record<string, string> = {
  deny: '列表中的 IP 将被拒绝访问，其他 IP 正常进行安全检测',
  allow: '仅列表中的 IP 可以访问，其他 IP 一律拒绝',
  绕过: '列表中的 IP 将跳过全部安全检测',
}
const aclListTip = computed(() => (hasOwn(ACL_MODE_TIPS, form.value.ip_acl_mode)
  ? ACL_MODE_TIPS[form.value.ip_acl_mode]
  : ''))
// 与后端口径一致：ACL 启用且列表非空，或黑名单非空（内联与引用列表合并计数）。
// 2026-09-21：信任名单（ip_whitelist）不再计入——信任恒归独立阶段 0（用户裁定），
// 计入会把纯信任策略误判为跨阶段 mixed 并在阶段 1 投出空行。
// 地域拦截启用口径与后端 PolicyHasGeoIP 一致：geoip_mode !== 'off' 且区域名单非空
//（off 为关闭哨兵：区域保留不清单，重开即复用）
const geoipRegionCount = (row: PolicySummary): number => parseIPList(row.geoip_countries).length


// /security/bindings 以 rule_caddy_id 为键（v2.2.0 起值为绑定数组，policy_id ASC），
// 反转为 policy_id → 规则列表供列表 tooltip 使用
const policyRulesMap = computed(() => {
  const map = new Map<number, Rule[]>()
  for (const rule of allRules.value) {
    const bindings = securityBindings.value[rule.caddy_id]
    if (!bindings) continue
    for (const binding of bindings) {
      const list = map.get(binding.policy_id) ?? []
      list.push(rule)
      map.set(binding.policy_id, list)
    }
  }
  return map
})

const policyBoundRules = (policyId: number): Rule[] => policyRulesMap.value.get(policyId) ?? []

const stepsClickable = computed(() => editingId.value !== null)
const hasPreviousStep = computed(() => visualStepIndex.value > 0)
const hasNextStep = computed(() => visualStepIndex.value < visibleSteps.value.length - 1)

const moveToAdjacentWizardStep = (direction: -1 | 1): void => {
  const targetStep = visibleSteps.value[visualStepIndex.value + direction]
  if (targetStep !== undefined) currentStep.value = targetStep
}

const jumpToStep = (step: WizardStep): void => {
  if (!stepsClickable.value || saving.value) return
  currentStep.value = step
}

const validateIpAclList = (): boolean => {
  // 白名单空列表校验采用合并口径：内联为空但已引用列表时，生效名单非空即合法
  if (form.value.ip_acl_enabled && form.value.ip_acl_mode === 'allow' && aclSaveCount.value === 0) {
    ElMessage.error('白名单模式下 IP 列表不能为空，否则所有请求将被拒绝')
    return false
  }
  // 校验只作用于生效字段（与渲染门同源）：关闭 IP 访问控制后内联名单按保留语义
  // 继续回传但零发射，此时点名不可见条目会让用户既看不到也删不掉。
  if (form.value.ip_acl_enabled) {
    const invalidEntry = ipACLList.value.find((entry) => !isValidCidr(entry))
    if (invalidEntry) {
      ElMessage.error(`IP/CIDR 条目格式不正确：${invalidEntry}`)
      return false
    }
  }
  if (ipWhitelistEnabled.value) {
    const invalidTrustEntry = ipWhitelist.value.find((entry) => !isValidCidr(entry))
    if (invalidTrustEntry) {
      ElMessage.error(`信任名单中的 IP/CIDR 条目格式不正确：${invalidTrustEntry}`)
      return false
    }
  }
  if (form.value.geoip_enabled && geoipCountries.value.length === 0) {
    ElMessage.error('区域控制启用后必须选择至少一个区域（引用即生效）')
    return false
  }
  return true
}

const nextStep = (): void => {
  if (currentStep.value === WIZARD_STEP.BASIC) {
    if (!form.value.name.trim()) {
      ElMessage.warning('请输入策略名称')
      return
    }
    moveToAdjacentWizardStep(1)
    return
  }
  if (currentStep.value === WIZARD_STEP.WAF_RULES) {
    if (!validateExcludedRules()) return
    moveToAdjacentWizardStep(1)
    return
  }
  if (currentStep.value === WIZARD_STEP.IP_ACL) {
    if (!validateIpAclList()) return
    moveToAdjacentWizardStep(1)
    return
  }
  moveToAdjacentWizardStep(1)
}

const prevStep = (): void => {
  moveToAdjacentWizardStep(-1)
}

const pickerFilteredRules = computed(() => {
  // 安全策略仅对 HTTP 规则生效（TCP 走 L4 链不经过 WAF/ACL/限流），选择器只列 HTTP
  const httpRules = allRules.value.filter((rule) => rule.protocol === 'http')
  const query = pickerSearch.value.trim().toLowerCase()
  if (!query) return httpRules
  return httpRules.filter((rule) =>
    rule.name.toLowerCase().includes(query)
    || (rule.domain || '').toLowerCase().includes(query)
    || rule.caddy_id.toLowerCase().includes(query))
})

const pickerPagedRules = computed(() => {
  const start = (pickerPage.value - 1) * PICKER_PAGE_SIZE
  return pickerFilteredRules.value.slice(start, start + PICKER_PAGE_SIZE)
})

watch(pickerSearch, () => {
  pickerPage.value = 1
})

// 全选作用于当前搜索筛选出且可选择的全部规则（跨分页；已达绑定上限/限流冲突的
// 规则不可选，不参与全选），selection 存于 pickerSelected 与分页无关
const pickerSelectableRules = computed(() => pickerFilteredRules.value.filter((rule) => pickerMeta(rule.caddy_id).blockReason === ''))
const pickerFilteredSelectedCount = computed(() => {
  const selected = new Set(pickerSelected.value)
  return pickerSelectableRules.value.reduce((count, rule) => count + (selected.has(rule.caddy_id) ? 1 : 0), 0)
})
const pickerSelectAllChecked = computed(() =>
  pickerSelectableRules.value.length > 0 && pickerFilteredSelectedCount.value === pickerSelectableRules.value.length)
const pickerSelectAllIndeterminate = computed(() =>
  pickerFilteredSelectedCount.value > 0 && pickerFilteredSelectedCount.value < pickerSelectableRules.value.length)

const handlePickerSelectAll = (checked: string | number | boolean): void => {
  const selectableIds = pickerSelectableRules.value.map((rule) => rule.caddy_id)
  if (checked === true) {
    pickerSelected.value = [...new Set([...pickerSelected.value, ...selectableIds])]
    return
  }
  const selectableIdSet = new Set(selectableIds)
  pickerSelected.value = pickerSelected.value.filter((id) => !selectableIdSet.has(id))
}

// 拦截页面 = 首绑策略的页面（启用策略中 policy_id 最小者）；单规则最多
// MAX_POLICIES_PER_RULE 条（securityStages 单源，与后端 maxBindingsPerRule 同口径）；
// security_policies.id 为 AUTOINCREMENT——新建策略的 ID 必然大于全部现存策略，
// 因此新建策略在任何规则的绑定链上都落在末位。
const PERF_POLICY_THRESHOLD = 3

// 选中规则的完整绑定策略明细（冲突检测需要 crs_rule_groups/custom_rules 内容，
// /security/bindings 的 BindingInfo 不含这些字段）——按规则懒加载，对话框关闭时
// 清空防止跨编辑会话的 stale 数据。
const ruleBoundPolicies = ref<Record<string, RuleBoundPolicy[]>>({})
const ensureBindingDetails = async (caddyIds: string[]): Promise<void> => {
  const missing = caddyIds.filter((id) => !(id in ruleBoundPolicies.value))
  if (missing.length === 0) return
  // 捕获对话框会话序列号——对话框关闭（resetWizard 已清空缓存）后落地的
  // 过期响应不得回写，否则下一次会话把 stale 条目当作缓存跳过重取（missing 过滤）
  const openSeq = policyDialogOpenSeq
  const results = await Promise.allSettled(
    missing.map((id) => request.get<APIResponse<RuleBoundPolicy[]>>(`/security/rules/${encodeURIComponent(id)}/policy`)),
  )
  if (!dialogVisible.value || openSeq !== policyDialogOpenSeq) return
  const next = { ...ruleBoundPolicies.value }
  results.forEach((res, i) => {
    // 失败的不写入：保持缺省以便下次进入步骤时重试（全局拦截器已 toast）
    if (res.status !== 'fulfilled') return
    const caddyId = missing[i]
    if (caddyId === undefined) return
    next[caddyId] = res.value.data || []
  })
  ruleBoundPolicies.value = next
}

watch(currentStep, (step) => {
  if (step === WIZARD_STEP.BINDINGS && dialogVisible.value) void ensureBindingDetails(boundRules.value)
})

// IP 名单归一化（去空白、去重）统一走 mergeIpEntryValues(values, [])。
// v1 仅做精确字符串匹配——10.0.0.0/8 与 10.0.0.1 之类的 CIDR 包含关系不在本期范围
//（跨策略冲突检测用）。

// 策略 IP 名单按真实生效范围拆分：ACL 允许侧与信任名单不能合并——ACL 与存量
// 非阶段 0 信任仅豁免所属策略，阶段 0 信任则跨策略直通或降级为仅检测。
// 拒绝侧 = 黑名单模式下的 ACL 列表 + 独立 ip_blacklist 字段（由策略页外入口维护）。
// 供 Step 4 冲突检测与 WAF/IP 步骤实时警告共用，保证两处口径一致。
// 信任名单须看启用态（三态：关闭=保留名单零生效）——否则对端已关闭的信任名单
// 仍会触发误报冲突告警。返回的三组条目分别归一去重，不再制造第二份合并允许侧。
const ipAclSideEntries = (mode: string, aclEnabled: boolean, aclList: string[], whitelist: string[], blacklist: string[], whitelistEnabled = true): { aclAllow: string[]; trust: string[]; deny: string[] } => {
  const aclAllow = aclEnabled && (mode === 'allow' || mode === '绕过') ? aclList : []
  const trust = whitelistEnabled ? whitelist : []
  const deny: string[] = []
  if (aclEnabled && mode === 'deny') deny.push(...aclList)
  deny.push(...blacklist)
  return { aclAllow: mergeIpEntryValues(aclAllow, []), trust: mergeIpEntryValues(trust, []), deny: mergeIpEntryValues(deny, []) }
}

// 本策略（表单实时值）的允许/信任/拒绝三侧名单——引用列表条目并入内联后参与比较
const selfIpAclSides = computed(() => ipAclSideEntries(form.value.ip_acl_mode, form.value.ip_acl_enabled, mergeIpEntries(ipACLList.value, ipACLListRefs.value), mergeIpEntries(ipWhitelist.value, ipWhitelistRefs.value), ipBlacklistSelf.value, trustEnabledInEditor.value))

const customRuleActionOf = (id: number): string => allCustomRules.value.find((r) => r.id === id)?.action ?? ''

// 自定义规则引用解析：兼容纯 ID 数组与内嵌对象（{id, action}）两种存储形状；
// 内嵌对象缺 action 或纯 ID 时回查自定义规则表
const parseCustomRuleRefs = (raw: unknown): CustomRuleRef[] => {
  let items: unknown[] = []
  if (Array.isArray(raw)) items = raw
  else if (typeof raw === 'string') {
    try {
      const parsed: unknown = JSON.parse(raw)
      if (Array.isArray(parsed)) items = parsed
    } catch { items = [] }
  }
  const refs: CustomRuleRef[] = []
  for (const item of items) {
    if (typeof item === 'number' && item > 0) {
      refs.push({ id: item, action: customRuleActionOf(item) })
    } else if (typeof item === 'object' && item !== null && 'id' in item) {
      const id = (item as { id?: unknown }).id
      if (typeof id === 'number' && id > 0) {
        const embeddedAction = (item as { action?: unknown }).action
        refs.push({ id, action: typeof embeddedAction === 'string' && embeddedAction !== '' ? embeddedAction : customRuleActionOf(id) })
      }
    }
  }
  return refs
}

// 展示链：完整绑定列表（含禁用策略，标灰）+ 本策略，按 policy_id ASC。
// 本策略条目以表单实时值为准（编辑中的 name/enabled/block_page_id 可能与服务端快照不同）；
// blockPageId/blockStatusCode 用于拦截页归因提示（配置不一致/空页预告，与后端
// caddy.go 按触发策略归因口径一致——哪条策略触发的拦截就显示哪条策略的拦截页）。
const buildDisplayChain = (caddyId: string): ChainEntry[] => {
  const existing = (securityBindings.value[caddyId] || [])
    .filter((b) => b.policy_id !== editingId.value)
    .map((b): ChainEntry => ({ policyId: b.policy_id, name: b.name, enabled: b.enabled, isSelf: false, blockPageId: b.block_page_id, blockStatusCode: b.block_status_code }))
  const self: ChainEntry = { policyId: editingId.value, name: form.value.name || '本策略', enabled: form.value.enabled, isSelf: true, blockPageId: form.value.block_page_id, blockStatusCode: form.value.block_status_code }
  const all = [...existing, self]
  // 绑定链显示顺序严格按处理流程（任务 7）：阶段 0（信任，最高优先）→ 阶段 1（IP ACL）
  // → 阶段 2（限流）→ 阶段 3（WAF）→ mixed；同阶段内按 policy_id ASC
  const rankOf = (entry: ChainEntry): number => {
    const type = entry.isSelf
      ? editorPolicyType.value
      : (() => { const p = policies.value.find((sp) => sp.id === entry.policyId); return p ? policyTypeOf(p) : 'stage3' })()
    return type === 'stage0' ? 0 : type === 'stage1' ? 1 : type === 'stage2' ? 2 : type === 'stage3' ? 3 : 4
  }
  all.sort((a, b) => rankOf(a) - rankOf(b) || (a.policyId ?? Number.MAX_SAFE_INTEGER) - (b.policyId ?? Number.MAX_SAFE_INTEGER))
  return all
}

// 选择器单条规则元信息：绑定链、本策略落点（1-based）、不可选原因（空串=可选）。
// 判据与后端 bulk 校验同源（冲突整批 400，故必须在选择阶段就置灰）：
// ①阶段 2（限流）策略 → 该规则已绑定其它限流策略（每规则仅一条，与
// SecurityBindingEditor.pickerBlockReason 同源谓词）；②每规则绑定条数上限。
// 本策略已在绑定中的规则重选不新增绑定，恒可选。
const pickerMeta = (caddyId: string): { chain: ChainEntry[]; selfPos: number; blockReason: string } => {
  const existing = securityBindings.value[caddyId] || []
  const selfBound = editingId.value !== null && existing.some((b) => b.policy_id === editingId.value)
  const chain = buildDisplayChain(caddyId)
  let blockReason = ''
  if (!selfBound) {
    if (editorPolicyType.value === 'stage2'
      && hasOtherStage2Binding(existing, editingId.value, (id) => policyTypeById.value.get(id))) {
      blockReason = '该规则已绑定其它限流策略（每规则仅一条），需先解绑'
    } else if (existing.length >= MAX_POLICIES_PER_RULE) {
      blockReason = `已达 ${MAX_POLICIES_PER_RULE} 条绑定上限，无法继续绑定`
    }
  }
  return { chain, selfPos: chain.findIndex((e) => e.isSelf) + 1, blockReason }
}

// 冲突检测视图：仅启用策略参与（禁用策略不生成配置）；
// 服务端快照中本策略的条目被移除，以表单实时值替代
interface ConflictPolicyView {
  id: number | null
  name: string
  enabled: boolean
  mode: string
  ipAclEnabled: boolean
  ipAclMode: string
  policyType: SecurityPolicyType
  trustDetection: boolean
  crsGroups: string[]
  customRefs: CustomRuleRef[]
  ipAclAllowEntries: string[]
  ipTrustEntries: string[]
  ipDenyEntries: string[]
}

const buildConflictChain = (caddyId: string): ConflictPolicyView[] => {
  const serverPolicies = (ruleBoundPolicies.value[caddyId] || [])
    .filter((p) => p.id !== editingId.value)
    .map((p): ConflictPolicyView => {
      // /security/rules/:id/policy 不携带 IP 名单——按 id 回联策略列表快照
      //（PolicySummary 含 ip_acl_list/ip_whitelist/ip_blacklist）
      const summary = policies.value.find((sp) => sp.id === p.id)
      const sides = summary
        ? ipAclSideEntries(
          summary.ip_acl_mode,
          summary.ip_acl_enabled,
          mergeIpEntries(parseIPList(summary.ip_acl_list), parseRefIds(summary.ip_acl_list_refs)),
          mergeIpEntries(parseIPList(summary.ip_whitelist), parseRefIds(summary.ip_whitelist_refs)),
          parseIPList(summary.ip_blacklist),
          summary.ip_whitelist_enabled !== false,
        )
        : { aclAllow: [] as string[], trust: [] as string[], deny: [] as string[] }
      return {
        id: p.id,
        name: p.name,
        enabled: p.enabled,
        mode: p.mode,
        ipAclEnabled: p.ip_acl_enabled,
        ipAclMode: p.ip_acl_mode,
        policyType: summary ? policyTypeOf(summary) : 'stage3',
        trustDetection: summary?.trust_detection === true,
        crsGroups: normalizeCrsGroups(parseUnknownStrings(p.crs_rule_groups)),
        customRefs: parseCustomRuleRefs(p.custom_rules),
        ipAclAllowEntries: sides.aclAllow,
        ipTrustEntries: sides.trust,
        ipDenyEntries: sides.deny,
      }
    })
  const selfSides = selfIpAclSides.value
  const self: ConflictPolicyView = {
    id: editingId.value,
    name: form.value.name || '本策略',
    enabled: form.value.enabled,
    mode: form.value.mode,
    ipAclEnabled: form.value.ip_acl_enabled,
    ipAclMode: form.value.ip_acl_mode,
    policyType: editorPolicyType.value,
    trustDetection: form.value.trust_detection,
    crsGroups: crsRuleGroups.value,
    customRefs: selectedCustomRules.value.map((id) => ({ id, action: customRuleActionOf(id) })),
    ipAclAllowEntries: selfSides.aclAllow,
    ipTrustEntries: selfSides.trust,
    ipDenyEntries: selfSides.deny,
  }
  const all = [...serverPolicies, self]
  all.sort((a, b) => (a.id ?? Number.MAX_SAFE_INTEGER) - (b.id ?? Number.MAX_SAFE_INTEGER))
  return all
}

// 五类绑定冲突提示（client-side 计算，规则完整绑定链 = 现有 + 本策略）：
// (1) 绑定策略间 CRS 规则组重叠；(2) 免检测/白名单型策略夹在拦截策略中间；
// (3) 前位策略含放行型自定义规则 vs 后位策略含拦截型；(4) 自定义规则 ID 跨策略重复；
// (5) 地址级允许×拒绝冲突（一侧允许/信任名单条目出现在另一侧黑名单中）
const computeBindingConflicts = (chain: ConflictPolicyView[]): string[] => {
  const hints: string[] = []
  const active = chain.filter((p) => p.enabled)
  if (active.length < 2) return hints

  // (1) CRS 规则组重叠：空数组 = 加载全部规则 → 与任何选择重叠；仅 CRS 生效模式(blocking/detection)加载 CRS(2026-09-09 四态化)
  const wafActive = active.filter((p) => p.mode === 'blocking' || p.mode === 'detection')
  for (let i = 0; i < wafActive.length; i++) {
    for (let j = i + 1; j < wafActive.length; j++) {
      const a = wafActive[i]
      const b = wafActive[j]
      if (!a || !b) continue
      let overlap: string[]
      if (a.crsGroups.length === 0 && b.crsGroups.length === 0) overlap = ['全部规则组']
      else if (a.crsGroups.length === 0) overlap = b.crsGroups
      else if (b.crsGroups.length === 0) overlap = a.crsGroups
      else overlap = a.crsGroups.filter((g) => b.crsGroups.includes(g))
      if (overlap.length > 0) {
        const shown = overlap.slice(0, 3).join('、')
        hints.push(`「${a.name}」与「${b.name}」加载了相同的 CRS 规则组（${shown}${overlap.length > 3 ? ' 等' : ''}），同一请求将被重复检测，建议只保留一个`)
      }
    }
  }

  // (2) 免检测/白名单型策略夹在拦截型策略中间：免检测/白名单仅作用于自身引擎，
  // 不会为前后策略放行流量（各策略引擎独立判定、互不影响），位置安排不影响拦截效果
  const isBlocking = (p: ConflictPolicyView): boolean => p.mode === 'blocking'
  const isBypassLike = (p: ConflictPolicyView): boolean => p.ipAclEnabled && (p.ipAclMode === '绕过' || p.ipAclMode === 'allow')
  active.forEach((p, i) => {
    if (!isBypassLike(p)) return
    const hasBlockingBefore = active.slice(0, i).some(isBlocking)
    const hasBlockingAfter = active.slice(i + 1).some(isBlocking)
    if (hasBlockingBefore && hasBlockingAfter) {
      hints.push(`「${p.name}」为${p.ipAclMode === '绕过' ? '免检测' : '白名单'}模式且夹在拦截策略中间：免检测/白名单仅作用于自身引擎，不会为前后策略放行流量，各策略引擎独立判定、位置不影响拦截效果；如需对特定来源整体放行，请使用免检测名单`)
    }
  })

  // (3) 前位策略含放行型（pass）自定义规则，后位策略含拦截型（block）：pass 不阻断请求、
  // 仅跳过本策略引擎内的匹配，后位拦截不受影响；顺序上真正需注意的是前位拦截策略
  // 一旦命中即中断整条链，后位策略只处理前位放行的流量
  const hasAllowRule = (p: ConflictPolicyView): boolean => p.customRefs.some((r) => r.action === 'pass')
  const hasDenyRule = (p: ConflictPolicyView): boolean => p.customRefs.some((r) => r.action === 'block')
  for (let i = 0; i < active.length; i++) {
    const earlier = active[i]
    if (!earlier || !hasAllowRule(earlier)) continue
    for (let j = i + 1; j < active.length; j++) {
      const later = active[j]
      if (!later || !hasDenyRule(later)) continue
      hints.push(`「${earlier.name}」的放行型自定义规则仅在本策略引擎内跳过匹配、不阻断请求，「${later.name}」的拦截型规则仍会独立执行；需注意前位拦截策略一旦命中将中断整条链，后位策略只处理前位放行的流量`)
      break
    }
  }

  // (4) 自定义规则 ID 跨策略重复引用 → 同一请求重复计分/处理
  const idOwners = new Map<number, string[]>()
  active.forEach((p) => {
    const seen = new Set<number>()
    p.customRefs.forEach((r) => {
      if (seen.has(r.id)) return
      seen.add(r.id)
      const owners = idOwners.get(r.id) ?? []
      owners.push(p.name)
      idOwners.set(r.id, owners)
    })
  })
  idOwners.forEach((owners, ruleId) => {
    if (owners.length <= 1) return
    const ruleName = allCustomRules.value.find((r) => r.id === ruleId)?.name || `#${ruleId}`
    hints.push(`自定义规则「${ruleName}」被 ${owners.map((n) => `「${n}」`).join('、')} 重复引用，同一请求会被重复计分/处理，建议只保留一个`)
  })

  // (5) 地址级允许×拒绝提示：ACL/存量信任只豁免所属策略；阶段 0 信任
  // 则按直通或保留检测模式跨策略优先。与 WAF/IP 步骤实时警告同源
  //（ipAclSideEntries），仅精确字符串匹配，不展开 CIDR 包含关系。
  // 万级名单下 includes 扫描是 O(A×D)，先为每个策略建 Set 再求交。
  const denySets = active.map((p) => new Set(p.ipDenyEntries))
  for (let i = 0; i < active.length; i++) {
    for (let j = 0; j < active.length; j++) {
      if (i === j) continue
      const allowSide = active[i]
      const denySide = active[j]
      if (!allowSide || !denySide) continue
      const aclOverlap = entriesIntersect(allowSide.ipAclAllowEntries, denySets[j] ?? new Set())
      if (aclOverlap.length > 0) {
        const shown = aclOverlap.slice(0, 2).join('、')
        hints.push(`地址 ${shown}${aclOverlap.length > 2 ? ' 等' : ''} 在「${allowSide.name}」的访问控制名单中、同时在「${denySide.name}」的黑名单中——${addressAllowDenyConflictText({ kind: 'acl', denyPolicyName: denySide.name })}`)
      }
      const trustOverlap = entriesIntersect(allowSide.ipTrustEntries, denySets[j] ?? new Set())
      if (trustOverlap.length > 0) {
        const shown = trustOverlap.slice(0, 2).join('、')
        hints.push(`地址 ${shown}${trustOverlap.length > 2 ? ' 等' : ''} 在「${allowSide.name}」的信任名单中、同时在「${denySide.name}」的黑名单中——${addressAllowDenyConflictText({ kind: 'trust', policyType: allowSide.policyType, trustDetection: allowSide.trustDetection, denyPolicyName: denySide.name })}`)
      }
    }
  }

  return hints
}

// ================= 跨策略重复/冲突的实时步骤内警告（WAF/IP 步骤） =================
// 与 Step 4 computeBindingConflicts 同源语义，但比较范围不同：
// - 比较集合 = 与本策略当前绑定上下文（boundRules，编辑时含服务端既有绑定）共享
//   ≥1 条规则的其他启用策略（与 buildDisplayChain/pickerMeta 同数据源 securityBindings）；
// - 若该集合为空（新建未选规则），退化为全部其他启用策略，文案用「若绑定同一规则」。
// 数据源：策略列表接口（policies）——列表已携带 crs_rule_groups 与全部 IP 名单字段，
// 直接由 policies.value 同步派生（computed），随列表刷新自动更新，无逐策略详情 GET。

interface PeerPolicyView { id: number; name: string; mode: string; policyType: SecurityPolicyType; trustDetection: boolean; crsGroups: string[]; aclAllowSet: ReadonlySet<string>; trustSet: ReadonlySet<string>; denySet: ReadonlySet<string> }
// 响应式依赖只有策略列表与引用名单条目镜像（ipListEntries 仅在缓存确有新增时
// 重建）——编辑态输入（ipACLList/ipWhitelist/ipBlacklistSelf/form）不在依赖
// 面内，故并集与 Set 只在策略或条目镜像变化时重建，不随名单增删重算；实时
// 警告随输入重算的部分仅是本策略侧条目与已建 Set 的求交（O(本策略条目)）。
// 新增编辑输入依赖会让 N 个启用策略 × 万级条目在每次增删时全量重跑。
const peerPolicyViews = computed<PeerPolicyView[]>(() =>
  policies.value
    .filter((p) => p.enabled && p.id !== editingId.value)
    .map((p) => {
      // 对端名单同样采用合并口径（内联 ∪ 引用列表条目）；引用列表缓存缺失时
      // mergeIpEntries 跳过该 id，防御性回退为仅内联
      const sides = ipAclSideEntries(
        p.ip_acl_mode,
        p.ip_acl_enabled,
        mergeIpEntries(parseIPList(p.ip_acl_list), parseRefIds(p.ip_acl_list_refs)),
        mergeIpEntries(parseIPList(p.ip_whitelist), parseRefIds(p.ip_whitelist_refs)),
        parseIPList(p.ip_blacklist),
        p.ip_whitelist_enabled !== false,
      )
      // 预建 Set——实时警告随输入逐字符重算，不得每次对万级名单做 includes。
      return { id: p.id, name: p.name, mode: p.mode, policyType: policyTypeOf(p), trustDetection: p.trust_detection === true, crsGroups: normalizeCrsGroups(parseUnknownStrings(p.crs_rule_groups)), aclAllowSet: new Set(sides.aclAllow), trustSet: new Set(sides.trust), denySet: new Set(sides.deny) }
    }),
)

// 与本策略共享 ≥1 条绑定规则的其他策略 ID（含禁用；禁用策略在比较时被过滤，
// 与 computeBindingConflicts 的 active 口径一致）
const coBoundPeerIds = computed<Set<number>>(() => {
  const ids = new Set<number>()
  for (const caddyId of boundRules.value) {
    for (const b of securityBindings.value[caddyId] || []) {
      if (b.policy_id !== editingId.value) ids.add(b.policy_id)
    }
  }
  return ids
})

const comparisonContext = computed<{ peers: PeerPolicyView[]; coBound: boolean }>(() => {
  const coIds = coBoundPeerIds.value
  const coPeers = peerPolicyViews.value.filter((p) => coIds.has(p.id))
  if (coPeers.length > 0) return { peers: coPeers, coBound: true }
  // 有共绑策略但均已禁用 → 不产生警告（同 active 口径）
  if (coIds.size > 0) return { peers: [], coBound: true }
  return { peers: peerPolicyViews.value, coBound: false }
})

// WAF 步骤：CRS 规则组与其他策略重复的实时警告。空数组 = 加载全部规则组
//（与 computeBindingConflicts 同语义），随当前选择实时重算——修复「有时候不显示」。
const wafStepCrsAlert = computed<string>(() => {
  if (form.value.mode !== 'blocking' && form.value.mode !== 'detection') return ''
  const { peers, coBound } = comparisonContext.value
  const selfGroups = crsRuleGroups.value
  const dups: Array<{ name: string; overlap: string[] }> = []
  for (const peer of peers) {
    if (peer.mode !== 'blocking' && peer.mode !== 'detection') continue
    let overlap: string[]
    if (selfGroups.length === 0 && peer.crsGroups.length === 0) overlap = ['全部规则组']
    else if (selfGroups.length === 0) overlap = peer.crsGroups
    else if (peer.crsGroups.length === 0) overlap = selfGroups
    else overlap = selfGroups.filter((g) => peer.crsGroups.includes(g))
    if (overlap.length > 0) dups.push({ name: peer.name, overlap })
  }
  if (dups.length === 0) return ''
  const names = dups.slice(0, 2).map((d) => `「${d.name}」`).join('、') + (dups.length > 2 ? ` 等 ${dups.length} 条` : '')
  let overlapUnion = [...new Set(dups.flatMap((d) => d.overlap))]
  if (overlapUnion.includes('全部规则组')) overlapUnion = ['全部规则组']
  const overlapShown = overlapUnion.slice(0, 3).join('、') + (overlapUnion.length > 3 ? ' 等' : '')
  return coBound
    ? `${names}已选择相同的 CRS 规则组（${overlapShown}），绑定到同一规则时将被重复检测，建议只保留一个`
    : `${names}也选择了相同的 CRS 规则组（${overlapShown}），若二者绑定同一规则将重复检测`
})

// IP 步骤：允许/信任名单 × 黑名单的地址级提示按真实生效范围分流——
// ACL/存量信任仅属策略本地，阶段 0 信任跨策略直通或保留检测。
// 按「本策略条目来源」拆到所属分区展示，避免无论冲突条目在哪都堆到信任名单下：
// - aclSectionAlert（访问控制区）：ACL 列表（允许侧=allow/绕过、拒绝侧=deny）
//   + ip_blacklist（服务端加载、本向导不编辑，语义属拒绝侧 → 归访问控制区）；
// - whitelistSectionAlert（信任名单区）：ip_whitelist（允许侧）。
// 名单生效口径与保存语义对齐：ip_whitelist 随保存下发且受 ip_whitelist_enabled
// 三态门应用——**门控在 computed 内**（信任关闭 = 条目零生效，与引擎发射门 /
// ipAclSideEntries 同源），不参与跨策略冲突比较；阶段 0 恒启用（与保存载荷
// trustEnabledForPolicyType 同源——新建阶段 0 时 ipWhitelistEnabled 初值 false
// 且无开关控件，按开关判断会漏掉恒启用信任条目的跨策略冲突）；模板只渲染结果，
// 不做二次判断。若把门挪到显示层，关闭态会误报「本策略信任 X 却在被拦截」的伪冲突。
// ip_acl_list 仅 ip_acl_enabled 时生效（同 ipAclSideEntries）；ip_blacklist 非空
// 即生效（无开关，但其警告随访问控制区显示，显示门控 form.ip_acl_enabled）。
// v1 仅精确字符串匹配，不展开 CIDR 包含。
// 冲突条目来源标注：内联直接命中不标注；仅经引用列表带入的条目标注列表名，
// 消除「地址不在访问控制名单（内联）却报冲突」的观感矛盾——引用即生效
const entrySourceSuffix = (entry: string, inline: string[], refs: number[]): string => {
  if (inline.includes(entry)) return ''
  const names = refs
    .filter((id) => (ipListEntries.value[id] || []).some((e) => e.trim() === entry))
    .map((id) => `「${ipLists.value.find((l) => l.id === id)?.name ?? `#${id}`}」`)
  return names.length > 0 ? `（来自引用列表${names.join('、')}）` : ''
}

const aclSectionAlert = computed<string>(() => {
  const { peers, coBound } = comparisonContext.value
  const aclEnabled = form.value.ip_acl_enabled
  // 本策略条目采用合并口径（内联 ∪ 引用列表），对端 peers 已在 peerPolicyViews 合并
  const mergedAcl = mergeIpEntries(ipACLList.value, ipACLListRefs.value)
  const aclAllow = aclEnabled && (form.value.ip_acl_mode === 'allow' || form.value.ip_acl_mode === '绕过') ? mergedAcl : []
  const aclDeny = aclEnabled && form.value.ip_acl_mode === 'deny' ? mergedAcl : []
  // 同一条目同时出现在 ACL 拒绝列表与黑名单时只按 ACL 列表口径报一次（黑名单
  // 在本向导不可见，避免同地址两条仅名单名不同的重复提示）
  const blacklist = mergeIpEntryValues(ipBlacklistSelf.value, []).filter((e) => !aclDeny.includes(e))
  if (aclAllow.length === 0 && aclDeny.length === 0 && blacklist.length === 0) return ''
  // 与 CRS 告警同口径：共绑 = 确定性冲突（当下就拦截）；非共绑 = 假设性提示
  //（仅当未来绑定同一规则才成立）
  const suffix = coBound ? '' : '（若两策略绑定同一规则）'
  const items: string[] = []
  for (const peer of peers) {
    for (const entry of entriesIntersect(aclAllow, peer.denySet)) {
      items.push(`地址 ${entry} 在「本策略」的访问控制名单中、同时在「${peer.name}」的黑名单中——${addressAllowDenyConflictText({ kind: 'acl', denyPolicyName: peer.name })}${suffix}`)
    }
    for (const entry of entriesIntersect(aclDeny, peer.aclAllowSet)) {
      items.push(`地址 ${entry} 在「本策略」的访问控制名单中${entrySourceSuffix(entry, ipACLList.value, ipACLListRefs.value)}、同时在「${peer.name}」的访问控制允许名单中——${addressAllowDenyConflictText({ kind: 'acl', denyPolicyName: '本策略' })}${suffix}`)
    }
    for (const entry of entriesIntersect(aclDeny, peer.trustSet)) {
      items.push(`地址 ${entry} 在「本策略」的访问控制名单中${entrySourceSuffix(entry, ipACLList.value, ipACLListRefs.value)}、同时在「${peer.name}」的信任名单中——${addressAllowDenyConflictText({ kind: 'trust', policyType: peer.policyType, trustDetection: peer.trustDetection, denyPolicyName: '本策略' })}${suffix}`)
    }
    for (const entry of entriesIntersect(blacklist, peer.aclAllowSet)) {
      items.push(`地址 ${entry} 在「本策略」的黑名单中、同时在「${peer.name}」的访问控制允许名单中——${addressAllowDenyConflictText({ kind: 'acl', denyPolicyName: '本策略' })}${suffix}`)
    }
    for (const entry of entriesIntersect(blacklist, peer.trustSet)) {
      items.push(`地址 ${entry} 在「本策略」的黑名单中、同时在「${peer.name}」的信任名单中——${addressAllowDenyConflictText({ kind: 'trust', policyType: peer.policyType, trustDetection: peer.trustDetection, denyPolicyName: '本策略' })}${suffix}`)
    }
  }
  if (items.length === 0) return ''
  return items.slice(0, 2).join('；') + (items.length > 2 ? `；共 ${items.length} 条类似冲突` : '')
})

const whitelistSectionAlert = computed<string>(() => {
  const { peers, coBound } = comparisonContext.value
  // 信任名单同样合并引用列表条目后与对端比较
  // 三态：信任关闭零生效（与后端发射门同口径），不参与跨策略冲突比较；
  // 阶段 0 恒启用（与保存载荷 trustEnabledForPolicyType 同源）
  const trust = trustEnabledInEditor.value ? mergeIpEntries(ipWhitelist.value, ipWhitelistRefs.value) : []
  if (trust.length === 0) return ''
  const suffix = coBound ? '' : '（若两策略绑定同一规则）'
  const items: string[] = []
  for (const peer of peers) {
    for (const entry of entriesIntersect(trust, peer.denySet)) {
      items.push(`地址 ${entry} 在「本策略」的信任名单中${entrySourceSuffix(entry, ipWhitelist.value, ipWhitelistRefs.value)}、同时在「${peer.name}」的黑名单中——${addressAllowDenyConflictText({ kind: 'trust', policyType: editorPolicyType.value, trustDetection: form.value.trust_detection, denyPolicyName: peer.name })}${suffix}`)
    }
  }
  if (items.length === 0) return ''
  return items.slice(0, 2).join('；') + (items.length > 2 ? `；共 ${items.length} 条类似冲突` : '')
})

// 拦截页归因（哪条策略触发的拦截就显示哪条策略的拦截页）的两类可静态检测提示：
// ② 空页预告（warn）——策略配置了拦截页但页已删除/内容为空（后端等同无页，
// 该策略 deny 不抬码，中断落首绑定有页策略的 403 兜底路由）。
// 拦截页列表未成功落地过一次时不得判定「已删除/内容为空」——bpRes
// 部分失败会让所有启用策略挂上假警告；加载门在单源谓词内（blockPageMissing）。
const blockPageBroken = (e: ChainEntry): boolean =>
  blockPageMissing(e.blockPageId ?? 0, blockPages.value, blockPagesLoaded.value)

// 本策略拦截页「按阶段实际生效」判定——单源走 resolveBlockPageAttribution
// （与 caddy.go 的阶段 1 首绑定有页/阶段 2 429 首绑定有页/阶段 3 逐策略合成码
// 逐条对齐）。旧实现 `enabled && block_page_id>0` 恒渲染绿色「生效中」，多策略
// 绑定或规则级覆盖在场时是假绿。
const BLOCK_PAGE_STAGE_LABEL: Record<BlockPageStage, string> = { 1: '阶段 1', 2: '阶段 2', 3: '阶段 3' }
const pageHasContent = (id: number): boolean =>
  blockPagesLoaded.value && id > 0 && !blockPageMissing(id, blockPages.value, blockPagesLoaded.value)
const editorBlockPageStages = (): BlockPageStage[] => {
  const type = editorPolicyType.value
  if (type === 'stage1') return [1]
  if (type === 'stage2') return [2]
  if (type === 'stage3') return [3]
  if (type === 'mixed') return [1, 2, 3]
  return [] // stage0 无拦截页概念
}
const inactiveReason = (a: BlockPageAttribution): string => {
  if (a.effective === 'rule-override') return '规则已配置阶段页覆盖，实际显示规则级页面'
  if (a.effective === 'peer') return `实际显示绑定链首位有页策略「${a.winnerName ?? '其他策略'}」的页面`
  if (a.stage === 2) return '没有启用限流的策略，不会产生 429'
  return '绑定链无其他有效拦截页，拦截回落 Caddy 默认响应'
}
const blockPageNotes = (caddyId: string, chain: ChainEntry[]): BlockPageNote[] => {
  // 类型门先行：阶段 0 策略没有拦截页概念（向导无该步骤、后端归一
  // block_page_id=0）——不得为其渲染「未选择自定义页面」等任何页面提示。
  // 旧顺序先判 block_page_id<=0，stage0 永远命中该分支，类型门不可达。
  const stages = editorBlockPageStages()
  if (stages.length === 0) return []
  if (!form.value.enabled) return [{ kind: 'disabled', text: '策略禁用中，拦截页面不生效' }]
  const type = editorPolicyType.value
  if (form.value.block_page_id <= 0) {
    return [{ kind: 'info', text: type === 'stage2'
      ? '未选择自定义页面：限流拦截返回空响应体 429'
      : '未选择自定义页面：拦截返回 Caddy 默认 403（规则级阶段 1/3 覆盖除外）' }]
  }
  // 页面列表未落地：不做任何生效判定（不得假设页面存在或已删除）
  if (!blockPagesLoaded.value) {
    return [{ kind: 'info', text: '拦截页列表未加载成功，无法判定本策略页面是否实际生效' }]
  }
  const notes: BlockPageNote[] = []
  if (!pageHasContent(form.value.block_page_id)) {
    notes.push({ kind: 'warning', text: '本策略拦截页已失效（页面已删除或内容为空）——保存前请重新选择' })
  }
  const overrideFor = (stage: 1 | 3): { pageId: number; pageHasContent: boolean } | null => {
    // 与「关联规则」步骤、保存载荷共用同一暂存视图（seed=库值 + 本会话编辑）：
    // 只读库值会让同一次会话里两步给出相反结论（关联规则显示「待保存」，本步
    // 仍按已保存配置说「规则已配置阶段页覆盖」）。
    const edit = overrideEditOf(caddyId)
    const pageId = (stage === 1 ? edit.stage1_id : edit.stage3_id) ?? 0
    return pageId > 0 ? { pageId, pageHasContent: pageHasContent(pageId) } : null
  }
  const input = chain.map((e) => ({
    policyId: e.policyId,
    name: e.name,
    enabled: e.enabled,
    isSelf: e.isSelf,
    blockPageId: e.blockPageId ?? 0,
    pageHasContent: pageHasContent(e.blockPageId ?? 0),
    // 列表摘要无 rate_limit_enabled 原始字段——has_rate_limit 即「启用且 rps>0」
    // （后端同一判定），用于阶段 2 是否可能产生 429 的门。
    rateLimitEnabled: e.isSelf
      ? form.value.rate_limit_enabled
      : (policies.value.find((p) => p.id === e.policyId)?.has_rate_limit ?? false),
  }))
  const results = stages.map((stage) =>
    resolveBlockPageAttribution(stage, input, stage === 2 ? null : overrideFor(stage as 1 | 3)))
  // 能力门：归因只判「页有效 + 绑定链位置」，不看该阶段是否真的会拦截——
  // stage3 默认 off、stage1 无 ACL/地域/黑名单时页面永不显示。不过门会与同页
  // 「WAF 关闭」「未启用 ACL」的摘要自相矛盾。
  const hasBlockingCustomRule = selectedCustomRules.value.some((id) => {
    const rule = allCustomRules.value.find((r) => r.id === id)
    return !!rule && customRuleCanBlockInMode(form.value.mode, rule)
  })
  const stageCapable = (stage: BlockPageStage): boolean => blockPageStageCanIntercept({
    stage,
    mode: form.value.mode,
    hasBlockingCustomRule,
    hasAclEntries: form.value.ip_acl_enabled && form.value.ip_acl_mode !== '绕过' && aclMergedCount.value > 0,
    hasBlacklistEntries: ipBlacklistSelf.value.length > 0,
    hasGeoip: form.value.geoip_enabled && geoipCountries.value.length > 0,
  })
  const capableResults = results.filter((r) => stageCapable(r.stage))
  const active = capableResults.filter((r) => r.effective === 'self').map((r) => r.stage)
  if (active.length > 0) {
    // 阶段 2 的 429 归因与触发策略无关（绑定链任一启用限流策略产生），
    // 不得沿用「触发本策略拦截时显示」。
    const parts = active.map((s) => s === 2
      ? '阶段 2：429 由绑定链任一启用限流策略产生时显示'
      : `${BLOCK_PAGE_STAGE_LABEL[s]} 触发本策略拦截时显示`)
    notes.push({ kind: 'active', text: `✓ 拦截页面生效中（${parts.join('；')}）` })
  }
  for (const r of capableResults.filter((x) => x.effective !== 'self')) {
    notes.push({ kind: 'warning', text: `${BLOCK_PAGE_STAGE_LABEL[r.stage]}：${inactiveReason(r)}` })
  }
  for (const r of results.filter((x) => !stageCapable(x.stage))) {
    notes.push({ kind: 'warning', text: `${BLOCK_PAGE_STAGE_LABEL[r.stage]}：当前配置不会产生该阶段拦截，页面不会被使用` })
  }
  return notes
}

// Step 4 已关联规则的逐条视图：绑定链 + 拦截页面生效标注 + 冲突提示
const boundRuleRows = computed<BoundRuleRow[]>(() => boundRules.value.map((caddyId) => {
  const rule = allRules.value.find((r) => r.caddy_id === caddyId)
  const chain = buildDisplayChain(caddyId)
  const enabledEntries = chain.filter((e) => e.enabled)
  // ② 空页预告（warn 级，与冲突提示同管线）
  const emptyPageHints = enabledEntries
    .filter((e) => blockPageBroken(e))
    .map((e) => `策略「${e.name}」配置的拦截页面已删除或内容为空，该策略拦截时将显示首位策略的拦截页`)
  // ① 配置不一致提示（info 级）：启用策略间 (拦截页, 状态码) 组合不一致——
  // 非错误，声明归因语义（与渲染层逐阶段对齐：阶段 3 逐策略，阶段 1/2 首位有页）
  const combos = new Set(enabledEntries.map((e) => `${e.blockPageId ?? 0}:${e.blockStatusCode || 403}`))
  const infoHints: string[] = []
  if (enabledEntries.length > 1 && combos.size > 1) {
    infoHints.push('这些策略的拦截页/状态码不同——阶段 3（WAF）按实际触发的策略显示，阶段 1/2 由绑定链首位有页策略显示')
  }
  return {
    caddyId,
    name: rule?.name || caddyId,
    domain: rule?.domain || '',
    listenPort: rule?.listen_port ?? 0,
    chain,
    blockPageNotes: blockPageNotes(caddyId, chain),
    // 性能提示应按实际生效的处理链计——禁用策略不产生处理链，
    // 计入会虚高（提示"超过 3 条可能影响性能"在不达 3 条时误报）。
    mergedCount: enabledEntries.length,
    showPerfTip: enabledEntries.length > PERF_POLICY_THRESHOLD,
    hints: [...computeBindingConflicts(buildConflictChain(caddyId)), ...emptyPageHints],
    infoHints,
  }
}))

// 配置预览 = 三阶段投影（策略视角）：以「本策略为唯一绑定」构造模型——
// 与规则侧流程抽屉共用 buildStageModel 同一投影；阶段外字段按类型裁剪（与服务端
// 显式 policy_type 提交时的归一零值同口径，预览即所得）
const previewModel = computed<RuleStageModel>(() => {
  const previewPolicy: SecurityStagePolicy = {
    id: editingId.value ?? 0,
    name: form.value.name || '本策略',
    // 类型随投影下发：信任模式/阶段能力判定按类型区分（非阶段 0 恒保留检测）
    policy_type: editorPolicyType.value,
    mode: typeAllowsStage(3) ? form.value.mode : 'off',
    enabled: form.value.enabled,
    // 阶段 1 不再承载信任名单（阶段 0 独立）；has_ip_control 只计 ACL 与黑名单
    // 原始字段必须随投影一并下发：buildStage1Rows 的 hasIPACLControl 在字段齐备时
    // 走「ACL 启用 ∧ 内联∪引用非空」定义判定，缺 ip_acl_enabled 会把引用了名单的
    // 策略误判为未启用（预览阶段 1 恒灰）。
    ip_acl_enabled: typeAllowsStage(1) && form.value.ip_acl_enabled,
    // 阶段 0 信任名单恒启用（与保存侧 buildPolicyPayload 的
    // trustEnabledForPolicyType 同口径）；其余类型按开关三态
    ip_whitelist_enabled: trustEnabledInEditor.value,
    block_page_id: typeAllowsStage(1) ? form.value.block_page_id : 0,
    block_status_code: form.value.block_status_code,
    has_ip_control: typeAllowsStage(1) && ((form.value.ip_acl_enabled && aclMergedCount.value > 0) || ipBlacklistSelf.value.length > 0),
    has_rate_limit: typeAllowsStage(2) && form.value.rate_limit_enabled && form.value.rate_limit_rps > 0,
    has_geoip: typeAllowsStage(1) && form.value.geoip_enabled && geoipCountries.value.length > 0,
    has_custom_rules: typeAllowsStage(3) && selectedCustomRules.value.length > 0,
    geoip_countries: JSON.stringify(typeAllowsStage(1) ? geoipCountries.value : []),
    custom_rules_count: typeAllowsStage(3) ? selectedCustomRules.value.length : 0,
    ip_acl_mode: form.value.ip_acl_mode,
    ip_acl_list: JSON.stringify(ipACLList.value),
    ip_whitelist: JSON.stringify(ipWhitelist.value),
    rate_limit_rps: form.value.rate_limit_rps,
    rate_limit_burst: form.value.rate_limit_burst,
    ip_blacklist: JSON.stringify(ipBlacklistSelf.value),
    ip_acl_list_refs: JSON.stringify(ipACLListRefs.value),
    ip_whitelist_refs: JSON.stringify(ipWhitelistRefs.value),
    geoip_mode: form.value.geoip_enabled ? form.value.geoip_mode : 'off',
    geoip_crawler_exempt: form.value.geoip_enabled && form.value.geoip_crawler_exempt,
    geoip_crawler_engines: JSON.stringify(form.value.geoip_crawler_engines ?? []),
    trust_detection: form.value.trust_detection,
  }
  // stage2 也投影策略页（可配拦截页的只读视图补呈现；stage0 无拦截页概念）
  const showBlockPage = editorPolicyType.value !== 'stage0'
  return buildStageModel(
    [{
      policy_id: previewPolicy.id,
      name: previewPolicy.name,
      mode: previewPolicy.mode,
      enabled: form.value.enabled,
      rate_limit_enabled: previewPolicy.has_rate_limit,
      block_page_id: showBlockPage ? form.value.block_page_id : 0,
      block_status_code: form.value.block_status_code,
    }],
    [previewPolicy],
    ipLists.value,
    blockPages.value,
    null,
  )
})

// 配置预览阶段裁剪（任务 F）：分类策略只显示本类型阶段的分组内容（不再出现其他阶段的
// 「未启用」灰条）；mixed 才显示全阶段
const previewVisibleStages = computed(() => {
  const type = editorPolicyType.value
  if (type === 'mixed') return previewModel.value.stages
  const stageNo: 0 | 1 | 2 | 3 = type === 'stage0' ? 0 : type === 'stage1' ? 1 : type === 'stage2' ? 2 : 3
  return previewModel.value.stages.filter((s) => s.stage === stageNo)
})

const openRulePicker = (): void => {
  pickerSelected.value = [...boundRules.value]
  pickerSearch.value = ''
  pickerPage.value = 1
  rulePickerVisible.value = true
}

const confirmRulePicker = (): void => {
  boundRules.value = [...pickerSelected.value]
  rulePickerVisible.value = false
  // 新选中的规则需要绑定明细来计算冲突提示（步骤内已选中规则由 watch 覆盖）
  void ensureBindingDetails(boundRules.value)
}

const removeBoundRule = (caddyId: string): void => {
  boundRules.value = boundRules.value.filter((id) => id !== caddyId)
}

// —— 提取为地址列表：内联名单一键转为可复用列表并改为引用 ——
const extractDialogVisible = ref(false)
const extractSide = ref<'acl' | 'trust'>('acl')
const extractForm = ref({ name: '', category: '' })
const extracting = ref(false)
const extractSourceEntries = computed<string[]>(() => (extractSide.value === 'acl' ? ipACLList.value : ipWhitelist.value))

const openExtractDialog = (side: 'acl' | 'trust'): void => {
  extractSide.value = side
  extractForm.value = { name: '', category: '' }
  extractDialogVisible.value = true
}

const confirmExtract = async (): Promise<void> => {
  if (extracting.value) return
  const name = extractForm.value.name.trim()
  if (!name) { ElMessage.warning('请输入列表名称'); return }
  if (name.length > 50) { ElMessage.warning('列表名称不能超过 50 字符'); return }
  if (extractForm.value.category.length > 32) { ElMessage.warning('分类不能超过 32 字符'); return }
  const sourceEntries = extractSourceEntries.value.map((value) => value.trim()).filter((value) => value !== '')
  if (sourceEntries.length === 0) { ElMessage.warning('内联名单为空，无需提取'); return }
  if (sourceEntries.length > 2000) { ElMessage.warning('每个列表最多 2000 条条目'); return }
  try {
    await ElMessageBox.confirm(`确定创建列表「${name}」（${sourceEntries.length} 条）并转为引用？内联条目将清空，拦截语义不变。`, '确认', { type: 'warning' })
  } catch { return }
  // 捕获对话框会话——在途 POST 落地时若用户已关窗并打开另一策略，
  // 续体不得把 A 的列表 id 写进 B 的表单（持久化损坏）。
  const openSeq = policyDialogOpenSeq
  extracting.value = true
  try {
    const res = await request.post<APIResponse<{ id: number }>>('/security/ip-lists', {
      name,
      description: '',
      category: extractForm.value.category.trim(),
      // entries 与其余名单字段同口径：JSON 数组文本（后端 Entries 为 string）
      entries: JSON.stringify(sourceEntries.map((value) => ({ value, remark: '从策略提取' }))),
    })
    const newId = res.data?.id
    if (!newId) throw new Error('创建列表响应缺少 id')
    // 会话已切换（关窗重开另一策略）时丢弃续体——refs/内联写入
    // 属于表单会话状态，落到新会话即持久化损坏。
    if (openSeq !== policyDialogOpenSeq) return
    // 交换语义：新建列表 → 追加到该侧 refs → 清空内联（合并生效集不变）；
    // 策略本身不在此保存——用户在向导中显式点「保存」才落库
    if (extractSide.value === 'acl') {
      ipACLListRefs.value = [...new Set([...ipACLListRefs.value, newId])]
      ipACLList.value = []
    } else {
      ipWhitelistRefs.value = [...new Set([...ipWhitelistRefs.value, newId])]
      ipWhitelist.value = []
    }
    extractDialogVisible.value = false
    // 刷新引用列表缓存：选择器选项与「合计 N 条」提示立即反映新列表
    await fetchIpLists(openSeq)
    showSaveResult(res as unknown as { message?: string }, `已创建列表「${name}」并转为引用，内联条目已清空（引用后语义不变），保存策略后生效`)
  } catch (error: unknown) {
    // 409 重名 / 400 条目非法已由全局拦截器 toast，这里仅记录避免 unhandled rejection
    console.error('Failed to extract IP list:', error)
  } finally { extracting.value = false }
}

// 拦截页列表按弹框打开刷新：判「页面已删除」必须用本次打开的权威快照。旧实现
// 直接拿页面加载时的 blockPages 判定——他端/API 在本页加载后新建的页面会被读成
// 「已删除」，并被静默改写成默认页（保存即落库，拦截响应体/状态码归因随之改变）。
// 返回 false = 本次未取得权威快照，调用方不得据此改写用户已绑定的页面。
const refreshBlockPages = async (openSeq: number): Promise<boolean> => {
  try {
    const res = await request.get<APIResponse<BlockPage[]>>('/security/block-pages', { silent: true })
    if (openSeq !== policyDialogOpenSeq) return false
    blockPages.value = res.data || []
    blockPagesLoaded.value = true
    return true
  } catch {
    return false
  }
}

async function openDialog(row?: PolicySummary) {
  // 对话框打开序列号（同 Rules.vue wizardOpenSeq 模式）——
  // 详情 GET 在途期间用户再点"新建策略"或另一行"编辑"，首个返回会覆盖
  // editingId/表单，把保存语义错位成 PUT 到错误策略。
  const openSeq = ++policyDialogOpenSeq
  // 引用名单条目不再按会话清空：取数走跨组件共享缓存（IP 地址列表的写入口
  // 已统一调用 invalidateSharedEntriesCache 使条目失效重拉），此处清空只会
  // 让向导重复下载同一批大名单。
  // 混合策略（兼容旧版）：「编辑」改为只读查看弹框——零可编辑字段，唯一操作=更新迁移
  if (row && policyTypeOf(row) === 'mixed') {
    await openViewDialog(row, openSeq)
    return
  }
  editingId.value = row?.id ?? null
  // 编辑态类型固定（行 policy_type 或内容推断）；新建态由 createPolicyType 驱动
  editingPolicyType.value = row ? policyTypeOf(row) : null
  if (row) {
    try {
      const [res, blockPagesFresh] = await Promise.all([
        request.get<APIResponse<{ policy: PolicyDetail; bindings: string[] }>>(`/security/policies/${row.id}`),
        refreshBlockPages(openSeq),
      ])
      if (openSeq !== policyDialogOpenSeq) return
      const d = res.data?.policy
      if (!d) throw new Error('策略详情响应缺少数据')
      form.value = {
        name: d.name,
        description: d.description,
        enabled: d.enabled,
        mode: d.mode,
        anomaly_threshold: d.anomaly_threshold,
        ip_acl_enabled: d.ip_acl_enabled,
        ip_acl_mode: d.ip_acl_mode ?? '',
        rate_limit_enabled: d.rate_limit_enabled,
        rate_limit_rps: d.rate_limit_rps,
        rate_limit_burst: d.rate_limit_burst,
        block_page_id: d.block_page_id,
        block_status_code: d.block_status_code || 403,
        geoip_enabled: false,
        geoip_mode: d.geoip_mode ?? 'off',
        geoip_crawler_exempt: d.geoip_crawler_exempt === true,
        // 字段缺失 → 默认三引擎；显式 "[]" 原样保留（后端空集语义=全部引擎）——
        // 用兜底改写成三项会让「全部」在任意一次保存后被静默收窄。
        geoip_crawler_engines: d.geoip_crawler_engines === undefined || d.geoip_crawler_engines === ''
          ? ['googlebot', 'bingbot', 'baiduspider']
          : parseIPList(d.geoip_crawler_engines),
        waf_check_response: d.waf_check_response ?? false,
        log_request_body: d.log_request_body ?? false,
        trust_detection: d.trust_detection === true,
    }
    ipACLList.value = parseIPList(d.ip_acl_list)
    ipWhitelist.value = parseIPList(d.ip_whitelist)
    ipACLListRefs.value = parseRefIds(d.ip_acl_list_refs)
    ipWhitelistRefs.value = parseRefIds(d.ip_whitelist_refs)
    // 三态开关读真实持久化值（旧数据缺字段回退名单非空派生）
    ipWhitelistEnabled.value = typeof d.ip_whitelist_enabled === 'boolean' ? d.ip_whitelist_enabled : ipWhitelist.value.length > 0
    ipBlacklistSelf.value = parseIPList(d.ip_blacklist)
    geoipCountries.value = parseIPList(d.geoip_countries)
    form.value.geoip_enabled = (d.geoip_mode ?? 'off') !== 'off' && geoipCountries.value.length > 0
      crsRuleGroups.value = normalizeCrsGroups(parseIPList(d.crs_rule_groups))
      crsExcludedRows.value = parseCrsExcludedRules(d.crs_excluded_rules)
      selectedCustomRules.value = parseCustomRuleIds(d.custom_rules)
      boundRules.value = res.data?.bindings || []
      // 拦截页面失效兜底：block_page_id=0 是「无拦截页面」的合法状态（schema 默认 0），
      // 原样保留不得回退；仅当引用的页面 id>0 且「本次打开取到的权威快照」里不存在
      // 时才回退默认页（优先 #1，其次第一个可用页），避免保存写回无效 id。
      // 快照取不到（refreshBlockPages 失败）时保持用户已绑定的页面不动——用陈旧
      // 快照或空列表判「已删除」会把仍存在的页面静默改掉。
      if (form.value.block_page_id > 0 && blockPagesFresh) {
        if (!blockPages.value.some((p) => p.id === form.value.block_page_id)) {
          form.value.block_page_id = blockPages.value.find((p) => p.id === 1)?.id ?? blockPages.value[0]?.id ?? 0
          ElMessage.warning('原拦截页面已删除，已回退默认页面')
        }
      } else if (form.value.block_page_id > 0 && !blockPagesFresh) {
        ElMessage.warning('拦截页列表刷新失败，未能核对所选拦截页；保存前请刷新页面重试')
      }
    } catch (error: unknown) {
      // catch 路径也要先比对序列号——GET 失败的过期请求会清空
      // 在途新编辑的 editingId（try 前同步赋值的旧值），保存误走 POST 创建
      // 重复策略。
      if (openSeq !== policyDialogOpenSeq) return
      // HTTP 错误已由全局拦截器 toast；本地契约异常（200+code0 但响应缺数据）无用户
      // 提示。两类失败都保持弹窗关闭：editingId 已在 try 前赋值，若照常打开弹窗，
      // 共享 form ref 残留上一行数据，会以旧值静默覆盖新行（PUT 覆盖写链）。
      console.error('Failed to load policy detail:', error)
      editingId.value = null
      return
    }
  } else { resetForm() }
  // 每次打开对话框刷新引用列表缓存（提取为列表/他处新建后选项保持最新）；
  // 传入 openSeq 丢弃过期返回，防止快速关闭重开后旧响应覆盖新缓存
  void fetchIpLists(openSeq)
  // CRS 规则索引同口径：每次对话框打开取一次（同会话内步骤切换复用缓存），
  // 供规则组/排除目标的单条规则选项与预览明细共用（openSeq 过期守卫见 useCrsRuleIndex）
  void ensureCrsRuleIndex(issueCrsIndexSession())
  // 共绑判定依赖 securityBindings（页面挂载时加载的快照）——对话框打开时轻量
  // 刷新一次，外部变更（他端会话/API）的绑定关系才能进入冲突告警口径；
  // 同样按 openSeq 丢弃过期返回
  request.get<APIResponse<Record<string, BindingInfo[]>>>('/security/bindings')
    .then((res) => { if (openSeq !== policyDialogOpenSeq) return; securityBindings.value = res.data || {} })
    .catch(() => { /* 刷新失败保留快照兜底 */ })
  // 规则阶段页字段（生效投影/行内编辑数据源）同节奏刷新一次，与绑定明细同口径
  request.get<APIResponse<Rule[]>>('/rules')
    .then((res) => { if (openSeq !== policyDialogOpenSeq) return; allRules.value = res.data || [] })
    .catch(() => { /* 刷新失败保留快照兜底 */ })
  originalBoundRules.value = [...boundRules.value]
  wizardSnapshot = wizardStateSnapshot()
  currentStep.value = WIZARD_STEP.BASIC
  dialogVisible.value = true
}

const resetForm = () => {
  form.value = defaultForm()
  ipACLList.value = []; ipWhitelist.value = []; ipWhitelistEnabled.value = false; ipBlacklistSelf.value = []; ipACLListRefs.value = []; ipWhitelistRefs.value = []; geoipCountries.value = []; crsRuleGroups.value = []; crsExcludedRows.value = []; selectedCustomRules.value = []; boundRules.value = []; editingId.value = null
  stageOverrideEdits.value = {}; stageOverrideSaving.value = {}; stageOverrideFailed.value = {}; stageOverrideSkipped.value = {}
}

let wizardSnapshot = ''
const wizardStateSnapshot = (): string => JSON.stringify({
  form: form.value,
  ipACLList: ipACLList.value,
  ipWhitelist: ipWhitelist.value,
  ipWhitelistEnabled: ipWhitelistEnabled.value,
  ipBlacklistSelf: ipBlacklistSelf.value,
  ipACLListRefs: ipACLListRefs.value,
  ipWhitelistRefs: ipWhitelistRefs.value,
  geoipCountries: geoipCountries.value,
  crsRuleGroups: crsRuleGroups.value,
  crsExcludedRows: crsExcludedRows.value,
  selectedCustomRules: selectedCustomRules.value,
  boundRules: boundRules.value,
  pendingOverrideRules: pendingOverrideRules.value,
})
const wizardDirty = computed(() => dialogVisible.value && wizardSnapshot !== '' && wizardStateSnapshot() !== wizardSnapshot)

const resetWizard = () => {
  currentStep.value = WIZARD_STEP.BASIC
  editingId.value = null
  editingPolicyType.value = null
  rulePickerVisible.value = false
  ruleBoundPolicies.value = {}
  // 阶段页覆盖编辑暂存须随向导复位清空——否则编辑策略 A
  // 暂存的覆盖会跨会话泄漏到绑定同规则的策略 B（保存写入 A 的暂存值）。
  stageOverrideEdits.value = {}
  stageOverrideSaving.value = {}
  stageOverrideFailed.value = {}
  stageOverrideSkipped.value = {}
  wizardSnapshot = ''
}

const beforeWizardClose = (done: () => void): void => {
  if (saving.value) return
  if (!wizardDirty.value) {
    done()
    return
  }
  void ElMessageBox.confirm('有未保存的修改，关闭将丢弃本次编辑。是否继续？', '放弃修改', {
    type: 'warning', confirmButtonText: '放弃修改', cancelButtonText: '继续编辑',
  }).then(() => done()).catch(() => { /* 继续编辑：保留当前弹框与全部暂存 */ })
}

const handleSave = async () => {
  if (saving.value) return
  if (!form.value.name.trim()) {
    ElMessage.warning('请输入策略名称')
    currentStep.value = WIZARD_STEP.BASIC
    return
  }
  // 类型裁剪后的阶段不参与校验（步骤已被裁剪，校验跳转目标不存在）
  // 阶段 0 信任名单策略：名单（内联∪引用合并口径）必须非空
  if (typeAllowsStage(0) && whitelistSaveCount.value === 0) {
    ElMessage.error('阶段 0 · 信任名单策略必须配置至少一个信任 IP（内联或引用列表）')
    currentStep.value = WIZARD_STEP.TRUST
    return
  }
  // stage0 信任内联条目此前绕过 CIDR 前置校验（开关门恒
  // false、typeAllowsStage(1) 恒 false）——逐条前置，报错带定位（后端 400 兜底）。
  if (typeAllowsStage(0)) {
    const bad = ipWhitelist.value.find((v) => !isValidCidr(v))
    if (bad !== undefined) {
      ElMessage.error(`信任名单条目「${bad}」不是合法的 IP/CIDR`)
      currentStep.value = WIZARD_STEP.TRUST
      return
    }
  }
  if (typeAllowsStage(1) && !validateIpAclList()) {
    currentStep.value = WIZARD_STEP.IP_ACL
    return
  }
  if (typeAllowsStage(3) && !validateExcludedRules()) {
    currentStep.value = WIZARD_STEP.WAF_RULES
    return
  }
  // 爬虫豁免开启但未勾选任何引擎 = 后端渲染器空集语义「全部引擎」
  // （crawlerEngineSelected: len==0 → true，为兼容存量不允许改），而 UI 复选框
  // 「全不选」的直觉语义是「不豁免任何引擎」——两者相反，必须阻止静默放宽。
  if (typeAllowsStage(1) && crawlerExemptionNeedsEngines({ geoipEnabled: form.value.geoip_enabled, crawlerExempt: form.value.geoip_crawler_exempt, engines: form.value.geoip_crawler_engines })) {
    ElMessage.error('已开启爬虫豁免但未勾选任何引擎：空选等于豁免「全部引擎」。请至少勾选一个引擎，或关闭爬虫豁免')
    currentStep.value = WIZARD_STEP.IP_ACL
    return
  }
  // 保存确认（与提取为列表/删除确认同款 warning 弹窗）：取消静默返回，不进入提交
  try {
    await ElMessageBox.confirm(`确定保存安全策略「${form.value.name.trim()}」？将立即重新加载 Caddy 配置。`, '确认', { type: 'warning' })
  } catch { return }
  saving.value = true
  try {
    // v2.2.0 上限守卫：POST bind 为 additive 且服务端不强制上限
    //（上限由 PUT /security/rules/:caddy_id/policies 强制），本流程的绑定上限闸门在客户端。
    // 保存前刷新绑定快照，避免并发会话下用过期数据放行超限绑定。
    try {
      const bindRes = await request.get<APIResponse<Record<string, BindingInfo[]>>>('/security/bindings')
      securityBindings.value = bindRes.data || {}
    } catch { /* 快照刷新失败时用已有数据兜底守卫 */ }
    const added = boundRules.value.filter((id) => !originalBoundRules.value.includes(id))
    const removed = originalBoundRules.value.filter((id) => !boundRules.value.includes(id))
    const overLimit = added.filter((caddyId) => {
      const siblings = (securityBindings.value[caddyId] || []).filter((b) => b.policy_id !== editingId.value)
      return siblings.length >= MAX_POLICIES_PER_RULE
    })
    if (overLimit.length > 0) {
      const names = overLimit.map((id) => allRules.value.find((r) => r.caddy_id === id)?.name || id).join('、')
      ElMessage.error(`以下规则已达 ${MAX_POLICIES_PER_RULE} 条绑定上限，无法继续关联：${names}`)
      currentStep.value = WIZARD_STEP.BINDINGS
      return
    }
    // 阶段 2 唯一门（与选择器置灰同一谓词）：每条规则仅一条限流策略，后端 bulk
    // 对冲突整片 400——不在此拦截会先落库策略、再同步失败，重试永不成功。
    const stage2Conflict = editorPolicyType.value === 'stage2'
      ? added.filter((caddyId) => hasOtherStage2Binding(
        securityBindings.value[caddyId] || [],
        editingId.value,
        (id) => policyTypeById.value.get(id),
      ))
      : []
    if (stage2Conflict.length > 0) {
      const names = stage2Conflict.map((id) => allRules.value.find((r) => r.caddy_id === id)?.name || id).join('、')
      ElMessage.error(`以下规则已绑定其它限流策略（每规则仅一条），请先解绑后再关联：${names}`)
      currentStep.value = WIZARD_STEP.BINDINGS
      return
    }
    // 名单保留语义（与 ip_acl_list 对齐）：关闭开关不清空已配置的名单，保存时
    // 始终回传当前名单内容，避免"关掉开关再打开"丢数据；ip_blacklist 本页不下发，
    // 后端指针语义自动保留原值。区域控制开关 = geoip_mode 三态：开启提交
    // deny/allow，关闭提交 'off'（后端零发射、caddygeoip handler 不注入）；
    // geoip_enabled 是编辑器本地派生开关，后端无此字段，不下发。
    // IP 地址列表引用（refs）：与内联名单位列存储的列表 ID 数组，同样以 JSON
    // 数组文本下发（ip_acl_list_refs / ip_whitelist_refs）；后端将引用列表条目与
    // 内联条目合并生效，允许/拒绝侧归属与对应内联字段一致。
    // 显式白名单：仅提交 UpdateSecurityPolicyRequest 实际字段；组装单源见
    // utils/policyPayload。
    const payload = buildPolicyPayload({
      name: form.value.name,
      description: form.value.description,
      enabled: form.value.enabled,
      mode: form.value.mode,
      anomalyThreshold: form.value.anomaly_threshold,
      ipAclEnabled: form.value.ip_acl_enabled,
      ipAclMode: form.value.ip_acl_mode,
      ipAclList: ipACLList.value,
      ipAclListRefs: ipACLListRefs.value,
      ipWhitelist: ipWhitelist.value,
      ipWhitelistRefs: ipWhitelistRefs.value,
      ipWhitelistEnabled: ipWhitelistEnabled.value,
      rateLimitEnabled: form.value.rate_limit_enabled,
      rateLimitRps: form.value.rate_limit_rps,
      rateLimitBurst: form.value.rate_limit_burst,
      crsRuleGroups: crsRuleGroups.value,
      crsExcludedRules: serializedExcludedRules.value,
      customRuleIds: selectedCustomRules.value,
      blockPageId: form.value.block_page_id,
      blockStatusCode: form.value.block_status_code,
      geoipCountries: geoipCountries.value,
      geoipEnabled: form.value.geoip_enabled,
      geoipMode: form.value.geoip_mode,
      geoipCrawlerExempt: form.value.geoip_crawler_exempt,
      geoipCrawlerEngines: form.value.geoip_crawler_engines ?? [],
      wafCheckResponse: form.value.waf_check_response,
      logRequestBody: form.value.log_request_body,
      trustDetection: form.value.trust_detection,
      policyType: editorPolicyType.value,
    })
    let saveRes: APIResponse<{ id: number }> | undefined
    if (editingId.value) {
      saveRes = await request.put(`/security/policies/${editingId.value}`, payload)
    } else {
      saveRes = await request.post<APIResponse<{ id: number }>>('/security/policies', payload)
      const createdId = saveRes.data?.id
      if (!createdId) throw new Error('创建策略响应缺少 id')
      editingId.value = createdId
      // 新建落库即转入已保存实体（后续 bind/阶段页覆盖用新 id）——同步锁定
      // 编辑器类型为用户所选类型：否则 editingPolicyType 仍为 null，editorPolicyType
      // fallback 'mixed' → 步骤瞬间跳全阶段、标题/标签错变「混合策略」（bind 失败
      // 保持打开重试时用户停留在此错乱视图）。
      editingPolicyType.value = createPolicyType.value
    }
    // v2.2.0 多策略绑定保存组合：新增/取消走策略侧批量端点
    // （单事务批量增删本策略绑定行，不触碰兄弟绑定——与原逐规则
    // additive POST/DELETE 语义一致，但从 N 次全链请求收敛为 1 次单渲染请求）。
    // 逐片响应汇总后再呈现——只保留末片会让早先分片的
    // 退化 200（Caddy 应用失败但 DB 已提交）被覆盖丢失。
    const bindResponses: Array<{ message?: string } | undefined> = []
    try {
      // 2026-09-08 审计 FE1：捕获响应传 showSaveResult——退化 200+后缀
      // （Caddy 应用失败但 DB 已提交）时持续警告可见（有全局横幅兜底但即时
      // 反馈更佳）。bulk 端点同样经 finishTxApply 可产生后缀。
      // 后端单次 bind+unbind 合计 ≤100（超限整批 400 且原样重试仍失败）
      // ——按方向分片提交（每片 ≤100，天然满足合计上限）；端点幂等，重试安全。
      for (const ids of chunkForBulk(added, SECURITY_BULK_LIMITS.policyBindings)) {
        bindResponses.push(await request.post<{ message?: string }>(`/security/policies/${editingId.value}/bindings/bulk`, {
          bind: ids,
          unbind: [],
        }) as { message?: string })
      }
      for (const ids of chunkForBulk(removed, SECURITY_BULK_LIMITS.policyBindings)) {
        bindResponses.push(await request.post<{ message?: string }>(`/security/policies/${editingId.value}/bindings/bulk`, {
          bind: [],
          unbind: ids,
        }) as { message?: string })
      }
    } catch (error: unknown) {
      // 失败的绑定请求已由全局拦截器 toast，这里仅记录并中止收尾。
      // 业务校验失败（400：绑定上限/限流唯一门/规则不存在等）是结构性拒绝——
      // 原样重试必然再失败，不能承诺「可重试」；其余（网络/5xx）幂等重试安全。
      console.error('Failed to sync policy bindings:', error)
      ElMessage.warning(error instanceof ApiRequestError && error.status === 400
        ? '策略已保存，但规则绑定被服务端拒绝：请按提示解绑冲突策略或调整关联规则后重试（原样重试不会成功）'
        : '策略已保存，但部分规则绑定同步失败；对话框保持打开，重新点击保存可重试绑定（幂等）')
      return
    }
    // 历史（用户裁定 A：向导内延迟生效）：本次会话暂存的规则级阶段拦截页覆盖
    // 在策略落库后调批量端点（lb_rules 上的独立资源，无法与策略保存同一事务）；
    // 任一失败即列出规则名并保持对话框打开以便重试（与绑定同步失败同款处理）。
    let pendingOverrides = pendingOverrideRules.value
    const stageOverrideResponses: Array<{ message?: string }> = []
    let skippedOverrideCount = 0
    if (pendingOverrides.length > 0) {
      // 写前重读库值：pending 的 seed 来自打开时的快照，批量端点没有 per-stage
      // 语义（一次写全 4 列）——未编辑阶段必须取最新库值，否则会把另一会话刚
      // 写入的覆盖静默回退。重读失败时不写（拿旧快照写等于复原缺陷）。
      let latestRules: Rule[]
      try {
        const rulesRes = await request.get<APIResponse<Rule[]>>('/rules', { silent: true })
        latestRules = rulesRes.data || []
      } catch (error: unknown) {
        console.error('reload rules before stage override write failed', error)
        ElMessage.error('策略已保存，但写入阶段拦截页覆盖前无法读取最新规则（避免覆盖他人修改）；对话框保持打开，重新点击保存可重试')
        return
      }
      const editedStages = editableOverrideStages.value
      pendingOverrides = pendingOverrides.map(({ caddyId, edit }) => {
        const fresh = latestRules.find((r) => r.caddy_id === caddyId)
        return {
          caddyId,
          edit: {
            stage1_id: editedStages.includes(1) ? edit.stage1_id : (fresh?.block_page_stage1_id ?? 0),
            stage1_status: editedStages.includes(1) ? edit.stage1_status : (fresh?.block_page_stage1_status ?? 0),
            stage3_id: editedStages.includes(3) ? edit.stage3_id : (fresh?.block_page_stage3_id ?? 0),
            stage3_status: editedStages.includes(3) ? edit.stage3_status : (fresh?.block_page_stage3_status ?? 0),
          },
        }
      })
      // 按 4 字段覆盖值分组，改调已发布
      // POST /rules/batch-block-pages（单事务一次渲染）。原实现逐规则整对象
      // PUT /rules/:id：N 条规则=N 次全链渲染，且携带 name/protocol/domain/
      // listen_port 快照会把另一标签页的改名回退。
      const groups = new Map<string, { ids: string[]; edit: StageOverrideEdit }>()
      for (const { caddyId, edit } of pendingOverrides) {
        const key = `${edit.stage1_id}|${edit.stage1_status}|${edit.stage3_id}|${edit.stage3_status}`
        const group = groups.get(key)
        if (group) group.ids.push(caddyId)
        else groups.set(key, { ids: [caddyId], edit })
      }
      const failedRules: string[] = []
      const skippedNotes: string[] = []
      // /rules/batch-block-pages 单次 rule_ids ≤500（超限 400）——按上限分片。
      for (const { ids, edit } of groups.values()) {
        for (const chunk of chunkForBulk(ids, SECURITY_BULK_LIMITS.ruleBlockPages)) {
          const savingFlags = { ...stageOverrideSaving.value }
          for (const caddyId of chunk) savingFlags[caddyId] = true
          stageOverrideSaving.value = savingFlags
          try {
            const res = await request.post<APIResponse<{ bound: number; skipped?: Array<{ rule_id: string; reason: string }> }>>('/rules/batch-block-pages', {
              rule_ids: chunk,
              block_page_stage1_id: edit.stage1_id,
              block_page_stage1_status: edit.stage1_id > 0 ? edit.stage1_status : 0,
              block_page_stage3_id: edit.stage3_id,
              block_page_stage3_status: edit.stage3_id > 0 ? edit.stage3_status : 0,
            })
            stageOverrideResponses.push(res)
            const skippedItems = res.data?.skipped ?? []
            // 先归集 skipped 再回写——被跳过的规则（TCP/规则不存在等）库中
            // 未写入，回写会让 UI 谎报「已覆盖」且下次保存不再重试。
            const skippedIds = new Set(skippedItems.map((item) => item.rule_id))
            for (const caddyId of chunk) {
              if (!skippedIds.has(caddyId)) applyStageOverrideSuccess(caddyId, edit)
            }
            if (skippedItems.length > 0) {
              const skipNotes = { ...stageOverrideSkipped.value }
              for (const item of skippedItems) {
                skipNotes[item.rule_id] = item.reason
                skippedNotes.push(`${item.rule_id}（${item.reason}）`)
              }
              stageOverrideSkipped.value = skipNotes
            }
          } catch (error: unknown) {
            for (const caddyId of chunk) {
              failedRules.push(allRules.value.find((r) => r.caddy_id === caddyId)?.name || caddyId)
            }
            const flags = { ...stageOverrideFailed.value }
            for (const caddyId of chunk) flags[caddyId] = true
            stageOverrideFailed.value = flags
            console.error('save stage overrides failed', error)
          } finally {
            const cleared = { ...stageOverrideSaving.value }
            for (const caddyId of chunk) cleared[caddyId] = false
            stageOverrideSaving.value = cleared
          }
        }
      }
      if (failedRules.length > 0) {
        ElMessage.error(`策略已保存，但以下规则的阶段拦截页覆盖未写入：${failedRules.join('、')}；对话框保持打开，重新点击保存可重试`)
        return
      }
      if (skippedNotes.length > 0) {
        // 被跳过的规则行内已标「未写入（原因）」，此处给汇总口径；
        // 成功计数只数真正写入的规则（不得把 skipped 计入「已同步」）。
        ElMessage.warning(`部分规则未写入阶段拦截页覆盖：${skippedNotes.join('；')}；这些规则保持待保存，可重试`)
      }
      skippedOverrideCount = skippedNotes.length
    }
    // 保存成功与阶段拦截页覆盖同步数合并为一条提示；服务端 message 与
    // Caddy 退化后缀原样保留，skipped 不计入已同步。
    showSaveResult(
      { message: policySaveResultMessage(saveRes, pendingOverrides.length, skippedOverrideCount) },
      '保存成功',
    )
    // 2026-09-08 审计 FE1：bind/unbind 的退化 200+后缀也需可见（有后缀才弹，
    // 无后缀不重复 toast）；汇总全部分片而非末片。
    const mergedBind = mergeBulkResults(bindResponses)
    if (mergedBind?.message?.includes(CADDY_APPLY_FAILED_MARKER)) showSaveResult(mergedBind, '')
    const mergedStageOverrides = mergeBulkResults(stageOverrideResponses)
    if (mergedStageOverrides?.message?.includes(CADDY_APPLY_FAILED_MARKER)) showSaveResult(mergedStageOverrides, '')
    // 跳过项不是已完成的终态：保留其暂存、行内原因与当前弹框，成功项已回写 seed，
    // 下次保存只会重试剩余 pending。退化警告与策略保存结果已在上方完整呈现。
    if (stageOverrideDraftPending(skippedOverrideCount)) return
    // 保存后停在本次保存的类型 tab——否则新建非阶段 1 策略后列表仍停在
    // 阶段 1 空表，用户误读为「保存未生效」。类型须在关闭前取：关闭触发的
    // resetWizard 会清空 editingId/editingPolicyType。
    const savedType = editorPolicyType.value
    dialogVisible.value = false
    activeTypeTab.value = savedType
    fetchData()
    // 本地契约 throw(如「响应缺少 id」)不经 axios 拦截器,
    // 空 catch 会静默吞掉——点保存无反应且已落库可致重试重复创建;按错误
    // 来源分流:ApiRequestError=HTTP 层(拦截器已 toast,不二次弹),其余
    // (本地 throw)在此提示。
  } catch (error) {
    if (!(error instanceof ApiRequestError)) {
      ElMessage.error(error instanceof Error ? error.message : '保存失败')
    }
  } finally { saving.value = false }
}

const deletingPolicyId = ref<number | null>(null)
function handleDelete(row: PolicySummary) {
  // 重入守卫(快速双击叠加双确认框→双 DELETE 误报)+
  // 取消与失败分离(原空 catch 同时吞掉网络失败,行滞留至下轮)。
  if (deletingPolicyId.value !== null) return
  deletingPolicyId.value = row.id
  ElMessageBox.confirm(`将删除策略「${row.name}」。删除后无法恢复，规则上原有的其它策略不受影响。`, '删除安全策略', { type: 'warning', confirmButtonText: '确认删除', cancelButtonText: '取消' })
    .then(async () => {
      const del = await request.delete(`/security/policies/${row.id}`)
      showSaveResult(del, '已删除')
      fetchData()
    })
    .catch(() => { /* 用户取消:不动列表;HTTP 失败已由全局拦截器 toast */ })
    .finally(() => { deletingPolicyId.value = null })
}

const goToCustomRulesPage = () => { window.open(pageUrl('security-rules', { [DEEP_LINK_PARAMS.securityRulesTab]: 'custom' }), '_blank') }
const goToBlockPagesPage = () => { window.open(pageUrl('security-block-pages'), '_blank') }
const openRuleInNewTab = (caddyId: string): void => {
  // 交接改走 URL query（rs 参数），Rules.vue onMounted 消费后清除。
  window.open(pageUrl('rules', { [DEEP_LINK_PARAMS.ruleSearch]: caddyId }), '_blank')
}

// 地域树加载失败显性化——不再静默清空（保留已加载/已选值可见可
// 编辑），给 toast 与弹框内重试入口；「加载失败」不伪装成「无区域」。
const regionsError = ref(false)
const fetchRegions = async () => {
  try {
    const res = await request.get<APIResponse<RegionTree>>('/security/ip2region/regions')
    regionTree.value = {
      provinces: res.data?.provinces || [],
      cities: res.data?.cities || {},
      countries: res.data?.countries || [],
      country_names_cn: res.data?.country_names_cn || {},
    }
    regionsError.value = false
  } catch {
    regionsError.value = true
    ElMessage.error('地域数据加载失败，策略编辑中的地域选择暂不可用，可在编辑弹框内重试')
  }
}

onMounted(async () => {
  // 安全事件页「查看策略」交接改走 URL query（sp=策略 ID / sp-search=名称
  // 关键词），消费后 replaceState 清除——localStorage 通道在多标签/隐私模式下错乱。
  const query = new URLSearchParams(window.location.search)
  const search = query.get(DEEP_LINK_PARAMS.policySearch)
  if (search) policySearch.value = search
  const focusId = Number(query.get(DEEP_LINK_PARAMS.policyId) || 0)
  if (search || query.has(DEEP_LINK_PARAMS.policyId)) window.history.replaceState(null, '', window.location.pathname)
  const loaded = await fetchData()
  // 首屏默认落在第一个非空类型（全空回落阶段 1）——硬编码阶段 1 会让只部署
  // 阶段 0/2/3 策略的站点首屏看到空表 +「暂无安全策略」。
  if (loaded) activeTypeTab.value = pickDefaultPolicyTab(policyTypeCounts.value)
  if (search && loaded) {
    const query = search.trim().toLowerCase()
    const matched = policies.value.find((p) => (p.name || '').toLowerCase() === query)
      ?? policies.value.find((p) => (p.name || '').toLowerCase().includes(query))
    if (matched) activeTypeTab.value = policyTypeOf(matched)
  }
  if (focusId && loaded) {
    // 仅列表加载成功时才判定「已被删除」；加载失败时全局拦截器已弹错误
    // toast，这里不再叠加误导性的「已被删除」提示。
    const row = policies.value.find((p) => p.id === focusId)
    if (row) openDialog(row)
    else ElMessage.warning(`策略 #${focusId} 已被删除，事件中显示的是事件发生时的名称`)
  }
  fetchRegions()
})
</script>

<style scoped>
.table-toolbar { display: flex; gap: 12px; justify-content: flex-end; margin-bottom: 16px; }
/* .rules-pagination 已收敛 styles/main.css（四处逐字重复单源化） */

.mode-radio-group :deep(.el-radio__label) { white-space: nowrap; }
.mode-radio-group { flex-wrap: wrap; row-gap: 4px; }
.waf-off-hint {
  padding: 0 30px 0 120px;
  margin: -10px 0 18px;
  font-size: 12px;
  color: #e6a23c;
  line-height: 1.5;
}

.wizard-steps { margin-bottom: 24px; }
.wizard-steps.is-clickable :deep(.el-step) { cursor: pointer; }

.acl-divider { margin: 4px 0 16px; }
.acl-divider :deep(.el-divider__text) { font-size: 14px; font-weight: 500; padding: 0 8px; }

/* 内联名单行：select 占满剩余宽度，「提取为列表」链接按钮贴右侧（仅内联非空时出现） */
.acl-inline-row { display: flex; align-items: center; gap: 8px; width: 100%; }
.acl-inline-row .acl-inline-select { flex: 1; min-width: 0; }
.acl-extract-btn { flex-shrink: 0; margin-left: auto; }

.extract-source { font-size: 13px; color: #6b7280; }

.wizard-content { min-height: min(370px, calc(100dvh - 300px)); max-height: calc(100dvh - 300px); overflow-y: auto; padding-right: 8px; }
/* 弹框内 cascader 弹性兜底：本体不超出控件列宽（CRS 规则组 / 排除行 / 区域选择共用） */
.wizard-content :deep(.el-cascader) { max-width: 100%; }

.step-content { padding: 8px 0; }

.step-content :deep(.el-form-item) {
  padding: 0 30px 0 20px;
}

.wizard-footer {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
}

/* —— 排除规则行编辑器（WAF 步骤）——
   空态不渲染表格：单行紧凑引导（12px 灰调说明 + 添加按钮贴右），
   高度约一行，避免 el-empty 撑高挤占弹框；有条目才渲染表格。 */
.exclusion-empty { display: flex; flex-direction: column; align-items: flex-start; gap: 6px; width: 100%; }
/* 标签行高 32px、small 按钮 24px——按钮下移 4px 使两者中线重合(垂直居中) */
.exclusion-empty > .el-button { margin-top: 4px; }
.exclusion-empty-tip { flex: 1; min-width: 0; font-size: 12px; color: #9ca3af; line-height: 1.5; }
/* 条目多时限高内部滚动（:max-height 由 el-table 实现表头 sticky 固定），不撑高弹框 */
.exclusion-table { flex: 1 1 auto; min-width: 0; }
/* 行内两列顶部对齐：td 统一顶部对齐，合并列（单行控件组 ~32px）与删除列（24px
   按钮）首行基线一致；ghost 标签 / 冲突图标内联于合并列，出现或消失只改变
   cascader 可用宽度，不影响行高与删除列位置 */
.exclusion-table :deep(td.el-table__cell) { vertical-align: top; }
/* 单行合并行：目标 × 作用域 × 条件一条排除一行。1080px 弹框全宽下不换行；
   窄于该宽度 flex-wrap 优雅折行（条件控件先折），首行对齐不乱 */
.exclusion-row-cell { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; min-height: 24px; }
/* 子组件根尺寸一律经 :deep 下发——el-cascader/el-select/el-radio-group/el-tag/el-icon
   的根元素不继承父组件 data-v，scoped 块内按裸类名命中不到 */
.exclusion-row-cell :deep(.exclusion-target-select) { flex: 2 1 240px; min-width: 200px; max-width: 100%; }
/* ghost 兜底标签：级联无法映射路径的已存值（遗留文件名/陈旧规则 ID/被剔口径值）
   以可读标签内联呈现于 cascader 右侧，可删除；限宽省略 + title 悬浮全文 */
.exclusion-row-cell :deep(.exclusion-target-ghost) { flex: 0 1 auto; min-width: 0; margin-top: 0; }
.exclusion-row-cell :deep(.exclusion-target-ghost .el-tag__content) { max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
/* 行级矛盾提示（与规则组选择冲突/冗余）：不占布局流的行内警告图标，tooltip 悬浮
   展示全文；固定 16px 宽度占位稳定，出现/消失不推移其他控件 */
.exclusion-row-cell :deep(.exclusion-conflict-icon) { flex: 0 0 auto; font-size: 16px; color: #e6a23c; cursor: help; vertical-align: middle; }
/* 作用域 radios 自然紧凑宽；条件控件内联其后，条件区为恒定槽位——三态（ip 标签
   输入 / list 选择器 / all 灰字短提示）同 flex 规格（1 1 240、min 200；ip max
   320、list/all max 280），切换作用域不改变剩余空间分配，cascader 宽度与
   radios 位置恒定不抖动；控件统一 small（24px）与 cascader 同高。ip/list 给确定
   flex-basis（240px）而非 auto：el-select 根元素默认 width:100%
   （--el-select-width），basis:auto 会以整行宽参与 flex 折行判定（clamp 到
   max-width 280），行宽不足时被提前折到第二行 */
.exclusion-row-cell :deep(.exclusion-scope-radios) { flex: 0 0 auto; }
.exclusion-row-cell :deep(.exclusion-scope-radios .el-radio) { margin-right: 8px; }
.exclusion-row-cell :deep(.exclusion-scope-radios .el-radio:last-child) { margin-right: 0; }
.exclusion-row-cell :deep(.exclusion-scope-control-ip) { flex: 1 1 200px; min-width: 160px; max-width: 300px; }
.exclusion-row-cell :deep(.exclusion-scope-control-list) { flex: 1 1 200px; min-width: 160px; max-width: 240px; }
.exclusion-row-cell :deep(.exclusion-scope-all) { flex: 1 1 200px; min-width: 160px; max-width: 240px; font-size: 12px; color: #9ca3af; white-space: nowrap; }
/* ghost 兜底标签容器（crs_rule_groups 下方，普通 div） */
.crs-ghost-tags { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.crs-ghost-tags :deep(.el-tag__content) { max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.exclusion-toolbar { display: flex; align-items: center; justify-content: flex-start; gap: 8px; margin-top: 8px; }
/* 条目数徽标（N/50）随工具行右侧 */
.exclusion-count { margin-left: auto; }

.rule-bind-field { width: 100%; }

.rule-picker-trigger.is-locked { cursor: not-allowed; opacity: .7; }
.rule-picker-trigger {
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
  height: 32px;
  padding: 0 12px;
  border: 1px solid #dcdfe6;
  border-radius: 4px;
  background: #ffffff;
  cursor: pointer;
  font-size: 13px;
  color: #374151;
  box-sizing: border-box;
  transition: border-color 0.2s ease;
}
.rule-picker-trigger:hover { border-color: #c0c4cc; }
.rule-picker-trigger:focus-visible { border-color: #3b82f6; outline: none; }
.rule-picker-placeholder { color: #a8abb2; }
.rule-picker-arrow { color: #a8abb2; font-size: 12px; }

.bound-rule-list { display: flex; flex-direction: column; gap: 10px; margin-top: 8px; }
.bound-rule-row { border: 1px solid #ebeef5; padding: 12px; }
.bound-rule-head { display: flex; align-items: center; gap: 8px; }
.bound-rule-name { font-weight: 500; color: #1f2937; font-size: 13px; }
.bound-rule-meta { font-size: 12px; color: #9ca3af; font-family: monospace; }
.bound-rule-remove { margin-left: auto; }
.bound-rule-chain { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin-top: 6px; }


/* 2026-10-03 模板归一：向导表单内提示条不再有「表单项控件列」载体——
   统一为 el-form-item 包裹（EP label-width 自动对齐控件列，零 CSS 覆盖）
   单条缩进规则（宽度随容器自适应，无第二种弹框样式）。 */

.binding-order-chip { font-size: 12px; padding: 0 6px; border-radius: 10px; background: #f3f4f6; color: #4b5563; border: 1px solid #e5e7eb; display: inline-flex; align-items: center; line-height: 18px; vertical-align: middle; }
.binding-order-chip.is-self { background: #eff6ff; color: #1d4ed8; border-color: #bfdbfe; font-weight: 500; }
.binding-order-chip.is-disabled { opacity: 0.55; text-decoration: line-through; }
.binding-order-chip.is-trust { background: #ecfdf5; color: #047857; border-color: #a7f3d0; font-weight: 500; }

/* v2.2.0 拦截页面按规则生效状态注释块：跟随 .form-tip-line 的 12px/灰调，
   仅状态词使用克制的成功/警告/灰着色，避免使用 el-tag 造成视觉噪声。 */
.block-page-rule-annotations { display: flex; flex-direction: column; gap: 2px; margin-top: 6px; font-size: 12px; line-height: 1.5; color: #9ca3af; width: 100%; }
.block-page-rule-annotation { display: flex; align-items: center; flex-wrap: wrap; gap: 6px; }
.block-page-rule-annotation-name { color: #6b7280; }
.block-page-rule-annotation-status.is-active { color: #10b981; }
.block-page-rule-annotation-status.is-warning { color: #d97706; }
.block-page-rule-annotation-status.is-disabled { color: #9ca3af; }
.block-page-rule-annotation-status.is-info { color: #6b7280; }

.rule-binding-preview { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin: 2px 0 4px 24px; }
.rule-binding-landing { font-size: 12px; color: #6b7280; }
/* 阶段 0 绑定提示用成功色（信任先于拦截判定，与「排第 N 位」灰字区分） */
.rule-binding-landing--trust { color: var(--el-color-success); }
.rule-binding-limit { font-size: 12px; color: #e6a23c; }

.rule-picker-search { margin-bottom: 12px; }

.rule-picker-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 8px;
  padding: 0 4px;
}
.rule-picker-header-meta { font-size: 12px; color: #9ca3af; }

.rule-picker-list {
  min-height: 120px;
  max-height: 320px;
  overflow-y: auto;
  background: #fff;
}

.rule-picker-item {
  display: flex;
  flex-direction: column;
  align-items: stretch;
  padding: 4px 12px;
  border-bottom: 1px solid #f3f4f6;
}
.rule-picker-item:last-child { border-bottom: none; }
.rule-picker-item :deep(.el-checkbox) { width: 100%; height: auto; padding: 4px 0; }
.rule-picker-name { font-weight: 500; color: #1f2937; }
.rule-picker-meta { margin-left: 8px; font-size: 12px; color: #9ca3af; font-family: monospace; }

.rule-picker-pagination { display: flex; justify-content: flex-end; margin-top: 12px; }

.picker-footer { display: flex; align-items: center; justify-content: space-between; }
.picker-count { font-size: 13px; color: #6b7280; }
.picker-footer-buttons { display: flex; gap: 12px; }

/* ── 实体单职化：类型 tab / 阶段 chips / 生效投影 / 行内阶段页编辑 / 流水线预览 ── */
.policy-type-tabs { margin-bottom: 4px; }
.policy-type-tabs :deep(.el-tabs__header) { margin-bottom: 12px; }
.policy-summary-cell { display: flex; align-items: center; gap: 8px; min-width: 0; }
.policy-summary-text { font-size: 13px; color: #1f2937; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.policy-trigger-tag { font-variant-numeric: tabular-nums; }

/* 生效投影条（任务 8）：同一信息条左右两段——左=生效说明句、右=关联规则覆盖状态
   列表，同字号（12px）同基线（align-items: baseline） */
.stage-projection-bar {
  display: flex; align-items: baseline; justify-content: space-between; gap: 16px;
  margin: 0 20px 12px; padding: 8px 12px;
  background: #f8fafc; border: 1px dashed #e5e7eb;
  font-size: 12px;
}
.stage-projection-desc { font-weight: 600; color: #374151; line-height: 1.8; flex: 0 1 auto; }
.stage-projection-rules { flex: 0 0 auto; display: flex; flex-wrap: wrap; gap: 2px 12px; justify-content: flex-end; text-align: right; }
.stage-projection-empty { color: #9ca3af; line-height: 1.8; }

/* 关联规则行内阶段页编辑（改选暂存，随向导保存提交） */
.stage-override-editors { display: flex; flex-direction: column; gap: 6px; margin-top: 8px; padding-top: 8px; border-top: 1px dashed #e5e7eb; }
.stage-override-line { display: flex; align-items: center; gap: 8px; }
.stage-override-label { font-size: 12px; color: #6b7280; flex: 0 0 auto; }
.stage-override-page-select { width: 220px; }
.stage-override-status-select { width: 110px; }
.stage-override-saving { color: var(--el-color-primary); }

/* 配置预览：三阶段投影（策略视角） */
.preview-meta { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin: 0 20px 12px; }
.preview-meta-name { font-size: 15px; font-weight: 600; color: #1f2937; }
.preview-meta-desc { font-size: 12px; color: #6b7280; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 420px; }
.preview-pipeline { display: flex; flex-direction: column; gap: 12px; margin: 0 20px; }
.preview-bindings-card { margin: 12px 20px 0; }
.preview-stage-card.is-disabled > .dialog-panel { background: #fafafa; border-style: dashed; }
.preview-stage-empty { font-size: 12px; color: #9ca3af; }
.preview-policy-rows { margin-top: 0; }
.preview-row { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; font-size: 13px; line-height: 1.8; }
.preview-row-label { color: #6b7280; flex-shrink: 0; }
.preview-row-detail { color: #1f2937; text-align: right; overflow: hidden; text-overflow: ellipsis; }
.preview-stage-footnote { margin-top: 6px; font-size: 12px; color: #9ca3af; }

.migrate-preview { display: flex; flex-direction: column; gap: 14px; }

.migrate-preview-tags { display: flex; flex-wrap: wrap; gap: 6px; }
.migrate-preview-rule { display: flex; align-items: baseline; gap: 8px; font-size: 13px; line-height: 1.8; }
.migrate-preview-rule-name { color: #1f2937; font-weight: 500; }

/* 策略类型：与 el-form-item 完全同构的纵向独立 radio 列表（首行 32px 与输入框基线对齐） */
.policy-type-radio-list { display: flex; flex-direction: column; align-items: flex-start; gap: 2px; width: 100%; }
.policy-type-radio-list :deep(.el-radio) { margin-right: 0; height: 32px; }
.policy-type-radio-list :deep(.el-radio__label) { white-space: normal; }
.policy-type-tabs :deep(.el-tabs__item) { white-space: nowrap; }
.migrate-preview-rule-meta { color: #9ca3af; font-size: 12px; }
.migrate-preview-empty { font-size: 12px; color: #9ca3af; }

/* 混合策略只读查看（共享分区头 + 详情面板） */
.view-policy-body { min-height: 120px; }
.view-policy-section { margin-bottom: 12px; }
.view-policy-row { display: flex; align-items: baseline; gap: 12px; font-size: 13px; line-height: 1.9; }
.view-policy-label { color: #6b7280; flex: 0 0 96px; }
.view-policy-value { color: #1f2937; overflow: hidden; text-overflow: ellipsis; }
.view-policy-empty { font-size: 12px; color: #9ca3af; }
</style>

<!-- el-tooltip popper 挂载到 body， scoped 样式无法命中，单独非 scoped 块 -->
<style>

/* 兜底：关联规则多时 popper 可超视口——flip 回退之外由内部滚动承接*/
.policy-rules-popper { max-height: 60vh; overflow-y: auto; }
.policy-rules-popper .el-dropdown-menu { padding: 4px 0; }
.policy-rules-popper .el-dropdown-menu__item { font-size: 12px; line-height: 1.6; }
/* reference 是真按钮（原为无激活行为的 span）：清掉 UA 按钮外观，保留文本外观
   与焦点环；键盘激活交给 el-dropdown 的 click 触发 */
.policy-rule-count {
  padding: 0 2px;
  border: 0;
  background: transparent;
  color: inherit;
  font: inherit;
  cursor: pointer;
}
.policy-rule-count:focus-visible { outline: 2px solid var(--el-color-primary); outline-offset: 2px; border-radius: 2px; }

/* el-cascader 懒加载面板（teleported 到 body）：菜单放宽，给两行规则叶与组 label 留足宽度 */
.crs-rule-popper .el-cascader-menu { min-width: 260px; }
/* 两行规则叶节点：el-cascader-node 默认 34px 定高 / label 单行省略会裁切副行——
   含 .crs-rule-option 的节点覆写为高度自适应 + label 允许换行；单行组节点不受影响 */
.crs-rule-popper .el-cascader-node:has(.crs-rule-option) { height: auto; line-height: 1.4; padding-top: 5px; padding-bottom: 5px; }
.crs-rule-popper .el-cascader-node:has(.crs-rule-option) .el-cascader-node__label { white-space: normal; overflow: visible; text-overflow: clip; line-height: 1.4; }
.crs-rule-option { display: flex; flex-direction: column; line-height: 1.4; padding: 4px 0 5px; }
.crs-rule-option-label { font-size: 13px; }
.crs-rule-option-meta { font-size: 12px; color: #9ca3af; }
</style>
