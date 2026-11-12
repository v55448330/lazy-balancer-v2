<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Lock /></el-icon>
          {{ t('app.security.policies.page.title') }}
        </h2>
        <p class="page-desc">{{ t('app.security.policies.page.desc') }}</p>
      </div>
      <el-button v-if="!isReadOnly" type="primary" :disabled="loading" @click="openDialog()">
        <el-icon><Plus /></el-icon>
        {{ t('app.security.policies.page.create') }}
      </el-button>
    </div>

    <!-- 主数据失败与「确实没有策略」必须可区分——保留旧表 + 重试入口
         （同族页 SecurityRules/SecurityBlockPages 同款 error-banner 范式） -->
    <el-alert v-if="policiesLoadError" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
      <template #title>
        <div class="polling-error-title">
          <span>{{ t('app.security.policies.list.loadFailedBanner') }}</span>
          <el-button link type="danger" :loading="loading" @click="fetchData">{{ t('app.security.policies.common.retryNow') }}</el-button>
        </div>
      </template>
    </el-alert>

    <!-- 辅助端点部分失败：计数/冲突告警会降级，必须可见点名（同族页 error-banner 范式） -->
    <el-alert v-if="auxLoadFailures.length > 0" type="warning" :closable="false" show-icon class="polling-error-alert">
      <template #title>
        <div class="polling-error-title">
          <span>{{ t('app.security.policies.list.auxFailBanner', { items: auxLoadFailures.join(t('app.security.policies.common.sep')) }) }}</span>
          <el-button link type="warning" :loading="loading" @click="fetchData">{{ t('app.security.policies.common.reload') }}</el-button>
        </div>
      </template>
    </el-alert>

    <el-card class="list-card">
      <el-tabs v-model="activeTypeTab" class="policy-type-tabs">
        <el-tab-pane v-for="tab in policyTypeTabs" :key="tab.type" :label="t('app.security.policies.list.tabLabel', { label: tab.label, count: tab.count })" :name="tab.type" />
      </el-tabs>
      <div class="table-toolbar">
        <el-input v-model="policySearch" :placeholder="t('app.security.policies.list.searchPlaceholder')" clearable :prefix-icon="Search" style="width: 240px" />
      </div>
      <el-table :data="pagedPolicies" v-loading="loading" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="">
        <template #empty>
          <el-empty v-if="!policiesLoadError" :description="t('app.security.policies.list.empty')" :image-size="60" />
          <span v-else class="text-secondary">{{ t('app.security.policies.list.loadFailedHint') }}</span>
        </template>
        <el-table-column prop="name" :label="t('app.security.policies.table.name')" min-width="200">
          <template #default="{ row }">
            <AccessibleLink type="primary" @click="openDialog(row as PolicySummary)">{{ row.name }}</AccessibleLink>
          </template>
        </el-table-column>
        <el-table-column :label="t('app.security.policies.table.relatedRules')" width="112" align="center">
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
              <button type="button" class="policy-rule-count" :aria-label="t('app.security.policies.table.relatedRulesAria', { n: row.rule_count })">{{ row.rule_count }}</button>
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
        <el-table-column :label="t('app.security.policies.table.summary')" min-width="324">
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
        <el-table-column :label="t('app.security.policies.table.trigger24h')" width="108" align="center">
          <template #default="{ row }">
            <el-tag v-if="(row.trigger_24h ?? 0) > 0" disable-transitions size="small" type="danger" effect="plain" class="policy-trigger-tag">{{ row.trigger_24h }}</el-tag>
            <el-tag v-else disable-transitions size="small" type="info" effect="plain" class="policy-trigger-tag">0</el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="t('app.security.policies.table.status')" width="90" align="center">
          <template #default="{ row }">
            <el-tag :type="row.enabled ? 'success' : 'info'" disable-transitions size="small" effect="light">{{ row.enabled ? t('app.security.policies.status.enabled') : t('app.security.policies.status.disabled') }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="t('app.security.policies.table.updatedAt')" width="170" align="center">
          <template #default="{ row }">{{ formatDate(row.updated_at) || '-' }}</template>
        </el-table-column>
        <el-table-column :label="t('app.security.policies.table.updatedBy')" width="110" align="center">
          <template #default="{ row }">{{ getUpdaterName(row.updated_by) }}</template>
        </el-table-column>
        <el-table-column v-if="!isReadOnly" :label="t('app.security.policies.table.actions')" min-width="230" fixed="right">
          <template #default="{ row }">
            <el-button size="small" link type="primary" @click="openDialog(row as PolicySummary)">{{ policyTypeOf(row as PolicySummary) === 'mixed' ? t('app.security.policies.action.view') : t('app.security.policies.action.edit') }}</el-button>
            <el-button v-if="policyTypeOf(row as PolicySummary) !== 'mixed'" size="small" link type="primary" :disabled="securityBindingsLoading || securityBindingsFailed || bindRulesOpening" :title="securityBindingsLoading ? t('app.security.policies.bind.loadingTitle') : securityBindingsFailed ? t('app.security.policies.bind.failedTitle') : ''" @click="openBindRulesDialog(row as PolicySummary)">{{ t('app.security.policies.action.bindRules') }}</el-button>
            <el-button v-if="policyTypeOf(row as PolicySummary) === 'mixed'" size="small" link type="warning" @click="openMigrateDialog(row as PolicySummary)">{{ t('app.security.policies.action.migrate') }}</el-button>
            <el-button size="small" link type="danger" @click="handleDelete(row as PolicySummary)">{{ t('app.security.policies.common.delete') }}</el-button>
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
        <DialogHeader :icon="WarningFilled" :title="t('app.security.policies.migrate.title')"
          :subtitle="t('app.security.policies.migrate.subtitle', { name: migratePolicy?.name })" />
      </template>
      <div v-if="migratePolicy" class="migrate-preview">
        <div class="migrate-preview-section">
          <DialogSectionHeader :title="t('app.security.policies.migrate.willCreate', { n: migrateChildTypes.length })" tone="warning" />
          <div class="dialog-panel">
            <div class="migrate-preview-tags">
              <!-- 四阶段恒出（2026-09-21 用户裁定：与查看弹框/流程弹框同口径）——
                   空阶段灰态标注「未启用 · 不生成」，不再整段缺席 -->
              <el-tag v-for="type in (['stage0', 'stage1', 'stage2', 'stage3'] as const)" :key="type" size="small" effect="plain" :type="migrateChildTypes.includes(type) ? 'primary' : 'info'">
                {{ migrateChildTypes.includes(type) ? t('app.security.policies.migrate.childWithType', { name: migratePolicy.name, type: POLICY_TYPE_SHORT_LABELS[type] }) : t('app.security.policies.migrate.childDisabled', { type: POLICY_TYPE_SHORT_LABELS[type] }) }}
              </el-tag>
            </div>
          </div>
        </div>
        <div class="migrate-preview-section">
          <DialogSectionHeader :title="t('app.security.policies.migrate.remapTitle')" :description="t('app.security.policies.migrate.remapDesc')" tone="warning" />
          <div class="dialog-panel">
            <template v-if="migrateBoundRules.length > 0">
              <div v-for="rule in migrateBoundRules" :key="rule.caddy_id" class="migrate-preview-rule">
                <span class="migrate-preview-rule-name">{{ rule.name }}</span>
                <span class="migrate-preview-rule-meta">{{ rule.domain || '-' }}:{{ rule.listen_port }}</span>
                <el-tag v-if="migrateStage2SkipRisk.some((r) => r.caddy_id === rule.caddy_id)" size="small" type="warning" effect="plain">{{ t('app.security.policies.migrate.willSkip') }}</el-tag>
              </div>
            </template>
            <div v-else class="migrate-preview-empty">{{ t('app.security.policies.migrate.noBindings') }}</div>
          </div>
        </div>
        <div v-if="migrateStage2SkipRisk.length > 0" class="info-note-bar"><span class="info-note-desc">{{ t('app.security.policies.migrate.rateLimitRisk', { names: migrateStage2SkipRisk.map((r) => r.name).join(t('app.security.policies.common.sep')) }) }}</span></div>
        <div v-if="migrateCapRisk.length > 0" class="info-note-bar"><span class="info-note-desc">{{ t('app.security.policies.migrate.capRisk', { names: migrateCapRisk.map((r) => r.name).join(t('app.security.policies.common.sep')), max: MAX_POLICIES_PER_RULE }) }}</span></div>
        <div class="info-note-bar"><span class="info-note-desc">{{ t('app.security.policies.migrate.deleteNote') }}</span></div>
      </div>
      <template #footer>
        <el-button :disabled="migrateSaving" @click="cancelMigrate">{{ t('app.security.policies.common.cancel') }}</el-button>
        <el-button type="warning" :loading="migrateSaving" :disabled="migrateSaving" @click="submitMigrate">{{ t('app.security.policies.migrate.confirm') }}</el-button>
      </template>
    </el-dialog>

    <!-- 混合策略只读查看：按阶段分组展示全部内容，零可编辑字段，底部唯一操作=更新迁移 -->
    <el-dialog v-model="viewPolicyVisible" width="min(760px, 94vw)" top="6vh">
      <template #header>
        <DialogHeader :icon="Lock" :title="viewPolicyDetail?.name || viewPolicyRow?.name || ''"
          :subtitle="t('app.security.policies.view.subtitle')" />
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
            <DialogSectionHeader :title="t('app.security.policies.view.relatedRulesTitle', { n: viewPolicyBoundRuleRows.length })" />
            <div class="dialog-panel">
              <template v-if="viewPolicyBoundRuleRows.length > 0">
                <div v-for="rule in viewPolicyBoundRuleRows" :key="rule.caddyId" class="view-policy-row">
                  <span class="view-policy-label">{{ rule.name }}</span>
                  <span class="view-policy-value">{{ rule.domain || '-' }}:{{ rule.listenPort }}</span>
                </div>
              </template>
              <div v-else class="view-policy-empty">{{ t('app.security.policies.view.noRules') }}</div>
            </div>
          </div>
        </template>
      </div>
      <template #footer>
        <el-button @click="viewPolicyVisible = false">{{ t('app.security.policies.common.close') }}</el-button>
        <el-button v-if="!isReadOnly" type="warning" @click="openMigrateFromView">{{ t('app.security.policies.action.migrate') }}</el-button>
      </template>
    </el-dialog>
    <el-dialog v-model="dialogVisible" class="dialog-body-inset policy-wizard-dialog" width="min(950px, 94vw)" top="5vh" :close-on-click-modal="false" :before-close="beforeWizardClose" @close="resetWizard">
      <template #header>
        <DialogHeader :icon="Lock" :title="editingId ? (isReadOnly ? t('app.security.policies.editor.titleView') : t('app.security.policies.editor.titleEdit')) : t('app.security.policies.editor.titleCreate')"
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
          <el-form :model="form" :label-width="$flw('100px')" :disabled="formFrozen">
            <!-- 策略类型：新建时选择（决定步骤条与表单裁剪）；编辑时固定展示。
                 与 el-form-item label 完全同构（用户裁定）；radio 不用 el-radio-group
                 包组——组容器 DIV 会被 EP 注册为表单输入 id 触发 Firefox label-for 告警，
                 改为同 model-value 的独立 radio 纵向列表（首行与输入框基线对齐） -->
            <el-form-item v-if="editingId === null" :label="t('app.security.policies.editor.typeLabel')" required>
              <div class="policy-type-radio-list" role="radiogroup" :aria-label="t('app.security.policies.editor.typeLabel')">
                <el-radio
                  v-for="opt in POLICY_TYPE_CREATE_OPTIONS"
                  :key="opt.value"
                  :model-value="createPolicyType"
                  :value="opt.value"
                  @update:model-value="createPolicyType = opt.value"
                >{{ opt.label }}</el-radio>
              </div>
            </el-form-item>
            <el-form-item v-else :label="t('app.security.policies.editor.typeLabel')" for="policy-type-static">
              <input type="text" id="policy-type-static" aria-hidden="true" tabindex="-1" autocomplete="off" style="display:none">
              <el-tag :type="editorPolicyType === 'mixed' ? 'warning' : 'primary'" effect="plain">{{ POLICY_TYPE_LABELS[editorPolicyType] }}</el-tag>
            </el-form-item>
            <el-form-item :label="t('app.security.policies.editor.nameLabel')" required>
              <el-input v-model="form.name" :placeholder="t('app.security.policies.editor.namePlaceholder')" :maxlength="SECURITY_NAME_MAX_RUNES" show-word-limit />
            </el-form-item>
            <el-form-item :label="t('app.security.policies.editor.descLabel')">
              <el-input v-model="form.description" :placeholder="t('app.security.policies.editor.descPlaceholder')" :maxlength="SECURITY_DESCRIPTION_MAX_RUNES" show-word-limit />
            </el-form-item>
            <el-form-item :label="t('app.security.policies.editor.enabledLabel')">
              <el-switch v-model="form.enabled" />
              <span class="form-tip-inline">{{ t('app.security.policies.editor.enabledTip') }}</span>
            </el-form-item>
          </el-form>
        </div>
        <!-- Step: 阶段 0 · 信任名单（stage0 编辑器表单：信任名单内联+引用 + 保留检测记录开关） -->
        <div v-show="currentStep === WIZARD_STEP.TRUST" class="step-content">
          <div class="stage-projection-bar">
            <span class="stage-projection-desc">{{ t('app.security.policies.stage0.projection') }}</span>
            <div class="stage-projection-rules">
              <span v-if="boundRules.length === 0" class="stage-projection-empty">{{ t('app.security.policies.bind.none') }}</span>
              <span v-else class="stage-projection-empty">{{ t('app.security.policies.bind.appliesTo', { n: boundRules.length }) }}</span>
            </div>
          </div>
          <el-form :model="form" :label-width="$flw('100px')" :disabled="formFrozen">
            <el-form-item :label="t('app.security.policies.stage0.trustIpLabel')">
              <div class="acl-inline-row">
                <el-select v-model="ipWhitelist" multiple filterable allow-create default-first-option :placeholder="t('app.security.policies.common.ipEntryPlaceholder')" class="acl-inline-select" />
                <el-button v-if="!isReadOnly" link type="primary" class="acl-extract-btn" :disabled="ipWhitelist.length === 0" @click="openExtractDialog('trust')">{{ t('app.security.policies.common.extractAsList') }}</el-button>
              </div>
              <div class="form-tip-line">{{ t('app.security.policies.stage0.trustTip') }}</div>
            </el-form-item>
            <el-form-item :label="t('app.security.policies.common.refListLabel')">
              <el-select v-model="ipWhitelistRefs" multiple filterable :placeholder="t('app.security.policies.common.refListPlaceholder')" style="width: 100%">
                <!-- 内置威胁名单仅可用于 IP ACL 黑名单（2026-09-24 用户裁定），信任名单不可引用 -->
                <el-option-group v-if="customIpLists.length > 0" :label="t('app.security.policies.common.groupCustom')">
                  <el-option v-for="l in customIpLists" :key="l.id" :label="t('app.security.policies.common.listWithNameCount', { name: l.name, count: l.entry_count })" :value="l.id" />
                </el-option-group>
              </el-select>
              <div v-if="showWhitelistRefHint" class="form-tip-line">{{ whitelistRefHint }}</div>
            </el-form-item>
            <el-form-item :label="t('app.security.policies.stage0.keepDetectLabel')">
              <el-switch v-model="form.trust_detection" />
              <span class="form-tip-inline">{{ form.trust_detection ? t('app.security.policies.stage0.detectOn') : t('app.security.policies.stage0.detectOff') }}</span>
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
          <!-- 投影条：左=生效说明句、右=关联规则数量摘要。历史改为摘要口径（原逐规则
               清单在关联规则多时撑破弹框：右段 flex:0 0 auto 按 max-content 定尺挤压左段
               成单字竖排，见 SecurityPolicies 弹框实测）；逐规则绑定与执行序在「关联规则」步骤 -->
          <div class="stage-projection-bar">
            <span class="stage-projection-desc">{{ t('app.security.policies.waf.projection') }}</span>
            <div class="stage-projection-rules">
              <span v-if="boundRules.length === 0" class="stage-projection-empty">{{ t('app.security.policies.bind.none') }}</span>
              <span v-else class="stage-projection-empty">{{ t('app.security.policies.bind.appliesTo', { n: boundRules.length }) }}</span>
            </div>
          </div>
          <el-form :model="form" :label-width="$flw('100px')" :disabled="formFrozen">
            <!-- 原生表单行（2026-10-11 用户裁定：对齐统一走 el-form-item；Firefox
                 label-for 控制台告警为 EP 上游已知形态，非用户可见） -->
            <el-form-item :label="t('app.security.policies.waf.modeLabel')" for="radio-waf--10">
              <input type="text" id="radio-waf--10" aria-hidden="true" tabindex="-1" autocomplete="off" style="display:none">
              <el-radio-group v-model="form.mode" class="mode-radio-group" :aria-label="t('app.security.policies.waf.modeLabel')">
                <!-- 2026-09-09 四态化:off=CRS 与自定义均不生效;custom_only=仅自定义生效;
                     detection=CRS 只记录;blocking=CRS 阻断。每项标签+描述单行不换行。 -->
                <el-radio value="off">{{ t('app.security.policies.waf.modeOff') }}</el-radio>
                <el-radio value="custom_only">{{ t('app.security.policies.waf.modeCustomOnly') }}</el-radio>
                <el-radio value="detection">{{ t('app.security.policies.waf.modeDetection') }}</el-radio>
                <el-radio value="blocking">{{ t('app.security.policies.waf.modeBlocking') }}</el-radio>
              </el-radio-group>
              <div class="form-tip-line">{{ t('app.security.policies.waf.offTip') }}</div>
              <div class="form-tip-line">{{ t('app.security.policies.waf.customTip') }}</div>
            </el-form-item>
            <div v-if="form.mode === 'off'" class="waf-off-hint">{{ t('app.security.policies.waf.offHint') }}</div>
            <div v-else-if="form.mode === 'custom_only'" class="waf-off-hint">{{ t('app.security.policies.waf.customOnlyHint') }}</div>
            <el-form-item :label="t('app.security.policies.waf.thresholdLabel')">
              <el-select v-model="form.anomaly_threshold" :disabled="crsFieldsOff || isReadOnly" style="width: 140px">
                <el-option v-if="[1, 3].includes(form.anomaly_threshold)" :value="1" :label="t('app.security.policies.waf.thStrict', { n: 1 })" disabled />
                <el-option v-if="form.anomaly_threshold === 3" :value="3" :label="t('app.security.policies.waf.thStrict', { n: 3 })" disabled />
                <el-option :value="5" :label="t('app.security.policies.waf.thStandard', { n: 5 })" />
                <el-option :value="10" :label="t('app.security.policies.waf.thLoose', { n: 10 })" />
                <el-option :value="15" :label="t('app.security.policies.waf.thVeryLoose', { n: 15 })" />
                <el-option :value="20" :label="t('app.security.policies.waf.thUltraLoose', { n: 20 })" />
              </el-select>
              <div class="form-tip-line">{{ t('app.security.policies.waf.thresholdTip') }}</div>
              <div class="form-tip-line">{{ t('app.security.policies.waf.thresholdTip2') }}</div>
            </el-form-item>
            <el-form-item :label="t('app.security.policies.waf.crsGroupsLabel')">
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
                :placeholder="t('app.security.policies.waf.crsPlaceholder')"
                style="width: 100%"
              >
                <template #default="{ data }">
                  <div v-if="data.isRule" class="crs-rule-option" :title="`${data.value} — ${data.fullLabel}`">
                    <div class="crs-rule-option-label">{{ data.label }}</div>
                    <div class="crs-rule-option-meta">{{ data.file }} · {{ crsCategoryLabel(data.category) }}</div>
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
              <div class="form-tip-line">{{ t('app.security.policies.waf.crsTip') }}</div>
              <div class="form-tip-line">{{ t('app.security.policies.waf.crsTip2') }}</div>
            </el-form-item>
            <!-- 跨策略 CRS 规则组重复实时警告（随当前选择重算）：el-form 直接子级
                 提示条在表单项内自然对齐控件列（EP label-width 布局，零 CSS 覆盖） -->
            <el-form-item v-if="wafStepCrsAlert"><div class="info-note-bar"><span class="info-note-desc">{{ wafStepCrsAlert }}</span></div>
            </el-form-item>
            <el-form-item v-if="hasResponsePhaseGroupWithoutCheck"><div class="info-note-bar"><span class="info-note-desc">{{ t('app.security.policies.waf.responsePhaseWarn') }}</span></div>
            </el-form-item>
            <el-form-item :label="t('app.security.policies.waf.checkResponseBody')">
              <el-switch v-model="form.waf_check_response" :disabled="crsFieldsOff || isReadOnly" />
              <div class="form-tip-line">{{ t('app.security.policies.waf.checkResponseBodyTip') }}</div>
            </el-form-item>
            <el-form-item :label="t('app.security.policies.waf.logRequestBody')">
              <el-switch v-model="form.log_request_body" :disabled="isReadOnly || form.mode === 'off'" />
              <div class="form-tip-line">{{ t('app.security.policies.waf.logRequestBodyTip') }}</div>
              <!-- 警示条挂在带标签表单项内（EP 无标签项内容从行首渲染，会贴弹框左缘
                   且比控件列宽 ~100px——2026-11-03 用户验收反馈）；撑满走 form-item-note-bar，
                   盒模型样式主体走全局 info-note-bar 规范（padding 8px 12px），零局部覆写 -->
              <div v-if="form.log_request_body" class="info-note-bar form-item-note-bar"><span class="info-note-desc">{{ t('app.security.policies.waf.logRequestBodyWarn') }}</span></div>
            </el-form-item>
            <el-form-item :label="t('app.security.policies.waf.exclusionLabel')" for="radio---11">
              <input type="text" id="radio---11" aria-hidden="true" tabindex="-1" autocomplete="off" style="display:none">
              <div class="exclusion-body">

              <!-- 表格行编辑器：目标（目录自动补全，可自由输入）× 作用域（全部 IP/指定 IP/
                   地址列表/路径 URI）× 条件控件（ip → 标签输入 + isValidCidr 即时拒绝；
                   list → 引用 /security/ip-lists 列表；path → URI 前缀输入）× 删除。
                   上限 50 行；旧字符串数组存储读取时已归一为 scope:all 行，保存统一写
                   对象数组。
                    布局：空态不渲染表格——单行紧凑引导（说明 + 添加按钮）避免挤占弹框
                    高度；有条目才渲染表格，条目多时容器 max-height 260px 内部滚动（表头
                    sticky 固定），不再撑高弹框。每条排除单行呈现（目标 × 作用域 × 条件
                    合并列）：行内控件统一 small（24px）同高 + 单元格顶部对齐；目标输入
                    弹性占满剩余宽（min 200px）、radios 自然紧凑、条件控件内联于 radios
                    之后（all 灰字短提示 / ip 标签输入 / list 紧凑选择 / path 前缀输入），
                    行高 ~32-40px（原双行 60px+）；合并列 min-width 560 + 删除列 60 低于
                    弹框内容宽 → 1080px 全宽不换行、无横向滚动；条目数徽标随工具行。 -->
              <!-- 2026-09-19 用户裁定:空态按钮在首行(与「排除规则」标题同一
                   水平线、内容列左对齐),描述文字居其下 -->
              <div v-if="crsExcludedRows.length === 0" class="exclusion-empty">
                <el-button size="small" type="primary" plain :disabled="crsFieldsOff || isReadOnly" @click="addExcludedRule">{{ t('app.security.policies.waf.addExclusion') }}</el-button>
                <span class="exclusion-empty-tip">{{ t('app.security.policies.waf.exclusionEmptyTip') }}</span>
              </div>
              <template v-else>
                <el-table :data="crsExcludedRows" size="small" class="exclusion-table" :max-height="260">
                  <!-- 单行合并列：目标规则 × 作用域 × 条件，一条排除规则一行呈现——
                       左起：目标自动补全输入（弹性占满剩余，min 200px）+ ghost 内联标签 +
                       冲突警告图标（tooltip 悬浮）→ 作用域 radios（自然宽）→ 条件控件
                       内联随 radios 之后，条件区为恒定槽位（见下方 CSS——四态同
                       flex 规格，切换作用域不改变剩余空间分配，输入框宽与
                       radios 位置恒定不抖动），行高 ~32-40px；1080px 弹框全宽下
                       不换行，窄于该宽度时 flex-wrap 优雅折行且首行对齐不乱；ghost /
                       冲突图标出现只挤压目标输入宽度，不改行结构 -->
                  <el-table-column :label="t('app.security.policies.waf.exclusionColTarget')" min-width="560">
                    <template #default="{ row }">
                      <div class="exclusion-row-cell">
                        <!-- 目标自动补全（数据源 = 既有 rule-index 索引单例，WAF 步骤
                             首次进入惰性取一次）：按 id 数字前缀或 msg 关键字过滤，
                             ≤50 条建议（901 初始化规则不出建议，后端硬拒）；选中回填
                             规则 id。索引缺失/加载失败时 search 恒空建议——输入框
                             退化为纯自由输入不阻塞（组号两位/6 位 ID/遗留文件名等
                             目录外形态本就允许手输，后端 SecRuleRemoveById 兼容）。
                             不能映射为已知值的存量 target 仍由右侧 ghost 标签兜底，
                             可清除（×）。 -->
                        <el-autocomplete
                          v-model="row.target"
                          :fetch-suggestions="fetchExclusionSuggestions"
                          size="small"
                          clearable
                          :disabled="crsFieldsOff || isReadOnly"
                          popper-class="crs-rule-popper"
                          :placeholder="t('app.security.policies.waf.exclusionSearchPlaceholder')"
                          class="exclusion-target-select"
                        >
                          <template #default="{ item }">
                            <div class="crs-rule-suggestion" :title="`${item.value} — ${item.fullMsg}`">
                              <span class="crs-rule-suggestion-id">{{ item.value }}</span>
                              <span class="crs-rule-suggestion-desc">{{ t('app.security.policies.waf.suggestionDesc', { label: item.label, file: item.file }) }}</span>
                            </div>
                          </template>
                        </el-autocomplete>
                        <el-tag
                          v-if="exclusionRowGhostLabel(row.target) !== ''"
                          size="small"
                          type="info"
                          effect="plain"
                          class="exclusion-target-ghost"
                          :title="exclusionRowGhostTitle(row.target)"
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
                          <el-radio value="all">{{ t('app.security.policies.waf.scopeAll') }}</el-radio>
                          <el-radio value="ip">{{ t('app.security.policies.waf.scopeIp') }}</el-radio>
                          <el-radio value="list">{{ t('app.security.policies.waf.scopeList') }}</el-radio>
                          <el-radio value="path">{{ t('app.security.policies.waf.scopePath') }}</el-radio>
                        </el-radio-group>
                        <!-- 条件控件内联于 radios 之后：all → 灰字短提示（自然宽、不预留
                             布局空间）/ ip → 标签输入 / list → 列表多选（紧凑宽）/
                             path → URI 前缀输入（@beginsWith 前缀匹配，≤256 字符）；
                             切换只影响 radios 之后的空位，radios 与目标输入位置不抖动 -->
                        <el-select
                          v-if="row.scope === 'ip'"
                          v-model="row.ips"
                          size="small"
                          multiple
                          filterable
                          allow-create
                          default-first-option
                          :disabled="crsFieldsOff || isReadOnly"
                          :placeholder="t('app.security.policies.common.ipEntryPlaceholder')"
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
                          :placeholder="t('app.security.policies.waf.ipListSelectPlaceholder')"
                          class="exclusion-scope-control-list"
                        >
                          <el-option-group v-if="customIpLists.length > 0" :label="t('app.security.policies.common.groupCustom')">
                  <el-option v-for="l in customIpLists" :key="l.id" :label="t('app.security.policies.common.listWithNameCount', { name: l.name, count: l.entry_count })" :value="l.id" />
                </el-option-group>
                        </el-select>
                        <el-input
                          v-else-if="row.scope === 'path'"
                          v-model="row.path"
                          size="small"
                          :disabled="crsFieldsOff || isReadOnly"
                          maxlength="256"
                          :placeholder="t('app.security.policies.waf.pathPlaceholder')"
                          class="exclusion-scope-control-path"
                        />
                        <span v-else class="exclusion-scope-all">{{ t('app.security.policies.waf.scopeAllHint') }}</span>
                      </div>
                    </template>
                  </el-table-column>
                  <el-table-column label="" width="60" align="center">
                    <template #default="{ $index }">
                      <el-button link type="danger" size="small" :disabled="crsFieldsOff || isReadOnly" @click="removeExcludedRule($index)">{{ t('app.security.policies.common.delete') }}</el-button>
                    </template>
                  </el-table-column>
                </el-table>
                <div class="exclusion-toolbar">
                  <el-button size="small" type="primary" plain :disabled="crsFieldsOff || isReadOnly || crsExcludedRows.length >= CRS_EXCLUDED_MAX_ROWS" @click="addExcludedRule">{{ t('app.security.policies.waf.addExclusion') }}</el-button>
                  <el-tag size="small" type="info" effect="plain" class="exclusion-count">{{ crsExcludedRows.length }}/{{ CRS_EXCLUDED_MAX_ROWS }}</el-tag>
                </div>
                <div class="form-tip-line">{{ t('app.security.policies.waf.exclusionTableTip') }}</div>
              </template>
            
              </div></el-form-item>
            <el-form-item v-if="blockingEvalExclusionAlert"><div class="info-note-bar"><span class="info-note-desc">{{ t('app.security.policies.waf.blockingEvalWarn') }}</span></div>
            </el-form-item>
            <el-form-item :label="t('app.security.policies.waf.customRulesLabel')">
              <el-select v-model="selectedCustomRules" :disabled="form.mode === 'off'" multiple filterable :placeholder="t('app.security.policies.waf.customRulesPlaceholder')" style="width: 100%">
                <el-option v-for="rule in allCustomRules" :key="rule.id" :label="rule.name" :value="rule.id" />
              </el-select>
              <div class="form-tip-line">{{ t('app.security.policies.waf.customRulesTip') }}<AccessibleLink type="primary" @click="goToCustomRulesPage">{{ t('app.security.policies.common.goCreateEdit') }}</AccessibleLink></div>
            </el-form-item>
          </el-form>
        </div>
        <!-- Step 2: IP 访问控制 -->
        <div v-show="currentStep === WIZARD_STEP.IP_ACL" class="step-content">
          <div class="stage-projection-bar">
            <span class="stage-projection-desc">{{ t('app.security.policies.acl.projection') }}</span>
            <div class="stage-projection-rules">
              <span v-if="boundRules.length === 0" class="stage-projection-empty">{{ t('app.security.policies.bind.none') }}</span>
              <span v-else class="stage-projection-empty">{{ t('app.security.policies.bind.appliesTo', { n: boundRules.length }) }}</span>
            </div>
          </div>
          <el-divider content-position="left" class="acl-divider">{{ t('app.security.policies.acl.divider') }}</el-divider>
          <el-form :model="form" :label-width="$flw('100px')" :disabled="formFrozen">
            <el-form-item :label="t('app.security.policies.common.enableLabel')">
              <el-switch v-model="form.ip_acl_enabled" />
            </el-form-item>
            <template v-if="form.ip_acl_enabled">
              <el-form-item :label="t('app.security.policies.common.modeLabel')" for="radio---12">
                <input type="text" id="radio---12" aria-hidden="true" tabindex="-1" autocomplete="off" style="display:none">
                <el-radio-group v-model="form.ip_acl_mode" :aria-label="t('app.security.policies.acl.modeAria')">
                  <el-radio value="deny">{{ t('app.security.policies.acl.modeDeny') }}</el-radio>
                  <el-radio value="allow">{{ t('app.security.policies.acl.modeAllow') }}</el-radio>
                  <!-- 历史 绕过 策略仅作展示，不再提供新选 -->
                  <el-radio v-if="form.ip_acl_mode === '绕过'" value="绕过">{{ t('app.security.policies.acl.modeBypass') }}</el-radio>
                </el-radio-group>
              </el-form-item>
              <el-form-item :label="aclListLabel">
                <div class="acl-inline-row">
                  <el-select v-model="ipACLList" multiple filterable allow-create default-first-option :placeholder="t('app.security.policies.common.ipEntryPlaceholder')" class="acl-inline-select" />
                  <el-button v-if="!isReadOnly" link type="primary" class="acl-extract-btn" :disabled="ipACLList.length === 0" @click="openExtractDialog('acl')">{{ t('app.security.policies.common.extractAsList') }}</el-button>
                </div>
                <div class="form-tip-line">{{ aclListTip }}</div>
              </el-form-item>
              <el-form-item :label="t('app.security.policies.common.refListLabel')">
                <el-select v-model="ipACLListRefs" multiple filterable :placeholder="t('app.security.policies.common.refListPlaceholder')" style="width: 100%">
                  <el-option-group v-if="form.ip_acl_mode === 'deny' && builtinIpLists.length > 0" :label="t('app.security.policies.common.groupBuiltin')">
                  <el-option v-for="l in builtinIpLists" :key="l.id" :label="t('app.security.policies.common.listWithNameCount', { name: l.name, count: l.entry_count })" :value="l.id" />
                </el-option-group>
                <el-option-group v-if="customIpLists.length > 0" :label="t('app.security.policies.common.groupCustom')">
                  <el-option v-for="l in customIpLists" :key="l.id" :label="t('app.security.policies.common.listWithNameCount', { name: l.name, count: l.entry_count })" :value="l.id" />
                </el-option-group>
                </el-select>
                <div v-if="showAclRefHint" class="form-tip-line">{{ aclRefHint }}</div>
                <div class="form-tip-line">{{ t('app.security.policies.acl.refTip') }}</div>
              </el-form-item>
              <!-- 访问控制区地址级冲突实时警告（本区条目：ACL 列表 + 黑名单）：
                   el-form 直接子级（2026-10-03 模板归一），缩进由
                   提示条在表单项内自然对齐控件列（EP label-width 布局，零 CSS 覆盖） -->
              <el-form-item v-if="aclSectionAlert"><div class="info-note-bar"><span class="info-note-desc">{{ aclSectionAlert }}</span></div>
              </el-form-item>
            </template>
          </el-form>
          <el-divider content-position="left" class="acl-divider">{{ t('app.security.policies.geo.divider') }}</el-divider>
          <el-form :model="form" :label-width="$flw('100px')" :disabled="formFrozen">
            <el-form-item :label="t('app.security.policies.common.enableLabel')">
              <!-- 开关即生效状态：关闭提交 geoip_mode='off'（后端零发射），名单
                   保留不清单（重开即复用）；从 off 重开时控制模式回落 deny。 -->
              <el-switch v-model="form.geoip_enabled" @change="onGeoipEnabledChange" />
            </el-form-item>
            <template v-if="form.geoip_enabled">
              <!-- （裁决）：披露 IPv6/不可解析客户端语义——
                   fail-closed 设计下它们按「海外」处理。 -->
              <el-form-item><div class="info-note-bar"><span class="info-note-desc">{{ t('app.security.policies.geo.ipv4Note') }}</span></div>
              </el-form-item>
              <el-form-item :label="t('app.security.policies.common.modeLabel')" for="radio---13">
                <input type="text" id="radio---13" aria-hidden="true" tabindex="-1" autocomplete="off" style="display:none">
                <el-radio-group v-model="form.geoip_mode" :aria-label="t('app.security.policies.geo.modeAria')">
                  <el-radio value="deny">{{ t('app.security.policies.geo.modeDeny') }}</el-radio>
                  <el-radio value="allow">{{ t('app.security.policies.geo.modeAllow') }}</el-radio>
                </el-radio-group>
              </el-form-item>
              <el-form-item :label="t('app.security.policies.geo.regionLabel')">
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
                  :placeholder="t('app.security.policies.geo.regionPlaceholder')"
                  style="width: 100%"
                />
                <div class="form-tip-line">{{ t('app.security.policies.geo.regionTip') }}</div>
                <!-- 加载失败显性化+重试；已保存的地域值保留不清空-->
                <div v-if="regionsError" class="form-tip-line">
                  <el-text type="danger" size="small">{{ t('app.security.policies.geo.loadFailed') }}</el-text>
                  <AccessibleLink type="primary" size="small" @click="fetchRegions">{{ t('app.security.policies.common.retry') }}</AccessibleLink>
                </div>
              </el-form-item>
              <!-- v2.3.8 爬虫豁免（方案 B）：已验证搜索引擎/AI 爬虫跳过地域拦截。
                   验证=UA+PTR 双跳（360=官方 IP 段），伪装 UA 独立记「爬虫伪装」事件。 -->
              <el-form-item :label="t('app.security.policies.geo.crawlerLabel')">
                <el-switch v-model="form.geoip_crawler_exempt" />
                <template v-if="form.geoip_crawler_exempt">
                  <el-checkbox-group v-model="form.geoip_crawler_engines" style="margin-left: 12px">
                    <el-checkbox v-for="e in crawlerEngineOptions" :key="e.id" :value="e.id">{{ e.name }}</el-checkbox>
                  </el-checkbox-group>
                  <div class="form-tip-line">{{ t('app.security.policies.geo.crawlerTip') }}</div>
                  <!-- 空选=全部引擎（后端空集语义），必须显性说明——否则
                       用户以为「全不选=不豁免」，实际是全豁免 -->
                  <div v-if="form.geoip_crawler_engines.length === 0" class="form-tip-line">
                    <el-text type="warning" size="small">{{ t('app.security.policies.geo.crawlerNoneWarn') }}</el-text>
                  </div>
                </template>
              </el-form-item>
            </template>
          </el-form>
        </div>
        <!-- 阶段 2 · CC 防护：突刺/4xx/多UA 触发、人机挑战与豁免（配额限流已下线） -->
        <div v-show="currentStep === WIZARD_STEP.RATE_LIMIT && typeAllowsCC" class="step-content">
          <div class="stage-projection-bar">
            <span class="stage-projection-desc">{{ t('app.security.policies.human.projection') }}</span>
            <div class="stage-projection-rules">
              <span class="stage-projection-empty">{{ boundRules.length > 0 ? t('app.security.policies.bind.appliesTo', { n: boundRules.length }) : t('app.security.policies.bind.none') }}</span>
            </div>
          </div>
          <el-form :model="form" :label-width="$flw('100px')" :disabled="formFrozen">
            <el-form-item :label="t('app.security.policies.human.modeLabel')">
              <el-radio-group v-model="form.human_verify_mode">
                <el-radio-button value="off">{{ t('app.security.policies.human.modeOff') }}</el-radio-button>
                <el-radio-button value="auto">{{ t('app.security.policies.human.modeAuto') }}</el-radio-button>
                <el-radio-button value="force">{{ t('app.security.policies.human.modeForce') }}</el-radio-button>
              </el-radio-group>
              <div class="form-tip-line">{{ t('app.security.policies.human.modeTip') }}</div>
              <div v-if="form.human_verify_mode === 'auto' && !form.cc_detect_enabled" class="form-tip-line">
                <el-text type="warning" size="small">{{ t('app.security.policies.human.autoNeedsCc') }}</el-text>
              </div>
            </el-form-item>
            <template v-if="form.human_verify_mode !== 'off'">
              <el-form-item :label="t('app.security.policies.human.typeLabel')">
                <el-radio-group v-model="form.human_verify_type">
                  <el-radio-button value="slider">{{ t('app.security.policies.human.typeSlider') }}</el-radio-button>
                  <el-radio-button value="js">{{ t('app.security.policies.human.typeJs') }}</el-radio-button>
                </el-radio-group>
                <div class="form-tip-line">{{ t('app.security.policies.human.typeTip') }}</div>
              </el-form-item>
              <el-form-item :label="t('app.security.policies.human.ttlLabel')">
                <el-input-number v-model="form.human_verify_ttl" :min="1" :max="1440" style="width: 120px" />
                <span class="form-tip-inline">{{ t('app.security.policies.human.ttlTip') }}</span>
              </el-form-item>
              <el-form-item :label="t('app.security.policies.human.exemptPathsLabel')">
                <el-select v-model="form.human_exempt_paths" multiple filterable allow-create default-first-option :placeholder="t('app.security.policies.human.exemptPathsTip')" style="width: 100%" />
                <div class="form-tip-line">{{ t('app.security.policies.human.exemptIpGuide') }}</div>
              </el-form-item>
              <template v-if="form.human_verify_mode !== 'force'">
              <el-divider>{{ t('app.security.policies.human.ccSection') }}</el-divider>
              <el-form-item :label="t('app.security.policies.human.ccEnabledLabel')">
                <el-switch v-model="form.cc_detect_enabled" />
                <span class="form-tip-inline">{{ t('app.security.policies.human.ccEnabledTip') }}</span>
              </el-form-item>
              <template v-if="form.cc_detect_enabled">

                <el-form-item :label="t('app.security.policies.human.ccRpsLabel')">
                  <el-input-number v-model="form.cc_rps_limit" :min="1" :max="100000" style="width: 120px" />
                  <span class="form-tip-inline">{{ t('app.security.policies.human.ccRpsPer') }}</span>
                  <el-input-number v-model="form.cc_rps_window" :min="1" :max="3600" style="width: 100px; margin-left: 6px" />
                  <span class="form-tip-inline">{{ t('app.security.policies.human.ccRpsSec') }}</span>
                </el-form-item>
                <el-form-item :label="t('app.security.policies.human.cc4xxLabel')">
                  <el-input-number v-model="form.cc_4xx_ratio" :min="0" :max="100" style="width: 110px" />
                  <span class="form-tip-inline">%</span>
                  <span class="form-tip-inline">{{ t('app.security.policies.human.cc4xxTip') }}</span>
                </el-form-item>
                <el-form-item :label="t('app.security.policies.human.ccSessionLabel')">
                  <el-switch v-model="form.cc_session_anomaly" />
                  <el-input-number v-if="form.cc_session_anomaly" v-model="form.cc_session_ua_threshold" :min="1" :max="100" style="width: 100px; margin-left: 10px" />
                  <span v-if="form.cc_session_anomaly" class="form-tip-inline">{{ t('app.security.policies.human.ccSessionTip') }}</span>
                </el-form-item>
              </template>
              </template>
              <div v-else class="form-tip-line">{{ t('app.security.policies.human.forceIgnoresCc') }}</div>
            </template>
          </el-form>
        </div>

        <!-- Step 4: 关联规则 -->
        <div v-show="currentStep === WIZARD_STEP.BINDINGS" class="step-content">
          <el-form :model="form" :label-width="$flw('100px')" :disabled="formFrozen">
            <el-form-item :label="t('app.security.policies.bind.boundLabel')">
              <div class="rule-bind-field">
                <div class="rule-picker-trigger" role="button" tabindex="0" :class="{ 'is-locked': isReadOnly }" @click="!isReadOnly && openRulePicker()" @keydown.enter.prevent="activateOnce($event, () => !isReadOnly && openRulePicker())" @keydown.space.prevent="activateOnce($event, () => !isReadOnly && openRulePicker())">
                  <span :class="{ 'rule-picker-placeholder': boundRules.length === 0 }">{{ boundRules.length > 0 ? t('app.security.policies.common.selectedCount', { n: boundRules.length }) : t('app.security.policies.bind.pickPlaceholder') }}</span>
                  <el-icon class="rule-picker-arrow"><ArrowDown /></el-icon>
                </div>
                <div v-if="boundRuleWarnPerf" class="info-note-bar"><span class="info-note-desc">{{ t('app.security.policies.bind.perfWarn') }}</span></div>
                <div v-if="hasTcpBoundRule" class="info-note-bar"><span class="info-note-desc">{{ t('app.security.policies.bind.tcpWarn') }}</span></div>
                <div v-if="boundRuleRows.length > 0" class="bound-rule-list">
                  <div v-for="row in boundRuleRows" :key="row.caddyId" class="bound-rule-row">
                    <div class="bound-rule-head">
                      <el-tag v-if="row.protocol === 'tcp'" size="small" effect="plain" class="proto-tcp-tag rule-proto-badge">TCP</el-tag>
                      <el-tag v-else size="small" type="primary" effect="plain" class="rule-proto-badge">HTTP</el-tag>
                      <span class="bound-rule-name">{{ row.name }}</span>
                      <span class="bound-rule-meta">{{ row.domain || '-' }}:{{ row.listenPort }}</span>
                      <!-- 策略顺序=执行序（用户裁定）：上移/下移调整本策略在该规则绑定链中的
                           位置，只暂存（bindingOrderEdits），随「保存」按新序整链提交；
                           与页面显示无关（拦截页按触发策略归因，见拦截页步骤注记）。 -->
                      <span class="bound-rule-order">
                        <el-tag v-if="bindingOrderPending(row.caddyId)" type="primary" size="small" effect="plain" disable-transitions class="bound-rule-order-tag">{{ t('app.security.policies.bind.orderPending') }}</el-tag>
                        <el-button v-if="!isReadOnly" size="small" link :disabled="saving || !canMoveSelf(row.caddyId, -1)" @click="moveSelfInChain(row.caddyId, -1)">{{ t('app.security.policies.common.moveUp') }}</el-button>
                        <el-button v-if="!isReadOnly" size="small" link :disabled="saving || !canMoveSelf(row.caddyId, 1)" @click="moveSelfInChain(row.caddyId, 1)">{{ t('app.security.policies.common.moveDown') }}</el-button>
                      </span>
                      <el-button v-if="!isReadOnly" size="small" link type="danger" class="bound-rule-remove" @click="removeBoundRule(row.caddyId)">{{ t('app.security.policies.common.remove') }}</el-button>
                    </div>
                    <!-- 完整绑定链（执行序，1-based 序号）+ 本策略落点：顺序即保存后的执行序
                         （阶段 0 信任恒先于拦截判定，固定在前）。每条规则的拦截页生效状态
                         统一展示在「拦截页面」配置项说明区。 -->
                    <div class="bound-rule-chain">
                      <span
                        v-for="(entry, idx) in row.chain"
                        :key="entry.policyId ?? 'self'"
                        class="binding-order-chip"
                        :class="['stage-' + chainEntryStageKey(entry), { 'is-self': entry.isSelf, 'is-disabled': !entry.enabled }]"
                      >{{ chainChipText(entry, idx) }}</span>
                    </div>
                  </div>
                </div>
                <!-- 标准提示框（用户验收裁定：禁裸文本长说明）+ 归属汇总行（单源派生：
                     逐条整句收敛为一条汇总） -->
                <div class="info-note-bar"><span class="info-note-desc">{{ t('app.security.policies.bind.orderNote') }}</span></div>
                <div class="info-note-bar"><span class="info-note-desc">{{ bindingsSummaryLine }}</span></div>
              </div>
            </el-form-item>
          </el-form>
        </div>

        <!-- Step: 拦截页（阶段 1/2/3 策略可配；阶段 2 状态码恒 429——步内隐藏状态码项） -->
        <div v-show="currentStep === WIZARD_STEP.BLOCK_PAGE" class="step-content">
          <div class="stage-projection-bar">
            <span class="stage-projection-desc">{{ t('app.security.policies.bp.projection') }}</span>
            <div class="stage-projection-rules">
              <span v-if="boundRules.length > 0" class="stage-projection-empty">{{ t('app.security.policies.bind.relatedCount', { n: boundRules.length }) }}</span>
            </div>
          </div>
          <el-form :model="form" :label-width="$flw('100px')" :disabled="formFrozen">
            <el-form-item v-if="editorPolicyType === 'stage2'" :label="t('app.security.policies.human.ccResponseLabel')">
              <el-radio-group v-model="form.cc_response">
                <el-radio-button value="verify">{{ t('app.security.policies.human.ccResponseVerify') }}</el-radio-button>
                <el-radio-button value="ban">{{ t('app.security.policies.human.ccResponseBan') }}</el-radio-button>
              </el-radio-group>
              <div class="form-tip-line">{{ t('app.security.policies.human.ccResponseTip') }}</div>
            </el-form-item>
            <el-form-item v-if="editorPolicyType === 'stage2' && form.cc_response !== 'ban'" :label="t('app.security.policies.human.challengePageLabel')">
              <el-tag type="info" size="small" effect="plain">{{ t('app.security.policies.human.challengePageBuiltin') }}</el-tag>
              <div class="form-tip-line">{{ t('app.security.policies.human.challengePageTip') }}</div>
            </el-form-item>
            <el-form-item v-if="editorPolicyType !== 'stage2' || form.cc_response === 'ban'" :label="t('app.security.policies.bp.pageLabel')">
              <el-select v-model="form.block_page_id" :placeholder="t('app.security.policies.bp.pagePlaceholder')" style="width: 100%">
                <el-option :value="0" :label="t('app.security.policies.bp.noPageDefault')" />
                <el-option v-for="p in blockPages" :key="p.id" :label="pageLabel(p)" :value="p.id" />
              </el-select>
              <div v-if="form.block_page_id === 0" class="form-tip-line">{{ t('app.security.policies.bp.noPageTipDefault') }}</div>
              <div v-else class="form-tip-line">{{ t('app.security.policies.bp.manageTip') }}<AccessibleLink type="primary" @click="goToBlockPagesPage">{{ t('app.security.policies.common.goCreateEdit') }}</AccessibleLink></div>
              <!-- 归属汇总卡（用户验收裁定）：逐条重复提示收敛为单源汇总——主行 +
                   例外分面（限流/TCP/兜底差异，仅存在才渲染）+ 能力门行；
                   数据源复用绑定列表与 capableAttributions 单源，不平行实现。 -->
              <div v-if="blockPageSummary && (editorPolicyType !== 'stage2' || form.cc_response === 'ban')" class="block-page-summary">
                <div v-for="line in blockPageSummary.lines" :key="line.text" class="info-note-bar block-page-summary-line" :class="`is-${line.tone}`">
                  <el-icon class="block-page-summary-icon" :size="14">
                    <CircleCheckFilled v-if="line.tone === 'active'" />
                    <WarningFilled v-else-if="line.tone === 'warning'" />
                    <InfoFilled v-else />
                  </el-icon>
                  <span class="info-note-desc">{{ line.text }}</span>
                </div>
              </div>
            </el-form-item>
            <el-form-item v-if="editorPolicyType !== 'stage2' || form.cc_response === 'ban'" :label="t('app.security.policies.bp.statusLabel')">
              <el-select v-model="form.block_status_code" style="width: 200px" :disabled="form.block_page_id === 0">
                <el-option v-for="opt in STAGE_BLOCK_STATUS_OPTIONS" :key="opt.value" :value="opt.value" :label="opt.label" />
              </el-select>
              <span class="form-tip-inline">{{ form.block_page_id === 0 ? t('app.security.policies.bp.statusTipNoPage') : t('app.security.policies.bp.statusTipDefault') }}</span>
            </el-form-item>

            <!-- 策略级响应方式：拦截页设置恒为双档（HTML + JSON），具体返回哪种在这里选。 -->
            <el-form-item v-if="editorPolicyType !== 'stage2' || form.cc_response === 'ban'" :label="t('app.security.policies.bp.responseLabel')">
              <el-radio-group v-model="form.block_response_mode" :disabled="form.block_page_id === 0">
                <el-radio-button value="auto">{{ t('app.security.policies.bp.responseAuto') }}</el-radio-button>
                <el-radio-button value="html">{{ t('app.security.policies.bp.responseHtml') }}</el-radio-button>
                <el-radio-button value="json">{{ t('app.security.policies.bp.responseJson') }}</el-radio-button>
              </el-radio-group>
              <div class="form-tip-line">{{ t('app.security.policies.bp.responseTip') }}</div>
            </el-form-item>
          </el-form>
        </div>

        <!-- Step: 配置预览（三阶段投影·策略视角——与规则侧流程抽屉共用 buildStageModel 投影） -->
        <div v-show="currentStep === WIZARD_STEP.PREVIEW" class="step-content">
          <div class="preview-meta">
            <span class="preview-meta-name">{{ form.name || '-' }}</span>
            <el-tag :type="editorPolicyType === 'mixed' ? 'warning' : 'primary'" size="small" effect="plain">{{ POLICY_TYPE_LABELS[editorPolicyType] }}</el-tag>
            <el-tag :type="form.enabled ? 'success' : 'info'" size="small" effect="light">{{ form.enabled ? t('app.security.policies.status.enabled') : t('app.security.policies.status.disabled') }}</el-tag>
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
                <div v-if="!stage.enabled" class="preview-stage-empty">{{ t('app.security.policies.common.notEnabled') }}</div>
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
          <!-- 影响范围与执行序：与上方阶段卡片同构（标题 + 键值行 + 脚注）。 -->
          <section class="preview-stage-card preview-bindings-card">
            <DialogSectionHeader :title="t('app.security.policies.preview.rulesTitle')" :description="boundRules.length > 0 ? t('app.security.policies.preview.rulesCount', { n: boundRules.length }) : t('app.security.policies.preview.rulesNone')" />
            <div class="dialog-panel">
              <div class="preview-policy-rows">
                <div class="preview-row">
                  <span class="preview-row-label">{{ t('app.security.policies.preview.scopeLabel') }}</span>
                  <span class="preview-row-detail">{{ boundRules.length > 0 ? t('app.security.policies.preview.scopeBound', { n: boundRules.length }) : t('app.security.policies.preview.scopeUnbound') }}</span>
                </div>
                <div v-if="orderEditedRules.length > 0" class="preview-row">
                  <span class="preview-row-label">{{ t('app.security.policies.preview.saveLabel') }}</span>
                  <span class="preview-row-detail">{{ t('app.security.policies.preview.orderUpdate', { n: orderEditedRules.length }) }}</span>
                </div>
              </div>
            </div>
          </section>
        </div>
      </div>

      <template #footer>
        <div class="wizard-footer">
          <el-button v-if="hasPreviousStep" :disabled="saving" @click="prevStep">
            <el-icon><ArrowLeft /></el-icon>{{ t('app.security.policies.common.prevStep') }}
          </el-button>
          <el-button v-if="hasNextStep" type="primary" :disabled="saving" @click="nextStep">
            {{ t('app.security.policies.common.nextStep') }}<el-icon><ArrowRight /></el-icon>
          </el-button>
          <el-button v-if="currentStep === WIZARD_STEP.PREVIEW" type="primary" :disabled="isReadOnly" :loading="saving" @click="handleSave">
            <span>{{ t('app.security.policies.common.savePolicy') }}</span><el-icon style="margin-left: 6px;"><Check /></el-icon>
          </el-button>
        </div>
      </template>
    </el-dialog>

    <!-- 关联规则选择器 -->
    <el-dialog v-model="rulePickerVisible" class="dialog-body-inset" width="min(640px, 90vw)" append-to-body>
      <template #header>
        <DialogHeader :icon="Connection" :title="t('app.security.policies.picker.title')" />
      </template>
      <div class="rule-picker-toolbar">
        <el-input v-model="pickerSearch" :placeholder="t('app.security.policies.picker.searchPlaceholder')" clearable :prefix-icon="Search" class="rule-picker-search" />
        <!-- 协议筛选（默认 HTTP）：TCP（阶段 0/1）放开后候选混排，默认档保持既有 HTTP 选择视野 -->
        <el-select v-model="pickerProtoFilter" class="rule-picker-proto-filter" :aria-label="t('app.security.policies.picker.protoAria')">
          <el-option :label="t('app.security.policies.common.all')" value="all" />
          <el-option label="HTTP" value="http" />
          <el-option label="TCP" value="tcp" />
        </el-select>
      </div>
      <DialogSectionHeader :title="t('app.security.policies.picker.availableTitle')" />
      <div class="dialog-panel">
        <div class="rule-picker-header">
          <el-checkbox
            :model-value="pickerSelectAllChecked"
            :indeterminate="pickerSelectAllIndeterminate"
            :disabled="pickerSelectableRules.length === 0"
            @change="handlePickerSelectAll"
          >{{ t('app.security.policies.common.selectAll') }}</el-checkbox>
          <span class="rule-picker-header-meta">{{ t('app.security.policies.picker.filteredCount', { n: pickerFilteredRules.length }) }}</span>
        </div>
        <div class="rule-picker-list">
          <el-checkbox-group v-model="pickerSelected">
            <div v-for="rule in pickerPagedRules" :key="rule.caddy_id" class="rule-picker-item">
              <el-checkbox :value="rule.caddy_id" :disabled="pickerMeta(rule).blockReason !== ''">
                <!-- 行协议徽标在规则名左（用户裁定）：TCP 青/HTTP 蓝 = 事件日志方法列同款 el-tag 单源 -->
                <el-tag v-if="rule.protocol === 'tcp'" size="small" effect="plain" class="proto-tcp-tag rule-picker-proto">TCP</el-tag>
                <el-tag v-else size="small" type="primary" effect="plain" class="rule-picker-proto">HTTP</el-tag>
                <span class="rule-picker-name">{{ rule.name }}</span>
                <span class="rule-picker-meta">{{ rule.domain || '-' }}:{{ rule.listen_port }}</span>
              </el-checkbox>
              <!-- 每条候选规则展示当前绑定链（rank 序=执行序，1-based）与本策略落点；
                   后端必然拒绝的形态（绑定条数上限 / 阶段 2 限流唯一门）在选择阶段
                   禁用并逐条说明原因——冲突在整批提交时会让本片全部失败。 -->
              <div class="rule-binding-preview">
                <span v-if="pickerMeta(rule).blockReason" class="rule-binding-limit">{{ pickerMeta(rule).blockReason }}</span>
                <template v-else>
                  <span
                    v-for="(entry, idx) in pickerMeta(rule).chain"
                    :key="entry.policyId ?? 'self'"
                    class="binding-order-chip"
                    :class="['stage-' + chainEntryStageKey(entry), { 'is-self': entry.isSelf, 'is-disabled': !entry.enabled }]"
                  >{{ chainChipText(entry, idx) }}</span>
                  <!-- 阶段 0 排位语义：信任 IP 在任何策略判定前直达上游/进入检测，与绑定顺序无关 -->
                  <span v-if="editorPolicyType !== 'stage0'" class="rule-binding-landing">{{ t('app.security.policies.picker.selfPos', { n: pickerMeta(rule).selfPos }) }}</span>
                </template>
              </div>
            </div>
          </el-checkbox-group>
          <el-empty v-if="pickerPagedRules.length === 0" :description="t('app.security.policies.picker.noMatch')" :image-size="60" />
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
          <span class="picker-count">{{ t('app.security.policies.common.selectedCount', { n: pickerSelected.length }) }}</span>
          <div class="picker-footer-buttons">
            <el-button :disabled="pickerSelected.length === 0" @click="pickerSelected = []">{{ t('app.security.policies.common.clear') }}</el-button>
            <el-button @click="rulePickerVisible = false">{{ t('app.security.policies.common.cancel') }}</el-button>
            <el-button type="primary" @click="confirmRulePicker">{{ t('app.security.policies.common.confirm') }}</el-button>
          </div>
        </div>
      </template>
    </el-dialog>

    <el-dialog v-model="extractDialogVisible" class="dialog-body-inset" width="min(480px, 92vw)" append-to-body :close-on-click-modal="false" :close-on-press-escape="!extracting" :show-close="!extracting">
      <template #header>
        <DialogHeader :icon="Document" :title="t('app.security.policies.extract.title')" :subtitle="t('app.security.policies.extract.subtitle')" />
      </template>
      <div class="info-note-bar"><span class="info-note-desc">{{ t('app.security.policies.extract.note') }}</span></div>
      <el-form :label-width="$flw('80px')" @submit.prevent>
        <el-form-item :label="t('app.security.policies.extract.sourceLabel')" for="extract-source-static">
          <input type="text" id="extract-source-static" aria-hidden="true" tabindex="-1" autocomplete="off" style="display:none">
          <span class="extract-source">{{ extractSide === 'acl' ? aclListLabel : t('app.security.policies.stage0.trustIpLabel') }}{{ t('app.security.policies.extract.inlineCount', { n: extractSourceEntries.length }) }}</span>
        </el-form-item>
        <el-form-item :label="t('app.security.policies.extract.nameLabel')" required>
          <el-input v-model="extractForm.name" :placeholder="t('app.security.policies.extract.namePlaceholder')" maxlength="50" show-word-limit />
        </el-form-item>
        <el-form-item :label="t('app.security.policies.extract.categoryLabel')">
          <el-select v-model="extractForm.category" allow-create filterable default-first-option :placeholder="t('app.security.policies.extract.categoryPlaceholder')" style="width: 100%">
            <el-option v-for="c in IP_LIST_CATEGORIES" :key="c" :label="ipListCategoryLabel(c)" :value="c" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="extractDialogVisible = false" :disabled="extracting">{{ t('app.security.policies.common.cancel') }}</el-button>
        <el-button type="primary" :loading="extracting" @click="confirmExtract">{{ t('app.security.policies.extract.confirm') }}</el-button>
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
      @saved="onBindRulesSaved"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed, watch } from 'vue'
import { ipListCategoryLabel } from '@/utils/ipListCategoryLabel'
import { cityEnName } from '@/utils/cityEnNames'
import { useI18n } from 'vue-i18n'
import { Plus, Lock, InfoFilled, CircleCheckFilled, Connection, Odometer, Link, Check, ArrowLeft, ArrowRight, ArrowDown, Search, WarningFilled, Document, View } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import type { CascaderOption, CascaderProps, LazyLoad } from 'element-plus'
import { request, ApiRequestError, mfaAwareSuccess } from '@/utils/api'
import { showSaveResult } from '@/utils/saveResult'
import { CADDY_APPLY_FAILED_MARKER, mergeBulkResults } from '@/utils/bulkApplyResult'
import { isValidCidr } from '@/utils/ipAddress'
import { popperViewportSafe } from '@/utils/popper'
import { formatDate } from '@/utils/date'
import { useAuthStore } from '@/stores/auth'
import { useCrsRuleIndex, useCrsRuleDirectory, issueCrsIndexSession, crsRuleLabelView, parseCrsExcludedRules, CRS_EXCLUDED_MAX_ROWS } from '@/composables/useCrsRuleIndex'
import { useClampedPagination } from '@/composables/useClampedPagination'
import type { CrsExcludedRow, CrsRuleOptionView, CrsDirectorySuggestion } from '@/composables/useCrsRuleIndex'
import type { APIResponse, UserListItem } from '@/types'
import SecurityBindingEditor from '@/components/SecurityBindingEditor.vue'
import DialogHeader from '@/components/DialogHeader.vue'
import DialogSectionHeader from '@/components/DialogSectionHeader.vue'
import AccessibleLink from '@/components/common/AccessibleLink.vue'
import { crsCategoryLabel } from '@/utils/crsCategories.ts'
import { builtinBlockPageLabel, type BlockPageLike } from '@/utils/builtinBlockPages'
import { POLICY_TYPE_LABELS, POLICY_TYPE_SHORT_LABELS, STAGE_BLOCK_STATUS_OPTIONS, addressAllowDenyConflictText, blockPageMissing, blockPageStageCanIntercept, buildStageModel, chunkForBulk, customRuleCanBlockInMode, entriesIntersect, ensureSharedEntries, formatAclModeDetail, hasGeoIPControl, hasIPACLControl, hasOtherStage2Binding, hasStage3Features, hasTrustEntries, inferPolicyType, normalizePolicyType, mergeChainOrder, mergeIpEntryCount, mergeIpEntryValues, normalizePolicyChainOrder, parseCrsFilename, parseIPList, parseRefIds, parseUnknownIds, parseUnknownStrings, pickDefaultPolicyTab, sharedEntriesCache, subscribeSharedEntriesCache, trustHitMode, wafModeLabel, IP_LIST_CATEGORIES, MAX_POLICIES_PER_RULE, policySupportsTcp, TCP_BIND_UNSUPPORTED_REASON, SECURITY_BULK_LIMITS, resolveBlockPageAttribution, type BlockPageAttribution, type BlockPageChainPolicy, type BlockPageStage } from '@/utils/securityStages'
import type { RuleStageModel, SecurityPolicyType, SecurityStagePolicy, SecurityStageCustomRule, CrsRuleFileOption } from '@/utils/securityStages'
import { fetchAllCrsRuleFiles } from '@/utils/crsRuleFiles'
import { updaterName } from '@/utils/updaterName'
import { hasOwn } from '@/utils/hasOwn'
import { SECURITY_DESCRIPTION_MAX_RUNES, SECURITY_NAME_MAX_RUNES } from '@/utils/securityLimits'
import { CRS_HIDDEN_GROUP_CODES, CRS_INFRA_GROUP_CODES, isInfraRuleId, normalizeCrsGroups } from '@/utils/crsGroups'
import { DEEP_LINK_PARAMS, pageUrl } from '@/utils/deepLink'
import { buildPolicyPayload, crawlerExemptionNeedsEngines, trustEnabledForPolicyType } from '@/utils/policyPayload'
import { activateOnce } from '@/utils/keyboardActivate'

const { t, locale } = useI18n()

interface PolicyDetail { id: number; name: string; description: string; mode: string; anomaly_threshold: number; ip_acl_mode: string; ip_acl_list: string; ip_acl_enabled: boolean; ip_whitelist: string; ip_whitelist_enabled?: boolean; ip_blacklist?: string; ip_acl_list_refs?: string; ip_whitelist_refs?: string; crs_rule_groups: string; crs_excluded_rules: string; custom_rules: string; block_page_id: number; block_status_code: number; block_response_mode?: string; enabled: boolean; updated_at: string; geoip_mode?: string; geoip_countries?: string; geoip_crawler_exempt?: boolean; geoip_crawler_engines?: string; waf_check_response?: boolean; log_request_body?: boolean; trust_detection?: boolean; human_verify_mode?: string; human_verify_type?: string; human_verify_ttl?: number; human_exempt_paths?: string[]; cc_detect_enabled?: boolean; cc_rps_limit?: number; cc_rps_window?: number; cc_4xx_ratio?: number; cc_session_anomaly?: boolean; cc_session_ua_threshold?: number; cc_response?: string }
// 规则行消费面（关联规则行内执行序/投影数据源；协议与域名等展示字段）
interface Rule { caddy_id: string; name: string; domain: string; listen_port: number; protocol: string }
// v2.2.0 多策略绑定：/security/bindings 的值从单 BindingInfo 改为数组（rank 序=执行序；
// policy_id 仅作遗留 rank=0 行的并列兜底）
interface BindingInfo { policy_id: number; name: string; mode: string; enabled: boolean; block_page_id?: number; block_status_code?: number }
// GET /security/rules/:caddy_id/policy 直接序列化 models.SecurityPolicy——json.RawMessage
// 字段以原生 JSON（数组）出现，与策略详情接口的字符串形态不同，按 unknown 接收再解析。
interface RuleBoundPolicy { id: number; name: string; mode: string; enabled: boolean; ip_acl_enabled: boolean; ip_acl_mode: string; crs_rule_groups: unknown; custom_rules: unknown; block_page_id: number }
interface CustomRuleRef { id: number; action: string }
interface ChainEntry { policyId: number | null; name: string; enabled: boolean; isSelf: boolean; blockPageId?: number; blockStatusCode?: number }
interface BoundRuleRow { caddyId: string; name: string; protocol: string; domain: string; listenPort: number; chain: ChainEntry[]; mergedCount: number; showPerfTip: boolean; hints: string[]; infoHints: string[] }
interface BlockPage { id: number; name: string; content?: string }

const blockPages = ref<BlockPage[]>([])

interface PolicySummary { id: number; name: string; mode: string; enabled: boolean; rule_count: number; has_waf: boolean; has_ip_control: boolean; has_custom_rules: boolean; anomaly_threshold: number; ip_acl_mode: string; ip_acl_list: string; ip_whitelist: string; ip_whitelist_enabled?: boolean; ip_blacklist: string; ip_acl_list_refs?: string; ip_whitelist_refs?: string; crs_excluded_count: number; custom_rules_count: number; custom_rules_ref_count?: number; ip_acl_enabled: boolean; updated_by: number; updated_at: string; crs_rule_groups?: string | string[]; has_geoip?: boolean; geoip_countries?: string; geoip_mode?: string; policy_type?: string; trust_detection?: boolean; trigger_24h?: number; human_verify_mode?: string; human_verify_type?: string; cc_detect_enabled?: boolean; cc_rps_limit?: number; cc_rps_window?: number }




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
    // en:省级名词条映射(value 保持 zh 供后端匹配);市级无 en 数据源,回落原名
    // 裸键兜底:IP 库采样可能引入词条未覆盖的区域名(如广州/武汉这类库内置市级
    // 条目混入省列),t() 返回裸键时回落原名,任何数据变化都不出现 app.security.*
    let provLabel = prov
    if (locale.value === 'en') {
      const mapped = t(`app.security.policies.geo.provinces.${prov}`)
      if (!mapped.includes('app.security.policies')) provLabel = mapped
    }
    if (cities.length === 0) {
      options.push({ value: prov, label: provLabel })
      continue
    }
    options.push({
      value: prov,
      label: provLabel,
      children: cities.map((city) => ({ value: `${prov}/${city}`, label: locale.value === 'en' ? cityEnName(city) : city })),
    })
  }
  const overseas = regionTree.value.countries || []
  if (regionTree.value.provinces.length > 0 || overseas.length > 0) {
    const zhNames = regionTree.value.country_names_cn || {}
    options.push({
      value: '海外',
      label: t('app.security.policies.geo.overseasGroup'),
      children:
        overseas.length > 0
          ? // X5：按展示标签（中文简称，未命中回退英文）排序——
            // 后端 Countries 为英文字典序，中文标签直显时乱序；提交值不变。
            overseas
              .map((country) => ({
                value: country,
                label: locale.value === 'en' ? country : zhNames[country] || country,
              }))
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
// —— 排除目标目录（数据源 = 既有端点 GET /security/crs/rule-index 索引单例）：
//    WAF 步骤首次进入时惰性取一次（已加载/在途直接复用，失败静默降级）——
//    search 恒空建议时输入框退化为自由输入，不阻塞排除编辑 ——
const { ensure: ensureCrsDirectory, search: searchCrsDirectory } = useCrsRuleDirectory()
// —— 排除规则行编辑器（存储形态：对象数组 [{target,scope,ips,listRefs,path}]，旧字符串
//     数组读取时由 parseCrsExcludedRules 归一为 scope:all 行；path 仅 scope==='path' 消费）——
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
// 内置页名称/描述多语言（自定义页回退库内原文）：选择器/摘要/阶段行统一走本组。
const pageLabel = (page: BlockPage | BlockPageLike): string => builtinBlockPageLabel(page, 'name', t)
// 阶段模型（流程/预览行）按显示名入模——行文案里的页面名随界面语言切换。
const blockPagesLocalized = computed(() => blockPages.value.map((p) => ({ ...p, name: pageLabel(p) })))
const policySearch = ref('')

// ── 列表按类型分组（阶段 1/2/3 + 混合兼容组）：policy_type 缺省时按内容推断（inferPolicyType
// 与后端兜底同形状） ──
const activeTypeTab = ref<SecurityPolicyType>('stage1')

// 名单分类显示映射(后端/存储 zh 分类码;下拉 label 翻译,筛选 value 保持 zh)
// ipListCategoryLabel 迁移至 utils/ipListCategoryLabel.ts 单源(audit140-U2-F4 三份同构收敛)

const policyTypeOf = (row: PolicySummary): SecurityPolicyType =>
  normalizePolicyType(inferPolicyType(row)) as SecurityPolicyType
// 策略 id → 阶段类型（绑定选择器/提交门的 stage2 唯一性判据用）：与列表分组同一
// 推断口径（inferPolicyType 优先 policy_type 列，缺省按内容推断）。
const policyTypeById = computed<ReadonlyMap<number, SecurityPolicyType>>(() => {
  const map = new Map<number, SecurityPolicyType>()
  for (const p of policies.value) map.set(p.id, policyTypeOf(p))
  return map
})
// 各类型条数（tab 标签 + 默认/回落 tab 选择共用一个计数源）
const policyTypeCounts = computed<Record<SecurityPolicyType, number>>(() => {
  const counts: Record<SecurityPolicyType, number> = { stage0: 0, stage1: 0, stage2: 0, stage3: 0, stage4: 0, mixed: 0 }
  for (const p of policies.value) {
    const t = normalizePolicyType(policyTypeOf(p)) as SecurityPolicyType
    counts[t]++
  }
  // 旧编号 stage4 已并入 stage3（normalizePolicyType），不再单独成 tab
  // （计数表本身仍保留该键，仅 tab 列表不消费它）。
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


// ── 绑定摘要：投影条与预览步自历史起只出摘要（「将应用于 N 条已关联规则」），
// 逐规则绑定链、执行序（上移/下移）与归属提示在「关联规则」步骤 ──

// 内容摘要列（按类型一行摘要）：stage0=信任条数+模式、stage1=模式+ACL+GeoIP、
// stage2=限流值、stage3=WAF 模式+自定义+CRS 组、mixed=混合（任务 2）

// 关联规则链条目：一律按绑定链顺序显示「N.名称」（2026-11-12 用户裁定：
// 不再为阶段 0 使用特殊措辞；阶段语义由颜色区分，本策略加粗）。
const chainEntryStageKey = (entry: ChainEntry): string => {
  const raw = entry.isSelf
    ? normalizePolicyType(editorPolicyType.value)
    : (() => {
        const policy = policies.value.find((p) => p.id === entry.policyId)
        return policy ? normalizePolicyType(policyTypeOf(policy)) : 'mixed'
      })()
  // CSS 选择器用 stage-0…stage-3 / stage-mixed（raw 形如 stage0）。
  return raw.startsWith('stage') ? raw.slice('stage'.length) : raw
}
// WAF 模式展示词单源已上移 utils/securityStages（wafModeLabel/WAF_MODE_TEXT）——列表摘要、
// 只读详情分段、触发详情策略行、流程投影四处同词（此前文件内两份 + 跨文件一份
// 措辞互斥：拦截/阻断、仅自定义/仅自定义规则）。
const chainChipText = (entry: ChainEntry, index: number): string => {
  const name = entry.isSelf ? t('app.security.policies.common.selfPolicy') : entry.name
  return `${index + 1}.${name}`
}
const policySummaryLine = (row: PolicySummary): string => {
  const type = policyTypeOf(row)
  if (type === 'stage0') {
    const count = mergeIpEntryCount(ipLists.value, parseIPList(row.ip_whitelist), parseRefIds(row.ip_whitelist_refs))
    return t('app.security.policies.summary.trustSummary', { n: count, mode: trustHitMode(row.policy_type, row.trust_detection) === 'detection' ? t('app.security.policies.stage0.modeDetection') : t('app.security.policies.stage0.modePass') })
  }
  if (type === 'stage2') {
    // 阶段 2 · CC 防护（2026-11-12 用户裁定）：配额限流与挑战同属一条策略。
    const parts: string[] = []
    if (row.human_verify_mode && row.human_verify_mode !== 'off') {
      const modeLabel = row.human_verify_mode === 'force'
        ? t('app.security.policies.human.modeForce')
        : t('app.security.policies.human.modeAuto')
      parts.push(t('app.security.policies.summary.ccChallenge', { mode: modeLabel }))
    }
    if (row.cc_detect_enabled && row.human_verify_mode && row.human_verify_mode !== 'off') {
      parts.push(t('app.security.policies.summary.ccSpike', { n: row.cc_rps_limit ?? 0, sec: row.cc_rps_window ?? 0 }))
    }
    return parts.length > 0 ? parts.join(' · ') : t('app.security.policies.common.notEnabled')
  }
  if (type === 'stage3') {
    // 组数口径与编辑器写回同源（normalizeCrsGroups）：历史文件名前缀、重复值、
    // 系统基础组（01/49/59）都不该让「N 组」虚增——否则同一策略在编辑器里是
    // 2 组、在列表摘要里是 4 组，用户无从判断哪份是生效配置。
    const crsCount = normalizeCrsGroups(parseUnknownStrings(row.crs_rule_groups)).length
    // WAF 全关=CRS 与自定义规则均不生效（共享 buildStage3Rows 同门）——不得把
    // 保留的自定义条数说成生效中。
    if (row.mode === 'off') return t('app.security.policies.summary.wafOff')
    const parts = [t('app.security.policies.summary.wafMode', { mode: wafModeLabel(row.mode) }), t('app.security.policies.summary.customCount', { n: row.custom_rules_count })]
    if (row.mode === 'blocking' || row.mode === 'detection') parts.push(crsCount > 0 ? t('app.security.policies.summary.crsGroups', { n: crsCount }) : t('app.security.policies.summary.crsAll'))
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
    const aclPart = row.ip_acl_enabled === true || hasIPACLControl(row) ? formatAclModeDetail(ipLists.value, row) : t('app.security.policies.summary.aclOff')
    const geoPart = hasGeoIPControl(row)
      ? t('app.security.policies.summary.geoRegions', { n: geoCount })
      : geoCount > 0 ? t('app.security.policies.summary.geoClosedKeep', { n: geoCount }) : t('app.security.policies.summary.geoOff')
    return `${aclPart} · ${geoPart}`
  }
  return t('app.security.policies.summary.mixedCombo')
}

// ── 绑定执行序编辑（用户裁定：策略顺序=执行序）：关联规则行内上移/下移只暂存
// 本策略在该规则绑定链中的新位置（完整有序 policy_id 列表），随向导「保存」
// 按新序调 PUT /security/rules/:caddy_id/policies 整链提交——后端按提交序持久化
// rank，读路径（渲染链/GET /security/bindings）返回 rank 序。执行序与拦截页
// 显示无关（触发归因，见 resolveBlockPageAttribution）。
const bindingOrderEdits = ref<Record<string, number[]>>({})

// 服务端绑定基线（GET /security/bindings 返回 rank 序）：本策略尚未落库的规则
// （本次会话新关联）基线 = 既有绑定 + 本策略垫底。
const serverChainOrder = (caddyId: string): number[] => {
  const bound = (securityBindings.value[caddyId] || []).map((b) => b.policy_id)
  if (editingId.value !== null && !bound.includes(editingId.value)) bound.push(editingId.value)
  return bound
}

// 阶段 0（信任）恒先于拦截判定：展示与提交序统一把阶段 0 置顶，其余按 rank 序。
// 归一内核单源 normalizePolicyChainOrder（utils，与 mergeChainOrder 共用同一形状）。
const normalizeOrder = (ids: number[]): number[] =>
  normalizePolicyChainOrder(ids, (id) => policyTypeById.value.get(id))

// 展示/提交用的有序链：暂存序优先，否则按服务端基线（阶段 0 置顶）。
const orderedChainPolicyIds = (caddyId: string): number[] =>
  normalizeOrder(bindingOrderEdits.value[caddyId] ?? serverChainOrder(caddyId))

// 暂存序与基线归一后逐位比较：移过去又移回来 = 无暂存（不得触发「顺序待保存」
// 与保存收尾的 PUT）。
const bindingOrderPending = (caddyId: string): boolean => {
  const staged = bindingOrderEdits.value[caddyId]
  return !!staged && JSON.stringify(normalizeOrder(staged)) !== JSON.stringify(normalizeOrder(serverChainOrder(caddyId)))
}
const orderEditedRules = computed<string[]>(() => boundRules.value.filter((caddyId) => bindingOrderPending(caddyId)))

// 同阶段排序约束（用户裁定 2026-11-12）：策略顺序=执行序，但只允许在同阶段
// 内调整——跨阶段排序违反「阶段1 预检→阶段2 限流→阶段3 人机验证→阶段4 WAF」
// 原则。阶段 0（信任）恒置顶不参与交换；其余阶段各自成组。
const chainStageGroupOf = (id: number): string => policyTypeById.value.get(id) ?? 'stage3'

const canMoveSelf = (caddyId: string, direction: -1 | 1): boolean => {
  const order = orderedChainPolicyIds(caddyId)
  const pos = order.indexOf(editingId.value ?? Number.NaN)
  if (pos < 0) return false
  const target = pos + direction
  if (target < 0 || target >= order.length) return false
  // 同阶段门：目标位置策略与本策略必须同阶段组（stage0 永不参与）
  const selfStage = chainStageGroupOf(editingId.value ?? Number.NaN)
  if (selfStage === 'stage0') return false
  return chainStageGroupOf(order[target]) === selfStage
}
const moveSelfInChain = (caddyId: string, direction: -1 | 1): void => {
  if (!canMoveSelf(caddyId, direction)) return // 同阶段门（与按钮禁用同源）
  const order = orderedChainPolicyIds(caddyId)
  const pos = order.indexOf(editingId.value ?? Number.NaN)
  const target = pos + direction
  if (pos < 0 || target < 0 || target >= order.length) return
  const next = [...order]
  const tmp = next[pos]!
  next[pos] = next[target]!
  next[target] = tmp
  // 归一还原检测：相邻为信任名单（阶段 0）×非阶段 0 时，交换会被
  // 阶段 0 置顶归一还原（触发顺序不变）——保留现状行为（不硬禁用、暂存照常
  // 写入），给 info 反馈代替零反馈的无效点击。
  if (JSON.stringify(normalizeOrder(next)) === JSON.stringify(normalizeOrder(order))) {
    ElMessage.info(t('app.security.policies.msg.swapNoop'))
  }
  bindingOrderEdits.value = { ...bindingOrderEdits.value, [caddyId]: next }
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
  if (p.policy_type === 'stage2' || p.human_verify_mode && p.human_verify_mode !== 'off' || p.cc_detect_enabled) types.push('stage2')
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
    return type ? type === 'stage2' : false
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
    if (data && data.created.length > 0) parts.push(t('app.security.policies.msg.migrateCreated', { n: data.created.length, names: data.created.map((c) => c.name).join(t('app.security.policies.common.sep')) }))
    if (data && data.remapped > 0) parts.push(t('app.security.policies.msg.migrateRemapped', { n: data.remapped }))
    if (data && !data.deleted_original) parts.push(t('app.security.policies.msg.migrateKeepOriginal'))
    mfaAwareSuccess(parts.length > 0 ? parts.join(t('app.security.policies.common.sepSemi')) : t('app.security.policies.msg.migrateDone'))
    // 退化 200+后缀（Caddy 应用失败但 DB 已提交）须持续警告可见——
    // 有后缀才弹，无后缀不重复 toast（同下方保存主链路 FE1 口径）
    if (res.message?.includes(CADDY_APPLY_FAILED_MARKER)) showSaveResult(res, '')
    if (data && data.skipped.length > 0) {
      ElMessage.warning(t('app.security.policies.msg.migrateSkipped', { n: data.skipped.length, reasons: data.skipped.map((s) => s.reason).join(t('app.security.policies.common.sepSemi')) }))
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
  const excludedEntries = parseCrsExcludedRules(d.crs_excluded_rules)
  const excludedCount = excludedEntries.length
  // 路径作用域排除在只读详情披露具体前缀（去重后前 3 条 + 「等 N 条」），
  // 否则与旧行为一致仅出计数
  const excludedPaths = [...new Set(excludedEntries.filter((e) => e.scope === 'path' && e.path !== '').map((e) => e.path))]
  const customCount = parseCustomRuleIds(d.custom_rules).length
  const stage3Rows: Array<{ label: string; value: string }> = [{ label: t('app.security.policies.waf.modeLabel'), value: wafModeLabel(d.mode) }]
  if (d.mode === 'blocking' || d.mode === 'detection') {
    stage3Rows.push({ label: t('app.security.policies.waf.thresholdLabel'), value: String(d.anomaly_threshold) })
    stage3Rows.push({ label: t('app.security.policies.waf.crsGroupsLabel'), value: crsGroupCount === 0 ? t('app.security.policies.view.crsAllDefault') : t('app.security.policies.common.groupsCount', { n: crsGroupCount }) })
    stage3Rows.push({ label: t('app.security.policies.waf.exclusionLabel'), value: excludedPaths.length > 0 ? t('app.security.policies.view.excludedWithPath', { n: excludedCount, paths: excludedPaths.slice(0, 3).join(t('app.security.policies.common.sep')) + (excludedPaths.length > 3 ? t('app.security.policies.view.pathMore', { n: excludedPaths.length }) : '') }) : t('app.security.policies.common.countItems', { n: excludedCount }) })
  }
  if (d.mode !== 'off') {
    stage3Rows.push({ label: t('app.security.policies.waf.customRulesLabel'), value: t('app.security.policies.common.countItems', { n: customCount }) })
    stage3Rows.push({ label: t('app.security.policies.waf.checkResponseBody'), value: d.waf_check_response ? t('app.security.policies.status.enabled') : t('app.security.policies.status.off') })
    stage3Rows.push({ label: t('app.security.policies.waf.logRequestBody'), value: d.log_request_body ? t('app.security.policies.status.enabled') : t('app.security.policies.status.off') })
  }
  const page = d.block_page_id > 0 ? blockPages.value.find((p) => p.id === d.block_page_id) : undefined
  // 地域模式词表键（off 已在上游分支排除；未知/空模式显性说明，不得代填 deny）
  const geoipMode = d.geoip_mode ?? 'off'
  return [
    {
      title: t('app.security.policies.step.basic'),
      rows: [
        { label: t('app.security.policies.editor.nameLabel'), value: d.name },
        { label: t('app.security.policies.editor.descLabel'), value: d.description || '-' },
        { label: t('app.security.policies.view.typeLabel'), value: POLICY_TYPE_LABELS.mixed },
        { label: t('app.security.policies.editor.enabledLabel'), value: d.enabled ? t('app.security.policies.status.enabled') : t('app.security.policies.status.disabled') },
      ],
    },
    // 阶段 0 段恒出（与流程弹框同口径 2026-09-21：无信任名单也显「未启用」，
    // 缺环节比灰态更误导）；有名单时显条目数与模式，开关关闭标注（未启用）
    {
      title: t('app.security.policies.step.stage0'),
      rows: trustCount === 0
        ? [{ label: t('app.security.policies.stage0.trustListLabel'), value: t('app.security.policies.common.notEnabled') }]
        : [
            { label: t('app.security.policies.stage0.trustListLabel'), value: t('app.security.policies.view.trustCount', { n: trustCount, off: d.ip_whitelist_enabled === false ? t('app.security.policies.common.disabledSuffix') : '' }) },
            { label: t('app.security.policies.view.modeLabel'), value: trustHitMode('mixed', d.trust_detection) === 'detection' ? t('app.security.policies.stage0.detectDetail') : t('app.security.policies.stage0.passDetail') },
          ],
    },
    {
      title: t('app.security.policies.step.stage1'),
      rows: [
        // 与列表摘要同口径——ip_acl_enabled 开启即展示模式（即使名单为空），
        // 内容门只用于阶段能力/类型推断
        { label: t('app.security.policies.acl.divider'), value: d.ip_acl_enabled === true || hasIPACLControl(d) ? formatAclModeDetail(ipLists.value, d) : t('app.security.policies.common.notEnabled') },
        // 信任名单只归阶段 0 段（2026-09-21 用户裁定：独立阶段 0，阶段 1 不再重复展示）
        { label: t('app.security.policies.geo.geoBlockLabel'), value: (d.geoip_mode ?? 'off') !== 'off'
          ? t('app.security.policies.view.geoModeRegions', { mode: hasOwn(GEOIP_MODE_LABELS, geoipMode) ? GEOIP_MODE_LABELS[geoipMode] : geoipMode || t('app.security.policies.view.geoModeUnset'), n: geoCount })
          : (geoCount > 0 ? t('app.security.policies.summary.geoClosedKeep', { n: geoCount }) : t('app.security.policies.common.notEnabled')) },
      ],
    },
    {
      title: t('app.security.policies.step.stage2'),
      rows: [
        { label: t('common.app.views.stages.humanModeLabel'), value: (d.human_verify_mode ?? 'off') !== 'off' ? t('common.app.views.stages.humanMode_' + d.human_verify_mode) : t('app.security.policies.common.notEnabled') },
        { label: t('common.app.views.stages.humanTypeLabel'), value: (d.human_verify_mode ?? 'off') !== 'off' ? t('common.app.views.stages.humanType_' + (d.human_verify_type ?? 'slider')) : '—' },
        { label: t('app.security.policies.human.ccResponseLabel'), value: d.cc_detect_enabled ? t('app.security.policies.human.ccResponse' + (d.cc_response === 'ban' ? 'Ban' : 'Verify')) : t('app.security.policies.common.notEnabled') },
      ],
    },
    { title: t('app.security.policies.step.stage3'), rows: stage3Rows },
    {
      title: t('app.security.policies.step.blockPage'),
      rows: [
        { label: t('app.security.policies.bp.pageLabel'), value: d.block_page_id > 0
          ? t('app.security.policies.view.pageWithStatus', { name: page?.name ?? t('app.security.policies.common.pageNum', { n: d.block_page_id }), code: d.block_status_code || 403 })
            + ' · ' + t(`app.security.policies.bp.response${d.block_response_mode === 'html' ? 'Html' : d.block_response_mode === 'json' ? 'Json' : 'Auto'}`)
          : t('app.security.policies.bp.noPageDefault') },
        { label: t('app.security.policies.view.attributionLabel'), value: t('app.security.policies.view.attributionValue') },
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
    ElMessage.warning(securityBindingsLoading.value ? t('app.security.policies.msg.bindingsLoading') : t('app.security.policies.msg.bindingsFailedReload'))
    return
  }
  bindRulesOpening.value = true
  try {
    // 打开前重取一次快照（保存是全量替换，旧快照的 delta 不等于当前真实绑定集）
    if (!(await refreshBindingsSnapshot())) {
      ElMessage.error(t('app.security.policies.msg.bindingsRefreshFailed'))
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
const aclRefHint = computed(() => t('app.security.policies.hint.refCombo', { inline: ipACLList.value.length, refs: selectedRefEntryCount(ipACLListRefs.value), total: aclMergedCount.value }))
const showAclRefHint = computed(() => ipACLList.value.length > 0 || ipACLListRefs.value.length > 0)
const whitelistMergedCount = computed(() => mergeIpEntries(ipWhitelist.value, ipWhitelistRefs.value).length)
const whitelistSaveCount = computed(() => mergeIpEntryCount(ipLists.value, ipWhitelist.value, ipWhitelistRefs.value))
const whitelistRefHint = computed(() => t('app.security.policies.hint.refCombo', { inline: ipWhitelist.value.length, refs: selectedRefEntryCount(ipWhitelistRefs.value), total: whitelistMergedCount.value }))
const showWhitelistRefHint = computed(() => ipWhitelist.value.length > 0 || ipWhitelistRefs.value.length > 0)
// 本策略既有 ip_blacklist（仅用于跨策略冲突比较；本对话框不编辑该字段，
// 保存时由后端指针语义自动保留原值）
const ipBlacklistSelf = ref<string[]>([])
const geoipCountries = ref<string[]>([])
const crsRuleGroups = ref<string[]>([])
const boundRules = ref<string[]>([])

// 解绑/规则集变化即作废对应暂存执行序（移除后重加按基线序重新开始）。
// 位置约束：watch 在 setup 期即注册，必须晚于 boundRules 声明（TDZ）。
watch(boundRules, (rules) => {
  const alive = new Set(rules)
  const entries = Object.entries(bindingOrderEdits.value)
  if (entries.every(([cid]) => alive.has(cid))) return
  const next: Record<string, number[]> = {}
  for (const [cid, order] of entries) {
    if (alive.has(cid)) next[cid] = order
  }
  bindingOrderEdits.value = next
}, { immediate: true })

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
  HUMAN: 4,
  WAF_RULES: 5,
  BLOCK_PAGE: 6,
  BINDINGS: 7,
  PREVIEW: 8,
} as const
type WizardStep = (typeof WIZARD_STEP)[keyof typeof WIZARD_STEP]
const WIZARD_STEP_META: Record<WizardStep, { title: string; icon: typeof InfoFilled }> = {
  [WIZARD_STEP.BASIC]: { title: t('app.security.policies.step.basic'), icon: InfoFilled },
  [WIZARD_STEP.TRUST]: { title: t('app.security.policies.step.stage0'), icon: Connection },
  [WIZARD_STEP.IP_ACL]: { title: t('app.security.policies.step.stage1'), icon: Connection },
  [WIZARD_STEP.RATE_LIMIT]: { title: t('app.security.policies.step.stage2cc'), icon: Odometer },
  [WIZARD_STEP.HUMAN]: { title: t('app.security.policies.step.stage3Human'), icon: View },
  [WIZARD_STEP.WAF_RULES]: { title: t('app.security.policies.step.stage3waf'), icon: Lock },
  [WIZARD_STEP.BLOCK_PAGE]: { title: t('app.security.policies.step.blockPage'), icon: Document },
  [WIZARD_STEP.BINDINGS]: { title: t('app.security.policies.step.bindings'), icon: Link },
  [WIZARD_STEP.PREVIEW]: { title: t('app.security.policies.step.preview'), icon: Check },
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
  { value: 'stage0', label: t('app.security.policies.type.stage0') },
  { value: 'stage1', label: t('app.security.policies.type.stage1') },
  { value: 'stage2', label: t('app.security.policies.type.stage2') },
  { value: 'stage3', label: t('app.security.policies.type.stage3') },
]
// ── 策略类型（实体单职化）：新建先选类型；编辑态类型由行推断/后端 policy_type 携带 ──
const createPolicyType = ref<'stage0' | 'stage1' | 'stage2' | 'stage3'>('stage0')
watch(createPolicyType, (t) => {
  // 新建人机验证策略：默认智能触发（off 会让该类型不产生任何渲染面）
  if (t === 'stage2' && form.value.human_verify_mode === 'off') form.value.human_verify_mode = 'auto'
})
const editingPolicyType = ref<SecurityPolicyType | null>(null)
const editorPolicyType = computed<SecurityPolicyType>(() =>
  editingId.value === null ? createPolicyType.value : (editingPolicyType.value ?? 'mixed'))

// 信任名单在编辑器内的生效口径（与保存载荷 trustEnabledForPolicyType 同源）：
// 阶段 0 恒启用——新建阶段 0 时 ipWhitelistEnabled 初值 false 且向导没有开关控件，
// 告警/预览若各自读开关会把恒启用的信任条目判成零生效（跨策略冲突静默）。
const trustEnabledInEditor = computed(() => trustEnabledForPolicyType(editorPolicyType.value, ipWhitelistEnabled.value))

// 弹框副标题按策略类型描述；mixed/缺省保持兼容组总述文案
const EDITOR_SUBTITLES: Record<SecurityPolicyType, string> = {
  stage3: t('app.security.policies.editor.subHuman'),
  stage0: t('app.security.policies.editor.subStage0'),
  stage1: t('app.security.policies.editor.subStage1'),
  stage2: t('app.security.policies.editor.subStage2'),
  stage4: t('app.security.policies.editor.subStage4'),
  mixed: t('app.security.policies.editor.subMixed'),
}

// 单职化（2026-11-12 用户裁定）：一条策略只含一个阶段——stage3=人机验证、
// stage4=WAF，互斥不共存；mixed 兼容组例外。
const typeAllowsStage = (stage: 0 | 1 | 2 | 3 | 4): boolean =>
  editorPolicyType.value === 'mixed' || editorPolicyType.value === `stage${stage}`
// 挑战/CC 检测阈值属阶段 2（CC 防护）。旧编号 stage4 由 normalizePolicyType 归一。
const typeAllowsCC = computed(() => normalizePolicyType(editorPolicyType.value) === 'stage2' || editorPolicyType.value === 'mixed')

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
// 协议筛选（默认 HTTP）：全部/HTTP/TCP 三档。默认档不是「全部」是有意裁定——
// TCP（L4 阶段 0/1）放开前选择器只见 HTTP，放开后混排，默认 HTTP 保持既有视野。
const pickerProtoFilter = ref<'all' | 'http' | 'tcp'>('http')
const pickerPage = ref(1)
const pickerSelected = ref<string[]>([])
const PICKER_PAGE_SIZE = 20
const defaultForm = () => ({ name: '', description: '', enabled: true, mode: 'off', anomaly_threshold: 5, ip_acl_enabled: false, ip_acl_mode: 'allow', block_page_id: 1, block_status_code: 403, block_response_mode: 'auto', geoip_enabled: false, geoip_mode: 'deny', geoip_crawler_exempt: false, geoip_crawler_engines: ['googlebot', 'bingbot', 'baiduspider'], waf_check_response: false, log_request_body: false, trust_detection: false, human_verify_mode: 'off', human_verify_type: 'slider', human_verify_ttl: 30, human_exempt_paths: [] as string[], cc_detect_enabled: false, cc_rps_limit: 40, cc_rps_window: 10, cc_4xx_ratio: 70, cc_session_anomaly: false, cc_session_ua_threshold: 5, cc_response: 'verify' })

const form = ref(defaultForm())
// v2.3.8 爬虫豁免引擎注册表（geoipnames 单源镜像；ID 稳定——后端白名单校验）
const crawlerEngineOptions = [
  { id: 'googlebot', name: 'Google' },
  { id: 'bingbot', name: 'Bing' },
  { id: 'baiduspider', name: t('app.security.policies.crawler.baidu') },
  { id: 'sogouspider', name: t('app.security.policies.crawler.sogou') },
  { id: 'so360spider', name: '360' },
  { id: 'yisouspider', name: t('app.security.policies.crawler.yisou') },
  { id: 'petalbot', name: t('app.security.policies.crawler.petal') },
  { id: 'duckduckbot', name: 'DuckDuckGo' },
  { id: 'yandexbot', name: 'Yandex' },
  { id: 'gptbot', name: t('app.security.policies.crawler.gpt') },
  { id: 'deepseekbot', name: t('app.security.policies.crawler.deepseek') },
  { id: 'claudebot', name: 'Anthropic Claude' },
  { id: 'perplexitybot', name: 'Perplexity' },
  { id: 'kimisearchbot', name: t('app.security.policies.crawler.kimi') },
  { id: 'bytespider', name: t('app.security.policies.crawler.bytespider') },
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
    // 阶段序严格排序（2026-11-12 用户裁定）：stage0→stage4，mixed 垫底。
    // 同阶段按名称 localeCompare 稳定——阶段 4 不得排在阶段 2/3 之前。
    policies.value = (polRes.value.data || []).slice().sort((a, b) => {
      const order = { stage0: 0, stage1: 1, stage2: 2, stage3: 3, stage4: 4, mixed: 5 }
      const oa = order[policyTypeOf(a)] ?? 5, ob = order[policyTypeOf(b)] ?? 5
      return oa !== ob ? oa - ob : a.name.localeCompare(b.name)
    })
    policiesLoadError.value = false
    const failures: string[] = []
    if (ruleRes.status === 'fulfilled') allRules.value = ruleRes.value.data || []
    else failures.push(t('app.security.policies.aux.rules'))
    if (crsRes.status === 'fulfilled') crsRuleOptions.value = crsRes.value || []
    else failures.push(t('app.security.policies.aux.crsOptions'))
    if (bpRes.status === 'fulfilled') { blockPages.value = bpRes.value.data || []; blockPagesLoaded.value = true }
    else failures.push(t('app.security.policies.aux.blockPages'))
    if (crRes.status === 'fulfilled') allCustomRules.value = crRes.value.data || []
    else failures.push(t('app.security.policies.aux.customRules'))
    if (bindRes.status === 'fulfilled') { securityBindings.value = bindRes.value.data || {}; securityBindingsFailed.value = false }
    else { failures.push(t('app.security.policies.aux.bindings')); securityBindingsFailed.value = true }
    if (userRes.status === 'fulfilled') users.value = userRes.value.data || []
    else failures.push(t('app.security.policies.aux.users'))
    if (ipListRes.status === 'fulfilled') ipLists.value = ipListRes.value.data || []
    else failures.push(t('app.security.policies.aux.ipLists'))
    auxLoadFailures.value = failures
    if (failures.length > 0) console.warn(t('app.security.policies.list.auxFailBanner', { items: failures.join(t('app.security.policies.common.sep')) }))
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
const crsOptionPhase = (filename: string): string => parseCrsFilename(filename)?.phase ?? t('app.security.policies.waf.phaseRequest')

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
      ? t('app.security.policies.waf.fileMetaCat', { phase: crsOptionPhase(v), code: crsOptionCode(v), category: fileRule.category })
      : t('app.security.policies.waf.fileMeta', { phase: crsOptionPhase(v), code: crsOptionCode(v) })
    return { value: v, label, title: v }
  }
  if (/^\d{6}$/.test(v)) {
    // 陈旧判定仅在索引成功加载后生效——加载失败/在途时不得把规则 ID 误标为已移除
    if (!crsIndexLoaded.value) return null
    return { value: v, label: t('app.security.policies.waf.ghostRule', { v }), title: v }
  }
  if (/^\d{2}$/.test(v)) {
    // 两数字组码组：旧版 CRS 遗留的失效组码（如 10/12，当前 CRS 4.x 已无对应文件）。
    // 守卫：规则文件列表未加载/失败（该列表恒 27 组，空=未就绪）时不标记，防误报。
    if (crsRuleOptions.value.length === 0) return null
    if (CRS_HIDDEN_GROUP_CODES.includes(v)) {
      const label = t('app.security.policies.waf.ghost99', { v })
      return { value: v, label, title: label }
    }
    const label = t('app.security.policies.waf.ghostGroup', { v })
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

// 区间遗留形态（6 位数字 a-b / a:b）单源判定：评估组排除交集判定与排除行
// ghost 释义共用同一正则（两个消费面必须对「什么算区间形态」口径一致）。
const CRS_RANGE_TARGET_RE = /^(\d{6})\s*[-:]\s*(\d{6})$/
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
  const rangeMatch = CRS_RANGE_TARGET_RE.exec(t)
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
    seen.set(code, `${crsOptionPhase(rule.filename)} · 9${code} · ${crsCategoryLabel(rule.category)}`)
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
    seen.set(code, `${crsOptionPhase(rule.filename)} · 9${code} · ${crsCategoryLabel(rule.category)}`)
  }
  return [...seen.entries()].map(([value, label]) => ({ value, label }))
})

// CRS 规则组多选 cascader 的懒加载实现：一级返回组节点（label 沿用「请求 · 942 ·
// SQL 注入」），展开组时才从已缓存索引按文件名两位组号切出该组规则叶（相位与组号
// 一一对应：REQUEST/RESPONSE 前缀决定）。懒的是组件挂载不是数据获取——索引仍由
// useCrsRuleIndex 一次性拉回（约 832 条），叶节点数组仅在组展开时生成，832 条全集
// 不随 cascader 挂载渲染。剔除口径：组节点由 crsGroupOptions（剔 01/49/59）保证；
// 规则叶剔基础设施 ID（901/949/959，写入面同语义剥离，提供选项=选了保存后消失）。
// （排除行的目标选择已改走目录自动补全，不再消费级联；其 ghost 判定仍走下方
// crsValueToPath 的 exclusion 侧映射。）

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

const crsGroupCascaderLazyLoad: LazyLoad = (node, resolve) => {
  // 一级：组节点（常渲染可浏览）
  if (node.level === 0) {
    resolve(crsGroupOptions.value.map((g): CrsCascaderOption => ({ value: g.value, label: g.label, leaf: false })))
    return
  }
  // 二级：展开组时才生成该组规则叶（索引已按 id 升序）
  const code = typeof node.value === 'string' ? node.value : ''
  const rules: CrsRuleOptionView[] = crsIndexOptions.value.filter((r) =>
    crsGroupCodeOfFile(r.file) === code && !isInfraRuleId(r.id))
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
  lazyLoad: crsGroupCascaderLazyLoad,
}

// 存储值 → 级联路径：两位组号 → [组号]（组须在对应侧可选组列表内）；6 位规则 ID
// → [组号, 规则ID]（组号由索引条目文件名解析，且该组节点存在）。无法映射（陈旧
// ID/遗留文件名/索引未就绪/被剔除口径的值）返回 null——group 侧（crs_rule_groups
// 桥接）不可映射值交 ghost 标签兜底；exclusion 侧（排除行 ghost 判定）返回空
// ghost，可映射值视为已知目标不再提示。
type CrsCascaderSide = 'group' | 'exclusion'
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

// 排除目标建议源：el-autocomplete 每次输入回调（自带 300ms 防抖）——目录已加载
// 则过滤（id 数字前缀 ∪ msg 关键字，≤50 条）；未加载/加载失败时目录为空，回调
// 空建议 = 输入框退化为纯自由输入，不阻塞。
const fetchExclusionSuggestions = (queryString: string, cb: (items: CrsDirectorySuggestion[]) => void): void => {
  cb(searchCrsDirectory(queryString))
}

// ================= 排除规则行编辑器 =================
const addExcludedRule = (): void => {
  if (crsExcludedRows.value.length >= CRS_EXCLUDED_MAX_ROWS) return
  crsExcludedRows.value.push({ target: '', scope: 'all', ips: [], listRefs: [], path: '' })
}

const removeExcludedRule = (idx: number): void => {
  crsExcludedRows.value.splice(idx, 1)
}

// 指定 IP 标签输入即时校验：非法条目立即拒绝（toast + 回滚为仅合法条目），
// 与 ACL 内联名单位同一 isValidCidr 口径（后端 400 为最终裁决，此处前置拦截）
const onExclusionIpsChange = (row: CrsExcludedRow, value: string[]): void => {
  const invalid = value.find((entry) => !isValidCidr(entry))
  if (invalid !== undefined) {
    ElMessage.error(t('app.security.policies.msg.invalidCidr', { items: invalid }))
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
  return /^\d{2}$/.test(target) ? t('app.security.policies.conflict.redundant') : t('app.security.policies.conflict.contradicts')
}

// 提交口径：全空行（无目标且无条件）静默丢弃，其余按 target+scope+ips+listRefs+path 去重
// 作用域切换清残留——否则 scope=all 残留 ips 保存 400，
// scope=list 残留 ips 被静默并入匹配集（语义漂移且 UI 不可见）。
const onScopeChange = (row: CrsExcludedRow): void => {
  if (row.scope === 'all') { row.ips = []; row.listRefs = []; row.path = '' }
  else if (row.scope === 'ip') { row.listRefs = []; row.path = '' }
  else if (row.scope === 'list') { row.ips = []; row.path = '' }
  else { row.ips = []; row.listRefs = [] }
}

type SerializedExcludedRow = Omit<CrsExcludedRow, 'path'> & { path?: string }
const serializedExcludedRules = computed<SerializedExcludedRow[]>(() => {
  const seen = new Set<string>()
  const out: SerializedExcludedRow[] = []
  for (const row of crsExcludedRows.value) {
    const target = row.target.trim()
    const path = row.path.trim()
    if (target === '' && row.ips.length === 0 && row.listRefs.length === 0 && path === '') continue
    // 去重键归一：ips/listRefs 排序后参与键——元素相同仅顺序不同的行视为
    // 同条（与后端 dedupeCRSExcludedEntries 的 refs 排序键同族口径；ips 侧后端按
    // 字面键兜底无害，本键在 FE 侧收敛）。仅键归一：下方载荷保持用户输入序。
    const key = `${target}\u0000${row.scope}\u0000${[...row.ips].sort().join(',')}\u0000${[...row.listRefs].sort((a, b) => a - b).join(',')}\u0000${path}`
    if (seen.has(key)) continue
    seen.add(key)
    // 序列化按 scope 剥离非当前作用域的残留——
      // 带外数据（scope=all 但 ips 非空）会 400 卡保存。
      // path 键仅 scope==='path' 携带（其余作用域保持历史形状，payload 字节兼容）
      if (row.scope === 'path') out.push({ target, scope: row.scope, ips: [], listRefs: [], path })
      else out.push({ target, scope: row.scope,
        ips: row.scope === 'ip' ? [...row.ips] : [],
        listRefs: row.scope === 'list' ? [...row.listRefs] : [] })
  }
  return out
})

// 行是否为待校验的有效配置行（非全空行即需通过校验）
const isFilledExclusionRow = (row: CrsExcludedRow): boolean =>
  row.target.trim() !== '' || row.ips.length > 0 || row.listRefs.length > 0 || row.path.trim() !== ''

// 保存/跨步闸门：非空行必须目标齐备，scope=ip 需至少一个 IP，scope=list 需至少一个列表，
// scope=path 需非空路径
const validateExcludedRules = (): boolean => {
  for (let i = 0; i < crsExcludedRows.value.length; i++) {
    const row = crsExcludedRows.value[i]
    if (!row || !isFilledExclusionRow(row)) continue
    if (row.target.trim() === '') {
      ElMessage.error(t('app.security.policies.msg.exclusionNoTarget', { n: i + 1 }))
      return false
    }
    if (row.scope === 'ip' && row.ips.length === 0) {
      ElMessage.error(t('app.security.policies.msg.exclusionNoIp', { n: i + 1 }))
      return false
    }
    if (row.scope === 'list' && row.listRefs.length === 0) {
      ElMessage.error(t('app.security.policies.msg.exclusionNoList', { n: i + 1 }))
      return false
    }
    if (row.scope === 'path') {
      const p = row.path.trim()
      if (p === '') {
        ElMessage.error(t('app.security.policies.msg.exclusionNoPath', { n: i + 1 }))
        return false
      }
      // 与后端 400 规则同口径前置拦截（后端 400 为最终裁决，此处避免保存卡死）：
      // 必须以 / 开头；≤256 字符（输入框 maxlength 已限，此处兜底）；
      // 无空白/控制字符/双引号/反斜杠（渲染为 @beginsWith 字面量，含引号会破配置）
      if (!p.startsWith('/')) {
        ElMessage.error(t('app.security.policies.msg.exclusionPathSlash', { n: i + 1 }))
        return false
      }
      if (p.length > 256 || /[\s"'\\]/.test(p) || /[\u0000-\u0008\u000e-\u001f\u007f]/.test(p)) {
        ElMessage.error(t('app.security.policies.msg.exclusionPathChars', { n: i + 1 }))
        return false
      }
    }
  }
  return true
}

// 预览目标 label：两位组号 → 组选项 label；6 位 ID → 索引「ID — 描述」（截断版）；
// 旧文件名/未知值 → 解析化文件形态或原值
const exclusionTargetLabel = (target: string): string => {
  if (/^\d{2}$/.test(target)) return crsGroupOptions.value.find((o) => o.value === target)?.label ?? t('app.security.policies.waf.groupLabel', { target })
  const entry = crsIndexById.value.get(target)
  if (entry) return `${target} — ${crsRuleLabelView(entry).label}`
  if (parseCrsFilename(target)) return t('app.security.policies.waf.fileMeta', { phase: crsOptionPhase(target), code: crsOptionCode(target) })
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

// 排除行 ghost 标签的 title 释义：区间遗留形态（如「942100-942199」手输，
// 旧字符串数组存储的常见形态）按字面保存并按字面下发——scope=all 走
// SecRuleRemoveById 原生区间（security.go scopeAllTargets 逐条直出，不展开为
// 规则组内全部规则 ID），作用域限定（指定 IP/地址列表/路径）不支持区间目标
// （保存侧已拒，后端口径「仅 scope=all」）；其余不可映射值维持裸值 title
// （现状行为不变）。返回空串仅当 ghost 标签本身不渲染。
const exclusionRowGhostTitle = (target: string): string => {
  const v = target.trim()
  if (v === '' || crsValueToPath(v, 'exclusion') !== null) return ''
  if (CRS_RANGE_TARGET_RE.test(v)) {
    return t('app.security.policies.waf.rangeGhostTitle')
  }
  return v
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
    ElMessage.warning(t('app.security.policies.msg.builtinDenyOnly'))
  }
})

const ACL_LIST_LABELS: Record<string, string> = { deny: t('app.security.policies.acl.labelDeny'), allow: t('app.security.policies.acl.labelAllow'), 绕过: t('app.security.policies.acl.labelBypass') }
// 词表查表统一过 hasOwn：库值可能命中原型键（constructor/toString/__proto__，
// 只能由带外改库产生），裸下标会把 Object.prototype 上的函数当标签渲染。
const aclListLabel = computed(() => (hasOwn(ACL_LIST_LABELS, form.value.ip_acl_mode)
  ? ACL_LIST_LABELS[form.value.ip_acl_mode]
  : t('app.security.policies.acl.listFallback')))

const GEOIP_MODE_LABELS: Record<string, string> = { deny: t('app.security.policies.geo.modeDeny'), allow: t('app.security.policies.geo.modeAllow') }
// 从 off 态重开开关时控制模式回落 deny（off 只是关闭哨兵，radio 无此项）。
const onGeoipEnabledChange = (enabled: string | number | boolean) => {
  if (enabled && form.value.geoip_mode === 'off') form.value.geoip_mode = 'deny'
}

const ACL_MODE_TIPS: Record<string, string> = {
  deny: t('app.security.policies.acl.hintDeny'),
  allow: t('app.security.policies.acl.hintAllow'),
  绕过: t('app.security.policies.acl.hintBypass'),
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


// /security/bindings 以 rule_caddy_id 为键（v2.2.0 起值为绑定数组，rank 序=执行序），
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
  // 白名单空生效集不再在此阻断（用户裁定 warning-not-block）：保存流在
  // handleSave 里以 ElMessageBox.confirm 显性确认「关联规则将拒绝所有请求」后
  // 照常保存；本函数只保留格式类校验（关闭开关后隐藏的条目不得点名）。
  // 校验只作用于生效字段（与渲染门同源）：关闭 IP 访问控制后内联名单按保留语义
  // 继续回传但零发射，此时点名不可见条目会让用户既看不到也删不掉。
  if (form.value.ip_acl_enabled) {
    const invalidEntry = ipACLList.value.find((entry) => !isValidCidr(entry))
    if (invalidEntry) {
      ElMessage.error(t('app.security.policies.msg.invalidCidr', { items: invalidEntry }))
      return false
    }
  }
  if (ipWhitelistEnabled.value) {
    const invalidTrustEntry = ipWhitelist.value.find((entry) => !isValidCidr(entry))
    if (invalidTrustEntry) {
      ElMessage.error(t('app.security.policies.msg.invalidTrustCidr', { items: invalidTrustEntry }))
      return false
    }
  }
  if (form.value.geoip_enabled && geoipCountries.value.length === 0) {
    ElMessage.error(t('app.security.policies.msg.regionRequired'))
    return false
  }
  return true
}

const nextStep = (): void => {
  if (currentStep.value === WIZARD_STEP.BASIC) {
    if (!form.value.name.trim()) {
      ElMessage.warning(t('app.security.policies.msg.nameRequired'))
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
  // 阶段 0/1 放开后 TCP 规则可绑定；含限流/WAF 特征的策略对 TCP 不可绑——
  // 该形态在选择侧由 pickerMeta 置灰并给行内原因（不再只列 HTTP）。
  // 协议筛选先收窄候选（默认 HTTP），搜索再在档内匹配。
  const proto = pickerProtoFilter.value
  const candidates = proto === 'all'
    ? allRules.value
    : allRules.value.filter((rule) => rule.protocol === (proto === 'tcp' ? 'tcp' : 'http'))
  const query = pickerSearch.value.trim().toLowerCase()
  const matched = (rule: Rule): boolean =>
    rule.name.toLowerCase().includes(query)
    || (rule.domain || '').toLowerCase().includes(query)
    || rule.caddy_id.toLowerCase().includes(query)
  if (!query) return [...candidates]
  return candidates.filter(matched)
})

const pickerPagedRules = computed(() => {
  const start = (pickerPage.value - 1) * PICKER_PAGE_SIZE
  return pickerFilteredRules.value.slice(start, start + PICKER_PAGE_SIZE)
})

watch(pickerSearch, () => {
  pickerPage.value = 1
})

// 切协议档回到第 1 页（同搜索复位先例）：高页码在收窄后的候选集会落空页
watch(pickerProtoFilter, () => {
  pickerPage.value = 1
})

// 全选作用于当前搜索筛选出且可选择的全部规则（跨分页；已达绑定上限/限流冲突的
// 规则不可选，不参与全选），selection 存于 pickerSelected 与分页无关
const pickerSelectableRules = computed(() => pickerFilteredRules.value.filter((rule) => pickerMeta(rule).blockReason === ''))
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

// 拦截页面 = 首绑策略的页面（执行序首个有页策略）；单规则最多
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
  if (step === WIZARD_STEP.WAF_RULES && dialogVisible.value) void ensureCrsDirectory()
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

// 展示链：完整绑定列表（含禁用策略，标灰）+ 本策略，按绑定执行序（rank 序，
// 上移/下移暂存序优先；阶段 0 信任置顶——恒先于拦截判定）。本策略条目以表单
// 实时值为准（编辑中的 name/enabled/block_page_id 可能与服务端快照不同）；
// blockPageId/blockStatusCode 用于拦截页归因提示（触发归因单源
// resolveBlockPageAttribution 消费同一链序——兜底目标=执行序首个有页策略）。
const buildDisplayChain = (caddyId: string): ChainEntry[] => {
  const byId = new Map<number, ChainEntry>()
  for (const b of securityBindings.value[caddyId] || []) {
    if (b.policy_id !== editingId.value) {
      byId.set(b.policy_id, { policyId: b.policy_id, name: b.name, enabled: b.enabled, isSelf: false, blockPageId: b.block_page_id, blockStatusCode: b.block_status_code })
    }
  }
  if (editingId.value !== null) {
    byId.set(editingId.value, { policyId: editingId.value, name: form.value.name || t('app.security.policies.common.selfPolicy'), enabled: form.value.enabled, isSelf: true, blockPageId: form.value.block_page_id, blockStatusCode: form.value.block_status_code })
  }
  return orderedChainPolicyIds(caddyId)
    .map((id) => byId.get(id))
    .filter((entry): entry is ChainEntry => entry !== undefined)
}

// 选择器单条规则元信息：绑定链、本策略落点（1-based）、不可选原因（空串=可选）。
// 判据与后端 bulk 校验同源（冲突整批 400，故必须在选择阶段就置灰）：
// ①TCP 规则 × 含限流/WAF 特征策略（阶段 2/3/混合）→ TCP_BIND_UNSUPPORTED_REASON
// （与 SecurityBindingEditor.pickerBlockReason 同谓词同文案）；
// ②阶段 2（限流）策略 → 该规则已绑定其它限流策略（每规则仅一条，与
// SecurityBindingEditor.pickerBlockReason 同源谓词）；③每规则绑定条数上限。
// 本策略已在绑定中的规则重选不新增绑定，恒可选。
const pickerMeta = (rule: Rule): { chain: ChainEntry[]; selfPos: number; blockReason: string } => {
  const caddyId = rule.caddy_id
  const existing = securityBindings.value[caddyId] || []
  const selfBound = editingId.value !== null && existing.some((b) => b.policy_id === editingId.value)
  const chain = buildDisplayChain(caddyId)
  let blockReason = ''
  if (!selfBound) {
    if (rule.protocol === 'tcp' && !policySupportsTcp(editorPolicyType.value)) {
      blockReason = TCP_BIND_UNSUPPORTED_REASON
    } else if (editorPolicyType.value === 'stage2'
      && hasOtherStage2Binding(existing, editingId.value, (id) => policyTypeById.value.get(id))) {
      blockReason = t('app.security.policies.picker.blockStage2')
    } else if (existing.length >= MAX_POLICIES_PER_RULE) {
      blockReason = t('app.security.policies.picker.blockCap', { max: MAX_POLICIES_PER_RULE })
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
    name: form.value.name || t('app.security.policies.common.selfPolicy'),
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
      if (a.crsGroups.length === 0 && b.crsGroups.length === 0) overlap = [t('app.security.policies.conflict.allGroups')]
      else if (a.crsGroups.length === 0) overlap = b.crsGroups
      else if (b.crsGroups.length === 0) overlap = a.crsGroups
      else overlap = a.crsGroups.filter((g) => b.crsGroups.includes(g))
      if (overlap.length > 0) {
        const shown = overlap.slice(0, 3).join(t('app.security.policies.common.sep'))
        hints.push(t('app.security.policies.conflict.crsOverlap', { a: a.name, b: b.name, groups: shown + (overlap.length > 3 ? t('app.security.policies.common.etcSuffix') : '') }))
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
      hints.push(t('app.security.policies.conflict.bypassMiddle', { name: p.name, mode: p.ipAclMode === '绕过' ? t('app.security.policies.acl.bypassShort') : t('app.security.policies.acl.allowShort') }))
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
      hints.push(t('app.security.policies.conflict.passBlock', { earlier: earlier.name, later: later.name }))
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
    hints.push(t('app.security.policies.conflict.duplicateRule', { rule: ruleName, owners: owners.map((n) => t('app.security.policies.common.nameQuoted', { name: n })).join(t('app.security.policies.common.sep')) }))
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
        const shown = aclOverlap.slice(0, 2).join(t('app.security.policies.common.sep'))
        hints.push(t('app.security.policies.conflict.addrAclDeny', { addr: shown + (aclOverlap.length > 2 ? t('app.security.policies.common.etcSuffix') : ''), allow: allowSide.name, deny: denySide.name, detail: addressAllowDenyConflictText({ kind: 'acl', denyPolicyName: denySide.name }) }))
      }
      const trustOverlap = entriesIntersect(allowSide.ipTrustEntries, denySets[j] ?? new Set())
      if (trustOverlap.length > 0) {
        const shown = trustOverlap.slice(0, 2).join(t('app.security.policies.common.sep'))
        hints.push(t('app.security.policies.conflict.addrTrustDeny', { addr: shown + (trustOverlap.length > 2 ? t('app.security.policies.common.etcSuffix') : ''), allow: allowSide.name, deny: denySide.name, detail: addressAllowDenyConflictText({ kind: 'trust', policyType: allowSide.policyType, trustDetection: allowSide.trustDetection, denyPolicyName: denySide.name }) }))
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
    if (selfGroups.length === 0 && peer.crsGroups.length === 0) overlap = [t('app.security.policies.conflict.allGroups')]
    else if (selfGroups.length === 0) overlap = peer.crsGroups
    else if (peer.crsGroups.length === 0) overlap = selfGroups
    else overlap = selfGroups.filter((g) => peer.crsGroups.includes(g))
    if (overlap.length > 0) dups.push({ name: peer.name, overlap })
  }
  if (dups.length === 0) return ''
  const names = dups.slice(0, 2).map((d) => t('app.security.policies.common.nameQuoted', { name: d.name })).join(t('app.security.policies.common.sep')) + (dups.length > 2 ? t('app.security.policies.common.etcCountSuffix', { n: dups.length }) : '')
  let overlapUnion = [...new Set(dups.flatMap((d) => d.overlap))]
  if (overlapUnion.includes(t('app.security.policies.conflict.allGroups'))) overlapUnion = [t('app.security.policies.conflict.allGroups')]
  const overlapShown = overlapUnion.slice(0, 3).join(t('app.security.policies.common.sep')) + (overlapUnion.length > 3 ? t('app.security.policies.common.etcSuffix') : '')
  return coBound
    ? t('app.security.policies.conflict.crsOverlapNow', { names, groups: overlapShown })
    : t('app.security.policies.conflict.crsOverlapIfCoBound', { names, groups: overlapShown })
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
    .map((id) => t('app.security.policies.common.nameQuoted', { name: ipLists.value.find((l) => l.id === id)?.name ?? `#${id}` }))
  return names.length > 0 ? t('app.security.policies.conflict.fromRefLists', { names: names.join(t('app.security.policies.common.sep')) }) : ''
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
  const suffix = coBound ? '' : t('app.security.policies.conflict.ifCoBoundSuffix')
  const items: string[] = []
  for (const peer of peers) {
    for (const entry of entriesIntersect(aclAllow, peer.denySet)) {
      items.push(t('app.security.policies.conflict.selfAclDeny', { addr: entry, peer: peer.name, detail: addressAllowDenyConflictText({ kind: 'acl', denyPolicyName: peer.name }), suffix }))
    }
    for (const entry of entriesIntersect(aclDeny, peer.aclAllowSet)) {
      items.push(t('app.security.policies.conflict.selfAclAllow', { addr: entry, src: entrySourceSuffix(entry, ipACLList.value, ipACLListRefs.value), peer: peer.name, detail: addressAllowDenyConflictText({ kind: 'acl', denyPolicyName: t('app.security.policies.common.selfPolicy') }), suffix }))
    }
    for (const entry of entriesIntersect(aclDeny, peer.trustSet)) {
      items.push(t('app.security.policies.conflict.selfAclTrust', { addr: entry, src: entrySourceSuffix(entry, ipACLList.value, ipACLListRefs.value), peer: peer.name, detail: addressAllowDenyConflictText({ kind: 'trust', policyType: peer.policyType, trustDetection: peer.trustDetection, denyPolicyName: t('app.security.policies.common.selfPolicy') }), suffix }))
    }
    for (const entry of entriesIntersect(blacklist, peer.aclAllowSet)) {
      items.push(t('app.security.policies.conflict.selfDenyAllow', { addr: entry, peer: peer.name, detail: addressAllowDenyConflictText({ kind: 'acl', denyPolicyName: t('app.security.policies.common.selfPolicy') }), suffix }))
    }
    for (const entry of entriesIntersect(blacklist, peer.trustSet)) {
      items.push(t('app.security.policies.conflict.selfDenyTrust', { addr: entry, peer: peer.name, detail: addressAllowDenyConflictText({ kind: 'trust', policyType: peer.policyType, trustDetection: peer.trustDetection, denyPolicyName: t('app.security.policies.common.selfPolicy') }), suffix }))
    }
  }
  if (items.length === 0) return ''
  return items.slice(0, 2).join(t('app.security.policies.common.sepSemi')) + (items.length > 2 ? t('app.security.policies.conflict.moreSuffix', { n: items.length }) : '')
})

const whitelistSectionAlert = computed<string>(() => {
  const { peers, coBound } = comparisonContext.value
  // 信任名单同样合并引用列表条目后与对端比较
  // 三态：信任关闭零生效（与后端发射门同口径），不参与跨策略冲突比较；
  // 阶段 0 恒启用（与保存载荷 trustEnabledForPolicyType 同源）
  const trust = trustEnabledInEditor.value ? mergeIpEntries(ipWhitelist.value, ipWhitelistRefs.value) : []
  if (trust.length === 0) return ''
  const suffix = coBound ? '' : t('app.security.policies.conflict.ifCoBoundSuffix')
  const items: string[] = []
  for (const peer of peers) {
    for (const entry of entriesIntersect(trust, peer.denySet)) {
      items.push(t('app.security.policies.conflict.selfTrustDeny', { addr: entry, src: entrySourceSuffix(entry, ipWhitelist.value, ipWhitelistRefs.value), peer: peer.name, detail: addressAllowDenyConflictText({ kind: 'trust', policyType: editorPolicyType.value, trustDetection: form.value.trust_detection, denyPolicyName: peer.name }), suffix }))
    }
  }
  if (items.length === 0) return ''
  return items.slice(0, 2).join(t('app.security.policies.common.sepSemi')) + (items.length > 2 ? t('app.security.policies.conflict.moreSuffix', { n: items.length }) : '')
})

// 拦截页归因（哪条策略触发的拦截就显示哪条策略的拦截页）的两类可静态检测提示：
// ② 空页预告（warn）——策略配置了拦截页但页已删除/内容为空（后端等同无页，
// 该策略 deny 不抬码，中断落首绑定有页策略的 403 兜底路由）。
// 拦截页列表未成功落地过一次时不得判定「已删除/内容为空」——bpRes
// 部分失败会让所有启用策略挂上假警告；加载门在单源谓词内（blockPageMissing）。
const blockPageBroken = (e: ChainEntry): boolean =>
  blockPageMissing(e.blockPageId ?? 0, blockPages.value, blockPagesLoaded.value)

// 本策略拦截页「按阶段实际生效」判定——单源走 resolveBlockPageAttribution
// （与 caddy.go 触发归因口径逐条对齐：阶段 1 deny 链/阶段 3 逐策略合成码，
// 阶段 2 429 恒走兜底路由）。旧实现 `enabled && block_page_id>0` 恒渲染绿色
// 「生效中」，多策略绑定下是假绿。
const BLOCK_PAGE_STAGE_LABEL: Record<BlockPageStage, string> = { 1: t('app.security.policies.stageName.s1'), 2: t('app.security.policies.stageName.s2'), 3: t('app.security.policies.stageName.s3') }
const pageHasContent = (id: number): boolean =>
  blockPagesLoaded.value && id > 0 && !blockPageMissing(id, blockPages.value, blockPagesLoaded.value)
const editorBlockPageStages = (): BlockPageStage[] => {
  const type = normalizePolicyType(editorPolicyType.value)
  if (type === 'stage1') return [1]
  if (type === 'stage2') return [2]
  if (type === 'stage3') return [3]
  if (type === 'mixed') return [1, 2, 3]
  return [] // stage0 无拦截页概念
}
// 归因输入（单源 resolveBlockPageAttribution 的视图适配）：链序=绑定执行序
// （buildDisplayChain，兜底扫描按此序取首个有页策略）。stage1DenyContributor
// 仅 isSelf 消费——本策略是否发射可触发拦截的阶段 1 deny 链（deny 模式 ACL
// 有条目 ∪ 独立黑名单非空 ∪ GeoIP 启用有区域）；allow 模式 ACL 只参与交集外
// 恒拒（兜底路由），无归属语义。
const selfDenyContributor = computed<boolean>(() =>
  (form.value.ip_acl_enabled && form.value.ip_acl_mode !== 'allow' && form.value.ip_acl_mode !== '绕过' && aclMergedCount.value > 0)
  || ipBlacklistSelf.value.length > 0
  || (form.value.geoip_enabled && geoipCountries.value.length > 0))

const attributionInput = (chain: ChainEntry[]): BlockPageChainPolicy[] => chain.map((e) => ({
  policyId: e.policyId,
  name: e.name,
  enabled: e.enabled,
  isSelf: e.isSelf,
  blockPageId: e.blockPageId ?? 0,
  pageHasContent: pageHasContent(e.blockPageId ?? 0),
  // 列表摘要无 rate_limit_enabled 原始字段——has_rate_limit 即「启用且 rps>0」
  // （后端同一判定），用于阶段 2 是否可能产生 429 的门。
  stage1DenyContributor: e.isSelf ? selfDenyContributor.value : undefined,
}))

// 能力门：归因只判「页有效 + 触发归属/链位置」，不看该阶段是否真的会拦截——
// stage3 默认 off、stage1 无 ACL/地域/黑名单 deny 链时页面永不显示。不过门会
// 与同页「WAF 关闭」「未启用 ACL」的摘要自相矛盾。
const stageCapableOf = (stage: BlockPageStage): boolean => blockPageStageCanIntercept({
  stage,
  mode: form.value.mode,
  hasBlockingCustomRule: selectedCustomRules.value.some((id) => {
    const rule = allCustomRules.value.find((r) => r.id === id)
    return !!rule && customRuleCanBlockInMode(form.value.mode, rule)
  }),
  hasAclEntries: form.value.ip_acl_enabled && form.value.ip_acl_mode !== '绕过' && aclMergedCount.value > 0,
  hasBlacklistEntries: ipBlacklistSelf.value.length > 0,
  hasGeoip: form.value.geoip_enabled && geoipCountries.value.length > 0,
})

// 逐阶段归因（过能力门）：拦截页步骤注记与关联规则行内提示共用同一结果。
const capableAttributions = (chain: ChainEntry[]): BlockPageAttribution[] => {
  const stages = editorBlockPageStages()
  return stages
    .filter((stage) => stageCapableOf(stage))
    .map((stage) => resolveBlockPageAttribution(stage, attributionInput(chain)))
}

// 关联规则步骤归属汇总行（单源派生）：兜底目标名在全部规则一致时点名，否则泛指。
const bindingsSummaryLine = computed<string>(() => {
  const total = boundRuleRows.value.length
  const winners = new Set<string>()
  for (const row of boundRuleRows.value) {
    for (const r of capableAttributions(row.chain)) {
      if (r.effective === 'peer' && r.winnerName) winners.add(r.winnerName)
    }
  }
  const winnerPart = winners.size === 1 ? t('app.security.policies.common.nameQuoted', { name: [...winners][0] ?? '' }) : ''
  return t('app.security.policies.bp.bindingsAttribution', { n: total, winner: winnerPart })
})

// 拦截页步骤归属汇总卡（用户验收裁定：逐条重复提示收敛为主行 + 例外分面 +
// 能力门行）。数据源复用绑定列表（boundRuleRows 的链）与 capableAttributions
// 单源，不平行实现。类型门先行：阶段 0 策略无拦截页概念（向导无该步骤、
// 后端归一 block_page_id=0）——不出任何页面提示。
const blockPageSummary = computed<{ lines: Array<{ text: string; tone: 'active' | 'info' | 'warning' }> } | null>(() => {
  const editorStages = editorBlockPageStages()
  if (editorStages.length === 0) return null
  const total = boundRuleRows.value.length
  const lines: Array<{ text: string; tone: 'active' | 'info' | 'warning' }> = []
  if (total === 0) return { lines: [{ text: t('app.security.policies.bind.none'), tone: 'info' }] }
  const pageId = form.value.block_page_id
  const page = pageId > 0 ? blockPages.value.find((p) => p.id === pageId) : undefined
  const pageName = page ? pageLabel(page) : t('app.security.policies.common.pageNum', { n: pageId })
  const pageInvalid = pageId > 0 && blockPagesLoaded.value && blockPageMissing(pageId, blockPages.value, blockPagesLoaded.value)
  // 主行（触发归因总述；未落地不做生效判定）
  if (!blockPagesLoaded.value) {
    lines.push({ text: t('app.security.policies.bp.listUnavailable'), tone: 'info' })
  } else if (pageId <= 0) {
    lines.push({ text: editorPolicyType.value === 'stage2'
      ? t('app.security.policies.bp.stage2NoPage', { n: total })
      : t('app.security.policies.bp.noPageFallback', { n: total }), tone: 'info' })
  } else if (pageInvalid) {
    lines.push({ text: t('app.security.policies.bp.pageInvalid', { n: total }), tone: 'warning' })
    lines.push({ text: t('app.security.policies.bp.fallbackNote'), tone: 'info' })
  } else {
    lines.push({ text: t('app.security.policies.bp.pageActive', { n: total, page: pageName }), tone: 'active' })
  }
  // 能力门行：页面配置了但当前配置不会产生该阶段拦截 → 页面不会被使用
  const capableStages = new Set(editorStages.filter((stage) => stageCapableOf(stage)))
  for (const stage of editorStages.filter((s) => !capableStages.has(s))) {
    lines.push({ text: t('app.security.policies.bp.stageIneffective', { stage: BLOCK_PAGE_STAGE_LABEL[stage] }), tone: 'info' })
  }
  // 例外分面（按规则归类，仅存在才渲染）：TCP > 限流 > 兜底差异
  let tcpCount = 0
  let fallbackCount = 0
  for (const row of boundRuleRows.value) {
    if (row.protocol === 'tcp') { tcpCount++; continue }
    if (!pageInvalid && pageId > 0 && capableAttributions(row.chain).some((r) => r.effective === 'peer')) fallbackCount++
  }
  if (tcpCount > 0) lines.push({ text: t('app.security.policies.bp.tcpFacet', { n: tcpCount }), tone: 'info' })
  if (fallbackCount > 0) lines.push({ text: t('app.security.policies.bp.fallbackFacet', { n: fallbackCount }), tone: 'info' })
  return { lines }
})

// Step 4 已关联规则的逐条视图：绑定链 + 执行序 + 行内归属提示 + 冲突提示
const boundRuleRows = computed<BoundRuleRow[]>(() => boundRules.value.map((caddyId) => {
  const rule = allRules.value.find((r) => r.caddy_id === caddyId)
  const chain = buildDisplayChain(caddyId)
  const enabledEntries = chain.filter((e) => e.enabled)
  // ② 空页预告（warn 级，与冲突提示同管线）：失效页策略触发时由兜底路由显示
  // 绑定链首个有页策略的页面（触发归因，见 resolveBlockPageAttribution）。
  const emptyPageHints = enabledEntries
    .filter((e) => blockPageBroken(e))
    .map((e) => t('app.security.policies.bind.deadPageHint', { name: e.name }))
  // ① 配置不一致提示（info 级）：启用策略间 (拦截页, 状态码) 组合不一致——
  // 非错误，声明触发归因语义（触发策略显示自己的页；未配置的策略触发时兜底）
  const combos = new Set(enabledEntries.map((e) => `${e.blockPageId ?? 0}:${e.blockStatusCode || 403}`))
  const infoHints: string[] = []
  if (rule?.protocol === 'tcp') {
    // TCP（L4）规则能力注记：拒绝动作=断连（无 HTTP 拦截页/状态码面）；
    // CDN 回源真实客户端 IP 依赖上游连接的 PROXY protocol（回源对端是 CDN 时必须开启）
    infoHints.push(t('app.security.policies.bind.tcpHint'))
  }
  if (enabledEntries.length > 1 && combos.size > 1) {
    infoHints.push(t('app.security.policies.bind.mixedPagesHint'))
  }
  return {
    caddyId,
    name: rule?.name || caddyId,
    protocol: rule?.protocol || 'http',
    domain: rule?.domain || '',
    listenPort: rule?.listen_port ?? 0,
    chain,
    // 性能提示应按实际生效的处理链计——禁用策略不产生处理链，
    // 计入会虚高（提示"超过 3 条可能影响性能"在不达 3 条时误报）。
    mergedCount: enabledEntries.length,
    showPerfTip: enabledEntries.length > PERF_POLICY_THRESHOLD,
    hints: [...computeBindingConflicts(buildConflictChain(caddyId)), ...emptyPageHints],
    infoHints,
  }
}))

// 步骤顶紧凑预警（用户裁定：三条灰横幅按预警语义收敛为两条条件行——
// 低价值的「拦截页/状态码不同」进各规则行 infoHint（触发归因语义自明）；
// TCP 断连注记仅在绑定 TCP 规则时出现）。
const boundRuleWarnPerf = computed(() => boundRuleRows.value.some((r) => r.showPerfTip))
const hasTcpBoundRule = computed(() => boundRuleRows.value.some((r) => r.protocol === 'tcp'))


// 配置预览 = 三阶段投影（策略视角）：以「本策略为唯一绑定」构造模型——
// 与规则侧流程抽屉共用 buildStageModel 同一投影；阶段外字段按类型裁剪（与服务端
// 显式 policy_type 提交时的归一零值同口径，预览即所得）
const previewModel = computed<RuleStageModel>(() => {
  const previewPolicy: SecurityStagePolicy = {
    id: editingId.value ?? 0,
    name: form.value.name || t('app.security.policies.common.selfPolicy'),
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
    has_geoip: typeAllowsStage(1) && form.value.geoip_enabled && geoipCountries.value.length > 0,
    has_custom_rules: typeAllowsStage(3) && selectedCustomRules.value.length > 0,
    geoip_countries: JSON.stringify(typeAllowsStage(1) ? geoipCountries.value : []),
    custom_rules_count: typeAllowsStage(3) ? selectedCustomRules.value.length : 0,
    ip_acl_mode: form.value.ip_acl_mode,
    ip_acl_list: JSON.stringify(ipACLList.value),
    ip_whitelist: JSON.stringify(ipWhitelist.value),
    human_verify_mode: form.value.human_verify_mode,
    human_verify_type: form.value.human_verify_type,
    human_verify_ttl: form.value.human_verify_ttl,
    human_exempt_paths: form.value.human_exempt_paths,
    cc_detect_enabled: form.value.cc_detect_enabled,
    cc_rps_limit: form.value.cc_rps_limit,
    cc_rps_window: form.value.cc_rps_window,
    cc_4xx_ratio: form.value.cc_4xx_ratio,
    cc_session_anomaly: form.value.cc_session_anomaly,
    cc_session_ua_threshold: form.value.cc_session_ua_threshold,
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
      block_page_id: showBlockPage ? form.value.block_page_id : 0,
      block_status_code: form.value.block_status_code,
    }],
    [previewPolicy],
    ipLists.value,
    blockPagesLocalized.value,
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
  pickerProtoFilter.value = 'http'
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
  if (!name) { ElMessage.warning(t('app.security.policies.msg.listNameRequired')); return }
  if (name.length > 50) { ElMessage.warning(t('app.security.policies.msg.listNameTooLong')); return }
  if (extractForm.value.category.length > 32) { ElMessage.warning(t('app.security.policies.msg.categoryTooLong')); return }
  const sourceEntries = extractSourceEntries.value.map((value) => value.trim()).filter((value) => value !== '')
  if (sourceEntries.length === 0) { ElMessage.warning(t('app.security.policies.msg.extractEmpty')); return }
  if (sourceEntries.length > 2000) { ElMessage.warning(t('app.security.policies.msg.extractMax')); return }
  try {
    await ElMessageBox.confirm(t('app.security.policies.msg.extractConfirm', { name, n: sourceEntries.length }), t('app.security.policies.common.confirmTitle'), { type: 'warning' })
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
      entries: JSON.stringify(sourceEntries.map((value) => ({ value, remark: t('app.security.policies.extract.remark') }))),
    })
    const newId = res.data?.id
    if (!newId) throw new Error(t('app.security.policies.msg.createdListNoId'))
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
    showSaveResult(res as unknown as { message?: string }, t('app.security.policies.msg.extractDone', { name }))
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
      if (!d) throw new Error(t('app.security.policies.msg.detailNoData'))
      form.value = {
        name: d.name,
        description: d.description,
        enabled: d.enabled,
        mode: d.mode,
        anomaly_threshold: d.anomaly_threshold,
        ip_acl_enabled: d.ip_acl_enabled,
        ip_acl_mode: d.ip_acl_mode ?? '',
        block_page_id: d.block_page_id,
        block_status_code: d.block_status_code || 403,
        block_response_mode: d.block_response_mode || 'auto',
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
        human_verify_mode: d.human_verify_mode ?? 'off',
        human_verify_type: d.human_verify_type ?? 'slider',
        human_verify_ttl: d.human_verify_ttl ?? 30,
        human_exempt_paths: Array.isArray(d.human_exempt_paths) ? d.human_exempt_paths : parseIPList(d.human_exempt_paths as unknown as string),
        cc_detect_enabled: d.cc_detect_enabled ?? false,
        cc_rps_limit: d.cc_rps_limit ?? 40,
        cc_rps_window: d.cc_rps_window ?? 10,
        cc_4xx_ratio: d.cc_4xx_ratio ?? 70,
        cc_session_anomaly: d.cc_session_anomaly ?? false,
        cc_session_ua_threshold: d.cc_session_ua_threshold ?? 5,
        cc_response: d.cc_response ?? 'verify',
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
          ElMessage.warning(t('app.security.policies.msg.pageResetDefault'))
        }
      } else if (form.value.block_page_id > 0 && !blockPagesFresh) {
        ElMessage.warning(t('app.security.policies.msg.pageRefreshFailed'))
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
  // 规则行（执行序/投影数据源）同节奏刷新一次，与绑定明细同口径
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
  bindingOrderEdits.value = {}
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
  bindingOrderEdits: bindingOrderEdits.value,
})
const wizardDirty = computed(() => dialogVisible.value && wizardSnapshot !== '' && wizardStateSnapshot() !== wizardSnapshot)

const resetWizard = () => {
  currentStep.value = WIZARD_STEP.BASIC
  editingId.value = null
  editingPolicyType.value = null
  rulePickerVisible.value = false
  ruleBoundPolicies.value = {}
  // 执行序暂存须随向导复位清空——否则编辑策略 A 暂存的新顺序会跨会话
  // 泄漏到绑定同规则的策略 B（保存时按 A 的暂存序提交）。
  bindingOrderEdits.value = {}
  wizardSnapshot = ''
}

const beforeWizardClose = (done: () => void): void => {
  if (saving.value) return
  if (!wizardDirty.value) {
    done()
    return
  }
  void ElMessageBox.confirm(t('app.security.policies.msg.unsavedConfirm'), t('app.security.policies.msg.discard'), {
    type: 'warning', confirmButtonText: t('app.security.policies.msg.discard'), cancelButtonText: t('app.security.policies.msg.keepEditing'),
  }).then(() => done()).catch(() => { /* 继续编辑：保留当前弹框与全部暂存 */ })
}

const handleSave = async () => {
  if (saving.value) return
  if (!form.value.name.trim()) {
    ElMessage.warning(t('app.security.policies.msg.nameRequired'))
    currentStep.value = WIZARD_STEP.BASIC
    return
  }
  // 类型裁剪后的阶段不参与校验（步骤已被裁剪，校验跳转目标不存在）
  // 阶段 0 信任名单策略：名单（内联∪引用合并口径）必须非空
  if (typeAllowsStage(0) && whitelistSaveCount.value === 0) {
    ElMessage.error(t('app.security.policies.msg.stage0NeedsIp'))
    currentStep.value = WIZARD_STEP.TRUST
    return
  }
  // stage0 信任内联条目此前绕过 CIDR 前置校验（开关门恒
  // false、typeAllowsStage(1) 恒 false）——逐条前置，报错带定位（后端 400 兜底）。
  if (typeAllowsStage(0)) {
    const bad = ipWhitelist.value.find((v) => !isValidCidr(v))
    if (bad !== undefined) {
      ElMessage.error(t('app.security.policies.msg.invalidTrustEntry', { entry: bad }))
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
    ElMessage.error(t('app.security.policies.msg.crawlerNoneSelected'))
    currentStep.value = WIZARD_STEP.IP_ACL
    return
  }
  // 白名单空生效集：warning-not-block（用户裁定）。不再阻断保存，改为显性确认
  // 后照常保存（与 ipListSaveGuard 先例同形态）；运行时 fail-closed 恒拒语义
  // 不变，确认文案与渲染事实一致。
  if (typeAllowsStage(1) && form.value.ip_acl_enabled && form.value.ip_acl_mode === 'allow' && aclSaveCount.value === 0) {
    try {
      await ElMessageBox.confirm(t('app.security.policies.msg.emptyAllowConfirm'), t('app.security.policies.msg.emptyAllowTitle'), { type: 'warning', confirmButtonText: t('app.security.policies.common.continueSave'), cancelButtonText: t('app.security.policies.common.cancel') })
    } catch { return }
  }
  // 保存确认（与提取为列表/删除确认同款 warning 弹窗）：取消静默返回，不进入提交
  try {
    await ElMessageBox.confirm(t('app.security.policies.msg.saveConfirm', { name: form.value.name.trim() }), t('app.security.policies.common.confirmTitle'), { type: 'warning' })
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
      const names = overLimit.map((id) => allRules.value.find((r) => r.caddy_id === id)?.name || id).join(t('app.security.policies.common.sep'))
      ElMessage.error(t('app.security.policies.msg.capReached', { max: MAX_POLICIES_PER_RULE, names }))
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
      const names = stage2Conflict.map((id) => allRules.value.find((r) => r.caddy_id === id)?.name || id).join(t('app.security.policies.common.sep'))
      ElMessage.error(t('app.security.policies.msg.stage2Conflict', { names }))
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
      crsRuleGroups: crsRuleGroups.value,
      crsExcludedRules: serializedExcludedRules.value,
      customRuleIds: selectedCustomRules.value,
      blockPageId: form.value.block_page_id,
      blockStatusCode: form.value.block_status_code,
      blockResponseMode: form.value.block_response_mode,
      geoipCountries: geoipCountries.value,
      geoipEnabled: form.value.geoip_enabled,
      geoipMode: form.value.geoip_mode,
      geoipCrawlerExempt: form.value.geoip_crawler_exempt,
      geoipCrawlerEngines: form.value.geoip_crawler_engines ?? [],
      wafCheckResponse: form.value.waf_check_response,
      logRequestBody: form.value.log_request_body,
      trustDetection: form.value.trust_detection,
      policyType: editorPolicyType.value,
      humanVerifyMode: form.value.human_verify_mode,
      humanVerifyType: form.value.human_verify_type,
      humanVerifyTtl: form.value.human_verify_ttl,
      humanExemptPaths: form.value.human_exempt_paths,
      ccDetectEnabled: form.value.cc_detect_enabled,
      ccRpsLimit: form.value.cc_rps_limit,
      ccRpsWindow: form.value.cc_rps_window,
      cc4xxRatio: form.value.cc_4xx_ratio,
      ccSessionAnomaly: form.value.cc_session_anomaly,
      ccSessionUaThreshold: form.value.cc_session_ua_threshold,
      ccResponse: form.value.cc_response,
    })
    let saveRes: APIResponse<{ id: number }> | undefined
    if (editingId.value) {
      saveRes = await request.put(`/security/policies/${editingId.value}`, payload)
    } else {
      saveRes = await request.post<APIResponse<{ id: number }>>('/security/policies', payload)
      const createdId = saveRes.data?.id
      if (!createdId) throw new Error(t('app.security.policies.msg.createdPolicyNoId'))
      editingId.value = createdId
      // 新建落库即转入已保存实体（后续 bind/执行序提交用新 id）——同步锁定
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
        ? t('app.security.policies.msg.bindRejected')
        : t('app.security.policies.msg.bindPartialFail'))
      return
    }
    // 绑定执行序应用（用户裁定：策略顺序=执行序）：随批量端点 orders 字段单事务
    // 应用——N 条规则一次渲染+一次 reload（逐规则整链 PUT 是 N×渲染+reload 的
    // 保存耗时回归，v2.2.0 批量绑定同因修过一次）。单规则校验失败进 skipped
    // 不整体拒绝：坏规则保持「顺序待保存」待下次保存重试，好规则即时清标记；
    // 与现状一致的顺序服务端零写入幂等（unchanged，不推 cluster_version）。
    // bind/unbind 与 orders 分请求提交（同一规则混入两者是后端 400 冲突面）。
    const skippedOrderNotes: string[] = []
    for (const ids of chunkForBulk(orderEditedRules.value, SECURITY_BULK_LIMITS.policyBindings)) {
      const orders: Record<string, number[]> = {}
      // orders 合并：staged 对「打开时基线」的重排应用到**最新基线链**
      // （serverChainOrder 读保存前刷新的 securityBindings 快照）——整链重建语义
      // 下，staged 未涉及的并发新增/本次 bulk bind 新绑定成员不再被静默剔除，
      // 按其阶段锚定最近同阶段成员后（无锚点尾插）；staged 相对序与阶段 0 置顶
      // 归一不变式由 mergeChainOrder 单源保证。
      for (const caddyId of ids) {
        orders[caddyId] = mergeChainOrder(
          bindingOrderEdits.value[caddyId] ?? [],
          serverChainOrder(caddyId),
          (id) => policyTypeById.value.get(id),
        )
      }
      try {
        const res = await request.post<APIResponse<{ ordered?: number; unchanged?: number; skipped?: Array<{ rule_id: string; reason: string }> }>>(`/security/policies/${editingId.value}/bindings/bulk`, {
          bind: [],
          unbind: [],
          orders,
        })
        bindResponses.push(res as { message?: string })
        const skippedItems = res.data?.skipped ?? []
        // 先归集 skipped 再回写——被跳过的规则未应用新序，保持「顺序待保存」
        // 待重试；成功规则即时清标记，下次保存重试只补坏规则。
        const skippedIds = new Set(skippedItems.map((item) => item.rule_id))
        const next = { ...bindingOrderEdits.value }
        for (const caddyId of ids) {
          if (skippedIds.has(caddyId)) {
            for (const item of skippedItems) {
              if (item.rule_id === caddyId) {
                skippedOrderNotes.push(t('app.security.policies.msg.orderSkipNote', { name: allRules.value.find((rule) => rule.caddy_id === caddyId)?.name || caddyId, reason: item.reason }))
              }
            }
          } else {
            delete next[caddyId]
          }
        }
        bindingOrderEdits.value = next
      } catch (error: unknown) {
        // 失败不静默：整片保持暂存，对话框保持打开以便重试（与绑定同步失败同款
        // 处理：结构性 400 不承诺可重试，其余幂等重试安全）。
        console.error('apply binding order failed', error)
        ElMessage.warning(error instanceof ApiRequestError && error.status === 400
          ? t('app.security.policies.msg.orderRejected')
          : t('app.security.policies.msg.orderPartialFail'))
        return
      }
    }
    if (skippedOrderNotes.length > 0) {
      ElMessage.warning(t('app.security.policies.msg.orderSkipped', { notes: skippedOrderNotes.join(t('app.security.policies.common.sepSemi')) }))
    }
    // 保存结果单条呈现：服务端 message 与 Caddy 退化后缀原样保留。
    showSaveResult(
      { message: saveRes?.message || t('app.security.policies.common.saveSuccess') },
      t('app.security.policies.common.saveSuccess'),
    )
    // 2026-09-08 审计 FE1：bind/执行序的退化 200+后缀也需可见（有后缀才弹，
    // 无后缀不重复 toast）；汇总全部分片而非末片。
    const mergedBind = mergeBulkResults(bindResponses)
    if (mergedBind?.message?.includes(CADDY_APPLY_FAILED_MARKER)) showSaveResult(mergedBind, '')
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
      ElMessage.error(error instanceof Error ? error.message : t('app.security.policies.msg.saveFailed'))
    }
  } finally { saving.value = false }
}

const deletingPolicyId = ref<number | null>(null)
function handleDelete(row: PolicySummary) {
  // 重入守卫(快速双击叠加双确认框→双 DELETE 误报)+
  // 取消与失败分离(原空 catch 同时吞掉网络失败,行滞留至下轮)。
  if (deletingPolicyId.value !== null) return
  deletingPolicyId.value = row.id
  ElMessageBox.confirm(t('app.security.policies.msg.deleteConfirm', { name: row.name }), t('app.security.policies.msg.deleteTitle'), { type: 'warning', confirmButtonText: t('app.security.policies.msg.deleteConfirmBtn'), cancelButtonText: t('app.security.policies.common.cancel') })
    .then(async () => {
      const del = await request.delete(`/security/policies/${row.id}`)
      showSaveResult(del, t('app.security.policies.common.deleted'))
      fetchData()
    })
    .catch(() => { /* 用户取消:不动列表;HTTP 失败已由全局拦截器 toast */ })
    .finally(() => { deletingPolicyId.value = null })
}

const goToCustomRulesPage = () => { window.open(pageUrl('security-rules', { [DEEP_LINK_PARAMS.securityRulesTab]: 'custom' }), '_blank', 'noopener') }
const goToBlockPagesPage = () => { window.open(pageUrl('security-block-pages'), '_blank', 'noopener') }
const openRuleInNewTab = (caddyId: string): void => {
  // 交接改走 URL query（rs 参数），Rules.vue onMounted 消费后清除。
  window.open(pageUrl('rules', { [DEEP_LINK_PARAMS.ruleSearch]: caddyId }), '_blank', 'noopener')
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
    ElMessage.error(t('app.security.policies.msg.regionLoadFailed'))
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
    else ElMessage.warning(t('app.security.policies.msg.policyDeleted', { id: focusId }))
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
.wizard-steps :deep(.el-step__title) { white-space: nowrap; font-size: 13px; }
html[data-locale='en'] .wizard-steps :deep(.el-step__title) { font-size: 14px; }
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
/* 排除编辑器外层容器：el-form-item__content 是 flex 列，裸 div 子项收缩到内容
   自然宽（旧行比同步骤全宽控件窄 ~100px+，2026-11-03 用户验收反馈）——
   width:100% 填满内容列（与同步骤 cascader/select 全宽控件同机制，不写死 px） */
.exclusion-body { width: 100%; min-width: 0; }
/* 表单项内警示条撑满控件列（flex 子项缺省收缩贴内容）；盒模型走全局
   info-note-bar 规范（padding 8px 12px），此处仅布局不碰样式 */
.form-item-note-bar { width: 100%; }
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
/* 作用域 radios 自然紧凑宽；条件控件内联其后，条件区为恒定槽位——四态（ip 标签
   输入 / list 选择器 / path 前缀输入 / all 灰字短提示）同 flex 规格（1 1 200、
   min 160；ip/path max 300、list/all max 240），切换作用域不改变剩余空间分配，
   目标输入宽与 radios 位置恒定不抖动；控件统一 small（24px）与目标输入同高。
   ip/list 给确定 flex-basis（200px）而非 auto：el-select 根元素默认 width:100%
   （--el-select-width），basis:auto 会以整行宽参与 flex 折行判定（clamp 到
   max-width 240），行宽不足时被提前折到第二行 */
.exclusion-row-cell :deep(.exclusion-scope-radios) { flex: 0 0 auto; }
.exclusion-row-cell :deep(.exclusion-scope-radios .el-radio) { margin-right: 8px; }
.exclusion-row-cell :deep(.exclusion-scope-radios .el-radio:last-child) { margin-right: 0; }
.exclusion-row-cell :deep(.exclusion-scope-control-ip) { flex: 1 1 200px; min-width: 160px; max-width: 300px; }
.exclusion-row-cell :deep(.exclusion-scope-control-list) { flex: 1 1 200px; min-width: 160px; max-width: 240px; }
/* path 前缀输入与 ip 标签输入同一 flex 规格（四态条件区同槽位，切换作用域不抖动） */
.exclusion-row-cell :deep(.exclusion-scope-control-path) { flex: 1 1 200px; min-width: 160px; max-width: 300px; }
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
/* 关联规则步骤：列表定高自滚——本步唯一滚动容器，弹框 body 不再出第二条滚动条 */
.policy-wizard-dialog .bound-rule-list { max-height: 40vh; min-height: 200px; overflow-y: auto; padding-right: 4px; }
.bound-rule-row { border: 1px solid #ebeef5; padding: 12px; }
.bound-rule-head { display: flex; align-items: center; gap: 8px; }
.bound-rule-name { font-weight: 500; color: #1f2937; font-size: 13px; }
.bound-rule-meta { font-size: 12px; color: #9ca3af; font-family: monospace; }
.bound-rule-remove { margin-left: 6px; }
.bound-rule-chain { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin-top: 6px; }


/* 2026-10-03 模板归一：向导表单内提示条不再有「表单项控件列」载体——
   统一为 el-form-item 包裹（EP label-width 自动对齐控件列，零 CSS 覆盖）
   单条缩进规则（宽度随容器自适应，无第二种弹框样式）。 */

.binding-order-chip { font-size: 12px; padding: 0 6px; border-radius: 10px; background: #f3f4f6; color: #4b5563; border: 1px solid #e5e7eb; display: inline-flex; align-items: center; line-height: 18px; vertical-align: middle; }
.binding-order-chip.is-self { font-weight: 700; box-shadow: inset 0 0 0 1px currentColor; }
.binding-order-chip.is-disabled { opacity: 0.55; text-decoration: line-through; }
/* 同阶段同色（阶段语义靠颜色区分，文案只保留序号）。 */
.binding-order-chip.stage-0 { background: #ecfdf5; color: #047857; border-color: #a7f3d0; }
.binding-order-chip.stage-1 { background: #eff6ff; color: #1d4ed8; border-color: #bfdbfe; }
.binding-order-chip.stage-2 { background: #f5f3ff; color: #6d28d9; border-color: #ddd6fe; }
.binding-order-chip.stage-3 { background: #ecfeff; color: #0e7490; border-color: #a5f3fc; }
.binding-order-chip.stage-mixed { background: #f3f4f6; color: #4b5563; border-color: #e5e7eb; }

/* 拦截页归属汇总卡（用户验收裁定：逐条重复提示收敛为主行+例外分面；
   info-note 全局规范 + tone 修饰，禁局部 hack） */
.block-page-summary { margin-top: 8px; width: 100%; }
.block-page-summary-line { display: flex; align-items: flex-start; gap: 6px; margin: 4px 0 0; padding: 6px 10px; }
.block-page-summary-line:first-child { margin-top: 0; }
.block-page-summary-line .info-note-desc { font-weight: 500; }
.block-page-summary-icon { flex: none; margin-top: 2px; color: var(--el-color-info); }
.block-page-summary-line.is-active { border-style: solid; border-color: var(--el-color-success-light-5); background: var(--el-color-success-light-9); }
.block-page-summary-line.is-active .block-page-summary-icon { color: var(--el-color-success); }
.block-page-summary-line.is-active .info-note-desc { color: var(--el-color-success-dark-2); }
.block-page-summary-line.is-warning { border-style: solid; border-color: var(--el-color-warning-light-5); background: var(--el-color-warning-light-9); }
.block-page-summary-line.is-warning .block-page-summary-icon { color: var(--el-color-warning); }
.block-page-summary-line.is-warning .info-note-desc { color: var(--el-color-warning-dark-2); }

.rule-binding-preview { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin: 2px 0 4px 24px; }
.rule-binding-landing { font-size: 12px; color: #6b7280; }
.rule-binding-limit { font-size: 12px; color: #e6a23c; }

.rule-picker-toolbar { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; }
.rule-picker-toolbar .rule-picker-search { flex: 1; margin-bottom: 0; }
.rule-picker-proto-filter { width: 104px; flex-shrink: 0; }

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
.rule-picker-item :deep(.el-checkbox__label) { display: inline-flex; align-items: center; gap: 8px; }
.rule-picker-proto { margin: 0; flex-shrink: 0; }
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

/* 关联规则行内：执行序上移/下移（暂存随保存提交）+ 归属紧凑标识 */
.bound-rule-order { display: inline-flex; align-items: center; gap: 6px; margin-left: auto; }
.bound-rule-order-tag { margin-right: 2px; }

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

/* 策略向导弹框整体限高（flex 列）：弹框不超视口，唯一滚动容器=正文
 * （关联规则多时只出一条滚动条；header/步骤条/footer 固定）。 */
.policy-wizard-dialog.el-dialog {
  display: flex;
  flex-direction: column;
  max-height: calc(100vh - 60px);
  margin-top: 30px !important;
  margin-bottom: 30px !important;
  overflow: hidden;
}
.policy-wizard-dialog .el-dialog__header,
.policy-wizard-dialog .el-dialog__footer { flex-shrink: 0; }
.policy-wizard-dialog .el-dialog__body {
  flex: 1 1 auto;
  min-height: 0;
  overflow-y: auto;
}

/* 已关联规则行的协议徽标（TCP 青/HTTP 蓝全局单源 + 间距）。 */
.rule-proto-badge { margin-right: 8px; vertical-align: middle; flex-shrink: 0; }
.policy-rules-popper .el-dropdown-menu__item { font-size: 12px; line-height: 1.6; }
/* reference 是真按钮（原为无激活行为的 span）：清掉 UA 按钮外观，保留文本外观
   与焦点环；键盘激活交给 el-dropdown 的 click 触发 */
.policy-rule-count {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 24px;
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
/* 排除目标自动补全（el-autocomplete，面板 teleported 到 body）：两列建议——左列
   规则 ID 定宽等宽字体，右列「描述（文件名）」单行省略；item 内建 title 悬浮全文 */
.crs-rule-popper .crs-rule-suggestion { display: flex; align-items: baseline; gap: 10px; padding: 2px 0; }
.crs-rule-popper .crs-rule-suggestion-id { flex: 0 0 auto; min-width: 52px; font-family: monospace; font-size: 13px; color: #1f2937; }
.crs-rule-popper .crs-rule-suggestion-desc { flex: 1 1 auto; min-width: 0; font-size: 12px; color: #6b7280; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
/* 两行规则叶节点：el-cascader-node 默认 34px 定高 / label 单行省略会裁切副行——
   含 .crs-rule-option 的节点覆写为高度自适应 + label 允许换行；单行组节点不受影响 */
.crs-rule-popper .el-cascader-node:has(.crs-rule-option) { height: auto; line-height: 1.4; padding-top: 5px; padding-bottom: 5px; }
.crs-rule-popper .el-cascader-node:has(.crs-rule-option) .el-cascader-node__label { white-space: normal; overflow: visible; text-overflow: clip; line-height: 1.4; }
.crs-rule-option { display: flex; flex-direction: column; line-height: 1.4; padding: 4px 0 5px; }
.crs-rule-option-label { font-size: 13px; }
.crs-rule-option-meta { font-size: 12px; color: #9ca3af; }
</style>
