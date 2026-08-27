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

    <el-card>
      <div class="table-toolbar">
        <el-input v-model="policySearch" placeholder="搜索策略名称" clearable :prefix-icon="Search" class="search-input" />
      </div>
      <el-table :data="filteredPolicies" v-loading="loading" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="">
        <template #empty>
          <el-empty description="暂无安全策略" :image-size="60" />
        </template>
        <el-table-column prop="name" label="策略名称" min-width="140">
          <template #default="{ row }">
            <el-link type="primary" @click="openDialog(row)">{{ row.name }}</el-link>
          </template>
        </el-table-column>
        <el-table-column label="WAF 模式" width="100" align="center">
          <template #default="{ row }">
            <el-tag v-if="row.mode === 'blocking'" type="danger" size="small" effect="light">拦截</el-tag>
            <el-tag v-else-if="row.mode === 'detection'" type="warning" size="small" effect="light">检测</el-tag>
            <el-tag v-else type="info" size="small" effect="plain">关闭</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="关联规则" width="100" align="center">
          <template #default="{ row }">
            <el-tooltip v-if="policyBoundRules(row.id).length > 0" placement="top" popper-class="policy-rules-popper">
              <template #content>
                <div v-for="rule in policyBoundRules(row.id)" :key="rule.caddy_id" class="policy-rule-row" @click="openRuleInNewTab(rule.caddy_id)">
                  {{ rule.name }} ({{ rule.caddy_id }})
                </div>
              </template>
              <span>{{ row.rule_count }}</span>
            </el-tooltip>
            <template v-else>{{ row.rule_count }}</template>
          </template>
        </el-table-column>
        <el-table-column label="防护能力" min-width="220">
          <template #default="{ row }">
            <div class="capability-tags">
              <el-tooltip v-if="row.has_waf" :content="wafTip(row)" placement="top">
                <el-tag size="small" effect="plain">WAF</el-tag>
              </el-tooltip>
              <el-tooltip v-if="hasIpControl(row)" :content="ipControlTip(row)" placement="top">
                <el-tag size="small" type="success" effect="plain">IP 控制</el-tag>
              </el-tooltip>
              <el-tooltip v-if="row.has_rate_limit" :content="`${row.rate_limit_rps} 次/秒 · 突发 ${row.rate_limit_burst}`" placement="top">
                <el-tag size="small" type="warning" effect="plain">限流</el-tag>
              </el-tooltip>
              <span v-if="!row.has_waf && !hasIpControl(row) && !row.has_rate_limit" class="text-secondary">—</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="90" align="center">
          <template #default="{ row }">
            <el-tag :type="row.enabled ? 'success' : 'info'" size="small" effect="light">{{ row.enabled ? '启用' : '禁用' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="更新时间" width="170" align="center">
          <template #default="{ row }">{{ formatDate(row.updated_at) || '-' }}</template>
        </el-table-column>
        <el-table-column label="更新者" width="100" align="center">
          <template #default="{ row }">{{ getUpdaterName(row.updated_by) }}</template>
        </el-table-column>
        <el-table-column v-if="!isReadOnly" label="操作" width="160" fixed="right">
          <template #default="{ row }">
            <el-button size="small" link type="primary" @click="openDialog(row)">编辑</el-button>
            <el-button size="small" link type="danger" @click="handleDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="dialogVisible" :title="editingId ? (isReadOnly ? '查看策略' : '编辑策略') : '新建策略'" width="min(800px, 94vw)" top="5vh" :close-on-click-modal="false" :before-close="beforeWizardClose" @close="resetWizard">
      <el-steps :active="currentStep" finish-status="success" align-center class="wizard-steps" :class="{ 'is-clickable': stepsClickable }">
        <el-step title="基础信息" :icon="InfoFilled" @click="jumpToStep(WIZARD_STEP.BASIC)" />
        <el-step title="WAF 规则" :icon="Lock" @click="jumpToStep(WIZARD_STEP.WAF_RULES)" />
        <el-step title="IP 访问控制" :icon="Connection" @click="jumpToStep(WIZARD_STEP.IP_ACL)" />
        <el-step title="限流" :icon="Odometer" @click="jumpToStep(WIZARD_STEP.RATE_LIMIT)" />
        <el-step title="关联规则" :icon="Link" @click="jumpToStep(WIZARD_STEP.BINDINGS)" />
        <el-step title="配置预览" :icon="Check" @click="jumpToStep(WIZARD_STEP.PREVIEW)" />
      </el-steps>

      <div class="wizard-content">
        <!-- Step 0: 基础信息 -->
        <div v-show="currentStep === WIZARD_STEP.BASIC" class="step-content">
          <el-form :model="form" label-width="100px" :disabled="isReadOnly">
            <el-form-item label="名称" required>
              <el-input v-model="form.name" placeholder="策略名称" />
            </el-form-item>
            <el-form-item label="描述">
              <el-input v-model="form.description" placeholder="策略描述" />
            </el-form-item>
            <el-form-item label="启用状态">
              <el-switch v-model="form.enabled" />
              <span class="form-tip-inline">禁用后该策略对所有关联规则停止生效</span>
            </el-form-item>
          </el-form>
        </div>

        <!-- Step 1: WAF 规则 -->
        <div v-show="currentStep === WIZARD_STEP.WAF_RULES" class="step-content">
          <el-form :model="form" label-width="100px" :disabled="isReadOnly">
            <el-form-item label="WAF 模式">
              <el-radio-group v-model="form.mode">
                <el-radio value="off">关闭</el-radio>
                <el-radio value="detection">检测（仅记录）</el-radio>
                <el-radio value="blocking">拦截（阻断请求）</el-radio>
              </el-radio-group>
            </el-form-item>
            <div v-if="form.mode === 'off'" class="waf-off-hint">当前 WAF 已关闭，以下配置不生效</div>
            <el-form-item label="异常阈值">
              <el-select v-model="form.anomaly_threshold" :disabled="form.mode === 'off' || isReadOnly" style="width: 140px">
                <el-option :value="1" label="极严格（1）" />
                <el-option :value="3" label="严格（3）" />
                <el-option :value="5" label="标准（5）" />
                <el-option :value="10" label="宽松（10）" />
                <el-option :value="20" label="极宽松（20）" />
              </el-select>
              <span class="form-tip-inline">规则异常分值累计达到此阈值后触发拦截，越低越严格</span>
            </el-form-item>
            <el-form-item label="CRS 规则组">
              <el-select v-model="crsRuleGroups" :disabled="form.mode === 'off'" multiple filterable placeholder="留空加载全部 CRS 规则" style="width: 100%">
                <el-option v-for="opt in crsGroupOptions" :key="opt.value" :label="opt.label" :value="opt.value" />
              </el-select>
              <div class="form-tip-line">选择后仅加载所选规则组，留空加载全部 CRS 规则</div>
            </el-form-item>
            <!-- 跨策略 CRS 规则组重复实时警告（随当前选择重算） -->
            <el-alert
              v-if="wafStepCrsAlert"
              type="warning"
              :closable="false"
              show-icon
              :title="wafStepCrsAlert"
              class="wizard-alert"
            />
            <el-alert
              v-if="hasResponsePhaseGroupWithoutCheck"
              type="warning"
              :closable="false"
              show-icon
              title="已选含响应阶段的规则组（955 Webshell 等），但未开启「检查响应体」——这些组不会加载生效，请开启「检查响应体」或移除响应阶段组"
              style="margin-bottom: 12px"
            />
            <el-form-item label="检查响应体">
              <el-switch v-model="form.waf_check_response" :disabled="form.mode === 'off'" />
              <div class="form-tip-line">开启后 WAF 读取并检查上游响应内容（响应泄露类规则需要）；关闭可显著降低内存与 CPU 开销，大多数部署只需检查请求</div>
            </el-form-item>
            <el-form-item label="排除规则">
              <el-select v-model="crsExcludedRules" :disabled="form.mode === 'off'" multiple filterable placeholder="搜索并选择要排除的规则" style="width: 100%">
                <!-- R72 二十八次二调（用户反馈）：按请求/响应阶段分组，label 带
                     phase 前缀——「请求 · 942 · SQL 注入」/「响应 · 955 · Webshell」，
                     与规则组同款「代码 · 类别」解析形态；文件名保留在 title 悬浮。 -->
                <el-option-group label="OWASP CRS · 请求阶段">
                  <el-option v-for="rule in crsRequestRuleOptions" :key="rule.filename" :label="`请求 · ${crsOptionCode(rule.filename)} · ${rule.category}`" :value="rule.filename" :title="rule.filename" />
                </el-option-group>
                <el-option-group label="OWASP CRS · 响应阶段">
                  <el-option v-for="rule in crsResponseRuleOptions" :key="rule.filename" :label="`响应 · ${crsOptionCode(rule.filename)} · ${rule.category}`" :value="rule.filename" :title="rule.filename" />
                </el-option-group>
              </el-select>
              <div class="form-tip-line">排除的规则不会被检测或拦截</div>
            </el-form-item>
            <el-form-item label="自定义规则">
              <el-select v-model="selectedCustomRules" :disabled="form.mode === 'off'" multiple filterable placeholder="选择要包含的自定义规则" style="width: 100%">
                <el-option v-for="rule in allCustomRules" :key="rule.id" :label="rule.name" :value="rule.id" />
              </el-select>
              <div class="form-tip-line">自定义规则在"规则集"页面创建，<el-link type="primary" @click="goToCustomRulesPage">去创建/编辑</el-link></div>
            </el-form-item>
          </el-form>
        </div>

        <!-- Step 2: IP 访问控制 -->
        <div v-show="currentStep === WIZARD_STEP.IP_ACL" class="step-content">
          <el-divider content-position="left" class="acl-divider">访问控制</el-divider>
          <el-form :model="form" label-width="100px" :disabled="isReadOnly">
            <el-form-item label="启用">
              <el-switch v-model="form.ip_acl_enabled" />
            </el-form-item>
            <template v-if="form.ip_acl_enabled">
              <el-form-item label="控制模式">
                <el-radio-group v-model="form.ip_acl_mode">
                  <el-radio value="deny">黑名单（拒绝列表中的 IP，其他正常检测）</el-radio>
                  <el-radio value="allow">白名单（仅允许列表中的 IP，其他一律拒绝）</el-radio>
                  <!-- 历史 bypass 策略仅作展示，不再提供新选 -->
                  <el-radio v-if="form.ip_acl_mode === 'bypass'" value="bypass">免检测（列表中的 IP 跳过全部安全检测）</el-radio>
                </el-radio-group>
              </el-form-item>
              <el-form-item :label="aclListLabel">
                <el-select v-model="ipACLList" multiple filterable allow-create default-first-option placeholder="输入 IP/CIDR 后回车" style="width: 100%" />
                <div class="form-tip-line">{{ aclListTip }}</div>
              </el-form-item>
            </template>
          </el-form>
          <el-divider content-position="left" class="acl-divider">信任名单</el-divider>
          <el-form :model="form" label-width="100px" :disabled="isReadOnly">
            <el-form-item label="启用">
              <el-switch v-model="ipWhitelistEnabled" />
            </el-form-item>
            <template v-if="ipWhitelistEnabled">
              <el-form-item label="信任 IP">
                <el-select v-model="ipWhitelist" multiple filterable allow-create default-first-option placeholder="输入 IP/CIDR 后回车" style="width: 100%" />
                <div class="form-tip-line">名单内 IP 跳过 WAF 与访问控制检测（限流仍然生效）</div>
              </el-form-item>
            </template>
          </el-form>
          <!-- 跨策略允许/信任 × 黑名单地址级冲突实时警告（覆盖上方访问控制与信任名单） -->
          <el-alert
            v-if="ipStepAclAlert"
            type="warning"
            :closable="false"
            show-icon
            :title="ipStepAclAlert"
            class="wizard-alert"
          />
          <el-divider content-position="left" class="acl-divider">区域控制</el-divider>
          <el-form :model="form" label-width="100px" :disabled="isReadOnly">
            <el-form-item label="启用">
              <el-switch v-model="form.geoip_enabled" />
            </el-form-item>
            <template v-if="form.geoip_enabled">
              <!-- R72 二十七次 N3（裁决）：披露 IPv6/不可解析客户端语义——
                   fail-closed 设计下它们按「海外」处理。 -->
              <el-alert
                type="info"
                :closable="false"
                show-icon
                title="地域规则仅对 IPv4 生效：IPv6 与不可解析客户端按「海外」处理（拦截模式勾选海外时将被拦截；仅允许模式只勾选省份时将被拦截）。IP 库未安装时地域规则不可启用。"
                style="margin-bottom: 12px"
              />
              <el-form-item label="控制模式">
                <el-radio-group v-model="form.geoip_mode">
                  <el-radio value="deny">拦截所选区域（其他放行）</el-radio>
                  <el-radio value="allow">仅允许所选区域（其他拦截）</el-radio>
                </el-radio-group>
              </el-form-item>
              <el-form-item label="区域选择">
                <!-- R72 二十三次（用户裁决）：区域精确到市——省级联选择；只选省 =
                     整省生效（存量语义），展开选市 = 省+市联合匹配（省/市 形态）。
                     海外为一级条目（不细分国家）。 -->
                <el-cascader
                  v-model="geoipCountries"
                  :options="regionCascaderOptions"
                  :props="{ multiple: true, checkStrictly: true, emitPath: false }"
                  filterable
                  clearable
                  placeholder="选择区域（可选省或精确到市）"
                  style="width: 100%"
                />
                <div class="form-tip-line">基于 IP2Region 离线库判断访客所在区域，与 CIDR 规则同时生效；只选省份 = 整省生效</div>
              </el-form-item>
            </template>
          </el-form>
        </div>

        <!-- Step 3: 限流 -->
        <div v-show="currentStep === WIZARD_STEP.RATE_LIMIT" class="step-content">
          <el-form :model="form" label-width="100px" :disabled="isReadOnly">
            <el-form-item label="启用">
              <el-switch v-model="form.rate_limit_enabled" />
            </el-form-item>
            <template v-if="form.rate_limit_enabled">
              <el-form-item label="速率上限">
                <el-input-number v-model="form.rate_limit_rps" :min="1" style="width: 120px" />
                <span class="form-tip-inline">次/秒，持续请求时的速率上限</span>
              </el-form-item>
              <el-form-item label="突发余量">
                <el-input-number v-model="form.rate_limit_burst" :min="0" style="width: 120px" />
                <span class="form-tip-inline">次，短时允许超出速率上限的额外请求数</span>
              </el-form-item>
            </template>
          </el-form>
        </div>

        <!-- Step 4: 关联规则 -->
        <div v-show="currentStep === WIZARD_STEP.BINDINGS" class="step-content">
          <el-form :model="form" label-width="100px" :disabled="isReadOnly">
            <el-form-item label="已关联">
              <div class="rule-bind-field">
                <div class="rule-picker-trigger" role="button" tabindex="0" :class="{ 'is-locked': isReadOnly }" @click="!isReadOnly && openRulePicker()" @keydown.enter.prevent="!isReadOnly && openRulePicker()" @keydown.space.prevent="!isReadOnly && openRulePicker()">
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
                         拦截页面仅首绑（启用策略中 policy_id 最小者）生效。每条规则的拦截页面生效状态
                         统一展示在下方「拦截页面」配置项说明区。 -->
                    <div class="bound-rule-chain">
                      <span
                        v-for="(entry, idx) in row.chain"
                        :key="entry.policyId ?? 'self'"
                        class="binding-order-chip"
                        :class="{ 'is-self': entry.isSelf, 'is-disabled': !entry.enabled }"
                      >{{ idx + 1 }}.{{ entry.isSelf ? '本策略' : entry.name }}</span>
                    </div>
                    <el-alert
                      v-if="row.showPerfTip"
                      type="warning"
                      :closable="false"
                      show-icon
                      :title="`该规则将绑定 ${row.mergedCount} 条策略：每条策略都会叠加一层处理链（WAF/ACL/限流），超过 3 条可能影响转发性能`"
                      class="bound-rule-alert"
                    />
                    <el-alert
                      v-for="hint in row.hints"
                      :key="hint"
                      type="warning"
                      :closable="false"
                      show-icon
                      :title="hint"
                      class="bound-rule-alert"
                    />
                  </div>
                </div>
                <div class="form-tip-line">策略将应用到所选负载均衡规则的入站流量；同一规则绑定多条策略时按策略 ID 升序依次评估</div>
              </div>
            </el-form-item>
            <el-form-item label="拦截页面">
              <el-select v-model="form.block_page_id" placeholder="选择拦截页面" style="width: 100%">
                <el-option v-for="p in blockPages" :key="p.id" :label="p.name" :value="p.id" />
              </el-select>
              <div v-if="blockPages.length === 0" class="form-tip-line">暂无拦截页面，<el-link type="primary" @click="goToBlockPagesPage">去创建</el-link></div>
              <div v-else class="form-tip-line">拦截时返回给客户端的自定义页面，在"拦截页面"页面管理，<el-link type="primary" @click="goToBlockPagesPage">去创建/编辑</el-link></div>
              <!-- v2.2.0：按规则逐条展示拦截页面是否生效（仅首绑启用策略生效），
                   保持与已关联列表中每条规则的顺序落点一致。 -->
              <div v-if="boundRuleRows.length > 0" class="block-page-rule-annotations">
                <div v-for="row in boundRuleRows" :key="row.caddyId" class="block-page-rule-annotation">
                  <span class="block-page-rule-annotation-name">{{ row.name }}</span>
                  <span v-if="row.selfBlockPageActive" class="block-page-rule-annotation-status is-active">✓ 拦截页面当前生效</span>
                  <span v-else-if="!form.enabled" class="block-page-rule-annotation-status is-disabled">策略禁用中，拦截页面不生效</span>
                  <span v-else class="block-page-rule-annotation-status is-warning">拦截页面移至第一位后生效（当前第 {{ row.selfPosition }} 位）</span>
                </div>
              </div>
            </el-form-item>
            <el-form-item label="返回状态码">
              <el-select v-model="form.block_status_code" style="width: 200px">
                <el-option :value="400" label="400 Bad Request" />
                <el-option :value="401" label="401 Unauthorized" />
                <el-option :value="403" label="403 Forbidden" />
                <el-option :value="404" label="404 Not Found" />
                <el-option :value="429" label="429 Too Many Requests" />
                <el-option :value="503" label="503 Service Unavailable" />
              </el-select>
              <span class="form-tip-inline">WAF、IP ACL、限流拦截统一使用此状态码</span>
            </el-form-item>
          </el-form>
        </div>

        <!-- Step 5: 配置预览 -->
        <div v-show="currentStep === WIZARD_STEP.PREVIEW" class="step-content">
          <el-descriptions title="配置预览" :column="1" border>
            <el-descriptions-item label="名称">{{ form.name || '-' }}</el-descriptions-item>
            <el-descriptions-item label="描述">{{ form.description || '-' }}</el-descriptions-item>
            <el-descriptions-item label="启用状态">
              <el-tag :type="form.enabled ? 'success' : 'info'" size="small" effect="light">{{ form.enabled ? '启用' : '禁用' }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item v-if="form.mode === 'off'" label="WAF">已关闭</el-descriptions-item>
            <el-descriptions-item v-if="form.mode !== 'off'" label="WAF 模式">
              <el-tag v-if="form.mode === 'blocking'" type="danger" size="small" effect="light">拦截</el-tag>
              <el-tag v-else-if="form.mode === 'detection'" type="warning" size="small" effect="light">检测</el-tag>
              <el-tag v-else type="info" size="small" effect="plain">关闭</el-tag>
            </el-descriptions-item>
            <el-descriptions-item v-if="form.mode !== 'off'" label="异常阈值">{{ thresholdLabel(form.anomaly_threshold) }}</el-descriptions-item>
            <el-descriptions-item v-if="form.mode !== 'off'" label="CRS 规则组">{{ crsRuleGroups.length === 0 ? '全部（默认）' : `${crsRuleGroups.length} 组` }}</el-descriptions-item>
            <el-descriptions-item v-if="form.mode !== 'off'" label="排除规则">{{ crsExcludedRules.length }} 条</el-descriptions-item>
            <el-descriptions-item v-if="form.mode !== 'off'" label="自定义规则">{{ selectedCustomRules.length }} 条</el-descriptions-item>
            <el-descriptions-item label="拦截页面">{{ blockPageName }}</el-descriptions-item>
            <el-descriptions-item label="IP 访问控制">
              <template v-if="form.ip_acl_enabled">{{ aclModeLabel }} · 列表 {{ ipACLList.length }} 条</template>
              <template v-else>禁用</template>
            </el-descriptions-item>
            <el-descriptions-item label="区域控制">
              <template v-if="form.geoip_enabled">{{ geoipModeLabel }} · 区域 {{ geoipCountries.length }} 个</template>
              <template v-else>禁用</template>
            </el-descriptions-item>
            <el-descriptions-item label="限流">
              <template v-if="form.rate_limit_enabled">{{ form.rate_limit_rps }} 次/秒 · 突发 {{ form.rate_limit_burst }} 次</template>
              <template v-else>禁用</template>
            </el-descriptions-item>
            <el-descriptions-item label="关联规则">
              <template v-if="boundRuleList.length > 0">
                {{ boundRuleList.length }} 条 · {{ boundRuleList.slice(0, 3).map((rule) => rule.name).join('、') }}{{ boundRuleList.length > 3 ? ' 等' : '' }}
              </template>
              <template v-else>未关联</template>
            </el-descriptions-item>
          </el-descriptions>
        </div>
      </div>

      <template #footer>
        <div class="wizard-footer">
          <el-button v-if="hasPreviousStep" @click="prevStep">
            <el-icon><ArrowLeft /></el-icon>上一步
          </el-button>
          <el-button v-if="hasNextStep" type="primary" @click="nextStep">
            下一步<el-icon><ArrowRight /></el-icon>
          </el-button>
          <el-button v-if="currentStep === WIZARD_STEP.PREVIEW" type="primary" :disabled="isReadOnly" :loading="saving" @click="handleSave">
            <span>保存</span><el-icon style="margin-left: 6px;"><Check /></el-icon>
          </el-button>
        </div>
      </template>
    </el-dialog>

    <!-- 关联规则选择器 -->
    <el-dialog v-model="rulePickerVisible" title="选择关联规则" width="min(640px, 90vw)" append-to-body>
      <el-input v-model="pickerSearch" placeholder="搜索规则名 / 域名 / 规则 ID" clearable :prefix-icon="Search" class="rule-picker-search" />
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
            <el-checkbox :value="rule.caddy_id" :disabled="pickerMeta(rule.caddy_id).wouldExceed">
              <span class="rule-picker-name">{{ rule.name }}</span>
              <span class="rule-picker-meta">{{ rule.domain || '-' }}:{{ rule.listen_port }}</span>
            </el-checkbox>
            <!-- v2.2.0：每条候选规则展示当前绑定链（policy_id ASC，1-based）与本策略落点；
                 已达 5 条上限的规则禁用并说明原因。 -->
            <div class="rule-binding-preview">
              <span v-if="pickerMeta(rule.caddy_id).wouldExceed" class="rule-binding-limit">已达 5 条绑定上限，无法继续绑定</span>
              <template v-else>
                <span
                  v-for="(entry, idx) in pickerMeta(rule.caddy_id).chain"
                  :key="entry.policyId ?? 'self'"
                  class="binding-order-chip"
                  :class="{ 'is-self': entry.isSelf, 'is-disabled': !entry.enabled }"
                >{{ idx + 1 }}.{{ entry.isSelf ? '本策略' : entry.name }}</span>
                <span class="rule-binding-landing">本策略排第 {{ pickerMeta(rule.caddy_id).selfPos }} 位</span>
              </template>
            </div>
          </div>
        </el-checkbox-group>
        <el-empty v-if="pickerPagedRules.length === 0" description="没有匹配的规则" :image-size="60" />
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
            <el-button @click="rulePickerVisible = false">取消</el-button>
            <el-button type="primary" @click="confirmRulePicker">确定</el-button>
          </div>
        </div>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed, watch } from 'vue'
import { Plus, Lock, InfoFilled, Connection, Odometer, Link, Check, ArrowLeft, ArrowRight, ArrowDown, Search } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { request } from '@/utils/api'
import { showSaveResult } from '@/utils/saveResult'
import { isValidCidr } from '@/utils/ruleValidation'
import { formatDate } from '@/utils/date'
import { useAuthStore } from '@/stores/auth'
import type { APIResponse, UserListItem } from '@/types'

interface PolicySummary { id: number; name: string; mode: string; enabled: boolean; rule_count: number; has_waf: boolean; has_ip_control: boolean; has_rate_limit: boolean; anomaly_threshold: number; ip_acl_mode: string; ip_acl_list: string; ip_whitelist: string; ip_blacklist: string; rate_limit_rps: number; rate_limit_burst: number; crs_excluded_count: number; custom_rules_count: number; ip_acl_enabled: boolean; updated_by: number; updated_at: string }
interface PolicyDetail { id: number; name: string; description: string; mode: string; anomaly_threshold: number; ip_acl_mode: string; ip_acl_list: string; ip_acl_enabled: boolean; ip_whitelist: string; ip_blacklist?: string; rate_limit_enabled: boolean; rate_limit_rps: number; rate_limit_burst: number; crs_rule_groups: string; crs_excluded_rules: string; custom_rules: string; block_page_id: number; block_status_code: number; enabled: boolean; updated_at: string; geoip_mode?: string; geoip_countries?: string; waf_check_response?: boolean }
interface Rule { caddy_id: string; name: string; domain: string; listen_port: number; protocol: string }
// v2.2.0 多策略绑定：/security/bindings 的值从单 BindingInfo 改为数组（policy_id ASC）
interface BindingInfo { policy_id: number; name: string; mode: string; enabled: boolean; rate_limit_enabled: boolean }
// GET /security/rules/:caddy_id/policy 直接序列化 models.SecurityPolicy——json.RawMessage
// 字段以原生 JSON（数组）出现，与策略详情接口的字符串形态不同，按 unknown 接收再解析。
interface RuleBoundPolicy { id: number; name: string; mode: string; enabled: boolean; ip_acl_enabled: boolean; ip_acl_mode: string; crs_rule_groups: unknown; custom_rules: unknown; block_page_id: number }
interface CustomRuleRef { id: number; action: string }
interface ChainEntry { policyId: number | null; name: string; enabled: boolean; isSelf: boolean }
interface BoundRuleRow { caddyId: string; name: string; domain: string; listenPort: number; chain: ChainEntry[]; selfPosition: number; selfBlockPageActive: boolean; mergedCount: number; showPerfTip: boolean; hints: string[] }
interface CRSRuleOption { filename: string; category: string }
interface BlockPage { id: number; name: string }

const blockPages = ref<BlockPage[]>([])




interface RegionTree { provinces: string[]; cities: Record<string, string[]> }
const regionTree = ref<RegionTree>({ provinces: [], cities: {} })
// 级联选项：各省为父节点（选父 = 整省），省内城市为子节点（省/市 联合匹配）；
// 海外为一级条目（无子节点）。
const regionCascaderOptions = computed(() =>
  regionTree.value.provinces.map((prov) => {
    const cities = regionTree.value.cities[prov] || []
    if (cities.length === 0) {
      return { value: prov, label: prov }
    }
    return {
      value: prov,
      label: prov,
      children: cities.map((city) => ({ value: `${prov}/${city}`, label: city })),
    }
  }),
)

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.readOnlyReason !== null)

const users = ref<UserListItem[]>([])
const getUpdaterName = (userId?: number) => {
  if (!userId || userId === 0) return '-'
  const user = users.value.find(u => u.id === userId)
  return user?.display_name || user?.username || '-'
}

const crsRuleOptions = ref<CRSRuleOption[]>([])
const loading = ref(false)
const saving = ref(false)
const policies = ref<PolicySummary[]>([])
const policySearch = ref('')
const filteredPolicies = computed(() => {
  const query = policySearch.value.trim().toLowerCase()
  if (!query) return policies.value
  return policies.value.filter((p) => (p.name || '').toLowerCase().includes(query))
})
const allRules = ref<Rule[]>([])
const securityBindings = ref<Record<string, BindingInfo[]>>({})
const dialogVisible = ref(false)
const editingId = ref<number | null>(null)
const ipACLList = ref<string[]>([])
const ipWhitelist = ref<string[]>([])
const ipWhitelistEnabled = ref(false)
// 本策略既有 ip_blacklist（仅用于跨策略冲突比较；本对话框不编辑该字段，
// 保存时由后端指针语义自动保留原值）
const ipBlacklistSelf = ref<string[]>([])
const geoipCountries = ref<string[]>([])
const crsRuleGroups = ref<string[]>([])
const crsExcludedRules = ref<string[]>([])
const boundRules = ref<string[]>([])
const originalBoundRules = ref<string[]>([])
// R60 D60-F1：策略对话框打开序列号——丢弃在途详情 GET 的过期返回。
let policyDialogOpenSeq = 0

const WIZARD_STEP = {
  BASIC: 0,
  WAF_RULES: 1,
  IP_ACL: 2,
  RATE_LIMIT: 3,
  BINDINGS: 4,
  PREVIEW: 5,
} as const
type WizardStep = (typeof WIZARD_STEP)[keyof typeof WIZARD_STEP]
const WIZARD_STEPS_ORDER: readonly WizardStep[] = [
  WIZARD_STEP.BASIC,
  WIZARD_STEP.WAF_RULES,
  WIZARD_STEP.IP_ACL,
  WIZARD_STEP.RATE_LIMIT,
  WIZARD_STEP.BINDINGS,
  WIZARD_STEP.PREVIEW,
]
const currentStep = ref<WizardStep>(WIZARD_STEP.BASIC)

const rulePickerVisible = ref(false)
const pickerSearch = ref('')
const pickerPage = ref(1)
const pickerSelected = ref<string[]>([])
const PICKER_PAGE_SIZE = 20

const defaultForm = () => ({ name: '', description: '', enabled: true, mode: 'off', anomaly_threshold: 5, ip_acl_enabled: false, ip_acl_mode: 'allow', rate_limit_enabled: false, rate_limit_rps: 100, rate_limit_burst: 50, block_page_id: 1, block_status_code: 403, geoip_enabled: false, geoip_mode: 'deny', waf_check_response: false })
const form = ref(defaultForm())
const selectedCustomRules = ref<number[]>([])
// action 用于多策略冲突检测（放行型 pass / 拦截型 block）；enabled 预留
const allCustomRules = ref<Array<{ id: number; name: string; action?: string; enabled?: boolean }>>([])

// 返回是否加载成功——R62 D-4：聚焦流程（security-policies-focus-id）需区分
// 「列表加载失败」与「策略确已删除」，否则瞬时失败会被误报为「已被删除」。
const fetchData = async (): Promise<boolean> => {
  loading.value = true
  try {
    // R72 二十六次 W3-1：allSettled 替代 all——策略主数据失败才整体报错，
    // 辅助数据（规则/CRS 选项/拦截页/绑定/用户）部分失败保留已有数据，
    // 避免「保存策略后任一辅助端点失败 → 整个列表不刷新」的 stale 状态。
    const [polRes, ruleRes, crsRes, bpRes, crRes, bindRes, userRes] = await Promise.allSettled([
      request.get<APIResponse<PolicySummary[]>>('/security/policies'),
      request.get<APIResponse<Rule[]>>('/rules'),
      request.get<APIResponse<{ rules: CRSRuleOption[] }>>('/security/crs/rules?page_size=100'),
      request.get<APIResponse<BlockPage[]>>('/security/block-pages'),
      request.get<APIResponse<Array<{ id: number; name: string; action?: string; enabled?: boolean }>>>('/security/custom-rules'),
      request.get<APIResponse<Record<string, BindingInfo[]>>>('/security/bindings'),
      request.get<APIResponse<UserListItem[]>>('/users'),
    ])
    if (polRes.status === 'rejected') {
      console.error('Failed to load policies data:', polRes.reason)
      return false
    }
    policies.value = polRes.value.data || []
    if (ruleRes.status === 'fulfilled') allRules.value = ruleRes.value.data || []
    if (crsRes.status === 'fulfilled') crsRuleOptions.value = crsRes.value.data?.rules || []
    if (bpRes.status === 'fulfilled') blockPages.value = bpRes.value.data || []
    if (crRes.status === 'fulfilled') allCustomRules.value = crRes.value.data || []
    if (bindRes.status === 'fulfilled') securityBindings.value = bindRes.value.data || {}
    if (userRes.status === 'fulfilled') users.value = userRes.value.data || []
    const partial = [ruleRes, crsRes, bpRes, crRes, bindRes, userRes].some(r => r.status === 'rejected')
    if (partial) console.warn('部分辅助数据加载失败，保留已有数据')
    return true
  } catch (error: unknown) {
    console.error('Failed to load policies data:', error)
    return false
  } finally { loading.value = false }
}

const parseJsonList = (raw: string | undefined): string[] => {
  if (!raw) return []
  try {
    const parsed: unknown = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    return parsed.filter((item): item is string => typeof item === 'string')
  } catch { return [] }
}

const parseCustomRuleIds = (raw: string | undefined): number[] => {
  if (!raw) return []
  try {
    const parsed: unknown = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    return parsed.map((item) => {
      if (typeof item === 'number') return item
      if (typeof item === 'object' && item !== null && 'id' in item) {
        const id = item.id
        return typeof id === 'number' ? id : 0
      }
      return 0
    }).filter((id) => id > 0)
  } catch { return [] }
}

// CRS 规则组以后端 Include 的两位组代码存储（REQUEST-9<code>-*.conf），兼容历史上存过的完整文件名前缀
const normalizeCrsGroups = (values: string[]): string[] => {
  const codes = values.map((value) => {
    if (/^\d{2}$/.test(value)) return value
    const match = /^(?:REQUEST|RESPONSE)-9(\d{2})-/i.exec(value)
    return match?.[1] ?? ''
  }).filter((code) => code !== '')
  return [...new Set(codes)]
}

// crsOptionCode 从 CRS 文件名提取两位组代码（REQUEST-942-*.conf → "942"）——
// 与 normalizeCrsGroups 同源，用于排除规则选项的解析化显示。
const crsOptionCode = (filename: string): string => {
  const match = /^(?:REQUEST|RESPONSE)-9(\d{2})-/i.exec(filename)
  return match ? `9${match[1]}` : filename
}

// crsOptionPhase（用户反馈）：CRS 规则文件分请求/响应两个阶段——REQUEST-*
// 为请求阶段（请求行/头/参数/体），RESPONSE-* 为响应阶段（响应体）。选项
// 必须区分阶段，否则「942 · SQL 注入」与「955 · Webshell」无法看出分别作用
// 于请求还是响应。命名取 CRS 官方 phase 术语的最简中文：请求 / 响应
//（REQUEST 规则查的不只是请求体，叫「请求体」不准确）。
const crsOptionPhase = (filename: string): string => (/^RESPONSE-/i.test(filename) ? '响应' : '请求')

// 排除规则选项按阶段分组（el-option-group 视觉分组 + label 内 phase 前缀供
// 已选 tag 区分）。
const crsRequestRuleOptions = computed(() => crsRuleOptions.value.filter((r) => !/^RESPONSE-/i.test(r.filename)))
const crsResponseRuleOptions = computed(() => crsRuleOptions.value.filter((r) => /^RESPONSE-/i.test(r.filename)))

// crsResponsePhaseGroupCodes（R72 二十九次 L9）：响应阶段 CRS 类别两位代码
//（950-956/959/980）——这些组仅在「检查响应体」开启时才被后端 Include
//（security.go:169-177），否则静默 no-op。用于给选中响应组但开关关闭的用户
// 一个针对性提示。
const crsResponsePhaseGroupCodes = ['50', '51', '52', '53', '54', '55', '56', '59', '80']
const hasResponsePhaseGroupWithoutCheck = computed(
  () => form.value.mode !== 'off' && !form.value.waf_check_response && crsRuleGroups.value.some((g) => crsResponsePhaseGroupCodes.includes(g)),
)

const crsGroupOptions = computed(() => {
  const seen = new Map<string, string>()
  for (const rule of crsRuleOptions.value) {
    const match = /^(?:REQUEST|RESPONSE)-9(\d{2})-/i.exec(rule.filename)
    const code = match?.[1]
    if (!code || seen.has(code)) continue
    seen.set(code, `${crsOptionPhase(rule.filename)} · 9${code} · ${rule.category}`)
  }
  return [...seen.entries()].map(([value, label]) => ({ value, label }))
})

const THRESHOLD_LABELS: Record<number, string> = { 1: '极严格（1）', 3: '严格（3）', 5: '标准（5）', 10: '宽松（10）', 20: '极宽松（20）' }
const thresholdLabel = (value: number): string => THRESHOLD_LABELS[value] ?? String(value)

const ACL_MODE_LABELS: Record<string, string> = { deny: '黑名单', allow: '白名单', bypass: '免检测' }
const aclModeLabel = computed(() => ACL_MODE_LABELS[form.value.ip_acl_mode] ?? form.value.ip_acl_mode)

const ACL_LIST_LABELS: Record<string, string> = { deny: '拒绝 IP', allow: '允许 IP', bypass: '免检测 IP' }
const aclListLabel = computed(() => ACL_LIST_LABELS[form.value.ip_acl_mode] ?? 'IP 列表')

const GEOIP_MODE_LABELS: Record<string, string> = { deny: '拦截所选区域', allow: '仅允许所选区域' }
const geoipModeLabel = computed(() => GEOIP_MODE_LABELS[form.value.geoip_mode] ?? form.value.geoip_mode)

const ACL_MODE_TIPS: Record<string, string> = {
  deny: '列表中的 IP 将被拒绝访问，其他 IP 正常进行安全检测',
  allow: '仅列表中的 IP 可以访问，其他 IP 一律拒绝',
  bypass: '列表中的 IP 将跳过全部安全检测',
}
const aclListTip = computed(() => ACL_MODE_TIPS[form.value.ip_acl_mode] ?? '')

const blockPageName = computed(() => blockPages.value.find((p) => p.id === form.value.block_page_id)?.name || '-')

// 与后端口径一致：ACL 启用且列表非空，或白名单/黑名单非空
const hasIpControl = (row: PolicySummary): boolean => {
  const aclCount = parseJsonList(row.ip_acl_list).length
  const aclEnabled = row.ip_acl_enabled
  return (aclEnabled && aclCount > 0) || parseJsonList(row.ip_whitelist).length > 0 || parseJsonList(row.ip_blacklist).length > 0
}

const wafTip = (row: PolicySummary): string =>
  `模式：${row.mode === 'blocking' ? '拦截' : '检测'} · 阈值 ${row.anomaly_threshold} · 排除 ${row.crs_excluded_count} 条 · 自定义 ${row.custom_rules_count} 条`

const ipControlTip = (row: PolicySummary): string => {
  const aclCount = parseJsonList(row.ip_acl_list).length
  const wlCount = parseJsonList(row.ip_whitelist).length
  const blCount = parseJsonList(row.ip_blacklist).length
  return `访问控制：${row.ip_acl_mode === 'allow' ? '白名单模式' : '黑名单模式'} · 列表 ${aclCount} 条 · 白名单 ${wlCount} 条 · 黑名单 ${blCount} 条`
}

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
const hasPreviousStep = computed(() => WIZARD_STEPS_ORDER.indexOf(currentStep.value) > 0)
const hasNextStep = computed(() => WIZARD_STEPS_ORDER.indexOf(currentStep.value) < WIZARD_STEPS_ORDER.length - 1)

const moveToAdjacentWizardStep = (direction: -1 | 1): void => {
  const currentIndex = WIZARD_STEPS_ORDER.indexOf(currentStep.value)
  const targetStep = WIZARD_STEPS_ORDER[currentIndex + direction]
  if (targetStep !== undefined) currentStep.value = targetStep
}

const jumpToStep = (step: WizardStep): void => {
  if (!stepsClickable.value) return
  currentStep.value = step
}

const validateIpAclList = (): boolean => {
  if (form.value.ip_acl_enabled && form.value.ip_acl_mode === 'allow' && ipACLList.value.length === 0) {
    ElMessage.error('白名单模式下 IP 列表不能为空，否则所有请求将被拒绝')
    return false
  }
  const invalidEntry = ipACLList.value.find((entry) => !isValidCidr(entry))
  if (invalidEntry) {
    ElMessage.error(`IP/CIDR 条目格式不正确：${invalidEntry}`)
    return false
  }
  if (ipWhitelistEnabled.value) {
    const invalidTrustEntry = ipWhitelist.value.find((entry) => !isValidCidr(entry))
    if (invalidTrustEntry) {
      ElMessage.error(`信任名单中的 IP/CIDR 条目格式不正确：${invalidTrustEntry}`)
      return false
    }
  }
  if (form.value.geoip_enabled && geoipCountries.value.length === 0) {
    ElMessage.error('区域控制启用后必须选择至少一个区域，否则所有请求将被拒绝')
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

// 全选作用于当前搜索筛选出且可选择的全部规则（跨分页；已达 5 条绑定上限的规则
// 不可选，不参与全选），selection 存于 pickerSelected 与分页无关
const pickerSelectableRules = computed(() => pickerFilteredRules.value.filter((rule) => !pickerMeta(rule.caddy_id).wouldExceed))
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

const boundRuleList = computed(() => boundRules.value.map((caddyId) => {
  const rule = allRules.value.find((r) => r.caddy_id === caddyId)
  return { caddy_id: caddyId, name: rule?.name || caddyId }
}))

// ================= v2.2.0 多策略绑定（SC-BIND-02 配套） =================
// 语义：评估顺序 = policy_id ASC（后端排序，绑定顺序即策略 ID 顺序）；
// 拦截页面 = 首绑策略的页面（启用策略中 policy_id 最小者）；单规则最多 5 条；
// security_policies.id 为 AUTOINCREMENT——新建策略的 ID 必然大于全部现存策略，
// 因此新建策略在任何规则的绑定链上都落在末位。
const MAX_POLICIES_PER_RULE = 5
const PERF_POLICY_THRESHOLD = 3

// 选中规则的完整绑定策略明细（冲突检测需要 crs_rule_groups/custom_rules 内容，
// /security/bindings 的 BindingInfo 不含这些字段）——按规则懒加载，对话框关闭时
// 清空防止跨编辑会话的 stale 数据。
const ruleBoundPolicies = ref<Record<string, RuleBoundPolicy[]>>({})
const ensureBindingDetails = async (caddyIds: string[]): Promise<void> => {
  const missing = caddyIds.filter((id) => !(id in ruleBoundPolicies.value))
  if (missing.length === 0) return
  const results = await Promise.allSettled(
    missing.map((id) => request.get<APIResponse<RuleBoundPolicy[]>>(`/security/rules/${encodeURIComponent(id)}/policy`)),
  )
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

const parseUnknownStringList = (raw: unknown): string[] => {
  if (Array.isArray(raw)) return raw.filter((item): item is string => typeof item === 'string')
  if (typeof raw === 'string') return parseJsonList(raw)
  return []
}

// IP 名单归一化：去空白、去重。v1 仅做精确字符串匹配——10.0.0.0/8 与 10.0.0.1
// 之类的 CIDR 包含关系不在本期范围（跨策略冲突检测用）。
const normalizeIpList = (values: string[]): string[] => [...new Set(values.map((v) => v.trim()).filter((v) => v !== ''))]

// 策略 IP 名单按语义分两侧：允许侧 = 白名单/免检测模式下的 ACL 列表 + 信任名单；
// 拒绝侧 = 黑名单模式下的 ACL 列表 + 独立 ip_blacklist 字段（由策略页外入口维护）。
// 供 Step 4 冲突检测与 WAF/IP 步骤实时警告共用，保证两处口径一致。
const ipAclSideEntries = (mode: string, aclEnabled: boolean, aclList: string[], whitelist: string[], blacklist: string[]): { allow: string[]; deny: string[] } => {
  const allow: string[] = []
  if (aclEnabled && (mode === 'allow' || mode === 'bypass')) allow.push(...aclList)
  allow.push(...whitelist)
  const deny: string[] = []
  if (aclEnabled && mode === 'deny') deny.push(...aclList)
  deny.push(...blacklist)
  return { allow: normalizeIpList(allow), deny: normalizeIpList(deny) }
}

// 本策略（表单实时值）的允许/拒绝两侧名单
const selfIpAclSides = computed(() => ipAclSideEntries(form.value.ip_acl_mode, form.value.ip_acl_enabled, ipACLList.value, ipWhitelist.value, ipBlacklistSelf.value))

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
// 本策略条目以表单实时值为准（编辑中的 name/enabled 可能与服务端快照不同）。
const buildDisplayChain = (caddyId: string): ChainEntry[] => {
  const existing = (securityBindings.value[caddyId] || [])
    .filter((b) => b.policy_id !== editingId.value)
    .map((b): ChainEntry => ({ policyId: b.policy_id, name: b.name, enabled: b.enabled, isSelf: false }))
  const self: ChainEntry = { policyId: editingId.value, name: form.value.name || '本策略', enabled: form.value.enabled, isSelf: true }
  const all = [...existing, self]
  all.sort((a, b) => (a.policyId ?? Number.MAX_SAFE_INTEGER) - (b.policyId ?? Number.MAX_SAFE_INTEGER))
  return all
}

// 选择器单条规则元信息：绑定链、本策略落点（1-based）、是否因达 5 条上限而不可选。
// 本策略已在绑定中的规则重选不新增绑定，永不受上限限制。
const pickerMeta = (caddyId: string): { chain: ChainEntry[]; selfPos: number; wouldExceed: boolean } => {
  const existing = securityBindings.value[caddyId] || []
  const selfBound = editingId.value !== null && existing.some((b) => b.policy_id === editingId.value)
  const chain = buildDisplayChain(caddyId)
  return {
    chain,
    selfPos: chain.findIndex((e) => e.isSelf) + 1,
    wouldExceed: !selfBound && existing.length >= MAX_POLICIES_PER_RULE,
  }
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
  crsGroups: string[]
  customRefs: CustomRuleRef[]
  ipAllowEntries: string[]
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
        ? ipAclSideEntries(summary.ip_acl_mode, summary.ip_acl_enabled, parseJsonList(summary.ip_acl_list), parseJsonList(summary.ip_whitelist), parseJsonList(summary.ip_blacklist))
        : { allow: [] as string[], deny: [] as string[] }
      return {
        id: p.id,
        name: p.name,
        enabled: p.enabled,
        mode: p.mode,
        ipAclEnabled: p.ip_acl_enabled,
        ipAclMode: p.ip_acl_mode,
        crsGroups: normalizeCrsGroups(parseUnknownStringList(p.crs_rule_groups)),
        customRefs: parseCustomRuleRefs(p.custom_rules),
        ipAllowEntries: sides.allow,
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
    crsGroups: crsRuleGroups.value,
    customRefs: selectedCustomRules.value.map((id) => ({ id, action: customRuleActionOf(id) })),
    ipAllowEntries: selfSides.allow,
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

  // (1) CRS 规则组重叠：空数组 = 加载全部规则 → 与任何选择重叠；mode=off 的策略不加载 CRS
  const wafActive = active.filter((p) => p.mode !== 'off')
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
  const isBypassLike = (p: ConflictPolicyView): boolean => p.ipAclEnabled && (p.ipAclMode === 'bypass' || p.ipAclMode === 'allow')
  active.forEach((p, i) => {
    if (!isBypassLike(p)) return
    const hasBlockingBefore = active.slice(0, i).some(isBlocking)
    const hasBlockingAfter = active.slice(i + 1).some(isBlocking)
    if (hasBlockingBefore && hasBlockingAfter) {
      hints.push(`「${p.name}」为${p.ipAclMode === 'bypass' ? '免检测' : '白名单'}模式且夹在拦截策略中间：免检测/白名单仅作用于自身引擎，不会为前后策略放行流量，各策略引擎独立判定、位置不影响拦截效果；如需对特定来源整体放行，请使用免检测名单`)
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

  // (5) 地址级允许×拒绝冲突：一侧策略的允许/信任名单条目出现在另一侧策略的黑名单中——
  // 允许/信任不跨策略生效，该地址仍会被黑名单侧策略拦截。与 WAF/IP 步骤实时警告同源
  //（ipAclSideEntries），仅精确字符串匹配，不展开 CIDR 包含关系。
  for (let i = 0; i < active.length; i++) {
    for (let j = 0; j < active.length; j++) {
      if (i === j) continue
      const allowSide = active[i]
      const denySide = active[j]
      if (!allowSide || !denySide) continue
      const overlap = allowSide.ipAllowEntries.filter((e) => denySide.ipDenyEntries.includes(e))
      if (overlap.length > 0) {
        const shown = overlap.slice(0, 2).join('、')
        hints.push(`地址 ${shown}${overlap.length > 2 ? ' 等' : ''} 在「${allowSide.name}」的允许/信任名单中、同时在「${denySide.name}」的黑名单中——允许/信任不跨策略生效，该地址仍会被「${denySide.name}」拦截`)
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
// 数据源：策略列表接口不携带 crs_rule_groups 明细（ruleBoundPolicies 又缺 IP 名单），
// 因此对话框打开时按需拉取各启用策略的详情（镜像 ensureBindingDetails 的 allSettled
// 模式，对话框关闭时清空），一处数据同时服务 CRS 与 IP 两类步骤内警告。

interface PeerPolicyView { id: number; name: string; mode: string; crsGroups: string[]; allowEntries: string[]; denyEntries: string[] }
const peerPolicyViews = ref<PeerPolicyView[]>([])

const loadPeerPolicyViews = async (openSeq: number): Promise<void> => {
  const targets = policies.value.filter((p) => p.enabled && p.id !== editingId.value)
  if (targets.length === 0) { peerPolicyViews.value = []; return }
  const results = await Promise.allSettled(
    targets.map((p) => request.get<APIResponse<{ policy: PolicyDetail; bindings: string[] }>>(`/security/policies/${p.id}`)),
  )
  // 过期返回丢弃（同 openDialog 详情 GET 的序列号守卫）
  if (openSeq !== policyDialogOpenSeq) return
  const views: PeerPolicyView[] = []
  results.forEach((res) => {
    if (res.status !== 'fulfilled') return
    const d = res.value.data?.policy
    if (!d) return
    const sides = ipAclSideEntries(d.ip_acl_mode, d.ip_acl_enabled, parseJsonList(d.ip_acl_list), parseJsonList(d.ip_whitelist), parseJsonList(d.ip_blacklist))
    views.push({ id: d.id, name: d.name, mode: d.mode, crsGroups: normalizeCrsGroups(parseJsonList(d.crs_rule_groups)), allowEntries: sides.allow, denyEntries: sides.deny })
  })
  peerPolicyViews.value = views
}

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
  if (form.value.mode === 'off') return ''
  const { peers, coBound } = comparisonContext.value
  const selfGroups = crsRuleGroups.value
  const dups: Array<{ name: string; overlap: string[] }> = []
  for (const peer of peers) {
    if (peer.mode === 'off') continue
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

// IP 步骤：允许/信任名单 × 黑名单的地址级冲突实时警告——允许/信任不跨策略生效。
const ipStepAclAlert = computed<string>(() => {
  const { peers } = comparisonContext.value
  const { allow: selfAllow, deny: selfDeny } = selfIpAclSides.value
  if (selfAllow.length === 0 && selfDeny.length === 0) return ''
  const items: string[] = []
  for (const peer of peers) {
    for (const entry of selfAllow.filter((e) => peer.denyEntries.includes(e))) {
      items.push(`地址 ${entry} 在「本策略」的允许/信任名单中、同时在「${peer.name}」的黑名单中——允许/信任不跨策略生效，该地址仍会被「${peer.name}」拦截`)
    }
    for (const entry of selfDeny.filter((e) => peer.allowEntries.includes(e))) {
      items.push(`地址 ${entry} 在「本策略」的黑名单中、同时在「${peer.name}」的允许/信任名单中——允许/信任不跨策略生效，该地址仍会被「本策略」拦截`)
    }
  }
  if (items.length === 0) return ''
  return items.slice(0, 2).join('；') + (items.length > 2 ? `；共 ${items.length} 条类似冲突` : '')
})

// Step 4 已关联规则的逐条视图：绑定链 + 本策略落点 + 拦截页面生效标注 + 冲突提示
const boundRuleRows = computed<BoundRuleRow[]>(() => boundRules.value.map((caddyId) => {
  const rule = allRules.value.find((r) => r.caddy_id === caddyId)
  const chain = buildDisplayChain(caddyId)
  const selfIndex = chain.findIndex((e) => e.isSelf)
  const firstEnabled = chain.find((e) => e.enabled)
  return {
    caddyId,
    name: rule?.name || caddyId,
    domain: rule?.domain || '',
    listenPort: rule?.listen_port ?? 0,
    chain,
    selfPosition: selfIndex + 1,
    selfBlockPageActive: form.value.enabled && firstEnabled?.isSelf === true,
    mergedCount: chain.length,
    showPerfTip: chain.length > PERF_POLICY_THRESHOLD,
    hints: computeBindingConflicts(buildConflictChain(caddyId)),
  }
}))

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

async function openDialog(row?: PolicySummary) {
  // R60 D60-F1：对话框打开序列号（同 Rules.vue wizardOpenSeq 模式）——
  // 详情 GET 在途期间用户再点"新建策略"或另一行"编辑"，首个返回会覆盖
  // editingId/表单，把保存语义错位成 PUT 到错误策略。
  const openSeq = ++policyDialogOpenSeq
  editingId.value = row?.id ?? null
  if (row) {
    try {
      const res = await request.get<APIResponse<{ policy: PolicyDetail; bindings: string[] }>>(`/security/policies/${row.id}`)
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
        ip_acl_mode: d.ip_acl_mode || 'allow',
        rate_limit_enabled: d.rate_limit_enabled,
        rate_limit_rps: d.rate_limit_rps,
        rate_limit_burst: d.rate_limit_burst,
        block_page_id: d.block_page_id || 1,
        block_status_code: d.block_status_code || 403,
        geoip_enabled: false,
        geoip_mode: d.geoip_mode || 'deny',
        waf_check_response: d.waf_check_response ?? false,
    }
    ipACLList.value = parseJsonList(d.ip_acl_list)
    ipWhitelist.value = parseJsonList(d.ip_whitelist)
    ipWhitelistEnabled.value = ipWhitelist.value.length > 0
    ipBlacklistSelf.value = parseJsonList(d.ip_blacklist)
    geoipCountries.value = parseJsonList(d.geoip_countries)
    form.value.geoip_enabled = geoipCountries.value.length > 0
      crsRuleGroups.value = normalizeCrsGroups(parseJsonList(d.crs_rule_groups))
      crsExcludedRules.value = parseJsonList(d.crs_excluded_rules)
      selectedCustomRules.value = parseCustomRuleIds(d.custom_rules)
      boundRules.value = res.data?.bindings || []
      // 拦截页面失效兜底：策略引用的拦截页面可能已被删除，select 匹配不到时回退
      // 默认页（优先 #1，其次第一个可用页），避免保存写回无效 id
      if (blockPages.value.length > 0 && !blockPages.value.some((p) => p.id === form.value.block_page_id)) {
        form.value.block_page_id = blockPages.value.find((p) => p.id === 1)?.id ?? blockPages.value[0].id
        ElMessage.warning('原拦截页面已删除，已回退默认页面')
      }
    } catch (error: unknown) {
      // R61 D-N1：catch 路径也要先比对序列号——GET 失败的过期请求会清空
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
  originalBoundRules.value = [...boundRules.value]
  currentStep.value = WIZARD_STEP.BASIC
  dialogVisible.value = true
  // 拉取其他启用策略的明细用于 WAF/IP 步骤的跨策略重复警告（列表接口不含
  // crs_rule_groups 明细；镜像 ensureBindingDetails 的懒加载模式，关闭时清空）
  void loadPeerPolicyViews(openSeq)
}

const resetForm = () => {
  form.value = defaultForm()
  ipACLList.value = []; ipWhitelist.value = []; ipWhitelistEnabled.value = false; ipBlacklistSelf.value = []; geoipCountries.value = []; crsRuleGroups.value = []; crsExcludedRules.value = []; selectedCustomRules.value = []; boundRules.value = []; editingId.value = null
}

const resetWizard = () => {
  currentStep.value = WIZARD_STEP.BASIC
  editingId.value = null
  rulePickerVisible.value = false
  ruleBoundPolicies.value = {}
  peerPolicyViews.value = []
}

const beforeWizardClose = (done: () => void): void => {
  if (!saving.value) done()
}

const handleSave = async () => {
  if (!form.value.name.trim()) {
    ElMessage.warning('请输入策略名称')
    currentStep.value = WIZARD_STEP.BASIC
    return
  }
  if (!validateIpAclList()) {
    currentStep.value = WIZARD_STEP.IP_ACL
    return
  }
  saving.value = true
  try {
    // v2.2.0 上限守卫（SC-BIND-02 配套）：POST bind 为 additive 且服务端不强制上限
    //（上限由 PUT /security/rules/:caddy_id/policies 强制），本流程的 5 条闸门在客户端。
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
      ElMessage.error(`以下规则已达 5 条绑定上限，无法继续关联：${names}`)
      currentStep.value = WIZARD_STEP.BINDINGS
      return
    }
    // 名单保留语义（与 ip_acl_list 对齐）：关闭开关不再清空已配置的名单，保存时始终
    // 回传当前名单内容，避免"关掉开关再打开"丢数据；ip_blacklist 本页不下发，后端
    // 指针语义自动保留原值。注意：后端按"名单非空即生效"发射，信任名单/区域控制
    // 的真正关闭方式是清空名单条目，开关仅控制编辑器显隐并在重开时按名单派生。
    // 显式白名单：仅提交 UpdateSecurityPolicyRequest 实际字段（geoip_enabled 为
    // 编辑器派生开关，后端无此字段，不下发；ip_blacklist 由其他入口管理）。
    const payload = {
      name: form.value.name,
      description: form.value.description,
      enabled: form.value.enabled,
      mode: form.value.mode,
      anomaly_threshold: form.value.anomaly_threshold,
      ip_acl_enabled: form.value.ip_acl_enabled,
      ip_acl_mode: form.value.ip_acl_mode,
      ip_acl_list: JSON.stringify(ipACLList.value),
      ip_whitelist: JSON.stringify(ipWhitelist.value),
      rate_limit_enabled: form.value.rate_limit_enabled,
      rate_limit_rps: form.value.rate_limit_rps,
      rate_limit_burst: form.value.rate_limit_burst,
      crs_rule_groups: JSON.stringify(crsRuleGroups.value),
      crs_excluded_rules: JSON.stringify(crsExcludedRules.value),
      custom_rules: JSON.stringify(selectedCustomRules.value),
      block_page_id: form.value.block_page_id,
      block_status_code: form.value.block_status_code,
      geoip_countries: JSON.stringify(geoipCountries.value),
      geoip_mode: form.value.geoip_mode,
      waf_check_response: form.value.waf_check_response,
    }
    let saveRes: APIResponse<{ id: number }> | undefined
    if (editingId.value) {
      saveRes = await request.put(`/security/policies/${editingId.value}`, payload)
    } else {
      saveRes = await request.post<APIResponse<{ id: number }>>('/security/policies', payload)
      const createdId = saveRes.data?.id
      if (!createdId) throw new Error('创建策略响应缺少 id')
      editingId.value = createdId
    }
    // v2.2.0 多策略绑定保存组合（SC-BIND-02）：新增规则走 additive POST bind（仅
    // INSERT OR IGNORE 本策略一行，绝不动该规则的兄弟绑定）；取消选择的规则只
    // DELETE 解绑本策略一行。规则的完整绑定列表不经本对话框改写——PUT 全量替换
    // 需要持有兄弟绑定快照，在本入口属于危险且无必要的写法。
    try {
      await Promise.all([
        ...added.map((caddyId) => request.post(`/security/policies/${editingId.value}/bind`, { rule_caddy_id: caddyId })),
        ...removed.map((caddyId) => request.delete(`/security/policies/${editingId.value}/bind/${caddyId}`)),
      ])
    } catch (error: unknown) {
      // 失败的 bind 请求已由全局拦截器逐个 toast，这里仅记录并中止收尾
      console.error('Failed to sync policy bindings:', error)
      return
    }
    showSaveResult(saveRes, '保存成功'); dialogVisible.value = false; fetchData()
  } catch { /* 具体错误已由全局 axios 拦截器统一展示 */ } finally { saving.value = false }
}

function handleDelete(row: PolicySummary) {
  ElMessageBox.confirm(`确定删除策略"${row.name}"？`, '确认', { type: 'warning' })
    .then(async () => { const del = await request.delete(`/security/policies/${row.id}`); showSaveResult(del, '已删除'); fetchData() }).catch(() => {})
}

const goToCustomRulesPage = () => { window.open('/?page=security-rules&tab=custom', '_blank') }
const goToBlockPagesPage = () => { window.open('/?page=security-block-pages', '_blank') }
const openRuleInNewTab = (caddyId: string): void => {
  localStorage.setItem('rules-search', caddyId)
  window.open('/?page=rules', '_blank')
}

const fetchRegions = async () => {
  try {
    const res = await request.get<APIResponse<RegionTree>>('/security/ip2region/regions')
    regionTree.value = { provinces: res.data?.provinces || [], cities: res.data?.cities || {} }
  } catch {
    regionTree.value = { provinces: [], cities: {} }
  }
}

onMounted(async () => {
  const search = localStorage.getItem('security-policies-search')
  if (search) { policySearch.value = search; localStorage.removeItem('security-policies-search') }
  const focusId = Number(localStorage.getItem('security-policies-focus-id') || 0)
  if (focusId) localStorage.removeItem('security-policies-focus-id')
  const loaded = await fetchData()
  if (focusId && loaded) {
    // R62 D-4：仅列表加载成功时才判定「已被删除」；加载失败时全局拦截器已弹错误
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
.search-input { width: 280px; }

.capability-tags { display: flex; gap: 6px; }

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

.wizard-content { min-height: min(350px, 55dvh); max-height: 55dvh; overflow-y: auto; padding-right: 8px; }

.step-content { padding: 8px 0; }

.step-content :deep(.el-form-item) {
  padding: 0 30px 0 20px;
}

.wizard-footer {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
}

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
.bound-rule-row { border: 1px solid #ebeef5; border-radius: 4px; padding: 8px 10px; }
.bound-rule-head { display: flex; align-items: center; gap: 8px; }
.bound-rule-name { font-weight: 500; color: #1f2937; font-size: 13px; }
.bound-rule-meta { font-size: 12px; color: #9ca3af; font-family: monospace; }
.bound-rule-remove { margin-left: auto; }
.bound-rule-chain { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin-top: 6px; }
.bound-rule-alert { margin-top: 8px; }
.wizard-alert { margin-bottom: 12px; }
/* 紧凑化 el-alert（Step 4 冲突提示与 WAF/IP 步骤实时警告共用）：默认 14px 标题 +
   8px/16px 内边距在表单内过重，统一收敛到 12px/1.5 的提示文本视觉；max-width 对齐
   表单控件列宽（弹窗 800px − label 100px − 内边距 ≈ 660px，取 640px），避免横贯弹窗。 */
.bound-rule-alert, .wizard-alert { max-width: 640px; }
.bound-rule-alert :deep(.el-alert__content), .wizard-alert :deep(.el-alert__content) { padding: 0; }
.bound-rule-alert :deep(.el-alert__title), .wizard-alert :deep(.el-alert__title) { font-size: 12px; line-height: 1.5; }
.bound-rule-alert :deep(.el-alert__icon), .wizard-alert :deep(.el-alert__icon) { font-size: 14px; width: 14px; }
.bound-rule-alert :deep(.el-alert__close-btn), .wizard-alert :deep(.el-alert__close-btn) { font-size: 12px; }
.bound-rule-alert.el-alert, .wizard-alert.el-alert { padding: 4px 10px; }

/* v2.2.0 绑定顺序 chip：本策略高亮（蓝），禁用策略灰显删除线；
   显式 line-height + inline-flex 保证 chip 视觉高度 ≈ 18-20px（避免继承表单上下文行高撑高）。 */
.binding-order-chip { font-size: 12px; padding: 0 6px; border-radius: 10px; background: #f3f4f6; color: #4b5563; border: 1px solid #e5e7eb; display: inline-flex; align-items: center; line-height: 18px; vertical-align: middle; }
.binding-order-chip.is-self { background: #eff6ff; color: #1d4ed8; border-color: #bfdbfe; font-weight: 500; }
.binding-order-chip.is-disabled { opacity: 0.55; text-decoration: line-through; }

/* v2.2.0 拦截页面按规则生效状态注释块：跟随 .form-tip-line 的 12px/灰调，
   仅状态词使用克制的成功/警告/灰着色，避免使用 el-tag 造成视觉噪声。 */
.block-page-rule-annotations { display: flex; flex-direction: column; gap: 2px; margin-top: 6px; font-size: 12px; line-height: 1.5; color: #9ca3af; width: 100%; }
.block-page-rule-annotation { display: flex; align-items: center; gap: 6px; }
.block-page-rule-annotation-name { color: #6b7280; }
.block-page-rule-annotation-status.is-active { color: #10b981; }
.block-page-rule-annotation-status.is-warning { color: #d97706; }
.block-page-rule-annotation-status.is-disabled { color: #9ca3af; }

.rule-binding-preview { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin: 2px 0 4px 24px; }
.rule-binding-landing { font-size: 12px; color: #6b7280; }
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
  border: 1px solid #ebeef5;
  border-radius: 4px;
  min-height: 120px;
  max-height: 320px;
  overflow-y: auto;
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
</style>

<!-- el-tooltip popper 挂载到 body， scoped 样式无法命中，单独非 scoped 块 -->
<style>
.policy-rules-popper .policy-rule-row {
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 12px;
  line-height: 1.6;
  cursor: pointer;
  transition: background-color 0.2s ease;
}
.policy-rules-popper .policy-rule-row:hover { background-color: rgba(255, 255, 255, 0.12); }
</style>
