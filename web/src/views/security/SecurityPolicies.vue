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
            <el-form-item label="检查响应体">
              <el-switch v-model="form.waf_check_response" :disabled="form.mode === 'off'" />
              <div class="form-tip-line">开启后 WAF 读取并检查上游响应内容（响应泄露类规则需要）；关闭可显著降低内存与 CPU 开销，大多数部署只需检查请求</div>
            </el-form-item>
            <el-form-item label="排除规则">
              <el-select v-model="crsExcludedRules" :disabled="form.mode === 'off'" multiple filterable placeholder="搜索并选择要排除的规则" style="width: 100%">
                <el-option-group label="OWASP CRS 规则">
                  <el-option v-for="rule in crsRuleOptions" :key="rule.filename" :label="`${rule.filename} (${rule.category})`" :value="rule.filename" />
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
          <el-divider content-position="left" class="acl-divider">区域控制</el-divider>
          <el-form :model="form" label-width="100px" :disabled="isReadOnly">
            <el-form-item label="启用">
              <el-switch v-model="form.geoip_enabled" />
            </el-form-item>
            <template v-if="form.geoip_enabled">
              <el-form-item label="控制模式">
                <el-radio-group v-model="form.geoip_mode">
                  <el-radio value="deny">拦截所选区域（其他放行）</el-radio>
                  <el-radio value="allow">仅允许所选区域（其他拦截）</el-radio>
                </el-radio-group>
              </el-form-item>
              <el-form-item label="区域选择">
                <el-select v-model="geoipCountries" multiple filterable allow-create default-first-option placeholder="选择或输入区域名称" style="width: 100%">
                  <el-option v-for="r in availableRegions" :key="r" :label="r" :value="r" />
                </el-select>
                <div class="form-tip-line">基于 IP2Region 离线库判断访客所在区域，与 CIDR 规则同时生效</div>
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
                <div v-if="boundRuleList.length > 0" class="bound-rule-tags">
                  <el-tag v-for="rule in boundRuleList" :key="rule.caddy_id" :closable="!isReadOnly" size="small" effect="plain" @close="removeBoundRule(rule.caddy_id)">{{ rule.name }}</el-tag>
                </div>
                <div class="form-tip-line">策略将应用到所选负载均衡规则的入站流量</div>
              </div>
            </el-form-item>
            <el-form-item label="拦截页面">
              <el-select v-model="form.block_page_id" placeholder="选择拦截页面" style="width: 100%">
                <el-option v-for="p in blockPages" :key="p.id" :label="p.name" :value="p.id" />
              </el-select>
              <div v-if="blockPages.length === 0" class="form-tip-line">暂无拦截页面，<el-link type="primary" @click="goToBlockPagesPage">去创建</el-link></div>
              <div v-else class="form-tip-line">拦截时返回给客户端的自定义页面，在"拦截页面"页面管理，<el-link type="primary" @click="goToBlockPagesPage">去创建/编辑</el-link></div>
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
          :disabled="pickerFilteredRules.length === 0"
          @change="handlePickerSelectAll"
        >全选</el-checkbox>
        <span class="rule-picker-header-meta">筛选 {{ pickerFilteredRules.length }} 条</span>
      </div>
      <div class="rule-picker-list">
        <el-checkbox-group v-model="pickerSelected">
          <div v-for="rule in pickerPagedRules" :key="rule.caddy_id" class="rule-picker-item">
            <el-checkbox :value="rule.caddy_id">
              <span class="rule-picker-name">{{ rule.name }}</span>
              <span class="rule-picker-meta">{{ rule.domain || '-' }}:{{ rule.listen_port }}</span>
            </el-checkbox>
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
interface PolicyDetail { id: number; name: string; description: string; mode: string; anomaly_threshold: number; ip_acl_mode: string; ip_acl_list: string; ip_acl_enabled: boolean; ip_whitelist: string; rate_limit_enabled: boolean; rate_limit_rps: number; rate_limit_burst: number; crs_rule_groups: string; crs_excluded_rules: string; custom_rules: string; block_page_id: number; block_status_code: number; enabled: boolean; updated_at: string; geoip_mode?: string; geoip_countries?: string; waf_check_response?: boolean }
interface Rule { caddy_id: string; name: string; domain: string; listen_port: number }
interface SecurityBinding { policy_id: number; name: string; mode: string; enabled: boolean; rate_limit_enabled: boolean }
interface CRSRuleOption { filename: string; category: string }
interface BlockPage { id: number; name: string }

const blockPages = ref<BlockPage[]>([])




const availableRegions = ref<string[]>([])

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
const securityBindings = ref<Record<string, SecurityBinding>>({})
const dialogVisible = ref(false)
const editingId = ref<number | null>(null)
const ipACLList = ref<string[]>([])
const ipWhitelist = ref<string[]>([])
const ipWhitelistEnabled = ref(false)
const geoipCountries = ref<string[]>([])
const crsRuleGroups = ref<string[]>([])
const crsExcludedRules = ref<string[]>([])
const boundRules = ref<string[]>([])
const originalBoundRules = ref<string[]>([])

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
const allCustomRules = ref<Array<{ id: number; name: string }>>([])

const fetchData = async () => {
  loading.value = true
  try {
    const [polRes, ruleRes, crsRes, bpRes, crRes, bindRes, userRes] = await Promise.all([
      request.get<APIResponse<PolicySummary[]>>('/security/policies'),
      request.get<APIResponse<Rule[]>>('/rules'),
      request.get<APIResponse<{ rules: CRSRuleOption[] }>>('/security/crs/rules?page_size=100'),
      request.get<APIResponse<BlockPage[]>>('/security/block-pages'),
      request.get<APIResponse<Array<{ id: number; name: string }>>>('/security/custom-rules'),
      request.get<APIResponse<Record<string, SecurityBinding>>>('/security/bindings'),
      request.get<APIResponse<UserListItem[]>>('/users'),
    ])
    policies.value = polRes.data || []
    allRules.value = ruleRes.data || []
    crsRuleOptions.value = crsRes.data?.rules || []
    blockPages.value = bpRes.data || []
    allCustomRules.value = crRes.data || []
    securityBindings.value = bindRes.data || {}
    users.value = userRes.data || []
  } catch (error: unknown) {
    // 全局拦截器已弹 toast，这里仅记录避免 unhandled rejection
    console.error('Failed to load policies data:', error)
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

const crsGroupOptions = computed(() => {
  const seen = new Map<string, string>()
  for (const rule of crsRuleOptions.value) {
    const match = /^(?:REQUEST|RESPONSE)-9(\d{2})-/i.exec(rule.filename)
    const code = match?.[1]
    if (!code || seen.has(code)) continue
    seen.set(code, `9${code} · ${rule.category}`)
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

// /security/bindings 以 rule_caddy_id 为键，反转为 policy_id → 规则列表供列表 tooltip 使用
const policyRulesMap = computed(() => {
  const map = new Map<number, Rule[]>()
  for (const rule of allRules.value) {
    const binding = securityBindings.value[rule.caddy_id]
    if (!binding) continue
    const list = map.get(binding.policy_id) ?? []
    list.push(rule)
    map.set(binding.policy_id, list)
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
  const query = pickerSearch.value.trim().toLowerCase()
  if (!query) return allRules.value
  return allRules.value.filter((rule) =>
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

// 全选作用于当前搜索筛选出的全部规则（跨分页），selection 存于 pickerSelected 与分页无关
const pickerFilteredSelectedCount = computed(() => {
  const selected = new Set(pickerSelected.value)
  return pickerFilteredRules.value.reduce((count, rule) => count + (selected.has(rule.caddy_id) ? 1 : 0), 0)
})
const pickerSelectAllChecked = computed(() =>
  pickerFilteredRules.value.length > 0 && pickerFilteredSelectedCount.value === pickerFilteredRules.value.length)
const pickerSelectAllIndeterminate = computed(() =>
  pickerFilteredSelectedCount.value > 0 && pickerFilteredSelectedCount.value < pickerFilteredRules.value.length)

const handlePickerSelectAll = (checked: string | number | boolean): void => {
  const filteredIds = pickerFilteredRules.value.map((rule) => rule.caddy_id)
  if (checked === true) {
    pickerSelected.value = [...new Set([...pickerSelected.value, ...filteredIds])]
    return
  }
  const filteredIdSet = new Set(filteredIds)
  pickerSelected.value = pickerSelected.value.filter((id) => !filteredIdSet.has(id))
}

const boundRuleList = computed(() => boundRules.value.map((caddyId) => {
  const rule = allRules.value.find((r) => r.caddy_id === caddyId)
  return { caddy_id: caddyId, name: rule?.name || caddyId }
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
}

const removeBoundRule = (caddyId: string): void => {
  boundRules.value = boundRules.value.filter((id) => id !== caddyId)
}

async function openDialog(row?: PolicySummary) {
  editingId.value = row?.id ?? null
  if (row) {
    try {
      const res = await request.get<APIResponse<{ policy: PolicyDetail; bindings: string[] }>>(`/security/policies/${row.id}`)
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
      // 全局拦截器已弹 toast，这里仅记录避免 unhandled rejection
      console.error('Failed to load policy detail:', error)
    }
  } else { resetForm() }
  originalBoundRules.value = [...boundRules.value]
  currentStep.value = WIZARD_STEP.BASIC
  dialogVisible.value = true
}

const resetForm = () => {
  form.value = defaultForm()
  ipACLList.value = []; ipWhitelist.value = []; ipWhitelistEnabled.value = false; geoipCountries.value = []; crsRuleGroups.value = []; crsExcludedRules.value = []; selectedCustomRules.value = []; boundRules.value = []; editingId.value = null
}

const resetWizard = () => {
  currentStep.value = WIZARD_STEP.BASIC
  editingId.value = null
  rulePickerVisible.value = false
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
    const added = boundRules.value.filter((id) => !originalBoundRules.value.includes(id))
    const removed = originalBoundRules.value.filter((id) => !boundRules.value.includes(id))
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

const fetchRegions = async () => { try { const res = await request.get<APIResponse<string[]>>('/security/ip2region/regions'); availableRegions.value = res.data || [] } catch { availableRegions.value = [] } }

onMounted(async () => {
  const search = localStorage.getItem('security-policies-search')
  if (search) { policySearch.value = search; localStorage.removeItem('security-policies-search') }
  const focusId = Number(localStorage.getItem('security-policies-focus-id') || 0)
  if (focusId) localStorage.removeItem('security-policies-focus-id')
  await fetchData()
  if (focusId) {
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

.bound-rule-tags { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }

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
  align-items: center;
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
