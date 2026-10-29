<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Notebook /></el-icon>
          规则集
        </h2>
        <p class="page-desc">管理 WAF 规则来源：OWASP CRS 规则库、IP 地理库、威胁情报库、爬虫地址库、自定义规则与 IP 地址列表</p>
      </div>
    </div>

    <el-card class="crs-card mb-5">
      <template #header>
        <div class="crs-header">
          <div class="crs-header-title">
            <span style="font-weight: 500;">规则库</span>
          </div>
          <!-- 库健康标签组（2026-09-24 用户裁定）：逐库彩色标签（正常=success/
               异常=danger），缺库时追加红色警示后缀；替换原统计文本摘要 -->
          <div class="lib-summary lib-summary-tags">
            <el-tag v-for="t in libHealthTags" :key="t.label" :type="t.type" size="small" effect="light" disable-transitions class="lib-health-tag">{{ t.label }}</el-tag>
            <span v-if="libSummaryWarn" class="lib-summary-warn-text">所有安全规则已暂停生效，请立即检查规则库</span>
          </div>
        </div>
      </template>
      <el-table :data="libRows" size="small" class="lib-table">
        <el-table-column label="名称" min-width="340">
          <template #default="{ row }">
            <div class="lib-name">
              <span class="lib-icon" :class="row.iconClass"><el-icon :size="15"><component :is="row.icon" /></el-icon></span>
              <div class="lib-name-text">
                <div class="lib-name-main">{{ row.name }}</div>
                <div v-if="row.sub" class="lib-name-sub">{{ row.sub }}</div>
              </div>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="版本" width="120">
          <template #default="{ row }"><span class="lib-version">{{ row.version }}</span></template>
        </el-table-column>
        <!-- 本列对 CRS/威胁/爬虫是条目数，对 IP 地理库是库文件大小——
             列名必须两义都覆盖，否则字节数会被读成条目数 -->
        <el-table-column label="数量 / 大小" width="120" align="right">
          <template #default="{ row }"><span class="lib-count">{{ row.count }}</span></template>
        </el-table-column>
        <el-table-column label="状态" width="110">
          <template #default="{ row }">
            <!-- 失败 hover 长文案已撤（2026-09-25 用户裁定）：用户直接看更新日志，
                 状态标签自身已表达失败态 -->
            <el-tag v-if="row.status" :type="libraryStatusTagType(row.status)" size="small" effect="light">{{ libraryStatusLabel(row.status) }}</el-tag>
            <span v-else class="text-secondary">—</span>
          </template>
        </el-table-column>
        <el-table-column label="自动更新" width="90" align="center">
          <template #default="{ row }">
            <!-- 库状态读取失败/首次响应未落地时开关态不可信——显示「—」并禁用，
                 不得按本地默认 true 冒充「已开启」 -->
            <span v-if="!row.autoUpdateKnown" class="text-secondary" title="库状态未知（读取失败），开关态不可信">—</span>
            <el-switch v-else :model-value="row.autoUpdate" :loading="autoUpdateSaving.has(row.key)" :disabled="isReadOnly || isSlaveNode || autoUpdateSaving.has(row.key)" @change="(v: string | number | boolean) => toggleLibAutoUpdate(row as LibRow, v === true)" />
          </template>
        </el-table-column>
        <el-table-column v-if="!isSlaveNode" label="上次更新" width="150">
          <template #default="{ row }">{{ row.lastChecked }}</template>
        </el-table-column>
        <el-table-column v-if="!isSlaveNode" label="下次更新" width="150">
          <template #default="{ row }">{{ row.nextUpdate }}</template>
        </el-table-column>
        <el-table-column label="操作" width="170" align="center">
          <template #default="{ row }">
            <el-button size="small" link type="primary" @click="openLibDialog(row as LibRow)">更新详情</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div v-if="isSlaveNode" style="margin-top: 8px;">
        <el-tag type="info" size="small" effect="plain">跟随主节点同步</el-tag>
      </div>
    </el-card>

    <el-alert v-if="rulesLoadError" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
      <template #title>
        <div class="polling-error-title">
          <span>{{ rules.length === 0 ? 'CRS 规则文件加载失败，「暂无规则文件」不代表真实状态' : 'CRS 规则文件加载失败：当前显示的是上次成功结果（与分页/搜索条件不符）' }}</span>
          <el-button link type="danger" :loading="loadingRules" @click="fetchRules">立即重试</el-button>
        </div>
      </template>
    </el-alert>

    <el-card>
      <el-tabs v-model="activeTab">
        <el-tab-pane label="CRS 规则" name="rules">
          <div class="table-toolbar">
            <el-input v-model="searchQuery" placeholder="搜索规则文件名或分类" clearable :prefix-icon="Search" class="search-input" @clear="searchRules" @keyup.enter="searchRules" />
          </div>
          <el-table :data="rules" v-loading="loadingRules" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="" @row-click="openRuleContent" style="cursor: pointer">
            <template #empty><el-empty :description="rulesLoadError ? '加载失败，请重试' : '暂无规则文件'" :image-size="60" /></template>
            <el-table-column prop="filename" label="文件名" min-width="320" show-overflow-tooltip />
            <el-table-column prop="category" label="分类" width="160">
              <template #default="{ row }"><el-tag size="small" effect="plain" type="info">{{ row.category }}</el-tag></template>
            </el-table-column>
            <el-table-column label="大小" width="100" align="right">
              <template #default="{ row }">{{ formatSize(row.size) }}</template>
            </el-table-column>
            <el-table-column label="更新时间" width="170" align="center">
              <template #default="{ row }">{{ formatDate(row.updated_at) || '-' }}</template>
            </el-table-column>
            <el-table-column label="" width="80" align="center">
              <template #default><el-button link type="primary" size="small">查看</el-button></template>
            </el-table-column>
          </el-table>
          <div class="rules-pagination">
            <el-pagination v-model:current-page="page" v-model:page-size="pageSize" :page-sizes="[10, 20, 50]" :total="total" layout="total, sizes, prev, pager, next" @current-change="fetchRules" @size-change="onRulesSizeChange" />
          </div>
        </el-tab-pane>
      <el-tab-pane label="自定义规则" name="custom">
            <el-alert v-if="customRulesError || usersError" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
              <template #title>
                <div class="polling-error-title">
                  <span>{{ customRulesError ? '自定义规则加载失败：表格为空不代表没有规则' : '用户名册加载失败：更新者列显示为 -（规则数据不受影响）' }}</span>
                  <el-button link type="danger" :loading="loadingCustom" @click="retryCustomRules">立即重试</el-button>
                </div>
              </template>
            </el-alert>
            <div class="table-toolbar">
              <el-button v-if="!isReadOnly" type="primary" :icon="Plus" @click="openRuleDialog()">新建规则</el-button>
            </div>
            <el-table :data="customRulesPaged" v-loading="loadingCustom" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="">
            <template #empty>
              <el-empty v-if="!customRulesError" description="暂无自定义规则" :image-size="60" />
              <span v-else class="text-secondary">加载失败</span>
            </template>
            <el-table-column prop="name" label="规则名称" min-width="150">
              <template #default="{ row }">
                <AccessibleLink type="primary" @click="openRuleDialog(row as CustomRule)">{{ row.name }}</AccessibleLink>
              </template>
            </el-table-column>
            <el-table-column prop="description" label="描述" min-width="200" show-overflow-tooltip />
            <!-- 条件关系（AND/OR）独立成窄列：与条件内容同列时标签挤占文本宽度，
                 长正则被压成折行/错位（2026-10-27 用户裁定）。 -->
            <el-table-column label="条件关系" width="140" align="center">
              <template #default="{ row }">
                <el-tag size="small" effect="light" :type="row.condition_logic === 'or' ? 'warning' : 'info'">{{ row.condition_logic === 'or' ? '任一满足（OR）' : '同时满足（AND）' }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="条件" min-width="320" class-name="rule-cond-cell">
              <template #default="{ row }">
                <!-- 逐条单行 chip：长正则省略 + tooltip 全文，多条按行排布不挤压
                     （样式在 styles/main.css 的 .cond-chip-list/.cond-chip） -->
                <div class="cond-chip-list">
                  <el-tooltip v-for="(cond, i) in row.conditions" :key="i" :content="`${cond.target} ${cond.operator} ${cond.pattern}`" placement="top" :show-after="200">
                    <el-tag size="small" effect="plain" class="cond-chip">{{ cond.target }} {{ cond.operator }} {{ cond.pattern }}</el-tag>
                  </el-tooltip>
                </div>
              </template>
            </el-table-column>
            <el-table-column label="动作" width="80" align="center">
              <template #default="{ row }">
                <!-- 三态映射与编辑器（拦截/仅记录/放行计分）语义对齐——
                     pass 会累加异常分参与 949 评分拦截，与 log（仅记录）不可混示 -->
                <el-tag :type="customActionView(row.action).type" size="small" effect="light">{{ customActionView(row.action).label }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="状态" width="80" align="center">
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
            <el-table-column label="操作" width="140" fixed="right">
              <template #default="{ row }">
                <el-button size="small" link type="primary" @click="openRuleDialog(row as CustomRule)">{{ isReadOnly ? '查看' : '编辑' }}</el-button>
                <el-button size="small" link type="danger" :disabled="isReadOnly" @click="deleteCustomRule(row as CustomRule)">删除</el-button>
            </template>
            </el-table-column>
          </el-table>
          <div class="rules-pagination">
            <el-pagination v-model:current-page="customPage" v-model:page-size="customPageSize" :total="customRules.length" layout="total, sizes, prev, pager, next" @size-change="customPage = 1" />
          </div>
        </el-tab-pane>
        <el-tab-pane label="IP 地址列表" name="ip-lists">
            <el-alert v-if="ipListsError" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
              <template #title>
                <div class="polling-error-title">
                  <span>IP 地址列表加载失败：表格为空不代表没有名单</span>
                  <el-button link type="danger" :loading="loadingIpLists" @click="retryIpLists">立即重试</el-button>
                </div>
              </template>
            </el-alert>
          <div class="table-toolbar ip-list-toolbar">
            <el-input v-model="ipListSearch" placeholder="搜索名称或分类" clearable :prefix-icon="Search" class="search-input" />
            <el-button v-if="!isReadOnly" type="primary" :icon="Plus" @click="openIpListDialog()">新建列表</el-button>
          </div>
          <el-table :data="ipListsPaged" v-loading="loadingIpLists" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="">
            <template #empty>
              <el-empty v-if="!ipListsError" description="暂无 IP 地址列表" :image-size="60" />
              <span v-else class="text-secondary">加载失败</span>
            </template>
            <el-table-column prop="name" label="名称" min-width="150">
              <template #default="{ row }">
                <AccessibleLink type="primary" @click="openIpListDialog(row as IPListRow)">{{ row.name }}</AccessibleLink>
                <el-tag v-if="row.preset_autoban" size="small" type="danger" effect="plain" style="margin-left: 6px;">自动封禁</el-tag>
                <el-tag v-else-if="row.system" size="small" type="warning" effect="plain" style="margin-left: 6px;">内置</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="分类" width="120" align="center">
              <template #default="{ row }">
                <el-tag v-if="row.category" size="small" effect="plain" type="info">{{ row.category }}</el-tag>
                <template v-else>—</template>
              </template>
            </el-table-column>
            <el-table-column label="条目数" width="100" align="center">
              <template #default="{ row }">
                {{ row.entry_count }}
                <el-tooltip v-if="row.preset_autoban" content="含已到期条目：到期即自动解封，此处为名单总条数（含待清理的到期项）" placement="top">
                  <el-icon class="count-tip"><InfoFilled /></el-icon>
                </el-tooltip>
              </template>
            </el-table-column>
            <el-table-column label="引用" width="90" align="center">
              <template #default="{ row }">
                <el-tooltip v-if="row.ref_policies.length > 0 || row.trusted_proxy_referenced" placement="top" popper-class="ip-list-refs-popper" :popper-options="popperViewportSafe">
                  <template #content>
                    <div v-for="p in row.ref_policies" :key="p.id">{{ p.name }}<template v-if="!p.enabled">（已禁用，不阻止删除）</template></div>
                    <div v-if="row.trusted_proxy_referenced">{{ row.trusted_proxy_scope || '受信代理网段' }}</div>
                  </template>
                  <span>{{ row.ref_count }}</span>
                </el-tooltip>
                <template v-else>{{ row.ref_count }}</template>
              </template>
            </el-table-column>
            <el-table-column label="更新时间" width="170" align="center">
              <template #default="{ row }">{{ formatDate(row.updated_at) || '-' }}</template>
            </el-table-column>
            <el-table-column label="更新者" width="100" align="center">
              <template #default="{ row }">{{ getUpdaterName(row.updated_by) }}</template>
            </el-table-column>
            <el-table-column label="操作" width="140" fixed="right">
              <template #default="{ row }">
                <el-button size="small" link type="primary" @click="openIpListDialog(row as IPListRow)">{{ isReadOnly || (row.system && !row.preset_autoban) ? '查看' : '编辑' }}</el-button>
                <el-button v-if="!row.system" size="small" link type="danger" :disabled="isReadOnly" @click="deleteIpList(row as IPListRow)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
          <div class="rules-pagination">
            <el-pagination v-model:current-page="ipListPage" v-model:page-size="ipListPageSize" :total="ipListsFiltered.length" layout="total, sizes, prev, pager, next" @size-change="ipListPage = 1" />
          </div>
        </el-tab-pane>
      </el-tabs>
    </el-card>

    <el-dialog v-model="contentDialogVisible" width="min(900px, 94vw)" top="5vh">
      <template #header>
        <DialogHeader :icon="Notebook" title="规则文件预览" :subtitle="currentFilename" />
      </template>
      <DialogSectionHeader title="规则内容" />
      <div v-loading="loadingContent" class="dialog-panel dialog-panel--flush"><SyntaxHighlight :content="currentContent" language="apacheconf" /></div>
    </el-dialog>

    <el-dialog v-model="ruleDialogVisible" width="min(760px, 94vw)" class="custom-rule-dialog" top="6vh" :close-on-click-modal="false" :close-on-press-escape="!savingRule" :show-close="!savingRule">
      <template #header>
        <DialogHeader :icon="Filter" :title="editingRuleId ? (isReadOnly ? '查看自定义规则' : '编辑自定义规则') : '新建自定义规则'"
          subtitle="按请求特征匹配并执行拦截 / 记录 / 计分动作，多条件可同时满足或任一满足" tone="danger" />
      </template>
      <el-form :model="ruleForm" label-width="80px" label-position="right" :disabled="isReadOnly || savingRule">
        <!-- 值与后端写侧门同源（internal/handlers/security.go：名称 ≤100 rune、
             描述 ≤500 rune）——超长只能等 400 的旧形态没有字段级定位 -->
        <el-form-item label="名称" required>
          <el-input v-model="ruleForm.name" placeholder="规则名称" :maxlength="SECURITY_NAME_MAX_RUNES" show-word-limit />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="ruleForm.description" placeholder="规则描述" :maxlength="SECURITY_DESCRIPTION_MAX_RUNES" show-word-limit />
        </el-form-item>
        <el-form-item label="条件关系">
          <el-radio-group v-model="ruleForm.condition_logic" aria-label="条件关系">
            <el-radio value="and">同时满足（AND）</el-radio>
            <el-radio value="or">任一满足（OR）</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="条件">
          <div style="width: 100%">
            <div v-for="(cond, idx) in ruleForm.conditions" :key="idx" class="rule-condition-row">
              <el-select v-model="cond.target" style="width: 120px" size="small">
                <el-option label="请求路径" value="uri" />
                <el-option label="请求参数" value="args" />
                <el-option label="请求头" value="headers" />
                <el-option label="请求体" value="body" />
                <el-option label="User-Agent" value="user_agent" />
              </el-select>
              <el-select v-model="cond.operator" style="width: 110px" size="small">
                <el-option label="包含" value="contains" />
                <el-option label="正则匹配" value="regex" />
                <el-option label="完全匹配" value="equals" />
                <el-option label="前缀匹配" value="starts_with" />
              </el-select>
              <div class="pattern-col">
                <div class="pattern-input-row">
                  <el-input v-model="cond.pattern" :placeholder="patternPlaceholder(cond)" size="small" :class="{ 'is-error': (cond.operator === 'regex' && !isValidRegex(cond.pattern)) || patternOverLimit(cond.pattern) }" />
                  <el-icon v-if="cond.operator === 'regex' && !isValidRegex(cond.pattern)" class="regex-error-icon"><WarningFilled /></el-icon>
                  <el-icon v-else-if="patternOverLimit(cond.pattern)" class="regex-error-icon"><WarningFilled /></el-icon>
                </div>
                <!-- 与后端写侧门同口径：4KiB 按 UTF-8 字节计（中文字符 3 字节），
                     按字符数看不出超限，故给出实时字节数 -->
                <div v-if="patternOverLimit(cond.pattern)" class="form-tip-line port-warning">
                  匹配内容不能超过 {{ CUSTOM_RULE_MAX_PATTERN_BYTES }} 字节（当前 {{ patternByteLength(cond.pattern) }} 字节）
                </div>
              </div>
              <el-button link type="danger" size="small" :disabled="isReadOnly || savingRule" @click="removeCondition(idx)">删除</el-button>
                <div v-if="cond.target === 'user_agent'" class="preset-section">
                  <button type="button" class="preset-header" :aria-expanded="!uaCollapsed[idx]" @click="uaCollapsed[idx] = !uaCollapsed[idx]">
                    <span class="preset-toggle">{{ uaCollapsed[idx] ? '▶' : '▼' }} 快捷标签</span>
                  </button>
                  <div v-show="!uaCollapsed[idx]" class="preset-tags-block">
                    <div v-for="g in UA_PRESET_GROUPS" :key="g.label" class="preset-group">
                      <span class="preset-group-label">{{ g.label }}</span>
                      <div class="preset-group-tags">
                        <el-tag v-for="t in g.values" :key="t.value" size="small" effect="plain" class="preset-tag" role="button" tabindex="0" @click="cond.pattern = t.value" @keydown.enter.prevent="activateOnce($event, () => { cond.pattern = t.value })" @keydown.space.prevent="activateOnce($event, () => { cond.pattern = t.value })">{{ t.label }}</el-tag>
                      </div>
                    </div>
                    <div class="preset-hint">标签写入真实 UA 片段（contains 精确匹配，区分大小写）</div>
                  </div>
                </div>
                <div v-if="cond.operator === 'regex'" class="preset-section">
                  <button type="button" class="preset-header" :aria-expanded="!regexCollapsed[idx]" @click="regexCollapsed[idx] = !regexCollapsed[idx]">
                    <span class="preset-toggle">{{ regexCollapsed[idx] ? '▶' : '▼' }} 正则模板与测试</span>
                  </button>
                  <div v-show="!regexCollapsed[idx]" class="regex-extras">
                    <div class="regex-presets">
                      <el-button v-for="p in REGEX_PRESETS" :key="p.label" link type="primary" size="small" class="regex-preset-link" @click="cond.pattern = p.value">{{ p.label }}</el-button>
                    </div>
                    <div class="regex-tester">
                      <el-input v-model="regexTestStrings[idx]" placeholder="输入测试字符串" size="small" class="regex-test-input" />
                      <span class="regex-test-result" :class="regexResultClass(cond, idx)">{{ regexResultText(cond, idx) }}</span>
                    </div>
                  </div>
                </div>
            </div>
            <div class="add-condition-row">
              <el-button v-if="!isReadOnly" size="small" type="primary" plain class="add-condition-btn" :disabled="!canAddCondition(ruleForm.conditions.length) || savingRule" @click="ruleForm.conditions.push({ target: 'uri', operator: 'contains', pattern: '' })">
                + 添加条件
              </el-button>
              <!-- 条件数上限与后端 customRuleMaxConditions 同源：超出只能提交后吃 400 -->
              <span class="form-tip-inline">{{ ruleForm.conditions.length }}/{{ CUSTOM_RULE_MAX_CONDITIONS }}</span>
            </div>
          </div>
        </el-form-item>
        <!-- 原生表单行（2026-10-11 用户裁定：对齐统一走 el-form-item；Firefox
             label-for 控制台告警为 EP 上游已知形态，非用户可见） -->
        <el-form-item label="动作">
          <el-radio-group v-model="ruleForm.action" aria-label="动作">
            <el-radio value="block">拦截</el-radio>
            <el-radio value="log">仅记录</el-radio>
            <el-radio value="pass">放行计分</el-radio>
          </el-radio-group>
          <div class="form-tip-line">拦截=命中即阻断；仅记录=只记录事件；放行计分=记录并向异常分累加（CRS 检测/拦截模式下由异常阈值统一裁决；仅自定义模式下只记录不拦截）</div>
        </el-form-item>
        <el-form-item label="异常分值">
          <el-select v-model="ruleForm.score" style="width: 160px">
            <el-option :value="1" label="轻微（1）" />
            <el-option :value="3" label="较低（3）" />
            <el-option :value="5" label="中等（5）" />
            <el-option :value="10" label="较高（10）" />
            <el-option :value="20" label="严重（20）" />
          </el-select>
          <div class="form-tip-line">匹配此规则时累加的异常分值，累计达到策略异常阈值后触发拦截；仅自定义模式无阈值评估，只记录</div>
        </el-form-item>
        <el-form-item label="启用">
          <el-switch v-model="ruleForm.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button :disabled="savingRule" @click="ruleDialogVisible = false">取消</el-button>
        <el-button type="primary" :disabled="isReadOnly || savingRule" :loading="savingRule" @click="saveCustomRule">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="ipListDialogVisible" width="min(900px, 94vw)" class="ip-list-dialog" top="6vh" :close-on-click-modal="false" :close-on-press-escape="!savingIpList" :show-close="!savingIpList">
      <template #header>
        <DialogHeader :icon="List" :title="editingIpListId ? (ipListDialogReadOnly ? '查看 IP 地址列表' : '编辑 IP 地址列表') : '新建 IP 地址列表'"
          subtitle="可复用 IP/CIDR 集合，供安全策略引用（黑白名单 / 信任名单）" />
      </template>
      <div v-if="ipListDetailFailed" class="info-note-bar">
        <span class="info-note-desc">名单条目加载失败：为避免以空条目覆盖原列表，保存与条目增删/导入已禁用；请先重新加载。</span>
        <el-button size="small" type="primary" plain @click="reloadIpListDetail">重新加载</el-button>
      </div>
      <el-form :model="ipListForm" label-width="80px" label-position="right" v-loading="loadingIpListDetail" :disabled="savingIpList">
        <!-- 自动封禁预置名单名称/分类/描述为内置字段（后端 400 守卫同口径），
             前端直接禁用灰态——禁止修改的字段不可输入，而非提交后报 400 -->
        <el-form-item label="名称" required>
          <el-input v-model="ipListForm.name" placeholder="列表名称" maxlength="50" show-word-limit :disabled="ipListDialogReadOnly || editingIpListPreset || savingIpList" />
        </el-form-item>
        <el-form-item label="分类">
          <el-select v-model="ipListForm.category" allow-create filterable default-first-option placeholder="选择或输入分类" style="width: 100%" :disabled="ipListDialogReadOnly || editingIpListPreset || savingIpList">
            <el-option v-for="c in IP_LIST_CATEGORIES" :key="c" :label="c" :value="c" />
          </el-select>
          <div class="form-tip-line">预设分类可直接选择，也可自定义（≤32 字符）</div>
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="ipListForm.description" placeholder="列表用途说明" maxlength="200" show-word-limit :disabled="ipListDialogReadOnly || editingIpListPreset || savingIpList" />
        </el-form-item>
        <el-form-item label="条目" required>
          <div class="entries-block">
            <DialogSectionHeader title="名单条目" />
            <div class="dialog-panel dialog-panel--flush">
              <el-table :data="ipListEntriesPaged" size="small" max-height="360" empty-text="">
              <template #empty><el-empty description="暂无条目，点击下方按钮添加" :image-size="50" /></template>
              <el-table-column label="#" width="50" align="right">
                <template #default="{ $index }"><span class="ip-entry-index">{{ ipListEntryPageStart + $index + 1 }}</span></template>
              </el-table-column>
              <el-table-column label="IP / CIDR" min-width="230">
                <template #default="{ row }">
                  <span v-if="ipListDialogReadOnly" class="ip-entry-text">{{ row.value }}</span>
                  <el-input v-else v-model="row.value" placeholder="如 192.168.1.0/24" size="small" :class="{ 'ip-entry-invalid': !isValidCidr(row.value) }" />
                </template>
              </el-table-column>
              <el-table-column label="备注" min-width="140">
                <template #default="{ row }">
                  <span v-if="ipListDialogReadOnly" class="ip-entry-text">{{ row.remark }}</span>
                  <el-input v-else v-model="row.remark" placeholder="可选备注" size="small" maxlength="100" />
                </template>
              </el-table-column>
              <!-- 自动封禁名单条目展示加入时间/剩余（到期时间由剩余列表达；删除条目即解封）-->
              <template v-if="editingIpListPreset">
                <el-table-column label="加入时间" width="170" align="center" class-name="ip-entry-created">
                  <template #default="{ row }">{{ formatDate(row.created_at) || '—' }}</template>
                </el-table-column>
                <el-table-column label="剩余时长" width="90" align="center">
                  <template #default="{ row }">
                    <el-tag v-if="!row.expires_at" size="small" effect="plain" type="info">永久</el-tag>
                    <el-tag v-else-if="autobanEntryExpired(row.expires_at)" size="small" effect="plain" type="info">已到期</el-tag>
                    <span v-else class="text-secondary">{{ autobanEntryRemaining(row.expires_at) }}</span>
                  </template>
                </el-table-column>
              </template>
              <el-table-column v-if="!ipListDialogReadOnly" label="" width="60" align="center">
                <template #default="{ $index }">
                  <el-button link type="danger" size="small" :disabled="savingIpList" @click="removeIpListEntry(ipListEntryPageStart + $index)">删除</el-button>
                </template>
              </el-table-column>
              </el-table>
            </div>
            <div v-if="ipListForm.entries.length > ipListEntryPageSize" class="entries-pagination">
              <el-pagination
                v-model:current-page="ipListEntryPage"
                :page-size="ipListEntryPageSize"
                :total="ipListForm.entries.length"
                layout="total, prev, pager, next"
                size="small"
              />
            </div>
            <div class="entries-toolbar">
              <el-button v-if="!ipListDialogReadOnly" size="small" type="primary" plain :disabled="ipListDetailFailed || savingIpList" @click="addIpListEntry">
                + 添加条目
              </el-button>
              <div class="entries-toolbar-right">
                <el-button v-if="!ipListDialogReadOnly" size="small" type="primary" plain :disabled="ipListDetailFailed || savingIpList" @click="triggerImportEntries">导入</el-button>
                <el-button size="small" type="primary" plain @click="exportIpListEntries">导出</el-button>
              </div>
            </div>
            <input ref="importEntriesInput" type="file" accept=".txt,.csv" class="entries-import-input" @change="onImportEntriesFileChange" />
            <div class="form-tip-line">每条支持单 IP 或 CIDR（如 10.0.0.1、2001:db8::/32）；每个列表最多 {{ IP_LIST_MAX_ENTRIES }} 条（已到期条目不计入），用户创建的名单最多 200 个（内置名单不占额度），格式错误的行以红色标出；导入支持 .txt/.csv（每行一条：IP/CIDR + 可选备注，逗号或空白分隔）</div>
          </div>
        </el-form-item>
      </el-form>
      <template #footer>
        <template v-if="ipListDialogReadOnly">
          <el-button :disabled="savingIpList" @click="ipListDialogVisible = false">关闭</el-button>
        </template>
        <template v-else>
          <el-button :disabled="savingIpList" @click="ipListDialogVisible = false">取消</el-button>
          <el-tooltip v-if="ipListDetailFailed" content="名单条目加载失败：保存会以空条目覆盖列表，已禁用；请重试加载" placement="top">
            <span>
              <el-button type="primary" disabled>保存</el-button>
            </span>
          </el-tooltip>
          <el-button v-else type="primary" :loading="savingIpList" :disabled="!canSaveIpList(loadingIpListDetail, ipListDetailFailed)" @click="saveIpList">保存</el-button>
        </template>
      </template>
    </el-dialog>

    <el-dialog
      v-model="updateDialogVisible"
      width="min(900px, 94vw)"
      top="8vh"
      destroy-on-close
      @opened="onUpdateDialogOpened"
      @closed="onUpdateDialogClosed"
    >
      <template #header>
        <DialogHeader :icon="Lock" title="更新 CRS 规则库" subtitle="OWASP 核心规则集的更新任务与更新日志" tone-class="lib-icon--crs" />
      </template>
      <RuleLibScheduleEditor
        :days="crsInfo.schedule_days"
        :time="crsInfo.schedule_time"
        :disabled="isReadOnly || isSlaveNode"
        :unavailable-hint="crsScheduleHint"
        :saving="savingCRSSchedule"
        :tz="scheduleTz"
        @save="saveCRSSchedule"
      />
      <DialogSectionHeader title="更新日志" />
      <div class="dialog-panel dialog-panel--flush">
        <div ref="updateLogRef" class="update-log-container">
          <pre v-if="updateLog" class="update-log-content">{{ updateLog }}</pre>
          <el-empty v-else description="暂无更新日志" :image-size="60" />
        </div>
      </div>
      <template #footer>
        <div style="display: flex; align-items: center;">
          <LogStorageBar log-key="crs_update" style="margin-right: auto" />
          <el-button @click="updateDialogVisible = false">关闭</el-button>
        <el-button v-if="!crsUpdateRunning" type="primary" :disabled="isReadOnly || isSlaveNode" :loading="startingUpdate" @click="confirmUpdate">立即更新</el-button>
        </div>
      </template>
    </el-dialog>

    <el-dialog
      v-model="ip2regionUpdateDialogVisible"
      width="min(900px, 94vw)"
      top="8vh"
      destroy-on-close
      @opened="onIP2RegionUpdateDialogOpened"
      @closed="onIP2RegionUpdateDialogClosed"
    >
      <template #header>
        <DialogHeader :icon="Location" title="更新 IP 库" subtitle="IP2Region 地理归属数据库的更新任务与更新日志" tone-class="lib-icon--ip" />
      </template>
      <RuleLibScheduleEditor
        :days="ip2regionInfo.schedule_days"
        :time="ip2regionInfo.schedule_time"
        :disabled="isReadOnly || isSlaveNode"
        :unavailable-hint="ip2regionScheduleHint"
        :saving="savingIP2RegionSchedule"
        :tz="scheduleTz"
        @save="saveIP2RegionSchedule"
      />
      <DialogSectionHeader title="更新日志" />
      <div class="dialog-panel dialog-panel--flush">
        <div ref="ip2regionUpdateLogRef" class="update-log-container">
          <pre v-if="ip2regionUpdateLog" class="update-log-content">{{ ip2regionUpdateLog }}</pre>
          <el-empty v-else description="暂无更新日志" :image-size="60" />
        </div>
      </div>
      <template #footer>
        <div style="display: flex; align-items: center;">
          <LogStorageBar log-key="ip2region_update" style="margin-right: auto" />
          <el-button @click="ip2regionUpdateDialogVisible = false">关闭</el-button>
        <el-button v-if="!ip2regionUpdateRunning" type="primary" :disabled="isReadOnly || isSlaveNode" :loading="startingIP2RegionUpdate" @click="confirmIP2RegionUpdate">立即更新</el-button>
        </div>
      </template>
    </el-dialog>

    <el-dialog
      v-model="threatUpdateDialogVisible"
      width="min(900px, 94vw)"
      top="8vh"
      destroy-on-close
      @opened="onThreatUpdateDialogOpened"
      @closed="onThreatUpdateDialogClosed"
    >
      <template #header>
        <DialogHeader :icon="Aim" title="更新威胁情报库" subtitle="三个内置恶意 IP 源的更新任务与更新日志" tone-class="lib-icon--threat" />
      </template>
      <DialogSectionHeader title="威胁情报来源" />
      <div class="dialog-panel dialog-panel--flush library-sources-panel">
        <el-table :data="threatSources" size="small" class="threat-source-table">
        <el-table-column label="来源" min-width="260">
          <!-- 标题加粗 + 更新地址次行（与规则库表格「名称+描述」两行同构，
               2026-09-24 用户裁定替代独立更新地址列） -->
          <template #default="{ row }">
            <div class="lib-name-text">
              <div class="lib-name-main">{{ row.display_name }}</div>
              <div class="lib-name-sub threat-source-url">{{ row.url }}</div>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="条目数" width="100" align="right">
          <template #default="{ row }">{{ row.entry_count ? row.entry_count.toLocaleString() : '—' }}</template>
        </el-table-column>
        <el-table-column label="版本" width="110">
          <template #default="{ row }"><span class="lib-version">{{ row.version || '未更新' }}</span></template>
        </el-table-column>
        <el-table-column label="状态" width="110">
          <template #default="{ row }">
            <el-tag v-if="!row.update_enabled" type="info" size="small" effect="light">已关闭</el-tag>
            <el-tag v-else :type="libraryStatusTagType(row.update_status)" size="small" effect="light">{{ libraryStatusLabel(row.update_status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="自动更新" width="90" align="center">
          <template #default="{ row }">
            <el-switch v-model="row.update_enabled" :loading="sourceFlagPending('threat', row.id)" :disabled="isReadOnly || isSlaveNode || sourceFlagPending('threat', row.id)" @change="(v: string | number | boolean) => toggleThreatFlag(row as ThreatSource, v === true)" />
          </template>
        </el-table-column>
        </el-table>
      </div>
      <RuleLibScheduleEditor
        :days="threatSchedule.days"
        :time="threatSchedule.time"
        :disabled="isReadOnly || isSlaveNode"
        :unavailable-hint="threatScheduleHint"
        :saving="savingThreatSchedule"
        :tz="scheduleTz"
        @save="saveThreatSchedule"
      />
      <DialogSectionHeader title="更新日志" />
      <div class="dialog-panel dialog-panel--flush">
        <div ref="threatUpdateLogRef" class="update-log-container update-log-container--compact">
          <pre v-if="threatUpdateLog" class="update-log-content">{{ threatUpdateLog }}</pre>
          <el-empty v-else description="暂无更新日志" :image-size="60" />
        </div>
      </div>
      <template #footer>
        <div style="display: flex; align-items: center;">
          <LogStorageBar log-key="threat_update" style="margin-right: auto" />
          <el-button @click="threatUpdateDialogVisible = false">关闭</el-button>
          <el-button v-if="!threatUpdateRunning" type="primary" :disabled="isReadOnly || isSlaveNode" :loading="startingThreatUpdate" @click="confirmThreatUpdate">立即更新</el-button>
        </div>
      </template>
    </el-dialog>

    <el-dialog
      v-model="crawlerUpdateDialogVisible"
      width="min(900px, 94vw)"
      top="8vh"
      destroy-on-close
      @opened="onCrawlerUpdateDialogOpened"
      @closed="onCrawlerUpdateDialogClosed"
    >
      <template #header>
        <DialogHeader :icon="Link" title="爬虫地址更新" subtitle="四个官方爬虫 IP 源的更新任务与更新日志" tone-class="lib-icon--crawler" />
      </template>
      <DialogSectionHeader title="爬虫地址来源" />
      <div class="dialog-panel dialog-panel--flush library-sources-panel">
        <el-table :data="crawlerSources" size="small" class="threat-source-table">
        <el-table-column label="来源" min-width="260">
          <template #default="{ row }">
            <div class="lib-name-text">
              <div class="lib-name-main">{{ row.display_name }}</div>
              <div class="lib-name-sub threat-source-url">{{ row.url }}</div>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="条目数" width="100" align="right">
          <template #default="{ row }">{{ row.entry_count ? row.entry_count.toLocaleString() : '—' }}</template>
        </el-table-column>
        <el-table-column label="版本" width="110">
          <template #default="{ row }"><span class="lib-version">{{ row.version || '未更新' }}</span></template>
        </el-table-column>
        <el-table-column label="状态" width="110">
          <template #default="{ row }">
            <el-tag v-if="!row.update_enabled" type="info" size="small" effect="light">已关闭</el-tag>
            <el-tag v-else :type="libraryStatusTagType(row.update_status)" size="small" effect="light">{{ libraryStatusLabel(row.update_status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="自动更新" width="90" align="center">
          <template #default="{ row }">
            <el-switch v-model="row.update_enabled" :loading="sourceFlagPending('crawler', row.id)" :disabled="isReadOnly || isSlaveNode || sourceFlagPending('crawler', row.id)" @change="(v: string | number | boolean) => toggleCrawlerFlag(row as ThreatSource, v === true)" />
          </template>
        </el-table-column>
        </el-table>
      </div>
      <RuleLibScheduleEditor
        :days="crawlerSchedule.days"
        :time="crawlerSchedule.time"
        :disabled="isReadOnly || isSlaveNode"
        :unavailable-hint="crawlerScheduleHint"
        :saving="savingCrawlerSchedule"
        :tz="scheduleTz"
        @save="saveCrawlerSchedule"
      />
      <DialogSectionHeader title="更新日志" />
      <div class="dialog-panel dialog-panel--flush">
        <div ref="crawlerUpdateLogRef" class="update-log-container update-log-container--compact">
          <pre v-if="crawlerUpdateLog" class="update-log-content">{{ crawlerUpdateLog }}</pre>
          <el-empty v-else description="暂无更新日志" :image-size="60" />
        </div>
      </div>
      <template #footer>
        <div style="display: flex; align-items: center;">
          <LogStorageBar log-key="crawlerbot_update" style="margin-right: auto" />
          <el-button @click="crawlerUpdateDialogVisible = false">关闭</el-button>
          <el-button v-if="!crawlerUpdateRunning" type="primary" :disabled="isReadOnly || isSlaveNode" :loading="startingCrawlerUpdate" @click="confirmCrawlerUpdate">立即更新</el-button>
        </div>
      </template>
    </el-dialog>

  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed, watch } from 'vue'
import { Aim, Filter, List, Location, Lock, Search, Notebook, Plus, WarningFilled, Link, InfoFilled } from '@element-plus/icons-vue'
import LogStorageBar from '@/components/LogStorageBar.vue'
import { formatDate } from '@/utils/date'
import { autobanEntryExpired, autobanEntryRemaining } from '@/utils/autobanEntry'
import { IP_LIST_CATEGORIES, invalidateSharedEntriesCache } from '@/utils/securityStages'
import { crsRuleCountLabel, libraryHealthTag, librarySourceHealthTag, libraryStatusLabel, libraryStatusTagType, summarizeLibrarySources } from '@/utils/securityLibraries'
import { updaterName } from '@/utils/updaterName'
import { hasOwn } from '@/utils/hasOwn'
import { SECURITY_DESCRIPTION_MAX_RUNES, SECURITY_NAME_MAX_RUNES } from '@/utils/securityLimits'
import { DEEP_LINK_PARAMS } from '@/utils/deepLink'
import SyntaxHighlight from '@/components/SyntaxHighlight.vue'
import RuleLibScheduleEditor from '@/components/RuleLibScheduleEditor.vue'
import DialogHeader from '@/components/DialogHeader.vue'
import DialogSectionHeader from '@/components/DialogSectionHeader.vue'
import AccessibleLink from '@/components/common/AccessibleLink.vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { request, mfaAwareSuccess } from '@/utils/api'
import { formatBytes } from '@/utils/formatBytes'
import { showSaveResult } from '@/utils/saveResult'
import { isValidCidr } from '@/utils/ruleValidation'
import { IP_LIST_MAX_ENTRIES, canSaveIpList, mergeConcurrentBanEntries, needsEmptyListConfirm } from '@/utils/ipListSaveGuard'
import { CUSTOM_RULE_MAX_CONDITIONS, CUSTOM_RULE_MAX_PATTERN_BYTES, canAddCondition, patternByteLength, patternOverLimit } from '@/utils/customRuleLimits'
import { formatIpListEntryLine, ipListRemarkMaxLength, parseIpListEntryLine } from '@/utils/ipListCsv'
import { popperViewportSafe } from '@/utils/popper'
import { activateOnce } from '@/utils/keyboardActivate'
import { useAuthStore } from '@/stores/auth'

import { useClampedPagination } from '@/composables/useClampedPagination'
import { useLibUpdateDialog } from '@/composables/useLibUpdateDialog'
import { createVisibilityIntervals } from '@/composables/useVisibilityIntervals'
import type { APIResponse, UserListItem } from '@/types'
// —— 威胁情报库（v2.3.x 第二张规则来源卡）——
interface ThreatSource {
  id: number; name: string; display_name: string; url: string; format: string
  update_enabled: boolean
  entry_count: number; version: string; update_status: string; message: string
  last_checked: string; next_update: string; list_id: number
}
const threatSources = ref<ThreatSource[]>([])
const threatAutoUpdate = ref(true)
const threatSchedule = ref({ days: [1, 2, 3, 4, 5, 6, 7] as number[], time: '04:00' })

const fetchThreatLib = async () => {
  const seq = ++threatLibInfoSeq
  try {
    // 回刷由 60s 定时与操作后补拉触发：失败态已由健康标签/排程提示承载，
    // 不再每次失败都弹全局 toast（后端抖动期每分钟四条）。
    const res = await request.get<APIResponse<{ sources: ThreatSource[]; total_entries: number; auto_update?: boolean; schedule_days?: number[]; schedule_time?: string }>>('/security/threat-lib', { silent: true })
    if (seq !== threatLibInfoSeq) return
    if (res.data) {
      threatSources.value = res.data.sources
      threatAutoUpdate.value = res.data.auto_update !== false
      if (res.data.schedule_days?.length) threatSchedule.value = { days: res.data.schedule_days, time: res.data.schedule_time || '04:00' }
    }
    threatLibError.value = false
    threatLibLoaded.value = true
  } catch {
    if (seq !== threatLibInfoSeq) return
    // 只读拉取失败：不打断页面，但健康标签必须显性为「加载失败」
    threatLibError.value = true
    threatLibLoaded.value = true
  }
}

type SourceFlagLibrary = 'threat' | 'crawler'
const sourceFlagSaving = ref(new Set<string>())
const sourceFlagRequestSeq = new Map<string, number>()
const sourceFlagKey = (library: SourceFlagLibrary, id: number): string => `${library}:${id}`
const sourceFlagPending = (library: SourceFlagLibrary, id: number): boolean => sourceFlagSaving.value.has(sourceFlagKey(library, id))

// 同一来源只允许一个在途写；序号保证过期失败不会回滚后续选择。
// 回拉也留在占位期内，避免旧详情响应覆盖下一次乐观置值。
const toggleSourceFlag = async (
  library: SourceFlagLibrary,
  row: ThreatSource,
  val: boolean,
  refresh: () => Promise<void>,
): Promise<void> => {
  const key = sourceFlagKey(library, row.id)
  if (sourceFlagSaving.value.has(key)) return
  if (!val) {
    try {
      await ElMessageBox.confirm(`将停止来源「${row.display_name || row.name}」的自动更新，已下载条目保留但不再自动更新。确认关闭？`, '关闭自动更新', {
        type: 'warning', confirmButtonText: '确认关闭', cancelButtonText: '取消',
      })
    } catch { row.update_enabled = !val; return }
  }
  const requestSeq = (sourceFlagRequestSeq.get(key) ?? 0) + 1
  sourceFlagRequestSeq.set(key, requestSeq)
  sourceFlagSaving.value.add(key)
  try {
    try {
      await request.put(`/security/${library}-lib/${row.id}/flags`, { update_enabled: val })
      mfaAwareSuccess('已更新')
    } catch {
      if (sourceFlagRequestSeq.get(key) === requestSeq) row.update_enabled = !val
    }
    await refresh()
  } finally {
    if (sourceFlagRequestSeq.get(key) === requestSeq) sourceFlagSaving.value.delete(key)
  }
}

const toggleThreatFlag = async (row: ThreatSource, val: boolean): Promise<void> => {
  await toggleSourceFlag('threat', row, val, fetchThreatLib)
}

// —— 爬虫地址库（独立源表/总闸/排程/日志，与威胁情报库完全分离）——
type CrawlerSource = ThreatSource
const crawlerSources = ref<CrawlerSource[]>([])
const crawlerAutoUpdate = ref(true)
const crawlerSchedule = ref({ days: [1, 2, 3, 4, 5, 6, 7] as number[], time: '04:00' })

const fetchCrawlerLib = async () => {
  const seq = ++crawlerLibInfoSeq
  try {
    const res = await request.get<APIResponse<{ sources: CrawlerSource[]; total_entries: number; auto_update?: boolean; schedule_days?: number[]; schedule_time?: string }>>('/security/crawler-lib', { silent: true })
    if (seq !== crawlerLibInfoSeq) return
    if (res.data) {
      crawlerSources.value = res.data.sources
      crawlerAutoUpdate.value = res.data.auto_update !== false
      if (res.data.schedule_days?.length) crawlerSchedule.value = { days: res.data.schedule_days, time: res.data.schedule_time || '04:00' }
    }
    crawlerLibError.value = false
    crawlerLibLoaded.value = true
  } catch {
    if (seq !== crawlerLibInfoSeq) return
    crawlerLibError.value = true
    crawlerLibLoaded.value = true
  }
}

const toggleCrawlerFlag = async (row: CrawlerSource, val: boolean): Promise<void> => {
  await toggleSourceFlag('crawler', row, val, fetchCrawlerLib)
}

// —— 规则库统一表（v2.3.2）：CRS/IP2Region/威胁三源五行同一口径 ——
interface LibRow {
  key: string
  icon: typeof Lock
  iconClass: string
  name: string
  sub: string
  version: string
  count: string
  status: string
  autoUpdate: boolean
  // 读取失败/首次响应未落地时 autoUpdate 是本地默认值而非库值——
  // 开关必须显示「未知」并禁用，不得冒充「已开启」。
  autoUpdateKnown: boolean
  lastChecked: string
  nextUpdate: string
}

const libRows = computed<LibRow[]>(() => {
  const rows: LibRow[] = [
    {
      key: 'crs', icon: Lock, iconClass: 'lib-icon--crs', name: 'CRS 规则库', sub: 'OWASP Core Rule Set',
      // 读取失败时版本/条目显示 —（行保留，不冒充默认值）
      version: crsInfoError.value ? '—' : crsInfo.value.available === false ? '未安装' : (crsInfo.value.version || '—'),  // 缺失态文案与 IP 库统一「未安装」（2026-09-24 用户裁定）
      // 库容量=GET /security/crs 的 rule_count（服务端全量）；分页 total 只反映
      // 当前搜索条件下的结果集，二者不可共用。
      // rule_count 是 SecRule 指令条数（后端 countSecRules 只数 SecRule 行），
      // 不是文件数——文案必须是「条规则」（单源 crsRuleCountLabel，有行为测试）。
      count: crsInfoError.value ? '—' : crsRuleCountLabel(crsInfo.value.rule_count),
      autoUpdateKnown: !crsInfoError.value && crsInfoLoaded.value,
      status: crsInfoError.value ? 'failed' : crsInfo.value.available === false ? 'missing' : crsInfo.value.update_status,
      autoUpdate: crsInfo.value.auto_update,
      lastChecked: formatDate(crsInfo.value.last_checked) || '—',
      nextUpdate: formatDate(crsInfo.value.next_update) || '—',
    },
    {
      key: 'ip2region', icon: Location, iconClass: 'lib-icon--ip', name: 'IP 地理库', sub: 'IP 地理归属数据库',
      version: ip2regionInfoError.value ? '—' : ip2regionInfo.value.available === false ? '未安装' : ip2regionVersionLabel.value,
      // db_size 是库文件字节数——必须带单位（B/KB/MB）呈现，不得让
      // 用户把字节数读成条目数（条目口径见「数量/大小」列名的「大小」段）。
      count: !ip2regionInfoError.value && ip2regionInfo.value.db_size && ip2regionInfo.value.version && ip2regionInfo.value.version !== 'unknown' ? formatSize(ip2regionInfo.value.db_size) : '—',
      autoUpdateKnown: !ip2regionInfoError.value && ip2regionInfoLoaded.value,
      status: ip2regionInfoError.value ? 'failed' : ip2regionInfo.value.available === false ? 'missing' : ip2regionStatusForTag.value,
      autoUpdate: ip2regionInfo.value.auto_update,
      lastChecked: formatDate(ip2regionInfo.value.last_checked) || '—',
      nextUpdate: formatDate(ip2regionInfo.value.next_update) || '—',
    },
  ]
  // 威胁情报库与爬虫地址库共用「多源聚合成一行」单源
  // 与安全总览同一实现（utils/securityLibraries），空源/无版本为 never（未更新），
  // 不再折叠为 idle「已最新」。
  // 零源也出占位行（状态「未配置」）：卡头健康标签已显示未配置，缺行会让用户
  // 找不到该库的更新详情/排程入口（行消失=入口消失）。首次响应未落地前不出行。
  const summarize = (srcs: ThreatSource[]) => summarizeLibrarySources(srcs, formatDate)
  if (threatLibError.value || threatLibLoaded.value) {
    const configured = threatSources.value.length > 0
    const summary = threatLibError.value
      ? { totalEntries: 0, latestVersion: '', status: 'failed', lastChecked: '—', nextUpdate: '—' }
      : summarize(threatSources.value)
    rows.push({
      key: 'threat', icon: Aim, iconClass: 'lib-icon--threat',
      name: '威胁情报库',
      sub: 'IP 威胁名单，可被黑名单策略引用',
      version: configured ? (summary.latestVersion || '未更新') : '—',
      count: configured && summary.totalEntries > 0 ? summary.totalEntries.toLocaleString() + ' 条' : '—',
      status: threatLibError.value ? 'failed' : configured ? summary.status : 'not-configured',
      autoUpdate: threatAutoUpdate.value,
      autoUpdateKnown: threatLibLoaded.value && !threatLibError.value,
      lastChecked: configured ? summary.lastChecked : '—',
      nextUpdate: configured ? summary.nextUpdate : '—',
    })
  }
  if (crawlerLibError.value || crawlerLibLoaded.value) {
    const configured = crawlerSources.value.length > 0
    const summary = crawlerLibError.value
      ? { totalEntries: 0, latestVersion: '', status: 'failed', lastChecked: '—', nextUpdate: '—' }
      : summarize(crawlerSources.value)
    rows.push({
      key: 'crawler', icon: Link, iconClass: 'lib-icon--crawler',
      name: '爬虫地址库',
      sub: 'Google/OpenAI/Bing/360 官方爬虫 IP 段',
      version: configured ? (summary.latestVersion || '未更新') : '—',
      count: configured && summary.totalEntries > 0 ? summary.totalEntries.toLocaleString() + ' 条' : '—',
      status: crawlerLibError.value ? 'failed' : configured ? summary.status : 'not-configured',
      autoUpdate: crawlerAutoUpdate.value,
      autoUpdateKnown: crawlerLibLoaded.value && !crawlerLibError.value,
      lastChecked: configured ? summary.lastChecked : '—',
      nextUpdate: configured ? summary.nextUpdate : '—',
    })
  }
  return rows
})

// 卡头库健康标签组（2026-09-24 用户裁定）：逐库彩色标签，异常 danger/
// 正常 success；缺库（后端渲染层已停用全部安全规则，见
// SecurityLibrariesAvailable）时模板追加红色警示后缀。
const libHealthTags = computed(() => [
  // 健康标签单源（utils/securityLibraries）——IP 库未安装时
  // 显示「未安装」警示，不再与版本列「未安装」/状态列「已最新」互相矛盾。
  libraryHealthTag('CRS 规则库', {
    // 首次响应未落地不得冒充「正常」——loaded 三态
    loaded: crsInfoLoaded.value,
    loadError: crsInfoError.value,
    available: crsInfo.value.available,
    status: crsInfoError.value ? 'failed' : crsInfo.value.update_status,
  }),
  libraryHealthTag('IP 地理库', {
    loaded: ip2regionInfoLoaded.value,
    loadError: ip2regionInfoError.value,
    available: ip2regionInfo.value.available,
    status: ip2regionInfoError.value ? 'failed' : ip2regionStatusForTag.value,
  }),
  librarySourceHealthTag('威胁情报库', threatSources.value, threatLibError.value, threatLibLoaded.value),
  librarySourceHealthTag('爬虫地址库', crawlerSources.value, crawlerLibError.value, crawlerLibLoaded.value),
])
const libSummaryWarn = computed(() => crsInfo.value.available === false || ip2regionInfo.value.available === false)

// 自动更新开关：按行分发到四个库的既有端点。统一乐观置值 + 在途标记
// （此前威胁/爬虫要等响应才置值，点击后开关纹丝不动，用户会重复点击）。
const autoUpdateSaving = ref(new Set<string>())
const applyLibAutoUpdate = async (key: string, val: boolean): Promise<void> => {
  if (key === 'crs') await request.put('/security/crs/auto-update', { auto_update: val })
  else if (key === 'ip2region') await request.put('/security/ip2region/auto-update', { auto_update: val })
  else if (key === 'threat') await request.put('/security/threat-lib/auto-update', { auto_update: val })
  else if (key === 'crawler') await request.put('/security/crawler-lib/auto-update', { auto_update: val })
}
const toggleLibAutoUpdate = async (row: LibRow, val: boolean): Promise<void> => {
  if (autoUpdateSaving.value.has(row.key)) return
  if (!val) {
    try {
      await ElMessageBox.confirm(`将停止「${row.name}」的自动更新，当前版本保留但不再自动更新。确认关闭？`, '关闭自动更新', {
        type: 'warning', confirmButtonText: '确认关闭', cancelButtonText: '取消',
      })
    } catch { return }
  }
  autoUpdateSaving.value.add(row.key)
  const previous = row.autoUpdate
  setLibAutoUpdateShown(row.key, val)
  try {
    await applyLibAutoUpdate(row.key, val)
    mfaAwareSuccess('已更新')
  } catch {
    // 失败回滚显示值（服务端为准；各库 fetch 亦会回填）
    setLibAutoUpdateShown(row.key, previous)
  } finally {
    autoUpdateSaving.value.delete(row.key)
  }
}
const setLibAutoUpdateShown = (key: string, val: boolean): void => {
  if (key === 'crs') crsInfo.value.auto_update = val
  else if (key === 'ip2region') ip2regionInfo.value.auto_update = val
  else if (key === 'threat') threatAutoUpdate.value = val
  else if (key === 'crawler') crawlerAutoUpdate.value = val
}

// 更新/日志按钮：打开对应库的更新弹框（autoStart=false 时仅查看日志）。
const openLibDialog = (row: LibRow) => {
  if (row.key === 'crs') {
    manualUpdate()
  } else if (row.key === 'ip2region') {
    manualIP2RegionUpdate()
  } else if (row.key === 'threat') {
    threatDialog.open()
  } else if (row.key === 'crawler') {
    crawlerDialog.open()
  }
}


// 威胁库更新弹框（useLibUpdateDialog 统一范式，；状态/日志拉取失败静默，与原实现一致）——
const threatUpdateLogRef = ref<HTMLDivElement | null>(null)
const threatDialog = useLibUpdateDialog<ThreatUpdateInfo>({
  apiPrefix: '/security/threat-lib',
  logContainer: threatUpdateLogRef,
  isRunning: (info) => info?.running === true,
  isFinished: (info) => info.running !== true,
  isSuccess: (info) => info.outcome === 'success',
  onSuccess: fetchThreatLib,
  onOpen: () => { ensureScheduleTz() },
})
const {
  visible: threatUpdateDialogVisible,
  logs: threatUpdateLog,
  updating: threatUpdateRunning,
  starting: startingThreatUpdate,
  onOpened: onThreatUpdateDialogOpened,
  onClosed: onThreatUpdateDialogClosed,
  confirmUpdate: confirmThreatUpdate,
} = threatDialog

// —— 爬虫地址库独立更新弹框（同一 composable，独立状态/日志/轮询会话）——
const crawlerUpdateLogRef = ref<HTMLDivElement | null>(null)
const crawlerDialog = useLibUpdateDialog<ThreatUpdateInfo>({
  apiPrefix: '/security/crawler-lib',
  logContainer: crawlerUpdateLogRef,
  isRunning: (info) => info?.running === true,
  isFinished: (info) => info.running !== true,
  isSuccess: (info) => info.outcome === 'success',
  onSuccess: fetchCrawlerLib,
  onOpen: () => { ensureScheduleTz() },
})
const {
  visible: crawlerUpdateDialogVisible,
  logs: crawlerUpdateLog,
  updating: crawlerUpdateRunning,
  starting: startingCrawlerUpdate,
  onOpened: onCrawlerUpdateDialogOpened,
  onClosed: onCrawlerUpdateDialogClosed,
  confirmUpdate: confirmCrawlerUpdate,
} = crawlerDialog
interface CRSRuleFile { filename: string; category: string; size: number; updated_at: string }
interface CustomRuleCondition { target: string; operator: string; pattern: string }
interface CustomRule { id: number; name: string; description: string; conditions: CustomRuleCondition[]; condition_logic: 'and' | 'or'; action: string; score: number; enabled: boolean; updated_at: string; updated_by: number }
// 自动封禁名单条目携带加入时间/到期时间（UTC 墙钟串，formatDate 消费）
interface IPListEntry { value: string; remark: string; created_at?: string; expires_at?: string }
// enabled=引用策略的启用态：禁用策略的引用只作展示（不阻止删除，409 门只计启用）
interface IPListRefPolicy { id: number; name: string; enabled: boolean }
interface IPListRow { id: number; name: string; description: string; category: string; entries: IPListEntry[]; entry_count: number; ref_count: number; ref_count_enabled?: number; ref_policies: IPListRefPolicy[]; trusted_proxy_referenced?: boolean; trusted_proxy_scope?: string; created_by: number; created_at: string; updated_by: number; updated_at: string; system: boolean; preset_autoban?: boolean }
interface CRSUpdateInfo { readonly status: string; readonly trigger: string; readonly started_at: string; readonly finished_at: string; readonly message: string; readonly version: string }
interface IP2RegionUpdateInfo { readonly status: string; readonly trigger: string; readonly started_at: string; readonly finished_at: string; readonly message: string; readonly version: string }
interface ThreatUpdateInfo { running: boolean; trigger: string; started_at: string; finished_at: string; outcome: string }

const authStore = useAuthStore()
const isSlaveNode = computed(() => authStore.isSlaveNode)
const isReadOnly = computed(() => authStore.readOnlyReason !== null)

const users = ref<UserListItem[]>([])
// 更新者显示名走 utils/updaterName 单源
const getUpdaterName = (userId?: number) => updaterName(users.value, userId)

const crsInfo = ref({ version: '', auto_update: true, updated_at: '', last_checked: '', next_update: '', update_status: '', message: '', available: true, rule_count: 0, schedule_days: [1, 2, 3, 4, 5, 6, 7] as number[], schedule_time: '04:00' })

const ip2regionInfo = ref({ version: '', db_size: 0, auto_update: true, updated_at: '', last_checked: '', next_update: '', update_status: '', message: '', available: true, schedule_days: [1, 2, 3, 4, 5, 6, 7] as number[], schedule_time: '04:00' })
// 读取失败标记：读取失败≠库缺失，更≠正常——标签与表格行都要显性
// 表达「加载失败」，不能用默认值（available:true/空源列表）冒充正常态。
const crsInfoError = ref(false)
const ip2regionInfoError = ref(false)
const threatLibError = ref(false)
const crawlerLibError = ref(false)
// 加载三态——首次响应落地（成功或失败）前健康标签显示「加载中」，
// 初值 available:true/空源列表不得冒充「正常」。
const crsInfoLoaded = ref(false)
const ip2regionInfoLoaded = ref(false)
const threatLibLoaded = ref(false)
const crawlerLibLoaded = ref(false)
// 四库信息回刷的请求序号（按库各自一条）：60s 定时回刷与用户操作后的补拉会
// 并发，响应乱序落地会把新版本/新排程覆盖回旧值。每库只允许最新一代写回。
let crsInfoSeq = 0
let ip2regionInfoSeq = 0
let threatLibInfoSeq = 0
let crawlerLibInfoSeq = 0
// 库信息未落地/读取失败时排程未知：编辑器禁用并显性提示，
// 不得用默认值（周一–周日 04:00）冒充库内排程被保存覆盖。
const SCHEDULE_UNKNOWN_HINT = '排程未知：库信息读取失败，请关闭后重新加载'
const crsScheduleHint = computed(() => (!crsInfoLoaded.value || crsInfoError.value) ? SCHEDULE_UNKNOWN_HINT : '')
const ip2regionScheduleHint = computed(() => (!ip2regionInfoLoaded.value || ip2regionInfoError.value) ? SCHEDULE_UNKNOWN_HINT : '')
const threatScheduleHint = computed(() => (!threatLibLoaded.value || threatLibError.value) ? SCHEDULE_UNKNOWN_HINT : '')
const crawlerScheduleHint = computed(() => (!crawlerLibLoaded.value || crawlerLibError.value) ? SCHEDULE_UNKNOWN_HINT : '')
const ip2regionVersionLabel = computed(() => {
  if (ip2regionInfo.value.version === 'bundled') return '内置版本（未更新）'
  return (ip2regionInfo.value.version && ip2regionInfo.value.version !== 'unknown') ? ip2regionInfo.value.version : '未安装'
})// unknown/空版本统一显示「未安装」（灰），结构上与正常态同一 tag 元素。
const ip2regionStatusForTag = computed(() => {
  const v = ip2regionInfo.value.version
  if (!v || v === 'unknown') return 'not-installed'
  return ip2regionInfo.value.update_status
})

const activeTab = ref('rules')
const loadingRules = ref(false)
const rules = ref<CRSRuleFile[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = ref(10)
const searchQuery = ref('')
const contentDialogVisible = ref(false)
const loadingContent = ref(false)
const currentFilename = ref('')
const currentContent = ref('')

const customRules = ref<CustomRule[]>([])
// 列表加载失败显性化（原空 catch，失败与「暂无自定义规则」不可区分）
const customRulesError = ref(false)
const customPage = ref(1)
const customPageSize = ref(10)
// 分页夹紧+切片：useClampedPagination 单一范式——删除末页
// 末条后自动回夹，不再空页。
const { pagedItems: customRulesPaged } = useClampedPagination(customRules, customPage, customPageSize)
const loadingCustom = ref(false)
const ruleDialogVisible = ref(false)
const editingRuleId = ref<number | null>(null)
const savingRule = ref(false)
const ruleForm = ref({ name: '', description: '', conditions: [] as CustomRuleCondition[], condition_logic: 'and' as 'and' | 'or', action: 'block', score: 5, enabled: true })

const CUSTOM_ACTION_VIEWS: Record<string, { label: string; type: 'danger' | 'info' | 'warning' }> = {
  block: { label: '拦截', type: 'danger' },
  log: { label: '仅记录', type: 'info' },
  pass: { label: '放行计分', type: 'warning' },
}
// 自定义规则动作三态视图：block=拦截 / log=仅记录 / pass=放行计分，
// 与编辑器 radio 及后端发射语义（pass 累加异常分、log 不累分）一一对应；
// 未知动作兜底原样展示（info），不与任何已知语义混淆。查表过 hasOwn：
// action 来自库值，命中原型键时裸下标会把 Object.prototype 上的函数当标签渲染。
const customActionView = (action: string): { label: string; type: 'danger' | 'info' | 'warning' } =>
  (hasOwn(CUSTOM_ACTION_VIEWS, action) ? CUSTOM_ACTION_VIEWS[action] : { label: action || '—', type: 'info' })

// —— 可复用 IP 地址列表（第三个标签页）——
// 分类预设：与安全策略「提取为列表」共用同一组选项

const ipLists = ref<IPListRow[]>([])
const loadingIpLists = ref(false)
const ipListSearch = ref('')
const ipListPage = ref(1)
const ipListPageSize = ref(10)
const ipListsFiltered = computed(() => {
  const query = ipListSearch.value.trim().toLowerCase()
  if (!query) return ipLists.value
  return ipLists.value.filter((l) => l.name.toLowerCase().includes(query) || (l.category || '').toLowerCase().includes(query))
})
// IP 地址列表同款：删除末页末条后自动回夹——此前仅搜索有
// 复位 watch，删除路径无收敛，越界 slice 返回空数组呈空白表格。
const { pagedItems: ipListsPaged } = useClampedPagination(ipListsFiltered, ipListPage, ipListPageSize)
// 搜索收窄后高页码会落在空页，回到第 1 页
watch(ipListSearch, () => { ipListPage.value = 1 })
const ipListDialogVisible = ref(false)
// 内置名单（威胁情报库 system=1）弹框恒只读（管理员同）——内容只读查看/导出。
// 例外：自动封禁预置名单条目可改（手动封禁/删除条目——删除即解封，
// 2026-10-15 用户裁定：无抑制窗口，IP 重新达标会被再次封禁）。
const editingIpListPreset = ref(false)
const ipListDialogReadOnly = computed(() => isReadOnly.value || (editingIpListSystem.value && !editingIpListPreset.value))
const editingIpListId = ref<number | null>(null)
const savingIpList = ref(false)
// 打开弹框时服务端已有的条目值快照：保存前的最终复核据此区分「任务并发新增」
// 与「用户在弹框里主动删除」——前者必须保留（否则提前解封），后者按用户意图移除。
const ipListOpenSnapshot = ref<string[]>([])
const ipListForm = ref<{ name: string; description: string; category: string; entries: IPListEntry[] }>({ name: '', description: '', category: '', entries: [] })

const ipListsError = ref(false)
const fetchIpLists = async () => {
  loadingIpLists.value = true
  try {
    const res = await request.get<APIResponse<IPListRow[]>>('/security/ip-lists')
    ipLists.value = res.data || []
    ipListsError.value = false
  } catch {
    ipListsError.value = true
  } finally { loadingIpLists.value = false }
}
const retryIpLists = (): void => { void fetchIpLists() }

const editingIpListSystem = ref(false)
const loadingIpListDetail = ref(false)
// 详情加载失败：entries 为空且保存可用 → 全量 PUT 会清空名单
const ipListDetailFailed = ref(false)
const ipListDetailRowId = ref<number | null>(null)
const ipListEntryPage = ref(1)
const ipListEntryPageSize = 200
const ipListEntryPageStart = computed(() => (ipListEntryPage.value - 1) * ipListEntryPageSize)
// 分页只切窗口（slice 共享底层数组引用——编辑直接写回 ipListForm.entries，
// 跨页修改随保存整体提交）；只读形态纯文本渲染，万级条目不再实例化 input。
const ipListEntriesPaged = computed(() =>
  ipListForm.value.entries.slice(ipListEntryPageStart.value, ipListEntryPageStart.value + ipListEntryPageSize))

const addIpListEntry = (): void => {
  ipListForm.value.entries.push({ value: '', remark: '' })
  ipListEntryPage.value = Math.ceil(ipListForm.value.entries.length / ipListEntryPageSize)
}

// 删除末页末条后页码越界会落在空页（空白表格）——splice 后回夹最大页

//（同 useClampedPagination 的 maxPage 夹紧口径，entries 切片另有共享数组注释见上）
const removeIpListEntry = (index: number): void => {
  ipListForm.value.entries.splice(index, 1)
  const maxPage = Math.max(1, Math.ceil(ipListForm.value.entries.length / ipListEntryPageSize))
  if (ipListEntryPage.value > maxPage) ipListEntryPage.value = maxPage
}

// 自动封禁名单弹框的到期展示 ——

// 到期判定/剩余时长口径单源 utils/autobanEntry（与 IP 快捷处置弹框共用）。


// 乱序响应守卫（镜像同文件 openRuleContent 的 ruleContentSeq 范式）——
// 快速关开/切换名单时在途详情响应晚到，不再覆盖当前弹框（含「新建」空表单被
// 旧名单条目覆盖的形态）
let ipListDetailSeq = 0
const openIpListDialog = async (row?: IPListRow) => {
  const requestSeq = ++ipListDetailSeq
  editingIpListSystem.value = row?.system === true
  editingIpListPreset.value = row?.preset_autoban === true
  ipListEntryPage.value = 1
  editingIpListId.value = row?.id ?? null
  if (!row) {
    // seq 已自增：在途详情响应作废且其 finally 不再清 loading——新建表单自身
    // 复位，否则继承上一会话的 v-loading 转圈
    loadingIpListDetail.value = false
    ipListDetailFailed.value = false
    ipListDetailRowId.value = null
    ipListForm.value = { name: '', description: '', category: '', entries: [{ value: '', remark: '' }] }
    ipListOpenSnapshot.value = []
    ipListDialogVisible.value = true
    return
  }
  // 列表载荷不再内联 entries（大名单瘦身）——弹框按需拉详情。
  ipListForm.value = { name: row.name, description: row.description, category: row.category, entries: [] }
  ipListDetailRowId.value = row.id
  ipListDetailFailed.value = false
  ipListDialogVisible.value = true
  loadingIpListDetail.value = true
  try {
    // 全局拦截器已 toast——本请求 silent，失败提示只用本地那条带
    // 「已禁用保存」动作信息的文案（否则同一次失败弹两条 error）。
    const res = await request.get<APIResponse<IPListRow>>(`/security/ip-lists/${row.id}`, { silent: true })
    if (requestSeq !== ipListDetailSeq) return
    if (res.data && ipListDialogVisible.value) {
      // 自动封禁名单条目保留 created_at/expires_at（保存随全量写回，
      // 任务 merge 的到期语义与弹框到期列依赖这两字段）
      ipListForm.value.entries = (res.data.entries || []).map((e) => ({ value: e.value, remark: e.remark, created_at: e.created_at, expires_at: e.expires_at }))
      ipListOpenSnapshot.value = ipListForm.value.entries.map((e) => e.value)
    }
  } catch {
    if (requestSeq !== ipListDetailSeq) return
    // 失败态显性化并禁用保存：空 entries 下保存=全量清空名单
    ipListDetailFailed.value = true
    ElMessage.error('加载列表条目失败，已禁用保存；请重新加载')
  } finally {
    if (requestSeq === ipListDetailSeq) loadingIpListDetail.value = false
  }
}

/** 详情重试（仅重拉条目，不回填名称/分类等已在表单中的字段）。 */
const reloadIpListDetail = async (): Promise<void> => {
  const id = ipListDetailRowId.value
  if (id == null) return
  // 重试会用服务端条目整表替换：已有未保存条目（含加载成功后又失败、用户继续
  // 补录的形态）必须先确认，不得静默丢弃。
  if (ipListForm.value.entries.length > 0) {
    try {
      await ElMessageBox.confirm(
        `重新加载将用服务端条目覆盖当前 ${ipListForm.value.entries.length} 条（含未保存的新增/编辑），确定继续？`,
        '重新加载确认',
        { type: 'warning', confirmButtonText: '重新加载', cancelButtonText: '取消' },
      )
    } catch { return }
  }
  const requestSeq = ++ipListDetailSeq
  loadingIpListDetail.value = true
  try {
    // 同 openIpListDialog——silent + 本地文案，避免双 toast。
    const res = await request.get<APIResponse<IPListRow>>(`/security/ip-lists/${id}`, { silent: true })
    if (requestSeq !== ipListDetailSeq) return
    ipListForm.value.entries = (res.data?.entries || []).map((e) => ({ value: e.value, remark: e.remark, created_at: e.created_at, expires_at: e.expires_at }))
    ipListOpenSnapshot.value = ipListForm.value.entries.map((e) => e.value)
    ipListDetailFailed.value = false
    ipListEntryPage.value = 1
    ElMessage.success('已加载最新条目')
  } catch {
    if (requestSeq !== ipListDetailSeq) return
    ipListDetailFailed.value = true
    ElMessage.error('加载列表条目失败，请稍后重试')
  } finally {
    if (requestSeq === ipListDetailSeq) loadingIpListDetail.value = false
  }
}

/**
 * 内置名单保存前的最终复核（保存流程里最后一个异步步骤，紧邻 PUT）：
 * 重取详情，把「打开弹框后由任务新增、本次载荷又没有」的封禁条目原样并入载荷。
 *
 * 旧实现的差集发生在最后一次确认框之前——用户在该确认框停留期间新封禁的 IP 仍会
 * 被整表替换掉（提前解封），故差集必须落到确认之后。无法核对时中止保存
 * （fail-closed：不能拿未知状态做全表覆盖）。打开快照里的条目不计入「并发新增」，
 * 用户主动删除的封禁仍可移除。
 */
const mergeFreshAutobanEntries = async (id: number, entries: IPListEntry[]): Promise<IPListEntry[] | null> => {
  let serverEntries: IPListEntry[] = []
  try {
    const res = await request.get<APIResponse<IPListRow>>(`/security/ip-lists/${id}`, { silent: true })
    serverEntries = res.data?.entries || []
  } catch {
    ElMessage.error('无法核对最新封禁条目，已中止保存（避免解封刚封禁的 IP）；请稍后重试')
    return null
  }
  const merged = mergeConcurrentBanEntries(serverEntries, entries, ipListOpenSnapshot.value)
  if (merged.preserved.length > 0) {
    const preview = merged.preserved.slice(0, 5).join('、') + (merged.preserved.length > 5 ? ' 等' : '')
    ElMessage.warning(`保存期间新增的 ${merged.preserved.length} 条封禁条目已保留（${preview}），不会随本次保存移除`)
  }
  return merged.entries
}

const saveIpList = async () => {
  if (savingIpList.value) return
  const name = ipListForm.value.name.trim()
  if (!name) { ElMessage.warning('请输入列表名称'); return }
  if (name.length > 50) { ElMessage.warning('列表名称不能超过 50 字符'); return }
  if (ipListForm.value.category.length > 32) { ElMessage.warning('分类不能超过 32 字符'); return }
  if (ipListForm.value.description.length > 200) { ElMessage.warning('描述不能超过 200 字符'); return }
  // 值与备注均为空的行视为未填写的占位行，保存时静默丢弃
  const entries = ipListForm.value.entries
    .map((e) => ({ value: e.value.trim(), remark: e.remark.trim(), created_at: e.created_at || undefined, expires_at: e.expires_at || undefined }))
    .filter((e) => e.value !== '' || e.remark !== '')
  const invalidEntry = entries.find((e) => e.value === '' || !isValidCidr(e.value))
  if (invalidEntry) {
    ElMessage.error(invalidEntry.value
      ? `条目格式不正确：${invalidEntry.value}（仅支持单 IP 或 CIDR）`
      : '存在未填写条目值的行，请补全或删除空行')
    return
  }
  // 允许空列表保存（用户裁定）：后端 validateIPListShape 不要求非空；
  // allow 模式策略引用的清空由后端守卫 409 拦截（fail-open 防护）
  // 上限按**生效**条目计（与后端 validateIPListShape 及手动追加上限同口径）：
  // 已到期条目不渲染、保存时由后端剔除，若按原始条数计，自动封禁关闭后滞留
  // 的到期条目会把整表保存顶到上限（用户只能逐行删除）。
  const expiredEntryCount = entries.filter((e) => !!e.expires_at && autobanEntryExpired(e.expires_at)).length
  const activeEntryCount = entries.length - expiredEntryCount
  if (activeEntryCount > IP_LIST_MAX_ENTRIES) { ElMessage.warning(`每个列表最多 ${IP_LIST_MAX_ENTRIES} 条生效条目（已到期条目不计入，当前 ${activeEntryCount} 条）`); return }
  // 已有名单 + 0 条：全量 PUT 会清空——必须二次确认且文案明示
  if (needsEmptyListConfirm(editingIpListId.value, entries.length)) {
    try {
      await ElMessageBox.confirm(`将清空列表「${name}」的全部条目（保存后不可恢复），确定继续？`, '清空确认', { type: 'warning', confirmButtonText: '清空并保存' })
    } catch { return }
  }
  const action = editingIpListId.value ? '保存' : '创建'
  const expiredNote = expiredEntryCount > 0 ? `，其中 ${expiredEntryCount} 条已到期（保存后自动移除）` : ''
  try {
    await ElMessageBox.confirm(`确定${action} IP 地址列表「${name}」（${entries.length} 条条目${expiredNote}）？`, '确认', { type: 'warning' })
  } catch { return }
  // 并发新增核对必须落在最后一次确认之后。保存占位先于复核取得，
  // 使核对 GET 与 PUT 在途期间表单均保持冻结。
  savingIpList.value = true
  try {
    let payloadEntries: IPListEntry[] = entries
    if (editingIpListPreset.value && editingIpListId.value) {
      const merged = await mergeFreshAutobanEntries(editingIpListId.value, entries)
      if (merged === null) return
      payloadEntries = merged
    }
    // entries 与其余名单字段同口径：JSON 数组文本（后端 CreateIPListRequest.Entries 为 string）
    const body = { name, description: ipListForm.value.description.trim(), category: ipListForm.value.category.trim(), entries: JSON.stringify(payloadEntries) }
    const res = editingIpListId.value
      ? await request.put(`/security/ip-lists/${editingIpListId.value}`, body)
      : await request.post('/security/ip-lists', body)
    // 名单直编是共享条目缓存的另一写入口（此前仅 IPLocationAction
    // 失效缓存）——不失效时策略向导/处置弹层会继续读旧条目。
    invalidateSharedEntriesCache()
    showSaveResult(res, '保存成功'); ipListDialogVisible.value = false; fetchIpLists()
  } catch (error: unknown) {
    // 409 重名 / 400 条目非法等已由全局拦截器 toast，这里仅记录避免 unhandled rejection
    console.error('Failed to save IP list:', error)
  } finally { savingIpList.value = false }
}

const deletingIpListId = ref<number | null>(null)
const deleteIpList = (row: IPListRow) => {
  // 重入守卫（同 SecurityPolicies deletingPolicyId 范式）：快速双击
  // 不再叠加双确认框→双 DELETE 误报
  if (deletingIpListId.value !== null) return
  deletingIpListId.value = row.id
  ElMessageBox.confirm(`确定删除 IP 地址列表"${row.name}"？`, '确认', { type: 'warning' })
    .then(async () => {
      // 被策略引用时后端返回 409（含引用策略名的 message 由全局拦截器 toast）
      const del = await request.delete(`/security/ip-lists/${row.id}`)
      // 删除同样使条目缓存失效。
      invalidateSharedEntriesCache()
      showSaveResult(del, '已删除'); fetchIpLists()
    }).catch(() => { /* 用户取消:不动列表;HTTP 失败已由全局拦截器 toast */ })
    .finally(() => { deletingIpListId.value = null })
}

// —— 条目纯前端导入/导出：只修改弹框内条目表，点保存前不落库 ——
const importEntriesInput = ref<HTMLInputElement | null>(null)

const triggerImportEntries = (): void => {
  importEntriesInput.value?.click()
}

// 行格式：第一列 IP/CIDR，第二列备注（可空）；支持 CSV 双引号字段与 `""`
// 反转义（与导出单源：utils/ipListCsv，往返一致）
const parseEntryLine = (line: string): { value: string; remark: string } | { error: 'remark_too_long' } | null =>
  parseIpListEntryLine(line, isValidCidr)

const onImportEntriesFileChange = (event: Event): void => {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  input.value = '' // 复位以支持再次选择同一文件
  if (!file) return
  const reader = new FileReader()
  reader.onload = () => { importEntriesFromText(typeof reader.result === 'string' ? reader.result : '') }
  reader.onerror = () => { ElMessage.error('读取文件失败，请重试') }
  reader.readAsText(file)
}

const importEntriesFromText = (text: string): void => {
  // 保留原始文件行号（空行占位也计数）：备注超长拒绝须按行号点名
  const lines = text.split(/\r?\n/)
    .map((l, idx) => ({ no: idx + 1, text: l.trim() }))
    .filter((l) => l.text !== '')
  if (lines.length === 0) {
    ElMessage.error('文件为空或没有可解析的内容，已取消导入')
    return
  }
  // 与保存口径一致：值与备注均为空的占位行先行移除；先解析候选，
  // 上限门通过前不改写表单，避免超限文件只留下无法保存的部分导入。
  const cleanedEntries = ipListForm.value.entries.filter((e) => e.value.trim() !== '' || e.remark.trim() !== '')
  const existing = new Set(cleanedEntries.map((e) => e.value.trim()).filter((v) => v !== ''))
  const candidates: Array<{ value: string; remark: string }> = []
  let invalid = 0
  let duplicate = 0
  const remarkTooLongLines: number[] = []
  for (const line of lines) {
    const parsed = parseEntryLine(line.text)
    if (!parsed) { invalid++; continue }
    // 备注超长：与非法 CIDR 同策略整条拒绝（不静默截断），行号记入点名清单
    if ('error' in parsed) { invalid++; remarkTooLongLines.push(line.no); continue }
    if (existing.has(parsed.value)) { duplicate++; continue }
    existing.add(parsed.value)
    candidates.push({ value: parsed.value, remark: parsed.remark })
  }
  const activeExistingCount = cleanedEntries.filter((e) => !e.expires_at || !autobanEntryExpired(e.expires_at)).length
  const remaining = Math.max(0, IP_LIST_MAX_ENTRIES - activeExistingCount)
  if (candidates.length > remaining) {
    ElMessage.warning(`本次可导入 ${candidates.length} 条，超过当前剩余额度 ${remaining} 条（每个列表最多 ${IP_LIST_MAX_ENTRIES} 条生效条目），已取消导入`)
    return
  }
  ipListForm.value.entries = cleanedEntries
  ipListForm.value.entries.push(...candidates)
  const success = candidates.length
  ipListEntryPage.value = Math.ceil(ipListForm.value.entries.length / ipListEntryPageSize)
  const tooLongLineNos = remarkTooLongLines.slice(0, 10).join('、') + (remarkTooLongLines.length > 10 ? ' 等' : '')
  const tooLongNote = remarkTooLongLines.length > 0
    ? `；备注超过 ${ipListRemarkMaxLength} 字拒绝导入：第 ${tooLongLineNos} 行`
    : ''
  if (success === 0) {
    ElMessage.error(duplicate > 0 || remarkTooLongLines.length > 0
      ? `没有可导入的新条目（非法 ${invalid} 条 / 重复 ${duplicate} 条）${tooLongNote}`
      : '文件中未解析到合法的 IP/CIDR 条目，已取消导入')
    return
  }
  mfaAwareSuccess(`导入完成：成功 ${success} 条，跳过 ${invalid + duplicate} 条（非法 ${invalid} / 重复 ${duplicate}）${tooLongNote}`)
}

const exportIpListEntries = (): void => {
  const entries = ipListForm.value.entries
    .map((e) => ({ value: e.value.trim(), remark: e.remark.trim() }))
    .filter((e) => e.value !== '' || e.remark !== '')
  if (entries.length === 0) {
    ElMessage.warning('当前没有可导出的条目')
    return
  }
  // 首字符写入 UTF-8 BOM，避免 Excel 直接打开中文备注乱码；字段级 CSV
  // 转义与导入解析同源（utils/ipListCsv）
  const csv = `\uFEFF${entries.map((e) => formatIpListEntryLine(e.value, e.remark)).join('\r\n')}`
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = 'ip-list.csv'
  link.click()
  // Safari 下立即回收 objectURL 会截断下载文件，延迟释放（与 BasicSettings/Keys 导出一致）
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

const PATTERN_PLACEHOLDERS: Record<string, string> = {
  uri: '如 /admin',
  args: '如 debug=1',
  headers: '如 X-Custom-Header',
  body: '如 password',
  user_agent: '如 sqlmap',
}
const patternPlaceholder = (cond: CustomRuleCondition): string => {
  if (cond.operator === 'regex') return '如 ^/admin/.*$'
  // 同表查表过 hasOwn（target 来自库值，原型键不得渲染函数源码）
  return hasOwn(PATTERN_PLACEHOLDERS, cond.target) ? PATTERN_PLACEHOLDERS[cond.target] : '匹配值'
}

// 快捷预设：标签为用户友好文案，value 为真实 UA 中的准确片段
// （@contains 大小写敏感，value 必须与线上 UA 实际大小写一致才能命中）
const UA_PRESET_GROUPS: ReadonlyArray<{ label: string; values: ReadonlyArray<{ label: string; value: string }> }> = [
  { label: '攻击工具', values: [
    { label: 'sqlmap', value: 'sqlmap/' },
    { label: 'Nikto', value: 'Nikto/' },
    { label: 'Nmap NSE', value: 'Nmap Scripting Engine' },
    { label: 'masscan', value: 'masscan/' },
    { label: 'hydra', value: 'Hydra' },
  ] },
  { label: '爬虫', values: [
    { label: '机器人', value: 'bot' },
    { label: 'Spider 爬虫', value: 'spider' },
    { label: 'Python 脚本', value: 'python-requests' },
    { label: 'Go 脚本', value: 'Go-http-client' },
    { label: 'curl', value: 'curl/' },
    { label: 'Wget', value: 'Wget/' },
  ] },
  { label: '浏览器', values: [
    { label: 'Chromium', value: 'Chrome/' },
    { label: 'Firefox', value: 'Firefox/' },
    { label: 'Safari', value: 'Safari/' },
    { label: 'Edge', value: 'Edg' },
  ] },
  { label: '系统', values: [
    { label: 'Windows', value: 'Windows NT' },
    { label: 'Linux 桌面', value: 'X11; Linux' },
    { label: 'macOS', value: 'Macintosh' },
    { label: 'iPhone', value: 'iPhone' },
    { label: 'Android', value: 'Android' },
  ] },
]

// 正则模板：点击即填充
const REGEX_PRESETS: ReadonlyArray<{ label: string; value: string }> = [
  { label: 'SQL注入', value: '(?i)(union|select|insert|drop)' },
  { label: 'XSS', value: '(?i)(<script|javascript:|onerror=)' },
  { label: '路径穿越', value: '\\.\\.[\\\\/]' },
  { label: '命令注入', value: '(?i)(;|\\|\\||&&|\\$\\()' },
  { label: '敏感文件', value: '(?i)(\\.(env|git|svn|htaccess))' },
  { label: 'Linux 服务器', value: '(?i)linux (x86_64|aarch64|armv7l|armv6l|armv8l|i686|riscv64)' },
  { label: '手机浏览器', value: '(?i)(iphone|android)' },
]

// 每条 regex 条件的临时测试字符串（按 idx 索引；条件删除时同步重排避免错位）
const regexTestStrings = ref<Record<number, string>>({})
const uaCollapsed = ref<Record<number, boolean>>({})
const regexCollapsed = ref<Record<number, boolean>>({})

// 三个按条件下标索引的会话态必须在每次打开弹框时清空——原实现跨
// 规则复用，先编辑规则 A 输入测试串再打开规则 B，同下标条件会显示 A 的测试串
// 与「匹配/不匹配」结果，误导正则调试。
const resetRuleDialogSession = (): void => {
  regexTestStrings.value = {}
  uaCollapsed.value = {}
  regexCollapsed.value = {}
}

const regexResultClass = (cond: CustomRuleCondition, idx: number): string => {
  if (!cond.pattern) return ''
  const { re, valid } = buildJSRegex(cond.pattern)
  if (!valid) return 'regex-invalid'
  const ts = regexTestStrings.value[idx] || ''
  if (!ts) return ''
  return re!.test(ts) ? 'regex-match' : 'regex-nomatch'
}

const regexResultText = (cond: CustomRuleCondition, idx: number): string => {
  if (!cond.pattern) return ''
  const { re, valid } = buildJSRegex(cond.pattern)
  if (!valid) return '正则语法错误'
  const ts = regexTestStrings.value[idx] || ''
  if (!ts) return ''
  return re!.test(ts) ? '匹配 ✓' : '不匹配 ✗'
}

const isValidRegex = (pattern: string): boolean => {
  if (!pattern) return true
  return buildJSRegex(pattern).valid
}

// 正则预览编译结果按 pattern 记忆化：模板对同一条件同时求 class/text/isValid
// （输入事件触发高频重渲染），原实现每次都做三段试编译。上限 50 条防长会话
// 无界增长；编译只产出 i/m/s flag（无 g/y），RegExp 复用无 lastIndex 状态。
const REGEX_PREVIEW_CACHE_LIMIT = 50
const regexPreviewCache = new Map<string, { re: RegExp | null; valid: boolean }>()

function buildJSRegex(pattern: string): { re: RegExp | null; valid: boolean } {
  const cached = regexPreviewCache.get(pattern)
  if (cached) return cached
  const compiled = compileJSRegex(pattern)
  if (regexPreviewCache.size >= REGEX_PREVIEW_CACHE_LIMIT) {
    const oldest = regexPreviewCache.keys().next().value
    if (oldest !== undefined) regexPreviewCache.delete(oldest)
  }
  regexPreviewCache.set(pattern, compiled)
  return compiled
}

function compileJSRegex(pattern: string): { re: RegExp | null; valid: boolean } {
	// +:合法性以后端 RE2(coraza)为准。
	// RE2 支持:组合内联 flag(?im)/中置 flag(a(?i)b)/flag 组((?i:...))/
	// 命名组((?P<name>))/flag 取反((?-i));不支持 lookaround/反向引用。
	if (/\(\?<?[=!]/.test(pattern) || /\\[1-9]/.test(pattern) || /\\k</.test(pattern)) {
		return { re: null, valid: false }
	}
	// lead 捕获含取反 '-'——白名单 {i,m,s,U,-} 真正
	// 生效(此前捕获组不含 '-',取反形态连 lead 都匹配不上)。
	const lead = pattern.match(/^\(\?([-a-zA-Z]+)\)/)
	if (lead && !/^(?:[imsU]+(?:-[imsU]+)?|-[imsU]+)$/.test(lead[1])) {
		return { re: null, valid: false }
	}
	let src = pattern
	let flags = ''
	if (lead) {
		// +:RE2 取反语义——'-' 后的 flag 关闭、前缀
		// 开启;JS 无原生取反,预览近似:'-' 前的正向 flag 照收(!negated
		// 守卫),'-' 后的跳过(不重置累积——(?i-s) 保留 i、丢弃 s,比全清
		// 更接近 RE2);纯取反((?-i))不加任何 flag(全默认)。
		let negated = false
		for (const f of lead[1].toLowerCase()) {
			if (f === '-') { negated = true; continue }
			if (!negated && (f === 'i' || f === 'm' || f === 's') && !flags.includes(f)) flags += f
		}
		src = src.slice(lead[0].length)
	}
	src = src.replace(/\(\?P</g, '(?<')
	// 中置内联 flag((?i)a(?m)b)——JS 不识别,剥离后重试(RE2 合法)。
	const midFlagStripped = src.replace(/\(\?(?:[imsU]+(?:-[imsU]+)?|-[imsU]+)\)(?=[^)]|$)/g, '')
	// flag 组((?i:...))——JS 不识别,替换为普通分组后再试;真语法错误
	// (未闭合括号等)在三段试编译全失败后判 invalid,不再被兜底掩盖。
	const flagGroupsOpened = src.replace(/\(\?[-imsU]+:/g, '(')
	const candidates = [src, midFlagStripped, flagGroupsOpened]
	for (const candidate of candidates) {
		try {
			return { re: new RegExp(candidate, flags), valid: true }
		} catch {
			continue
		}
	}
	return { re: null, valid: false }
}

const fetchCRS = async () => {
  const seq = ++crsInfoSeq
  try {
    const res = await request.get<APIResponse<typeof crsInfo.value>>('/security/crs', { silent: true })
    if (seq !== crsInfoSeq) return
    if (res.data) crsInfo.value = res.data
    crsInfoError.value = false
    crsInfoLoaded.value = true
  } catch {
    if (seq !== crsInfoSeq) return
    // 读取失败：标签/行状态显性化，不沿用默认值伪装正常
    crsInfoError.value = true
    crsInfoLoaded.value = true
  }
}

const removeCondition = (idx: number) => {
  ruleForm.value.conditions.splice(idx, 1)
  // 同步重排 regex 测试字符串的 idx 键，避免错位显示
  const prev = regexTestStrings.value
  const next: Record<number, string> = {}
  for (const k of Object.keys(prev)) {
    const n = Number(k)
    if (n < idx) next[n] = prev[n]
    else if (n > idx) next[n - 1] = prev[n]
  }
  regexTestStrings.value = next
  // 折叠态键同步重排（同 regexTestStrings 口径，否则删除后整体错位）
  for (const src of [uaCollapsed, regexCollapsed]) {
    const p = src.value
    const n2: Record<number, boolean> = {}
    for (const k of Object.keys(p)) {
      const n = Number(k)
      if (n < idx) n2[n] = p[n]
      else if (n > idx) n2[n - 1] = p[n]
    }
    src.value = n2
  }
}
// 搜索提交先回到第 1 页:高页码叠加收窄后的结果集会落在空页上
const searchRules = () => { page.value = 1; fetchRules() }
// CRS 标签服务端分页 size-change 不复位 page——高页码叠加放大 pageSize
// 会请求越界 offset(空表停留在空页);对齐本文件自定义规则/IP 列表「size-change 回第 1 页」口径
const onRulesSizeChange = () => { page.value = 1; fetchRules() }
// 乱序响应守卫：翻页/搜索快速切换时，慢响应晚到不得覆盖当前页
let rulesRequestSeq = 0
const rulesLoadError = ref(false)
const fetchRules = async () => {
  const requestSeq = ++rulesRequestSeq
  loadingRules.value = true
  try {
    const p = new URLSearchParams({ page: String(page.value), page_size: String(pageSize.value) })
    if (searchQuery.value) p.set('search', searchQuery.value)
    const res = await request.get<APIResponse<{ rules: CRSRuleFile[]; total: number }>>(`/security/crs/rules?${p}`)
    if (requestSeq !== rulesRequestSeq) return
    rules.value = res.data?.rules || []
    total.value = res.data?.total || 0
    rulesLoadError.value = false
  } catch {
    // 失败一律进入可见错误态（全局拦截器只 toast 一次）：已有数据时保留上一页
    // 结果，但横幅明示「当前显示的是上次成功结果」——分页器/搜索框已切到新
    // 条件而内容仍是旧页时，不再无提示地错配。过期请求的失败不污染当前态。
    if (requestSeq !== rulesRequestSeq) return
    rulesLoadError.value = true
  } finally {
    if (requestSeq === rulesRequestSeq) loadingRules.value = false
  }
}
const fetchCustomRules = async () => {
  loadingCustom.value = true
  try {
    const res = await request.get<APIResponse<CustomRule[]>>('/security/custom-rules')
    customRules.value = res.data || []
    customRulesError.value = false
  } catch {
    customRulesError.value = true
  } finally { loadingCustom.value = false }
}
const retryCustomRules = (): void => {
  void fetchCustomRules()
  if (usersError.value) void fetchUsers()
}
// 用户名册失败只影响「更新者」列（显示 '-'），不冒充规则数据空态——
// 与自定义规则错误共用横幅但文案区分。
const usersError = ref(false)
const fetchUsers = async () => {
  try {
    const res = await request.get<APIResponse<UserListItem[]>>('/users')
    users.value = res.data || []
    usersError.value = false
  } catch {
    usersError.value = true
  }
}

let ruleContentSeq = 0
const openRuleContent = async (row: CRSRuleFile) => {
  // 乱序响应守卫：只有最新一次打开的文件才允许写入标题与内容，避免旧响应覆盖新文件
  const requestSeq = ++ruleContentSeq
  currentFilename.value = row.filename
  contentDialogVisible.value = true
  loadingContent.value = true
  currentContent.value = ''
  try {
    const res = await request.get<APIResponse<{ content: string; size: number }>>(`/security/crs/rules/${encodeURIComponent(row.filename)}`)
    if (requestSeq !== ruleContentSeq) return
    currentContent.value = res.data?.content || '(空文件)'
  } catch {
    if (requestSeq !== ruleContentSeq) return
    currentContent.value = '加载失败'
  } finally {
    if (requestSeq === ruleContentSeq) loadingContent.value = false
  }
}
const fetchIP2RegionInfo = async () => {
  const seq = ++ip2regionInfoSeq
  try {
    const res = await request.get<APIResponse<typeof ip2regionInfo.value>>('/security/ip2region', { silent: true })
    if (seq !== ip2regionInfoSeq) return
    if (res.data) ip2regionInfo.value = res.data
    ip2regionInfoError.value = false
    ip2regionInfoLoaded.value = true
  } catch {
    if (seq !== ip2regionInfoSeq) return
    ip2regionInfoError.value = true
    ip2regionInfoLoaded.value = true
  }
}

// —— 定时更新排程（三库同构：星期多选 + 时间；保存即重排下次更新，时区遵循基础设置）——
const scheduleTz = ref('')
let scheduleTzLoaded = false
let scheduleTzLoading = false
const ensureScheduleTz = async () => {
  if (scheduleTzLoaded || scheduleTzLoading) return
  scheduleTzLoading = true
  try {
    const res = await request.get<APIResponse<{ timezone?: string }>>('/config', { silent: true })
    scheduleTz.value = res.data?.timezone || ''
    scheduleTzLoaded = true
  } catch { /* 失败不闩死：下次打开弹框重试 */ } finally {
    scheduleTzLoading = false
  }
}

const savingCRSSchedule = ref(false)
const saveCRSSchedule = async ({ days, time }: { days: number[]; time: string }) => {
  if (crsScheduleHint.value) { ElMessage.warning(crsScheduleHint.value); return }
  savingCRSSchedule.value = true
  try {
    await request.put('/security/crs/schedule', { days, time })
    mfaAwareSuccess('定时更新设置已保存')
    await fetchCRS()
  } catch { /* 全局拦截器已 toast */ } finally { savingCRSSchedule.value = false }
}

const savingIP2RegionSchedule = ref(false)
const saveIP2RegionSchedule = async ({ days, time }: { days: number[]; time: string }) => {
  if (ip2regionScheduleHint.value) { ElMessage.warning(ip2regionScheduleHint.value); return }
  savingIP2RegionSchedule.value = true
  try {
    await request.put('/security/ip2region/schedule', { days, time })
    mfaAwareSuccess('定时更新设置已保存')
    await fetchIP2RegionInfo()
  } catch { /* 全局拦截器已 toast */ } finally { savingIP2RegionSchedule.value = false }
}

const savingThreatSchedule = ref(false)
const saveThreatSchedule = async ({ days, time }: { days: number[]; time: string }) => {
  if (threatScheduleHint.value) { ElMessage.warning(threatScheduleHint.value); return }
  savingThreatSchedule.value = true
  try {
    await request.put('/security/threat-lib/schedule', { days, time })
    mfaAwareSuccess('定时更新设置已保存')
    await fetchThreatLib()
  } catch { /* 全局拦截器已 toast */ } finally { savingThreatSchedule.value = false }
}

const savingCrawlerSchedule = ref(false)
const saveCrawlerSchedule = async ({ days, time }: { days: number[]; time: string }) => {
  if (crawlerScheduleHint.value) { ElMessage.warning(crawlerScheduleHint.value); return }
  savingCrawlerSchedule.value = true
  try {
    await request.put('/security/crawler-lib/schedule', { days, time })
    mfaAwareSuccess('定时更新设置已保存')
    await fetchCrawlerLib()
  } catch { /* 全局拦截器已 toast */ } finally { savingCrawlerSchedule.value = false }
}

// CRS 规则库更新弹框（useLibUpdateDialog 统一范式）——
const updateLogRef = ref<HTMLDivElement | null>(null)
const crsDialog = useLibUpdateDialog<CRSUpdateInfo>({
  apiPrefix: '/security/crs',
  logContainer: updateLogRef,
  errorLabel: 'CRS',
  isRunning: (info) => ['checking', 'downloading', 'installing', 'reloading'].includes(info?.status || ''),
  isFinished: (info) => info.status === 'success' || info.status === 'failed',
  isSuccess: (info) => info.status === 'success',
  onSuccess: () => { fetchCRS(); fetchRules() },
  onOpen: () => { ensureScheduleTz() },
})
const {
  visible: updateDialogVisible,
  logs: updateLog,
  updating: crsUpdateRunning,
  starting: startingUpdate,
  open: manualUpdate,
  onOpened: onUpdateDialogOpened,
  onClosed: onUpdateDialogClosed,
  confirmUpdate,
} = crsDialog

// IP2Region 库更新弹框（useLibUpdateDialog 统一范式）——
const ip2regionUpdateLogRef = ref<HTMLDivElement | null>(null)
const ip2regionDialog = useLibUpdateDialog<IP2RegionUpdateInfo>({
  apiPrefix: '/security/ip2region',
  logContainer: ip2regionUpdateLogRef,
  errorLabel: 'IP2Region',
  isRunning: (info) => ['checking', 'downloading', 'installing', 'reloading'].includes(info?.status || ''),
  isFinished: (info) => info.status === 'success' || info.status === 'failed',
  isSuccess: (info) => info.status === 'success',
  onSuccess: fetchIP2RegionInfo,
  onOpen: () => { ensureScheduleTz() },
})
const {
  visible: ip2regionUpdateDialogVisible,
  logs: ip2regionUpdateLog,
  updating: ip2regionUpdateRunning,
  starting: startingIP2RegionUpdate,
  open: manualIP2RegionUpdate,
  onOpened: onIP2RegionUpdateDialogOpened,
  onClosed: onIP2RegionUpdateDialogClosed,
  confirmUpdate: confirmIP2RegionUpdate,
} = ip2regionDialog

const openRuleDialog = (row?: CustomRule) => {
  resetRuleDialogSession()
  editingRuleId.value = row?.id ?? null
  if (row) {
    // 存量空条件规则：自动补一条空条件行，让用户可见地修正而非卡在无法保存的死角
    // 逐条深拷贝——浅拷贝数组会让弹框 v-model 直接改写
    // 列表行对象（取消/保存失败后表格展示未落库的修改态）。
    const conditions = row.conditions.length ? row.conditions.map((c) => ({ ...c })) : [{ target: 'uri', operator: 'contains', pattern: '' }]
    ruleForm.value = { name: row.name, description: row.description, conditions, condition_logic: row.condition_logic ?? 'and', action: row.action, score: row.score, enabled: row.enabled }
  } else {
    ruleForm.value = { name: '', description: '', conditions: [{ target: 'uri', operator: 'contains', pattern: '' }], condition_logic: 'and', action: 'block', score: 5, enabled: true }
  }
  ruleDialogVisible.value = true
}

const saveCustomRule = async () => {
  if (isReadOnly.value || savingRule.value) return
  if (!ruleForm.value.name.trim()) { ElMessage.warning('请输入规则名称'); return }
  if (!ruleForm.value.conditions.length) { ElMessage.warning('至少需要一个匹配条件'); return }
  // 上限与后端写侧门同源（条件数/pattern 字节）：不前置拦截只能等 400，且无字段定位。
  if (ruleForm.value.conditions.length > CUSTOM_RULE_MAX_CONDITIONS) {
    ElMessage.error(`自定义规则最多支持 ${CUSTOM_RULE_MAX_CONDITIONS} 个匹配条件（当前 ${ruleForm.value.conditions.length} 个）`)
    return
  }
  for (const cond of ruleForm.value.conditions) {
    if (!cond.pattern.trim()) { ElMessage.error('每个条件必须填写匹配值'); return }
    if (patternOverLimit(cond.pattern)) {
      ElMessage.error(`匹配内容不能超过 ${CUSTOM_RULE_MAX_PATTERN_BYTES} 字节（当前「${cond.pattern.slice(0, 20)}…」${patternByteLength(cond.pattern)} 字节）`)
      return
    }
    if (cond.pattern.endsWith('\\')) {
      ElMessage.error(cond.operator === 'regex'
        ? '正则匹配内容不能以反斜杠结尾，可用 `\\$` 结尾锚定或末尾追加 `(?:)` 空组表达尾部反斜杠'
        : '该运算符不支持以反斜杠结尾的匹配内容，请改用正则运算符（如 `\\$`）表达')
      return
    }
    if (cond.operator === 'regex' && !isValidRegex(cond.pattern)) { ElMessage.error(`正则表达式语法错误：${cond.pattern}`); return }
  }
  savingRule.value = true
  try {
    const res = editingRuleId.value
      ? await request.put(`/security/custom-rules/${editingRuleId.value}`, ruleForm.value)
      : await request.post('/security/custom-rules', ruleForm.value)
    showSaveResult(res, '保存成功'); ruleDialogVisible.value = false; fetchCustomRules()
  } catch (error: unknown) {
    // 全局拦截器已弹 toast，这里仅记录避免 unhandled rejection
    console.error('Failed to save custom rule:', error)
  } finally { savingRule.value = false }
}

const deletingCustomRuleId = ref<number | null>(null)
const deleteCustomRule = (row: CustomRule) => {
  // 重入守卫（同 SecurityPolicies deletingPolicyId 范式）：快速双击
  // 不再叠加双确认框→双 DELETE 误报
  if (deletingCustomRuleId.value !== null) return
  deletingCustomRuleId.value = row.id
  ElMessageBox.confirm(`确定删除规则"${row.name}"？`, '确认', { type: 'warning' })
    .then(async () => { const del = await request.delete(`/security/custom-rules/${row.id}`); showSaveResult(del, '已删除'); fetchCustomRules() })
    .catch((reason: unknown) => {
      // 取消与失败分离：ElMessageBox 取消/close 以字符串 reject；其余为真失败
      // （toast 已由全局拦截器弹出），留痕避免吞错
      if (reason === 'cancel' || reason === 'close') return
      console.error('Failed to delete custom rule:', reason)
    })
    .finally(() => { deletingCustomRuleId.value = null })
}

// WAF 文件大小：formatBytes 单一事实源
const formatSize = (b: number) => formatBytes(b)

// 四库信息低频回刷（60s）：后台定时更新完成后卡片不再停留旧版本/旧「已最新」，
// 更新失败也能自行浮出；隐藏页停表、恢复可见立即补一轮（全站轮询同口径）。
const refreshLibraryInfo = (): void => {
  void fetchCRS(); void fetchIP2RegionInfo(); void fetchThreatLib(); void fetchCrawlerLib()
}
let libraryRefreshTimer: ReturnType<typeof createVisibilityIntervals> | null = null

onMounted(() => {
  // 消费?tab= 后剥离(与 sp 口径一致,SecurityPolicies.vue
  // 先例)——视图切换走 authStore.currentPage 而非 hash 路由,replaceState 仅留
  // pathname 不破坏页面基座;仅当 URL 实际携带 tab 参数时才剥离。
  const query = new URLSearchParams(location.search)
  const urlTab = query.get(DEEP_LINK_PARAMS.securityRulesTab)
  if (urlTab && ['rules', 'custom', 'ip-lists'].includes(urlTab)) {
    activeTab.value = urlTab
  }
  if (query.has(DEEP_LINK_PARAMS.securityRulesTab)) window.history.replaceState(null, '', window.location.pathname)
  fetchCRS(); fetchIP2RegionInfo(); fetchRules(); fetchCustomRules(); fetchUsers(); fetchIpLists(); fetchThreatLib(); fetchCrawlerLib()
  libraryRefreshTimer = createVisibilityIntervals({ intervals: [{ tick: refreshLibraryInfo, ms: 60_000 }] })
  libraryRefreshTimer.start()
})

onUnmounted(() => {
  // 作废在途响应并暂停轮询（轮询终态清理由 usePollingTask 内置 onUnmounted 兜底）
  libraryRefreshTimer?.stop()
  libraryRefreshTimer = null
  crsDialog.dispose()
  ip2regionDialog.dispose()
  threatDialog.dispose() // 与两兄弟对齐（曾缺席）
  crawlerDialog.dispose()
})
</script>

<style scoped>
.count-tip { font-size: 12px; vertical-align: -1px; margin-left: 2px; color: var(--text-secondary); cursor: help; }
/* 条件列（rule-cond-cell）的多条件布局已收敛到 styles/main.css
   （.rule-cond-cell/.cond-chip-list/.cond-chip 与其他表格全局规则同源），
   本页不再保留本地覆盖。 */

.crs-card :deep(.el-card__header) .crs-header { display: flex; justify-content: space-between; align-items: center; width: 100%; }
.crs-card :deep(.el-card__header) .crs-header-title { display: flex; align-items: center; gap: 12px; }
.rule-condition-row {
  display: flex; gap: 10px; margin-bottom: 10px; align-items: center; flex-wrap: wrap;
  padding: 12px; background: #f9fafb; border: 1px solid #e5e7eb;
  position: relative; transition: border-color 0.2s;
}
.rule-condition-row:hover { border-color: #d1d5db; }
.rule-condition-row .el-button--danger { margin-left: auto; align-self: center; }

/* 弹框头库专属色（DialogHeader tone-class 透传；:deep 穿透子组件——本页弹框未 append-to-body） */
:deep(.dh-icon.lib-icon--crs) { background: #eff6ff; color: #3b82f6; }
:deep(.dh-icon.lib-icon--ip) { background: #f0fdfa; color: #0d9488; }
:deep(.dh-icon.lib-icon--threat) { background: #fff1f2; color: #e11d48; }
:deep(.dh-icon.lib-icon--crawler) { background: #fff7ed; color: #ea580c; }
.add-condition-row { display: flex; align-items: center; gap: 8px; }
.add-condition-btn { margin-top: 4px; }
.pattern-col { flex: 1; min-width: 220px; display: flex; flex-direction: column; gap: 6px; }
.pattern-input-row { display: flex; align-items: center; gap: 6px; }
.preset-section { flex: 1 1 100%; min-width: 0; width: 100%; margin-top: 4px; }
.preset-header {
  cursor: pointer; padding: 2px 0; user-select: none;
  display: inline-flex; align-items: center; width: 100%;
  background: none; border: 0; font: inherit; text-align: left;
}
.preset-header:focus-visible,
.preset-tag:focus-visible,
.regex-preset-link:focus-visible { outline: 2px solid #409eff; outline-offset: 2px; border-radius: 2px; }
.preset-toggle { font-size: 12px; color: #6b7280; }
.preset-tags-block { display: flex; flex-direction: column; gap: 4px; padding: 6px 8px; background: #fff; border: 1px dashed #e5e7eb; margin-left: 0; }
.preset-group { display: flex; align-items: baseline; gap: 8px; margin-bottom: 4px; }
.preset-group-label { font-size: 12px; color: #6b7280; flex: 0 0 56px; text-align: right; line-height: 1; }
.preset-hint { font-size: 12px; color: #9ca3af; margin-top: 6px; line-height: 1.4; }
.preset-group-tags { display: inline-flex; flex-wrap: wrap; gap: 4px; flex: 1; align-items: center; }
.preset-group-tags .el-tag { margin: 0; }
.preset-group-tags .preset-tag { cursor: pointer; }
.regex-extras { display: flex; flex-direction: column; align-items: flex-start; gap: 6px; width: 100%; padding: 6px 8px; background: #fff; border: 1px dashed #e5e7eb; box-sizing: border-box; }
.regex-presets { display: flex; flex-wrap: wrap; align-items: center; column-gap: 12px; row-gap: 4px; }
.regex-preset-link { font-size: 12px; }
.regex-tester { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.regex-test-input { width: 240px; }
.regex-test-result { font-size: 12px; font-weight: 500; white-space: nowrap; }
.regex-test-result.regex-match { color: #10b981; }
.regex-test-result.regex-nomatch { color: #ef4444; }
.regex-test-result.regex-invalid { color: #f59e0b; }
.table-toolbar { display: flex; justify-content: flex-end; margin-bottom: 16px; }
.search-input { width: 280px; }
.ip-list-toolbar { gap: 12px; }
.entries-block { width: 100%; }
.entries-toolbar { display: flex; align-items: center; margin-top: 8px; }
.entries-toolbar-right { margin-left: auto; }
.entries-import-input { display: none; }
.ip-entry-text { font-family: 'SF Mono', 'Monaco', 'Menlo', monospace; font-size: 13px; }
.ip-entry-index { color: #9ca3af; font-variant-numeric: tabular-nums; }
.entries-pagination { display: flex; justify-content: flex-end; margin-top: 8px; }
.ip-entry-invalid :deep(.el-input__wrapper) { box-shadow: 0 0 0 1px var(--el-color-danger, #ef4444) inset; }
/* .rules-pagination 已收敛 styles/main.css（四处逐字重复单源化） */
.threat-source-url {
  display: inline-block;
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  vertical-align: bottom;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
  color: #64748b;
}

.threat-source-table { margin-bottom: 0; }
.library-sources-panel { margin-bottom: 12px; }
.update-log-container { min-height: 320px; max-height: 480px; overflow: auto; background: #1e293b; padding: 12px; }
.lib-summary-tags { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.lib-health-tag { margin: 0; }
.lib-summary-warn-text { color: #dc2626; font-weight: 600; font-size: 12px; margin-left: 4px; }

.lib-summary { color: #909399; font-size: 12px; font-weight: 400; }
.lib-name { display: flex; align-items: center; gap: 10px; min-width: 0; }
.lib-icon { flex-shrink: 0; width: 28px; height: 28px; border-radius: 7px; display: flex; align-items: center; justify-content: center; }
.lib-icon--crs { background: #eff6ff; color: #3b82f6; }
.lib-icon--ip { background: #f0fdfa; color: #0d9488; }
.lib-icon--threat { background: #fff1f2; color: #e11d48; }
.lib-icon--crawler { background: #fff7ed; color: #ea580c; }
.lib-name-text { min-width: 0; }
.update-log-container--compact { min-height: 200px; max-height: 240px; }
.lib-name-main { font-weight: 600; color: var(--el-text-color-primary); }
.lib-name-sub { color: #909399; font-size: 12px; word-break: break-all; }
.lib-version { font-family: 'SF Mono', 'Monaco', 'Menlo', monospace; font-size: 12px; }
.lib-count { font-variant-numeric: tabular-nums; }
.update-log-content { margin: 0; color: #e4e4e7; font-family: 'SF Mono', 'Monaco', 'Menlo', 'Consolas', monospace; font-size: 12px; line-height: 1.7; white-space: pre-wrap; word-break: break-all; }
</style>

<!-- el-tooltip popper 挂载到 body，scoped 样式无法命中，单独非 scoped 块 -->
<style>
/* .rules-pagination 已收敛 styles/main.css（四处逐字重复单源化） */
.ip-list-refs-popper { line-height: 1.6; max-width: 280px; }
/* 自动封禁名单「加入时间」单元格不换行：formatDate 输出 "YYYY-MM-DD HH:mm:ss"，
   列宽不足时 el-table 单元格会折成两行（2026-10-28 用户反馈）。单元格 td 由
   el-table 内部渲染、dialog class 又经 attrs 绑定，scoped 选择器命不中，故放
   非 scoped 块（与本块其余弹框/popper 规则同因）。 */
.ip-entry-created { white-space: nowrap; }
</style>
