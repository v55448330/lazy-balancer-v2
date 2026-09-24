<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Notebook /></el-icon>
          规则集
        </h2>
        <p class="page-desc">管理 WAF 规则来源：OWASP CRS 规则库、IP2Region IP 库、威胁情报库、自定义规则与 IP 地址列表</p>
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
        <el-table-column label="条目数" width="110" align="right">
          <template #default="{ row }"><span class="lib-count">{{ row.count }}</span></template>
        </el-table-column>
        <el-table-column label="状态" width="110">
          <template #default="{ row }">
            <el-tooltip :disabled="!row.statusMessage" :content="row.statusMessage">
              <el-tag :type="crsStatusTagType(row.status)" size="small" effect="light">{{ crsStatusLabel(row.status) }}</el-tag>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="自动更新" width="90" align="center">
          <template #default="{ row }">
            <el-switch :model-value="row.autoUpdate" :disabled="isReadOnly || isSlaveNode" @change="(v: boolean) => toggleLibAutoUpdate(row, v)" />
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
            <el-button size="small" link type="primary" @click="openLibDialog(row)">更新详情</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div v-if="isSlaveNode" style="margin-top: 8px;">
        <el-tag type="info" size="small" effect="plain">跟随主节点同步</el-tag>
      </div>
    </el-card>

    <el-card>
      <el-tabs v-model="activeTab">
        <el-tab-pane label="CRS 规则" name="rules">
          <div class="table-toolbar">
            <el-input v-model="searchQuery" placeholder="搜索规则文件名或分类" clearable :prefix-icon="Search" class="search-input" @clear="fetchRules" @keyup.enter="searchRules" />
          </div>
          <el-table :data="rules" v-loading="loadingRules" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="" @row-click="openRuleContent" style="cursor: pointer">
            <template #empty><el-empty description="暂无规则文件" :image-size="60" /></template>
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
          <div style="display: flex; justify-content: center; margin-top: 16px;">
          <div class="rules-pagination">
            <el-pagination v-model:current-page="page" v-model:page-size="pageSize" :page-sizes="[10, 20, 50]" :total="total" layout="total, sizes, prev, pager, next" @current-change="fetchRules" @size-change="onRulesSizeChange" />
          </div>
          </div>
        </el-tab-pane>
      <el-tab-pane label="自定义规则" name="custom">
            <div class="table-toolbar">
              <el-button v-if="!isReadOnly" type="primary" :icon="Plus" @click="openRuleDialog()">新建规则</el-button>
            </div>
            <el-table :data="customRulesPaged" v-loading="loadingCustom" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="">
            <template #empty><el-empty description="暂无自定义规则" :image-size="60" /></template>
            <el-table-column prop="name" label="规则名称" min-width="150">
              <template #default="{ row }">
                <el-link type="primary" @click="openRuleDialog(row)">{{ row.name }}</el-link>
              </template>
            </el-table-column>
            <el-table-column prop="description" label="描述" min-width="200" show-overflow-tooltip />
            <el-table-column label="条件" min-width="250">
              <template #default="{ row }">
                <el-tag v-for="(cond, i) in row.conditions" :key="i" size="small" effect="plain" style="margin-right: 4px;">{{ cond.target }} {{ cond.operator }} {{ cond.pattern }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="动作" width="80" align="center">
              <template #default="{ row }">
                <!-- W2：三态映射与编辑器（拦截/仅记录/放行计分）语义对齐——
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
                <el-button size="small" link type="primary" @click="openRuleDialog(row)">{{ isReadOnly ? '查看' : '编辑' }}</el-button>
                <el-button size="small" link type="danger" :disabled="isReadOnly" @click="deleteCustomRule(row)">删除</el-button>
            </template>
            </el-table-column>
          </el-table>
          <div class="rules-pagination">
            <el-pagination v-model:current-page="customPage" v-model:page-size="customPageSize" :total="customRules.length" layout="total, sizes, prev, pager, next" @size-change="customPage = 1" />
          </div>
        </el-tab-pane>
        <el-tab-pane label="IP 地址列表" name="ip-lists">
          <div class="table-toolbar ip-list-toolbar">
            <el-input v-model="ipListSearch" placeholder="搜索名称或分类" clearable :prefix-icon="Search" class="search-input" />
            <el-button v-if="!isReadOnly" type="primary" :icon="Plus" @click="openIpListDialog()">新建列表</el-button>
          </div>
          <el-table :data="ipListsPaged" v-loading="loadingIpLists" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="">
            <template #empty><el-empty description="暂无 IP 地址列表" :image-size="60" /></template>
            <el-table-column prop="name" label="名称" min-width="150">
              <template #default="{ row }">
                <el-link type="primary" @click="openIpListDialog(row)">{{ row.name }}</el-link>
                <el-tag v-if="row.system" size="small" type="warning" effect="plain" style="margin-left: 6px;">内置</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="分类" width="120" align="center">
              <template #default="{ row }">
                <el-tag v-if="row.category" size="small" effect="plain" type="info">{{ row.category }}</el-tag>
                <template v-else>—</template>
              </template>
            </el-table-column>
            <el-table-column label="条目数" width="90" align="center">
              <template #default="{ row }">{{ row.entry_count }}</template>
            </el-table-column>
            <el-table-column label="引用" width="90" align="center">
              <template #default="{ row }">
                <el-tooltip v-if="row.ref_policies.length > 0" placement="top" popper-class="ip-list-refs-popper">
                  <template #content>
                    <div v-for="p in row.ref_policies" :key="p.id">{{ p.name }}</div>
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
                <el-button size="small" link type="primary" @click="openIpListDialog(row)">{{ isReadOnly || row.system ? '查看' : '编辑' }}</el-button>
                <el-button v-if="!row.system" size="small" link type="danger" :disabled="isReadOnly" @click="deleteIpList(row)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
          <div class="rules-pagination">
            <el-pagination v-model:current-page="ipListPage" v-model:page-size="ipListPageSize" :total="ipListsFiltered.length" layout="total, sizes, prev, pager, next" @size-change="ipListPage = 1" />
          </div>
        </el-tab-pane>
      </el-tabs>
    </el-card>

    <el-dialog v-model="contentDialogVisible" :title="currentFilename" width="min(900px, 94vw)" top="5vh">
      <div v-loading="loadingContent"><SyntaxHighlight :content="currentContent" language="apacheconf" /></div>
    </el-dialog>

    <el-dialog v-model="ruleDialogVisible" width="min(760px, 94vw)" class="custom-rule-dialog" top="6vh">
      <template #header>
        <div class="dialog-header">
          <div class="dialog-header__icon dialog-header__icon--danger"><el-icon :size="18"><Filter /></el-icon></div>
          <div class="dialog-header__text">
            <div class="dialog-header__title">{{ editingRuleId ? (isReadOnly ? '查看自定义规则' : '编辑自定义规则') : '新建自定义规则' }}</div>
            <div class="dialog-header__subtitle">按请求特征匹配并执行拦截 / 记录 / 计分动作，多条件为 AND 关系</div>
          </div>
        </div>
      </template>
      <el-form :model="ruleForm" label-width="80px" label-position="right" :disabled="isReadOnly">
        <el-form-item label="名称" required>
          <el-input v-model="ruleForm.name" placeholder="规则名称" />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="ruleForm.description" placeholder="规则描述" />
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
                  <el-input v-model="cond.pattern" :placeholder="patternPlaceholder(cond)" size="small" :class="{ 'is-error': cond.operator === 'regex' && !isValidRegex(cond.pattern) }" />
                  <el-icon v-if="cond.operator === 'regex' && !isValidRegex(cond.pattern)" class="regex-error-icon"><WarningFilled /></el-icon>
                </div>
                <div v-if="cond.target === 'user_agent'" class="preset-section">
                  <div class="preset-header" @click="uaCollapsed[idx] = !uaCollapsed[idx]">
                    <span class="preset-toggle">{{ uaCollapsed[idx] ? '▶' : '▼' }} 快捷标签</span>
                  </div>
                  <div v-show="!uaCollapsed[idx]" class="preset-tags-block">
                    <div v-for="g in UA_PRESET_GROUPS" :key="g.label" class="preset-group">
                      <span class="preset-group-label">{{ g.label }}</span>
                      <div class="preset-group-tags">
                        <el-tag v-for="t in g.values" :key="t.value" size="small" effect="plain" class="preset-tag" @click="cond.pattern = t.value">{{ t.label }}</el-tag>
                      </div>
                    </div>
                    <div class="preset-hint">标签写入真实 UA 片段（contains 精确匹配，区分大小写）</div>
                  </div>
                </div>
                <div v-if="cond.operator === 'regex'" class="preset-section">
                  <div class="preset-header" @click="regexCollapsed[idx] = !regexCollapsed[idx]">
                    <span class="preset-toggle">{{ regexCollapsed[idx] ? '▶' : '▼' }} 正则模板与测试</span>
                  </div>
                  <div v-show="!regexCollapsed[idx]" class="regex-extras">
                    <div class="regex-presets">
                      <el-link v-for="p in REGEX_PRESETS" :key="p.label" type="primary" underline="never" class="regex-preset-link" @click="cond.pattern = p.value">{{ p.label }}</el-link>
                    </div>
                    <div class="regex-tester">
                      <el-input v-model="regexTestStrings[idx]" placeholder="输入测试字符串" size="small" class="regex-test-input" />
                      <span class="regex-test-result" :class="regexResultClass(cond, idx)">{{ regexResultText(cond, idx) }}</span>
                    </div>
                  </div>
                </div>
              </div>
              <el-button link type="danger" size="small" :disabled="isReadOnly" @click="removeCondition(idx)">删除</el-button>
            </div>
            <el-button v-if="!isReadOnly" size="small" type="primary" plain class="add-condition-btn" @click="ruleForm.conditions.push({ target: 'uri', operator: 'contains', pattern: '' })">
              + 添加条件
            </el-button>
          </div>
        </el-form-item>
        <!-- 自管标签行(EP 2.14.4 规避,同 ClusterModeCard 范式):el-radio-group
             会把组容器 DIV 注册为表单输入 id,label for 指向 DIV 触发 Firefox 告警 -->
        <div class="mode-row" role="group" aria-label="动作">
          <span class="mode-row-label">动作</span>
          <div class="mode-row-content">
            <el-radio-group v-model="ruleForm.action">
              <el-radio value="block">拦截</el-radio>
              <el-radio value="log">仅记录</el-radio>
              <el-radio value="pass">放行计分</el-radio>
            </el-radio-group>
            <div class="form-tip-line">拦截=命中即阻断；仅记录=只记录事件；放行计分=记录并向异常分累加（CRS 检测/拦截模式下由异常阈值统一裁决；仅自定义模式下只记录不拦截）</div>
          </div>
        </div>
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
        <el-button @click="ruleDialogVisible = false">取消</el-button>
        <el-button type="primary" :disabled="isReadOnly" :loading="savingRule" @click="saveCustomRule">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="ipListDialogVisible" width="min(900px, 94vw)" class="ip-list-dialog" top="6vh">
      <template #header>
        <div class="dialog-header">
          <div class="dialog-header__icon"><el-icon :size="18"><List /></el-icon></div>
          <div class="dialog-header__text">
            <div class="dialog-header__title">{{ editingIpListId ? (ipListDialogReadOnly ? '查看 IP 地址列表' : '编辑 IP 地址列表') : '新建 IP 地址列表' }}</div>
            <div class="dialog-header__subtitle">可复用 IP/CIDR 集合，供安全策略引用（黑白名单 / 信任名单）</div>
          </div>
        </div>
      </template>
      <el-form :model="ipListForm" label-width="80px" label-position="right" :disabled="ipListDialogReadOnly" v-loading="loadingIpListDetail">
        <el-form-item label="名称" required>
          <el-input v-model="ipListForm.name" placeholder="列表名称" maxlength="50" show-word-limit />
        </el-form-item>
        <el-form-item label="分类">
          <el-select v-model="ipListForm.category" allow-create filterable default-first-option placeholder="选择或输入分类" style="width: 100%">
            <el-option v-for="c in IP_LIST_CATEGORIES" :key="c" :label="c" :value="c" />
          </el-select>
          <div class="form-tip-line">预设分类可直接选择，也可自定义（≤32 字符）</div>
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="ipListForm.description" placeholder="列表用途说明" maxlength="200" show-word-limit />
        </el-form-item>
        <el-form-item label="条目" required>
          <div class="entries-block">
            <el-table :data="ipListEntriesPaged" size="small" max-height="360" empty-text="">
              <template #empty><el-empty description="暂无条目，点击下方按钮添加" :image-size="50" /></template>
              <el-table-column label="#" width="70" align="right">
                <template #default="{ $index }"><span class="ip-entry-index">{{ ipListEntryPageStart + $index + 1 }}</span></template>
              </el-table-column>
              <el-table-column label="IP / CIDR" min-width="260">
                <template #default="{ row }">
                  <span v-if="ipListDialogReadOnly" class="ip-entry-text">{{ row.value }}</span>
                  <el-input v-else v-model="row.value" placeholder="如 192.168.1.0/24" size="small" :class="{ 'ip-entry-invalid': !isValidCidr(row.value) }" />
                </template>
              </el-table-column>
              <el-table-column label="备注" min-width="160">
                <template #default="{ row }">
                  <span v-if="ipListDialogReadOnly" class="ip-entry-text">{{ row.remark }}</span>
                  <el-input v-else v-model="row.remark" placeholder="可选备注" size="small" maxlength="100" />
                </template>
              </el-table-column>
              <el-table-column v-if="!ipListDialogReadOnly" label="" width="80" align="center">
                <template #default="{ $index }">
                  <el-button link type="danger" size="small" @click="ipListForm.entries.splice(ipListEntryPageStart + $index, 1)">删除</el-button>
                </template>
              </el-table-column>
            </el-table>
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
              <el-button v-if="!ipListDialogReadOnly" size="small" type="primary" plain @click="addIpListEntry">
                + 添加条目
              </el-button>
              <div class="entries-toolbar-right">
                <el-button v-if="!ipListDialogReadOnly" size="small" type="primary" plain @click="triggerImportEntries">导入</el-button>
                <el-button size="small" type="primary" plain @click="exportIpListEntries">导出</el-button>
              </div>
            </div>
            <input ref="importEntriesInput" type="file" accept=".txt,.csv" class="entries-import-input" @change="onImportEntriesFileChange" />
            <div class="form-tip-line">每条支持单 IP 或 CIDR（如 10.0.0.1、2001:db8::/32）；每个列表最多 500 条，全站列表总数上限 200 个，格式错误的行以红色标出；导入支持 .txt/.csv（每行一条：IP/CIDR + 可选备注，逗号或空白分隔）</div>
          </div>
        </el-form-item>
      </el-form>
      <template #footer>
        <template v-if="ipListDialogReadOnly">
          <el-button @click="ipListDialogVisible = false">关闭</el-button>
        </template>
        <template v-else>
          <el-button @click="ipListDialogVisible = false">取消</el-button>
          <el-button type="primary" :loading="savingIpList" @click="saveIpList">保存</el-button>
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
        <div class="dialog-header">
          <div class="dialog-header__icon lib-icon--crs"><el-icon :size="18"><Lock /></el-icon></div>
          <div class="dialog-header__text">
            <div class="dialog-header__title">更新 CRS 规则库</div>
            <div class="dialog-header__subtitle">OWASP 核心规则集的更新任务与更新日志</div>
          </div>
        </div>
      </template>
      <RuleLibScheduleEditor
        :days="crsInfo.schedule_days"
        :time="crsInfo.schedule_time"
        :disabled="isReadOnly || isSlaveNode"
        :saving="savingCRSSchedule"
        :tz="scheduleTz"
        @save="saveCRSSchedule"
      />
      <div ref="updateLogRef" class="update-log-container">
        <pre v-if="updateLog" class="update-log-content">{{ updateLog }}</pre>
        <el-empty v-else description="暂无更新日志" :image-size="60" />
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
        <div class="dialog-header">
          <div class="dialog-header__icon lib-icon--ip"><el-icon :size="18"><Location /></el-icon></div>
          <div class="dialog-header__text">
            <div class="dialog-header__title">更新 IP 库</div>
            <div class="dialog-header__subtitle">IP2Region 地理归属数据库的更新任务与更新日志</div>
          </div>
        </div>
      </template>
      <RuleLibScheduleEditor
        :days="ip2regionInfo.schedule_days"
        :time="ip2regionInfo.schedule_time"
        :disabled="isReadOnly || isSlaveNode"
        :saving="savingIP2RegionSchedule"
        :tz="scheduleTz"
        @save="saveIP2RegionSchedule"
      />
      <div ref="ip2regionUpdateLogRef" class="update-log-container">
        <pre v-if="ip2regionUpdateLog" class="update-log-content">{{ ip2regionUpdateLog }}</pre>
        <el-empty v-else description="暂无更新日志" :image-size="60" />
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
        <div class="dialog-header">
          <div class="dialog-header__icon lib-icon--threat"><el-icon :size="18"><Aim /></el-icon></div>
          <div class="dialog-header__text">
            <div class="dialog-header__title">更新威胁情报库</div>
            <div class="dialog-header__subtitle">三个内置恶意 IP 源的更新任务与更新日志</div>
          </div>
        </div>
      </template>
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
            <el-tooltip :disabled="!(row.update_status === 'failed' && row.message)" :content="row.message">
              <el-tag :type="crsStatusTagType(row.update_status)" size="small" effect="light">{{ crsStatusLabel(row.update_status) }}</el-tag>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="自动更新" width="90" align="center">
          <template #default="{ row }">
            <el-switch v-model="row.update_enabled" :disabled="isReadOnly || isSlaveNode" @change="(v: boolean) => toggleThreatFlag(row, 'update_enabled', v)" />
          </template>
        </el-table-column>
      </el-table>
      <RuleLibScheduleEditor
        :days="threatSchedule.days"
        :time="threatSchedule.time"
        :disabled="isReadOnly || isSlaveNode"
        :saving="savingThreatSchedule"
        :tz="scheduleTz"
        @save="saveThreatSchedule"
      />
      <div ref="threatUpdateLogRef" class="update-log-container update-log-container--compact">
        <pre v-if="threatUpdateLog" class="update-log-content">{{ threatUpdateLog }}</pre>
        <el-empty v-else description="暂无更新日志" :image-size="60" />
      </div>
      <template #footer>
        <div style="display: flex; align-items: center;">
          <LogStorageBar log-key="threat_update" style="margin-right: auto" />
          <el-button @click="threatUpdateDialogVisible = false">关闭</el-button>
          <el-button v-if="!threatUpdateRunning" type="primary" :disabled="isReadOnly || isSlaveNode" :loading="startingThreatUpdate" @click="confirmThreatUpdate">立即更新</el-button>
        </div>
      </template>
    </el-dialog>

  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed, nextTick, watch } from 'vue'
import { Aim, Filter, List, Location, Lock, Search, Notebook, Plus, WarningFilled } from '@element-plus/icons-vue'
import { formatDate } from '@/utils/date'
import SyntaxHighlight from '@/components/SyntaxHighlight.vue'
import RuleLibScheduleEditor from '@/components/RuleLibScheduleEditor.vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { request, ApiRequestError, mfaAwareSuccess } from '@/utils/api'
import { showSaveResult } from '@/utils/saveResult'
import { isValidCidr } from '@/utils/ruleValidation'
import { useAuthStore } from '@/stores/auth'

import { usePollingTask } from '@/composables/usePollingTask'
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
const threatMergedCount = ref(0)
const threatSchedule = ref({ days: [1, 2, 3, 4, 5, 6, 7] as number[], time: '04:00' })

const fetchThreatLib = async () => {
  try {
    const res = await request.get<APIResponse<{ sources: ThreatSource[]; total_entries: number; auto_update?: boolean; schedule_days?: number[]; schedule_time?: string }>>('/security/threat-lib')
    if (res.data) {
      threatSources.value = res.data.sources
      threatMergedCount.value = res.data.total_entries
      threatAutoUpdate.value = res.data.auto_update !== false
      if (res.data.schedule_days?.length) threatSchedule.value = { days: res.data.schedule_days, time: res.data.schedule_time || '04:00' }
    }
  } catch { /* 只读拉取失败静默（页面其余区域不受影响） */ }
}

const toggleThreatFlag = async (row: ThreatSource, field: 'update_enabled', val: boolean) => {
  try {
    await request.put(`/security/threat-lib/${row.id}/flags`, { [field]: val })
    mfaAwareSuccess('已更新')
  } catch {
    row[field] = !val // 失败回滚开关
  }
  fetchThreatLib()
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
  statusMessage: string
  autoUpdate: boolean
  lastChecked: string
  nextUpdate: string
}

const libRows = computed<LibRow[]>(() => {
  const rows: LibRow[] = [
    {
      key: 'crs', icon: Lock, iconClass: 'lib-icon--crs', name: 'CRS 规则库', sub: 'OWASP Core Rule Set',
      version: crsInfo.value.available === false ? '未安装' : (crsInfo.value.version || '—'),  // 缺失态文案与 IP 库统一「未安装」（2026-09-24 用户裁定）
      count: total.value ? total.value.toLocaleString() + ' 文件' : '—',
      status: crsInfo.value.available === false ? 'missing' : crsInfo.value.update_status, statusMessage: crsFailureMessage.value,
      autoUpdate: crsInfo.value.auto_update,
      lastChecked: formatDate(crsInfo.value.updated_at) || '—',
      nextUpdate: formatDate(crsInfo.value.next_update) || '—',
    },
    {
      key: 'ip2region', icon: Location, iconClass: 'lib-icon--ip', name: 'IP2Region IP 库', sub: 'IP 地理归属数据库',
      version: ip2regionInfo.value.available === false ? '未安装' : ip2regionVersionLabel.value,
      count: ip2regionInfo.value.db_size && ip2regionInfo.value.version && ip2regionInfo.value.version !== 'unknown' && ip2regionInfo.value.version !== 'bundled' ? ip2regionInfo.value.db_size.toLocaleString() : '—',
      status: ip2regionInfo.value.available === false ? 'missing' : (ip2regionStatusForTag.value === 'not-installed' ? 'idle' : ip2regionStatusForTag.value),
      statusMessage: ip2regionFailureMessage.value,
      autoUpdate: ip2regionInfo.value.auto_update,
      lastChecked: formatDate(ip2regionInfo.value.updated_at) || '—',
      nextUpdate: formatDate(ip2regionInfo.value.next_update) || '—',
    },
  ]
  // 威胁情报库=父行（三源为子集）：版本=最近更新日期，条目=三源合计，
  // 状态聚合（任一失败>更新中>成功>未更新），开关=全开/全关。
  if (threatSources.value.length > 0) {
    const srcs = threatSources.value
    const totalEntries = srcs.reduce((sum, x) => sum + x.entry_count, 0)
    const latestVersion = srcs.map(x => x.version).filter(Boolean).sort().pop() || ''
    const anyFailed = srcs.find(x => x.update_status === 'failed')
    const anyRunning = srcs.some(x => x.update_status === 'running')
    const status = anyRunning ? 'running' : anyFailed ? 'failed' : latestVersion ? 'success' : 'idle'
    rows.push({
      key: 'threat', icon: Aim, iconClass: 'lib-icon--threat',
      name: '威胁情报库',
      sub: 'IP 威胁名单，可被黑名单策略引用',  // 来源明细见「更新详情」弹框（2026-09-24：名称列收窄后三源名折行断词，撤）
      version: latestVersion || '未更新',
      count: totalEntries > 0 ? totalEntries.toLocaleString() + ' 条' : '—',
      status, statusMessage: anyFailed?.message || '',
      autoUpdate: threatAutoUpdate.value,
      lastChecked: srcs.map(x => formatDate(x.last_checked)).filter(Boolean).sort().pop() || '—',
      nextUpdate: srcs.map(x => formatDate(x.next_update)).filter(Boolean).sort().shift() || '—',
    })
  }
  return rows
})

// 卡头库健康标签组（2026-09-24 用户裁定）：逐库彩色标签，异常 danger/
// 正常 success；缺库（后端渲染层已停用全部安全规则，见
// SecurityLibrariesAvailable）时模板追加红色警示后缀。
const libHealthTags = computed<Array<{ label: string; type: 'success' | 'danger' | 'warning' }>>(() => {
  const tags: Array<{ label: string; type: 'success' | 'danger' | 'warning' }> = [
    crsInfo.value.available === false
      ? { label: 'CRS 规则库 · 缺失', type: 'danger' }
      : { label: 'CRS 规则库 · 正常', type: 'success' },
    ip2regionInfo.value.available === false
      ? { label: 'IP 地址库 · 缺失', type: 'danger' }
      : { label: 'IP 地址库 · 正常', type: 'success' },
  ]
  const threatFail = threatSources.value.filter(x => x.update_status === 'failed').length
  tags.push(threatFail > 0
    ? { label: `威胁情报库 · ${threatFail} 源更新失败`, type: 'warning' }
    : { label: '威胁情报库 · 正常', type: 'success' })
  return tags
})
const libSummaryWarn = computed(() => crsInfo.value.available === false || ip2regionInfo.value.available === false)

// 自动更新开关：按行分发到三个库的既有端点（开关状态以服务端为准，
// 失败由对应 fetch 回滚）。
const toggleLibAutoUpdate = (row: LibRow, val: boolean) => {
  if (row.key === 'crs') {
    crsInfo.value.auto_update = val
    toggleAutoUpdate(val)
  } else if (row.key === 'ip2region') {
    ip2regionInfo.value.auto_update = val
    toggleIP2RegionAutoUpdate(val)
  } else if (row.key === 'threat') {
    // 父开关=任务级总闸（整任务启停）；逐源微调在更新弹框内（update_enabled
    // 决定任务更新哪些源）——两者解耦，不再逐源循环写（曾连弹三次提示）。
    toggleThreatAutoUpdate(val)
  }
}

// 任务级总闸开关（单次写 + 单次提示）。
const toggleThreatAutoUpdate = async (val: boolean) => {
  try {
    await request.put('/security/threat-lib/auto-update', { auto_update: val })
    threatAutoUpdate.value = val
    mfaAwareSuccess('已更新')
  } catch {
    fetchThreatLib() // 失败回滚显示值
  }
}

// 更新/日志按钮：打开对应库的更新弹框（autoStart=false 时仅查看日志）。
const openLibDialog = (row: LibRow) => {
  if (row.key === 'crs') {
    manualUpdate()
  } else if (row.key === 'ip2region') {
    manualIP2RegionUpdate()
  } else if (row.key === 'threat') {
    threatRequestSeq++
    threatUpdateInfo.value = null
    threatUpdateLog.value = ''
    threatUpdateDialogVisible.value = true
  }
}


// —— 威胁库更新弹框（与 CRS/IP 库同款：状态 + 日志流 + 立即更新）——
const threatUpdateDialogVisible = ref(false)
const threatUpdateInfo = ref<{ running: boolean; trigger: string; started_at: string; finished_at: string; outcome: string } | null>(null)
const threatUpdateLog = ref('')
const threatUpdateLogRef = ref<HTMLDivElement | null>(null)
const startingThreatUpdate = ref(false)
let threatRequestSeq = 0

const threatUpdateRunning = computed(() => threatUpdateInfo.value?.running === true)

const refreshThreatUpdateStatus = async () => {
  if (!threatUpdateDialogVisible.value) return
  const requestSeq = ++threatRequestSeq
  const [statusResult, logsResult] = await Promise.allSettled([
    request.get<APIResponse<{ running: boolean; trigger: string; started_at: string; finished_at: string; outcome: string }>>('/security/threat-lib/update/status', { silent: true }),
    request.get<APIResponse<{ content: string }>>('/security/threat-lib/update/logs', { silent: true }),
  ])
  if (!threatUpdateDialogVisible.value || requestSeq !== threatRequestSeq) return
  if (statusResult.status === 'fulfilled') {
    threatUpdateInfo.value = statusResult.value.data || null
  }
  if (logsResult.status === 'fulfilled') {
    threatUpdateLog.value = logsResult.value.data?.content || ''
    await nextTick()
    if (threatUpdateLogRef.value) threatUpdateLogRef.value.scrollTop = threatUpdateLogRef.value.scrollHeight
  }
  if (!threatUpdateRunning.value && threatUpdateInfo.value) {
    stopThreatPolling()
    if (threatUpdateInfo.value.outcome === 'success') fetchThreatLib()
  }
}

const threatUpdatePolling = usePollingTask(async () => { await refreshThreatUpdateStatus() }, { interval: 2000 })
const startThreatPolling = () => { threatUpdatePolling.resume() }
const stopThreatPolling = () => { threatUpdatePolling.pause() }

const onThreatUpdateDialogOpened = async () => {
  ensureScheduleTz()
  await refreshThreatUpdateStatus()
  if (threatUpdateRunning.value) startThreatPolling()
}
const onThreatUpdateDialogClosed = () => {
  threatRequestSeq++
  stopThreatPolling()
  threatUpdateInfo.value = null
  threatUpdateLog.value = ''
}

const confirmThreatUpdate = async () => {
  startingThreatUpdate.value = true
  try {
    await request.post('/security/threat-lib/update', undefined, { silent: true })
  } catch (error) {
    if (!(error instanceof ApiRequestError && error.status === 409)) {
      ElMessage.error(error instanceof Error ? error.message : '触发更新失败')
    }
  } finally {
    startingThreatUpdate.value = false
  }
  if (!threatUpdateDialogVisible.value) return
  await refreshThreatUpdateStatus()
  if (!threatUpdateDialogVisible.value) return
  startThreatPolling()
}
interface CRSRuleFile { filename: string; category: string; size: number; updated_at: string }
interface CustomRuleCondition { target: string; operator: string; pattern: string }
interface CustomRule { id: number; name: string; description: string; conditions: CustomRuleCondition[]; action: string; score: number; enabled: boolean; updated_at: string; updated_by: number }
interface IPListEntry { value: string; remark: string }
interface IPListRefPolicy { id: number; name: string }
interface IPListRow { id: number; name: string; description: string; category: string; entries: IPListEntry[]; entry_count: number; ref_count: number; ref_policies: IPListRefPolicy[]; created_by: number; created_at: string; updated_by: number; updated_at: string; system: boolean }
interface CRSUpdateInfo { readonly status: string; readonly trigger: string; readonly started_at: string; readonly finished_at: string; readonly message: string; readonly version: string }
interface IP2RegionUpdateInfo { readonly status: string; readonly trigger: string; readonly started_at: string; readonly finished_at: string; readonly message: string; readonly version: string }

const authStore = useAuthStore()
const isSlaveNode = computed(() => authStore.nodeMode === 'slave')
const isReadOnly = computed(() => authStore.readOnlyReason !== null)

const users = ref<UserListItem[]>([])
const getUpdaterName = (userId?: number) => {
  if (!userId || userId === 0) return '-'
  const user = users.value.find(u => u.id === userId)
  return user?.display_name || user?.username || '-'
}

const crsStageLabels: Record<string, string> = {
  running: '更新中',
  checking: '检查更新',
  downloading: '下载规则库',
  installing: '安装规则库',
  reloading: '重载配置',
  success: '更新成功',
  failed: '更新失败',
  idle: '空闲',
}
const crsStatusLabel = (s: string): string => s === 'missing' ? '缺失' : (crsStageLabels[s] || s || '—')

const crsStatusTagType = (s: string): 'success' | 'warning' | 'danger' | 'info' => {
  if (s === 'missing') return 'danger'
  if (!s || s === 'idle') return 'info'
  if (s === 'checking' || s === 'downloading' || s === 'installing' || s === 'reloading' || s === 'running') return 'warning'
  if (s === 'success' || s === '已最新' || s === '更新成功') return 'success'
  if (s === 'failed' || s === '更新失败') return 'danger'
  if (s.includes('失败') || s.includes('错误')) return 'danger'
  if (s.includes('最新')) return 'success'
  if (s.includes('中')) return 'warning'
  return 'info'
}

const crsInfo = ref({ version: '', auto_update: true, updated_at: '', next_update: '', update_status: '', message: '', available: true, schedule_days: [1, 2, 3, 4, 5, 6, 7] as number[], schedule_time: '04:00' })
const crsFailureMessage = computed(() => {
  const s = crsInfo.value.update_status
  return (s === 'failed' || s === '更新失败') ? crsInfo.value.message : ''
})

const ip2regionInfo = ref({ version: '', db_size: 0, auto_update: true, updated_at: '', next_update: '', update_status: '', message: '', available: true, schedule_days: [1, 2, 3, 4, 5, 6, 7] as number[], schedule_time: '04:00' })
const ip2regionVersionLabel = computed(() => {
  if (ip2regionInfo.value.version === 'bundled') return '内置版本（未更新）'
  return (ip2regionInfo.value.version && ip2regionInfo.value.version !== 'unknown') ? ip2regionInfo.value.version : '未安装'
})// unknown/空版本统一显示「未安装」（灰），结构上与正常态同一 tag 元素。
const ip2regionStatusForTag = computed(() => {
  const v = ip2regionInfo.value.version
  if (!v || v === 'unknown') return 'not-installed'
  return ip2regionInfo.value.update_status
})
const ip2regionFailureMessage = computed(() => {
  const s = ip2regionInfo.value.update_status
  return (s === 'failed' || s === '更新失败') ? ip2regionInfo.value.message : ''
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
const customPage = ref(1)
const customPageSize = ref(10)
const customRulesPaged = computed(() => {
  const start = (customPage.value - 1) * customPageSize.value
  return customRules.value.slice(start, start + customPageSize.value)
})
// F-47-34：删除某页最后一条后 customPage 会超出最大页——slice 越界返回空数组、
// 表格空白直至手动翻页（IP 列表有 search watch 复位口径,自定义规则无收敛路径）。
// watch 源不含 customPage 本身,不会自触发死循环
watch([customRules, customPageSize], () => {
  const maxPage = Math.max(1, Math.ceil(customRules.value.length / customPageSize.value))
  if (customPage.value > maxPage) customPage.value = maxPage
})
const loadingCustom = ref(false)
const ruleDialogVisible = ref(false)
const editingRuleId = ref<number | null>(null)
const savingRule = ref(false)
const ruleForm = ref({ name: '', description: '', conditions: [] as CustomRuleCondition[], action: 'block', score: 5, enabled: true })

// 自定义规则动作三态视图（W2）：block=拦截 / log=仅记录 / pass=放行计分，
// 与编辑器 radio 及后端发射语义（pass 累加异常分、log 不累分）一一对应；
// 未知动作兜底原样展示（info），不与任何已知语义混淆。
const CUSTOM_ACTION_VIEWS: Record<string, { label: string; type: 'danger' | 'info' | 'warning' }> = {
  block: { label: '拦截', type: 'danger' },
  log: { label: '仅记录', type: 'info' },
  pass: { label: '放行计分', type: 'warning' },
}
const customActionView = (action: string): { label: string; type: 'danger' | 'info' | 'warning' } =>
  CUSTOM_ACTION_VIEWS[action] ?? { label: action || '—', type: 'info' }

// —— 可复用 IP 地址列表（第三个标签页）——
// 分类预设：与安全策略「提取为列表」共用同一组选项
const IP_LIST_CATEGORIES = ['搜索引擎爬虫', 'CDN 节点', '云服务商', '办公网络', '数据中心', '可信地址', '恶意 IP', '其他']
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
const ipListsPaged = computed(() => {
  const start = (ipListPage.value - 1) * ipListPageSize.value
  return ipListsFiltered.value.slice(start, start + ipListPageSize.value)
})
// 搜索收窄后高页码会落在空页，回到第 1 页
watch(ipListSearch, () => { ipListPage.value = 1 })
const ipListDialogVisible = ref(false)
// 内置名单（威胁情报库 system=1）弹框恒只读（管理员同）——内容只读查看/导出。
const ipListDialogReadOnly = computed(() => isReadOnly.value || editingIpListSystem.value)
const editingIpListId = ref<number | null>(null)
const savingIpList = ref(false)
const ipListForm = ref<{ name: string; description: string; category: string; entries: IPListEntry[] }>({ name: '', description: '', category: '', entries: [] })

const fetchIpLists = async () => {
  loadingIpLists.value = true
  try { const res = await request.get<APIResponse<IPListRow[]>>('/security/ip-lists'); ipLists.value = res.data || [] } catch {} finally { loadingIpLists.value = false }
}

const editingIpListSystem = ref(false)
const loadingIpListDetail = ref(false)
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

const openIpListDialog = async (row?: IPListRow) => {
  editingIpListSystem.value = row?.system === true
  ipListEntryPage.value = 1
  editingIpListId.value = row?.id ?? null
  if (!row) {
    ipListForm.value = { name: '', description: '', category: '', entries: [{ value: '', remark: '' }] }
    ipListDialogVisible.value = true
    return
  }
  // 列表载荷不再内联 entries（大名单瘦身）——弹框按需拉详情。
  ipListForm.value = { name: row.name, description: row.description, category: row.category, entries: [] }
  ipListDialogVisible.value = true
  loadingIpListDetail.value = true
  try {
    const res = await request.get<APIResponse<IPListRow>>(`/security/ip-lists/${row.id}`)
    if (res.data && ipListDialogVisible.value) {
      ipListForm.value.entries = (res.data.entries || []).map((e) => ({ value: e.value, remark: e.remark }))
    }
  } catch {
    ElMessage.error('加载列表条目失败')
  } finally {
    loadingIpListDetail.value = false
  }
}

const saveIpList = async () => {
  const name = ipListForm.value.name.trim()
  if (!name) { ElMessage.warning('请输入列表名称'); return }
  if (name.length > 50) { ElMessage.warning('列表名称不能超过 50 字符'); return }
  if (ipListForm.value.category.length > 32) { ElMessage.warning('分类不能超过 32 字符'); return }
  if (ipListForm.value.description.length > 200) { ElMessage.warning('描述不能超过 200 字符'); return }
  // 值与备注均为空的行视为未填写的占位行，保存时静默丢弃
  const entries = ipListForm.value.entries
    .map((e) => ({ value: e.value.trim(), remark: e.remark.trim() }))
    .filter((e) => e.value !== '' || e.remark !== '')
  const invalidEntry = entries.find((e) => e.value === '' || !isValidCidr(e.value))
  if (invalidEntry) {
    ElMessage.error(invalidEntry.value
      ? `条目格式不正确：${invalidEntry.value}（仅支持单 IP 或 CIDR）`
      : '存在未填写条目值的行，请补全或删除空行')
    return
  }
  if (entries.length === 0) { ElMessage.warning('至少添加一条 IP/CIDR 条目'); return }
  if (entries.length > 500) { ElMessage.warning('每个列表最多 500 条条目'); return }
  const action = editingIpListId.value ? '保存' : '创建'
  try {
    await ElMessageBox.confirm(`确定${action} IP 地址列表「${name}」（${entries.length} 条条目）？`, '确认', { type: 'warning' })
  } catch { return }
  savingIpList.value = true
  try {
    // entries 与其余名单字段同口径：JSON 数组文本（后端 CreateIPListRequest.Entries 为 string）
    const body = { name, description: ipListForm.value.description.trim(), category: ipListForm.value.category.trim(), entries: JSON.stringify(entries) }
    const res = editingIpListId.value
      ? await request.put(`/security/ip-lists/${editingIpListId.value}`, body)
      : await request.post('/security/ip-lists', body)
    showSaveResult(res, '保存成功'); ipListDialogVisible.value = false; fetchIpLists()
  } catch (error: unknown) {
    // 409 重名 / 400 条目非法等已由全局拦截器 toast，这里仅记录避免 unhandled rejection
    console.error('Failed to save IP list:', error)
  } finally { savingIpList.value = false }
}

const deleteIpList = (row: IPListRow) => {
  ElMessageBox.confirm(`确定删除 IP 地址列表"${row.name}"？`, '确认', { type: 'warning' })
    .then(async () => {
      // 被策略引用时后端返回 409（含引用策略名的 message 由全局拦截器 toast）
      const del = await request.delete(`/security/ip-lists/${row.id}`)
      showSaveResult(del, '已删除'); fetchIpLists()
    }).catch(() => {})
}

// —— 条目纯前端导入/导出：只修改弹框内条目表，点保存前不落库 ——
const importEntriesInput = ref<HTMLInputElement | null>(null)

const triggerImportEntries = (): void => {
  importEntriesInput.value?.click()
}

// 行格式：第一列 IP/CIDR，第二列备注（可空）；分隔符为半角逗号或空白（取第一段分隔，其余归入备注）
const parseEntryLine = (line: string): { value: string; remark: string } | null => {
  const match = line.match(/^([^,\s]+)(?:[,\s]+(.*))?$/)
  if (!match) return null
  const value = (match[1] ?? '').trim()
  if (!isValidCidr(value)) return null
  const remark = (match[2] ?? '').trim().slice(0, 100)
  return { value, remark }
}

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
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l !== '')
  if (lines.length === 0) {
    ElMessage.error('文件为空或没有可解析的内容，已取消导入')
    return
  }
  // 与保存口径一致：值与备注均为空的占位行先行移除，导入后表格不留空行
  ipListForm.value.entries = ipListForm.value.entries.filter((e) => e.value.trim() !== '' || e.remark.trim() !== '')
  const existing = new Set(ipListForm.value.entries.map((e) => e.value.trim()).filter((v) => v !== ''))
  let success = 0
  let invalid = 0
  let duplicate = 0
  for (const line of lines) {
    const parsed = parseEntryLine(line)
    if (!parsed) { invalid++; continue }
    if (existing.has(parsed.value)) { duplicate++; continue }
    existing.add(parsed.value)
    ipListForm.value.entries.push({ value: parsed.value, remark: parsed.remark })
    success++
  }
  ipListEntryPage.value = Math.ceil(ipListForm.value.entries.length / ipListEntryPageSize)
  if (success === 0) {
    ElMessage.error(duplicate > 0
      ? `没有可导入的新条目（非法 ${invalid} 条 / 重复 ${duplicate} 条）`
      : '文件中未解析到合法的 IP/CIDR 条目，已取消导入')
    return
  }
  ElMessage.success(`导入完成：成功 ${success} 条，跳过 ${invalid + duplicate} 条（非法 ${invalid} / 重复 ${duplicate}）`)
}

const exportIpListEntries = (): void => {
  const entries = ipListForm.value.entries
    .map((e) => ({ value: e.value.trim(), remark: e.remark.trim() }))
    .filter((e) => e.value !== '' || e.remark !== '')
  if (entries.length === 0) {
    ElMessage.warning('当前没有可导出的条目')
    return
  }
  // 备注含逗号/引号时按 CSV 规则双引号包裹并转义内部引号
  const escapeRemark = (remark: string): string => /[",]/.test(remark) ? `"${remark.replace(/"/g, '""')}"` : remark
  // 首字符写入 UTF-8 BOM，避免 Excel 直接打开中文备注乱码
  const csv = `\uFEFF${entries.map((e) => `${e.value},${escapeRemark(e.remark)}`).join('\r\n')}`
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
  return PATTERN_PLACEHOLDERS[cond.target] ?? '匹配值'
}

// User-Agent 快捷预设：标签为用户友好文案，value 为真实 UA 中的准确片段
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

function buildJSRegex(pattern: string): { re: RegExp | null; valid: boolean } {
	// SR15-P3① + F-2/F-3(第 16 轮):合法性以后端 RE2(coraza)为准。
	// RE2 支持:组合内联 flag(?im)/中置 flag(a(?i)b)/flag 组((?i:...))/
	// 命名组((?P<name>))/flag 取反((?-i));不支持 lookaround/反向引用。
	if (/\(\?<?[=!]/.test(pattern) || /\\[1-9]/.test(pattern) || /\\k</.test(pattern)) {
		return { re: null, valid: false }
	}
	// SR17-2(第 17 轮):lead 捕获含取反 '-'——白名单 {i,m,s,U,-} 真正
	// 生效(此前捕获组不含 '-',取反形态连 lead 都匹配不上)。
	const lead = pattern.match(/^\(\?([-a-zA-Z]+)\)/)
	if (lead && !/^(?:[imsU]+(?:-[imsU]+)?|-[imsU]+)$/.test(lead[1])) {
		return { re: null, valid: false }
	}
	let src = pattern
	let flags = ''
	if (lead) {
		// SR18-2+SR19-5(第 19 轮):RE2 取反语义——'-' 后的 flag 关闭、前缀
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
	// F-2:中置内联 flag((?i)a(?m)b)——JS 不识别,剥离后重试(RE2 合法)。
	const midFlagStripped = src.replace(/\(\?(?:[imsU]+(?:-[imsU]+)?|-[imsU]+)\)(?=[^)]|$)/g, '')
	// F-3:flag 组((?i:...))——JS 不识别,替换为普通分组后再试;真语法错误
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

const fetchCRS = async () => { try { const res = await request.get<APIResponse<typeof crsInfo.value>>('/security/crs'); if (res.data) crsInfo.value = res.data } catch {} }

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
}
// 搜索提交先回到第 1 页:高页码叠加收窄后的结果集会落在空页上
const searchRules = () => { page.value = 1; fetchRules() }
// F-47-33：CRS 标签服务端分页 size-change 不复位 page——高页码叠加放大 pageSize
// 会请求越界 offset(空表停留在空页);对齐本文件自定义规则/IP 列表「size-change 回第 1 页」口径
const onRulesSizeChange = () => { page.value = 1; fetchRules() }
const fetchRules = async () => {
  loadingRules.value = true
  try { const p = new URLSearchParams({ page: String(page.value), page_size: String(pageSize.value) }); if (searchQuery.value) p.set('search', searchQuery.value); const res = await request.get<APIResponse<{ rules: CRSRuleFile[]; total: number }>>(`/security/crs/rules?${p}`); rules.value = res.data?.rules || []; total.value = res.data?.total || 0 } catch {} finally { loadingRules.value = false }
}
const fetchCustomRules = async () => { loadingCustom.value = true; try { const res = await request.get<APIResponse<CustomRule[]>>('/security/custom-rules'); customRules.value = res.data || [] } catch {} finally { loadingCustom.value = false } }
const fetchUsers = async () => { try { const res = await request.get<APIResponse<UserListItem[]>>('/users'); users.value = res.data || [] } catch {} }

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
const toggleAutoUpdate = async (val: boolean) => { try { await request.put('/security/crs/auto-update', { auto_update: val }); mfaAwareSuccess('已更新') } catch { crsInfo.value.auto_update = !val } }
const fetchIP2RegionInfo = async () => { try { const res = await request.get<APIResponse<typeof ip2regionInfo.value>>('/security/ip2region'); if (res.data) ip2regionInfo.value = res.data } catch {} }
const toggleIP2RegionAutoUpdate = async (val: boolean) => { try { await request.put('/security/ip2region/auto-update', { auto_update: val }); mfaAwareSuccess('已更新') } catch { ip2regionInfo.value.auto_update = !val } }

// —— 定时更新排程（三库同构：星期多选 + 时间；保存即重排下次更新，时区遵循基础设置）——
const scheduleTz = ref('')
let scheduleTzLoaded = false
const ensureScheduleTz = async () => {
  if (scheduleTzLoaded) return
  scheduleTzLoaded = true
  try {
    const res = await request.get<APIResponse<{ timezone?: string }>>('/config', { silent: true })
    scheduleTz.value = res.data?.timezone || ''
  } catch { /* 说明行降级为「…」，不影响设置功能 */ }
}

const savingCRSSchedule = ref(false)
const saveCRSSchedule = async ({ days, time }: { days: number[]; time: string }) => {
  savingCRSSchedule.value = true
  try {
    await request.put('/security/crs/schedule', { days, time })
    mfaAwareSuccess('定时更新设置已保存')
    await fetchCRS()
  } catch { /* 全局拦截器已 toast */ } finally { savingCRSSchedule.value = false }
}

const savingIP2RegionSchedule = ref(false)
const saveIP2RegionSchedule = async ({ days, time }: { days: number[]; time: string }) => {
  savingIP2RegionSchedule.value = true
  try {
    await request.put('/security/ip2region/schedule', { days, time })
    mfaAwareSuccess('定时更新设置已保存')
    await fetchIP2RegionInfo()
  } catch { /* 全局拦截器已 toast */ } finally { savingIP2RegionSchedule.value = false }
}

const savingThreatSchedule = ref(false)
const saveThreatSchedule = async ({ days, time }: { days: number[]; time: string }) => {
  savingThreatSchedule.value = true
  try {
    await request.put('/security/threat-lib/schedule', { days, time })
    mfaAwareSuccess('定时更新设置已保存')
    await fetchThreatLib()
  } catch { /* 全局拦截器已 toast */ } finally { savingThreatSchedule.value = false }
}

const updateDialogVisible = ref(false)
const updateInfo = ref<CRSUpdateInfo | null>(null)
const updateLog = ref('')
const updateLogRef = ref<HTMLDivElement | null>(null)
let updateRequestSeq = 0

const startingUpdate = ref(false)
const crsUpdateRunning = computed(() => {
  const s = updateInfo.value?.status || ''
  return s === 'checking' || s === 'downloading' || s === 'installing' || s === 'reloading'
})

const manualUpdate = () => {
  updateRequestSeq++
  updateInfo.value = null
  updateLog.value = ''
  updateDialogVisible.value = true
}

// 打开弹框只拉取一次当前状态与既有日志；若有任务在跑则继续实时轮询
const onUpdateDialogOpened = async () => {
  ensureScheduleTz()
  await refreshUpdateStatus()
  if (crsUpdateRunning.value) {
    startUpdatePolling()
  }
}

// 确认触发更新：409 表示已有任务在运行，跳过触发直接轮询进度
const confirmUpdate = async () => {
  startingUpdate.value = true
  try {
    await request.post<APIResponse<{ status: string; trigger: string }>>('/security/crs/update', undefined, { silent: true })
  } catch (error) {
    if (!(error instanceof ApiRequestError && error.status === 409)) {
      ElMessage.error(error instanceof Error ? error.message : '触发更新失败')
    }
  } finally {
    startingUpdate.value = false
  }
  if (!updateDialogVisible.value) return
  await refreshUpdateStatus()
  if (!updateDialogVisible.value) return
  startUpdatePolling()
}

const onUpdateDialogClosed = () => {
  updateRequestSeq++
  stopUpdatePolling()
  updateInfo.value = null
  updateLog.value = ''
}

// SR15-P3④:手写 setInterval → usePollingTask(后台标签页暂停/自动清理,
// 与 Dashboard 同源;两套重复裸轮询一并收敛)。
const crsUpdatePolling = usePollingTask(async () => { await refreshUpdateStatus() }, { interval: 2000 })

const startUpdatePolling = () => {
  crsUpdatePolling.resume()
}

const stopUpdatePolling = () => {
  // F-1:弹框会话级暂停(非终态)——stop 会永久 disposed,重开弹框即失效;
  // 组件卸载的终态清理由 usePollingTask 内置 onUnmounted 兜底。
  crsUpdatePolling.pause()
}

const refreshUpdateStatus = async () => {
  if (!updateDialogVisible.value) return
  const requestSeq = ++updateRequestSeq
  const [statusResult, logsResult] = await Promise.allSettled([
    request.get<APIResponse<CRSUpdateInfo>>('/security/crs/update/status', { silent: true }),
    request.get<APIResponse<{ content: string }>>('/security/crs/update/logs', { silent: true }),
  ])
  if (!updateDialogVisible.value || requestSeq !== updateRequestSeq) return
  if (statusResult.status === 'fulfilled') {
    updateInfo.value = statusResult.value.data || null
  } else {
    console.error('Failed to fetch CRS update status:', statusResult.reason)
  }
  if (logsResult.status === 'fulfilled') {
    updateLog.value = logsResult.value.data?.content || ''
    await scrollUpdateLogToBottom()
  } else {
    console.error('Failed to fetch CRS update logs:', logsResult.reason)
  }
  const status = updateInfo.value?.status
  if (status === 'success' || status === 'failed') {
    stopUpdatePolling()
    if (status === 'success') {
      fetchCRS()
      fetchRules()
    }
  }
}

const scrollUpdateLogToBottom = async () => {
  await nextTick()
  if (updateLogRef.value) {
    updateLogRef.value.scrollTop = updateLogRef.value.scrollHeight
  }
}

const ip2regionUpdateDialogVisible = ref(false)
const ip2regionUpdateInfo = ref<IP2RegionUpdateInfo | null>(null)
const ip2regionUpdateLog = ref('')
const ip2regionUpdateLogRef = ref<HTMLDivElement | null>(null)
let ip2regionRequestSeq = 0

const startingIP2RegionUpdate = ref(false)
const ip2regionUpdateRunning = computed(() => {
  const s = ip2regionUpdateInfo.value?.status || ''
  return s === 'checking' || s === 'downloading' || s === 'installing' || s === 'reloading'
})

const manualIP2RegionUpdate = () => {
  ip2regionRequestSeq++
  ip2regionUpdateInfo.value = null
  ip2regionUpdateLog.value = ''
  ip2regionUpdateDialogVisible.value = true
}

// 打开弹框只拉取一次当前状态与既有日志；若有任务在跑则继续实时轮询
const onIP2RegionUpdateDialogOpened = async () => {
  ensureScheduleTz()
  await refreshIP2RegionUpdateStatus()
  if (ip2regionUpdateRunning.value) {
    startIP2RegionPolling()
  }
}

// 确认触发更新：409 表示已有任务在运行，跳过触发直接轮询进度
const confirmIP2RegionUpdate = async () => {
  startingIP2RegionUpdate.value = true
  try {
    await request.post<APIResponse<{ status: string; trigger: string }>>('/security/ip2region/update', undefined, { silent: true })
  } catch (error) {
    if (!(error instanceof ApiRequestError && error.status === 409)) {
      ElMessage.error(error instanceof Error ? error.message : '触发更新失败')
    }
  } finally {
    startingIP2RegionUpdate.value = false
  }
  if (!ip2regionUpdateDialogVisible.value) return
  await refreshIP2RegionUpdateStatus()
  if (!ip2regionUpdateDialogVisible.value) return
  startIP2RegionPolling()
}

const onIP2RegionUpdateDialogClosed = () => {
  ip2regionRequestSeq++
  stopIP2RegionPolling()
  ip2regionUpdateInfo.value = null
  ip2regionUpdateLog.value = ''
}

// SR15-P3④:同 CRS 侧收敛。
const ip2regionUpdatePolling = usePollingTask(async () => { await refreshIP2RegionUpdateStatus() }, { interval: 2000 })

const startIP2RegionPolling = () => {
  ip2regionUpdatePolling.resume()
}

const stopIP2RegionPolling = () => {
  // F-1:同 CRS 侧,弹框会话级暂停。
  ip2regionUpdatePolling.pause()
}

const refreshIP2RegionUpdateStatus = async () => {
  if (!ip2regionUpdateDialogVisible.value) return
  const requestSeq = ++ip2regionRequestSeq
  const [statusResult, logsResult] = await Promise.allSettled([
    request.get<APIResponse<IP2RegionUpdateInfo>>('/security/ip2region/update/status', { silent: true }),
    request.get<APIResponse<{ content: string }>>('/security/ip2region/update/logs', { silent: true }),
  ])
  if (!ip2regionUpdateDialogVisible.value || requestSeq !== ip2regionRequestSeq) return
  if (statusResult.status === 'fulfilled') {
    ip2regionUpdateInfo.value = statusResult.value.data || null
  } else {
    console.error('Failed to fetch IP2Region update status:', statusResult.reason)
  }
  if (logsResult.status === 'fulfilled') {
    ip2regionUpdateLog.value = logsResult.value.data?.content || ''
    await scrollIP2RegionUpdateLogToBottom()
  } else {
    console.error('Failed to fetch IP2Region update logs:', logsResult.reason)
  }
  const status = ip2regionUpdateInfo.value?.status
  if (status === 'success' || status === 'failed') {
    stopIP2RegionPolling()
    if (status === 'success') {
      fetchIP2RegionInfo()
    }
  }
}

const scrollIP2RegionUpdateLogToBottom = async () => {
  await nextTick()
  if (ip2regionUpdateLogRef.value) {
    ip2regionUpdateLogRef.value.scrollTop = ip2regionUpdateLogRef.value.scrollHeight
  }
}

const openRuleDialog = (row?: CustomRule) => {
  editingRuleId.value = row?.id ?? null
  if (row) {
    // 存量空条件规则：自动补一条空条件行，让用户可见地修正而非卡在无法保存的死角
    const conditions = row.conditions.length ? [...row.conditions] : [{ target: 'uri', operator: 'contains', pattern: '' }]
    ruleForm.value = { name: row.name, description: row.description, conditions, action: row.action, score: row.score, enabled: row.enabled }
  } else {
    ruleForm.value = { name: '', description: '', conditions: [{ target: 'uri', operator: 'contains', pattern: '' }], action: 'block', score: 5, enabled: true }
  }
  ruleDialogVisible.value = true
}

const saveCustomRule = async () => {
  if (!ruleForm.value.name.trim()) { ElMessage.warning('请输入规则名称'); return }
  if (!ruleForm.value.conditions.length) { ElMessage.warning('至少需要一个匹配条件'); return }
  for (const cond of ruleForm.value.conditions) {
    if (!cond.pattern.trim()) { ElMessage.error('每个条件必须填写匹配值'); return }
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

const deleteCustomRule = (row: CustomRule) => {
  ElMessageBox.confirm(`确定删除规则"${row.name}"？`, '确认', { type: 'warning' })
    .then(async () => { const del = await request.delete(`/security/custom-rules/${row.id}`); showSaveResult(del, '已删除'); fetchCustomRules() }).catch(() => {})
}

const formatSize = (b: number) => b < 1024 ? `${b} B` : b < 1048576 ? `${(b/1024).toFixed(1)} KB` : `${(b/1048576).toFixed(1)} MB`

onMounted(() => {
  // FE43-1(第 43 轮):消费 ?tab= 后剥离(与 FE42-1 sp 口径一致,SecurityPolicies.vue
  // 先例)——视图切换走 authStore.currentPage 而非 hash 路由,replaceState 仅留
  // pathname 不破坏页面基座;仅当 URL 实际携带 tab 参数时才剥离。
  const query = new URLSearchParams(location.search)
  const urlTab = query.get('tab')
  if (urlTab && ['rules', 'custom', 'ip-lists'].includes(urlTab)) {
    activeTab.value = urlTab
  }
  if (query.has('tab')) window.history.replaceState(null, '', window.location.pathname)
  fetchCRS(); fetchIP2RegionInfo(); fetchRules(); fetchCustomRules(); fetchUsers(); fetchIpLists(); fetchThreatLib()
})

onUnmounted(() => {
  updateRequestSeq++
  stopUpdatePolling()
  ip2regionRequestSeq++
  stopIP2RegionPolling()
})
</script>

<style scoped>
/* SYSRENDER33-1(第 33 轮审计,P2):全局表格居中规则(main.css inline-flex
   nowrap+overflow hidden)把条件列多标签裁剪成单行——3/4 条件不可见。本列
   恢复换行展示(居中保持,scoped 属性选择器特异性高于全局规则)。 */
:deep(.el-table .cell:has(.el-tag)) { flex-wrap: wrap; row-gap: 4px; }
/* 自管标签行(EP 2.14.4 规避,同 ClusterModeCard 范式):复刻 EP
 * .el-form-item__label 计算样式(右对齐/32px 行高/12px 右内边距),
 * 宽度对齐本弹框 label-width=80px */
.mode-row { display: flex; margin-bottom: 18px; }
.mode-row-label { width: 80px; flex-shrink: 0; height: 32px; line-height: 32px; text-align: right; padding-right: 12px; box-sizing: border-box; color: var(--el-text-color-regular); font-size: var(--el-form-label-font-size, 14px); }
.mode-row-content { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 4px; }

.crs-card :deep(.el-card__header) .crs-header { display: flex; justify-content: space-between; align-items: center; width: 100%; }
.crs-card :deep(.el-card__header) .crs-header-title { display: flex; align-items: center; gap: 12px; }
.crs-card :deep(.el-card__header) .crs-header-actions { display: flex; gap: 8px; }
.crs-card :deep(.el-descriptions__table) { table-layout: fixed; width: 100%; }
.crs-card :deep(.el-descriptions__cell) { height: 48px; vertical-align: middle; }
.crs-card .ip2region-desc { margin-top: 20px; }
.crs-cell-flex { display: flex; align-items: center; height: 24px; }
.rule-condition-row {
  display: flex; gap: 10px; margin-bottom: 10px; align-items: flex-start; flex-wrap: wrap;
  padding: 12px; background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px;
  position: relative; transition: border-color 0.2s;
}
.rule-condition-row:hover { border-color: #d1d5db; }
.rule-condition-row .el-button--danger { margin-left: auto; }

/* ── 通用弹框头部(icon + 标题 + 副标题)── */
.dialog-header { display: flex; align-items: flex-start; gap: 12px; }
.dialog-header__icon {
  flex-shrink: 0; width: 36px; height: 36px; border-radius: 8px;
  background: #ecf5ff; color: #409eff;
  display: flex; align-items: center; justify-content: center;
}
.dialog-header__icon--danger { background: #fef0f0; color: #f56c6c; }
.dialog-header__title { font-size: 16px; font-weight: 600; color: var(--text-primary, #111827); line-height: 1.4; }
.dialog-header__subtitle { font-size: 12px; color: var(--text-secondary, #6b7280); margin-top: 2px; }
.add-condition-btn { margin-top: 4px; }
.pattern-col { flex: 1; min-width: 220px; display: flex; flex-direction: column; gap: 6px; }
.pattern-input-row { display: flex; align-items: center; gap: 6px; }
.preset-section { margin-top: 4px; }
.preset-header { cursor: pointer; padding: 2px 0; user-select: none; }
.preset-toggle { font-size: 12px; color: #6b7280; }
.preset-tags-block { display: flex; flex-direction: column; gap: 4px; padding: 6px 8px; background: #fff; border: 1px dashed #e5e7eb; border-radius: 4px; margin-left: 0; }
.preset-group { display: flex; align-items: baseline; gap: 8px; margin-bottom: 4px; }
.preset-group-label { font-size: 12px; color: #6b7280; flex: 0 0 56px; text-align: right; line-height: 1; }
.preset-hint { font-size: 12px; color: #9ca3af; margin-top: 6px; line-height: 1.4; }
.preset-group-tags { display: inline-flex; flex-wrap: wrap; gap: 4px; flex: 1; align-items: center; }
.preset-group-tags .el-tag { margin: 0; }
.preset-group-tags .preset-tag { cursor: pointer; }
.regex-extras { display: flex; flex-direction: column; gap: 6px; padding: 6px 8px; background: #fff; border: 1px dashed #e5e7eb; border-radius: 4px; }
.regex-presets { display: flex; flex-wrap: wrap; align-items: center; column-gap: 12px; row-gap: 4px; }
.regex-preset-link { font-size: 12px; }
.regex-tester { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.regex-test-input { width: 240px; }
.regex-test-result { font-size: 12px; font-weight: 500; white-space: nowrap; }
.regex-test-result.regex-match { color: #10b981; }
.regex-test-result.regex-nomatch { color: #ef4444; }
.regex-test-result.regex-invalid { color: #f59e0b; }
.add-condition-btn { margin-top: 4px; }
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
.rules-pagination { display: flex; justify-content: flex-end; margin-top: 16px; }
/* 弹框表单右缘留白（字段贴右边距视觉失衡，2026-09-24 用户反馈） */
.ip-list-dialog .el-form { padding-right: 20px; }
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

.threat-source-table { margin-bottom: 12px; }
.update-log-container { min-height: 320px; max-height: 480px; overflow: auto; background: #1e293b; border-radius: 6px; padding: 16px; }
.lib-summary-tags { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.lib-health-tag { margin: 0; }
.lib-summary-warn-text { color: #dc2626; font-weight: 600; font-size: 12px; margin-left: 4px; }

.lib-summary { color: #909399; font-size: 12px; font-weight: 400; }
.lib-name { display: flex; align-items: center; gap: 10px; min-width: 0; }
.lib-icon { flex-shrink: 0; width: 28px; height: 28px; border-radius: 7px; display: flex; align-items: center; justify-content: center; }
.lib-icon--crs { background: #eff6ff; color: #3b82f6; }
.lib-icon--ip { background: #f0fdfa; color: #0d9488; }
.lib-icon--threat { background: #fff1f2; color: #e11d48; }
.lib-name-text { min-width: 0; }
.update-log-container--compact { min-height: 200px; max-height: 240px; }
.lib-name-sub { color: #909399; font-size: 12px; word-break: break-all; }
.lib-version { font-family: 'SF Mono', 'Monaco', 'Menlo', monospace; font-size: 12px; }
.lib-count { font-variant-numeric: tabular-nums; }
.threat-url { color: #909399; font-size: 12px; word-break: break-all; }
.update-log-content { margin: 0; color: #e4e4e7; font-family: 'SF Mono', 'Monaco', 'Menlo', 'Consolas', monospace; font-size: 12px; line-height: 1.7; white-space: pre-wrap; word-break: break-all; }
</style>

<!-- el-tooltip popper 挂载到 body，scoped 样式无法命中，单独非 scoped 块 -->
<style>
.ip-list-refs-popper { line-height: 1.6; max-width: 280px; }
/* el-dialog 的 class 落在 .el-dialog 元素上（$attrs 手动绑定，非组件根），
   scoped 选择器无法命中，与上面 popper 同放非 scoped 块。
   统一加大弹框四向 padding（16→24px），条目表格不再贴右侧边缘，左右留白对称。 */
</style>
