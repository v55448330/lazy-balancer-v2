<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Key /></el-icon>
          {{ t('common.app.views.keys.pageTitle') }}
        </h2>
        <p class="page-desc">{{ t('common.app.views.keys.pageDesc') }}</p>
      </div>
    </div>

    <el-alert v-if="loadError" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
      <template #title>
        <div class="polling-error-title">
          <span>{{ t('common.app.views.keys.loadErrorBanner') }}</span>
          <el-button link type="danger" @click="fetchKeys">{{ t('common.app.views.keys.retryNow') }}</el-button>
        </div>
      </template>
    </el-alert>

    <el-tabs v-model="apiActiveTab">
      <el-tab-pane :label="t('app.notification.keysAccess.overviewTab')" name="overview">
        <AccessStatsCards :api-key-stats="apiKeyStats" :mcp-stats="mcpStats" :rest-stats="restOverview" />
        <div class="section-label">{{ t('app.notification.keysAccess.accessMethodTitle') }}</div>
        <el-row :gutter="16" class="keys-mcp-block">
          <el-col :xs="24" :md="12">
            <el-card class="access-card">
              <template #header>
                <div class="card-header">
                  <div class="card-title">
                    <el-icon class="title-icon"><Key /></el-icon>
                    <span>{{ t('app.notification.keysAccess.apiCardTitle') }}</span>
                  </div>
                  <div class="card-header-actions">
                    <el-switch v-if="isAdmin" v-model="apiEnabled" size="small" :disabled="switchSaving" :active-text="t('app.notification.keysAccess.apiEnabled')" @update:model-value="(val: string | number | boolean) => toggleApi(val === true)" />
                    <el-button size="small" tag="a" href="/api/v1/docs" target="_blank" rel="noopener noreferrer">
                      {{ t('common.app.views.keys.apiDocs') }}
                    </el-button>
                  </div>
                </div>
              </template>
              <div class="access-rows">
                <div class="access-row">
                  <span class="access-row-label">{{ t('app.notification.keysAccess.rowEndpoint') }}</span>
                  <code class="access-row-value">{{ restBaseURL }}</code>
                  <el-tooltip :content="t('common.app.views.keys.copy')" placement="top">
                    <el-button size="small" link :aria-label="t('common.app.views.keys.copy')" @click="copyRestBase">
                      <el-icon><CopyDocument /></el-icon>
                    </el-button>
                  </el-tooltip>
                </div>
                <div class="access-row">
                  <span class="access-row-label">{{ t('app.notification.keysAccess.rowAuth') }}</span>
                  <span class="access-row-value">{{ t('app.notification.keysAccess.authRest') }}</span>
                </div>
                <div class="access-row access-row-desc">
                  <span class="access-row-label">{{ t('app.notification.keysAccess.rowFor') }}</span>
                  <span class="access-row-value">{{ t('app.notification.keysAccess.apiCardDesc') }}</span>
                </div>
                <div class="access-note-slot">
                  <div v-if="isAdmin && !apiEnabled" class="info-note-bar"><span class="info-note-desc">{{ t('app.notification.keysAccess.apiDisabledNote') }}</span></div>
                </div>
              </div>
            </el-card>
          </el-col>
          <el-col :xs="24" :md="12">
            <el-card class="access-card">
              <template #header>
                <div class="card-header">
                  <div class="card-title">
                    <el-icon class="title-icon"><Connection /></el-icon>
                    <span>{{ t('app.notification.keysAccess.mcpCardTitle') }}</span>
                  </div>
                  <div class="card-header-actions">
                    <el-switch v-if="isAdmin" v-model="mcpEnabled" size="small" :disabled="switchSaving" :active-text="t('app.notification.creds.mcpEnabled')" @update:model-value="(val: string | number | boolean) => toggleMcp(val === true)" />
                    <el-button size="small" @click="mcpDocsVisible = true">
                      {{ t('common.app.views.keys.mcpDocs') }}
                    </el-button>
                  </div>
                </div>
              </template>
              <div class="access-rows">
                <div class="access-row">
                  <span class="access-row-label">{{ t('app.notification.keysAccess.rowEndpoint') }}</span>
                  <code class="access-row-value">{{ mcpServiceURL }}</code>
                  <el-tooltip :content="t('common.app.views.keys.copyMcpUrlAria')" placement="top">
                    <el-button size="small" link :aria-label="t('common.app.views.keys.copyMcpUrlAria')" @click="copyMCPServiceURL">
                      <el-icon><CopyDocument /></el-icon>
                    </el-button>
                  </el-tooltip>
                </div>
                <div class="access-row">
                  <span class="access-row-label">{{ t('app.notification.keysAccess.rowAuth') }}</span>
                  <span class="access-row-value">{{ t('app.notification.keysAccess.authMcp') }}</span>
                </div>
                <div class="access-row access-row-desc">
                  <span class="access-row-label">{{ t('app.notification.keysAccess.rowFor') }}</span>
                  <span class="access-row-value">{{ t('app.notification.keysAccess.mcpCardDesc') }}</span>
                </div>
                <div class="access-note-slot">
                  <div v-if="isAdmin && !mcpEnabled" class="info-note-bar"><span class="info-note-desc">{{ t('app.notification.keysSessions.mcpDisabledNote') }}</span></div>
                </div>
              </div>
            </el-card>
          </el-col>
        </el-row>
        <!-- MCP 会话（与 API 最近调用对称：会话=有状态连接的在线视图） -->
        <McpSessionsCard />

      </el-tab-pane>
      <el-tab-pane :label="t('app.notification.keysAccess.keysTab')" name="keys">
        <el-card class="list-card">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon"><Key /></el-icon>
                <span>{{ t('app.notification.keysAccess.keysTab') }}</span>
              </div>
              <div class="card-header-actions">
                <el-switch v-if="isAdmin" v-model="keysMineOnly" size="small" :active-text="t('app.notification.keysAccess.mineOnly')" @change="fetchKeys" />
                <el-tooltip :disabled="!nodeWriteBlocked" :content="nodeWriteBlockedReason">
                  <div>
                    <el-button type="primary" size="small" :disabled="nodeWriteBlocked || creating" @click="openCreateDialog">
                      <el-icon><Plus /></el-icon>
                      {{ t('common.app.views.keys.createKey') }}
                    </el-button>
                  </div>
                </el-tooltip>
              </div>
            </div>
          </template>
    <el-table
      v-loading="loading"
      :data="tableKeys"
      stripe
      :header-cell-style="{ background: '#f9fafb' }"
      class="keys-table"
      :empty-text="t('common.app.views.keys.emptyText')"
    >
      <el-table-column :label="t('common.app.views.keys.name')" min-width="160">
        <template #default="scope">
          <el-button link type="primary" class="key-name-cell" @click="openKeyDetail(asKey(scope.row))">{{ scope.row.name }}</el-button>
          <el-tag v-if="isAdmin && !keysMineOnly && scope.row.created_by !== authStore.user?.id" size="small" effect="plain" class="ml4">{{ scope.row.username }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="t('common.app.views.keys.status')" width="90" align="center">
        <template #default="scope">
          <el-tag v-if="keyExpired(asKey(scope.row))" type="danger" size="small">{{ t('common.app.views.keys.expiredTag') }}</el-tag>
          <el-tag v-else :type="scope.row.is_enabled ? 'success' : 'info'" size="small">
            {{ scope.row.is_enabled ? t('common.app.views.keys.enabledTag') : t('common.app.views.keys.disabledTag') }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="t('common.app.views.keys.features')" min-width="200">
        <template #default="scope">
          <div class="feature-tags">
            <el-tag :type="scope.row.api_enabled ? 'primary' : 'info'" size="small" effect="plain">
              API {{ scope.row.api_enabled ? t('common.app.views.keys.on') : t('common.app.views.keys.off') }}
            </el-tag>
            <el-tag :type="scope.row.mcp_enabled ? 'primary' : 'info'" size="small" effect="plain">
              MCP {{ scope.row.mcp_enabled ? t('common.app.views.keys.on') : t('common.app.views.keys.off') }}
            </el-tag>
            <el-tag :type="scope.row.api_read_only ? 'warning' : 'success'" size="small" effect="plain">
              API {{ scope.row.api_read_only ? t('common.app.views.keys.readOnly') : t('common.app.views.keys.readWrite') }}
            </el-tag>
            <el-tag :type="scope.row.mcp_read_only ? 'warning' : 'success'" size="small" effect="plain">
              MCP {{ scope.row.mcp_read_only ? t('common.app.views.keys.readOnly') : t('common.app.views.keys.readWrite') }}
            </el-tag>
            <el-tooltip v-if="whitelistEntries(asKey(scope.row).mcp_ip_whitelist).length" :content="whitelistSummary(asKey(scope.row).mcp_ip_whitelist)" placement="top">
              <el-tag type="warning" size="small" effect="plain">{{ t('common.app.views.keys.ipWhitelist') }}</el-tag>
            </el-tooltip>
          </div>
        </template>
      </el-table-column>
      <el-table-column :label="t('common.app.views.keys.createdAt')" width="170">
        <template #default="scope">{{ formatDate(scope.row.created_at) || '-' }}</template>
      </el-table-column>
      <el-table-column :label="t('common.app.views.keys.updatedAt')" width="170">
        <template #default="scope">
          {{ formatDate(scope.row.updated_at) || '-' }}
          <span v-if="scope.row.updated_by_username" class="ev-more">· {{ scope.row.updated_by_username }}</span>
        </template>
      </el-table-column>
      <el-table-column :label="t('common.app.views.keys.lastUsed')" width="170">
        <template #default="scope">{{ formatDate(scope.row.last_used) || t('common.app.views.keys.neverUsed') }}</template>
      </el-table-column>
      <el-table-column :label="t('common.app.views.keys.expiresAt')" width="170">
        <template #default="scope">{{ formatDate(scope.row.expires_at) || t('common.app.views.keys.neverExpires') }}</template>
      </el-table-column>
      <el-table-column :label="t('app.notification.deliveries.colAction')" width="170" align="right" fixed="right">
        <template #default="scope">
          <el-tooltip :disabled="!nodeWriteBlocked" :content="nodeWriteBlockedReason">
            <div class="row-actions">
              <el-button size="small" link type="primary" :disabled="nodeWriteBlocked || togglePendingId === scope.row.id || deletingIds.has(scope.row.id)" @click="openFeatureDialog(asKey(scope.row))">
                {{ t('common.app.views.keys.featureConfig') }}
              </el-button>
              <el-button size="small" link :type="scope.row.is_enabled ? 'warning' : 'success'" :loading="togglePendingId === scope.row.id" :disabled="nodeWriteBlocked || (togglePendingId !== null && togglePendingId !== scope.row.id) || deletingIds.has(scope.row.id)" @click="toggleKey(asKey(scope.row))">
                {{ scope.row.is_enabled ? t('common.app.views.keys.disable') : t('common.app.views.keys.enable') }}
              </el-button>
              <el-button size="small" link type="danger" :loading="deletingIds.has(scope.row.id)" :disabled="nodeWriteBlocked || togglePendingId === scope.row.id || deletingIds.has(scope.row.id)" @click="deleteKey(scope.row.id)">
                {{ t('common.app.views.keys.delete') }}
              </el-button>
            </div>
          </el-tooltip>
        </template>
      </el-table-column>
    </el-table>

    <el-empty v-if="!loading && keys.length === 0 && !loadError" :description="t('common.app.views.keys.emptyText')" :image-size="80" />
    </el-card>
      </el-tab-pane>
    </el-tabs>

    <el-dialog
      v-model="mcpDocsVisible"
      class="mcp-docs-dialog dialog-body-inset"
      width="min(1000px, 96vw)"
      top="5vh"
      @opened="fetchMCPTools"
    >
      <template #header>
        <DialogHeader :icon="SetUp" :title="t('common.app.views.keys.mcpDocsTitle')" :subtitle="t('common.app.views.keys.mcpDocsSubtitle')" />
      </template>
      <section class="dialog-panel mcp-connection-panel">
        <DialogSectionHeader :title="t('common.app.views.keys.connectionSection')" :description="t('common.app.views.keys.connectionDesc')" />
      <el-form label-position="top">
        <el-form-item :label="t('common.app.views.keys.mcpUrlLabel')">
          <el-input :model-value="mcpServiceURL" readonly>
            <template #append>
              <el-button :aria-label="t('common.app.views.keys.copyMcpUrlAria')" @click="copyMCPServiceURL">
                <el-icon><CopyDocument /></el-icon>
                {{ t('common.app.views.keys.copy') }}
              </el-button>
            </template>
          </el-input>
        </el-form-item>
        <el-form-item :label="t('common.app.views.keys.mcpConfigLabel')">
          <div style="width: 100%">
            <el-input
              class="mcp-config-json"
              type="textarea"
              :model-value="mcpConfigJSON"
              readonly
              :rows="13"
            />
            <div class="mcp-config-toolbar">
              <el-button size="small" @click="copyMCPConfig">
                <el-icon><CopyDocument /></el-icon>
                {{ t('common.app.views.keys.copyConfig') }}
              </el-button>
            </div>
            <div class="info-note-bar">
              <span class="info-note-desc">{{ t('common.app.views.keys.certHint') }}</span>
            </div>
          </div>
        </el-form-item>
      </el-form>
      </section>

      <div class="info-note-bar"><span class="info-note-desc">{{ t('common.app.views.keys.apiKeyHeaderNote') }}</span></div>

      <el-collapse class="mcp-agent-guide">
        <el-collapse-item :title="t('common.app.views.keys.agentGuideTitle')" name="agent-guide">
          <div class="mcp-guide-block">
            <section class="dialog-panel">
              <DialogSectionHeader :title="t('common.app.views.keys.protocolFlowTitle')" :description="t('common.app.views.keys.protocolFlowDesc', { url: mcpServiceURL })" />
            <pre class="mcp-guide-pre">{{ t('common.app.views.keys.flowInitStep') }}
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"your-agent","version":"1.0"}}}

{{ t('common.app.views.keys.flowListStep') }}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}

{{ t('common.app.views.keys.flowCallStep') }}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_metrics_overview","arguments":{}}}</pre>
            </section>
            <section class="dialog-panel">
              <DialogSectionHeader :title="t('common.app.views.keys.selfSignedTitle')" :description="t('common.app.views.keys.optionalConfig')" />
            <div class="mcp-guide-text">{{ t('common.app.views.keys.certFixA') }} <code>NODE_TLS_REJECT_UNAUTHORIZED=0</code>{{ t('common.app.views.keys.certFixB') }}</div>
            </section>
            <section class="dialog-panel">
              <DialogSectionHeader :title="t('common.app.views.keys.commonErrorsTitle')" />
            <div class="mcp-guide-text">{{ t('common.app.views.keys.commonErrorsBody') }}</div>
            </section>
            <section class="dialog-panel">
              <DialogSectionHeader :title="t('common.app.views.keys.scopeTitle')" />
            <div class="mcp-guide-text">{{ t('common.app.views.keys.scopeBodyA') }} <code>lazy-balancer://docs/ops-playbook</code> {{ t('common.app.views.keys.scopeBodyB') }}</div>
            </section>
            <section class="dialog-panel">
              <DialogSectionHeader :title="t('common.app.views.keys.commonFlowsTitle')" />
            <pre class="mcp-guide-pre">{{ t('common.app.views.keys.commonFlowsBody') }}</pre>
            </section>
            <section class="dialog-panel">
              <DialogSectionHeader :title="t('common.app.views.keys.playbookTitle')" />
            <div class="mcp-guide-text">{{ t('common.app.views.keys.playbookA') }} <code>resources/read</code> {{ t('common.app.views.keys.playbookRead') }} <code>lazy-balancer://docs/ops-playbook</code> {{ t('common.app.views.keys.playbookC') }}</div>
            <el-button size="small" :loading="mcpPlaybookDownloading" @click="downloadMCPPlaybook">{{ t('common.app.views.keys.downloadPlaybook') }}</el-button>
            </section>
          </div>
        </el-collapse-item>
        <el-collapse-item :title="t('common.app.views.keys.toolListTitle')" name="tools-list">
          <div class="info-note-bar mcp-table-scroll-hint"><span class="info-note-desc">{{ t('common.app.views.keys.toolListScrollHint') }}</span></div>
          <div v-loading="mcpToolsLoading" class="mcp-tools-table">
            <div v-if="mcpToolsError" class="info-note-bar">
              <span class="info-note-desc">{{ mcpToolsError }}</span>
              <span class="info-note-sub"><el-button size="small" @click="fetchMCPTools">{{ t('common.app.views.keys.reload') }}</el-button></span>
            </div>
            <div v-else class="dialog-panel dialog-panel--flush">
            <el-table :data="mcpTools" stripe max-height="38vh" :empty-text="t('common.app.views.keys.noTools')">
              <el-table-column type="expand">
                <template #default="scope">
                  <div class="mcp-tool-expand">
                    <div v-if="scope.row.usage" class="mcp-tool-usage"><span class="mcp-expand-label">{{ t('common.app.views.keys.usageLabel') }}</span>{{ scope.row.usage }}</div>
                    <template v-if="scope.row.input_schema">
                      <div class="mcp-expand-label">{{ t('common.app.views.keys.schemaLabel') }}</div>
                      <pre class="mcp-schema-pre">{{ formatSchema(scope.row.input_schema) }}</pre>
                    </template>
                    <div v-else class="mcp-tool-usage"><span class="mcp-expand-label">{{ t('common.app.views.keys.paramsLabel') }}</span>{{ t('common.app.views.keys.noParams') }}</div>
                  </div>
                </template>
              </el-table-column>
              <el-table-column prop="name" :label="t('common.app.views.keys.nameCol')" min-width="180" />
              <el-table-column :label="t('common.app.views.keys.descCol')" min-width="260">
                <template #default="scope">
                  <span class="mcp-tool-description">{{ scope.row.description }}</span>
                </template>
              </el-table-column>
              <el-table-column :label="t('common.app.views.keys.methodPathCol')" min-width="260">
                <template #default="scope">
                  <code>{{ scope.row.method }} {{ scope.row.path }}</code>
                </template>
              </el-table-column>
              <el-table-column :label="t('common.app.views.keys.typeCol')" width="90" align="center">
                <template #default="scope">
                  <el-tag :type="scope.row.read_only ? 'success' : 'warning'" size="small">
                    {{ scope.row.read_only ? t('common.app.views.keys.readOnly') : t('common.app.views.keys.write') }}
                  </el-tag>
                </template>
              </el-table-column>
            </el-table>
            </div>
          </div>
        </el-collapse-item>
      </el-collapse>
    </el-dialog>

    <el-dialog
      v-model="createDialogVisible"
      class="dialog-body-inset"
      width="min(620px, 92vw)"
      :close-on-click-modal="false"
      :close-on-press-escape="!creating"
      :show-close="!creating"
      top="6vh"
      @closed="resetCreateForm"
    >
      <template #header>
        <DialogHeader :icon="Key" :title="t('common.app.views.keys.createKeyTitle')" :subtitle="t('common.app.views.keys.createKeySubtitle')" tone="warning" />
      </template>
      <el-form :label-width="$flw('110px')" :disabled="creating">
        <el-form-item :label="t('common.app.views.keys.keyName')" :error="createNameError">
          <el-input v-model="createForm.name" maxlength="100" show-word-limit :placeholder="t('common.app.views.keys.enterKeyName')" @input="createNameError = ''" />
        </el-form-item>
        <el-divider content-position="left" class="section-divider">{{ t('common.app.views.keys.permSection') }}</el-divider>
        <!-- 双协议对称：接入开关 + 各自只读（管理员可分别设置；非管理员恒只读） -->
        <div class="perm-grid">
          <div class="perm-col">
            <div class="perm-col-title">REST API</div>
            <el-form-item :label="t('common.app.views.keys.apiFeature')">
              <el-switch v-model="createForm.api_enabled" />
            </el-form-item>
            <el-form-item :label="t('common.app.views.keys.readOnlyMode')">
              <el-tooltip :disabled="isAdmin" :content="t('common.app.views.keys.readOnlyOnlyTip')" placement="top">
                <el-switch v-model="createForm.api_read_only" :disabled="!isAdmin" />
              </el-tooltip>
            </el-form-item>
          </div>
          <div class="perm-col">
            <div class="perm-col-title">MCP</div>
            <el-form-item :label="t('common.app.views.keys.mcpFeature')">
              <el-switch v-model="createForm.mcp_enabled" />
            </el-form-item>
            <el-form-item :label="t('common.app.views.keys.readOnlyMode')">
              <el-tooltip :disabled="isAdmin" :content="t('common.app.views.keys.readOnlyOnlyTip')" placement="top">
                <el-switch v-model="createForm.mcp_read_only" :disabled="!isAdmin" />
              </el-tooltip>
            </el-form-item>
          </div>
        </div>
        <div class="info-note-bar"><span class="info-note-desc">{{ t('common.app.views.keys.permHint') }}</span></div>
        <div v-if="!isAdmin" class="info-note-bar readonly-alert"><span class="info-note-desc">{{ t('common.app.views.keys.readOnlyOnlyTip') }}</span></div>
        <el-divider content-position="left" class="section-divider">{{ t('common.app.views.keys.expirySourceSection') }}</el-divider>
        <el-form-item :label="t('common.app.views.keys.expiresAt')" :error="createExpiresError">
          <el-date-picker
            v-model="createForm.expiresAt"
            type="datetime"
            clearable
            format="YYYY-MM-DD HH:mm:ss"
            :disabled-date="disablePastDate"
            :placeholder="t('common.app.views.keys.expiresPlaceholder')"
            style="width: 100%"
            @change="createExpiresError = ''"
          />
        </el-form-item>
        <el-form-item :label="t('common.app.views.keys.ipWhitelist')" :error="createWhitelistError">
          <el-input
            v-model="createForm.whitelistText"
            type="textarea"
            :rows="5"
            resize="vertical"
            :placeholder="t('common.app.views.keys.whitelistPlaceholder')"
            @input="createWhitelistError = ''"
          />
        </el-form-item>
        <div class="info-note-bar"><span class="info-note-desc">{{ t('common.app.views.keys.whitelistNote') }}</span></div>
      </el-form>
      <template #footer>
        <el-button :disabled="creating" @click="createDialogVisible = false">{{ t('common.app.views.keys.cancel') }}</el-button>
        <el-button type="primary" :loading="creating" @click="createKey">{{ t('common.app.views.keys.createBtn') }}</el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="featureDialogVisible"
      class="dialog-body-inset"
      width="min(620px, 92vw)"
      :close-on-click-modal="false"
      :close-on-press-escape="!featureSaving"
      :show-close="!featureSaving"
      top="6vh"
      @closed="resetFeatureForm"
    >
      <template #header>
        <DialogHeader :icon="Setting" :title="t('common.app.views.keys.featureConfig')" :subtitle="t('common.app.views.keys.featureTargetSubtitle', { name: featureTarget?.name || '' })" />
      </template>
      <el-form :label-width="$flw('110px')" :disabled="featureSaving">
        <el-divider content-position="left" class="section-divider">{{ t('common.app.views.keys.permSection') }}</el-divider>
        <div class="perm-grid">
          <div class="perm-col">
            <div class="perm-col-title">REST API</div>
            <el-form-item :label="t('common.app.views.keys.apiFeature')">
              <el-switch v-model="featureForm.api_enabled" />
            </el-form-item>
            <el-form-item :label="t('common.app.views.keys.readOnlyMode')">
              <el-tooltip :disabled="isAdmin" :content="t('common.app.views.keys.readOnlyOnlyTip')" placement="top">
                <el-switch v-model="featureForm.api_read_only" :disabled="!isAdmin" />
              </el-tooltip>
            </el-form-item>
          </div>
          <div class="perm-col">
            <div class="perm-col-title">MCP</div>
            <el-form-item :label="t('common.app.views.keys.mcpFeature')">
              <el-switch v-model="featureForm.mcp_enabled" />
            </el-form-item>
            <el-form-item :label="t('common.app.views.keys.readOnlyMode')">
              <el-tooltip :disabled="isAdmin" :content="t('common.app.views.keys.readOnlyOnlyTip')" placement="top">
                <el-switch v-model="featureForm.mcp_read_only" :disabled="!isAdmin" />
              </el-tooltip>
            </el-form-item>
          </div>
        </div>
        <div class="info-note-bar"><span class="info-note-desc">{{ t('common.app.views.keys.permHint') }}</span></div>
        <div v-if="!isAdmin" class="info-note-bar readonly-alert"><span class="info-note-desc">{{ t('common.app.views.keys.readOnlyOnlyTip') }}</span></div>
        <el-divider content-position="left" class="section-divider">{{ t('common.app.views.keys.sourceRestrictSection') }}</el-divider>
        <el-form-item :label="t('common.app.views.keys.ipWhitelist')" :error="featureWhitelistError">
          <el-input
            v-model="featureForm.whitelistText"
            type="textarea"
            :rows="5"
            resize="vertical"
            :placeholder="t('common.app.views.keys.whitelistPlaceholder')"
            @input="featureWhitelistError = ''"
          />
        </el-form-item>
        <div class="info-note-bar"><span class="info-note-desc">{{ t('common.app.views.keys.whitelistNote') }}</span></div>
      </el-form>
      <template #footer>
        <el-button :disabled="featureSaving" @click="featureDialogVisible = false">{{ t('common.app.views.keys.cancel') }}</el-button>
        <el-button type="primary" :loading="featureSaving" @click="saveFeatures">{{ t('common.app.views.keys.save') }}</el-button>
      </template>
    </el-dialog>

    <!-- 密钥详情弹窗：名称点击触发，只读全量信息（前缀/属主/权限/时间） -->
    <el-dialog v-model="keyDetailVisible" class="dialog-body-inset" width="min(620px, 92vw)" top="6vh">
      <template #header>
        <DialogHeader :icon="Key" :title="t('common.app.views.keys.detailTitle')" :subtitle="keyDetailTarget?.name || ''" />
      </template>
      <el-descriptions v-if="keyDetailTarget" :column="1" border size="small">
        <el-descriptions-item :label="t('common.app.views.keys.name')">{{ keyDetailTarget.name }}</el-descriptions-item>
        <el-descriptions-item :label="t('common.app.views.keys.keyPrefix')"><code>{{ keyDetailTarget.key_prefix || '-' }}</code></el-descriptions-item>
        <el-descriptions-item :label="t('common.app.views.keys.status')">
          <el-tag v-if="keyExpired(keyDetailTarget)" type="danger" size="small">{{ t('common.app.views.keys.expiredTag') }}</el-tag>
          <el-tag v-else :type="keyDetailTarget.is_enabled ? 'success' : 'info'" size="small">{{ keyDetailTarget.is_enabled ? t('common.app.views.keys.enabledTag') : t('common.app.views.keys.disabledTag') }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item :label="t('common.app.views.keys.owner')">{{ keyDetailTarget.username || ('#' + keyDetailTarget.created_by) }}</el-descriptions-item>
        <el-descriptions-item :label="t('common.app.views.keys.features')">
          <div class="feature-tags">
            <el-tag :type="keyDetailTarget.api_enabled ? 'primary' : 'info'" size="small" effect="plain">API {{ keyDetailTarget.api_enabled ? t('common.app.views.keys.on') : t('common.app.views.keys.off') }}</el-tag>
            <el-tag :type="keyDetailTarget.mcp_enabled ? 'primary' : 'info'" size="small" effect="plain">MCP {{ keyDetailTarget.mcp_enabled ? t('common.app.views.keys.on') : t('common.app.views.keys.off') }}</el-tag>
            <el-tag :type="keyDetailTarget.api_read_only ? 'warning' : 'success'" size="small" effect="plain">API {{ keyDetailTarget.api_read_only ? t('common.app.views.keys.readOnly') : t('common.app.views.keys.readWrite') }}</el-tag>
            <el-tag :type="keyDetailTarget.mcp_read_only ? 'warning' : 'success'" size="small" effect="plain">MCP {{ keyDetailTarget.mcp_read_only ? t('common.app.views.keys.readOnly') : t('common.app.views.keys.readWrite') }}</el-tag>
          </div>
        </el-descriptions-item>
        <el-descriptions-item v-if="whitelistEntries(keyDetailTarget.mcp_ip_whitelist).length" :label="t('common.app.views.keys.ipWhitelist')">{{ whitelistSummary(keyDetailTarget.mcp_ip_whitelist) }}</el-descriptions-item>
        <el-descriptions-item :label="t('common.app.views.keys.createdAt')">{{ formatDate(keyDetailTarget.created_at) || '-' }}</el-descriptions-item>
        <el-descriptions-item :label="t('common.app.views.keys.updatedAt')">{{ formatDate(keyDetailTarget.updated_at) || '-' }}<span v-if="keyDetailTarget.updated_by_username" class="ev-more"> · {{ keyDetailTarget.updated_by_username }}</span></el-descriptions-item>
        <el-descriptions-item :label="t('common.app.views.keys.lastUsed')">{{ formatDate(keyDetailTarget.last_used) || t('common.app.views.keys.neverUsed') }}</el-descriptions-item>
        <el-descriptions-item :label="t('common.app.views.keys.expiresAt')">{{ formatDate(keyDetailTarget.expires_at) || t('common.app.views.keys.neverExpires') }}</el-descriptions-item>
      </el-descriptions>
      <template #footer>
        <el-button @click="keyDetailVisible = false">{{ t('common.app.views.keys.close') }}</el-button>
        <el-button type="primary" :disabled="nodeWriteBlocked" @click="keyDetailVisible = false; openFeatureDialog(keyDetailTarget!)">{{ t('common.app.views.keys.featureConfig') }}</el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="createdKeyVisible"
      class="dialog-body-inset"
      width="min(560px, 92vw)"
      :close-on-click-modal="false"
      :before-close="closeCreatedKey"
      @closed="createdKey = ''"
    >
      <template #header>
        <DialogHeader :icon="CircleCheckFilled" :title="t('common.app.views.keys.createdTitle')" :subtitle="t('common.app.views.keys.createdSubtitle')" tone="success" />
      </template>
      <div class="info-note-bar"><span class="info-note-desc">{{ t('common.app.views.keys.createdNote') }}</span></div>
      <div class="dialog-panel created-key-box">
        <code class="created-key-text">{{ createdKey }}</code>
        <el-button type="primary" @click="copyCreatedKey">
          <el-icon><CopyDocument /></el-icon>
          {{ t('common.app.views.keys.copyKey') }}
        </el-button>
      </div>
      <template #footer>
        <el-button type="primary" @click="createdKeyVisible = false">{{ t('common.app.views.keys.savedAck') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted } from 'vue'
import { request, mfaAwareSuccess } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import { formatDate } from '@/utils/date'
import { parseWhitelist, serializeWhitelist } from '@/utils/apiKeyWhitelist'
import { copyText } from '@/utils/copy'
import { createOneTimeSecretCloseGuard } from '@/utils/oneTimeSecretGuard'
import { saveBlob } from '@/utils/download'
import { ElMessageBox, ElMessage } from 'element-plus'
import { CircleCheckFilled, Connection, CopyDocument, Key, Plus, Setting, SetUp } from '@element-plus/icons-vue'
import type { APIKey, APIResponse, CreateAPIKeyInput, MCPToolSpec, UpdateAPIKeyInput } from '@/types'
import type { McpStats, McpStatsResponse } from '@/types/notifications.ts'
import { useI18n } from 'vue-i18n'
import DialogHeader from '@/components/DialogHeader.vue'
import DialogSectionHeader from '@/components/DialogSectionHeader.vue'
import McpSessionsCard from './settings/McpSessionsCard.vue'
import AccessStatsCards from './settings/AccessStatsCards.vue'

const { t } = useI18n()

interface CreateAPIKeyResponse {
  readonly data?: {
    readonly id: number
    readonly key: string
    readonly message: string
  }
}

const authStore = useAuthStore()
// MCP 调用统计（管理员）：/notification/mcp/stats，统计卡单次拉取
const mcpStats = ref<McpStats | null>(null)
// REST 调用统计（内存环形采集：今日调用/错误率/最近调用）
const restOverview = ref<{ today_calls: number; error_rate: number; recent_calls: { time: string; key_name: string; method: string; path: string; ip: string; status: number }[]; trend: { date: string; calls: number }[] } | null>(null)
const fetchMcpStats = async (): Promise<void> => {
  if (!isAdmin.value) return
  try {
    const res = await request.get<McpStatsResponse>('/notification/mcp/stats')
    mcpStats.value = res.data ?? null
  } catch (error: unknown) {
    // 统计缺失不阻断密钥管理主功能；全局拦截器已提示
    console.error('Failed to fetch MCP usage stats:', error)
    mcpStats.value = null
  }
  try {
    const r = await request.get<{ code: number; data?: { rest: typeof restOverview.value } }>('/api-keys/access-overview', { silent: true })
    restOverview.value = r.data?.rest ?? null
  } catch (error: unknown) {
    console.error('Failed to fetch REST call overview:', error)
    restOverview.value = null
  }
}
// 从节点判定走 store 单源；节点模式未知仍按既有契约 fail-closed。
// 主节点非 admin 可管理本人密钥，因此不能复用全站 non-admin 只读门。
const nodeWriteBlocked = computed(() => authStore.isSlaveNode || authStore.readOnlyReason === 'unknown')
const nodeWriteBlockedReason = computed(() => authStore.isSlaveNode ? t('common.app.views.keys.slaveReadOnly') : t('common.app.views.keys.nodeUnknownReadOnly'))
const isAdmin = computed(() => authStore.user?.role === 'admin')

const keys = ref<readonly APIKey[]>([])
const tableKeys = computed<APIKey[]>(() => [...keys.value])
const asKey = (row: unknown): APIKey => row as APIKey
const loading = ref(false)
// 加载失败不得呈现为「暂无 API 密钥」——显性错误态 + 重试
const loadError = ref(false)
// API 密钥统计（与 MCP 统计卡并列同形态）：数据全部来自密钥列表现成字段
// （总数/启用数/近 7 天活跃=last_used），不虚报调用计数
const ACTIVE_WINDOW_MS = 7 * 24 * 60 * 60 * 1000
const apiKeyStats = computed(() => {
  const activeThreshold = Date.now() - ACTIVE_WINDOW_MS
  let enabled = 0
  let active7d = 0
  for (const key of keys.value) {
    if (key.is_enabled) enabled += 1
    const lastUsed = key.last_used ? new Date(key.last_used).getTime() : NaN
    if (Number.isFinite(lastUsed) && lastUsed >= activeThreshold) active7d += 1
  }
  return { total: keys.value.length, enabled, active7d }
})
const creating = ref(false)
const createDialogVisible = ref(false)
const createNameError = ref('')
const createWhitelistError = ref('')
const createExpiresError = ref('')
const createForm = ref({ name: '', mcp_enabled: false, api_enabled: true, api_read_only: true, mcp_read_only: true, whitelistText: '', expiresAt: null as Date | null })
const featureDialogVisible = ref(false)
const featureSaving = ref(false)
const featureTarget = ref<APIKey | null>(null)
const keyDetailVisible = ref(false)
const keyDetailTarget = ref<APIKey | null>(null)
const openKeyDetail = (key: APIKey): void => { keyDetailTarget.value = key; keyDetailVisible.value = true }
const featureWhitelistError = ref('')
const featureForm = ref({ mcp_enabled: false, api_enabled: true, api_read_only: false, mcp_read_only: false, whitelistText: '' })
const keysMineOnly = ref(true) // 管理员默认看自己；关闭=全平台（可操作他人 key，明文不可见）
const togglePendingId = ref<number | null>(null)
const deletingIds = ref(new Set<number>())
const createdKey = ref('')
const createdKeyVisible = ref(false)
/** 明文密钥仅此一次下发（库内只存哈希）：ESC / 右上角 X 关闭前必须确认已保存，
 *  否则误触即永久丢失、只能删除重建（一次性凭据守卫单源——与集群注册令牌、
 *  MFA 恢复码同实现）。 */
const closeCreatedKey = createOneTimeSecretCloseGuard({
  message: t('common.app.views.keys.closeGuardMessage'),
  title: t('common.app.views.keys.closeGuardTitle'),
})
const mcpDocsVisible = ref(false)
const mcpTools = ref<MCPToolSpec[]>([])
const mcpToolsLoading = ref(false)
const mcpToolsLoaded = ref(false)
const mcpToolsError = ref('')
const apiActiveTab = ref('overview')
const mcpServiceURL = new URL('/api/v1/mcp', window.location.origin).toString()
const restBaseURL = new URL('/api/v1', window.location.origin).toString()

// 对外接入全局开关（API/MCP 对称；管理员可切换，普通用户只读不显示）
const apiEnabled = ref(true)
const mcpEnabled = ref(true)
const switchSaving = ref(false)
const fetchAccessSwitches = async (): Promise<void> => {
  if (!isAdmin.value) return
  try {
    const res = await request.get<{ data?: { api_enabled?: boolean; mcp_enabled?: boolean } }>('/notification/settings', { silent: true })
    apiEnabled.value = res.data?.api_enabled !== false
    mcpEnabled.value = res.data?.mcp_enabled !== false
  } catch { /* 缺省启用 */ }
}
const toggleApi = async (on: boolean): Promise<void> => {
  if (switchSaving.value) return
  switchSaving.value = true
  try {
    await request.put('/notification/settings', { api_enabled: on })
    mfaAwareSuccess(on ? t('app.notification.keysAccess.apiEnabledToast') : t('app.notification.keysAccess.apiDisabledToast'))
  } catch {
    apiEnabled.value = !on
  } finally { switchSaving.value = false }
}
const toggleMcp = async (on: boolean): Promise<void> => {
  if (switchSaving.value) return
  switchSaving.value = true
  try {
    await request.put('/notification/settings', { mcp_enabled: on })
    mfaAwareSuccess(on ? t('app.notification.keysSessions.mcpEnabledToast') : t('app.notification.keysSessions.mcpDisabledToast'))
  } catch {
    mcpEnabled.value = !on
  } finally { switchSaving.value = false }
}
const mcpConfigJSON = computed(() => JSON.stringify({
  mcpServers: {
    'lazy-balancer': {
      transport: 'streamable_http',
      url: mcpServiceURL,
      headers: { 'X-API-Key': '<YOUR_API_KEY>' },
    },
  },
}, null, 2))
const copyMCPConfig = async (): Promise<void> => {
  if (await copyText(mcpConfigJSON.value)) {
    ElMessage.success(t('common.app.views.keys.mcpConfigCopied'))
    return
  }
  ElMessage.error(t('common.app.views.keys.copyConfigFailed'))
}
const formatSchema = (schema: Record<string, unknown>): string => JSON.stringify(schema, null, 2)
const mcpPlaybookDownloading = ref(false)
const downloadMCPPlaybook = async (): Promise<void> => {
  if (mcpPlaybookDownloading.value) return
  mcpPlaybookDownloading.value = true
  try {
    const blob = await request.get<Blob>('/mcp/ops-playbook', { responseType: 'blob' })
    saveBlob(blob, 'lazy-balancer-mcp-ops-playbook.md')
  } catch (error: unknown) {
    // 全局拦截器已弹 toast（blob 错误体会被解析出后端 message），这里仅记录
    console.error('Failed to download MCP playbook:', error)
  } finally {
    mcpPlaybookDownloading.value = false
  }
}
let keysRequestSeq = 0

const fetchKeys = async () => {
  const requestSeq = ++keysRequestSeq
  loading.value = true
  try {
    // 管理员默认本人（mine=1）；关闭开关=全平台。非管理员恒本人端点。
    const url = isAdmin.value && !keysMineOnly.value ? '/api-keys' : '/users/me/api-keys'
    const res = await request.get<APIResponse<readonly APIKey[]>>(url)
    if (requestSeq === keysRequestSeq) {
      keys.value = res.data || []
      loadError.value = false
    }
  } catch (error: unknown) {
    console.error('Failed to fetch keys:', error)
    if (requestSeq === keysRequestSeq) loadError.value = true
  } finally {
    if (requestSeq === keysRequestSeq) loading.value = false
  }
}

// 白名单解析/归一/序列化/逐行 CIDR 校验收敛到 utils/apiKeyWhitelist 单源（可 node 行为测试）。

const whitelistEntries = (value: readonly string[]): string[] => value.filter(Boolean)

const whitelistSummary = (value: readonly string[]): string => {
  const entries = whitelistEntries(value)
  const preview = entries.slice(0, 3).join('、')
  return t('common.app.views.keys.whitelistSummary', { count: entries.length, preview, more: entries.length > 3 ? t('common.app.views.keys.summaryMore') : '' })
}

const openCreateDialog = (): void => {
  if (nodeWriteBlocked.value || creating.value) return
  resetCreateForm()
  createDialogVisible.value = true
}

const resetCreateForm = (): void => {
  createForm.value = { name: '', mcp_enabled: false, api_enabled: true, api_read_only: true, mcp_read_only: true, whitelistText: '', expiresAt: null }
  createNameError.value = ''
  createWhitelistError.value = ''
  createExpiresError.value = ''
}

const keyExpired = (key: APIKey): boolean => {
  if (!key.expires_at) return false
  const expiresAt = new Date(key.expires_at).getTime()
  return Number.isFinite(expiresAt) && expiresAt < Date.now()
}

const disablePastDate = (date: Date): boolean => {
  const today = new Date()
  today.setHours(0, 0, 0, 0)
  return date.getTime() < today.getTime()
}

async function createKey() {
  if (nodeWriteBlocked.value || creating.value) return
  const name = createForm.value.name.trim()
  if (!name) {
    createNameError.value = t('common.app.views.keys.enterKeyName')
    return
  }
  const whitelist = serializeWhitelist(createForm.value.whitelistText)
  if (whitelist.error) {
    createWhitelistError.value = whitelist.error
    return
  }
  // 日期面板仅按天禁用过去日期，仍可选到当天早于现在的时刻；
  // 该值必被后端 400（apikeys.go「过期时间不能早于当前时间」）——提交前同文案拦截。
  if (createForm.value.expiresAt && createForm.value.expiresAt.getTime() < Date.now()) {
    createExpiresError.value = t('common.app.views.keys.expiresPastError')
    return
  }

  creating.value = true
  try {
    try {
      await ElMessageBox.confirm(t('common.app.views.keys.createConfirmMsg', { name }), t('common.app.views.keys.createKeyTitle'), {
        type: 'warning', confirmButtonText: t('common.app.views.keys.confirmCreate'), cancelButtonText: t('common.app.views.keys.cancel'),
      })
    } catch { return }
    const payload: CreateAPIKeyInput = {
      name,
      mcp_enabled: createForm.value.mcp_enabled,
      api_enabled: createForm.value.api_enabled,
      api_read_only: isAdmin.value ? createForm.value.api_read_only : true,
      mcp_read_only: isAdmin.value ? createForm.value.mcp_read_only : true,
      mcp_ip_whitelist: whitelist.value,
      expires_at: createForm.value.expiresAt ? createForm.value.expiresAt.toISOString() : undefined,
    }
    const res = await request.post<CreateAPIKeyResponse>('/users/me/api-keys', payload)
    // 一次性明文是本次创建的唯一产出：响应缺 key（契约漂移/网关改写）时不得
    // 先报成功再关框——密钥已入库（列表会多一条），明文却永久不可得，用户只能
    // 删除重建。缺 key 即显性报错、保持创建框并刷新列表，把违约形态摆到眼前。
    if (!res.data?.key) {
      ElMessage.error(t('common.app.views.keys.createNoKeyError'))
      await fetchKeys()
      return
    }
    mfaAwareSuccess(t('common.app.views.keys.createSuccess'))
    createdKey.value = res.data.key
    createdKeyVisible.value = true
    createDialogVisible.value = false
    await fetchKeys()
  } catch (error: unknown) {
    // Error toast is already shown by the global axios interceptor.
    console.error('Failed to create API key:', error)
  } finally {
    creating.value = false
  }
}

const openFeatureDialog = (key: APIKey): void => {
  if (nodeWriteBlocked.value || featureSaving.value) return
  featureTarget.value = key
  featureForm.value = {
    mcp_enabled: key.mcp_enabled,
    api_enabled: key.api_enabled,
    api_read_only: isAdmin.value ? key.api_read_only : true,
    mcp_read_only: isAdmin.value ? key.mcp_read_only : true,
    whitelistText: parseWhitelist(key.mcp_ip_whitelist),
  }
  featureWhitelistError.value = ''
  featureDialogVisible.value = true
}

const resetFeatureForm = (): void => {
  featureTarget.value = null
  featureForm.value = { mcp_enabled: false, api_enabled: true, api_read_only: false, mcp_read_only: false, whitelistText: '' }
  featureWhitelistError.value = ''
}

// 管理端点选择：管理员全平台视角下操作他人 key 走 /api-keys/:id（PATCH/DELETE）；
// 本人 key 或非管理员恒自助端点。
const keyAdminEndpoint = (key: APIKey): boolean =>
  isAdmin.value && !keysMineOnly.value && key.created_by !== authStore.user?.id

const saveFeatures = async (): Promise<void> => {
  if (nodeWriteBlocked.value || featureSaving.value || !featureTarget.value) return
  const whitelist = serializeWhitelist(featureForm.value.whitelistText)
  if (whitelist.error) {
    featureWhitelistError.value = whitelist.error
    return
  }
  featureSaving.value = true
  try {
    try {
      await ElMessageBox.confirm(t('common.app.views.keys.featureSaveConfirmMsg', { name: featureTarget.value.name }), t('common.app.views.keys.featureSaveTitle'), {
        type: 'warning', confirmButtonText: t('common.app.views.keys.confirmSave'), cancelButtonText: t('common.app.views.keys.cancel'),
      })
    } catch { return }
    const payload: UpdateAPIKeyInput = {
      mcp_enabled: featureForm.value.mcp_enabled,
      api_enabled: featureForm.value.api_enabled,
      api_read_only: isAdmin.value ? featureForm.value.api_read_only : true,
      mcp_read_only: isAdmin.value ? featureForm.value.mcp_read_only : true,
      mcp_ip_whitelist: whitelist.value,
    }
    const url = keyAdminEndpoint(featureTarget.value)
      ? `/api-keys/${featureTarget.value.id}/status`
      : `/users/me/api-keys/${featureTarget.value.id}`
    await request.patch(url, payload)
    mfaAwareSuccess(t('common.app.views.keys.featureSaveSuccess'))
    featureDialogVisible.value = false
    await fetchKeys()
  } catch (error: unknown) {
    // Error toast is already shown by the global axios interceptor.
    console.error('Failed to save API key features:', error)
  } finally {
    featureSaving.value = false
  }
}

const deleteKey = async (id: number) => {
  if (nodeWriteBlocked.value || togglePendingId.value === id || deletingIds.value.has(id)) return
  deletingIds.value.add(id)
  try {
    await ElMessageBox.confirm(t('common.app.views.keys.deleteConfirmMsg'), t('common.app.views.keys.deleteTitle'), { type: 'warning', confirmButtonText: t('common.app.views.keys.confirmDelete'), cancelButtonText: t('common.app.views.keys.cancel') })
    const target = keys.value.find(k => k.id === id)
    await request.delete(target && keyAdminEndpoint(target) ? `/api-keys/${id}` : `/users/me/api-keys/${id}`)
    mfaAwareSuccess(t('common.app.views.keys.deleteSuccess'))
    await fetchKeys()
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    console.error('Failed to delete API key:', error)
  } finally {
    deletingIds.value.delete(id)
  }
}

const toggleKey = async (key: APIKey) => {
  if (nodeWriteBlocked.value || togglePendingId.value !== null || deletingIds.value.has(key.id)) return
  const isEnabled = !key.is_enabled

  // 占位先于确认（同 TaskMonitor/ClusterSettings 范式）：确认框悬挂期也是「操作在途」，
  // 此时没有门，连点会叠出第二个确认框并重复写。
  togglePendingId.value = key.id
  try {
    try {
      await ElMessageBox.confirm(
        isEnabled ? t('common.app.views.keys.enableConfirmMsg', { name: key.name }) : t('common.app.views.keys.disableConfirmMsg', { name: key.name }),
        isEnabled ? t('common.app.views.keys.enableTitle') : t('common.app.views.keys.disableTitle'),
        { type: 'warning', confirmButtonText: isEnabled ? t('common.app.views.keys.confirmEnable') : t('common.app.views.keys.confirmDisable'), cancelButtonText: t('common.app.views.keys.cancel') })
    } catch {
      return
    }
    const payload: UpdateAPIKeyInput = { is_enabled: isEnabled }
    await request.patch(keyAdminEndpoint(key) ? `/api-keys/${key.id}/status` : `/users/me/api-keys/${key.id}`, payload)
    mfaAwareSuccess(isEnabled ? t('common.app.views.keys.enableSuccess') : t('common.app.views.keys.disableSuccess'))
    await fetchKeys()
  } catch (error: unknown) {
    // Error toast is already shown by the global axios interceptor.
    console.error('Failed to toggle API key:', error)
  } finally {
    togglePendingId.value = null
  }
}

const copyCreatedKey = async () => {
  if (await copyText(createdKey.value)) {
    ElMessage.success(t('common.app.views.keys.keyCopied'))
    return
  }
  ElMessage.error(t('common.app.views.keys.copyKeyFailed'))
}

const fetchMCPTools = async (): Promise<void> => {
  if (mcpToolsLoading.value || mcpToolsLoaded.value) return
  mcpToolsLoading.value = true
  mcpToolsError.value = ''
  try {
    const response = await request.get<APIResponse<readonly MCPToolSpec[]>>('/mcp/tools')
    mcpTools.value = [...(response.data ?? [])].sort((left, right) => {
      const categoryOrder = Number(right.read_only) - Number(left.read_only)
      return categoryOrder || left.name.localeCompare(right.name)
    })
    mcpToolsLoaded.value = true
  } catch (error: unknown) {
    if (error instanceof Error) {
      mcpToolsError.value = t('common.app.views.keys.toolListLoadFailed', { reason: error.message })
      return
    }
    // 非 Error 异常同样置错误态——否则落入「暂无工具」误态。
    mcpToolsError.value = t('common.app.views.keys.toolListLoadFailed', { reason: String(error) || t('common.app.views.keys.unknownError') })
    console.error('Failed to fetch MCP tools:', error)
  } finally {
    mcpToolsLoading.value = false
  }
}

const copyRestBase = async (): Promise<void> => {
  if (await copyText(restBaseURL)) {
    ElMessage.success(t('common.app.views.keys.mcpUrlCopied'))
    return
  }
  ElMessage.error(t('common.app.views.keys.copyUrlFailed'))
}

const copyMCPServiceURL = async (): Promise<void> => {
  if (await copyText(mcpServiceURL)) {
    ElMessage.success(t('common.app.views.keys.mcpUrlCopied'))
    return
  }
  ElMessage.error(t('common.app.views.keys.copyUrlFailed'))
}

onMounted(() => {
  fetchKeys()
  void fetchMcpStats()
  void fetchAccessSwitches()
})
</script>

<style scoped>
/* 卡片规范（DESIGN_SPEC.md §2）：边框 #ebeef5 与安全总览一致。
 * tab 内容区 overflow:hidden 裁剪卡片四周阴影——padding 留出阴影空间。 */
:deep(.el-tabs__content) { overflow: visible; }
.el-tab-pane { padding: 6px; margin: -6px; }
.el-card { --el-card-border-color: #ebeef5; }
.card-header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; row-gap: 8px; }
.card-header-actions { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.card-header-actions :deep(a.el-button) { text-decoration: none; }
.card-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: #111827; }
.title-icon { font-size: 16px; color: #3b82f6; }
.keys-table { width: 100%; margin-bottom: 4px; }
.key-name-cell { font-weight: 600; padding: 0; height: auto; }
.ml4 { margin-left: 4px; }
.row-actions { display: inline-flex; gap: 8px; white-space: nowrap; flex-wrap: nowrap; }
.row-actions .el-button { padding: 0; }
/* API/MCP 接入卡（双协议同构：端点/鉴权/用途三行） */
.access-card :deep(.el-card__body) { padding: 14px 16px; }
.access-proto { display: inline-flex; align-items: center; gap: 8px; font-weight: 600; }
.access-proto-icon { color: var(--el-color-primary); font-size: 16px; }
.access-rows { display: flex; flex-direction: column; gap: 10px; }
.access-row { display: flex; align-items: baseline; gap: 10px; }
.access-row-label { flex: none; width: 64px; font-size: 12px; color: var(--text-secondary, #6b7280); }
.access-row-value { font-size: 13px; word-break: break-all; }
code.access-row-value { padding: 3px 8px; background: var(--el-fill-color-light); border-radius: 4px; }
.access-row-desc .access-row-value { color: var(--text-secondary, #6b7280); font-size: 12px; line-height: 1.6; }
/* 停用提示占位槽：两卡常驻等高（提示出现/消失不改变卡片高度） */
.access-note-slot { min-height: 46px; }
.access-note-slot .info-note-bar { margin: 8px 0 0; }
.ev-more { font-size: 11px; color: #6b7280; }
.perm-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.perm-col { border: 1px solid #f3f4f6; padding: 12px 14px 4px; }
.perm-col-title { font-size: 13px; font-weight: 600; color: #374151; margin-bottom: 10px; }
.card-header-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.section-divider { margin: 24px 0 20px; }
.section-divider :deep(.el-divider__text) { font-size: 14px; color: var(--text-secondary, #6b7280); font-weight: 600; }
.section-label { font-size: 14px; font-weight: 600; color: #374151; margin: 20px 0 12px; }
.switch-hint { margin-left: 10px; font-size: 12px; color: var(--text-secondary, #6b7280); }
.header-actions { display: flex; gap: 8px; }
.header-actions :deep(a.el-button) { text-decoration: none; }
.header-actions :deep(.el-button .el-icon) { margin-right: 4px; }

.key-col { margin-bottom: 20px; }

.keys-mcp-block { margin-bottom: 20px; }

.key-card-disabled { opacity: 0.72; }

.key-title-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.key-name { min-width: 0; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.feature-tags { display: flex; flex-wrap: wrap; gap: 6px; }

.key-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 16px; }
.key-actions :deep(.el-icon) { margin-right: 4px; }

.readonly-alert { margin: -2px 0 18px; }

.mcp-agent-guide { margin-bottom: 20px; }
.mcp-guide-text { color: var(--el-text-color-regular); font-size: 13px; line-height: 1.6; }
.mcp-guide-pre, .mcp-schema-pre { background: #f6f8fa; border-radius: 0; padding: 12px; font-family: 'SF Mono', Menlo, monospace; font-size: 12px; line-height: 1.55; overflow-x: auto; white-space: pre; }
.mcp-schema-pre { max-height: 320px; overflow-y: auto; }
.mcp-config-json { margin-top: 12px; }
.mcp-config-json :deep(textarea) { font-family: 'SF Mono', Menlo, monospace; font-size: 12px; }
.mcp-config-toolbar { display: flex; justify-content: flex-end; margin-top: 8px; }
.mcp-tool-expand { padding: 4px 12px 10px; }
.mcp-tool-usage { font-size: 13px; line-height: 1.6; margin-bottom: 8px; }
.mcp-expand-label { font-weight: 600; }
.mcp-table-scroll-hint { display: none; }
.mcp-tools-table { min-height: 120px; overflow-x: auto; }
.mcp-tools-table :deep(.el-table) { min-width: 800px; }
.mcp-tool-description { line-height: 1.5; white-space: normal; }
:deep(.mcp-docs-dialog .el-dialog__body) { max-height: calc(100dvh - 200px); overflow-y: auto; }

.created-key-box { display: flex; align-items: center; gap: 12px; margin-top: 20px; }

.created-key-text { flex: 1; min-width: 0; color: #111827; font-family: 'SF Mono', monospace; font-size: 12px; word-break: break-all; }


@media (max-width: 767px) {
  .page-header { align-items: flex-start; flex-direction: column; gap: 12px; }
  .header-actions { width: 100%; flex-wrap: wrap; }
  .key-actions { flex-wrap: wrap; }
}

@media (max-width: 1023px) {
  .mcp-table-scroll-hint { display: block; margin: -4px 0 8px; }
}
</style>
