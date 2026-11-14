package services

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// 操作日志词汇硬卡控（系统标准：操作标签 ≤4 词、事件对象 ≤5 词，词制计数见
// auditVocabWords）。扫描 internal/ 全部非测试源码，提取 RecordAuditLog /
// recordAudit / recordSystemAudit 的字面量词条与 FormatAuditAction 的返回
// 字面量逐一校验——新增超标词条此测试直接红。变量词条仅放行已核清的动态
// 调用点，其余动态传参视为违规（强制新调用点用字面量，保持可扫描）。

// auditVocabDynamicAllowlist 是已人工核清的动态词条调用点，粒度为
// 「相对 internal/ 的路径 + 参数下标 + 外层函数名」（C-发现2：文件级
// 白名单会放行同文件内新增函数的动态传参，收紧到函数级后新增函数即违规）：
//   - handlers/audit.go recordAudit 与 middleware auditMiddleware 是
//     recordAudit/RecordAuditLog 的透传封装；
//   - handlers/caddy.go UpdateConfig 的对象变量取自
//     GetConfigSection/GetConfigSourceSection（ACME配置/Caddy配置/基础设置/
//     全局配置/集群管理，均 ≤5 词）；
//   - handlers/cluster_registration.go clusterNodeAction 的动作形参实参仅有
//     审批/拒绝/删除/更新地址；
//   - handlers/config_backup.go importConfigBackupCore（HTTP 导入端点与自动
//     备份还原共用）、failImportAbort/failImportValidation（事务内/事务前失败
//     收尾，动作取 action+"失败"；failImportTx 已改为其薄封装，无独立动态
//     调用点）与 config_import_v1.go ImportV1Config 的
//     动作变量取值仅有导入/还原/导入失败/还原失败/部分失败；handlers/autobackup.go
//     RunAutoBackupOnce 的动作变量取值仅有 自动备份/手动备份；
//   - handlers/autobackup.go failAutoBackupAccess 是还原/下载/删除进入高危
//     操作核心之前的行面/文件面失败收口（动作取 verb+"失败"，取值仅
//     还原失败/下载失败/删除失败，均 ≤4 词；对象固定「配置备份」）；
//   - services/certificates.go renewExpiringCertificates 的动作变量取值仅有
//     续签排队/重试排队；
//   - handlers/handlers.go finishTxApply 的动作/对象取自 txApplyFinish 的字面量
//     字段（16 个调用点：动作 创建/更新/删除/写入+失败，对象 自定义规则/
//     拦截页面/安全策略/IP 地址列表，均 ≤ 上限；2026-09-06 裁定 ①②
//     事务内应用门控统一收尾）；
//   - services/downloadintegrity.go recordDownloadIntegrityAudits 的动作/对象变量由调用方
//     传入字面量（动作 校验阻断/下载校验、对象 CRS规则库/IP数据库/完整性记录，
//     均纳入扫描；锁外落库改造后审计写点收敛到该 flush 函数）；
var auditVocabDynamicAllowlist = map[string]map[int][]string{
	"handlers/audit.go":                {1: {"recordAudit"}, 2: {"recordAudit"}},
	"middleware/middleware.go":         {1: {"auditMiddleware"}, 2: {"auditMiddleware"}},
	"handlers/caddy.go":                {2: {"UpdateConfig"}},
	"handlers/cluster_registration.go": {1: {"clusterNodeAction"}},
	// failImportAbort 是 failImportTx 与 29 处锁内复核分支共用的「回滚→失败
	// 审计」收口（动作取 action+"失败"，取值仅 导入失败/还原失败）。
	"handlers/config_backup.go": {1: {"importConfigBackupCore", "failImportAbort", "failImportValidation"}},
	// config_import_coordinator abort：WAF 文件回退失败/说明性告警必须系统身份
	// 留痕，动作取 actionLabel()+"警告"（取值仅 导入警告/还原警告，均 ≤4 词），
	// 对象固定「配置备份」。会话上下文不携带用户身份，故在 abort 内直写。
	"handlers/config_import_coordinator.go": {1: {"abort",
		// close 兜底 abort：动作=session.actionLabel()+"失败"（取值仅
		// 导入失败/还原失败，均 ≤4 词）——未完成导入的回滚必须留痕，
		// 与 abort 同族的透传语义。
		"close"}},
	// applyLbbakWafFilesInLock：动作透传 core 的 action（取值仅 导入/还原——历史
	// 修复还原路径归因漂移），词汇均在标准动作集内。warn 是同一 action 的
	// 逐文件失败包装（action+"警告" ∈ 导入警告/还原警告，均 ≤4 词）。
	"handlers/config_backup_lbbak.go": {1: {"warn"}},
	// 触发审计统一在 RecordTaskTriggerResult 写库；Family 由调用点字面量
	// 传入（任务监控/安全防护/配置备份等，均 ≤5 词），动作固定为字面量
	// 「触发」/「触发失败」。TriggerTaskAsync 仅转发上下文，不再直写审计。
	"services/task_trigger.go": {2: {"RecordTaskTriggerResult"}},
	"handlers/autobackup.go":   {1: {"RunAutoBackupOnce", "failAutoBackupAccess"}},
	"handlers/handlers.go":     {1: {"finishTxApply", "writeApplyFailureBanner"}, 2: {"finishTxApply", "writeApplyFailureBanner"}},
	// tryIPListHotPathApply 的动作/对象透传 txApplyFinish 字段（热路径收尾镜像
	// finishTxApply 家族语义；字面量词条在各名单写路径调用点核清，
	// 2026-10-15 核清入白名单）。
	"handlers/securityiplists.go":   {1: {"tryIPListHotPathApply"}, 2: {"tryIPListHotPathApply"}},
	"services/certificates.go":      {1: {"renewExpiringCertificates"}},
	"services/downloadintegrity.go": {1: {"recordDownloadIntegrityAudits"}, 2: {"recordDownloadIntegrityAudits"}},
	// RunAutobanCycle 的动作传 AutobanAuditAction 包级常量（字面值「自动封禁」
	// 单源——merge 审计写点与 AutobanBannedToday 的 audit_log 计数共用同一
	// 常量，两处字面量漂移会让今日封禁恒 0；2026-10-15 核清入白名单）。
	// autobanAuditBanned：动作传 AutobanAuditAction 包级常量（字面值「自动封禁」
	// 单源）；逐 IP 行与超限汇总行共用。
	"services/autoban.go": {1: {"autobanAuditBanned"}},
	// updateLibSourceFlags：事件对象来自 libSourceFlagsSpec.Family，取值仅
	// 爬虫名单/威胁库两族（包内常量装配），词数均在标准内。
	"handlers/lib_source_flags.go": {2: {"updateLibSourceFlags"}},
}

// auditVocabCallSpecs 给出各审计写入口的 动作/对象 参数下标。
// recordAuthenticationSecurityAudit 是 middleware.go:38 对 services.RecordAuditLog
// 的函数变量别名（不登记则该调用点整点不被扫描，「认证拒绝」不进
// 后端动作集，danger 契约条目虚设）。
var auditVocabCallSpecs = map[string][2]int{
	"RecordAuditLog":                    {1, 2},
	"recordAudit":                       {1, 2},
	"recordSystemAudit":                 {0, 1},
	"recordAuthenticationSecurityAudit": {1, 2},
}

func auditVocabStringLit(e ast.Expr) (string, bool) {
	b, ok := e.(*ast.BasicLit)
	if !ok || b.Kind != token.STRING {
		return "", false
	}
	// 优先按 Go 语法反转义（转义形态按实际词数计数）；异常字面量回退原样剥引号。
	if unquoted, err := strconv.Unquote(b.Value); err == nil {
		return unquoted, true
	}
	return strings.Trim(b.Value, "\""), true
}

func TestAuditVocabulary_wordLimits(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "internal"))
	if err != nil {
		t.Fatalf("resolve internal dir: %v", err)
	}
	var violations []string
	// usedAllowlist 记录命中白名单的「文件|参数下标|函数」组合，测试末尾断言
	// 每个白名单条目都有真实动态调用点——条目失效（函数改名/调用点消失）即报错，
	// 防止白名单只增不减地淤积放行面。
	usedAllowlist := map[string]bool{}
	check := func(file string, line int, kind, value string, limit int) {
		if n := auditVocabWords(value); n > limit {
			violations = append(violations, file+":"+strconv.Itoa(line)+" "+kind+" "+strconv.Quote(value)+" 超上限（"+strconv.Itoa(n)+" 词 > "+strconv.Itoa(limit)+"）")
		}
	}
	// 字面量 (action, resource) 对命中归一表旧侧的
	// 成对判定已随移入 internal/db（谓词不再导出）
	// audit_vocabulary_migration_test.go 的 TestAuditWritePointsUseCanonicalVocabulary。
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Errorf("parse %s: %v", path, err)
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		// checkCalls 扫描一棵子树内的审计写入口调用，违规动态传参按外层函数名
		// 归因（enclosing 为空表示包级初始化表达式，不在白名单即违规）。
		checkCalls := func(node ast.Node, enclosing string) {
			ast.Inspect(node, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var name string
				switch fn := call.Fun.(type) {
				case *ast.SelectorExpr:
					name = fn.Sel.Name
				case *ast.Ident:
					name = fn.Name
				}
				spec, ok := auditVocabCallSpecs[name]
				if !ok {
					return true
				}
				line := fset.Position(call.Pos()).Line
				for _, arg := range []struct {
					idx   int
					kind  string
					limit int
				}{{spec[0], "操作标签", auditActionMaxWords}, {spec[1], "事件对象", auditResourceMaxWords}} {
					if arg.idx >= len(call.Args) {
						continue
					}
					if value, ok := auditVocabStringLit(call.Args[arg.idx]); ok {
						if value != "" {
							check(path, line, arg.kind, value, arg.limit)
						}
						continue
					}
					if !slices.Contains(auditVocabDynamicAllowlist[rel][arg.idx], enclosing) {
						violations = append(violations, path+":"+strconv.Itoa(line)+" "+arg.kind+" 为动态表达式且不在已核清白名单（函数 "+enclosing+"），请改用字面量词条")
					} else {
						usedAllowlist[rel+"|"+strconv.Itoa(arg.idx)+"|"+enclosing] = true
					}
				}
				return true
			})
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Name.Name == "FormatAuditAction" && d.Body != nil {
					ast.Inspect(d.Body, func(inner ast.Node) bool {
						ret, ok := inner.(*ast.ReturnStmt)
						if !ok || len(ret.Results) < 2 {
							return true
						}
						line := fset.Position(ret.Pos()).Line
						if value, ok := auditVocabStringLit(ret.Results[0]); ok && value != "" {
							check(path, line, "操作标签", value, auditActionMaxWords)
						}
						if value, ok := auditVocabStringLit(ret.Results[1]); ok && value != "" {
							check(path, line, "事件对象", value, auditResourceMaxWords)
						}
						return true
					})
					continue
				}
				checkCalls(d.Body, d.Name.Name)
			case *ast.GenDecl:
				checkCalls(d, "")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal: %v", err)
	}
	for rel, byIndex := range auditVocabDynamicAllowlist {
		for idx, funcs := range byIndex {
			for _, fn := range funcs {
				if !usedAllowlist[rel+"|"+strconv.Itoa(idx)+"|"+fn] {
					t.Errorf("白名单条目 %s 参数 %d 函数 %s 未命中任何动态调用点——调用点已消失或改名，请同步收紧白名单", rel, idx, fn)
				}
			}
		}
	}
	if len(violations) > 0 {
		t.Fatalf("操作日志词汇超标（标准：操作标签 ≤%d 词、事件对象 ≤%d 词）：\n%s", auditActionMaxWords, auditResourceMaxWords, strings.Join(violations, "\n"))
	}
}
