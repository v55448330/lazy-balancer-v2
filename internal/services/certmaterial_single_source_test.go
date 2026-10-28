package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 「材料可用性」只允许一处实现（certmaterial.go）：SQL 谓词必须调用
// CertJobMaterialPredicateSQL，内存行必须调用 CertJobMaterialUsable。
//
// 历史事故正是多套实现并存——渲染面把「有材料」判宽、导入清理判窄，结果把仍在
// 对外服务的证书文件删掉。此扫描把「不许再长出内联谓词」变成机器判定：扫描
// 整个 services 包（此前是手工文件清单，新增证书域生产文件时恰好漏扫，而且
// 失败是静默的——测试仍绿）。扫描本身只是只读字符串匹配，代价可忽略。
// certMaterialPredicateExemptions 登记「import 环逼出的物理副本」：这些位置
// 无法 import services（db 包被 services 依赖，反向引用即成环），只能复写谓词。
// 豁免必须逐声明登记（文件 + 声明名 + 理由），并由本用例断言：
//   - 登记项必须**真的仍存在**（删除副本后未登记的残留条目同样失败——防止
//     豁免表长成永久白名单）；
//   - 未登记的新副本一律失败（db 包再长出第二份谓词不会被静默放过）。
//
// 未登记且不在检测面内的形态：db 包 certJobsDedupeSQL 用「材料为空」的正向写法
// （COALESCE(cert_pem,”)=”）做去重排序键——它不是材料可用性门（不参与渲染/
// 物化/清理判定），只决定同 (rule_id,domain) 保留哪一行，故既不检测也不登记。
//
// 已知口径差异：db 侧的 legacyHTTPSHasCertPredicate 判空不带 TRIM（其余条件
// 与单源等价），仅「纯空白 PEM」这一带外形态上与 trim 口径结论相反——
// 一次性迁移据此把该规则判为「有证」而保留 enable_tls=1。保留差异而不是在 db
// 包里再写一遍 trim 表达式：迁移只跑一次，且两处 trim 字符集必须逐字节一致才
// 不会形成第三套口径。新增条件时必须同步两侧（本用例的等价断言覆盖列与状态）。
var certMaterialPredicateExemptions = map[string]map[string]string{
	filepath.Join("..", "db", "db.go"): {
		"legacyHTTPSHasCertPredicate": "migrateLegacyHTTPSProtocol 的有证预判（cert_pem/key_pem 非空 + status 非 disabled）：与单源条件集合等价，唯一差异是不带 TRIM（见本表注释）；import 环使 db 无法引用 services",
	},
}

func TestCertJobMaterialPredicate_hasNoInlineCopies(t *testing.T) {
	seenExempts := map[string]bool{}
	scanTargets := []string{}
	servicesFiles, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob services sources: %v", err)
	}
	scanTargets = append(scanTargets, servicesFiles...)
	handlerFiles, err := filepath.Glob(filepath.Join("..", "handlers", "cert*.go"))
	if err != nil {
		t.Fatalf("glob handler certificate files: %v", err)
	}
	scanTargets = append(scanTargets, handlerFiles...)
	scanTargets = append(scanTargets, filepath.Join("..", "handlers", "config_backup.go"))
	// db 包必须入扫描面：材料谓词在那里有一份物理副本（import 环），此前
	// 扫描面只有 services 与 handlers/cert* —— db 再长出第二份谓词不会被拦。
	dbFiles, err := filepath.Glob(filepath.Join("..", "db", "*.go"))
	if err != nil {
		t.Fatalf("glob db sources: %v", err)
	}
	scanTargets = append(scanTargets, dbFiles...)

	for _, path := range scanTargets {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		assertNoInlineMaterialPredicate(t, path, seenExempts)
	}
	for path, decls := range certMaterialPredicateExemptions {
		for decl := range decls {
			if !seenExempts[path+"\x00"+decl] {
				t.Errorf("豁免登记已失效：%s 的 %s 不再包含内联材料谓词（删除登记项）", path, decl)
			}
		}
	}
}

// enclosingDeclName 回溯最近的 func/const/var 声明名：豁免按「声明」登记，
// 而不是整文件豁免——同文件里新长出的第二份副本仍必须失败。
func enclosingDeclName(lines []string, index int) string {
	for i := index; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		var rest string
		switch {
		case strings.HasPrefix(line, "func "):
			rest = strings.TrimPrefix(line, "func ")
			// 方法形态：func (r *T) Name(...)
			if strings.HasPrefix(rest, "(") {
				if close := strings.Index(rest, ")"); close >= 0 {
					rest = strings.TrimSpace(rest[close+1:])
				}
			}
		case strings.HasPrefix(line, "const "):
			rest = strings.TrimPrefix(line, "const ")
		case strings.HasPrefix(line, "var "):
			rest = strings.TrimPrefix(line, "var ")
		default:
			continue
		}
		name := rest
		for i, r := range rest {
			if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
				name = rest[:i]
				break
			}
		}
		if name != "" && name != "(" {
			return name
		}
	}
	return ""
}

func assertNoInlineMaterialPredicate(t *testing.T, path string, seenExempts map[string]bool) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	lines := strings.Split(string(data), "\n")
	reportViolation := func(lineNo int, detail string) {
		decl := enclosingDeclName(lines, lineNo)
		if reasons, ok := certMaterialPredicateExemptions[path]; ok {
			if _, exempt := reasons[decl]; exempt {
				seenExempts[path+"\x00"+decl] = true
				return
			}
		}
		t.Errorf("%s:%d 内联材料谓词（声明 %s），必须复用 CertJobMaterialPredicateSQL/CertJobMaterialUsable: %s",
			path, lineNo+1, decl, detail)
	}
	for lineNo, line := range lines {
		if !strings.Contains(line, "cert_pem") || !strings.Contains(line, "key_pem") {
			continue
		}
		if strings.Contains(line, "CertJobMaterialPredicateSQL") || strings.Contains(line, "CertJobMaterialUsable") {
			continue
		}
		if strings.Contains(line, "<> ''") || strings.Contains(line, "!= ''") ||
			strings.Contains(line, "<>''") || strings.Contains(line, "!=''") {
			reportViolation(lineNo, strings.TrimSpace(line))
		}
	}
	// 行级扫描可被字符串拼接绕过（`cert_pem,'') <> "` + `"''` 两行各不含完整
	// 谓词）。这里去掉引号/加号/全部空白后按列名就近查比较运算符：拼接后的
	// 谓词必然在同一段连续文本里。
	squashedLines := make([]string, len(lines))
	starts := make([]int, len(lines))
	var squashedBuilder strings.Builder
	for index, line := range lines {
		part := strings.Join(strings.Fields(line), "")
		part = strings.NewReplacer(`"`, "", "`", "", "+", "").Replace(part)
		starts[index] = squashedBuilder.Len()
		squashedLines[index] = part
		squashedBuilder.WriteString(part)
	}
	squashed := squashedBuilder.String()
	// 单源标记名按等长占位替换：删除会改变偏移，回映射行号随之漂移（豁免归属
	// 就会落到相邻声明上）。
	for _, marker := range []string{"certJobCandidatePredicateSQL", "CertJobMaterialPredicateSQL", "CertJobMaterialUsable"} {
		squashed = strings.ReplaceAll(squashed, marker, strings.Repeat("_", len(marker)))
	}
	for _, column := range []string{"cert_pem", "key_pem"} {
		for offset := 0; ; {
			index := strings.Index(squashed[offset:], column)
			if index < 0 {
				break
			}
			position := offset + index
			tail := squashed[position:]
			if len(tail) > 48 {
				tail = tail[:48]
			}
			if strings.Contains(tail, "<>''") || strings.Contains(tail, "!=''") {
				reportViolation(positionToLine(starts, position), "跨行拼接内联材料谓词（squashed: "+tail+"）")
				break
			}
			offset = position + len(column)
		}
	}
}

// positionToLine 把「逐行去空白拼接文本」里的位置映射回源码行号（starts 是每行
// 段的起始偏移）。
func positionToLine(starts []int, position int) int {
	line := 0
	for index, start := range starts {
		if start > position {
			break
		}
		line = index
	}
	return line
}

// 空白 PEM 必须与单源 Go 判据同结论（无材料）：trim 口径分叉会让补偿路径把
// 「只有空格的材料」当作可部署，进入部署快速路径后永久重试。
func TestRequeueCanceledJob_whitespaceMaterialTreatedAsAbsent(t *testing.T) {
	jobID, _ := seedCertificateJob(t, "downloaded")
	if _, err := db.DB.Exec(`UPDATE cert_jobs SET cert_pem='   ', key_pem='key' WHERE id=?`, jobID); err != nil {
		t.Fatalf("seed whitespace material: %v", err)
	}

	// When
	requeueCanceledJob(jobID)

	// Then：按无材料处理 → 回落重新排队（而非保留部署态）
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read job status: %v", err)
	}
	if status != "queued" {
		t.Fatalf("status=%q, want queued（空白材料按无材料处理）", status)
	}
}
