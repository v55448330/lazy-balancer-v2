package services

import (
	"database/sql"
	"errors"
	"strings"

	"lazy-balancer-v2/internal/db"
)

// cert_jobs 的「可服务证书材料」判定必须单源：渲染候选、启动物化、文件对账、
// 导入后产物清理、删除任务后的文件回收都依赖同一语义。曾有三套实现
// （渲染=非 disabled + PEM 非空；启动/对账/导入清理=issued/downloaded + PEM 非空），
// 渲染面更宽——导入清理会把「queued/waiting_ca/failed 但保留旧 PEM」规则的证书
// 文件删掉，而渲染仍从该行取材料服务流量，形成磁盘/数据库分叉。
//
// 单一语义（=渲染可消费面）：
//   - status != 'disabled'（disabled 是退役终态，任何消费方都不使用其材料）
//   - cert_pem / key_pem 均非空
//
// 域名适用性（certJobRuleApplicable）与「证书是否仍在有效期」不属于本谓词：
// 前者由各消费方按规则当前域名单独判定，后者只能解析证书后判定（SQL 表达不了）。

// certJobCandidatePredicateSQL 返回「持有非空证书材料」的 SQL 谓词（不判
// status）。
//
// 保留 disabled 行只是 per-rule 补查（acmeCertCandidatesForRule）的口径：该路
// 让 selectCertificate 之后置跳过、同时供过期回退展示复用该行，由
// TestACMECertCandidatesForRule_preparses_leaf 钉住「候选数含 disabled」。
// 批量渲染候选（acmeCertCandidatesQuery）走 CertJobMaterialPredicateSQL，含
// `status <> 'disabled'`，**不保留** disabled 行——两路在 disabled 维度本就不同，
// 不得把「渲染装载保留 disabled」当成通则：把需要 disabled/过期行的消费
// （如 ExpiredACMECertInfoFallback）接到批量装载会静默漏行。
//
// PEM 判空口径必须与 Go 侧 CertJobMaterialUsable 同源——渲染面把空白 PEM 当
// 有材料会让物化把它写盘。
func certJobCandidatePredicateSQL(alias string) string {
	prefix := ""
	if alias != "" {
		prefix = alias + "."
	}
	const sqlWhitespace = "' '||char(9)||char(10)||char(11)||char(12)||char(13)"
	nonBlank := func(column string) string {
		return "TRIM(" + prefix + column + ", " + sqlWhitespace + ") <> ''"
	}
	return nonBlank("cert_pem") + " AND " + nonBlank("key_pem")
}

// CertJobMaterialPredicateSQL 返回「持有可服务证书材料」的 SQL 谓词。alias 为
// 列前缀（如 "j"），空串=裸列名。所有涉及材料可用性的 SQL 必须复用本函数，
// 不得另写条件组合；per-rule 渲染补查（需保留 disabled 行）复用其组成部分
// certJobCandidatePredicateSQL（批量候选不走该豁免，见其注释）。
//
// 判空必须是 trim 后的判空：只比较 ” 会把 ' ' 这类空白材料当作「有材料」，
// 而 Go 侧 CertJobMaterialUsable（TrimSpace）判为无材料——同一行在 SQL 扫描
// 链路（渲染/物化/补扫）与 Go 判定链路（补偿/失败降级）结论相反，补扫会把
// 空白材料写盘。trim 字符集与 Go 侧 ASCII 空白对齐（空格/制表/换行/回车/
// 垂直制表/换页）；非 ASCII 空白的带外写入仍属两侧差异，PEM 实际不会出现。
func CertJobMaterialPredicateSQL(alias string) string {
	prefix := ""
	if alias != "" {
		prefix = alias + "."
	}
	return certJobCandidatePredicateSQL(alias) + " AND COALESCE(" + prefix + "status,'') <> 'disabled'"
}

// certJobMissingMaterialPredicateSQL 是 CertJobMaterialPredicateSQL 的逻辑取反。
// 取反必须经 COALESCE 归一到布尔：SQL 三值逻辑下 NOT(NULL) 仍是 NULL，材料列
// 为 NULL（任务行创建时的默认形态——签发中断从未写入，正是「材料丢失」最常见
// 的形态）会被 `NOT (predicate)` 静默排除，而不是被当作「无材料」回收。
// 正向与取反共用同一表达式，不得另写条件组合。
func certJobMissingMaterialPredicateSQL(alias string) string {
	return "NOT COALESCE(" + CertJobMaterialPredicateSQL(alias) + ", 0)"
}

// CertJobMaterialUsable 是 CertJobMaterialPredicateSQL 的 Go 侧等价判定，供
// 内存中的行（已是查询结果）复用同一语义（含 trim 口径，见上）。
func CertJobMaterialUsable(status, certPEM, keyPEM string) bool {
	return strings.TrimSpace(certPEM) != "" && strings.TrimSpace(keyPEM) != "" && status != "disabled"
}

// certJobDeploymentExecutor 部署窗口推进写点接受的最小执行体（*sql.DB/*sql.Tx）。
type certJobDeploymentExecutor interface {
	Exec(query string, args ...any) (sql.Result, error)
}

// CertJobDeploymentWindowPush 描述一次「部署窗口推进」写点。
type CertJobDeploymentWindowPush struct {
	// Status 非空时同时把 status 置为该值——只有「删除失败恢复 disabled→
	// downloaded」一条路径需要（恢复必须与窗口同写，否则恢复后的行停在无窗口态）。
	Status string
	// Message 是要落库的任务消息（按 maxJobMessageBytes 截断）。
	Message string
	// Where 是追加在 `id=?` 之后的状态/业务谓词（可含占位符），WhereArgs 为其参数。
	Where     string
	WhereArgs []any
}

// PushCertJobDeploymentWindow 是「把部署窗口推到当前时刻 + 同写 message +
// 推 updated_at」的唯一实现。
//
// 窗口列与 updated_at 必须同写：重试冷却门（certJobRetryBlocked）以
// updated_at 为计时基准，只推窗口不推 updated_at 会让本轮重排对冷却门不可见
// （「补扫可见但冷却门不可见」的半套状态）。部署重排的五个写点曾各写一份内联
// SQL + 互相引用注释，任一处漏写 updated_at 就会复活该半套状态。
func PushCertJobDeploymentWindow(exec certJobDeploymentExecutor, jobID int, push CertJobDeploymentWindowPush) (int64, error) {
	assignments := "deployment_available_after=datetime('now'), message=?, updated_at=datetime('now')"
	args := []any{truncateJobMessage(push.Message)}
	if push.Status != "" {
		assignments = "status=?, " + assignments
		args = append([]any{push.Status}, args...)
	}
	query := "UPDATE cert_jobs SET " + assignments + " WHERE id=?"
	args = append(args, jobID)
	if push.Where != "" {
		query += " AND " + push.Where
		args = append(args, push.WhereArgs...)
	}
	result, err := exec.Exec(query, args...)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// loadCertJobDeploymentState 读取任务行的状态与「材料是否可用」，供所有
// 「部署生命周期 + 有材料」判定复用（补偿重排队 / CA provider 不可用降级 /
// 生命周期取消重排队 / 失败终态降级）。这四处曾各写一份同构 SELECT 与同一
// 布尔组合：材料口径或生命周期口径一变就容易漏改其余副本。
// 错误语义由调用方决定——found=false 表示行不存在，err!=nil 表示读故障；
// 本函数不替调用方选择 false-on-error / 上抛 / 跳过。
func loadCertJobDeploymentState(jobID int) (status string, hasMaterial bool, found bool, err error) {
	var certPEM, keyPEM string
	err = db.DB.QueryRow("SELECT status, COALESCE(cert_pem,''), COALESCE(key_pem,'') FROM cert_jobs WHERE id=?", jobID).
		Scan(&status, &certPEM, &keyPEM)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, false, nil
	}
	if err != nil {
		return "", false, false, err
	}
	return status, CertJobMaterialUsable(status, certPEM, keyPEM), true, nil
}
