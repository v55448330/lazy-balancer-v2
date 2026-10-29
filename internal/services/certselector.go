package services

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

type CertificateCandidate struct {
	ID        int64
	Domain    string
	Status    string
	CertPEM   string
	KeyPEM    string
	UpdatedAt float64
	// Leaf 是调用方预解析的证书（快照组选统一解析后传入，避免二次 X509KeyPair
	// 解析）；为空时 selectCertificate 自行解析。
	Leaf *x509.Certificate
}

type CertificateSelection struct {
	Candidate   CertificateCandidate
	Certificate *x509.Certificate
}

// CertificateCandidateColumnList 是 cert_jobs 候选装载的规范列序单源（顺序即
// Scan 顺序）：id, domain, status, cert_pem, key_pem, updated_at(julianday)。
// 所有候选装载（续期扫描、证书信息端点、渲染补查与批量渲染、配置巡检）都必须
// 用本常量拼 SQL——列序在某一处漂移会让 Scan 静默错位（PEM 落进 status 之类），
// 且只有该入口出问题。带 rule_id 前缀的批量查询写作 "rule_id, " + 本常量。
const CertificateCandidateColumnList = `id, domain, status, COALESCE(cert_pem, ''), COALESCE(key_pem, ''), COALESCE(julianday(COALESCE(updated_at, created_at)), 0)`

// NewCertificateCandidate 装配一行 cert_jobs 候选并统一 Leaf 预解析策略：
// disabled 行不解析（不参与选择，解析纯属浪费），其余行解析一次供
// selectCertificate 走快路径并与过期回退共用。leafCache 非空时按 PEM 内容复用
// 本轮内的解析结果（同一证书挂在多条规则下的批量装载、60s 巡检节拍）；传 nil
// 表示不缓存。
func NewCertificateCandidate(id int64, domain, status, certPEM, keyPEM string, updatedAt float64, leafCache map[string]*x509.Certificate) CertificateCandidate {
	candidate := CertificateCandidate{ID: id, Domain: domain, Status: status, CertPEM: certPEM, KeyPEM: keyPEM, UpdatedAt: updatedAt}
	if status == "disabled" {
		return candidate
	}
	leafKey := certPEM + "\x00" + keyPEM
	if leafCache != nil {
		if leaf, cached := leafCache[leafKey]; cached {
			candidate.Leaf = leaf
			return candidate
		}
	}
	candidate.Leaf = ParseCertificateLeaf(certPEM, keyPEM)
	if leafCache != nil {
		leafCache[leafKey] = candidate.Leaf
	}
	return candidate
}

// certJobCandidateQuerier 是候选装载的查询面：*sql.DB / *sql.Tx / caddyConfigStore
// 均满足 Query；额外提供 QueryContext 者（*sql.DB/*sql.Tx）优先使用——续期扫描
// 的取消必须能作用到查询本身（见 CheckExpiration）。
type certJobCandidateQuerier interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

type certJobCandidateContextQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// loadCertificateCandidates 按规则装载 ACME 证书候选（列序/行装配/预解析单源）。
// predicateSQL 由调用方给出（材料谓词 CertJobMaterialPredicateSQL，或需保留
// disabled 行的 certJobCandidatePredicateSQL）；错误原样上抛——语义由调用方
// 决定：渲染补查记 warn 返 nil、证书信息端点 500、续期扫描计入扫描失败。
func loadCertificateCandidates(ctx context.Context, q certJobCandidateQuerier, ruleID, predicateSQL string) ([]CertificateCandidate, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	query := `SELECT ` + CertificateCandidateColumnList + `
		FROM cert_jobs
		WHERE rule_id = ? AND ` + predicateSQL + `
		ORDER BY updated_at DESC, id DESC`
	var (
		rows *sql.Rows
		err  error
	)
	if ctxQuerier, ok := q.(certJobCandidateContextQuerier); ok {
		rows, err = ctxQuerier.QueryContext(ctx, query, ruleID)
	} else {
		rows, err = q.Query(query, ruleID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	candidates := make([]CertificateCandidate, 0)
	for rows.Next() {
		var id int64
		var domain, status, certPEM, keyPEM string
		var updatedAt float64
		if scanErr := rows.Scan(&id, &domain, &status, &certPEM, &keyPEM, &updatedAt); scanErr != nil {
			return nil, scanErr
		}
		candidates = append(candidates, NewCertificateCandidate(id, domain, status, certPEM, keyPEM, updatedAt, nil))
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, rowsErr
	}
	return candidates, nil
}

// ParseCertificateLeaf 解析候选证书为 Leaf。tls.X509KeyPair 会同时校验
// 证书/私钥配对并解析私钥——是候选筛选里最贵的步骤；批量装载阶段（渲染、
// 配置巡检、证书信息查询）统一预解析一次并填入 CertificateCandidate.Leaf，
// selectCertificate 走已解析快路径，避免同一候选在「选择 + 过期回退」等多
// 次调用间重复解析（与 cluster_snapshot 的同口径做法一致）。
// 解析失败返回 nil，语义等同未预解析：候选仍由 selectCertificate 按不可解析
// 跳过（disabled 候选由调用方直接跳过预解析）。
func ParseCertificateLeaf(certPEM, keyPEM string) *x509.Certificate {
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil || len(pair.Certificate) == 0 {
		return nil
	}
	if pair.Leaf != nil {
		return pair.Leaf
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil
	}
	return leaf
}

// errCertPEMEmpty 表示 PEM 里没有可解码的块（空串/纯私钥/损坏的封装）——
// 与「块存在但证书解析失败」区分开，让需要细分文案的调用方（签发链取时）
// 保留既有两种错误形态。
var errCertPEMEmpty = errors.New("pem: no certificate block")

// parseCertificateLeaf 是「PEM 首块 → x509 证书」的唯一实现：到期时间派生
// （CertNotAfterFromPEM）、签发链取时（parseCertTime，含 NotBefore）、域名覆盖
// 与生效时间判定（parseCertificateLeafFromPEM）全部经此，三份同形拷贝会任一侧
// 改动（多块链/容忍尾随垃圾）后静默分叉。
func parseCertificateLeaf(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errCertPEMEmpty
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return leaf, nil
}

// CertNotAfterFromPEM 解析证书 PEM 首块的 NotAfter（仅证书，不需要私钥）。
// 用于 cert_jobs.expires_at 缺失（导入/旧备份/集群快照/对账遗留）时回退派生
// 到期状态——否则任务页显示「-」而规则证书卡按 PEM 显示 valid/N 天，同一条
// 证书两处结论冲突。
func CertNotAfterFromPEM(certPEM string) (time.Time, bool) {
	leaf, err := parseCertificateLeaf(certPEM)
	if err != nil {
		return time.Time{}, false
	}
	return leaf.NotAfter, true
}

func selectCertificate(candidates []CertificateCandidate, ruleDomains string, now time.Time) (CertificateSelection, bool) {
	canonicalDomains, err := CanonicalACMEDomains(ruleDomains)
	if err != nil {
		return CertificateSelection{}, false
	}
	domains := strings.Split(canonicalDomains, ",")
	var selected CertificateSelection
	selectedExact := false
	found := false
	for _, candidate := range candidates {
		if candidate.Status == "disabled" {
			continue
		}
		certificate := candidate.Leaf
		if certificate == nil {
			pair, err := tls.X509KeyPair([]byte(candidate.CertPEM), []byte(candidate.KeyPEM))
			if err != nil || len(pair.Certificate) == 0 {
				continue
			}
			certificate = pair.Leaf
			if certificate == nil {
				certificate, err = x509.ParseCertificate(pair.Certificate[0])
			}
			if err != nil {
				continue
			}
		}
		if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			continue
		}
		coversDomains := true
		for _, domain := range domains {
			if certificate.VerifyHostname(domain) != nil {
				coversDomains = false
				break
			}
		}
		if !coversDomains {
			continue
		}
		candidateCanonical, canonicalErr := CanonicalACMEDomains(candidate.Domain)
		candidateExact := canonicalErr == nil && candidateCanonical == canonicalDomains
		candidateSelection := CertificateSelection{Candidate: candidate, Certificate: certificate}
		if !found || betterCertificate(selected, candidateSelection, selectedExact, candidateExact) {
			selected = candidateSelection
			selectedExact = candidateExact
			found = true
		}
	}
	return selected, found
}

// betterCertificate 返回 candidate 是否优于 selected：NotAfter 越晚（剩余有效期
// 越长）越优先，避免把快照到期更近的证书推给从节点；相同时精确域名匹配优先于
// 覆盖匹配，再按 updated_at、id 倒序决胜。
func betterCertificate(selected, candidate CertificateSelection, selectedExact, candidateExact bool) bool {
	if !candidate.Certificate.NotAfter.Equal(selected.Certificate.NotAfter) {
		return candidate.Certificate.NotAfter.After(selected.Certificate.NotAfter)
	}
	if candidateExact != selectedExact {
		return candidateExact
	}
	if candidate.Candidate.UpdatedAt != selected.Candidate.UpdatedAt {
		return candidate.Candidate.UpdatedAt > selected.Candidate.UpdatedAt
	}
	return candidate.Candidate.ID > selected.Candidate.ID
}
