package services

import (
	"crypto/tls"
	"crypto/x509"
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
}

type CertificateSelection struct {
	Candidate   CertificateCandidate
	Certificate *x509.Certificate
}

func SelectCertificate(candidates []CertificateCandidate, ruleDomains string, now time.Time) (CertificateSelection, bool) {
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
		pair, err := tls.X509KeyPair([]byte(candidate.CertPEM), []byte(candidate.KeyPEM))
		if err != nil || len(pair.Certificate) == 0 {
			continue
		}
		certificate := pair.Leaf
		if certificate == nil {
			certificate, err = x509.ParseCertificate(pair.Certificate[0])
		}
		if err != nil || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
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
