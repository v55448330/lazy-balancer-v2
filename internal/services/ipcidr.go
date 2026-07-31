package services

import (
	"fmt"
	"net"
	"strings"
)

func NormalizeCIDRs(values []string) ([]string, error) {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if ip := net.ParseIP(value); ip != nil {
			if ip.To4() != nil {
				value += "/32"
			} else {
				value += "/128"
			}
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("%q 不是有效 CIDR", value)
		}
		normalized = append(normalized, network.String())
	}
	return normalized, nil
}
