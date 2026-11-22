package services

// 安全库终态事件的「版本/详情」字段（CRS/IP2Region 共用）：版本缺失时给
// 可读兜底，避免正文出现「版本：」。

import "strings"

func libUpdateVersionDetail(version string) string {
	if strings.TrimSpace(version) == "" {
		return "已完成"
	}
	return "版本 " + version
}
