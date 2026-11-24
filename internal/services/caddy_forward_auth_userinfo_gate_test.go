package services

import (
	"testing"
)

// 认证网关地址的既有契约是「只承载 scheme://host:port，路径/查询/凭据一律
// 另配并在写侧显式拒绝」——渲染层只消费 Hostname()+Port()，userinfo 会被
// 静默丢弃：网关于是所有子请求都无认证信息（401/302），而配置看起来完全
// 合法。同仓已对集群节点地址（https://user:pass@node）判非法，本字段此前
// 漏了同一条门。
func TestValidateForwardAuthGatewayAddressForWrite_rejectsUserinfo(t *testing.T) {
	for _, upstream := range []string{
		"http://user:pass@gw:7000",
		"https://authelia:secret@auth.example.test",
		"http://user@gw:7000",
	} {
		if err := ValidateForwardAuthGatewayAddressForWrite(upstream); err == nil {
			t.Fatalf("认证网关地址 %q 带凭据必须写侧拒绝（渲染只取 host:port，凭据被静默丢弃）", upstream)
		}
		// 渲染/读取侧保持宽容：存量数据不得让整份配置生成失败。
		if _, _, err := ValidateForwardAuthGatewayAddress(upstream); err != nil {
			t.Fatalf("读侧必须对存量带凭据地址保持宽容: %v", err)
		}
	}
	for _, upstream := range []string{
		"http://gw:7000",
		"https://auth.example.test",
		"http://gw:7000/",
	} {
		if err := ValidateForwardAuthGatewayAddressForWrite(upstream); err != nil {
			t.Fatalf("合法地址 %q 不得被拒: %v", upstream, err)
		}
	}
}
