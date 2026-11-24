package handlers

import "testing"

// 80/443 端口-TLS 语义只有一个事实源：portTLSSemanticsError（保存/启用/
// 聚合三门共用）。checkPortTLSMix 只负责同端口 TLS/明文混布查询——
// 三入口均先过单源门，其 80/443 分支是永远命不中的重复实现（且文案已分叉）。
func TestCheckPortTLSMix_leavesPortTLSSemanticsToSingleSource(t *testing.T) {
	newBackupTestHandlers(t) // checkPortTLSMix 查 live 规则表，需要初始化 DB
	if msg := portTLSSemanticsError("http", 80, true, false); msg == "" {
		t.Fatal("portTLSSemanticsError 未拦住 80+TLS（单源门缺失）")
	}
	if msg := portTLSSemanticsError("http", 443, false, false); msg == "" {
		t.Fatal("portTLSSemanticsError 未拦住 443+明文（单源门缺失）")
	}
	if err := checkPortTLSMix("", 80, true); err != nil {
		t.Fatalf("checkPortTLSMix 仍实现 80+TLS 语义（重复判定，与单源门文案/边界可漂移）: %v", err)
	}
	if err := checkPortTLSMix("", 443, false); err != nil {
		t.Fatalf("checkPortTLSMix 仍实现 443+明文语义（重复判定，与单源门文案/边界可漂移）: %v", err)
	}
}
