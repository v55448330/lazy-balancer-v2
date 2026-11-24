package notify

import "testing"

// 绑定会话按属主隔离：轮询/中止都带发起用户 ID，他人持同一
// (type, scanner_id, bot_key) 既看不到 phase/receiver，也不能中止会话。
func TestBindSession_pollAndAbortAreOwnerScoped(t *testing.T) {
	const owner, other int64 = 41, 42
	t.Cleanup(func() {
		ClearBindSessionsByUser(owner)
		ClearBindSessionsByUser(other)
	})
	StartBindSessionWithCred(owner, "qq", "scan-owner", "bot-owner", "secret")

	if phase, _ := PollBindSession(owner, "qq", "scan-owner", "bot-owner"); phase != "awaiting_message" {
		t.Fatalf("属主轮询 phase=%q, want awaiting_message", phase)
	}
	if phase, receiver := PollBindSession(other, "qq", "scan-owner", "bot-owner"); phase != "idle" || receiver != "" {
		t.Fatalf("他人轮询不得看到会话: phase=%q receiver=%q", phase, receiver)
	}
	AbortBindSession(other, "qq", "scan-owner", "bot-owner")
	if phase, _ := PollBindSession(owner, "qq", "scan-owner", "bot-owner"); phase != "awaiting_message" {
		t.Fatalf("他人中止不得删除会话: phase=%q", phase)
	}
	AbortBindSession(owner, "qq", "scan-owner", "bot-owner")
	if phase, _ := PollBindSession(owner, "qq", "scan-owner", "bot-owner"); phase != "idle" {
		t.Fatalf("属主中止后 phase=%q, want idle", phase)
	}
}
