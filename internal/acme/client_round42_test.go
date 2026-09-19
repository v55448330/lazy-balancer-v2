package acme

import (
	"os"
	"path/filepath"
	"testing"
)

// CERT42-4（第 42 轮审计）：失效账户密钥清理的删除窗口内，元数据文件可能已被
// 外部清理（其他进程/手工删除）——元数据删除须与 key 删除同口径容忍
// os.ErrNotExist（文件已消失即目标终态），不得中止整轮清理。
func TestRemoveStaleAccountKeyPair_toleratesAlreadyRemovedMetadata(t *testing.T) {
	// Given the key file present but the metadata file already gone
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "stale.key")
	if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	metadataPath := keyPath + ".json"

	// When the pair is removed
	err := removeStaleAccountKeyPair(keyPath, metadataPath)

	// Then the missing metadata is tolerated and the key is still removed
	if err != nil {
		t.Fatalf("removeStaleAccountKeyPair()=%v, want nil（元数据已不存在应容忍）", err)
	}
	if _, statErr := os.Stat(keyPath); !os.IsNotExist(statErr) {
		t.Fatalf("key file still present: %v", statErr)
	}
}

// CERT42-4 回归形状：key 缺失元数据在（既有容忍口径保持）与双文件齐全
// （正常清理）两形态都不报错且全部删除。
func TestRemoveStaleAccountKeyPair_removesPresentFiles(t *testing.T) {
	t.Run("metadata present, key already gone", func(t *testing.T) {
		// Given only the metadata file
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "stale.key")
		metadataPath := keyPath + ".json"
		if err := os.WriteFile(metadataPath, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}

		// When
		err := removeStaleAccountKeyPair(keyPath, metadataPath)

		// Then
		if err != nil {
			t.Fatalf("removeStaleAccountKeyPair()=%v, want nil", err)
		}
		if _, statErr := os.Stat(metadataPath); !os.IsNotExist(statErr) {
			t.Fatalf("metadata file still present: %v", statErr)
		}
	})
	t.Run("both present", func(t *testing.T) {
		// Given both files
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "stale.key")
		metadataPath := keyPath + ".json"
		for _, path := range []string{keyPath, metadataPath} {
			if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}

		// When
		err := removeStaleAccountKeyPair(keyPath, metadataPath)

		// Then both are gone
		if err != nil {
			t.Fatalf("removeStaleAccountKeyPair()=%v, want nil", err)
		}
		for _, path := range []string{keyPath, metadataPath} {
			if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
				t.Fatalf("%s still present: %v", path, statErr)
			}
		}
	})
}
