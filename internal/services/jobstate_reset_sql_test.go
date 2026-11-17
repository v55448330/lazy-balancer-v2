package services

// IssuedFinalizeResetSQL 与 issuedFinalizeResetFields 字段集对账钉——
// SQL 片段单源必须恰覆盖 map 单源全部预算键（增列时两侧同步，漏项即红）。

import (
	"strings"
	"testing"
)

func TestIssuedFinalizeResetSQL_matchesFields(t *testing.T) {
	sqlFrag := IssuedFinalizeResetSQL()
	fields := issuedFinalizeResetFields()
	parts := strings.Split(sqlFrag, ",")
	if len(parts) != len(fields) {
		t.Fatalf("SQL 片段键数=%d, want map 单源键数 %d（增列必须两侧同步）", len(parts), len(fields))
	}
	for key, v := range fields {
		want := key + "=NULL"
		if v != nil {
			want = key + "=0"
		}
		found := false
		for _, p := range parts {
			if strings.TrimSpace(p) == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("SQL 片段缺预算键 %q（want %q）: %q", key, want, sqlFrag)
		}
	}
}
