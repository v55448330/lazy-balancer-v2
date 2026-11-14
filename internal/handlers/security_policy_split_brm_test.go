package handlers

// 混合策略拆分的子策略必须继承原策略的拦截响应方式（block_response_mode）：
// 拆分是列值原样复制，响应方式丢失会让子策略回退 auto——原策略显式 json/html
// 的拦截响应在迁移后静默变脸。子策略落库列投影与 Create 共用单一清单，
// 新增列不再可能「Create 有、拆分漏」。

import (
	"encoding/json"
	"net/http"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestSplitSecurityPolicy_childrenInheritBlockResponseMode(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := splitRouter(t)
	res, err := db.DB.Exec(`INSERT INTO security_policies (name,mode,ip_acl_enabled,ip_acl_mode,ip_acl_list,human_verify_mode,human_verify_type,block_response_mode,policy_type,enabled)
		VALUES ('brm-mix','blocking',1,'deny','["203.0.113.0/24"]','force','slider','json','mixed',1)`)
	if err != nil {
		t.Fatal(err)
	}
	mixedID, _ := res.LastInsertId()

	response := postSplit(t, router, int(mixedID))
	if response.Code != http.StatusOK {
		t.Fatalf("split status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var payload splitPayload
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, response.Body.String())
	}
	if len(payload.Data.Created) != 3 {
		t.Fatalf("created=%+v, want 3 children（G1+G2+G3）", payload.Data.Created)
	}
	for _, child := range payload.Data.Created {
		var mode string
		if err := db.DB.QueryRow(`SELECT COALESCE(block_response_mode,'') FROM security_policies WHERE id=?`, child.ID).Scan(&mode); err != nil {
			t.Fatalf("read child %d block_response_mode: %v", child.ID, err)
		}
		if mode != "json" {
			t.Fatalf("子策略 %s（%s）block_response_mode=%q, want json（继承原策略）", child.Name, child.PolicyType, mode)
		}
	}
}
