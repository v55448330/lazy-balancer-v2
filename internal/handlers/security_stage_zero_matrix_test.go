package handlers

// 阶段外字段归零矩阵的守卫面。键集必须从生产模型派生（reflect 遍历
// models.UpdateSecurityPolicyRequest 的指针字段），矩阵只作期望集——
// 此前三张手写清单（矩阵/createShape/updateShape）互为镜像，模型新增
// 阶段字段而清单两侧同时漏掉时全部等长、恒绿，门宣称的「任一侧漏字段
// 即红」不成立。现在模型一侧是唯一键源：新增字段未进矩阵（或未登记豁免）
// 即红，漏登记必须是一次显式决策。

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// stageZeroMatrixFields 是归零矩阵管辖的全部字段（与 outOfStageZeroFamilies
// 的族展开一一对应）。键集受 TestStageZeroMatrix_updatePointerFieldsCoveredByMatrix
// 约束：与生产模型指针字段集（扣除豁免）双向相等。
var stageZeroMatrixFields = []string{
	"mode",
	"crs_rule_groups",
	"crs_excluded_rules",
	"custom_rules",
	"rate_limit_enabled",
	"rate_limit_rps",
	"rate_limit_burst",
	"waf_check_response",
	"log_request_body",
	"ip_acl_enabled",
	"ip_acl_list",
	"ip_acl_list_refs",
	"ip_whitelist_enabled",
	"ip_whitelist",
	"ip_whitelist_refs",
	"ip_blacklist",
	"geoip_mode",
	"geoip_countries",
	"geoip_crawler_exempt",
	"geoip_crawler_engines",
	"block_page_id",
	"block_status_code",
	"trust_detection",
}

// stageZeroExemptFields 不参与阶段归零矩阵的指针字段（豁免理由必须登记，
// 拼写漂移会让豁免静默失效，由覆盖门校验真实存在）：
// name/description 标识与描述、enabled 启停正交、anomaly_threshold 全阶段
// 共用阈值、ip_acl_mode 随 ip_acl_enabled 的展示形态（矩阵只清 enabled 与
// 名单族）、policy_type 是矩阵开关本身。
var stageZeroExemptFields = map[string]string{
	"name":              "标识字段",
	"description":       "描述字段",
	"anomaly_threshold": "全阶段共用阈值",
	"ip_acl_mode":       "随 ip_acl_enabled 的展示形态（矩阵只清 enabled/名单族）",
	"enabled":           "启停正交",
	"policy_type":       "矩阵开关本身",
}

// stageZeroJSONTag 返回结构体字段的 json 键（无 tag/- 为不可管理字段）。
func stageZeroJSONTag(f reflect.StructField) (string, bool) {
	tag := strings.Split(f.Tag.Get("json"), ",")[0]
	if tag == "" || tag == "-" {
		return "", false
	}
	return tag, true
}

// TestStageZeroMatrix_updatePointerFieldsCoveredByMatrix 键集门：
// models.UpdateSecurityPolicyRequest 的全部指针字段 = 矩阵 ∪ 豁免，双向相等。
// 模型新增阶段字段而矩阵漏登记（或矩阵残留已删字段）在此显形。
func TestStageZeroMatrix_updatePointerFieldsCoveredByMatrix(t *testing.T) {
	tt := reflect.TypeOf(models.UpdateSecurityPolicyRequest{})
	inventory := make(map[string]bool, tt.NumField())
	for i := range tt.NumField() {
		f := tt.Field(i)
		tag, ok := stageZeroJSONTag(f)
		if !ok {
			continue
		}
		if f.Type.Kind() != reflect.Ptr {
			t.Fatalf("字段 %s（%s）非指针形态：矩阵口径只覆盖指针字段，新增非指针字段需同步登记", tag, f.Name)
		}
		inventory[tag] = true
	}
	for tag, reason := range stageZeroExemptFields {
		if reason == "" {
			t.Fatalf("豁免字段 %s 未登记理由（豁免必须携带归属说明）", tag)
		}
		if !inventory[tag] {
			t.Fatalf("豁免字段 %s 不在 UpdateSecurityPolicyRequest 中（结构体或豁免表漂移）", tag)
		}
	}
	var missing, extra []string
	for tag := range inventory {
		if _, exempt := stageZeroExemptFields[tag]; exempt {
			continue
		}
		if !slices.Contains(stageZeroMatrixFields, tag) {
			missing = append(missing, tag)
		}
	}
	for _, tag := range stageZeroMatrixFields {
		if !inventory[tag] {
			extra = append(extra, tag)
		}
	}
	if len(missing)+len(extra) > 0 {
		t.Fatalf("矩阵键集与模型指针字段漂移：矩阵缺少 %v，矩阵多出 %v（新增字段必须进矩阵或登记豁免）", missing, extra)
	}
}

// stageZeroStringZero 判定「阶段外归一」语义下字符串字段的零形态：空串恒零；
// mode 族认 "off"（applyStageZeros 的 mode 归一口径）；列表族认 "[]"（JSON
// 空清单）。
func stageZeroStringZero(tag, value string) bool {
	if value == "" {
		return true
	}
	if tag == "mode" || tag == "geoip_mode" {
		return value == "off"
	}
	return value == "[]"
}

// stageZeroValueZero 判定非指针值的零形态（int 0 / bool false / 字符串规则见上）。
func stageZeroValueZero(tag string, value reflect.Value) bool {
	switch value.Kind() {
	case reflect.String:
		return stageZeroStringZero(tag, value.String())
	case reflect.Int:
		return value.Int() == 0
	case reflect.Bool:
		return !value.Bool()
	}
	return false
}

// stageZeroManagedFields 返回类型中参与矩阵的字段（json 键非豁免）。
func stageZeroManagedFields(tt reflect.Type) []reflect.StructField {
	var fields []reflect.StructField
	for i := 0; i < tt.NumField(); i++ {
		f := tt.Field(i)
		tag, ok := stageZeroJSONTag(f)
		if !ok {
			continue
		}
		if _, exempt := stageZeroExemptFields[tag]; exempt {
			continue
		}
		fields = append(fields, f)
	}
	return fields
}

// 阶段外字段归零矩阵必须单源——Create 与 Update 两条写路径对同一阶段
// 归零同一组字段。此前双份逐字段 switch 已产生
// IPWhitelistEnabled nil/false 形状漂移。本测试把两条 applier 的决策逐阶段对齐：
// 请求全字段填入非零哨兵值，归零后两边的「字段→零/非零」视图必须完全一致。
func TestStageZeroMatrix_createUpdateParity(t *testing.T) {
	stages := []string{
		models.PolicyTypeStage0, models.PolicyTypeStage1,
		models.PolicyTypeStage2, models.PolicyTypeStage3,
	}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			createReq := pollutedCreateRequest()
			applyStageZerosToCreate(&createReq, stage)
			updateReq := pollutedUpdateRequest()
			applyStageZerosToUpdate(&updateReq, stage)

			created := createShape(createReq)
			updated := updateShape(updateReq)
			if len(created) != len(stageZeroMatrixFields) || len(updated) != len(stageZeroMatrixFields) {
				t.Fatalf("形状键集=create %d/update %d, 声明矩阵 %d（多出或漏掉的键必须先更新声明矩阵）",
					len(created), len(updated), len(stageZeroMatrixFields))
			}
			for _, field := range stageZeroMatrixFields {
				want, ok := created[field]
				if !ok {
					t.Fatalf("stage=%s: create 形状缺少矩阵字段 %s", stage, field)
				}
				got, ok := updated[field]
				if !ok {
					t.Fatalf("stage=%s: update 形状缺少矩阵字段 %s", stage, field)
				}
				if got != want {
					t.Fatalf("stage=%s field=%s: create zeroed=%v, update zeroed=%v（矩阵必须单源）", stage, field, want, got)
				}
			}
			// 阶段内字段不得被误清零：每阶段至少保留一项非零哨兵
			if !hasNonZero(created) {
				t.Fatalf("stage=%s: 所有字段被归零（矩阵过度清零）", stage)
			}
		})
	}
}

// 归零矩阵的指针别名钉：每个字段必须是独立变量地址（new(expr) 每字段一份）。
// 共享同一局部变量时，将来任何 `*req.X = v` 形态的归一都会经别名同时改写
// 多个落库字段，且在 review 中不可见。字段清单从模型指针字段反射派生
// （键集门已保证矩阵与模型一致），不再手抄第二份。
func TestStageZeroMatrix_zeroPointersAreDistinct(t *testing.T) {
	stages := []string{
		models.PolicyTypeStage0, models.PolicyTypeStage1,
		models.PolicyTypeStage2, models.PolicyTypeStage3,
	}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			req := pollutedUpdateRequest()
			applyStageZerosToUpdate(&req, stage)
			v := reflect.ValueOf(req)
			fields := map[string]any{}
			for _, f := range stageZeroManagedFields(v.Type()) {
				tag, _ := stageZeroJSONTag(f)
				fields[tag] = v.FieldByIndex(f.Index).Interface()
			}
			seen := make(map[uintptr]string, len(fields))
			for name, ptr := range fields {
				if ptr == nil {
					continue
				}
				addr := reflect.ValueOf(ptr).Pointer()
				if prev, dup := seen[addr]; dup {
					t.Fatalf("%s 与 %s 共享同一指针地址（归零矩阵别名，写入会互相覆盖）", name, prev)
				}
				seen[addr] = name
			}
		})
	}
}

// 矩阵内容钉住（各阶段保留面）：防止「单源但改错」。
func TestStageZeroMatrix_keepsInStageFields(t *testing.T) {
	cases := []struct {
		stage  string
		field  string
		zeroed bool
	}{
		{models.PolicyTypeStage0, "trust_detection", false},
		{models.PolicyTypeStage0, "block_page_id", true},
		{models.PolicyTypeStage1, "ip_acl_list", false},
		{models.PolicyTypeStage1, "geoip_countries", false},
		{models.PolicyTypeStage1, "geoip_crawler_engines", false},
		{models.PolicyTypeStage1, "trust_detection", true},
		{models.PolicyTypeStage2, "rate_limit_rps", false},
		{models.PolicyTypeStage2, "block_page_id", false},
		{models.PolicyTypeStage2, "block_status_code", true},
		{models.PolicyTypeStage2, "geoip_crawler_engines", true},
		{models.PolicyTypeStage3, "crs_rule_groups", false},
		{models.PolicyTypeStage3, "rate_limit_rps", true},
		{models.PolicyTypeStage3, "ip_acl_enabled", true},
	}
	for _, tc := range cases {
		createReq := pollutedCreateRequest()
		applyStageZerosToCreate(&createReq, tc.stage)
		shape := createShape(createReq)
		got, ok := shape[tc.field]
		if !ok {
			t.Fatalf("stage=%s field=%s 不在声明矩阵中（键集漂移）", tc.stage, tc.field)
		}
		if got != tc.zeroed {
			t.Fatalf("stage=%s field=%s zeroed=%v, want %v", tc.stage, tc.field, got, tc.zeroed)
		}
	}
}

func pollutedCreateRequest() models.CreateSecurityPolicyRequest {
	yes := true
	return models.CreateSecurityPolicyRequest{
		Name:                "p",
		Mode:                "blocking",
		IPACLMode:           "deny",
		IPACLList:           `["10.0.0.0/8"]`,
		IPACLListRefs:       `[1]`,
		IPACLEnabled:        true,
		IPWhitelist:         `["192.168.1.1"]`,
		IPWhitelistRefs:     `[2]`,
		IPWhitelistEnabled:  &yes,
		IPBlacklist:         `["203.0.113.9"]`,
		RateLimitEnabled:    true,
		RateLimitRPS:        120,
		RateLimitBurst:      240,
		CRSRuleGroups:       `[942]`,
		CRSExcludedRules:    `[942100]`,
		CustomRules:         `[1]`,
		BlockPageID:         3,
		BlockStatusCode:     403,
		GeoIPCountries:      `["CN"]`,
		GeoIPMode:           "deny",
		GeoIPCrawlerExempt:  true,
		GeoIPCrawlerEngines: `["googlebot"]`,
		WAFCheckResponse:    true,
		LogRequestBody:      true,
		TrustDetection:      true,
	}
}

func pollutedUpdateRequest() models.UpdateSecurityPolicyRequest {
	c := pollutedCreateRequest()
	return models.UpdateSecurityPolicyRequest{
		Name:                &c.Name,
		Mode:                &c.Mode,
		IPACLMode:           &c.IPACLMode,
		IPACLList:           &c.IPACLList,
		IPACLListRefs:       &c.IPACLListRefs,
		IPACLEnabled:        &c.IPACLEnabled,
		IPWhitelist:         &c.IPWhitelist,
		IPWhitelistRefs:     &c.IPWhitelistRefs,
		IPWhitelistEnabled:  c.IPWhitelistEnabled,
		IPBlacklist:         &c.IPBlacklist,
		RateLimitEnabled:    &c.RateLimitEnabled,
		RateLimitRPS:        &c.RateLimitRPS,
		RateLimitBurst:      &c.RateLimitBurst,
		CRSRuleGroups:       &c.CRSRuleGroups,
		CRSExcludedRules:    &c.CRSExcludedRules,
		CustomRules:         &c.CustomRules,
		BlockPageID:         &c.BlockPageID,
		BlockStatusCode:     &c.BlockStatusCode,
		GeoIPCountries:      &c.GeoIPCountries,
		GeoIPMode:           &c.GeoIPMode,
		GeoIPCrawlerExempt:  &c.GeoIPCrawlerExempt,
		GeoIPCrawlerEngines: &c.GeoIPCrawlerEngines,
		WAFCheckResponse:    &c.WAFCheckResponse,
		LogRequestBody:      &c.LogRequestBody,
		TrustDetection:      &c.TrustDetection,
	}
}

// createShape/updateShape 从请求结构体反射派生「字段→是否归零」视图：指针
// 字段 nil 或指向零值即零（与 applyStageZerosTo* 的赋值口径逐类一致：
// 字符串 ""/[]"/"off"（mode 族）、int 0、bool false）。键集受覆盖门约束，
// 不再与矩阵互为镜像。
func createShape(r models.CreateSecurityPolicyRequest) map[string]bool {
	shape := map[string]bool{}
	v := reflect.ValueOf(r)
	for _, f := range stageZeroManagedFields(v.Type()) {
		tag, _ := stageZeroJSONTag(f)
		fv := v.FieldByIndex(f.Index)
		if fv.Kind() == reflect.Ptr {
			shape[tag] = fv.IsNil() || stageZeroValueZero(tag, fv.Elem())
			continue
		}
		shape[tag] = stageZeroValueZero(tag, fv)
	}
	return shape
}

func updateShape(r models.UpdateSecurityPolicyRequest) map[string]bool {
	shape := map[string]bool{}
	v := reflect.ValueOf(r)
	for _, f := range stageZeroManagedFields(v.Type()) {
		tag, _ := stageZeroJSONTag(f)
		fv := v.FieldByIndex(f.Index)
		shape[tag] = fv.IsNil() || stageZeroValueZero(tag, fv.Elem())
	}
	return shape
}

func hasNonZero(shape map[string]bool) bool {
	for _, zeroed := range shape {
		if !zeroed {
			return true
		}
	}
	return false
}
