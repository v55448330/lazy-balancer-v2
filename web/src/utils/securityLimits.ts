/**
 * 安全域「名称 / 描述」长度上限：后端 `internal/handlers/security.go` 的
 * `securityNameMaxRunes`（名称 100 rune）与 `securityDescriptionMaxRunes`
 * （描述 500 rune）是唯一事实源，拦截页 / 自定义规则 / 安全策略三处写入口
 * 共用同一组常量（含备份还原路径）。
 *
 * 前端曾把这组数字以字面量写在各输入框上：后端放宽或收紧时控件不会跟着变，
 * 用户要么提前被截断、要么输入超长在保存时才吃 400。此处单源化并由
 * `web/tests/securityLimits.spec.ts` 与后端常量逐值对表（改一侧必须改两侧）。
 */
export const SECURITY_NAME_MAX_RUNES = 100
export const SECURITY_DESCRIPTION_MAX_RUNES = 500
