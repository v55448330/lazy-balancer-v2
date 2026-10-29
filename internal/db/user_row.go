package db

import (
	"fmt"

	"lazy-balancer-v2/internal/models"
)

// userRowColumnsTemplate 是「构造 UserResponse 所需」的用户行列清单单源
// （%[1]s 为表别名前缀，JOIN 查询传 "u."，单表查询传空串）。顺序与
// ScanUserRow 的扫描目标逐一对应。
//
// 单源的原因：此前登录/me/PATCH me/PUT/MFA 五处各手写一份列清单，新增
// is_setup_admin 时只有列表查询补了列——其余端点仍返回零值 false，前端
// 与脚本据 /users/me 判定 break-glass 身份会得到与列表相反的答案。新增
// 响应字段只改这里 + 在 ScanUserRow 接住（两处都在本文件，改动不会分裂）。
const userRowColumnsTemplate = "%[1]sid, %[1]susername, %[1]srole, %[1]sdisplay_name, %[1]sis_enabled, %[1]screated_at, %[1]slast_login, %[1]spassword_version, COALESCE(%[1]sauth_provider,'local'), COALESCE(%[1]smfa_enabled,0), COALESCE(%[1]sis_setup_admin,0)"

// UserRowColumns 返回用户行列清单（写入 `SELECT ` 之后、追加列之前）。
// alias 非空时逐列加表别名前缀（多表 JOIN 必须限定列归属）。
func UserRowColumns(alias string) string {
	prefix := ""
	if alias != "" {
		prefix = alias + "."
	}
	return fmt.Sprintf(userRowColumnsTemplate, prefix)
}

// UserRowMeta 承载 UserRowColumns 中「载入但不进响应体」的两列。
type UserRowMeta struct {
	// PasswordVersion 用于 JWT 的 pwd_ver 声明与 MFA 挑战版本比对。
	PasswordVersion int64
	// MFAEnabled 由调用方传给 models.NewUserResponse。
	MFAEnabled bool
}

// ScanUserRow 按 UserRowColumns 的顺序扫描一行用户记录；extra 依次追加在
// 清单末尾（调用方在 UserRowColumns 之后 SELECT 的附加列，如 password_hash、
// 挑战表的 password_version）。
func ScanUserRow(scanner interface{ Scan(dest ...any) error }, meta *UserRowMeta, extra ...any) (models.User, error) {
	var user models.User
	// mfa_enabled/is_setup_admin 以整型目标接（COALESCE 归一后恒两态，int
	// 扫描稳妥）；is_enabled 直接扫 bool——启动归一（normalizeUsersIsEnabledDomain）
	// 与 NOT NULL 重建共同保证值域恒 0/1，database/sql 的 driver.Bool 只认
	// 两态，带外非 0/1 值会在此报错（读取端点 500），这正是启动归一存在的根因。
	var mfaEnabled, setupAdmin int
	dest := []any{
		&user.ID,
		&user.Username,
		&user.Role,
		&user.DisplayName,
		&user.IsEnabled,
		&user.CreatedAt,
		&user.LastLogin,
		&meta.PasswordVersion,
		&user.AuthProvider,
		&mfaEnabled,
		&setupAdmin,
	}
	dest = append(dest, extra...)
	if err := scanner.Scan(dest...); err != nil {
		return models.User{}, err
	}
	meta.MFAEnabled = mfaEnabled == 1
	user.IsSetupAdmin = setupAdmin == 1
	return user, nil
}
