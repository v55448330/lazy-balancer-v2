package handlers

// 威胁情报库与爬虫地址库的「源开关」状态机单源：两条端点的门序、三分支
// 错误映射、状态归一与审计文案骨架逐字同构，任何单边修改都会静默分叉。
// 差异面全部经 libSourceFlagsSpec 注入。

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// libSourceFlagsSpec 两个源开关端点的差异面。
// Table 只接受包内常量（不拼用户输入），因此可直接内联进 SQL。
type libSourceFlagsSpec struct {
	Table         string
	Family        string
	NotFoundMsg   string
	ReadErrMsg    string
	UpdateErrMsg  string
	ArmFirstSlots func()
	InternalError func(message string, err error) models.APIResponse
}

// requireLibSourceFlagRowUpdated 把 0 行更新判为源已消失（404），其余
// RowsAffected 故障为 500；只返回「是否可继续提交」。
func requireLibSourceFlagRowUpdated(result sql.Result, c *gin.Context, spec libSourceFlagsSpec) bool {
	affected, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, spec.InternalError(spec.UpdateErrMsg, err))
		return false
	}
	if affected == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: spec.NotFoundMsg})
		return false
	}
	return true
}

// updateLibSourceFlags 更新源开关（update_enabled 单字段）的共享状态机：
//
//	导入窗口 409（先于 body 解析）→ JSON 体守卫 → ID/体校验 → 主节点门 →
//	开启事务后读 name/wasEnabled（缺行 404、其余 DB 故障 500）→ 同一事务内
//	启用（仅「由关闭转为启用」清失败态）或关闭（清失败态与排程槽、失败计数
//	清零）→ 校验 RowsAffected（0=404，不得假成功）→ commit → 仅在真实
//	「关闭→启用」变更后武装首槽 → 审计。
func updateLibSourceFlags(c *gin.Context, spec libSourceFlagsSpec) {
	// 源表在导入全量替代表清单内：窗口内写会被静默覆盖或撞写锁 500——
	// 与相邻库端点同口径 409 fast-fail，先于 body 解析。
	if rejectWriteDuringImport(c, fmt.Sprintf("修改%s设置（配置导入进行中）", spec.Family)) {
		return
	}
	if !guardConfiguredJSONBody(c) {
		return
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的源 ID"})
		return
	}
	var body struct {
		UpdateEnabled *bool `json:"update_enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求无效"})
		return
	}
	if body.UpdateEnabled == nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无可更新字段"})
		return
	}
	if !requireMasterNode(c) {
		return
	}
	var name string
	var wasEnabled int
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, spec.InternalError(spec.ReadErrMsg, err))
		return
	}
	defer func() { _ = tx.Rollback() }()
	if err := tx.QueryRow(
		fmt.Sprintf(`SELECT name, COALESCE(update_enabled,0) FROM %s WHERE id=?`, spec.Table), id,
	).Scan(&name, &wasEnabled); err != nil {
		// 三分支：缺行=404，其余 DB 故障=500（可重试故障不得误报「源不存在」）。
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: spec.NotFoundMsg})
		} else {
			c.JSON(http.StatusInternalServerError, spec.InternalError(spec.ReadErrMsg, err))
		}
		return
	}
	transitionDisabledToEnabled := wasEnabled == 0 && *body.UpdateEnabled
	if *body.UpdateEnabled {
		// 仅「由关闭转为启用」时清失败态（idle+空文案+计数清零）；已启用源
		// 重复提交不改运行态（否则留下「failed + 空失败文案」形态）。
		query := fmt.Sprintf(`UPDATE %s SET update_enabled=1, updated_at=datetime('now') WHERE id=?`, spec.Table)
		if wasEnabled == 0 {
			query = fmt.Sprintf(`UPDATE %s SET update_enabled=1, update_status='idle', message='', consecutive_failures=0, updated_at=datetime('now') WHERE id=?`, spec.Table)
		}
		result, err := tx.Exec(query, id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, spec.InternalError(spec.UpdateErrMsg, err))
			return
		}
		if !requireLibSourceFlagRowUpdated(result, c, spec) {
			return
		}
	} else {
		// 关闭即退出更新任务：清掉关闭前的瞬时失败态与排程槽，否则列表/库头
		// 继续显示「更新失败」，重新启用还会因残留未来槽无法武装首槽。
		// consecutive_failures 同步清零（经集群快照复制的失败计数不得跨禁用期
		// 陈旧）。
		result, err := tx.Exec(fmt.Sprintf(`UPDATE %s SET update_enabled=0, update_status='idle', message='已关闭自动更新', next_update=NULL, consecutive_failures=0, updated_at=datetime('now') WHERE id=?`, spec.Table), id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, spec.InternalError(spec.UpdateErrMsg, err))
			return
		}
		if !requireLibSourceFlagRowUpdated(result, c, spec) {
			return
		}
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, spec.InternalError(spec.UpdateErrMsg, err))
		return
	}
	// 单源启用即武装首槽——总闸已开且无任何启用源持 next_update 时，仅改开关
	// 会让排程槽恒空。只有关闭→启用的真实变更才需要（重复启用不变更运行态）。
	if transitionDisabledToEnabled && spec.ArmFirstSlots != nil {
		spec.ArmFirstSlots()
	}
	recordAudit(c, "更新", spec.Family, fmt.Sprintf("%s 更新开关：%s", name, enabledStateLabel(*body.UpdateEnabled)))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已更新"})
}
