package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// 威胁情报库（v2.3.x）：内置只读三源的管理面——展示、双开关、手动更新、
// 条目查看、导出。不提供任何源的新建/编辑/删除（用户不可删改）。

type threatSourceDTO struct {
	ID            int    `json:"id"`
	Name          string `json:"name"`
	DisplayName   string `json:"display_name"`
	URL           string `json:"url"`
	Format        string `json:"format"`
	UpdateEnabled bool   `json:"update_enabled"`
	ApplyEnabled  bool   `json:"apply_enabled"`
	EntryCount    int    `json:"entry_count"`
	Version       string `json:"version"`
	UpdateStatus  string `json:"update_status"`
	Message       string `json:"message"`
	LastChecked   string `json:"last_checked"`
	NextUpdate    string `json:"next_update"`
}

func (h *Handlers) GetThreatLib(c *gin.Context) {
	rows, err := db.DB.Query(`SELECT id, name, display_name, url, format, update_enabled, apply_enabled,
		entry_count, version, update_status, message, COALESCE(last_checked,''), COALESCE(next_update,'')
		FROM security_threat_sources ORDER BY id`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取威胁情报库失败: " + err.Error()})
		return
	}
	defer rows.Close()
	sources := []threatSourceDTO{}
	mergedApplyCount := 0
	for rows.Next() {
		var s threatSourceDTO
		if err := rows.Scan(&s.ID, &s.Name, &s.DisplayName, &s.URL, &s.Format, &s.UpdateEnabled, &s.ApplyEnabled,
			&s.EntryCount, &s.Version, &s.UpdateStatus, &s.Message, &s.LastChecked, &s.NextUpdate); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取威胁情报库失败: " + err.Error()})
			return
		}
		if s.ApplyEnabled {
			mergedApplyCount += s.EntryCount
		}
		sources = append(sources, s)
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"sources":            sources,
		"merged_apply_count": mergedApplyCount,
	}})
}

// UpdateThreatSourceFlags 仅允许改 update_enabled/apply_enabled 两字段——
// 请求体即便携带 url/name/format 也一律忽略（内置源不可变造）。apply 开关
// 变更触发主节点重载（id:14 规则随合并文件生效/停用——实际以渲染期文件
// 存在性为准，合并文件由下次更新重建）。
func (h *Handlers) UpdateThreatSourceFlags(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的源 ID"})
		return
	}
	var body struct {
		UpdateEnabled *bool `json:"update_enabled"`
		ApplyEnabled  *bool `json:"apply_enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求无效"})
		return
	}
	if body.UpdateEnabled == nil && body.ApplyEnabled == nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无可更新字段"})
		return
	}
	var name string
	if err := db.DB.QueryRow(`SELECT name FROM security_threat_sources WHERE id=?`, id).Scan(&name); err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "威胁库源不存在"})
		return
	}
	if body.UpdateEnabled != nil {
		if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_enabled=?, updated_at=datetime('now') WHERE id=?`, *body.UpdateEnabled, id); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新失败: " + err.Error()})
			return
		}
	}
	if body.ApplyEnabled != nil {
		if _, err := db.DB.Exec(`UPDATE security_threat_sources SET apply_enabled=?, updated_at=datetime('now') WHERE id=?`, *body.ApplyEnabled, id); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新失败: " + err.Error()})
			return
		}
		// 合并文件即刻按新开关重建（关闭的源退出并集），随后主节点重载。
		// nil=更新服务未初始化（测试注入形态）——开关落库不受影响。
		if mgr := services.GetThreatUpdateManager(); mgr != nil {
			mgr.RebuildMergedFile()
		}
		var isMaster bool
		if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err == nil && isMaster {
			if h.caddyService != nil {
				if err := h.caddyService.GenerateAndApplyConfig(); err != nil {
					services.Logf("error", "威胁库应用开关变更后重载失败: %v", err)
				}
			}
		}
	}
	recordAudit(c, "更新", "威胁情报库", fmt.Sprintf("%s 更新开关", name))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已更新"})
}

// StartThreatLibUpdate 手动触发更新（主节点；镜像 StartCRSUpdate 的受理/
// 重复任务 409 语义）。
func (h *Handlers) StartThreatLibUpdate(c *gin.Context) {
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		clusterError(c, http.StatusForbidden, "该操作仅允许在主节点执行", err)
		return
	}
	mgr := services.GetThreatUpdateManager()
	if mgr == nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "威胁库更新服务未初始化"})
		return
	}
	if _, err := mgr.StartUpdate("manual"); err != nil {
		if errors.Is(err, services.ErrThreatUpdateRunning) {
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	recordAudit(c, "手动更新", "威胁情报库", "手动更新 威胁情报库")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"status": "running", "trigger": "manual"}})
}

// threatSourceFilePath 按源 id 解析条目文件路径（只允许内置源 name，
// 文件名经 DB 反查——不接受路径输入，天然无穿越面）。
func threatSourceFilePath(id int) (string, string, error) {
	var name string
	if err := db.DB.QueryRow(`SELECT name FROM security_threat_sources WHERE id=?`, id).Scan(&name); err != nil {
		return "", "", err
	}
	return filepath.Join(services.ThreatDataDir, name+".txt"), name, nil
}

func readThreatEntries(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var entries []string
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			entries = append(entries, line)
		}
	}
	return entries, nil
}

func (h *Handlers) GetThreatSourceEntries(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的源 ID"})
		return
	}
	path, _, err := threatSourceFilePath(id)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "威胁库源不存在"})
		return
	}
	entries, err := readThreatEntries(path)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "该源尚无已下载的威胁库数据"})
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "200"))
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 1000 {
		size = 200
	}
	start := (page - 1) * size
	if start > len(entries) {
		start = len(entries)
	}
	end := start + size
	if end > len(entries) {
		end = len(entries)
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"total":   len(entries),
		"page":    page,
		"size":    size,
		"entries": entries[start:end],
	}})
}

func (h *Handlers) ExportThreatSource(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的源 ID"})
		return
	}
	path, name, err := threatSourceFilePath(id)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "威胁库源不存在"})
		return
	}
	if _, err := os.Stat(path); err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "该源尚无已下载的威胁库数据"})
		return
	}
	recordAudit(c, "导出", "威胁情报库", fmt.Sprintf("导出 %s", name))
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"threat-%s-%s.txt\"", name, time.Now().UTC().Format("2006.01.02")))
	c.File(path)
}
