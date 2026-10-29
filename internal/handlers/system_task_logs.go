package handlers

import (
	"database/sql"
	"errors"
	"strconv"
	"strings"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

// beforeSystemTaskLogDBQuery 关停交错测试缝（生产 no-op）：落在局部
// 句柄快照与查询之间，证明不再二次读取包级 db.DB。
var beforeSystemTaskLogDBQuery = func() {}

// systemTaskLogPathResolver 任务日志路径批量解析入口：普通注册任务直接按
// 任务 ID；cert-job 动态工作项一次全表预载 job_id→rule_id，供批量调用方
// （logstats 逐任务解析）复用避免 N+1。单条入口（GetSystemTaskLogs）走
// systemTaskLogPath 的单行查询，不经本 resolver。
type systemTaskLogPathResolver struct {
	certJobRuleIDs map[string]string
	certJobsLoaded bool
}

// parseCertJobTaskID 解析 cert-job:<id> 形态：批量 resolver 与单条入口共用，
// 保证 "007"/"+7"/"abc" 等形态在两条路径结论一致（此前批量按原始字符串查
// map、单条 Atoi 归一，同任务会一边有日志一边为空）。
func parseCertJobTaskID(taskID string) (int64, bool) {
	raw, ok := strings.CutPrefix(taskID, "cert-job:")
	if !ok {
		return 0, false
	}
	id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

func (r *systemTaskLogPathResolver) resolve(taskID string) (string, error) {
	if !strings.HasPrefix(taskID, "cert-job:") {
		return taskengine.TaskLogPath(taskID), nil
	}
	jobID, ok := parseCertJobTaskID(taskID)
	if !ok {
		return "", nil
	}
	if !r.certJobsLoaded {
		database := db.DB
		if database == nil {
			r.certJobRuleIDs = map[string]string{}
			r.certJobsLoaded = true
		} else {
			beforeSystemTaskLogDBQuery()
			rows, err := database.Query(`SELECT id, rule_id FROM cert_jobs`)
			if err != nil {
				return "", err
			}
			loaded := make(map[string]string)
			for rows.Next() {
				var jobID int
				var ruleID string
				if scanErr := rows.Scan(&jobID, &ruleID); scanErr != nil {
					rows.Close()
					return "", scanErr
				}
				loaded[strconv.Itoa(jobID)] = ruleID
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return "", err
			}
			r.certJobRuleIDs = loaded
			r.certJobsLoaded = true
		}
	}
	ruleID := r.certJobRuleIDs[strconv.FormatInt(jobID, 10)]
	if ruleID == "" {
		return "", nil
	}
	return services.CertJobLogPath(ruleID), nil
}

func systemTaskLogPath(taskID string) (string, error) {
	// 单条入口（日志弹框/MCP get_system_task_logs）：单行查询替代全表
	// 预载——cert_jobs 行数=规则×域名（无保留期清理，长期可达数千行），
	// 每次查看日志全表扫不可持续。批量调用方（logstats）仍走 resolver
	// 预载（一次全表扫供 N 次解析复用，N+1 防护不变）。
	if !strings.HasPrefix(taskID, "cert-job:") {
		return taskengine.TaskLogPath(taskID), nil
	}
	jobID, ok := parseCertJobTaskID(taskID)
	if !ok {
		return "", nil
	}
	database := db.DB
	if database == nil {
		return "", nil
	}
	beforeSystemTaskLogDBQuery()
	var ruleID string
	err := database.QueryRow(`SELECT rule_id FROM cert_jobs WHERE id=?`, jobID).Scan(&ruleID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	if ruleID == "" {
		return "", nil
	}
	return services.CertJobLogPath(ruleID), nil
}
