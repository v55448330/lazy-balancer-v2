package handlers

import (
	"database/sql"
	"errors"
	"strings"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

// systemTaskLogPath 是任务日志路径唯一解析入口。普通注册任务直接按任务 ID；
// cert-job 动态工作项必须先由 job_id 解析 rule_id，再进入证书日志目录。
func systemTaskLogPath(taskID string) (string, error) {
	if !strings.HasPrefix(taskID, "cert-job:") {
		return taskengine.TaskLogPath(taskID), nil
	}
	if db.DB == nil {
		return "", nil
	}
	var ruleID string
	err := db.DB.QueryRow(`SELECT rule_id FROM cert_jobs WHERE id=?`, strings.TrimPrefix(taskID, "cert-job:")).Scan(&ruleID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if ruleID == "" {
		return "", nil
	}
	return services.CertJobLogPath(ruleID), nil
}
