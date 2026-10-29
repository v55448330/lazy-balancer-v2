package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type rowQuery struct {
	label string
	query string
	args  []any
}

func queryRowsAsMaps(ctx context.Context, queryer tableQuerier, request rowQuery) (result []map[string]any, err error) {
	rows, err := queryer.QueryContext(ctx, request.query, request.args...)
	if err != nil {
		return nil, fmt.Errorf("读取%s: %w", request.label, err)
	}
	// Close 错误与同族读取点（certificates.go 批量证书规则等）同口径：
	// errors.Join 进错误面，不得静默丢弃（连接池/驱动异常时丢 Close 错误
	// 会让「结果可能不完整」被当成完整结果返回）。
	defer func() {
		err = errors.Join(err, rows.Close())
	}()
	columns, err := rows.Columns()
	if err != nil {
		// 与 Query/Scan 分支同口径——列读取失败也必须带表/快照
		// label，否则备份导出/规则快照日志无法定位失败源。
		return nil, fmt.Errorf("读取%s列: %w", request.label, err)
	}
	result = make([]map[string]any, 0)
	for rows.Next() {
		values := make([]any, len(columns))
		targets := make([]any, len(columns))
		for index := range values {
			targets[index] = &values[index]
		}
		if err := rows.Scan(targets...); err != nil {
			return nil, fmt.Errorf("扫描%s: %w", request.label, err)
		}
		row := make(map[string]any, len(columns))
		for index, column := range columns {
			if bytes, ok := values[index].([]byte); ok {
				row[column] = string(bytes)
			} else {
				row[column] = values[index]
			}
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历%s: %w", request.label, err)
	}
	return result, nil
}

var _ tableQuerier = (*sql.DB)(nil)
