package handlers

import (
	"context"
	"database/sql"
	"fmt"
)

type rowQuery struct {
	label string
	query string
	args  []any
}

func queryRowsAsMaps(ctx context.Context, queryer tableQuerier, request rowQuery) ([]map[string]any, error) {
	rows, err := queryer.QueryContext(ctx, request.query, request.args...)
	if err != nil {
		return nil, fmt.Errorf("读取%s: %w", request.label, err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	result := make([]map[string]any, 0)
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
	return result, rows.Err()
}

var _ tableQuerier = (*sql.DB)(nil)
