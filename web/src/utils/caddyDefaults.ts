// 「还原默认格式」按钮与初始 settings 共用的访问日志格式模板（唯一来源）。
// 注意：后端 db.go 迁移会在既有格式上追加 User-Agent / X-API-Key 行，
// 此处刻意保持前端原始模板不变（R41 F1：仅消除双份复制，不对齐后端迁移行）。
export const DEFAULT_ACCESS_LOG_FORMAT =
  'resp_headers -> delete\nrequest>tls -> delete\nrequest>remote_port -> delete\nlevel -> delete\nlogger -> delete\nmsg -> delete\nrequest>remote_ip -> src\nrequest>client_ip -> src_ip\nrequest>method -> http_method\nrequest>host -> server\nrequest>uri -> uri_path\nrequest>proto -> protocol\nuser_id -> user\nts -> time_local\nsize -> bytes_out\nbytes_read -> bytes_in\nduration -> request_time'
