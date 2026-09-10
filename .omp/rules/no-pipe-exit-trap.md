---
condition: "go test.*\\|.*grep.*;.*\\$\\?"
scope: "tool:bash"
interruptMode: "always"
---
# 管道退出码陷阱(R-3/MFA P0 隐藏 30 分钟根因)

检测到 `go test` 管道后使用 `$?` 获取退出码。

**违反**: 审计修复 TDD 强化第 4 条——管道中 `$?` 捕获的是管道尾命令(grep/head)的退出码,**不是 go test 的**。

**正确做法**:
```bash
# 方式 1: PIPESTATUS
go test ./... -count=1 2>&1 | grep -E '^FAIL'; echo "EXIT=${PIPESTATUS[0]}"

# 方式 2: 直跑(无管道)
go test ./... -count=1 > /dev/null 2>&1; echo $?
```
