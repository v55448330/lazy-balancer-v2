---
astCondition:
  - "go test $$$X"
condition: "go\\s+test\\s+\\./"
scope: "tool:bash"
interruptMode: "tool-only"
---
# TDD 门禁提醒(R-1~R-3)

即将运行 go test。确认以下门禁状态:

- **R-1 RED**: 新写的测试必须对当前(未修复)代码失败。若测试直接通过 → 假红 → 测试无效
- **R-2 GREEN**: 实现修复后同一测试必须通过
- **R-3 全量**: 交付前 `go test ./... -count=1` 必须 `${PIPESTATUS[0]}` = 0

每修一个 RED 测试,全形状覆盖(目标+回归+畸形),实证验证替代代码推理。
