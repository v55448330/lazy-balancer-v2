---
condition: "assert\\s+\\w+\\s+in\\s+s[\\s\\S]{0,200}assert\\s+\\w+\\s+in\\s+s[\\s\\S]{0,200}assert\\s+\\w+\\s+in\\s+s"
scope: "tool:bash"
interruptMode: "always"
---
# 禁止批量修复脚本(R-7/幻影修复根因)

检测到包含 3 个以上 `assert ... in s` 断言的 Python 批量修复脚本。

**违反**: 审计修复 TDD 强化第 7 条——禁止批量修复脚本。一个断言失败会静默跳过后续所有项,导致 commit 虚报(第 2 轮幻影修复×3 的直接技术根因)。

**正确做法**: 每个修复项独立脚本/独立验证/独立确认落盘。移除此脚本,逐项拆分修复。
