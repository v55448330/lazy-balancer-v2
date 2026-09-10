---
condition: "git\\s+commit\\s+-m"
scope: "tool:bash"
interruptMode: "tool-only"
---
# Commit 前必须逐项核对 diff(R-4/幻影修复根因)

即将执行 git commit。在提交前,必须逐项核对 commit message 中声称的每个修复在 diff 中实际存在。

** checklist(R-4 门禁)**:
1. `git diff --stat` — 文件列表与修复项对应
2. 对每个声称修复的关键代码片段: `grep '<片段>' <文件>` — 必须命中
3. 任何声称修复未在 diff 中命中 → commit 虚报 → **禁止提交**

**历史教训**: 第 2 轮批量脚本断言中断后,只重跑了部分项但 commit message 声称全部已修(幻影修复×3)。
