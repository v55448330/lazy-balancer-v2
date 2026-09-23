package caddygeoip

// @ipListFast 快算子（v2.3.x）的链接锚点——实现单一来源在 wafiplist 叶模块
// （排序不相交前缀集 + 二分，init 注册 coraza 算子）。本 blank import 保证
// xcaddy 构建的 Caddy 二进制经 caddygeoip 链入该算子（Dockerfile 另以
// --with lazy-balancer-v2/wafiplist=./wafiplist 双保险直达主模块）。
import _ "lazy-balancer-v2/wafiplist"
