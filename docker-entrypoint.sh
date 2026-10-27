#!/bin/sh
set -e

# Use /app/data as the single persistent data directory.
export XDG_DATA_HOME=/app/data
mkdir -p /app/data/caddy

# Caddy 崩溃监督器:前台运行 Caddy(退出即回收,零僵尸),崩溃自动重启(退避),
# admin 停止(pause 文件)不重启(尊重用户 stop_caddy 操作)。
# lazy-balancer 的 startCaddy/stopCaddy handler 经 pause 文件与监督器协调:
#   stopCaddy: 先建 pause → admin API 停 → 监督器见 pause 进入等待环
#   startCaddy: 删 pause → 监督器 ≤1s 检测到 → 启动 Caddy(handler 等 admin 就绪)
CADDY_PAUSE_FILE=/tmp/lazy-balancer-caddy-paused
# 「启动回放阶段完成」标记——reapply_last_good 尾部写（LKG 缺失/回放失败也写，
# 语义=「admin 就绪+回放阶段已了结」），app 侧 ApplyConfigOnStartup
# （handlers/caddy.go waitStartupReplayDone）等本标记后再应用。消除监督器首启
# LKG 回放与 app BootSync 应用的竞态：app 渲染先落时，迟到的 LKG 回放会覆盖
# 新配置。时序构造性定死：回放 → 标记 → app 应用。
CADDY_STARTUP_REPLAY_DONE=/tmp/lazy-balancer-caddy-startup-replayed

# Initialize database on first run
if [ ! -f /app/data/lazy-balancer.db ]; then
    echo "Initializing database..."
    /usr/local/bin/lazy-balancer --init
fi

# Generate Caddyfile if not exists
if [ ! -f /app/config/Caddyfile ]; then
    # 镜像内恒有出厂 config/Caddyfile(COPY 进镜像);挂载空目录覆盖时补写引导
    # 配置。内容必须与出厂文件同构:只声明 admin 接口与 metrics 采集,不写任何
    # 站点块——固定端口的站点块会在该端口被占用时使 caddy run 直接退出,监督器
    # 进入 1s/30s 退避的重启循环(面板 PID1 存活但 Caddy 永不可用)。对外端口
    # 一律由数据库渲染的配置接管。
    cat > /app/config/Caddyfile <<'CADDYFILE'
{
	admin 127.0.0.1:2019
	metrics {
		per_host
		observe_catchall_hosts
	}
}
CADDYFILE
fi

# Set timezone from database if available
if [ -f /app/data/lazy-balancer.db ]; then
    TZ=$(sqlite3 /app/data/lazy-balancer.db "SELECT COALESCE(timezone,'Asia/Shanghai') FROM global_config WHERE id=1" 2>/dev/null || echo "Asia/Shanghai")
    # || 只兜 sqlite3 非零退出——查询成功但零行（id=1 被手工删除）时返回空串，
    # 空 TZ 在 musl 下=UTC，与面板时区分叉。
    [ -z "$TZ" ] && TZ="Asia/Shanghai"
    export TZ
    echo "Timezone: $TZ"
fi

# —— Caddy 监督器(后台子 shell,容器生命周期存活)——
# 设计:
#   • Caddy 前台运行(caddy run 阻塞)——退出即被 shell 回收,零僵尸进程
#   • 退出后查 pause 文件:存在=admin 停止(用户意图),进入等待环
#   • 不存在=崩溃,1s 重启;连续 ≥5 次退避 30s 后重置计数(再给机会)
#   • startCaddy handler 删 pause 后监督器 ≤1s 检测并启动(等待环 1s 粒度)
#   • 容器 stop:tini(PID 1) 把信号转发给面板子进程 → 面板优雅退出后 tini 退出 → 容器 teardown 杀全部进程(含监督器)
# 监督器 pid 标记同属「容器运行期」状态——docker stop/start、restart 复用同一
# 可写层，上一生命周期的标记会留存，新标记（下方父壳写入）落盘前若被
# supervisorAlive 读到即陈旧误判。必须在父壳侧、后台化监督器之前清除；不可放进
# 子壳：子壳内清除会与下方父壳 `echo $!` 写入竞态（实测 300/300 子壳 rm 恒晚于
# 父壳写），误删刚写入的在位标记 → 永久失标。
rm -f /tmp/lazy-balancer-caddy-supervisor.pid
# 回放标记同属「容器运行期」状态——上一生命周期的标记留存会让 app 在监督器
# 本轮回放完成前误判就绪、提前应用。与上方 pid 标记同款父壳侧清除（不可放子壳：
# 子壳清除晚于本 exec 会有窗口）。
rm -f "$CADDY_STARTUP_REPLAY_DONE"
(
  # set +e: 监督器必须扛住 Caddy 的非零退出(被杀/崩溃)——外层 set -e 会在
  # caddy run 返回非零时杀死监督器本身(实测:kill -9 后监督器变僵尸不自愈)
  set +e
  # pid 标记在父壳侧写入（见下方 `) &` 后）——POSIX sh 的 $$ 在 subshell 内
  # 仍=父 shell pid，此处写入的是父壳 pid（exec 后为 tini 的面板子进程），
  # supervisorAlive 读到 app 自身恒判活。
  # 监督器日志双写: stdout(docker logs) + lazy-balancer.log(运行日志弹框可见,
  # 时间戳格式与 services.Logf 对齐)——用户在基础设置→运行日志可看完整自愈链
  APP_LOG="${LOG_FILE:-/app/logs/lazy-balancer.log}"
  sup_log() {
    LINE="$(date '+%Y/%m/%d %H:%M:%S') [caddy-supervisor] $1"
    echo "$LINE"
    echo "$LINE" >> "$APP_LOG" 2>/dev/null
  }
  # pause 生命周期=容器运行期。监督器启动即
  # 代表容器新生命周期，此刻 pause 必为上一生命周期残留（docker stop/start、
  # restart 复用同一容器可写层，/tmp 不清空——仅 compose 重建容器才清），
  # 残留会让监督器开机即 standby、永不拉起 Caddy，startup 配置载入全部 refused。
  # 运行期协议不受影响：监督器此时尚未进主循环，stopCaddy 建/startCaddy 删照旧。
  if [ -f "$CADDY_PAUSE_FILE" ]; then
    rm -f "$CADDY_PAUSE_FILE"
    sup_log "Cleared stale pause marker from previous container life"
  fi
  CRASHES=0
  FIRST_START=1  # V1（历史）：首启豁免——容器启动由 BootSync 权威载入，
  # 触发文件仅用于运行期 Caddy 崩溃自愈（否则启动载入审计/日志双行）
  while true; do
    # 暂停等待环(admin stop 后持 pause;startCaddy 删除后 ≤1s 退出本环)
    while [ -f "$CADDY_PAUSE_FILE" ]; do
      sleep 1
    done

    sup_log "Starting Caddy..."
    caddy run --config /app/config/Caddyfile --adapter caddyfile &
    CADDY_PID=$!

    # 就绪后的恢复动作(重应用 last-good + 写权威修正 trigger)
    reapply_last_good() {
      if [ -s /app/data/last_good_caddy_config.json ]; then
        if wget -q -O /dev/null -T 5 --header="Content-Type: application/json" \
          --post-file=/app/data/last_good_caddy_config.json \
          http://localhost:2019/load 2>/dev/null; then
          sup_log "Re-applied last known good config (last_good 快照)"
        else
          sup_log "WARN: last-good config re-apply failed"
        fi
      fi
      # trigger 文件:lazy-balancer 侧监听后走与启动完全相同的 DB 渲染→校验→
      # 应用流程(权威修正——last_good 只是快速恢复桥,可能滞后于 DB)。
      # 首启豁免:容器启动由 BootSync 权威载入,仅运行期崩溃自愈写触发。
      # 例外:slow-start 后台环(admin 就绪逾 10 探针)无条件补写本触发——该
      # 形态下 BootSync 载入已失败或将被迟到回放覆盖,见下方 slow-start 块注释。
      if [ "$FIRST_START" -eq 0 ]; then
        echo restarted > /tmp/caddy-restarted
      fi
      # 标记「回放阶段已了结」——app 启动载入
      # (waitStartupReplayDone)等本标记后再应用。无条件写(回放失败/LKG 缺失
      # 也写,否则 app 空等超时);两条调用路径(就绪主环+slow-start 后台环)
      # 经本函数单点覆盖。运行期崩溃重放重写本标记:app 已消费或不在等待,
      # 幂等无害。
      : > "$CADDY_STARTUP_REPLAY_DONE"
    }

    # 等 admin 就绪后重应用 last-good 配置(重启后 Caddy 只有 Caddyfile 的
    # 基础形态,443 规则等需经 admin API /load 重放——否则崩溃自愈后 HTTPS 缺失)
    READY=0
    for i in 1 2 3 4 5 6 7 8 9 10; do
      if wget -q -O /dev/null -T 1 http://localhost:2019/config/ 2>/dev/null; then
        READY=1
        reapply_last_good
        break
      fi
      sleep 1
    done

    # 就绪探针逾时的兜底自愈——此前逾时(慢磁盘/
    # 高负载下 admin 迟迟不就绪)既不补 last_good 也不写 trigger,Caddy 以
    # 零规则形态运行且权威修正链永不唤醒,恢复仅剩重启/人工 reload。后台
    # 子循环继续探:就绪后补 last_good + trigger;Caddy 退出(本轮 pid 被外层
    # wait 回收/下轮换新 pid)即退出,与监督器主环生命周期对齐。
    if [ "$READY" -eq 0 ]; then
      sup_log "WARN: Caddy admin not ready after 10 probes, background recovery loop continues"
      (
        while true; do
          sleep 1
          kill -0 "$CADDY_PID" 2>/dev/null || exit 0
          if wget -q -O /dev/null -T 1 http://localhost:2019/config/ 2>/dev/null; then
            reapply_last_good
            # slow-start 路径补写权威修正触发。本路径只在
            # admin 就绪逾 10 探针（>10s）时进入：app 侧启动应用链
            # （waitStartupReplayDone 30s 上限放行 + admin 就绪等待 + 应用）此刻
            # 大概率已失败（admin 未就绪，应用POST refused/超时仅记日志，无重试）
            # 或将被本处迟到的 last-good 回放覆盖——首启豁免
            # （reapply_last_good 内「首启不写 trigger」）假设的「BootSync 权威
            # 载入必然落地」在 slow-start 形态下不成立。补写 /tmp/caddy-restarted
            # 唤醒 app 侧 caddy-restart watcher（mtime 晚于进程启动=有效触发）
            # 走与启动完全相同的 DB 渲染→校验→应用流程，无论边界竞态落在哪一侧
            # 都强制重收敛；watcher 未启动时文件持久在场，启动后被拾取。快速路径
            # （≤10 探针就绪）不受影响：豁免保持，无启动审计/任务日志双行。
            # 运行期崩溃后 slow-start（FIRST_START=0）与 reapply_last_good 内的
            # 触发写入重复，文件幂等、watcher 单次消费，无害。
            # Ruling（方向取舍）：①提高 waitStartupReplayDone 超时——拿面板可用
            # 性换窄竞态：慢磁盘/监督器僵死时 app 启动被扣押更久（面板是诊断
            # 工具，不能失联），且超出新超时窗的就绪仍不收敛，否决；②就绪信号
            # 前移（admin 就绪即写回放标记、先于 LKG 回放）——拆毁历史
            # 「回放→标记→应用」构造性时序，重新引入 v2.3.7-beta 实锤的 LKG
            # 覆盖硬币竞态，否决。本方向复用既有权威修正通道（触发文件+watcher），
            # 快路径零影响、app 侧永不被扣押、自愈与启动同源（历史问题 裁定），
            # 最鲁棒。
            echo restarted > /tmp/caddy-restarted
            sup_log "Slow-start recovery: config re-applied after delayed admin readiness"
            exit 0
          fi
        done
      ) &
    fi

    # 首轮拉起流程到此结束——后续均为运行期（崩溃重拉走权威修正触发）
    FIRST_START=0
    # 等待 Caddy 退出(wait 同时回收进程——零僵尸)
    wait $CADDY_PID
    CODE=$?
    sup_log "Caddy exited (code $CODE)"

    # admin 停止(pause 已建)→ 不重启,回等待环
    if [ -f "$CADDY_PAUSE_FILE" ]; then
      sup_log "Admin stop detected, standing by..."
      CRASHES=0
      continue
    fi

    # 崩溃 → 退避重启
    CRASHES=$((CRASHES+1))
    if [ "$CRASHES" -lt 5 ]; then
      sup_log "Crash #$CRASHES, restarting in 1s"
      sleep 1
    else
      sup_log "Crash #$CRASHES, backing off 30s"
      sleep 30
      CRASHES=0
    fi
  done
) &

# 监督器 pid 标记在父壳侧写入——$! = 刚后台化的
# 子 shell 本体 pid（POSIX 后台作业 pid）；写入先于下方 exec 成 app，无
# 时序竞争。handlers/caddy.go supervisorAlive 按此标记+stat 状态字节判定。
echo $! > /tmp/lazy-balancer-caddy-supervisor.pid

# Start backend (tini 子进程 — 容器 stop 时接收 tini 转发的信号并优雅退出)
echo "Starting Lazy Balancer..."
# 不传 serve 位参——main.go 只有 -config/-init flag，无子命令分发，位参无
# 消费方（flag.Args 从不被读）。
exec /usr/local/bin/lazy-balancer
