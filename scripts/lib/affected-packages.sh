#!/usr/bin/env bash
# 变更面 -> Go 包测试目标（`scripts/test-all.sh --fast` 的判据本体）。
#
# 为什么单列成库：映射逻辑必须被门禁本体与自检脚本**共同**消费——两份实现
# 会在下一次改动里漂移，而这类漂移的表现恰好是「快检恒绿」（少测），不是红。
#
# 口径（三条，均为 fail-closed）：
#   1. 改动文件 = 受控变更（git diff HEAD，含已暂存）+ 未跟踪未忽略文件。
#      「先写文件 -> 跑门禁 -> 再 git add」是常见顺序，只看受控文件会漏测新包。
#   2. 变更文件所在包 + **反向依赖闭包**：改 services 会让依赖它的 handlers
#      回归，只跑 services 是本次「合并树才暴露跨域断裂」的直接成因。
#   3. 归属模块取最长前缀匹配（根模块与嵌套模块同名前缀不会串台）。无法
#      归属到任何模块的 .go 文件由调用方判失败，不静默跳过。
#
# 不在此处理的：go.mod/go.sum 变更（依赖图整体位移）由调用方升级为整模块
# 全量测试——按包裁剪在依赖图变化时没有意义。

# affected_changed_files
#   输出仓库内全部改动文件（仓库根相对路径，LF 分隔，LC_ALL=C 排序去重）。
affected_changed_files() {
  {
    if git rev-parse --verify -q HEAD >/dev/null 2>&1; then
      git diff --name-only HEAD
    else
      # 无提交的历史（全新仓）：把所有受控文件当变更面。
      git ls-files
    fi
    git ls-files --others --exclude-standard
  } 2>/dev/null | LC_ALL=C sort -u
}

# affected_module_of_go_file <file>
#   输出该 .go 文件所属模块（根模块为 "."），无法归属时输出空串。
#   modules 由调用方注入数组 module_list。
affected_module_of_go_file() {
  local file="$1" best="" module
  case "$file" in
    *.go) ;;
    *) return 0 ;;
  esac
  for module in "${module_list[@]}"; do
    if [[ "$module" == "." ]]; then
      # 根模块兜底：只在没有更长的嵌套模块前缀命中时使用。
      continue
    fi
    if [[ "$file" == "$module/"* ]] && [[ ${#module} -gt ${#best} ]]; then
      best="$module"
    fi
  done
  if [[ -n "$best" ]]; then
    printf '%s\n' "$best"
    return 0
  fi
  # 其余 .go 文件都属根模块：上方已对全部嵌套模块做最长前缀匹配，
  # 走到这里即没有任何嵌套模块认领该路径。
  printf '.\n'
}

# affected_module_changed_files <module> <file...>
#   过滤出属于该模块的 Go 文件并输出（仓库根相对路径）。
affected_module_changed_files() {
  local module="$1"; shift
  local file owner
  for file in "$@"; do
    owner="$(affected_module_of_go_file "$file")"
    if [[ "$owner" != "$module" ]]; then continue; fi
    printf '%s\n' "$file"
  done
}

# affected_module_dependency_changed <module> <file...>
#   该模块的 go.mod/go.sum 是否在变更面内（是则调用方跑整模块全量）。
affected_module_dependency_changed() {
  local module="$1"; shift
  local prefix file
  if [[ "$module" == "." ]]; then
    prefix=""
  else
    prefix="$module/"
  fi
  for file in "$@"; do
    if [[ "$file" == "${prefix}go.mod" || "$file" == "${prefix}go.sum" ]]; then
      return 0
    fi
  done
  return 1
}

# affected_module_changed_packages <module> <file...>
#   只输出变更文件所在包（不含反向依赖闭包）。
#   用途：`--fast` 的测试面——跨包类型/API 断裂由调用方先跑的 `go vet` +
#   `go build ./...` 承担；仅「依赖方的断言级回归」留到 `--fast-deep`/全量。
affected_module_changed_packages() {
  local module="$1"; shift
  local module_abs rel dir rel_pattern import_path
  module_abs="$(cd "$module" && pwd)"
  for file in "$@"; do
    if [[ "$module" == "." ]]; then
      rel="$file"
    else
      rel="${file#"$module"/}"
    fi
    dir="$(dirname "$rel")"
    if [[ "$dir" == "." ]]; then
      rel_pattern="."
    else
      rel_pattern="./$dir"
    fi
    import_path="$(cd "$module" && go list -e -f '{{.Dir}}' "$rel_pattern" 2>/dev/null | head -1 || true)"
    if [[ -n "$import_path" ]]; then
      local rel_out="${import_path#"$module_abs"}"
      rel_out="${rel_out#/}"
      if [[ -z "$rel_out" ]]; then
        printf './.\n'
      else
        printf './%s\n' "$rel_out"
      fi
    fi
  done
}

# affected_go_targets <module> <file...>
#   输出该模块内需要 `go test` 的包模式（每行一个 `./dir`）：
#   变更文件所在包 + 反向依赖闭包。
#   包无法解析（构建标签排除、目录已无 Go 文件等）时回退为目录模式本身，
#   交由 go test 判定——不静默丢弃。
affected_go_targets() {
  local module="$1"; shift
  local -a files=("$@")
  local -a rel_dirs=()
  local file rel dir

  for file in "${files[@]}"; do
    if [[ "$module" == "." ]]; then
      rel="$file"
    else
      rel="${file#"$module"/}"
    fi
    dir="$(dirname "$rel")"
    rel_dirs+=("$dir")
  done
  if [[ ${#rel_dirs[@]} -eq 0 ]]; then
    return 0
  fi

  local module_abs
  module_abs="$(cd "$module" && pwd)"

  # 种子导入路径：逐个变更目录解析（失败即回退目录模式）。
  local -a seed_paths=() fallback_dirs=()
  local d rel_pattern
  for d in "${rel_dirs[@]}"; do
    if [[ "$d" == "." ]]; then
      rel_pattern="."
    else
      rel_pattern="./$d"
    fi
    local import_path
    import_path="$(cd "$module" && go list -e -f '{{.ImportPath}}' "$rel_pattern" 2>/dev/null | head -1 || true)"
    if [[ -n "$import_path" ]]; then
      seed_paths+=("$import_path")
    else
      fallback_dirs+=("$rel_pattern")
    fi
  done

  # 反向依赖闭包：一次 go list 取模块内每包的 Deps，再在 awk 里做不动点迭代。
  if [[ ${#seed_paths[@]} -gt 0 ]]; then
    (cd "$module" && go list -e -f '{{.ImportPath}}|{{join .Deps " "}}' ./... 2>/dev/null) |
      awk -v module_abs="$module_abs" -v seeds="${seed_paths[*]}" '
        BEGIN { n = split(seeds, arr, " "); for (i = 1; i <= n; i++) if (arr[i] != "") want[arr[i]] = 1 }
        {
          split($0, parts, "|")
          pkg = parts[1]
          if (pkg == "") next
          pkgs[pkg] = 1
          m = split(parts[2], deps, " ")
          for (j = 1; j <= m; j++) if (deps[j] != "") rev[deps[j]] = rev[deps[j]] " " pkg
        }
        END {
          # 不动点：want 增长到不再变化（包数有限，最多 N 轮）。
          do {
            added = 0
            for (p in want) {
              cnt = split(rev[p], dependents, " ")
              for (k = 1; k <= cnt; k++) {
                q = dependents[k]
                if (q != "" && !(q in want)) { want[q] = 1; added = 1 }
              }
            }
          } while (added)
          for (p in want) if (p in pkgs) print p
        }' |
      while IFS= read -r import_path; do
        local pkg_dir rel_out
        pkg_dir="$(cd "$module" && go list -e -f '{{.Dir}}' "$import_path" 2>/dev/null | head -1 || true)"
        [[ -n "$pkg_dir" ]] || continue
        rel_out="${pkg_dir#"$module_abs"}"
        rel_out="${rel_out#/}"
        if [[ -z "$rel_out" ]]; then
          printf './.\n'
        else
          printf './%s\n' "$rel_out"
        fi
      done
  fi

  local pattern
  for pattern in "${fallback_dirs[@]+"${fallback_dirs[@]}"}"; do
    printf '%s\n' "$pattern"
  done
}
