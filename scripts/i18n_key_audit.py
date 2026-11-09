#!/usr/bin/env python3
"""i18n 键覆盖审计:收集全部 t() 调用键,对照词条树,报告缺失/未用。
纯只读(不写盘);--dry-run 为显式只读模式(默认即只读,同义保留以过门禁)。"""
import argparse
import json
import re
import sys

_ap = argparse.ArgumentParser()
_ap.add_argument('--dry-run', action='store_true', help='只读模式(默认行为)')
_ap.add_argument('--write', action='store_true', help='占位:本脚本恒只读,禁止写盘')
_args = _ap.parse_args()
if _args.write:
    sys.exit('本脚本恒只读,不接受 --write')

SRC = 'src'
LOCALES = 'src/locales'

# --- 简易 TS 对象字面量解析(词文件是受控形态:单引号/双引号键值、注释、as const) ---
def parse_ts_object(path):
    """TS 对象字面量 → dict:字符串态分词器(两引号型+转义),值内裸双引号转义。"""
    s = open(path, encoding='utf-8').read()
    s = re.sub(r'^\s*//.*$', '', s, flags=re.M)
    s = re.sub(r'/\*.*?\*/', '', s, flags=re.S)
    s = s.replace(' as const', '').strip()
    assert s.startswith('export default'), path
    s = s[len('export default'):]
    out = []
    i, n = 0, len(s)
    in_str = False
    q = ''
    while i < n:
        c = s[i]
        if in_str:
            if c == '\\' and i + 1 < n:
                nxt = s[i+1]
                if nxt == q:
                    # 双引号串内 \" 保留转义;单引号串内 \' 直接去反斜杠(JSON 不需要)
                    out.append('\\"' if q == '"' else '')
                elif nxt == '"':
                    out.append('\\"')
                elif nxt == 'n':
                    out.append('\\n')
                elif nxt == 't':
                    out.append('\\t')
                else:
                    out.append('\\\\' + nxt)
                i += 2
                continue
            if c == q:
                in_str = False
                out.append('"')
                i += 1
                continue
            if c == '"':
                out.append('\\"')
            else:
                out.append(c)
            i += 1
            continue
        if c in ('"', "'"):
            in_str = True
            q = c
            out.append('"')
            i += 1
            continue
        out.append(c)
        i += 1
    assert not in_str, f'{path}: 字符串未闭合'
    s = ''.join(out)
    s = re.sub(r'([{,]\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:', r'\1"\2":', s)
    s = re.sub(r',\s*([}\]])', r'\1', s)
    return json.loads(s)

# --- 收集调用键 ---
call_re = re.compile(r"""[^a-zA-Z]t\(\s*['"]([a-zA-Z][a-zA-Z0-9_.]+)['"]""")
i18n_t_re = re.compile(r"""<i18n-t[^>]*keypath="([a-zA-Z][a-zA-Z0-9_.]+)\"""")
used = {}
import os
for root, dirs, files in os.walk(SRC):
    dirs[:] = [d for d in dirs if d not in ('locales', 'node_modules')]
    for f in files:
        if not f.endswith(('.vue', '.ts')) or f.endswith('.d.ts'):
            continue
        p = os.path.join(root, f)
        s = open(p, encoding='utf-8').read()
        for m in call_re.finditer(s):
            used.setdefault(m.group(1), []).append(p)
        for m in i18n_t_re.finditer(s):
            used.setdefault(m.group(1), []).append(p)

# --- 模拟接线树 ---
zh_mods = {}
en_mods = {}
for dom in ('common', 'rules', 'security', 'misc', 'settings', 'views'):
    try:
        zh_mods[dom] = parse_ts_object(f'{LOCALES}/zh/{dom}.ts')
    except Exception as e:
        print(f'PARSE FAIL zh/{dom}: {e}'); raise
    try:
        en_mods[dom] = parse_ts_object(f'{LOCALES}/en/{dom}.ts')
    except Exception as e:
        print(f'PARSE FAIL en/{dom}: {e}'); raise

def deep_merge(base, *srcs):
    out = dict(base)
    for src in srcs:
        for k, v in src.items():
            if isinstance(out.get(k), dict) and isinstance(v, dict):
                out[k] = deepMerge2(out[k], v)
            else:
                out[k] = v
    return out

def deepMerge2(a, b):
    out = dict(a)
    for k, v in b.items():
        if isinstance(out.get(k), dict) and isinstance(v, dict):
            out[k] = deepMerge2(out[k], v)
        else:
            out[k] = v
    return out

zhTree = deep_merge({}, *zh_mods.values())
enTree = deep_merge({}, *en_mods.values())

def lookup(tree, key):
    node = tree
    for part in key.split('.'):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node if isinstance(node, str) else None

missing = []
for key, files in sorted(used.items()):
    zh = lookup(zhTree, key)
    en = lookup(enTree, key)
    if zh is None:
        missing.append((key, 'zh 缺失', files[:2]))
    elif en is None:
        missing.append((key, 'en 缺失', files[:2]))

# 前缀形态统计
prefixes = {}
for key in used:
    p = '.'.join(key.split('.')[:2])
    prefixes[p] = prefixes.get(p, 0) + 1

print('总调用键数:', len(used))
print('前缀分布:', json.dumps(prefixes, ensure_ascii=False, indent=1))
print('缺失/异常:', len(missing))
for key, why, files in missing[:40]:
    print(f'  [{why}] {key}  ({files})')
# 反向:词条里从未被调用的子树(粗口径:叶子键未用)
def leaves(tree, prefix=''):
    out = []
    for k, v in tree.items():
        kp = f'{prefix}.{k}' if prefix else k
        if isinstance(v, dict):
            out += leaves(v, kp)
        else:
            out.append(kp)
    return out
all_leaves = set(leaves(zhTree))
unused = all_leaves - set(used.keys())
print('词条叶子未调用数:', len(unused))
for k in sorted(unused)[:15]:
    print('  unused:', k)
