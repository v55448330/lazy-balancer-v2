#!/usr/bin/env python3
"""i18n 后端消息 codemod——extract(只读盘点) / apply(带 --write 与 dry-run 默认)。

批量编辑门禁遵守:①dry-run 默认,--write 才写盘;②逐文件报告命中数;
③只匹配单行精确模式 `Message: "<含中文>"` 与 `Message: <v>.Error()`;
④gin ctx 变量名按函数签名解析,解析失败即跳过并报告(宁漏勿错);
⑤幂等:已含 apimsg.T/apimsg.ErrMsg 的行跳过。
"""
import hashlib
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ZH = re.compile(r'Message: ("[^"]*[一-龥][^"]*")')
ERR = re.compile(r'Message: (\w+)\.Error\(\)')
FUNC = re.compile(r'func [^{]*?\((\w+) \*gin\.Context\)')
DONE = re.compile(r'apimsg\.(T|ErrMsg)\(')


def key_of(zh: str) -> str:
    h = 0x811C9DC5
    for b in zh.encode("utf-8"):
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return "k_" + f"{h:08x}"


def scan(path):
    """返回 (sites, skipped) sites=[(lineno, ctxvar, kind, payload)]"""
    src = open(path, encoding="utf-8").read()
    lines = src.splitlines(keepends=True)
    func_at = {}  # 行号->ctx 变量名
    cur = None
    for i, ln in enumerate(lines):
        m = FUNC.search(ln)
        if m:
            cur = m.group(1)
        if cur:
            func_at[i] = cur
    sites, skipped = [], []
    for i, ln in enumerate(lines):
        if DONE.search(ln):
            continue
        body = ln
        m = ZH.search(body)
        if m:
            zh = m.group(1)
            sites.append((i, func_at.get(i), "zh", zh))
            continue
        m = ERR.search(body)
        if m:
            sites.append((i, func_at.get(i), "err", m.group(1)))
    return sites, skipped


def apply_file(path, dry=True):
    src = open(path, encoding="utf-8").read()
    lines = src.splitlines(keepends=True)
    sites, _ = scan(path)
    catalog = {}
    changed = 0
    for lineno, ctxvar, kind, payload in sites:
        ln = lines[lineno]
        if ctxvar is None:
            print(f"  SKIP(no-ctx) {path}:{lineno+1}")
            continue
        indent = ln[: len(ln) - len(ln.lstrip())]
        if kind == "zh":
            k = key_of(payload)
            catalog[k] = payload.strip('"')
            new = ln.replace(
                f"Message: {payload}",
                f'Message: apimsg.T({ctxvar}, "{k}"), MessageKey: "{k}"',
            )
        else:
            new = ln.replace(
                f"Message: {payload}.Error()", f"Message: apimsg.ErrMsg({ctxvar}, {payload})"
            )
        lines[lineno] = new
        changed += 1
    if changed and not dry:
        body = "".join(lines)
        if '"lazy-balancer-v2/internal/apimsg"' not in body:
            body = body.replace(
                "import (", 'import (\n\t"lazy-balancer-v2/internal/apimsg"', 1
            )
            # gofmt 会排 import;此处先粗放,批量后统一 gofmt -w
        open(path, "w", encoding="utf-8").write(body)
    return changed, catalog


def main():
    mode = sys.argv[1]
    paths = sys.argv[2:]
    all_catalog = {}
    total = 0
    for p in paths:
        if not os.path.isfile(p):
            continue
        if mode == "extract":
            sites, _ = scan(p)
            for _, _, kind, payload in sites:
                if kind == "zh":
                    k = key_of(payload)
                    all_catalog[k] = payload.strip('"')
                else:
                    all_catalog[f"__err__{payload}"] = payload
            print(f"{p}: {len(sites)}")
            total += len(sites)
        elif mode == "apply":
            n, cat = apply_file(p, dry="--write" not in sys.argv)
            all_catalog.update(cat)
            print(f"{p}: {n} 替换")
            total += n
    if mode == "apply" and "--catalog-out" in sys.argv:
        out = sys.argv[sys.argv.index("--catalog-out") + 1]
        json.dump(all_catalog, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=0, sort_keys=True)
        print(f"catalog -> {out} ({len(all_catalog)})")
    print(f"TOTAL: {total}")


if __name__ == "__main__":
    main()
