#!/usr/bin/env python3
"""前端中文文案候选提取(只读)——为抽词批次产出逐文件工作清单。

输出 JSON:{file: [{line, text, kind}]}
kind: tpl-attr(模板属性值)/tpl-text(模板插值外文本)/js-str(TS 字符串字面量)
口径:仅用户可见文案;排除纯数字/单字符/地理数据文件(i18n 排除名单)。
用法:python3 scripts/i18n_fe_extract.py <file...> > /tmp/i18n_fe_candidates.json
"""
import json
import re
import sys

EXCLUDE = re.compile(r'(Provinces|countryCentroids|worldBorders|chinaProvinces|admin1)')
ZH = re.compile(r'[一-龥]')
# TS/模板字符串/单双引号字面量(粗筛,抽词人工复核)
JS_STR = re.compile(r'''(['"`])[^'"`\\]*[一-龥][^'"`\\]*\1''')
# 模板属性:label="中文" placeholder="中文" title="中文" description="中文" content="中文"
TPL_ATTR = re.compile(r'(label|placeholder|title|description|content|tooltip|text|message|header)="([^"]*[一-龥][^"]*)"')
# 插值外的模板文本:>中文<
TPL_TEXT = re.compile(r'>([^<>{}]*[一-龥][^<>{}]*)<')


def scan(path):
    out = []
    try:
        lines = open(path, encoding='utf-8').read().splitlines()
    except (OSError, UnicodeDecodeError):
        return out
    in_comment = False
    for i, ln in enumerate(lines, 1):
        s = ln.strip()
        if in_comment:
            in_comment = s.endswith('*/') and not s.startswith('*/') or (in_comment and not s.endswith('*/'))
            continue
        if s.startswith('/*'):
            in_comment = not s.endswith('*/')
            continue
        if s.startswith('//') or s.startswith('<!--'):
            continue
        for m in TPL_ATTR.finditer(ln):
            out.append({'line': i, 'text': m.group(2), 'kind': 'tpl-attr'})
        for m in TPL_TEXT.finditer(ln):
            t = m.group(1).strip()
            if t:
                out.append({'line': i, 'text': t, 'kind': 'tpl-text'})
        # JS 字符串:排除已被 tpl-attr 命中的行内重复(粗口径,人工复核)
        if '<template' not in ln:
            for m in JS_STR.finditer(ln):
                t = m.group(0)[1:-1]
                out.append({'line': i, 'text': t, 'kind': 'js-str'})
    return out


def main():
    result = {}
    total = 0
    for p in sys.argv[1:]:
        if EXCLUDE.search(p):
            continue
        items = scan(p)
        if items:
            result[p] = items
            total += len(items)
    json.dump(result, sys.stdout, ensure_ascii=False, indent=1)
    print(f'\n// files={len(result)} candidates={total}', file=sys.stderr)


if __name__ == '__main__':
    main()
