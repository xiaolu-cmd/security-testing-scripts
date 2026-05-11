# Security Testing Scripts

常见漏洞检测与利用脚本集，仅供授权安全测试使用。

## 脚本列表

| 脚本 | 类型 | 说明 |
|------|------|------|
| `burp_svg_xss_scanner.py` | XSS | Burp Suite 扩展，自动扫描 SVG 文件上传 XSS 漏洞 |
| `csrf_phpmyadmin_poc.html` | CSRF | phpMyAdmin setup 页面 CSRF PoC |
| `ip_to_long_converter.py` | 工具 | IP 地址转长整数工具 |
| `redis_cve_2022_0543_rce.py` | RCE | Redis CVE-2022-0543 Lua 沙箱逃逸漏洞测试 |
| `shellshock_cve_2014_6271_scanner.py` | RCE | Shellshock (破壳漏洞) CVE-2014-6271 Web 检测扫描器 |
| `supervisord_xmlrpc_rce.py` | RCE | Supervisor XML-RPC 接口命令执行漏洞利用 |
| `vnc_null_auth_bypass.py` | 认证绕过 | NeatVNC NULL 认证绕过检测 |
| `xwiki_cve_2025_24893_rce.py` | RCE | XWiki CVE-2025-24893 SolrSearch RCE 测试 |

## 免责声明

本仓库所有工具仅限**授权安全测试**使用。使用者应遵守相关法律法规，未经授权不得对非自有系统进行测试。作者不承担因滥用导致的任何法律责任。
