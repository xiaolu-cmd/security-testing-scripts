# Security Testing Scripts

安全测试脚本集合 — 覆盖常见漏洞的检测与利用工具。**仅用于授权安全测试和靶场验证。**

## 目录

- [Web 应用 / CMS](#web-应用--cms)
- [中间件 / 框架](#中间件--框架)
- [大数据 / 搜索引擎](#大数据--搜索引擎)
- [文件管理 / 文档预览](#文件管理--文档预览)
- [数据库 / 缓存](#数据库--缓存)
- [协作平台 / 办公系统](#协作平台--办公系统)
- [远程服务 / 协议](#远程服务--协议)
- [Burp Suite 扩展](#burp-suite-扩展)
- [工具 / 辅助](#工具--辅助)
- [使用说明](#使用说明)

---

## Web 应用 / CMS

| 脚本 | 目标 | CVE / 漏洞 | 说明 |
|------|------|------------|------|
| `ecshop_check.py` | ECShop 2.x/3.x/4.x | CVE-2024-31025 等 | 综合检测：Referer 序列化注入 RCE、collection_list SQL 注入、模板编辑 RCE |
| `thinkphp5_check.py` | ThinkPHP 5.0.x ~ 5.1.x | 多 CVE | 三大攻击面：未强制路由 RCE、`_method` 变量覆盖 RCE、多语言 pearcmd 文件包含 |

## 中间件 / 框架

| 脚本 | 目标 | CVE / 漏洞 | 说明 |
|------|------|------------|------|
| `spring4shell.py` | Spring Framework | CVE-2022-22965 | Spring4Shell — 操控 Tomcat AccessLogValve 写入 JSP webshell |
| `apache_parse_bypass.py` | Apache HTTPD 2.4.0~2.4.29 | CVE-2017-15715 | 上传文件名 `\x0A` 换行解析绕过，Apache 仍按 PHP 解析 |
| `nginx_ui_check.py` | Nginx-UI | CVE-2024-23827/22197/22198/23828/49368 | 综合检测：证书路径穿越文件写入、test_config_cmd/start_cmd 命令注入 RCE、CRLF 绕过、logrotate 注入 |
| `supervisord_exploit.py` | Supervisord | CVE-2017-11610/2019-12105 | XML-RPC 未授权访问、命名空间穿越 os.system RCE、日志/进程信息泄露、弱口令爆破 |
| `shellshock.py` | Bash CGI | CVE-2014-6271/7169 | Shellshock 破壳漏洞 Web 检测，多线程扫描 CGI 路径 + 命令执行验证 |
| `druid_rce.py` | Apache Druid | CVE-2023-25194 | 伪造 Kafka Broker → Java 反序列化 RCE（配合 ysoserial） |

## 大数据 / 搜索引擎

| 脚本 | 目标 | CVE / 漏洞 | 说明 |
|------|------|------------|------|
| `Apache-hadoop.py` | Apache Hadoop YARN | 未授权 RCE | YARN ResourceManager REST API 未授权 → 提交恶意 ApplicationMaster → 任意命令执行 |
| `hugegraph_check.py` | Apache HugeGraph | CVE-2024-27348/43441 | Gremlin Sandbox 绕过 RCE (CISA KEV)、硬编码 JWT Secret 认证绕过 |
| `geoserver_check.py` | GeoServer | CVE-2024-36401/36404 | WFS GetPropertyValue XPath 注入 RCE (CVSS 9.8, 未授权)、XXE、SQL 注入 |
| `xwiki.py` | XWiki | CVE-2025-24893 | SolrSearch text 参数 wiki 标记注入 → 脚本宏 RCE |

## 文件管理 / 文档预览

| 脚本 | 目标 | CVE / 漏洞 | 说明 |
|------|------|------------|------|
| `elfinder_check.py` | elFinder 2.x | CVE-2021-32682/2023-52044/2022-27115/2022-26960 | 综合检测：ZIP 命令注入、.php8 上传绕过、Windows 尾随点绕过、路径穿越文件读取 |
| `kkfileview_check.py` | kkFileView 4.x | 多漏洞 | 综合检测：任意文件读取、SSRF、文件上传 RCE、Zip Slip RCE |

## 数据库 / 缓存

| 脚本 | 目标 | CVE / 漏洞 | 说明 |
|------|------|------------|------|
| `redis_cve_2022_0543.py` | Redis (Debian/Ubuntu) | CVE-2022-0543 | Lua 沙箱逃逸 RCE — `package.loadlib` 加载系统库执行命令 |
| `mongodb_check.py` | MongoDB | CVE-2021-20330 等 | 综合检测：未授权访问、`$where`/`eval` JS RCE、NoSQL 注入 Fuzzer（认证绕过+盲注）、弱口令爆破、信息泄露审计 |

## 协作平台 / 办公系统

| 脚本 | 目标 | CVE / 漏洞 | 说明 |
|------|------|------------|------|
| `yanzhi_oa.py` | 然之 OA | 默认 AES 密钥 | 然之 OA xuanxuan 模块加密通信利用 |
| `openfire_test_plugin/` | Openfire | 插件漏洞 | 测试插件构建 / 部署，用于 Openfire 插件安全测试 |

## 远程服务 / 协议

| 脚本 | 目标 | CVE / 漏洞 | 说明 |
|------|------|------------|------|
| `samba_check.py` | Samba 3.x/4.x | CVE-2007-2447/2017-7494/2021-44142 等 | Samba 3.x 命令注入、Samba 4.x AD DC 多漏洞、SMBGhost 等 |
| `rmi_exploit.py` | Java RMI | CVE-2017-3241 等 | RMI Registry 枚举、JMX 检测、JRMP 反序列化攻击、远程类加载攻击 |
| `ylm.py` | NeatVNC | 认证绕过 | VNC 空认证 / 认证绕过检测 |

## Burp Suite 扩展

| 脚本 | 说明 |
|------|------|
| `svg-xss.py` | SVG XSS Scanner — Burp 扩展，5 种 SVG XSS payload 库、被动/安全注入双模式、Site Map SVG 查找、自动 Burp Issue 创建、多编码响应解码、深色主题 HTML 展示 |

## 工具 / 辅助

| 脚本 | 说明 |
|------|------|
| `url编码.py` | URL 编码 / 解码工具 |
| `security_scripts/ip_to_long_converter.py` | IP 地址 ↔ Long 整数互转 |

---

## 使用说明

### 环境要求

```bash
pip install requests pymongo pycryptodome urllib3
```

部分脚本需要额外依赖：
- `druid_rce.py` — 需要 `ysoserial-all.jar`（Java 反序列化 payload 生成）
- `spring4shell.py` — 需要目标运行 JDK 9+ + Tomcat WAR 部署
- `openfire_test_plugin/` — 需要 Maven 构建

### 基本用法

大多数脚本支持以下模式：

```bash
# 综合漏洞检测（默认）
python <script>.py -u http://target:port

# 远程命令执行
python <script>.py -u http://target:port rce "whoami"

# 交互式 Shell
python <script>.py -u http://target:port shell

# 查看帮助
python <script>.py -h
```

### 免责声明

本仓库所有工具仅用于：
- 授权的安全测试
- CTF 竞赛
- 靶场 / 教学环境验证
- 自身系统的安全评估

**禁止将本工具用于任何未经授权的攻击行为。使用者需自行承担法律责任。**

---

## 快速索引

| 服务/组件 | 脚本 | 严重程度 |
|-----------|------|----------|
| Hadoop YARN | `Apache-hadoop.py` | 严重 (未授权 RCE) |
| Apache HTTPD | `apache_parse_bypass.py` | 高 (解析绕过) |
| Druid | `druid_rce.py` | 严重 (RCE) |
| ECShop | `ecshop_check.py` | 严重 (RCE) |
| elFinder | `elfinder_check.py` | 严重 (RCE) |
| GeoServer | `geoserver_check.py` | 严重 (未授权 RCE) |
| HugeGraph | `hugegraph_check.py` | 严重 (未授权 RCE) |
| kkFileView | `kkfileview_check.py` | 严重 (RCE) |
| MongoDB | `mongodb_check.py` | 严重 (未授权/JS RCE) |
| Nginx-UI | `nginx_ui_check.py` | 严重 (文件写入→RCE) |
| Openfire | `openfire_test_plugin/` | 高 (插件漏洞) |
| Redis | `redis_cve_2022_0543.py` | 严重 (沙箱逃逸 RCE) |
| RMI | `rmi_exploit.py` | 严重 (反序列化 RCE) |
| Samba | `samba_check.py` | 严重 (RCE) |
| Shellshock | `shellshock.py` | 严重 (RCE) |
| Spring | `spring4shell.py` | 严重 (RCE) |
| Supervisord | `supervisord_exploit.py` | 严重 (RCE) |
| ThinkPHP | `thinkphp5_check.py` | 严重 (RCE) |
| VNC | `ylm.py` | 高 (认证绕过) |
| SVG XSS | `svg-xss.py` | 高 (Burp 扩展) |
| XWiki | `xwiki.py` | 严重 (RCE) |
| 然之 OA | `yanzhi_oa.py` | 高 (加密破解) |
