import socket
import struct

def ip_to_long(ip):
    return struct.unpack("!L", socket.inet_aton(ip))[0]

# 示例
ip = "144.48.243.213"
result = ip_to_long(ip)
print(f"{ip} -> {result}")  # 输出: 192.168.1.1 -> 3232235777